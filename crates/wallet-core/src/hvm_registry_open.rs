//! The WALLET half of opening a shared HVM registry V2 channel.
//!
//! The Hub half of this exchange is built and proven on a real chain in
//! `crates/l2-fast-pay-hub/tests/registry_open_countersign_on_chain.rs`. What
//! was missing was everything on this side of the wire: a way for a wallet to
//! left-sign the serial-1 full-refund bill, a way to check what the Hub sends
//! back rather than believe it, and a single derivable statement that funding
//! is now permitted.
//!
//! # The rule this module exists to make unbreakable
//!
//! **A user must never be able to put money into a registry channel without
//! already holding a Hub-countersigned bill that returns all of it.**
//!
//! The contract cannot enforce that. `PayableHAC` accepts any correctly-sized
//! HAC transfer from the left address while the channel is in FUNDING and has
//! no view of an off-chain signature. So the rule has to be a property of the
//! code that produces funding, and the way it is made a property rather than a
//! policy is [`HvmRegistryFundingAuthorizationV1`]: an opaque value with
//! private fields, no `Deserialize`, and exactly one constructor
//! ([`authorize_registry_funding`]) whose first statement validates a
//! countersigned refund bundle. There is no way to obtain one by parsing, by
//! defaulting, by cloning a stored record, or by asserting.
//!
//! # Why the wallet builds the bill and the Hub only signs it
//!
//! The request the Hub is asked to countersign carries the binding and the
//! bill the *wallet* derived. The answer carries 97 bytes and nothing else
//! (see `HvmRegistryRefundCountersignResponseV2`), so a Hub has no field
//! through which to propose a different channel id, deposit, reuse version or
//! objection window: those bytes never leave the wallet. What is left for a
//! hostile or broken Hub to get wrong is the signature, and
//! [`adopt_hub_countersignature`] verifies that against the *wallet's own*
//! `binding.right_hub_address` rather than against any key riding inside the
//! wire signature.
//!
//! # Why the ask expires and the answer does not
//!
//! The lifetime on the request stops a captured ask being replayed at the Hub.
//! The bill itself carries no time field and must not: an expiring refund is a
//! Hub-shaped weapon - wait it out and the user is back to holding nothing. So
//! [`require_askable`] is checked before the ask goes on the wire, and
//! [`adopt_hub_countersignature`] deliberately uses the *time-free* shape
//! check, because a wallet that crashed between the ask and the answer must
//! still be able to use what it holds.

use field::{Serialize as _, Sign};
use l2_fast_pay_hub::hvm_registry::{
    HVM_REGISTRY_BILL_SCHEMA, HVM_REGISTRY_REFUND_COUNTERSIGN_MAX_LIFETIME_SECONDS,
    HVM_REGISTRY_REFUND_COUNTERSIGN_REQUEST_SCHEMA, HvmRegistryBillV2, HvmRegistryBindingV2,
    HvmRegistryLiveSnapshotV2, HvmRegistryRecoveryBundleV2, HvmRegistryRefundCountersignRequestV2,
};
use l2_fast_pay_hub::hvm_registry_ledger::{
    HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA, HvmRegistryRefundCountersignResponseV2,
};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    SignedHvmRegistryFundingTransactionV2, build_signed_hvm_registry_funding_transaction,
};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;

use crate::hvm_registry_exit_driver::HvmRegistryExitSightingV1;
use serde::Serialize;
use sys::Account;

use crate::error::{WalletError, WalletResult};

/// How long a countersign ask this wallet builds stays valid at the Hub.
///
/// Well inside the protocol ceiling. A short window is the whole value of the
/// field: it bounds how long a captured ask can be replayed, and it costs a
/// user nothing, because a refused or expired ask can simply be rebuilt - the
/// channel has not been funded yet, and nothing has been spent.
pub const HVM_REGISTRY_OPEN_ASK_LIFETIME_SECONDS: u64 = 120;

const _: () = assert!(
    HVM_REGISTRY_OPEN_ASK_LIFETIME_SECONDS <= HVM_REGISTRY_REFUND_COUNTERSIGN_MAX_LIFETIME_SECONDS
);

/// The schema this module stamps on a funding authorization.
pub const HVM_REGISTRY_FUNDING_AUTHORIZATION_SCHEMA: &str =
    "hpay-hvm-registry-funding-authorization/1";

fn refuse(reason: &str) -> WalletError {
    WalletError::Policy(reason.into())
}

fn hub_error(error: l2_fast_pay_hub::HubError) -> WalletError {
    WalletError::L2(error.to_string())
}

/// Left-sign the serial-1 full-refund bill for a binding this wallet derived,
/// and produce the ask the Hub is sent.
///
/// # What is signed
///
/// Exactly one thing, and it is the most user-favourable bill the channel will
/// ever have: serial 1, `left_balance_zhu == binding.left_deposit_zhu`,
/// `hub_balance_zhu == 0`. Every one of those three is asserted here, after
/// the bill is built, so this function cannot be turned into a general bill
/// signer by a later edit to the struct literal above it.
///
/// # What the signing hash is
///
/// [`HvmRegistryBillV2::signing_hash`], the encoder both sides of this channel
/// already use for every bill of its life. Nothing here re-derives a hash of
/// its own: a second encoder that agreed today and drifted tomorrow would
/// produce a refund that verifies in the wallet and is worthless on chain.
pub fn build_left_signed_refund_request(
    signer: &Account,
    binding: HvmRegistryBindingV2,
    created_unix: u64,
) -> WalletResult<HvmRegistryRefundCountersignRequestV2> {
    binding.validate().map_err(hub_error)?;
    if signer.readable() != binding.left_address {
        return Err(refuse(
            "this wallet is not the left party of the channel it was asked to open",
        ));
    }
    if binding.left_address == binding.right_hub_address {
        return Err(refuse(
            "a registry channel cannot have this wallet on both sides",
        ));
    }
    if binding.left_deposit_zhu == 0 || binding.right_hub_deposit_zhu != 0 {
        return Err(refuse(
            "the shared registry profile funds the left deposit only",
        ));
    }
    if created_unix == 0 {
        return Err(refuse("a registry open ask needs a real clock"));
    }
    let expires_unix = created_unix
        .checked_add(HVM_REGISTRY_OPEN_ASK_LIFETIME_SECONDS)
        .ok_or_else(|| refuse("registry open ask deadline overflow"))?;

    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().map_err(hub_error)?,
        serial: 1,
        left_balance_zhu: binding.left_deposit_zhu,
        hub_balance_zhu: 0,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    // Read back what is about to be signed, from the bill itself rather than
    // from the literal that built it.
    if bill.serial != 1
        || bill.left_balance_zhu != binding.left_deposit_zhu
        || bill.hub_balance_zhu != 0
    {
        return Err(refuse(
            "this wallet will only left-sign the serial-1 full refund at open",
        ));
    }
    let hash = bill.signing_hash(&binding).map_err(hub_error)?;
    bill.left_signature_hex = hex::encode(Sign::create_by(signer, &hash).serialize());
    bill.validate_left_signed(&binding).map_err(hub_error)?;

    let request = HvmRegistryRefundCountersignRequestV2 {
        schema: HVM_REGISTRY_REFUND_COUNTERSIGN_REQUEST_SCHEMA.into(),
        binding,
        left_signed_refund_bill: bill,
        created_unix,
        expires_unix,
    };
    // `validate` rather than `validate_shape`: an ask this wallet just built
    // and cannot itself send is a bug worth failing on here.
    request.validate(created_unix).map_err(hub_error)?;
    Ok(request)
}

/// Refuse to put an ask on the wire that the Hub would be right to reject.
pub fn require_askable(
    request: &HvmRegistryRefundCountersignRequestV2,
    now_unix: u64,
) -> WalletResult<()> {
    request.validate(now_unix).map_err(hub_error)
}

/// Check the Hub's 97 bytes against the binding **this wallet** derived, and
/// turn them into a recovery bundle only if they hold up.
///
/// # What a hostile or broken Hub is refused for here
///
/// * A signature over a different channel, deposit, reuse version, objection
///   window or serial. All of those are inputs to
///   [`HvmRegistryBillV2::signing_hash`], which is recomputed from the
///   *wallet's* binding, so a signature made over anything else does not
///   verify.
/// * A well-formed signature from a key that is not
///   `binding.right_hub_address`. `validate_fully_signed` checks against the
///   bound address, not against a public key carried in the wire signature.
/// * A response that quietly replaced the left signature, the balances or the
///   binding while splicing. Each is compared field by field against the ask
///   this wallet kept.
/// * A response envelope of an unknown schema.
///
/// # What it deliberately does not check
///
/// The ask's expiry. This runs on stored state after a crash, and a bundle
/// that stopped being valid because five minutes passed would be a refund the
/// Hub could wait out.
pub fn adopt_hub_countersignature(
    request: &HvmRegistryRefundCountersignRequestV2,
    response: &HvmRegistryRefundCountersignResponseV2,
    expected_left_address: &str,
) -> WalletResult<HvmRegistryRecoveryBundleV2> {
    if response.schema != HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA {
        return Err(refuse(
            "the Hub answered the registry open with an unknown response schema",
        ));
    }
    request.validate_shape().map_err(hub_error)?;
    if request.binding.left_address != expected_left_address {
        return Err(refuse(
            "the stored registry open ask is for another wallet's channel",
        ));
    }
    let bundle = request
        .attach_hub_countersignature(&response.hub_refund_signature_hex)
        .map_err(hub_error)?;

    // Everything below is the wallet checking the splice rather than trusting
    // it. `attach_hub_countersignature` lives in the Hub crate and is shared
    // with the operator tooling; this is the wallet stating its own terms.
    if bundle.binding != request.binding {
        return Err(refuse(
            "the countersigned refund is bound to a channel this wallet did not ask for",
        ));
    }
    let bill = &bundle.initial_recovery_bill;
    if bill.serial != 1
        || bill.left_balance_zhu != request.binding.left_deposit_zhu
        || bill.hub_balance_zhu != 0
        || bill.left_signature_hex != request.left_signed_refund_bill.left_signature_hex
        || bill.binding_commitment != request.binding.commitment().map_err(hub_error)?
    {
        return Err(refuse(
            "the countersigned refund does not return this wallet's whole deposit",
        ));
    }
    bundle.validate_crypto().map_err(hub_error)?;
    if !bill.is_initial_recovery_bill(&bundle.binding) {
        return Err(refuse(
            "the countersigned refund is not the exact serial-1 full refund",
        ));
    }
    Ok(bundle)
}

/// The single statement that funding this channel is permitted.
///
/// Private fields, accessors only, `Serialize` but **no `Deserialize`**. It
/// cannot be read off a disk, defaulted, or built by a struct literal outside
/// this module; the only way to hold one is to have just handed
/// [`authorize_registry_funding`] a bundle that verified. A stored copy is a
/// souvenir, not permission - the permission has to be re-derived from the
/// bundle every time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HvmRegistryFundingAuthorizationV1 {
    schema: String,
    binding_commitment: String,
    contract_address: String,
    left_address: String,
    hub_address: String,
    amount_zhu: u64,
    refund_bill_commitment: String,
}

impl HvmRegistryFundingAuthorizationV1 {
    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn binding_commitment(&self) -> &str {
        &self.binding_commitment
    }

    /// Where the deposit goes: the registry contract, taken from the binding
    /// the refund bill is signed under, never from a caller.
    pub fn contract_address(&self) -> &str {
        &self.contract_address
    }

    pub fn left_address(&self) -> &str {
        &self.left_address
    }

    pub fn hub_address(&self) -> &str {
        &self.hub_address
    }

    /// Exactly `binding.left_deposit_zhu`, which is exactly what the
    /// countersigned bill returns.
    pub const fn amount_zhu(&self) -> u64 {
        self.amount_zhu
    }

    pub fn refund_bill_commitment(&self) -> &str {
        &self.refund_bill_commitment
    }
}

/// The chain, as opening and funding a registry channel needs to see it.
///
/// Four read-or-submit methods, and deliberately not one of them is a provider
/// call. Everything here would answer identically with the provider's process
/// deleted, which is the point: the user must be able to establish that the
/// contract they are about to pay is the reviewed registry without asking the
/// party who would profit from lying about it.
///
/// The implementation holds no key and decides nothing. It cannot choose an
/// amount, a fee, a timestamp or a destination; those are derived from the
/// countersigned bundle.
#[allow(async_fn_in_trait)]
pub trait HvmRegistryOpenChainV1 {
    /// The wallet's own pinned, fingerprint-verified node identity.
    ///
    /// Everything a binding claims about *where* it lives is checked against
    /// this and never against itself.
    async fn network_binding(&self) -> WalletResult<L1ChannelNetworkBinding>;

    /// Live contract storage for the channel this binding names, read raw.
    ///
    /// Raw on purpose: the judgement belongs to
    /// [`authorize_registry_funding`] and [`require_openable_binding`], in one
    /// place, rather than to whichever implementation happened to fetch it.
    async fn registry_snapshot(
        &self,
        binding: &HvmRegistryBindingV2,
    ) -> WalletResult<HvmRegistryLiveSnapshotV2>;

    /// Hand exact signed funding bytes to the node. A duplicate is success:
    /// the bytes are idempotent by hash and the caller made them durable first.
    async fn submit_funding_transaction(
        &self,
        binding: &HvmRegistryBindingV2,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> WalletResult<()>;

    /// What this node knows about the funding transaction hash.
    async fn funding_sighting(
        &self,
        transaction_hash: &str,
    ) -> WalletResult<HvmRegistryExitSightingV1>;
}

/// What a wallet must have read off **its own pinned fullnode** before any of
/// this is worth anything.
///
/// # Why this type exists at all
///
/// Every field of an [`HvmRegistryBindingV2`] is a claim, and until this
/// existed the wallet believed all of them. `binding.validate()` checks that
/// the *claimed* `bytecode_sha3` equals the reviewed constant; it cannot check
/// the code actually deployed at `contract_address`, because it has no chain.
/// `deployment_tx_hash` and `deployment_height` were carried and never used.
/// `chain_id` and `network_instance_id` were never compared with the node the
/// wallet is pinned to. A provider - or a poisoned blob of pasted JSON - could
/// therefore name a contract of its own, get an entirely honest Hub to
/// countersign a sincere full refund for it, and take the deposit; the refund
/// was real and the contract it referred to was not the registry.
///
/// Every one of those checks did exist. All of them lived on the far side of
/// the spend, in adoption. This type is how they are moved in front of it.
///
/// The `chain_id`, `network_instance_id` and `network_mode` here are the
/// wallet's **own node's**, read through the fingerprint-verified node binding,
/// never taken from the binding under test.
#[derive(Debug, Clone, Copy)]
pub struct HvmRegistryOpenChainEvidenceV1<'a> {
    /// The registry contract's live storage, read from the wallet's own node.
    pub snapshot: &'a HvmRegistryLiveSnapshotV2,
    pub node_chain_id: u32,
    pub node_network_instance_id: &'a str,
    pub node_network_mode: &'a str,
    pub minimum_required_live_blocks: u64,
    pub minimum_required_recover_blocks: u64,
}

impl HvmRegistryOpenChainEvidenceV1<'_> {
    /// The binding names the chain this wallet is actually on, and the
    /// contract at that address really is the reviewed registry carrying
    /// exactly the unfunded channel the binding describes.
    fn require_agrees_with(&self, binding: &HvmRegistryBindingV2) -> WalletResult<()> {
        binding.validate().map_err(hub_error)?;
        if binding.network_mode != self.node_network_mode {
            return Err(refuse(
                "this channel is for another network than the one this wallet is pinned to",
            ));
        }
        if binding.chain_id != self.node_chain_id
            || binding.network_instance_id != self.node_network_instance_id
        {
            return Err(refuse(
                "this channel is on a different chain than the fullnode this wallet verified; a \
                 refund enforceable only somewhere this wallet is not is not a refund",
            ));
        }
        // The one check that reads deployed code rather than a claim about
        // it: the snapshot's `bytecode_sha3` is hashed by the node from what
        // is actually at `contract_address`, and `validate_snapshot_identity`
        // compares it with the binding's, which `binding.validate()` has
        // already pinned to `HPAY_REGISTRY_BYTECODE_SHA3`. It also settles
        // `deployment_tx_hash`, `deployment_height` and
        // `deployment_action_verified`, and every channel parameter the
        // contract will later hash a bill against.
        self.snapshot
            .validate_prefunding_binding(
                binding,
                self.minimum_required_live_blocks,
                self.minimum_required_recover_blocks,
            )
            .map_err(hub_error)
    }
}

/// Everything about a stored refund that can be checked without a chain.
///
/// This is exactly the set of checks the funding gate applied before the chain
/// evidence above was added to it, kept as its own function so that the two
/// places which legitimately have no network - re-verifying wallet state on
/// load, and reasoning about a bundle held through a crash - keep applying
/// precisely what they always applied, while the funding gate itself gets
/// strictly stronger.
pub fn validate_stored_refund(
    bundle: &HvmRegistryRecoveryBundleV2,
    expected_left_address: &str,
) -> WalletResult<()> {
    bundle.validate_crypto().map_err(hub_error)?;
    let binding = &bundle.binding;
    if binding.left_address != expected_left_address {
        return Err(refuse(
            "this wallet holds no countersigned refund for the channel it was asked to fund",
        ));
    }
    let bill = &bundle.initial_recovery_bill;
    if !bill.is_initial_recovery_bill(binding) {
        return Err(refuse(
            "the stored refund is not the serial-1 full refund; funding is refused",
        ));
    }
    if bill.left_balance_zhu != binding.left_deposit_zhu || bill.hub_balance_zhu != 0 {
        return Err(refuse(
            "the stored refund does not return the whole deposit; funding is refused",
        ));
    }
    Ok(())
}

/// The check that runs **before this wallet will left-sign anything**.
///
/// Signing costs nothing and risks nothing by itself, so this is not here to
/// protect a signature. It is here so that a wallet cannot be walked into
/// holding a countersigned refund for a contract that is not the registry and
/// then be told, truthfully, that a provider has guaranteed its deposit back.
/// The refusal a user needs is the one that arrives before they believe they
/// are safe.
pub fn require_openable_binding(
    binding: &HvmRegistryBindingV2,
    expected_left_address: &str,
    chain: &HvmRegistryOpenChainEvidenceV1<'_>,
) -> WalletResult<()> {
    if binding.left_address != expected_left_address {
        return Err(refuse(
            "this wallet is not the left party of the channel it was asked to open",
        ));
    }
    chain.require_agrees_with(binding)
}

/// The one gate. Funding is authorised by producing this and no other way.
///
/// The first statement of the body is `bundle.validate_crypto()`. That is
/// exactly the first statement of
/// `l2_fast_pay_hub::hvm_registry_pilot::build_hvm_registry_pilot_exact_funding`
/// and of
/// `l2_fast_pay_hub::hvm_registry_watchtower::build_signed_hvm_registry_funding_transaction`,
/// the only two places in this workspace that can produce registry funding
/// bytes. All three doors carry the same check on their first line.
///
/// What the signature of this function makes unskippable is the second half:
/// permission cannot be produced without a live reading of the wallet's own
/// pinned fullnode that agrees with the binding. There is no argument through
/// which a caller can supply a chain-shaped promise instead - the snapshot is
/// a `HvmRegistryLiveSnapshotV2`, and the only production source of one is
/// `l2_fast_pay_hub::node::NodeClient`.
pub fn authorize_registry_funding(
    bundle: &HvmRegistryRecoveryBundleV2,
    expected_left_address: &str,
    chain: &HvmRegistryOpenChainEvidenceV1<'_>,
) -> WalletResult<HvmRegistryFundingAuthorizationV1> {
    bundle.validate_crypto().map_err(hub_error)?;
    validate_stored_refund(bundle, expected_left_address)?;
    let binding = &bundle.binding;
    chain.require_agrees_with(binding)?;
    let bill = &bundle.initial_recovery_bill;
    Ok(HvmRegistryFundingAuthorizationV1 {
        schema: HVM_REGISTRY_FUNDING_AUTHORIZATION_SCHEMA.into(),
        binding_commitment: binding.commitment().map_err(hub_error)?,
        contract_address: binding.contract_address.clone(),
        left_address: binding.left_address.clone(),
        hub_address: binding.right_hub_address.clone(),
        amount_zhu: binding.left_deposit_zhu,
        refund_bill_commitment: bill.commitment().map_err(hub_error)?,
    })
}

/// Build the exact signed deposit transfer, and refuse to build it from
/// anything but permission that was just derived.
///
/// The authorization is not decoration on this signature. It cannot be
/// defaulted, deserialised or cloned out of storage, so a caller holding one
/// has, in this process, just handed [`authorize_registry_funding`] a bundle
/// that verified against a live reading of the wallet's own node. Every field
/// of the bytes is then taken from the bundle, and the authorization is
/// re-compared with it here so that a mismatched pair cannot fund either
/// channel.
pub fn build_registry_funding_transaction(
    signer: &Account,
    authorization: &HvmRegistryFundingAuthorizationV1,
    bundle: &HvmRegistryRecoveryBundleV2,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> WalletResult<SignedHvmRegistryFundingTransactionV2> {
    let binding = &bundle.binding;
    if authorization.schema != HVM_REGISTRY_FUNDING_AUTHORIZATION_SCHEMA
        || authorization.binding_commitment != binding.commitment().map_err(hub_error)?
        || authorization.contract_address != binding.contract_address
        || authorization.left_address != binding.left_address
        || authorization.hub_address != binding.right_hub_address
        || authorization.amount_zhu != binding.left_deposit_zhu
        || authorization.refund_bill_commitment
            != bundle
                .initial_recovery_bill
                .commitment()
                .map_err(hub_error)?
    {
        return Err(refuse(
            "the funding permission this wallet holds is not for the refund it was handed",
        ));
    }
    if signer.readable() != authorization.left_address {
        return Err(refuse(
            "registry funding may only be signed by the wallet the refund pays",
        ));
    }
    build_signed_hvm_registry_funding_transaction(
        signer,
        bundle,
        network_fee_zhu,
        timestamp,
        gas_max,
    )
    .map_err(hub_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_fast_pay_hub::hvm_registry::{
        HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BINDING_SCHEMA,
    };

    fn account(seed: &str) -> Account {
        l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
        Account::create_by(seed).unwrap()
    }

    fn binding(left: &Account, hub: &Account, reuse_version: u32) -> HvmRegistryBindingV2 {
        let contract =
            vm::ContractAddress::from_unchecked(field::Address::create_contract([9; 20]))
                .to_readable();
        HvmRegistryBindingV2 {
            schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id: "1a".repeat(32),
            contract_address: contract,
            deployment_tx_hash: "2b".repeat(32),
            deployment_height: 9,
            bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
            channel_id: "3c".repeat(16),
            reuse_version,
            left_address: left.readable().to_owned(),
            right_hub_address: hub.readable().to_owned(),
            left_deposit_zhu: 4_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        }
    }

    /// `"1a".repeat(32)`, spelled out so it can be a `const`.
    const NODE_NETWORK_INSTANCE_ID: &str =
        "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a";

    fn entry<T>(value: T) -> l2_fast_pay_hub::node::HvmStorageEntry<T> {
        l2_fast_pay_hub::node::HvmStorageEntry {
            value,
            live_blocks: 300_000,
            recover_blocks: 0,
            active: true,
            recoverable: false,
        }
    }

    /// The chain as it is at the moment a wallet is about to fund: the
    /// reviewed registry is deployed, and the channel exists, is initialised
    /// and has taken no coin yet.
    fn unfunded_snapshot(binding: &HvmRegistryBindingV2) -> HvmRegistryLiveSnapshotV2 {
        use l2_fast_pay_hub::hvm_registry::{
            HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
            HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryChannelStorageV2,
            HvmRegistryGlobalStorageV2,
        };
        HvmRegistryLiveSnapshotV2 {
            ret: 0,
            schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            chain_id: binding.chain_id,
            network_instance_id: binding.network_instance_id.clone(),
            observed_height: binding.deployment_height + 4,
            evaluation_height: binding.deployment_height + 5,
            contract_address: binding.contract_address.clone(),
            deployment_tx_hash: binding.deployment_tx_hash.clone(),
            deployment_height: binding.deployment_height,
            deployment_action_verified: true,
            bytecode_sha3: binding.bytecode_sha3.clone(),
            hub_address: binding.right_hub_address.clone(),
            left_address: binding.left_address.clone(),
            registry_key_count: HVM_REGISTRY_STORAGE_KEY_COUNT,
            channel_key_count: HVM_REGISTRY_CHANNEL_KEY_COUNT,
            all_keys_active: true,
            minimum_live_blocks: 300_000,
            minimum_recover_blocks: 0,
            registry: HvmRegistryGlobalStorageV2 {
                g_network: entry(binding.network_instance_id.clone()),
                g_hub: entry(binding.right_hub_address.clone()),
                g_locked: entry(0),
                g_left_claimable: entry(0),
                g_hub_claimable: entry(0),
                g_open_count: entry(0),
            },
            channel: HvmRegistryChannelStorageV2 {
                status: entry(1),
                channel_id: entry(binding.channel_id.clone()),
                reuse: entry(binding.reuse_version),
                deposit: entry(binding.left_deposit_zhu),
                paid: entry(0),
                total: entry(binding.left_deposit_zhu),
                serial: entry(0),
                left_balance: entry(binding.left_deposit_zhu),
                hub_balance: entry(0),
                challenge_blocks: entry(binding.challenge_blocks),
                deadline: entry(0),
                left_claimed: entry(false),
            },
        }
    }

    fn evidence(snapshot: &HvmRegistryLiveSnapshotV2) -> HvmRegistryOpenChainEvidenceV1<'_> {
        HvmRegistryOpenChainEvidenceV1 {
            snapshot,
            node_chain_id: 7,
            node_network_instance_id: NODE_NETWORK_INSTANCE_ID,
            node_network_mode: "testnet",
            minimum_required_live_blocks: 1,
            minimum_required_recover_blocks: 0,
        }
    }

    fn hub_answer(
        hub: &Account,
        request: &HvmRegistryRefundCountersignRequestV2,
    ) -> HvmRegistryRefundCountersignResponseV2 {
        let hash = request
            .left_signed_refund_bill
            .signing_hash(&request.binding)
            .unwrap();
        HvmRegistryRefundCountersignResponseV2 {
            schema: HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA.into(),
            hub_refund_signature_hex: hex::encode(Sign::create_by(hub, &hash).serialize()),
            anchor_receipts: Vec::new(),
        }
    }

    #[test]
    fn the_wallet_left_signs_only_the_serial_one_full_refund() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        assert_eq!(request.left_signed_refund_bill.serial, 1);
        assert_eq!(
            request.left_signed_refund_bill.left_balance_zhu,
            request.binding.left_deposit_zhu
        );
        assert_eq!(request.left_signed_refund_bill.hub_balance_zhu, 0);
        assert!(request.left_signed_refund_bill.hub_signature_hex.is_empty());
        request
            .left_signed_refund_bill
            .validate_left_signed(&request.binding)
            .unwrap();
    }

    #[test]
    fn a_wallet_will_not_left_sign_somebody_elses_channel() {
        let left = account("open-left");
        let hub = account("open-hub");
        let stranger = account("open-stranger");
        assert!(
            build_left_signed_refund_request(&stranger, binding(&left, &hub, 0), 1_800_000_000)
                .is_err()
        );
    }

    #[test]
    fn a_countersignature_for_another_reuse_version_is_refused() {
        let left = account("open-left");
        let hub = account("open-hub");
        let real = build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
            .unwrap();
        // The Hub signs the same wallet, same channel id, same deposit - and a
        // reuse version one higher. On chain that is a different incarnation
        // and the bill is worthless.
        let other = build_left_signed_refund_request(&left, binding(&left, &hub, 1), 1_800_000_000)
            .unwrap();
        let answer = hub_answer(&hub, &other);
        assert!(adopt_hub_countersignature(&real, &answer, left.readable()).is_err());
    }

    #[test]
    fn a_countersignature_from_a_key_that_is_not_the_bound_hub_is_refused() {
        let left = account("open-left");
        let hub = account("open-hub");
        let impostor = account("open-impostor");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&impostor, &request);
        assert!(adopt_hub_countersignature(&request, &answer, left.readable()).is_err());
    }

    #[test]
    fn an_unknown_response_schema_is_refused() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let mut answer = hub_answer(&hub, &request);
        answer.schema = "hpay-hvm-registry-refund-countersign-response/99".into();
        assert!(adopt_hub_countersignature(&request, &answer, left.readable()).is_err());
    }

    #[test]
    fn the_good_answer_authorises_funding_for_exactly_the_deposit() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        let snapshot = unfunded_snapshot(&bundle.binding);
        let authorization =
            authorize_registry_funding(&bundle, left.readable(), &evidence(&snapshot)).unwrap();
        assert_eq!(authorization.amount_zhu(), bundle.binding.left_deposit_zhu);
        assert_eq!(
            authorization.contract_address(),
            bundle.binding.contract_address
        );
        assert_eq!(authorization.left_address(), left.readable());
    }

    #[test]
    fn an_expired_ask_is_never_sent_and_a_stored_bundle_never_expires() {
        let left = account("open-left");
        let hub = account("open-hub");
        let created = 1_800_000_000;
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), created).unwrap();
        require_askable(&request, created).unwrap();
        assert!(
            require_askable(&request, created + HVM_REGISTRY_OPEN_ASK_LIFETIME_SECONDS).is_err(),
            "an expired ask must not go on the wire"
        );
        // The answer to that same ask, adopted long after it expired, is still
        // a valid refund - and still authorises funding.
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        let snapshot = unfunded_snapshot(&bundle.binding);
        authorize_registry_funding(&bundle, left.readable(), &evidence(&snapshot)).unwrap();
    }

    /// THE HOLE THIS CLOSED, in the shape a reviewer drove it on chain.
    ///
    /// A provider deploys its own contract at the address the binding names,
    /// publishes the reviewed bytecode hash beside it, and countersigns the
    /// full refund with complete sincerity. Every signature is real. The
    /// refund is worthless, because the thing it refers to is not the
    /// registry, and the wallet used to find that out only in adoption -
    /// after the deposit had gone.
    #[test]
    fn a_contract_that_is_not_the_reviewed_registry_authorises_nothing() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();

        let honest = unfunded_snapshot(&bundle.binding);
        authorize_registry_funding(&bundle, left.readable(), &evidence(&honest))
            .expect("the reviewed registry, carrying this exact unfunded channel, funds");

        // The node hashes what is actually deployed. A different contract at
        // the same address answers with a different digest.
        let mut impostor = honest.clone();
        impostor.bytecode_sha3 = "ff".repeat(32);
        assert!(
            authorize_registry_funding(&bundle, left.readable(), &evidence(&impostor)).is_err(),
            "funding a contract whose deployed code is not the reviewed registry must be refused"
        );

        // And a node that cannot confirm the deployment action is not
        // evidence that the deployment happened.
        let mut unverified = honest.clone();
        unverified.deployment_action_verified = false;
        assert!(
            authorize_registry_funding(&bundle, left.readable(), &evidence(&unverified)).is_err()
        );
    }

    /// A refund enforceable only on a chain this wallet is not on is not a
    /// refund. Both halves of the identity are checked, and both are taken
    /// from the node rather than from the binding.
    #[test]
    fn a_channel_on_another_chain_authorises_nothing() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        let snapshot = unfunded_snapshot(&bundle.binding);

        let mut wrong_chain = evidence(&snapshot);
        wrong_chain.node_chain_id = 18;
        assert!(authorize_registry_funding(&bundle, left.readable(), &wrong_chain).is_err());

        let mut wrong_instance = evidence(&snapshot);
        wrong_instance.node_network_instance_id = "de".repeat(32).leak();
        assert!(authorize_registry_funding(&bundle, left.readable(), &wrong_instance).is_err());

        let mut wrong_mode = evidence(&snapshot);
        wrong_mode.node_network_mode = "mainnet";
        assert!(authorize_registry_funding(&bundle, left.readable(), &wrong_mode).is_err());
    }

    /// The channel parameters the contract will hash a bill against live on
    /// chain, not in the binding, and `PayableHAC` never compares the two.
    /// This is the substitution a perfect Hub signature cannot catch.
    #[test]
    fn a_channel_whose_on_chain_terms_differ_from_the_signed_binding_authorises_nothing() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        let honest = unfunded_snapshot(&bundle.binding);

        for mutate in [
            (|s: &mut HvmRegistryLiveSnapshotV2| s.channel.channel_id.value = "99".repeat(16))
                as fn(&mut HvmRegistryLiveSnapshotV2),
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.reuse.value += 1,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.challenge_blocks.value += 1,
            |s: &mut HvmRegistryLiveSnapshotV2| s.channel.deposit.value -= 1,
            |s: &mut HvmRegistryLiveSnapshotV2| s.registry.g_hub.value = "x".into(),
        ] {
            let mut mutated = honest.clone();
            mutate(&mut mutated);
            assert!(
                authorize_registry_funding(&bundle, left.readable(), &evidence(&mutated)).is_err(),
                "a channel whose on-chain terms differ from the signed binding must not be funded"
            );
        }
    }

    /// A channel that has already taken coin is not fundable again, and the
    /// gate says so by construction rather than by a flag.
    #[test]
    fn a_channel_that_is_already_funded_is_not_authorised_again() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        let mut funded = unfunded_snapshot(&bundle.binding);
        funded.channel.status.value = 2;
        funded.channel.paid.value = bundle.binding.left_deposit_zhu;
        funded.registry.g_locked.value = bundle.binding.left_deposit_zhu;
        funded.registry.g_open_count.value = 1;
        assert!(authorize_registry_funding(&bundle, left.readable(), &evidence(&funded)).is_err());
    }

    /// The bytes are exactly the deposit, into exactly the contract, on
    /// exactly this chain - and they can be read back that way by a reader
    /// that shares no line with the builder.
    #[test]
    fn the_funding_bytes_pay_exactly_the_deposit_into_exactly_the_contract() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        let snapshot = unfunded_snapshot(&bundle.binding);
        let authorization =
            authorize_registry_funding(&bundle, left.readable(), &evidence(&snapshot)).unwrap();

        let signed = build_registry_funding_transaction(
            &left,
            &authorization,
            &bundle,
            10_000,
            1_800_000_100,
            255,
        )
        .unwrap();
        assert_eq!(signed.amount_zhu, bundle.binding.left_deposit_zhu);
        assert_eq!(signed.contract_address, bundle.binding.contract_address);
        l2_fast_pay_hub::hvm_registry_watchtower::read_exact_registry_funding_transaction(
            &signed.signed_transaction_hex,
            &bundle.binding,
        )
        .unwrap();

        // A stranger's key cannot sign this wallet's funding.
        let stranger = account("open-stranger");
        assert!(
            build_registry_funding_transaction(
                &stranger,
                &authorization,
                &bundle,
                10_000,
                1_800_000_100,
                255
            )
            .is_err()
        );

        // Nor can permission for one channel build bytes for another.
        let other_request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 1), 1_800_000_000)
                .unwrap();
        let other_answer = hub_answer(&hub, &other_request);
        let other_bundle =
            adopt_hub_countersignature(&other_request, &other_answer, left.readable()).unwrap();
        assert!(
            build_registry_funding_transaction(
                &left,
                &authorization,
                &other_bundle,
                10_000,
                1_800_000_100,
                255
            )
            .is_err()
        );
    }

    /// The offline half is unchanged in strength, and is what a wallet loading
    /// its own state after a crash applies. It still refuses a refund that
    /// keeps a zhu back or pays somebody else; it simply cannot, and does not
    /// pretend to, know anything about a chain.
    #[test]
    fn the_offline_shape_check_is_the_old_gate_exactly() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        validate_stored_refund(&bundle, left.readable()).unwrap();
        assert!(validate_stored_refund(&bundle, "stranger").is_err());
        let mut short = bundle.clone();
        short.initial_recovery_bill.left_balance_zhu -= 1;
        short.initial_recovery_bill.hub_balance_zhu += 1;
        assert!(validate_stored_refund(&short, left.readable()).is_err());
    }

    #[test]
    fn funding_is_refused_for_a_bundle_that_pays_someone_else() {
        let left = account("open-left");
        let hub = account("open-hub");
        let stranger = account("open-stranger");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        let snapshot = unfunded_snapshot(&bundle.binding);
        assert!(
            authorize_registry_funding(&bundle, stranger.readable(), &evidence(&snapshot)).is_err()
        );
    }

    #[test]
    fn funding_is_refused_for_a_bundle_whose_refund_was_tampered_with() {
        let left = account("open-left");
        let hub = account("open-hub");
        let request =
            build_left_signed_refund_request(&left, binding(&left, &hub, 0), 1_800_000_000)
                .unwrap();
        let answer = hub_answer(&hub, &request);
        let mut bundle = adopt_hub_countersignature(&request, &answer, left.readable()).unwrap();
        // A refund that keeps one zhu back is not a full refund.
        bundle.initial_recovery_bill.left_balance_zhu -= 1;
        bundle.initial_recovery_bill.hub_balance_zhu += 1;
        let snapshot = unfunded_snapshot(&bundle.binding);
        assert!(
            authorize_registry_funding(&bundle, left.readable(), &evidence(&snapshot)).is_err()
        );
    }
}
