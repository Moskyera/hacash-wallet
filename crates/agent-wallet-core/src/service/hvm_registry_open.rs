//! Opening a shared HPAY HVM registry V2 channel, from the wallet's side.
//!
//! # The gap this closes
//!
//! The user-side unilateral exit works end to end through the production call
//! chain, and until this existed it could not help a single person, because no
//! Agent Wallet in this app could hold a provider channel at all. Adoption
//! (`super::hvm_registry::AgentWalletManager::verify_and_bind_hvm_registry`)
//! only accepts a bundle whose serial-1 refund bill carries this wallet's own
//! left signature; that signature can only be made at channel open; and
//! nothing in `agent-wallet-core` made one. The wallet's key never leaves its
//! vault, so the operator CLI that does build the open could not be handed one
//! either.
//!
//! # The order, which is the whole point
//!
//! 1. The wallet derives the binding and **left-signs** the serial-1 full
//!    refund through the signing boundary
//!    (`crate::signer::AgentTransactionSigner::sign_exact_registry_channel_open`).
//!    The ask is persisted through the journalled transition. Nothing has been
//!    funded.
//! 2. The Hub is asked for 97 bytes. It gets no field through which to propose
//!    a different channel.
//! 3. The wallet **validates the answer itself** against the binding it
//!    derived, and only then persists the countersigned bundle - again through
//!    the journalled transition.
//! 4. Only now is funding authorised, and only by re-deriving
//!    [`hacash_wallet_core::hvm_registry_open::HvmRegistryFundingAuthorizationV1`]
//!    from that stored bundle.
//!
//! A crash anywhere in that sequence is safe in the same direction. Between 1
//! and 2 the wallet holds a worthless half-bill and no money has moved; it
//! asks again. Between 3 and 4 the wallet holds a complete, valid, reusable
//! refund and still no money has moved; funding can be built at any later
//! time, because the bill carries no expiry. What cannot happen is the reverse
//! order, and that is enforced by the fact that the funding authorization has
//! exactly one constructor and it takes a verified bundle.
//!
//! # A Hub that will not countersign
//!
//! No channel opens. That is the whole consequence. This exchange happens
//! strictly before any funding transaction is built, so there is nothing
//! half-funded to unwind, and the owner is told so in those words by
//! [`crate::error::AgentWalletError::RegistryOpenHubRefused`].

use hacash_wallet_core::hvm_registry_open::validate_stored_refund;
use hacash_wallet_core::settings::validate_service_url;
use l2_fast_pay_hub::hvm_registry::{
    HvmRegistryRecoveryBundleV2, HvmRegistryRefundCountersignRequestV2,
};
use l2_fast_pay_hub::rollback_anchor::SignedHubWitnessReceiptV1;
use serde::{Deserialize, Serialize};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::types::AgentWalletId;

#[cfg(feature = "agent-wallet-testnet-pilot")]
use super::AgentWalletManager;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::hvm_registry_exit_driver::HvmRegistryExitSightingV1;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::hvm_registry_open::{
    HvmRegistryFundingAuthorizationV1, HvmRegistryOpenChainEvidenceV1, HvmRegistryOpenChainV1,
    adopt_hub_countersignature, authorize_registry_funding, require_openable_binding,
};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::l2_hub::L2HubClient;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryRefundCountersignResponseV2;

const AGENT_HVM_REGISTRY_OPEN_SCHEMA: u32 = 1;

/// The network fee this wallet pays to put its own deposit into a channel.
///
/// Deliberately the same number the exit pays for one of its steps. Funding is
/// a Type 3 transaction of the same shape and roughly the same size as the
/// calls the exit makes, and inventing a second fee constant would mean two
/// places to be wrong about the same chain.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const AGENT_REGISTRY_FUNDING_NETWORK_FEE_ZHU: u64 =
    super::hvm_registry::AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU;

/// Same reasoning, same constant.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const AGENT_REGISTRY_FUNDING_GAS_MAX: u8 = super::hvm_registry::AGENT_REGISTRY_EXIT_GAS_MAX;

/// One in-progress or completed registry channel open, as durable
/// authenticated wallet state.
///
/// There is at most one. A wallet opens one shared registry channel, and a
/// second ask started while a countersigned refund is held would be a way to
/// discard the only bill that gets the first channel's deposit back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryChannelOpen {
    schema_version: u32,
    wallet_id: AgentWalletId,
    hub_url: String,
    binding_commitment: String,
    request: HvmRegistryRefundCountersignRequestV2,
    requested_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    countersigned: Option<AgentHvmRegistryCountersignedRefund>,
    /// What this wallet knows about its own deposit having left.
    ///
    /// A reviewer drove the gap this closes: before it existed, a wallet that
    /// died between broadcasting the funding transaction and adopting the
    /// channel came back unable to tell a channel it had merely *authorised*
    /// from one it had already paid into. The exit had per-step durability
    /// from the first day and this had none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    funded: Option<AgentHvmRegistryFunding>,
}

/// The deposit transfer, made durable **before** it is handed to a node.
///
/// The bytes are kept verbatim rather than rebuilt on a retry: a second
/// signature over the same intent at a different timestamp is a second
/// transaction, and two funding transfers into one channel is the one mistake
/// this record exists to make impossible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryFunding {
    transaction_hash: String,
    signed_transaction_hex: String,
    contract_address: String,
    amount_zhu: u64,
    network_fee_zhu: u64,
    signed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmed_block_height: Option<u64>,
}

impl AgentHvmRegistryFunding {
    pub fn transaction_hash(&self) -> &str {
        &self.transaction_hash
    }

    pub fn contract_address(&self) -> &str {
        &self.contract_address
    }

    pub const fn amount_zhu(&self) -> u64 {
        self.amount_zhu
    }

    pub const fn network_fee_zhu(&self) -> u64 {
        self.network_fee_zhu
    }

    pub const fn signed_at(&self) -> u64 {
        self.signed_at
    }

    /// `true` once this wallet has seen its own funding in a block.
    pub const fn is_confirmed(&self) -> bool {
        self.confirmed_block_height.is_some()
    }

    pub const fn confirmed_block_height(&self) -> Option<u64> {
        self.confirmed_block_height
    }

    pub const fn confirmed_at(&self) -> Option<u64> {
        self.confirmed_at
    }
}

/// The Hub's half, after this wallet checked it.
///
/// The receipts ride along verbatim rather than being summarised or dropped.
/// This is the most important bill in the channel's life, and which witnesses
/// were covering the Hub when it was signed is exactly the thing a Hub must
/// not be able to restate later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryCountersignedRefund {
    bundle: HvmRegistryRecoveryBundleV2,
    #[serde(default)]
    anchor_receipts: Vec<SignedHubWitnessReceiptV1>,
    countersigned_at: u64,
}

impl AgentHvmRegistryCountersignedRefund {
    pub fn bundle(&self) -> &HvmRegistryRecoveryBundleV2 {
        &self.bundle
    }

    pub fn anchor_receipts(&self) -> &[SignedHubWitnessReceiptV1] {
        &self.anchor_receipts
    }

    pub const fn countersigned_at(&self) -> u64 {
        self.countersigned_at
    }
}

impl AgentHvmRegistryChannelOpen {
    pub fn hub_url(&self) -> &str {
        &self.hub_url
    }

    pub fn binding_commitment(&self) -> &str {
        &self.binding_commitment
    }

    pub fn request(&self) -> &HvmRegistryRefundCountersignRequestV2 {
        &self.request
    }

    pub const fn requested_at(&self) -> u64 {
        self.requested_at
    }

    pub fn countersigned(&self) -> Option<&AgentHvmRegistryCountersignedRefund> {
        self.countersigned.as_ref()
    }

    /// The bundle this wallet validated, or `None`.
    ///
    /// The one accessor adoption and funding both go through, so there is a
    /// single place that answers "has the provider guaranteed this user a way
    /// out yet".
    pub fn countersigned_bundle(&self) -> Option<&HvmRegistryRecoveryBundleV2> {
        self.countersigned.as_ref().map(|held| &held.bundle)
    }

    /// What this wallet knows about its own deposit having left, or `None`.
    pub fn funding(&self) -> Option<&AgentHvmRegistryFunding> {
        self.funded.as_ref()
    }

    /// Re-verify this record against the wallet it claims to belong to, on
    /// every state load.
    ///
    /// Deliberately time-free. A stored ask whose five-minute Hub window has
    /// long passed is still the ask a countersigned refund was built from, and
    /// a wallet that refused to load its own state because a clock moved would
    /// be refusing to load the user's route out of a funded channel.
    pub(crate) fn validate(
        &self,
        expected_wallet_id: &AgentWalletId,
        expected_address: &str,
        expected_network_mode: &str,
    ) -> AgentWalletResult<()> {
        if self.schema_version != AGENT_HVM_REGISTRY_OPEN_SCHEMA
            || &self.wallet_id != expected_wallet_id
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let canonical_hub_url = validate_service_url(&self.hub_url, "Agent HVM registry hub")
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if canonical_hub_url != self.hub_url {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.request
            .validate_shape()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let binding = &self.request.binding;
        if binding.left_address != expected_address
            || binding.network_mode != expected_network_mode
            || binding.right_hub_address == expected_address
            || binding
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?
                != self.binding_commitment
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Some(held) = self.countersigned.as_ref() {
            if held.bundle.binding != *binding {
                return Err(AgentWalletError::RecoveryRequired);
            }
            // The stored bundle is held to every standard the funding gate
            // applies that can be applied without a network. The gate itself
            // additionally requires a live reading of this wallet's own
            // fullnode, which a state load has no business demanding: a wallet
            // that refused to open because a node was unreachable would be
            // refusing to load the user's own route out of a funded channel.
            // So the offline half is applied here, in full, and the chain half
            // is applied where the money moves.
            validate_stored_refund(&held.bundle, expected_address)
                .map_err(|_| AgentWalletError::RecoveryRequired)?;
        }
        if let Some(funding) = self.funded.as_ref() {
            let held = self
                .countersigned
                .as_ref()
                .ok_or(AgentWalletError::RecoveryRequired)?;
            if funding.contract_address != binding.contract_address
                || funding.amount_zhu != binding.left_deposit_zhu
                || funding.signed_at == 0
                || funding.network_fee_zhu == 0
                || !is_lower_hex_hash(&funding.transaction_hash)
                || funding.confirmed_at.is_some() != funding.confirmed_block_height.is_some()
            {
                return Err(AgentWalletError::RecoveryRequired);
            }
            // Funding bytes are re-read against the binding they claim to
            // fund, by the reader that shares no line with the builder. A
            // record that no longer describes the deposit it says it made is
            // not a record of anything.
            l2_fast_pay_hub::hvm_registry_watchtower::read_exact_registry_funding_transaction(
                &funding.signed_transaction_hex,
                &held.bundle.binding,
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        }
        Ok(())
    }
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl AgentWalletManager {
    /// Open a registry channel with this Hub: left-sign the refund, get it
    /// countersigned, validate it, and store it. Funds nothing.
    ///
    /// The caller supplies the binding it wants, and the binding is the
    /// wallet's own statement of the channel - contract, channel id, reuse
    /// version, deposit, objection window. The Hub never gets to restate any
    /// of it; see `hacash_wallet_core::hvm_registry_open`.
    pub async fn open_hvm_registry_channel<C>(
        &mut self,
        wallet_id: &AgentWalletId,
        hub_url: &str,
        binding: HvmRegistryBindingV2,
        chain: &C,
        now: u64,
    ) -> AgentWalletResult<HvmRegistryRecoveryBundleV2>
    where
        C: HvmRegistryOpenChainV1,
    {
        self.ensure_session_active(wallet_id, now)?;
        let hub_url = validate_service_url(hub_url, "Agent HVM registry hub")
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        let hub = L2HubClient::new_for_wallet_policy(hub_url.clone(), "testnet", false);

        // Ask the Hub who it is before signing anything. A refund bill is only
        // worth what the key that countersigns it is, so a Hub whose published
        // identity is not the one this binding names is not the party this
        // wallet is trying to open with, and no signature should be spent
        // finding that out later.
        let health = hub
            .health()
            .await
            .map_err(|_| AgentWalletError::RegistryOpenHubRefused)?;
        if !health.ok
            || health.version < 7
            || health.hub_address.as_deref() != Some(binding.right_hub_address.as_str())
        {
            return Err(AgentWalletError::RegistryOpenHubRefused);
        }

        let ask = self
            .begin_hvm_registry_channel_open(wallet_id, &hub_url, binding, chain, now)
            .await?;
        hacash_wallet_core::hvm_registry_open::require_askable(&ask, now)
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        let answer = hub
            .countersign_hvm_registry_channel_open(&ask)
            .await
            .map_err(|_| AgentWalletError::RegistryOpenHubRefused)?;
        self.record_hvm_registry_channel_countersignature(wallet_id, &answer, now)
    }

    /// Step one: left-sign the serial-1 full refund and make the ask durable.
    ///
    /// # Repeats
    ///
    /// Asking again for the exact same channel returns the ask already stored
    /// rather than minting a second one, so a retry cannot leave two
    /// left-signed serial-1 bills in the world.
    ///
    /// Asking for a *different* channel is allowed only while nothing has been
    /// countersigned. Once a countersigned refund is held, this wallet may
    /// already have funded that channel, and quietly replacing the record
    /// would throw away the only bill that gets the deposit back.
    pub async fn begin_hvm_registry_channel_open<C>(
        &mut self,
        wallet_id: &AgentWalletId,
        hub_url: &str,
        binding: HvmRegistryBindingV2,
        chain: &C,
        now: u64,
    ) -> AgentWalletResult<HvmRegistryRefundCountersignRequestV2>
    where
        C: HvmRegistryOpenChainV1,
    {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let hub_url = validate_service_url(hub_url, "Agent HVM registry hub")
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if state.network_mode != "testnet"
            || state.hvm_channel_binding.is_some()
            || state.hvm_registry_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        if let Some(existing) = state.hvm_registry_open.as_ref() {
            if existing.request.binding == binding && existing.hub_url == hub_url {
                return Ok(existing.request.clone());
            }
            if existing.countersigned.is_some() {
                return Err(AgentWalletError::SigningBlocked);
            }
        }

        // THE CHAIN, BEFORE THE SIGNATURE.
        //
        // Every field of a binding is a claim, and a wallet that left-signs
        // one it has not checked ends up holding a countersigned refund that
        // it can truthfully call a provider guarantee and that refers to
        // something which is not the registry. Signing costs nothing; the
        // damage is done by what the owner then believes. So this runs first,
        // and it runs here rather than only in the caller, because a gate on
        // one of two doors is this project's own recurring defect.
        let chain_evidence = self
            .registry_open_chain_evidence(&state, &binding, chain)
            .await?;
        require_openable_binding(&binding, &state.address, &chain_evidence.evidence())
            .map_err(|_| AgentWalletError::RegistryOpenChainMismatch)?;

        // Reloaded, because the check above awaited on a network and this
        // wallet's own state may have moved underneath it.
        let mut state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if state.network_mode != "testnet"
            || state.hvm_channel_binding.is_some()
            || state.hvm_registry_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        if let Some(existing) = state.hvm_registry_open.as_ref() {
            if existing.request.binding == binding && existing.hub_url == hub_url {
                return Ok(existing.request.clone());
            }
            if existing.countersigned.is_some() {
                return Err(AgentWalletError::SigningBlocked);
            }
        }

        // Same interlock as every other signing path here, and `false` for the
        // same reason the exit passes `false`: a wallet is required to have
        // agent payments suspended at the moment it adopts a registry channel,
        // so reading the suspension flag here would make opening one
        // impossible.
        let permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(false)?;
        permit.checkpoint(false)?;

        let ask = {
            let session = self.session(wallet_id)?;
            session.signer.sign_exact_registry_channel_open(
                crate::signer::AgentRegistryChannelOpenSigningRequest {
                    wallet_scope: session.signer.wallet_scope(),
                    network_mode: &state.network_mode,
                    signer_epoch: state.signer_epoch,
                    binding: &binding,
                },
                &permit,
                now,
            )?
        };
        let record = AgentHvmRegistryChannelOpen {
            schema_version: AGENT_HVM_REGISTRY_OPEN_SCHEMA,
            wallet_id: wallet_id.clone(),
            hub_url,
            binding_commitment: binding
                .commitment()
                .map_err(|_| AgentWalletError::SigningBlocked)?,
            request: ask.clone(),
            requested_at: now,
            countersigned: None,
            funded: None,
        };
        record.validate(wallet_id, &state.address, &state.network_mode)?;
        state.hvm_registry_open = Some(record);
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::HvmRegistryChannelOpenRequested,
            None,
            None,
            now,
        )?;
        permit.checkpoint(false)?;
        Ok(ask)
    }

    /// Step two: judge the Hub's answer against the wallet's own binding, and
    /// make the whole refund durable before anything is funded.
    ///
    /// Nothing here trusts the response. The signature is verified against
    /// `binding.right_hub_address` from the ask this wallet stored, and every
    /// balance and identifier is compared with what this wallet signed. A
    /// worthless answer - wrong channel, wrong amount, wrong reuse version, a
    /// well-formed signature from some other key - is refused here and no
    /// channel opens.
    pub fn record_hvm_registry_channel_countersignature(
        &mut self,
        wallet_id: &AgentWalletId,
        response: &HvmRegistryRefundCountersignResponseV2,
        now: u64,
    ) -> AgentWalletResult<HvmRegistryRecoveryBundleV2> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let mut state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let address = state.address.clone();
        let network_mode = state.network_mode.clone();
        let open = state
            .hvm_registry_open
            .as_ref()
            .ok_or(AgentWalletError::OperationNotFound)?;
        let bundle = adopt_hub_countersignature(&open.request, response, &address)
            .map_err(|_| AgentWalletError::RegistryOpenHubRefused)?;
        if let Some(held) = open.countersigned.as_ref() {
            // A refund is already held for this ask, and the answer just
            // received has already been through `adopt_hub_countersignature`,
            // which pins the binding, the serial, both balances, this wallet's
            // own left signature and the commitment. The only field that can
            // still differ is the Hub's 97 bytes.
            //
            // That difference is not evidence of a lie. secp256k1 signatures
            // are malleable - `(r, s)` and `(r, n - s)` both verify - so a
            // provider answering the same ask twice may legitimately, or
            // deliberately, return the other valid signature. A reviewer found
            // that this wallet answered that by telling its owner it needed a
            // manual recovery, which a provider could therefore trigger at
            // will on a perfectly healthy wallet.
            //
            // Both signatures are a full refund of the same deposit on the same
            // channel, so the one already stored is kept and returned. Nothing
            // is weakened: the second answer had to pass every check the first
            // one did in order to reach this line, and the stored bundle is the
            // one the funding gate and the exit head are built from.
            return Ok(held.bundle.clone());
        }

        let mut record = open.clone();
        record.countersigned = Some(AgentHvmRegistryCountersignedRefund {
            bundle: bundle.clone(),
            anchor_receipts: response.anchor_receipts.clone(),
            countersigned_at: now,
        });
        record.validate(wallet_id, &address, &network_mode)?;
        state.hvm_registry_open = Some(record);
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::HvmRegistryChannelOpenCountersigned,
            None,
            None,
            now,
        )?;
        Ok(bundle)
    }

    /// What this wallet's durable record says about an open, without touching
    /// a Hub, a chain or a key.
    pub fn hvm_registry_channel_open(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Option<AgentHvmRegistryChannelOpen>> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        Ok(state.hvm_registry_open)
    }

    /// **The funding gate.** The only way, anywhere in this crate, to obtain
    /// permission to put this wallet's money into a registry channel.
    ///
    /// It re-derives the authorization from the stored bundle every time
    /// rather than reading a stored flag, so a record that was tampered with,
    /// restored from another wallet, or written by a future bug does not
    /// authorise anything: it has to pass
    /// `hacash_wallet_core::hvm_registry_open::authorize_registry_funding`,
    /// whose first statement is `bundle.validate_crypto()`.
    ///
    /// The refusal is not advice. There is no second entry point, and
    /// `HvmRegistryFundingAuthorizationV1` has private fields, no
    /// `Deserialize` and no other constructor, so a caller cannot obtain one
    /// by any route that skips this function.
    /// **The funding gate.** The only way, anywhere in this crate, to obtain
    /// permission to put this wallet's money into a registry channel.
    ///
    /// It re-derives the authorization every time rather than reading a stored
    /// flag, and it re-derives it from two things that must both hold: the
    /// stored countersigned bundle, and a live reading of **this wallet's own
    /// pinned fullnode**.
    ///
    /// # Why the chain half had to move in front of this
    ///
    /// Every field of a binding is a claim. `binding.validate()` checks that
    /// the *claimed* bytecode digest equals the reviewed constant; it has no
    /// chain and so cannot check the code actually deployed at
    /// `contract_address`. A provider - or a poisoned blob of pasted JSON -
    /// could name a contract of its own, have an entirely honest Hub
    /// countersign a sincere full refund for it, and take the deposit. Every
    /// check that would have caught that existed, and all of them lived in
    /// adoption, on the far side of the spend. They are here now.
    ///
    /// The refusal is not advice. There is no second entry point, and
    /// `HvmRegistryFundingAuthorizationV1` has private fields, no
    /// `Deserialize` and no other constructor, so a caller cannot obtain one
    /// by any route that skips this function.
    pub async fn hvm_registry_funding_authorization<C>(
        &mut self,
        wallet_id: &AgentWalletId,
        chain: &C,
        now: u64,
    ) -> AgentWalletResult<HvmRegistryFundingAuthorizationV1>
    where
        C: HvmRegistryOpenChainV1,
    {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let bundle = state
            .hvm_registry_open
            .as_ref()
            .and_then(AgentHvmRegistryChannelOpen::countersigned_bundle)
            .cloned()
            .ok_or(AgentWalletError::RegistryOpenRefundNotCountersigned)?;
        let reading = self
            .registry_open_chain_evidence(&state, &bundle.binding, chain)
            .await?;
        authorize_registry_funding(&bundle, &state.address, &reading.evidence())
            .map_err(|_| AgentWalletError::RegistryOpenChainMismatch)
    }

    /// Read this wallet's own pinned chain, and refuse a view that is not it.
    ///
    /// The node identity is not taken on the chain view's word either: it is
    /// compared with the block-1 fingerprint and network mode this wallet
    /// recorded when it was created, so a chain implementation pointed
    /// somewhere else cannot supply evidence about somewhere else.
    pub(super) async fn registry_open_chain_evidence<C>(
        &self,
        state: &super::AgentWalletState,
        binding: &HvmRegistryBindingV2,
        chain: &C,
    ) -> AgentWalletResult<AgentRegistryOpenChainReading>
    where
        C: HvmRegistryOpenChainV1,
    {
        let network_binding = chain
            .network_binding()
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        network_binding
            .validate()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if network_binding.mainnet != (state.network_mode == "mainnet")
            || network_binding.block_1_hash != state.block_one_fingerprint
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let snapshot = chain
            .registry_snapshot(binding)
            .await
            .map_err(|_| AgentWalletError::RegistryOpenChainMismatch)?;
        Ok(AgentRegistryOpenChainReading {
            snapshot,
            network_mode: state.network_mode.clone(),
            node_chain_id: network_binding.chain_id,
            node_network_instance_id: network_binding.network_instance_id.clone(),
            network_binding,
            // Every one of the eighteen storage keys must be active and hold
            // live credit. Deliberately not the *exit* floor: a channel that
            // has taken no coin has bought no rent yet, the driver's own
            // planner answers a short lease by renewing before it will start
            // an exit, and a floor applied here that only funding can satisfy
            // would refuse every honest open. This is the check that did not
            // exist at all before; the exit floor is where it always was.
            minimum_live_blocks: 1,
        })
    }

    /// Put the deposit into the channel, and make the bytes durable before a
    /// node ever sees them.
    ///
    /// # The order, which is the whole point
    ///
    /// 1. The gate above runs. No permission, no bytes: the value it produces
    ///    cannot be defaulted, parsed or restored, and this is its only
    ///    consumer that spends anything.
    /// 2. The transfer is signed through the signing boundary
    ///    [`crate::signer::AgentTransactionSigner::sign_exact_registry_funding`],
    ///    which takes the permission rather than an address and an amount.
    /// 3. The exact bytes are written into authenticated wallet state through
    ///    the journalled transition **before** they are handed to the node.
    /// 4. Only then are they submitted.
    ///
    /// A crash between 3 and 4 leaves a wallet that knows money may already be
    /// on its way, and pressing again re-submits the same bytes rather than
    /// signing a second transfer. A crash between 2 and 3 cannot lose money,
    /// because nothing was submitted. Before this record existed a reopened
    /// wallet could not tell a channel it had merely authorised from one it
    /// had already paid into, and the exit had per-step durability from its
    /// first day while this had none.
    pub async fn fund_hvm_registry_channel<C>(
        &mut self,
        wallet_id: &AgentWalletId,
        chain: &C,
        now: u64,
    ) -> AgentWalletResult<AgentHvmRegistryFunding>
    where
        C: HvmRegistryOpenChainV1,
    {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let state = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let open = state
            .hvm_registry_open
            .clone()
            .ok_or(AgentWalletError::RegistryOpenRefundNotCountersigned)?;
        let bundle = open
            .countersigned_bundle()
            .cloned()
            .ok_or(AgentWalletError::RegistryOpenRefundNotCountersigned)?;

        // Already signed once. Never sign a second transfer into one channel:
        // hand the same bytes over again and ask the chain what became of
        // them.
        if let Some(existing) = open.funding().cloned() {
            return self
                .confirm_hvm_registry_funding(wallet_id, &bundle.binding, existing, chain, now)
                .await;
        }

        let reading = self
            .registry_open_chain_evidence(&state, &bundle.binding, chain)
            .await?;
        let authorization =
            authorize_registry_funding(&bundle, &state.address, &reading.evidence())
                .map_err(|_| AgentWalletError::RegistryOpenChainMismatch)?;

        let permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(false)?;
        permit.checkpoint(false)?;

        let signed = {
            let session = self.session(wallet_id)?;
            session.signer.sign_exact_registry_funding(
                crate::signer::AgentRegistryFundingSigningRequest {
                    wallet_scope: session.signer.wallet_scope(),
                    network_mode: &state.network_mode,
                    signer_epoch: state.signer_epoch,
                    authorization: &authorization,
                    bundle: &bundle,
                    network_fee_zhu: AGENT_REGISTRY_FUNDING_NETWORK_FEE_ZHU,
                    timestamp: now,
                    gas_max: AGENT_REGISTRY_FUNDING_GAS_MAX,
                },
                &permit,
                now,
            )?
        };

        // Durable before the wire. No await between here and the write.
        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.address != state.address
            || current.network_mode != state.network_mode
            || current.signer_epoch != state.signer_epoch
            || current.node_url != state.node_url
            || current.block_one_fingerprint != state.block_one_fingerprint
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let mut record = current
            .hvm_registry_open
            .clone()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if record.countersigned_bundle() != Some(&bundle) {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if let Some(existing) = record.funding().cloned() {
            // Somebody else got there between the gate and here. Their bytes
            // win; ours are dropped unsubmitted.
            return self
                .confirm_hvm_registry_funding(wallet_id, &bundle.binding, existing, chain, now)
                .await;
        }
        let funding = AgentHvmRegistryFunding {
            transaction_hash: signed.transaction_hash.clone(),
            signed_transaction_hex: signed.signed_transaction_hex.clone(),
            contract_address: signed.contract_address.clone(),
            amount_zhu: signed.amount_zhu,
            network_fee_zhu: AGENT_REGISTRY_FUNDING_NETWORK_FEE_ZHU,
            signed_at: now,
            confirmed_at: None,
            confirmed_block_height: None,
        };
        record.funded = Some(funding.clone());
        record.validate(wallet_id, &current.address, &current.network_mode)?;
        current.hvm_registry_open = Some(record);
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::HvmRegistryChannelFundingSigned,
            None,
            None,
            now,
        )?;
        permit.checkpoint(false)?;

        self.confirm_hvm_registry_funding(wallet_id, &bundle.binding, funding, chain, now)
            .await
    }

    /// Submit the stored bytes if the node has not got them, and record a
    /// confirmation only when the node names the block.
    ///
    /// Idempotent in both directions: a duplicate submission is success, and a
    /// confirmation already written is returned unchanged rather than
    /// re-written at a new time.
    async fn confirm_hvm_registry_funding<C>(
        &mut self,
        wallet_id: &AgentWalletId,
        binding: &HvmRegistryBindingV2,
        funding: AgentHvmRegistryFunding,
        chain: &C,
        now: u64,
    ) -> AgentWalletResult<AgentHvmRegistryFunding>
    where
        C: HvmRegistryOpenChainV1,
    {
        if funding.is_confirmed() {
            return Ok(funding);
        }
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let sighting = match chain.funding_sighting(&funding.transaction_hash).await {
            Ok(sighting) => sighting,
            Err(_) => return Err(AgentWalletError::RegistryFundingNotConfirmed),
        };
        let sighting = match sighting {
            HvmRegistryExitSightingV1::Unknown => {
                chain
                    .submit_funding_transaction(
                        binding,
                        &funding.signed_transaction_hex,
                        &funding.transaction_hash,
                    )
                    .await
                    .map_err(|_| AgentWalletError::NodeRejected)?;
                chain
                    .funding_sighting(&funding.transaction_hash)
                    .await
                    .map_err(|_| AgentWalletError::RegistryFundingNotConfirmed)?
            }
            other => other,
        };
        let block_height = match sighting {
            HvmRegistryExitSightingV1::Mined { block_height, .. } => block_height,
            _ => return Err(AgentWalletError::RegistryFundingNotConfirmed),
        };

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        let mut record = current
            .hvm_registry_open
            .clone()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        let mut held = record
            .funding()
            .cloned()
            .ok_or(AgentWalletError::RecoveryRequired)?;
        if held.transaction_hash != funding.transaction_hash {
            return Err(AgentWalletError::RecoveryRequired);
        }
        if held.is_confirmed() {
            return Ok(held);
        }
        held.confirmed_at = Some(now);
        held.confirmed_block_height = Some(block_height);
        record.funded = Some(held.clone());
        record.validate(wallet_id, &current.address, &current.network_mode)?;
        current.hvm_registry_open = Some(record);
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::HvmRegistryChannelFunded,
            None,
            None,
            now,
        )?;
        Ok(held)
    }
}

/// One live reading of the wallet's own pinned chain, owned so the borrowed
/// evidence handed to the gate cannot outlive it.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub(crate) struct AgentRegistryOpenChainReading {
    pub(crate) snapshot: l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
    pub(crate) network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
    network_mode: String,
    node_chain_id: u32,
    node_network_instance_id: String,
    minimum_live_blocks: u64,
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl AgentRegistryOpenChainReading {
    pub(crate) fn evidence(&self) -> HvmRegistryOpenChainEvidenceV1<'_> {
        HvmRegistryOpenChainEvidenceV1 {
            snapshot: &self.snapshot,
            node_chain_id: self.node_chain_id,
            node_network_instance_id: &self.node_network_instance_id,
            node_network_mode: &self.network_mode,
            minimum_required_live_blocks: self.minimum_live_blocks,
            // A channel that has taken no coin has bought no recovery credit
            // yet, so demanding any here would refuse every honest open. The
            // live floor above is the one that matters before funding, and the
            // recovery floor is enforced from adoption onwards.
            minimum_required_recover_blocks: 0,
        }
    }
}
