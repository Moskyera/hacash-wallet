//! Authenticated Agent-only binding to one shared HPAY HVM registry V2 slot.
//!
//! This is deliberately separate from the per-channel HVM V1 binding. The
//! owner adopts one exact registry/channel incarnation from authenticated Hub
//! evidence and a fresh pinned-node proof. Adoption alone grants no signing
//! authority; payment execution has its own durable reviewed state machine.

#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::l2_hub::{L2HubClient, hub_fee_is_zero};
use hacash_wallet_core::settings::validate_service_url;
use l2_fast_pay_hub::hvm_registry::{HvmRegistryBillV2, HvmRegistryRecoveryBundleV2};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use l2_fast_pay_hub::hvm_registry_ledger::{
    HVM_REGISTRY_CHANNEL_STATUS_SCHEMA, HvmRegistryChannelStatusV2,
};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use serde::{Deserialize, Serialize};

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::types::AgentWalletId;

#[cfg(feature = "agent-wallet-testnet-pilot")]
use super::AgentWalletManager;

const AGENT_HVM_REGISTRY_BINDING_SCHEMA: u32 = 2;
// The head is a *serialised* field of wallet state, so the type and its schema
// tag must exist in every build - a build that dropped them would silently
// discard a user's exit evidence on the next save. Only the code that reads and
// advances it is pilot-gated, which is what makes these look unused without the
// feature.
#[cfg_attr(not(feature = "agent-wallet-testnet-pilot"), allow(dead_code))]
const AGENT_HVM_REGISTRY_EXIT_HEAD_SCHEMA: u32 = 1;

/// The newest fully-signed registry bill this wallet has ever held, kept as an
/// explicit monotone field of authenticated wallet state.
///
/// # Why this exists as its own field
///
/// The binding is already durable here. The evidence built *from* the binding
/// was not: the only durable home of a fully-signed registry bill was inside
/// an `AgentHvmPaymentOperation`, one record per payment, and finding the
/// newest one meant scanning that map. That makes a user's only route to their
/// own money depend on the operation map staying complete and on a pruning
/// predicate staying the way it is today. A wallet restored from a trimmed
/// backup would still hold a valid binding and would no longer hold the bill
/// that binding is worthless without.
///
/// So the head is one field, advanced in the same journalled transition that
/// commits the bill, and never accepting a lower serial than the one it
/// already carries. An out-of-order or replayed commit cannot walk it
/// backwards, which matters because on this rail an older bill always pays the
/// user *more* and the Hub *less* — presenting one is not an accident that
/// costs the user money, it is an accident that looks like the user attacking
/// the Hub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryExitHead {
    schema_version: u32,
    binding_commitment: String,
    bill: HvmRegistryBillV2,
    accepted_at: u64,
}

#[cfg_attr(not(feature = "agent-wallet-testnet-pilot"), allow(dead_code))]
impl AgentHvmRegistryExitHead {
    /// Seed the head at adoption from the binding's own initial recovery bill.
    ///
    /// The serial-1 full-refund bill is the weakest evidence the user will
    /// ever hold and the one they are guaranteed to hold: it is the bill the
    /// recovery bundle is validated against, so if the binding is adoptable
    /// this bill exists and is fully signed. Seeding with it means the exit
    /// head is never empty from the first moment a channel is bound, and the
    /// worst case of losing every later bill is an exit that refunds the whole
    /// deposit rather than an exit that cannot start.
    pub(crate) fn seed(binding: &AgentHvmRegistryBinding, now: u64) -> Self {
        Self {
            schema_version: AGENT_HVM_REGISTRY_EXIT_HEAD_SCHEMA,
            binding_commitment: binding.binding_commitment.clone(),
            bill: binding.recovery_bundle.initial_recovery_bill.clone(),
            accepted_at: now,
        }
    }

    pub fn bill(&self) -> &HvmRegistryBillV2 {
        &self.bill
    }

    pub fn binding_commitment(&self) -> &str {
        &self.binding_commitment
    }

    pub const fn accepted_at(&self) -> u64 {
        self.accepted_at
    }

    /// Accept a newer fully-signed bill, or refuse.
    ///
    /// Returns `true` when the head moved. A bill at the serial already held
    /// is accepted only if it is byte-identical, so a second bill minted at
    /// one serial is a `RecoveryRequired`, not a silent overwrite.
    pub(crate) fn advance(
        &mut self,
        binding: &AgentHvmRegistryBinding,
        bill: &HvmRegistryBillV2,
        now: u64,
    ) -> AgentWalletResult<bool> {
        if self.schema_version != AGENT_HVM_REGISTRY_EXIT_HEAD_SCHEMA
            || self.binding_commitment != binding.binding_commitment
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        bill.validate_fully_signed(&binding.recovery_bundle.binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if bill.serial < self.bill.serial {
            return Ok(false);
        }
        if bill.serial == self.bill.serial {
            return if bill == &self.bill {
                Ok(false)
            } else {
                Err(AgentWalletError::RecoveryRequired)
            };
        }
        self.bill = bill.clone();
        self.accepted_at = now;
        Ok(true)
    }

    /// Re-verify the head against the binding it claims to belong to.
    pub(crate) fn validate(&self, binding: &AgentHvmRegistryBinding) -> AgentWalletResult<()> {
        if self.schema_version != AGENT_HVM_REGISTRY_EXIT_HEAD_SCHEMA
            || self.binding_commitment() != binding.binding_commitment()
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        self.bill
            .validate_fully_signed(&binding.recovery_bundle.binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if self.bill.serial < binding.recovery_bundle.initial_recovery_bill.serial {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(())
    }

    /// Build the exportable exit kit: the binding plus this head.
    ///
    /// The kit carries no private key. Every registry entry point takes the
    /// left address as a parameter and checks the bill's own two signatures
    /// rather than the transaction signer, so a holder can finish this exit in
    /// the user's favour and cannot redirect a single zhu of it.
    pub fn exit_kit(
        &self,
        binding: &AgentHvmRegistryBinding,
    ) -> AgentWalletResult<hacash_wallet_core::hvm_registry_exit::HvmRegistryExitKitV1> {
        self.validate(binding)?;
        hacash_wallet_core::hvm_registry_exit::build_exit_kit(
            binding.recovery_bundle.binding.clone(),
            self.bill.clone(),
        )
        .map_err(|_| AgentWalletError::RecoveryRequired)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryBinding {
    schema_version: u32,
    wallet_id: AgentWalletId,
    network_mode: String,
    network_binding: L1ChannelNetworkBinding,
    hub_url: String,
    hub_address: String,
    binding_commitment: String,
    recovery_bundle: HvmRegistryRecoveryBundleV2,
    activation_snapshot_commitment: String,
    minimum_required_live_blocks: u64,
    minimum_required_recover_blocks: u64,
    adopted_at: u64,
}

impl AgentHvmRegistryBinding {
    pub(crate) fn wallet_id(&self) -> &AgentWalletId {
        &self.wallet_id
    }

    pub fn hub_url(&self) -> &str {
        &self.hub_url
    }

    pub fn hub_address(&self) -> &str {
        &self.hub_address
    }

    pub fn binding_commitment(&self) -> &str {
        &self.binding_commitment
    }

    pub fn recovery_bundle(&self) -> &HvmRegistryRecoveryBundleV2 {
        &self.recovery_bundle
    }

    pub fn network_binding(&self) -> &L1ChannelNetworkBinding {
        &self.network_binding
    }

    pub const fn minimum_required_live_blocks(&self) -> u64 {
        self.minimum_required_live_blocks
    }

    pub const fn operational_recover_blocks(&self) -> u64 {
        if self.minimum_required_recover_blocks == 0 {
            1
        } else {
            self.minimum_required_recover_blocks
        }
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(super) fn matches_status(&self, status: &HvmRegistryChannelStatusV2) -> bool {
        status.schema == HVM_REGISTRY_CHANNEL_STATUS_SCHEMA
            && status.binding_commitment == self.binding_commitment
            && status.recovery_bundle == self.recovery_bundle
            && status.activation_snapshot_commitment == self.activation_snapshot_commitment
            && status.minimum_required_live_blocks == self.minimum_required_live_blocks
            && status.minimum_required_recover_blocks == self.minimum_required_recover_blocks
            && status
                .latest_fully_signed_bill
                .validate_fully_signed(&self.recovery_bundle.binding)
                .is_ok()
    }

    pub(crate) fn validate(
        &self,
        expected_wallet_id: &AgentWalletId,
        expected_address: &str,
        expected_network_mode: &str,
    ) -> AgentWalletResult<()> {
        self.network_binding
            .validate()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        self.recovery_bundle
            .validate_crypto()
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let binding = &self.recovery_bundle.binding;
        let canonical_hub_url = validate_service_url(&self.hub_url, "Agent HVM registry hub")
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        if self.schema_version != AGENT_HVM_REGISTRY_BINDING_SCHEMA
            || &self.wallet_id != expected_wallet_id
            || self.network_mode != expected_network_mode
            || self.network_binding.mainnet != (expected_network_mode == "mainnet")
            || self.network_binding.chain_id != binding.chain_id
            || self.network_binding.network_instance_id != binding.network_instance_id
            || binding.network_mode != expected_network_mode
            || binding.left_address != expected_address
            || binding.right_hub_address != self.hub_address
            || canonical_hub_url != self.hub_url
            || expected_network_mode == "mainnet" && !self.hub_url.starts_with("https://")
            || self.minimum_required_live_blocks == 0
            || !is_lower_hash(&self.activation_snapshot_commitment)
            || binding
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?
                != self.binding_commitment
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        Ok(())
    }

    /// Build the adopted binding from **the wallet's own evidence only**.
    ///
    /// The Hub path takes an `HvmRegistryChannelStatusV2` because the Hub is
    /// where the channel is learned from. Here nothing is learned from
    /// anybody: the bundle is the wallet's own, the snapshot is the wallet's
    /// own node's, and the `activation_snapshot_commitment` is that snapshot's
    /// own commitment rather than a number a provider reported.
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    fn from_chain_evidence(
        wallet_id: AgentWalletId,
        address: &str,
        network_mode: &str,
        network_binding: L1ChannelNetworkBinding,
        hub_url: String,
        bundle: &HvmRegistryRecoveryBundleV2,
        snapshot: &l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
        adopted_at: u64,
    ) -> AgentWalletResult<Self> {
        if snapshot.minimum_live_blocks == 0 {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let activation_snapshot_commitment = snapshot
            .commitment()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if !is_lower_hash(&activation_snapshot_commitment) {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        bundle
            .initial_recovery_bill
            .validate_fully_signed(&bundle.binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let binding = Self {
            schema_version: AGENT_HVM_REGISTRY_BINDING_SCHEMA,
            wallet_id: wallet_id.clone(),
            network_mode: network_mode.to_owned(),
            network_binding,
            hub_url,
            hub_address: bundle.binding.right_hub_address.clone(),
            binding_commitment: bundle
                .binding
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?,
            recovery_bundle: bundle.clone(),
            activation_snapshot_commitment,
            minimum_required_live_blocks: snapshot.minimum_live_blocks,
            minimum_required_recover_blocks: snapshot.minimum_recover_blocks,
            adopted_at,
        };
        binding.validate(&wallet_id, address, network_mode)?;
        Ok(binding)
    }

    /// Is this candidate still describing the chain a second read just
    /// returned? The TOCTOU counterpart of [`Self::matches_status`].
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    pub(super) fn matches_chain_snapshot(
        &self,
        snapshot: &l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
    ) -> AgentWalletResult<bool> {
        let commitment = snapshot
            .commitment()
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        Ok(commitment == self.activation_snapshot_commitment
            && snapshot.minimum_live_blocks == self.minimum_required_live_blocks
            && snapshot.minimum_recover_blocks == self.minimum_required_recover_blocks)
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    fn from_verified_status(
        wallet_id: AgentWalletId,
        address: &str,
        network_mode: &str,
        network_binding: L1ChannelNetworkBinding,
        hub_url: String,
        hub_address: String,
        status: HvmRegistryChannelStatusV2,
        adopted_at: u64,
    ) -> AgentWalletResult<Self> {
        if status.schema != HVM_REGISTRY_CHANNEL_STATUS_SCHEMA
            || status.minimum_required_live_blocks == 0
            || !is_lower_hash(&status.activation_snapshot_commitment)
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        status
            .latest_fully_signed_bill
            .validate_fully_signed(&status.recovery_bundle.binding)
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        let binding = Self {
            schema_version: AGENT_HVM_REGISTRY_BINDING_SCHEMA,
            wallet_id: wallet_id.clone(),
            network_mode: network_mode.to_owned(),
            network_binding,
            hub_url,
            hub_address,
            binding_commitment: status.binding_commitment,
            recovery_bundle: status.recovery_bundle,
            activation_snapshot_commitment: status.activation_snapshot_commitment,
            minimum_required_live_blocks: status.minimum_required_live_blocks,
            minimum_required_recover_blocks: status.minimum_required_recover_blocks,
            adopted_at,
        };
        binding.validate(&wallet_id, address, network_mode)?;
        Ok(binding)
    }
}

/// What one press of the exit control did, in the words a screen can render.
///
/// # Why this is a record rather than a sentence
///
/// The exit is not one action. It is four or five transactions spread across
/// an objection window measured in blocks, and for most of that window the
/// correct thing to display is "nothing is happening yet, and here is the
/// block at which something will". A command that returned only success or
/// failure would force the screen to invent that sentence, and a screen that
/// invents progress is exactly how a person ends up believing an exit is
/// running when it stalled two hours ago.
///
/// So every field here is either read from the chain this pass or read from
/// the wallet's own durable record. Nothing is estimated.
///
/// # The two money numbers are deliberately different
///
/// `network_fees_confirmed_zhu` is what the chain has definitely taken:
/// transactions of this wallet's that are in a block. `network_fees_at_risk_zhu`
/// is what may additionally have been spent — bytes this wallet signed that a
/// node may be holding right now, or may have mined without this wallet
/// noticing yet. Collapsing the two into one "spent" figure would have to
/// round in some direction, and both directions are a lie on the screen a
/// person reads while deciding whether to press again.
#[cfg(feature = "agent-wallet-testnet-pilot")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryExitProgress {
    pub schema: String,
    /// `waiting`, `stepped` or `complete`.
    pub outcome: String,
    /// The step this pass acted on, as its durable slug. Absent while waiting.
    pub step: Option<String>,
    /// Where that step's durable record now stands.
    pub phase: Option<String>,
    pub transaction_hash: Option<String>,
    /// What the exit is waiting for, in the chain's own terms.
    pub waiting_reason: Option<String>,
    pub observed_height: Option<u64>,
    pub channel_status: Option<u8>,
    pub deadline_height: Option<u64>,
    /// Set only once the channel is settled and this wallet has been paid.
    pub claimed_zhu: Option<u64>,
    /// The serial of the receipt this exit is being driven with.
    pub bill_serial: u64,
    pub network_fees_confirmed_zhu: u64,
    pub network_fees_at_risk_zhu: u64,
    pub steps: Vec<AgentHvmRegistryExitStepProgress>,
}

/// One durable exit step, flattened for a surface.
#[cfg(feature = "agent-wallet-testnet-pilot")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentHvmRegistryExitStepProgress {
    pub step: String,
    pub attempt: u32,
    pub phase: String,
    pub network_fee_zhu: u64,
    pub transaction_hash: Option<String>,
    pub confirmed_block_height: Option<u64>,
    pub updated_unix: u64,
}

/// The fee one exit transaction is allowed to carry.
///
/// One number, used by the driver and shown on screen, because a ceiling an
/// owner was told and a fee the wallet actually spends that differ by even one
/// zhu make the screen a lie. It is the same per-transaction channel ceiling
/// the cooperative close is bound by, so an exit cannot cost more per
/// transaction than the ordinary path it replaces.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU: u64 =
    l2_fast_pay_hub::l1_channel::MAX_CHANNEL_NETWORK_FEE_ZHU;

/// The gas ceiling for one exit transaction.
///
/// The maximum the byte-encoded budget can express. A registry call that runs
/// out of gas is a fee spent for nothing and a step that has to be signed
/// again at a new timestamp, which is strictly worse than a slightly larger
/// ceiling: the ceiling is a maximum, not a price.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const AGENT_REGISTRY_EXIT_GAS_MAX: u8 = u8::MAX;

/// Unit-238 amounts per zhu.
///
/// The chain prices gas in unit-238 and this workspace quotes money in zhu.
/// `protocol/src/params.rs` records the conversion in its own words: "50000:238
/// == 100:244 == 0.000005 HAC per byte", and one zhu is 1e-8 HAC, so one zhu is
/// a hundred unit-238.
#[cfg(feature = "agent-wallet-testnet-pilot")]
const UNIT238_PER_ZHU: u64 = 100;

/// The gas budget the chain actually grants one exit transaction.
///
/// `decode_gas_budget(gas_max_byte.min(TX_GAS_BUDGET_CAP_BYTE))` in
/// `hacash-fullnodedev/protocol/src/transaction/type3.rs`, with
/// `TX_GAS_BUDGET_CAP_BYTE = 99` and `decode_gas_budget(99) == 111911`. Asking
/// for [`AGENT_REGISTRY_EXIT_GAS_MAX`] does not raise it: the chain clamps.
///
/// It is quoted here because it is what an owner has to be able to *hold*, not
/// what they end up spending. `Context::gas_initialize`
/// (`protocol/src/context/gas.rs`) computes the whole budget's worth of burn
/// and takes it out of the sender's main balance with `hac_sub` before the
/// call runs, refunding the unused part in `gas_refund`. A balance that cannot
/// cover the reserve fails the transaction outright.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const AGENT_REGISTRY_EXIT_GAS_BUDGET: u64 = 111_911;

/// The chain's own floor on fee purity, in unit-238 per billing byte.
/// `VM_LOWEST_FEE_PURITY` in `hacash-fullnodedev/protocol/src/params.rs`.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const AGENT_VM_LOWEST_FEE_PURITY_UNIT238: u64 = 50_000;

/// The smallest an exit transaction gets, in billing bytes.
///
/// The gas reserve is `budget * fee / billing_size`, so a *smaller*
/// transaction reserves *more*. Quoting a requirement therefore needs a lower
/// bound on the size, and this is one: the three transactions of a measured
/// exit encode to 187, 421, 210 and 209 bytes
/// (`the_managers_own_exit_drive_pays_the_owner_on_chain_with_the_hub_dead`
/// prints them), the smallest being a lease renewal, and that same proof
/// asserts none is ever smaller than this. Rounded down from the measurement
/// on purpose, because being wrong in this direction over-states what the
/// owner needs to hold rather than under-states it, and only the second kind
/// sends someone into an irreversible press they cannot afford to finish.
///
/// The first value tried here was 192, taken from a run that happened not to
/// need a renewal. The guard in that proof failed on the very next run at 187
/// bytes, which is the whole reason it is a guard and not a comment.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const AGENT_REGISTRY_EXIT_MIN_BILLING_BYTES: u64 = 160;

/// What the chain takes out of the owner's main balance before one exit
/// transaction runs, over and above the network fee.
///
/// # Why this exists
///
/// The exit screen used to quote three network fees and nothing else: 3,000,000
/// zhu for the whole exit. A measured exit on a real chain charged 30,682,605
/// zhu, and the amount the owner had to *hold* while it ran was larger still,
/// because the gas budget is reserved in full and refunded afterwards. Neither
/// number was anywhere on the screen, and the affordability precondition went
/// green at a balance that could not pay for the first transaction.
///
/// Mirrors `GasCounter::calc_burn_amount`: `ceil(budget * purity_fee /
/// purity_size)` with `purity_fee = max(raw_fee, floor * size)`, evaluated at
/// the smallest size an exit transaction is known to take.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const fn agent_registry_exit_gas_reserve_zhu() -> u64 {
    let size = AGENT_REGISTRY_EXIT_MIN_BILLING_BYTES;
    let raw_fee_238 = AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU * UNIT238_PER_ZHU;
    let floor_fee_238 = AGENT_VM_LOWEST_FEE_PURITY_UNIT238 * size;
    let purity_fee_238 = if raw_fee_238 > floor_fee_238 {
        raw_fee_238
    } else {
        floor_fee_238
    };
    let reserve_238 = AGENT_REGISTRY_EXIT_GAS_BUDGET
        .saturating_mul(purity_fee_238)
        .div_ceil(size);
    reserve_238.div_ceil(UNIT238_PER_ZHU)
}

/// Everything one exit transaction can take from the owner's main balance:
/// the network fee, plus the gas the chain reserves before it runs.
#[cfg(feature = "agent-wallet-testnet-pilot")]
pub const fn agent_registry_exit_transaction_ceiling_zhu() -> u64 {
    AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU.saturating_add(agent_registry_exit_gas_reserve_zhu())
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
const AGENT_HVM_REGISTRY_EXIT_PROGRESS_SCHEMA: &str = "agent-hvm-registry-exit-progress/1";

/// The wallet's own key, handed to the shipped driver under the durable
/// record's terms and never under its own.
///
/// This adapter holds no authority. Every refusal it can produce belongs to
/// [`crate::signer::AgentTransactionSigner::sign_exact_registry_exit`]; what
/// lives here is only the binding of that method to the trait
/// `hacash_wallet_core::hvm_registry_exit_driver` calls through, plus the
/// live safety permit so an emergency stop raised mid-exit stops the next
/// signature rather than the next screen refresh.
#[cfg(feature = "agent-wallet-testnet-pilot")]
struct AgentRegistryExitSigner<'a> {
    signer: &'a crate::signer::AgentTransactionSigner,
    permit: &'a crate::emergency::AgentSafetyPermit,
    wallet_scope: crate::types::WalletScope,
    network_mode: String,
    signer_epoch: u64,
    binding_commitment: String,
    now: u64,
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl hacash_wallet_core::hvm_registry_exit_driver::HvmRegistryExitSignerV1
    for AgentRegistryExitSigner<'_>
{
    fn sign_exit_step(
        &self,
        kit: &hacash_wallet_core::hvm_registry_exit::HvmRegistryExitKitV1,
        plan: &hacash_wallet_core::hvm_registry_exit::HvmRegistryExitPlanV1,
        record: &hacash_wallet_core::hvm_registry_exit_record::PersistedHvmRegistryExitStepV1,
    ) -> hacash_wallet_core::WalletResult<
        l2_fast_pay_hub::hvm_registry_watchtower::SignedHvmRegistryCallTransactionV2,
    > {
        self.signer
            .sign_exact_registry_exit(
                crate::signer::AgentRegistryExitSigningRequest {
                    wallet_scope: &self.wallet_scope,
                    network_mode: &self.network_mode,
                    signer_epoch: self.signer_epoch,
                    binding_commitment: &self.binding_commitment,
                    kit,
                    plan,
                    record,
                },
                self.permit,
                self.now,
            )
            .map_err(|error| {
                hacash_wallet_core::WalletError::Policy(format!(
                    "this wallet refused to sign the exit step: {error}"
                ))
            })
    }
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl AgentWalletManager {
    /// Make at most one unit of progress on this wallet's unilateral exit, and
    /// say truthfully what happened.
    ///
    /// This is the production caller of
    /// [`hacash_wallet_core::hvm_registry_exit_driver::advance_registry_exit`].
    /// Until it existed, that driver's only caller in the entire tree was a
    /// test, and this workspace has shipped a mechanism in that shape twice.
    ///
    /// # What the caller may not supply
    ///
    /// Not the binding, not the bill, not the fee and not the gas ceiling. The
    /// kit comes from [`Self::hvm_registry_exit_kit`], which reads the
    /// verified binding and the verified head bill out of this wallet's own
    /// encrypted state; the terms are constants above. The only thing a caller
    /// hands in is a view of a chain, and the trait it must satisfy has four
    /// read-or-submit methods a bare fullnode can answer with the provider's
    /// process deleted.
    ///
    /// # Pressing again after a crash
    ///
    /// Continues; it does not restart. The driver plans from the chain and
    /// then asks the durable record what may be done about that plan through
    /// `begin_or_resume_exit_step`, and honours that verdict: bytes that
    /// already exist are looked up on chain and re-submitted rather than
    /// re-signed, and a step whose signer was entered before the process died
    /// is re-signed at the record's own timestamp, which is byte-identical.
    pub async fn advance_hvm_registry_exit<C>(
        &mut self,
        wallet_id: &AgentWalletId,
        chain: &C,
        now: u64,
    ) -> AgentWalletResult<AgentHvmRegistryExitProgress>
    where
        C: hacash_wallet_core::hvm_registry_exit_driver::HvmRegistryExitChainV1,
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
        let binding = state
            .hvm_registry_binding
            .as_ref()
            .ok_or(AgentWalletError::OperationNotFound)?;
        if binding.wallet_id() != wallet_id || binding.network_mode != state.network_mode {
            return Err(AgentWalletError::RecoveryRequired);
        }

        // The exit spends the owner's own fee and is irreversible, so it is
        // held to the same interlock every other signing path here is: a
        // permit taken before the key is reachable and re-checked inside the
        // signer on every step.
        //
        // # Why `false` rather than `state.payments_suspended`
        //
        // The suspension flag disables *agent* spending, and it is `true` by
        // default: a wallet is required to have payments suspended at the
        // moment it adopts a registry channel. Passing it here would mean a
        // channel adopted and never enabled could never be exited, and that an
        // owner who paused their agents because they suspected something was
        // wrong had thereby locked themselves out of the one control that
        // recovers their principal. That is the exact trap this whole screen
        // exists to prevent.
        //
        // Nothing is loosened by this. `AgentEmergencyController::status`
        // reads `stopped` from three sources, and only one of them is the
        // state flag: a real Pause All Agents raises the durable marker and
        // the in-process request, both of which still refuse here, and a
        // generation change between the permit and the signature still refuses
        // at the checkpoint inside the signer. What this argument controls is
        // solely whether the default-disabled *payment* posture blocks the
        // owner from recovering their own deposit, and the exit cannot pay
        // anyone but `binding.left_address` — this wallet's own address —
        // which the signer refuses to sign without.
        let permit = self
            .emergency_controller(wallet_id)?
            .issue_safety_permit(false)?;
        permit.checkpoint(false)?;

        let kit = self.hvm_registry_exit_kit(wallet_id)?;
        let bill_serial = kit.latest_bill.serial;
        let (binding_commitment, mut store) = self.open_hvm_registry_exit_store(wallet_id)?;
        let session = self.session(wallet_id)?;
        let exit_signer = AgentRegistryExitSigner {
            signer: &session.signer,
            permit: &permit,
            wallet_scope: session.signer.wallet_scope().clone(),
            network_mode: state.network_mode.clone(),
            signer_epoch: state.signer_epoch,
            binding_commitment: binding_commitment.clone(),
            now,
        };
        let terms = hacash_wallet_core::hvm_registry_exit_driver::HvmRegistryExitTermsV1 {
            network_fee_zhu: AGENT_REGISTRY_EXIT_NETWORK_FEE_ZHU,
            gas_max: AGENT_REGISTRY_EXIT_GAS_MAX,
        };
        let progress = hacash_wallet_core::hvm_registry_exit_driver::advance_registry_exit(
            &mut store,
            &kit,
            chain,
            &exit_signer,
            terms,
        )
        .await
        .map_err(classify_exit_drive_error)?;
        permit.checkpoint(false)?;

        let records = store.exit_step_records(&binding_commitment);
        Ok(exit_progress_report(&progress, bill_serial, &records))
    }
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl AgentWalletManager {
    /// What this wallet's durable record already says about an exit, without
    /// touching a chain, a Hub or a key.
    ///
    /// # Why a screen needs this before anything is pressed
    ///
    /// An exit outlives the app. Most of one is an objection window measured
    /// in blocks, so the ordinary case is an owner who started an exit, closed
    /// the laptop, and came back. Until this existed the status object carried
    /// nothing about that, so the screen greeted them with "Once you start,
    /// your provider has N blocks to object" when the window might be half
    /// gone or already closed, offered a control labelled as a beginning, and
    /// said "The exit has started" all over again on the next press.
    ///
    /// The record was there the whole time; nothing read it. This reads it.
    /// An empty answer means no step of an exit has ever been opened for this
    /// channel, which is exactly the case where "once you start" is true.
    pub fn hvm_registry_exit_steps(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Vec<AgentHvmRegistryExitStepProgress>> {
        self.ensure_session_active(wallet_id, now)?;
        let (binding_commitment, store) = self.open_hvm_registry_exit_store(wallet_id)?;
        Ok(store
            .exit_step_records(&binding_commitment)
            .into_iter()
            .map(|record| AgentHvmRegistryExitStepProgress {
                step: record.step.slug().to_owned(),
                attempt: record.attempt,
                phase: exit_phase_slug(record.phase).to_owned(),
                network_fee_zhu: record.network_fee_zhu,
                transaction_hash: record.transaction_hash.clone(),
                confirmed_block_height: record.confirmed_block_height,
                updated_unix: record.updated_unix,
            })
            .collect())
    }
}

/// Turn one driver verdict plus the durable record into the object a screen
/// renders. Split out so it can be tested without a chain.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn exit_progress_report(
    progress: &hacash_wallet_core::hvm_registry_exit_driver::HvmRegistryExitProgressV1,
    bill_serial: u64,
    records: &[hacash_wallet_core::hvm_registry_exit_record::PersistedHvmRegistryExitStepV1],
) -> AgentHvmRegistryExitProgress {
    use hacash_wallet_core::hvm_registry_exit_driver::HvmRegistryExitProgressV1 as Progress;
    use hacash_wallet_core::hvm_registry_exit_record::HvmRegistryExitPhase as Phase;

    let mut report = AgentHvmRegistryExitProgress {
        schema: AGENT_HVM_REGISTRY_EXIT_PROGRESS_SCHEMA.to_owned(),
        outcome: String::new(),
        step: None,
        phase: None,
        transaction_hash: None,
        waiting_reason: None,
        observed_height: None,
        channel_status: None,
        deadline_height: None,
        claimed_zhu: None,
        bill_serial,
        network_fees_confirmed_zhu: 0,
        network_fees_at_risk_zhu: 0,
        steps: Vec::new(),
    };
    match progress {
        Progress::Waiting {
            reason,
            observed_height,
            status,
            deadline,
        } => {
            report.outcome = "waiting".to_owned();
            report.waiting_reason = Some(reason.clone());
            report.observed_height = Some(*observed_height);
            report.channel_status = Some(*status);
            report.deadline_height = Some(*deadline);
        }
        Progress::Stepped {
            step,
            transaction_hash,
            phase,
        } => {
            report.outcome = "stepped".to_owned();
            report.step = Some(step.slug().to_owned());
            report.transaction_hash = Some(transaction_hash.clone());
            report.phase = Some(exit_phase_slug(*phase).to_owned());
        }
        Progress::Complete { claimed_zhu } => {
            report.outcome = "complete".to_owned();
            report.claimed_zhu = Some(*claimed_zhu);
        }
    }
    for record in records {
        match record.phase {
            Phase::Confirmed => {
                report.network_fees_confirmed_zhu = report
                    .network_fees_confirmed_zhu
                    .saturating_add(record.network_fee_zhu);
            }
            // Bytes exist, or may exist, and a node may already hold them.
            // Nothing here has been observed in a block, so it is not
            // reported as spent; it is reported as at risk of being spent,
            // which is the truth.
            Phase::SignatureMayExist | Phase::Signed | Phase::Submitted => {
                report.network_fees_at_risk_zhu = report
                    .network_fees_at_risk_zhu
                    .saturating_add(record.network_fee_zhu);
            }
            // A step somebody else paid for cost this wallet nothing, and a
            // bare intent has never touched the key.
            Phase::SettledElsewhere | Phase::IntentPersisted => {}
        }
        report.steps.push(AgentHvmRegistryExitStepProgress {
            step: record.step.slug().to_owned(),
            attempt: record.attempt,
            phase: exit_phase_slug(record.phase).to_owned(),
            network_fee_zhu: record.network_fee_zhu,
            transaction_hash: record.transaction_hash.clone(),
            confirmed_block_height: record.confirmed_block_height,
            updated_unix: record.updated_unix,
        });
    }
    report
}

/// Stable lowercase names for the durable phases, for the same reason
/// `HvmRegistryExitStep::slug` exists: a screen and a support conversation
/// must not depend on a `Debug` rendering that a rename can move.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn exit_phase_slug(
    phase: hacash_wallet_core::hvm_registry_exit_record::HvmRegistryExitPhase,
) -> &'static str {
    use hacash_wallet_core::hvm_registry_exit_record::HvmRegistryExitPhase as Phase;
    match phase {
        Phase::IntentPersisted => "intent_persisted",
        Phase::SignatureMayExist => "signature_may_exist",
        Phase::Signed => "signed",
        Phase::Submitted => "submitted",
        Phase::Confirmed => "confirmed",
        Phase::SettledElsewhere => "settled_elsewhere",
    }
}

/// Route a failure from one pass of the driver.
///
/// The driver mixes two unrelated kinds of failure and they need opposite
/// answers on screen. A fullnode that will not answer is a network problem an
/// owner fixes by reconnecting; a durable record that refuses is a state
/// problem, and telling someone to check their internet when their record is
/// blocked wastes the one window they have.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn classify_exit_drive_error(error: hacash_wallet_core::WalletError) -> AgentWalletError {
    let message = error.to_string();
    if message.contains(hacash_wallet_core::hvm_registry_exit_record::REFUSAL_EXIT_STEP_BLOCKED)
        || message
            .contains(hacash_wallet_core::hvm_registry_exit_record::REFUSAL_EXIT_RECORD_INVALID)
    {
        return classify_exit_record_error(error);
    }
    match error {
        // The node's own words, not a category. See
        // `AgentWalletError::RegistryExitNodeUnavailable`.
        hacash_wallet_core::WalletError::Node(_)
        | hacash_wallet_core::WalletError::NodeHttpStatus { .. }
        | hacash_wallet_core::WalletError::L2(_) => {
            AgentWalletError::RegistryExitNodeUnavailable(message)
        }
        // Everything the planner and the driver refuse for is already a
        // sentence written for the owner: an objection window whose lease
        // floor this chain can never grant, a renewal that is not taking
        // effect, a channel that holds nothing, a response window too short to
        // answer safely. Carry it rather than replacing it with a category.
        hacash_wallet_core::WalletError::Policy(_) => {
            AgentWalletError::RegistryExitRefused(message)
        }
        other => classify_exit_record_error(other),
    }
}

/// Route a durable-exit refusal to the variant whose remedy is the right one.
///
/// The two failures below have opposite answers and must never be collapsed.
/// A step that is simply further along than the caller thought is *not* a
/// wallet that needs recovering — telling an owner mid-exit to run a recovery
/// procedure would be telling them to do the one thing that cannot help. A
/// record that does not re-derive genuinely is a store integrity failure.
///
/// Matched on the stable markers wallet-core tags its refusals with, exactly
/// as [`super::hvm::classify_anchor_error`] matches on
/// `ANCHOR_WITNESS_DECISION_REQUIRED`.
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn classify_exit_record_error(error: hacash_wallet_core::WalletError) -> AgentWalletError {
    let message = error.to_string();
    if message.contains(hacash_wallet_core::hvm_registry_exit_record::REFUSAL_EXIT_STEP_BLOCKED) {
        AgentWalletError::InvalidOperationState
    } else if message
        .contains(hacash_wallet_core::hvm_registry_exit_record::REFUSAL_EXIT_RECORD_INVALID)
    {
        AgentWalletError::RecoveryRequired
    } else {
        // Everything else here is a malformed request from the driver — a
        // zero fee, a missing timestamp, a plan that says Wait. Refusing as a
        // state error keeps it out of the recovery funnel too.
        AgentWalletError::InvalidOperationState
    }
}

fn is_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl AgentWalletManager {
    /// The binding and the newest fully-signed bill this wallet holds —
    /// everything needed to finish this channel's exit in the user's favour,
    /// and nothing else.
    ///
    /// Reads only authenticated wallet state. It asks the Hub nothing, and
    /// returns the same answer with the Hub's process deleted; that is the
    /// property the whole exit turns on, so it is a property of this accessor
    /// rather than of a code path taken when the Hub happens to be down.
    ///
    /// # The head is derived when it is missing, never demanded
    ///
    /// `hvm_registry_exit_head` is `#[serde(default)]` and is written at
    /// adoption or on the next committed bill. A wallet bound *before* that
    /// field existed therefore carries `None`, and refusing on `None` handed
    /// exactly the wrong answer to exactly the wrong person: a user whose
    /// channel predates this code and whose Hub has since died would be told
    /// their wallet needs recovery, when re-adoption is the one repair that
    /// requires the Hub to be alive.
    ///
    /// So a missing head falls back to the binding's own serial-1 recovery
    /// bill — the same seed `AgentHvmRegistryExitHead::seed` uses at adoption.
    /// That bill is guaranteed to exist, because the binding is not adoptable
    /// without it, and it is guaranteed to be fully signed for the same
    /// reason. It is also the *weakest* evidence the user can hold, which on
    /// this rail means it refunds the whole deposit: the failure mode of the
    /// fallback is a dead Hub forfeiting fees it already earned, not a user
    /// losing principal.
    pub fn hvm_registry_exit_kit(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<hacash_wallet_core::hvm_registry_exit::HvmRegistryExitKitV1> {
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let binding = state
            .hvm_registry_binding
            .as_ref()
            .ok_or(AgentWalletError::OperationNotFound)?;
        match state.hvm_registry_exit_head.as_ref() {
            Some(head) => head.exit_kit(binding),
            None => AgentHvmRegistryExitHead::seed(binding, 0).exit_kit(binding),
        }
    }

    /// The serial and accepted time of the wallet's own exit head, for a
    /// surface that wants to say which receipt it would exit with.
    ///
    /// `None` means this wallet has no registry channel at all. A wallet that
    /// has one always has a head, because a missing one falls back to the
    /// binding's serial-1 recovery bill exactly as
    /// [`Self::hvm_registry_exit_kit`] does — the two must never disagree
    /// about which receipt an exit would use, or the screen would name one
    /// bill and the driver would sign another.
    pub fn hvm_registry_exit_head_serial(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<Option<(u64, u64)>> {
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let Some(binding) = state.hvm_registry_binding.as_ref() else {
            return Ok(None);
        };
        let head = match state.hvm_registry_exit_head.as_ref() {
            Some(head) => head.clone(),
            None => AgentHvmRegistryExitHead::seed(binding, 0),
        };
        head.validate(binding)?;
        Ok(Some((head.bill().serial, head.accepted_at())))
    }

    // =====================================================================
    // The durable exit, from this wallet's side.
    //
    // Everything below is a thin, checked shell over
    // `hacash_wallet_core::l2_safety`'s exit-step store. The rules live there,
    // beside the lock, the authenticated journal and the state commitment;
    // this layer's whole job is to hand that store the *verified* binding and
    // the *verified* head bill from this wallet's own encrypted state, so a
    // caller cannot pass a binding or a bill of its own choosing.
    //
    // Nothing here signs, submits or talks to a node. The driver above does
    // that, and it must call these in order: `begin_hvm_registry_exit_step`,
    // then `mark_hvm_registry_exit_signing` immediately before the key, then
    // `record_hvm_registry_exit_signature` with the exact bytes, then submit,
    // then confirm.
    // =====================================================================

    /// What reopening this wallet should do about one exit step.
    ///
    /// `Ok(None)` means this wallet has never started that step, so there is
    /// nothing in flight and planning it fresh is safe.
    pub fn hvm_registry_exit_resume(
        &self,
        wallet_id: &AgentWalletId,
        step: hacash_wallet_core::hvm_registry_exit::HvmRegistryExitStep,
    ) -> AgentWalletResult<
        Option<hacash_wallet_core::hvm_registry_exit_record::HvmRegistryExitResumeV1>,
    > {
        let kit = self.hvm_registry_exit_kit(wallet_id)?;
        let (binding_commitment, store) = self.open_hvm_registry_exit_store(wallet_id)?;
        store
            .resume_exit_step(&kit, &binding_commitment, step)
            .map_err(classify_exit_record_error)
    }

    /// Every exit step this wallet has recorded for its current channel
    /// incarnation, for a screen that has to say where the exit stands.
    pub fn hvm_registry_exit_records(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<
        Vec<hacash_wallet_core::hvm_registry_exit_record::PersistedHvmRegistryExitStepV1>,
    > {
        let (binding_commitment, store) = self.open_hvm_registry_exit_store(wallet_id)?;
        Ok(store.exit_step_records(&binding_commitment))
    }

    /// Make one exit step durable before anything is signed, or resume the one
    /// already there.
    ///
    /// The plan and the snapshot it was decided from are turned into the
    /// durable intent by
    /// [`hacash_wallet_core::hvm_registry_exit_record::HvmRegistryExitIntentV1::from_plan`],
    /// which re-derives the plan's own call source before accepting it. The
    /// returned value is the only authority for whether the key may be used.
    pub fn begin_hvm_registry_exit_step(
        &self,
        wallet_id: &AgentWalletId,
        plan: &hacash_wallet_core::hvm_registry_exit::HvmRegistryExitPlanV1,
        snapshot: &l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2,
        network_fee_zhu: u64,
        transaction_timestamp: u64,
        gas_max: u8,
    ) -> AgentWalletResult<hacash_wallet_core::hvm_registry_exit_record::HvmRegistryExitResumeV1>
    {
        let kit = self.hvm_registry_exit_kit(wallet_id)?;
        let intent =
            hacash_wallet_core::hvm_registry_exit_record::HvmRegistryExitIntentV1::from_plan(
                &kit,
                plan,
                snapshot,
                network_fee_zhu,
                transaction_timestamp,
                gas_max,
            )
            .map_err(classify_exit_record_error)?;
        let (_, mut store) = self.open_hvm_registry_exit_store(wallet_id)?;
        store
            .begin_or_resume_exit_step(&kit, &intent)
            .map_err(classify_exit_record_error)
    }

    /// Record that the signing key is about to be used for this step. Called
    /// immediately before the signer and never after it.
    pub fn mark_hvm_registry_exit_signing(
        &self,
        wallet_id: &AgentWalletId,
        step: hacash_wallet_core::hvm_registry_exit::HvmRegistryExitStep,
    ) -> AgentWalletResult<()> {
        let kit = self.hvm_registry_exit_kit(wallet_id)?;
        let (binding_commitment, mut store) = self.open_hvm_registry_exit_store(wallet_id)?;
        store
            .mark_exit_step_signature_may_exist(&kit, &binding_commitment, step)
            .map(|_| ())
            .map_err(classify_exit_record_error)
    }

    /// Make the exact signed bytes and their transaction hash durable, before
    /// they are handed to any node.
    pub fn record_hvm_registry_exit_signature(
        &self,
        wallet_id: &AgentWalletId,
        step: hacash_wallet_core::hvm_registry_exit::HvmRegistryExitStep,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> AgentWalletResult<()> {
        let kit = self.hvm_registry_exit_kit(wallet_id)?;
        let (binding_commitment, mut store) = self.open_hvm_registry_exit_store(wallet_id)?;
        store
            .persist_exit_step_signature(
                &kit,
                &binding_commitment,
                step,
                signed_transaction_hex,
                transaction_hash,
            )
            .map(|_| ())
            .map_err(classify_exit_record_error)
    }

    /// Record that the durable bytes were handed to a node.
    pub fn mark_hvm_registry_exit_submitted(
        &self,
        wallet_id: &AgentWalletId,
        step: hacash_wallet_core::hvm_registry_exit::HvmRegistryExitStep,
    ) -> AgentWalletResult<()> {
        let kit = self.hvm_registry_exit_kit(wallet_id)?;
        let (binding_commitment, mut store) = self.open_hvm_registry_exit_store(wallet_id)?;
        store
            .mark_exit_step_submitted(&kit, &binding_commitment, step)
            .map(|_| ())
            .map_err(classify_exit_record_error)
    }

    /// Record that this wallet's own transaction for a step was found on
    /// chain. The hash is checked against the stored one inside the store.
    pub fn mark_hvm_registry_exit_confirmed(
        &self,
        wallet_id: &AgentWalletId,
        step: hacash_wallet_core::hvm_registry_exit::HvmRegistryExitStep,
        transaction_hash: &str,
        block_height: u64,
        block_hash: &str,
    ) -> AgentWalletResult<()> {
        let kit = self.hvm_registry_exit_kit(wallet_id)?;
        let (binding_commitment, mut store) = self.open_hvm_registry_exit_store(wallet_id)?;
        store
            .mark_exit_step_confirmed(
                &kit,
                &binding_commitment,
                step,
                transaction_hash,
                block_height,
                block_hash,
            )
            .map(|_| ())
            .map_err(classify_exit_record_error)
    }

    /// Record that a permissionless step was found already done by somebody
    /// else. `finalize` and the Action 14 payout can both be pressed by
    /// anybody, and the payout's destination is pinned by the contract, so
    /// this is an ordinary ending rather than a failure.
    pub fn mark_hvm_registry_exit_settled_elsewhere(
        &self,
        wallet_id: &AgentWalletId,
        step: hacash_wallet_core::hvm_registry_exit::HvmRegistryExitStep,
        observed_height: u64,
    ) -> AgentWalletResult<()> {
        let kit = self.hvm_registry_exit_kit(wallet_id)?;
        let (binding_commitment, mut store) = self.open_hvm_registry_exit_store(wallet_id)?;
        store
            .mark_exit_step_settled_elsewhere(&kit, &binding_commitment, step, observed_height)
            .map(|_| ())
            .map_err(classify_exit_record_error)
    }

    /// Open the authenticated per-channel store that holds this wallet's exit
    /// records, keyed by the registry binding's own commitment.
    ///
    /// Same store, same key derivation and same lock as the rollback-anchor
    /// memory in [`super::hvm`]: one channel incarnation, one file, one owner
    /// process. Keyed by `binding_commitment` rather than by channel id
    /// because the commitment carries the reuse version, and a new incarnation
    /// is a genuinely new channel whose exit starts empty.
    fn open_hvm_registry_exit_store(
        &self,
        wallet_id: &AgentWalletId,
    ) -> AgentWalletResult<(String, hacash_wallet_core::l2_safety::ClientL2Safety)> {
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let binding = state
            .hvm_registry_binding
            .as_ref()
            .ok_or(AgentWalletError::OperationNotFound)?;
        let binding_commitment = binding.binding_commitment().to_owned();
        let hub_address = binding.hub_address().to_owned();
        let l2_root = self.storage.paths(wallet_id)?.l2_dir();
        let wallet_scope = session.signer.wallet_scope().as_str().to_owned();
        let store =
            hacash_wallet_core::l2_safety::ClientL2Safety::open_scoped_with_key_provider_for_network(
                &session.signer,
                &l2_root,
                &wallet_scope,
                "testnet",
                &hub_address,
                &binding_commitment,
            )
            .map_err(|_| AgentWalletError::RecoveryRequired)?;
        Ok((binding_commitment, store))
    }

    /// Adopt one exact operational shared-registry channel. This flow is
    /// owner-only, requires payments to remain suspended, and never signs.
    pub async fn verify_and_bind_hvm_registry(
        &mut self,
        wallet_id: &AgentWalletId,
        hub_url: &str,
        binding_commitment: &str,
        now: u64,
    ) -> AgentWalletResult<AgentHvmRegistryBinding> {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let original = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if original.network_mode != "testnet"
            || !original.payments_suspended
            || super::state::active_reservations(&original)? != crate::amount::HacUnits::ZERO
            || !original.hvm_payment_operations.is_empty()
            || original.hvm_channel_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        // Adoption is the moment a channel becomes this wallet's own, and the
        // only evidence that makes it worth owning is a refund bill the wallet
        // itself left-signed and the Hub countersigned. That bundle is built
        // and validated at open (`super::hvm_registry_open`) and stored before
        // any funding may be authorised, so requiring it here is not an extra
        // hurdle: it is the same door, checked on the second side. Without it
        // this method would adopt whatever a Hub served, and every check below
        // would be verifying a stranger's arithmetic.
        let countersigned = original
            .hvm_registry_open
            .as_ref()
            .and_then(super::hvm_registry_open::AgentHvmRegistryChannelOpen::countersigned_bundle)
            .cloned()
            .ok_or(AgentWalletError::RegistryOpenRefundNotCountersigned)?;
        if binding_commitment
            != countersigned
                .binding
                .commitment()
                .map_err(|_| AgentWalletError::RecoveryRequired)?
        {
            return Err(AgentWalletError::RegistryOpenRefundNotCountersigned);
        }
        let hub_url = validate_service_url(hub_url, "Agent HVM registry hub")
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;
        let hub = L2HubClient::new_for_wallet_policy(hub_url.clone(), "testnet", false);
        let health = hub
            .health()
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        if !health.ok
            || health.version < 7
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !hub_fee_is_zero(&health)
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let hub_address = health
            .hub_address
            .clone()
            .filter(|address| !address.is_empty())
            .ok_or(AgentWalletError::NodeCapabilityMismatch)?;
        let status = hub
            .hvm_registry_channel_status(binding_commitment)
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        // Byte for byte, the bundle this wallet built and checked. A Hub that
        // serves a different binding, a different refund bill or a different
        // signature is not describing the channel this wallet holds a way out
        // of, and adopting it would hand the owner an exit kit that verifies
        // against nothing they can reach.
        if status.recovery_bundle != countersigned {
            return Err(AgentWalletError::RegistryOpenRefundNotCountersigned);
        }

        let verified_node = crate::node_binding::verified_agent_node(
            &original.node_url,
            &original.network_mode,
            &original.block_one_fingerprint,
        )
        .await?;
        let node_snapshot = verified_node.snapshot();
        let network_binding = L1ChannelNetworkBinding::from_node_identity(
            &node_snapshot.network_kind,
            node_snapshot.mainnet,
            node_snapshot.chain_id,
            &node_snapshot.block_one_fingerprint,
            &node_snapshot.node_profile_id,
            Some(&node_snapshot.network_instance_id),
            node_snapshot.transaction_format_version,
        )
        .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        let protocol_binding = &status.recovery_bundle.binding;
        if protocol_binding.left_address != original.address
            || protocol_binding.right_hub_address != hub_address
            || protocol_binding.chain_id != network_binding.chain_id
            || protocol_binding.network_instance_id != network_binding.network_instance_id
        {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let hvm_node = l2_fast_pay_hub::node::NodeClient::new(original.node_url.clone())
            .map_err(|_| AgentWalletError::NodeRejected)?;
        let runtime = hvm_node
            .verify_hvm_registry_runtime_bundle(
                &status.recovery_bundle,
                status.minimum_required_live_blocks,
                status.minimum_required_recover_blocks.max(1),
            )
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if runtime.channel.serial.value > status.latest_fully_signed_bill.serial {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let candidate = AgentHvmRegistryBinding::from_verified_status(
            wallet_id.clone(),
            &original.address,
            &original.network_mode,
            network_binding,
            hub_url,
            hub_address,
            status,
            now,
        )?;

        // Close the adoption TOCTOU window before touching authenticated
        // wallet state. No await is permitted after the final state reload.
        let final_status = hub
            .hvm_registry_channel_status(candidate.binding_commitment())
            .await
            .map_err(|_| AgentWalletError::NodeRejected)?;
        if !candidate.matches_status(&final_status) {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        let final_runtime = hvm_node
            .verify_hvm_registry_runtime_bundle(
                candidate.recovery_bundle(),
                candidate.minimum_required_live_blocks(),
                candidate.operational_recover_blocks(),
            )
            .await
            .map_err(|_| AgentWalletError::NodeCapabilityMismatch)?;
        if final_runtime.channel.serial.value > final_status.latest_fully_signed_bill.serial {
            return Err(AgentWalletError::RecoveryRequired);
        }

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.address != original.address
            || current.network_mode != original.network_mode
            || current.node_url != original.node_url
            || current.block_one_fingerprint != original.block_one_fingerprint
            || current.policy_epoch != original.policy_epoch
            || current.signer_epoch != original.signer_epoch
            || current.emergency_epoch != original.emergency_epoch
            || !current.payments_suspended
            || super::state::active_reservations(&current)? != crate::amount::HacUnits::ZERO
            || !current.hvm_payment_operations.is_empty()
            || current.hvm_channel_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        if let Some(existing) = current.hvm_registry_binding.as_ref() {
            return if existing == &candidate {
                Ok(existing.clone())
            } else {
                Err(AgentWalletError::RecoveryRequired)
            };
        }
        current.hvm_registry_binding = Some(candidate.clone());
        // Seed the exit head in the same journalled transition that adopts the
        // binding. Adoption is legitimately Hub-dependent — the Hub is alive
        // at this moment and is where the channel is learned from — which is
        // exactly why everything the wallet will later need without the Hub
        // has to be copied into its own state right here. The binding already
        // was. The evidence built from it was not.
        current.hvm_registry_exit_head = Some(AgentHvmRegistryExitHead::seed(&candidate, now));
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::HvmBindingVerified,
            None,
            None,
            now,
        )?;
        Ok(candidate)
    }

    /// Adopt this wallet's own funded channel **without asking the provider
    /// anything**.
    ///
    /// # The trap this closes
    ///
    /// A reviewer drove it end to end: the provider countersigns honestly, the
    /// deposit is funded honestly, the provider then vanishes, and the owner
    /// is stuck - not because the chain will not pay them, but because the
    /// only writer of `hvm_registry_binding` needed the Hub alive four times
    /// (health, channel status, a byte-identical served bundle, and a second
    /// status for the TOCTOU re-check), and `advance_hvm_registry_exit`
    /// refuses without that binding. The chain would have paid: the contract
    /// accepts the very bill the wallet already stores. The wallet held the
    /// way out and had no code path that reached the chain with it.
    ///
    /// # Why this is not a weaker second door
    ///
    /// Every fact adoption needs is already the wallet's own, and none of it
    /// is the Hub's to state:
    ///
    /// * the recovery bundle is the one **this wallet** built, left-signed and
    ///   validated at open, and is required to be present here exactly as the
    ///   Hub path requires it;
    /// * the deposit is required to be one **this wallet** signed, stored
    ///   before broadcast, and has since seen in a block;
    /// * the channel is read from **this wallet's own** pinned, block-1
    ///   fingerprint-verified fullnode, and held to
    ///   [`HvmRegistryLiveSnapshotV2::validate_open_binding`], which is
    ///   stricter than the `validate_runtime_binding` the Hub path applies: it
    ///   additionally demands status exactly OPEN, serial 0, the whole deposit
    ///   still on the left line, no deadline and no prior claim.
    ///
    /// What is *not* available without the Hub is a later fully-signed bill,
    /// and that is not a loss: no such bill can exist yet. Every bill of this
    /// channel's life needs this wallet's own left signature, and at this
    /// moment the only one it has ever made is the serial-1 full refund - which
    /// is exactly what the exit head is seeded with, in the same journalled
    /// transition, by the same `AgentHvmRegistryExitHead::seed` the Hub path
    /// uses.
    pub async fn adopt_hvm_registry_channel_from_chain<C>(
        &mut self,
        wallet_id: &AgentWalletId,
        chain: &C,
        now: u64,
    ) -> AgentWalletResult<AgentHvmRegistryBinding>
    where
        C: hacash_wallet_core::hvm_registry_open::HvmRegistryOpenChainV1,
    {
        self.ensure_session_active(wallet_id, now)?;
        let (state_master, journal_key) = {
            let session = self.session(wallet_id)?;
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let original = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if original.network_mode != "testnet"
            || !original.payments_suspended
            || super::state::active_reservations(&original)? != crate::amount::HacUnits::ZERO
            || !original.hvm_payment_operations.is_empty()
            || original.hvm_channel_binding.is_some()
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let open = original
            .hvm_registry_open
            .clone()
            .ok_or(AgentWalletError::RegistryOpenRefundNotCountersigned)?;
        let bundle = open
            .countersigned_bundle()
            .cloned()
            .ok_or(AgentWalletError::RegistryOpenRefundNotCountersigned)?;
        // A channel nobody has paid into is not a channel to walk out of, and
        // seeding an exit head over one would send an owner's fee at an empty
        // contract.
        let funding = open
            .funding()
            .filter(|funding| funding.is_confirmed())
            .ok_or(AgentWalletError::RegistryFundingNotConfirmed)?;
        if funding.contract_address() != bundle.binding.contract_address
            || funding.amount_zhu() != bundle.binding.left_deposit_zhu
        {
            return Err(AgentWalletError::RecoveryRequired);
        }
        let hub_url = validate_service_url(open.hub_url(), "Agent HVM registry hub")
            .map_err(|_| AgentWalletError::InvalidPaymentRequest)?;

        let reading = self
            .registry_open_chain_evidence(&original, &bundle.binding, chain)
            .await?;
        // Same floor the pre-funding gate applies, for the same reason: the
        // exit's own lease floor is enforced by the exit's own planner, which
        // answers a shortfall by renewing. A stricter floor here would refuse
        // to adopt exactly the channel whose lease the exit exists to renew.
        reading
            .snapshot
            .validate_open_binding(&bundle.binding, 1, 0)
            .map_err(|_| AgentWalletError::RegistryOpenChainMismatch)?;
        let candidate = AgentHvmRegistryBinding::from_chain_evidence(
            wallet_id.clone(),
            &original.address,
            &original.network_mode,
            reading.network_binding.clone(),
            hub_url,
            &bundle,
            &reading.snapshot,
            now,
        )?;

        // Close the TOCTOU window before touching authenticated wallet state.
        // No await is permitted after the final state reload.
        let confirm = self
            .registry_open_chain_evidence(&original, &bundle.binding, chain)
            .await?;
        confirm
            .snapshot
            .validate_open_binding(&bundle.binding, 1, 0)
            .map_err(|_| AgentWalletError::RegistryOpenChainMismatch)?;
        if !candidate.matches_chain_snapshot(&confirm.snapshot)? {
            return Err(AgentWalletError::RegistryOpenChainMismatch);
        }

        let mut current = self.load_verified_state(wallet_id, &state_master, &journal_key)?;
        if current.address != original.address
            || current.network_mode != original.network_mode
            || current.node_url != original.node_url
            || current.block_one_fingerprint != original.block_one_fingerprint
            || current.policy_epoch != original.policy_epoch
            || current.signer_epoch != original.signer_epoch
            || current.emergency_epoch != original.emergency_epoch
            || !current.payments_suspended
            || super::state::active_reservations(&current)? != crate::amount::HacUnits::ZERO
            || !current.hvm_payment_operations.is_empty()
            || current.hvm_channel_binding.is_some()
            || current.hvm_registry_open.as_ref().and_then(
                super::hvm_registry_open::AgentHvmRegistryChannelOpen::countersigned_bundle,
            ) != Some(&bundle)
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        if let Some(existing) = current.hvm_registry_binding.as_ref() {
            return if existing == &candidate {
                Ok(existing.clone())
            } else {
                Err(AgentWalletError::RecoveryRequired)
            };
        }
        current.hvm_registry_binding = Some(candidate.clone());
        // Same journalled transition, same seed, same reason as the Hub path:
        // everything the wallet will later need without the provider has to be
        // its own by the time this returns.
        current.hvm_registry_exit_head = Some(AgentHvmRegistryExitHead::seed(&candidate, now));
        current.updated_at = now;
        self.persist_event(
            &mut current,
            &state_master,
            &journal_key,
            crate::journal::AgentJournalEventKind::HvmBindingVerified,
            None,
            None,
            now,
        )?;
        Ok(candidate)
    }
}

/// The manager's own exit drive, against a real deployed contract in real
/// blocks with the Hub killed. Behind its own feature because it needs the
/// Hub crate's registry deployment builders in the graph.
#[cfg(all(test, feature = "on-chain-exit-proof"))]
mod exit_on_chain_tests;

#[cfg(test)]
mod tests {
    use super::is_lower_hash;

    #[test]
    fn binding_commitments_require_canonical_lowercase_sha256_hex() {
        assert!(is_lower_hash(&"ab".repeat(32)));
        assert!(!is_lower_hash(&"AB".repeat(32)));
        assert!(!is_lower_hash(&"ab".repeat(31)));
        assert!(!is_lower_hash(&"zz".repeat(32)));
    }

    /// A wallet bound before the exit head existed still has a route out.
    ///
    /// `hvm_registry_exit_head` is `#[serde(default)]` and is written at
    /// adoption or on the next committed bill. Any wallet whose channel
    /// predates that field therefore loads with `None` — and the accessor used
    /// to answer `None` with `RecoveryRequired`, which is the worst possible
    /// answer to the worst possible person: someone whose provider has already
    /// died, being told to re-adopt, when re-adoption is the one repair that
    /// needs the provider alive.
    ///
    /// The fallback is the binding's own serial-1 refund bill: guaranteed to
    /// exist, because the binding is not adoptable without it, and guaranteed
    /// to verify, for the same reason.
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[test]
    fn a_wallet_with_no_stored_exit_head_still_has_an_exit_kit() {
        let (binding, _) = super::tests_support::binding_with_signed_refund();

        // Exactly what a wallet bound before this field existed carries.
        let head: Option<super::AgentHvmRegistryExitHead> = None;
        let kit = match head.as_ref() {
            Some(head) => head.exit_kit(&binding),
            None => super::AgentHvmRegistryExitHead::seed(&binding, 0).exit_kit(&binding),
        }
        .expect("a bound channel must always yield an exit kit");

        assert_eq!(
            kit.latest_bill, binding.recovery_bundle.initial_recovery_bill,
            "the fallback must be the refund bill the binding was adopted against"
        );
        kit.validate_crypto()
            .expect("the fallback kit must stand on its own signatures");
    }
}

/// Fixtures shared by this module's tests. Kept beside the type so a test can
/// build a binding whose fields are private to this file.
#[cfg(all(test, feature = "agent-wallet-testnet-pilot"))]
mod tests_support {
    use super::*;
    use field::{Serialize as _, Sign};
    use l2_fast_pay_hub::hvm_registry::{
        HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
        HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA, HvmRegistryBindingV2,
    };

    pub(super) fn binding_with_signed_refund() -> (AgentHvmRegistryBinding, u64) {
        l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
        let left = sys::Account::create_by("exit-head-fallback-left").unwrap();
        let hub = sys::Account::create_by("exit-head-fallback-hub").unwrap();
        let deposit = 1_000_000_u64;
        let contract =
            vm::ContractAddress::from_unchecked(field::Address::create_contract([7; 20]))
                .to_readable();
        let inner = HvmRegistryBindingV2 {
            schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id: "11".repeat(32),
            contract_address: contract,
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 2,
            bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 0,
            left_address: field::Address::from(*left.address()).to_readable(),
            right_hub_address: field::Address::from(*hub.address()).to_readable(),
            left_deposit_zhu: deposit,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let mut bill = HvmRegistryBillV2 {
            schema: HVM_REGISTRY_BILL_SCHEMA.into(),
            binding_commitment: inner.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: deposit,
            hub_balance_zhu: 0,
            left_signature_hex: String::new(),
            hub_signature_hex: String::new(),
        };
        let hash = bill.signing_hash(&inner).unwrap();
        bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
        bill.hub_signature_hex = hex::encode(Sign::create_by(&hub, &hash).serialize());

        let commitment = inner.commitment().unwrap();
        let binding = AgentHvmRegistryBinding {
            schema_version: AGENT_HVM_REGISTRY_BINDING_SCHEMA,
            wallet_id: AgentWalletId::new(),
            network_mode: "testnet".into(),
            network_binding: L1ChannelNetworkBinding {
                network_kind: "testnet".into(),
                chain_id: 7,
                mainnet: false,
                block_1_hash: "55".repeat(32),
                node_profile_id: "66".repeat(32),
                network_instance_id: "11".repeat(32),
                transaction_format_version: 1,
            },
            hub_url: "http://127.0.0.1:8790".into(),
            hub_address: inner.right_hub_address.clone(),
            binding_commitment: commitment,
            recovery_bundle: HvmRegistryRecoveryBundleV2 {
                schema: HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA.into(),
                binding: inner,
                initial_recovery_bill: bill,
            },
            activation_snapshot_commitment: "44".repeat(32),
            minimum_required_live_blocks: 500,
            minimum_required_recover_blocks: 100,
            adopted_at: 1_700_000_000,
        };
        (binding, deposit)
    }
}
