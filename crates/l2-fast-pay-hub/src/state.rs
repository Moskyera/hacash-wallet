mod close;
mod hvm;
mod hvm_chain;
mod hvm_registry;
mod hvm_registry_chain;
mod open;
#[cfg(test)]
mod open_retirement_tests;
mod rollback_anchor;

/// What a rollback anchor startup probe means for the process, as opposed to
/// what it means for a signature. The boot path in `bin/fast-pay-hub.rs` reads
/// it; nothing gates on it.
pub use self::rollback_anchor::RollbackAnchorBootPosture;

use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::amount::{HacAmount, format_amount_mei, parse_amount_mei};
use crate::api::{FastPayInboxItem, FastPayResponse};
use crate::error::{HubError, HubResult};
use crate::hub_signer::HubSigner;
use crate::idempotency::response_from_state as idempotent_response_from_state;
use crate::journal::{
    AuthenticatedJournal, JournalBinding, JournalEvent, JournalHead, JournalOperationType,
    JournalPhase,
};
use crate::l1_channel::{
    L1_CHANNEL_OPEN_SCHEMA, L1ChannelOpenRequest, L1ChannelOpenResponse,
    request_commitment as l1_open_request_commitment, validate_and_cosign_channel_open,
    validate_channel_open,
};
use crate::ledger::{
    apply_credit, apply_debit, channel_ledger_from_l1, next_bill_auto_number, payer_available_mei,
};
use crate::node::{NodeClient, validate_mainnet_node_url};
use crate::operation::{
    IdempotencyRecord, ReservationStatus, request_commitment, validate_operation_identity,
};
use crate::readiness::{
    MAINNET_BOUNDED_PILOT_PROFILE, MainnetPilotAdmissionPolicy, ZHU_PER_MILLIMEI,
    is_mainnet_pilot_profile,
};
use crate::routing::{PayeeRoute, resolve_payee_route};
use crate::sealed_state::StateStore;
use crate::storage::{
    ChannelLedger, HubPersistedState, L1ChannelOpenStatus, PendingSettlement,
    PersistedL1ChannelOpen, acquire_state_lock, initialize_authenticated_state, state_commitment,
};
use crate::wire::{
    ChannelPayCompleteDocuments, ChannelWireInput, build_cross_channel_bill,
    build_same_channel_bill,
};

const PENDING_TTL_SECONDS: u64 = 300;
const MAX_PENDING_SETTLEMENTS: usize = 1024;

fn aggregate_pilot_tvl_zhu(state: &HubPersistedState) -> HubResult<u64> {
    let mut total = 0u64;
    for ledger in state.channels.values() {
        let channel_millimeis = ledger
            .left_balance_mei
            .as_millimeis()
            .checked_add(ledger.right_balance_mei.as_millimeis())
            .ok_or_else(|| HubError::State("channel TVL calculation overflow".into()))?;
        let channel_zhu = channel_millimeis
            .checked_mul(ZHU_PER_MILLIMEI)
            .ok_or_else(|| HubError::State("channel TVL calculation overflow".into()))?;
        total = total
            .checked_add(channel_zhu)
            .ok_or_else(|| HubError::State("aggregate Hub TVL calculation overflow".into()))?;
    }
    for operation in state
        .l1_channel_opens
        .values()
        .filter(|operation| operation.status.reserves_admission())
    {
        total = total
            .checked_add(operation.user_deposit_zhu)
            .ok_or_else(|| HubError::State("aggregate Hub TVL calculation overflow".into()))?;
    }
    Ok(total)
}

fn require_pilot_admission(
    policy: &MainnetPilotAdmissionPolicy,
    state: &HubPersistedState,
    user_address: &str,
    new_deposit_zhu: u64,
) -> HubResult<()> {
    if !policy.is_configured() || !policy.allows(user_address) {
        return Err(HubError::Admission(
            "mainnet pilot channel-open user is not allowlisted".into(),
        ));
    }
    let current = aggregate_pilot_tvl_zhu(state)?;
    let proposed = current.checked_add(new_deposit_zhu).ok_or_else(|| {
        HubError::Admission("mainnet pilot aggregate TVL calculation overflow".into())
    })?;
    if proposed > policy.max_aggregate_tvl_hac_zhu() {
        return Err(HubError::Admission(format!(
            "mainnet pilot aggregate Hub TVL cap exceeded: proposed {proposed} zhu, cap {} zhu. {}",
            policy.max_aggregate_tvl_hac_zhu(),
            describe_pilot_tvl_holders(state, current)
        )));
    }
    Ok(())
}

/// Name what is actually holding the aggregate TVL budget.
///
/// The bare cap sentence says a number is too big and stops. It does not say
/// that the budget is held by one channel-open for a different address that
/// was broadcast days ago and never mined, which is the only fact that tells
/// anyone whether to wait, raise the cap, or go looking for a stuck
/// transaction. A refusal that a person can act on has to carry that.
///
/// Deliberately bounded: at most four operations are named, and no signature,
/// key or transaction body appears - only what an operator would need to find
/// the record in their own journal.
fn describe_pilot_tvl_holders(state: &HubPersistedState, current_tvl_zhu: u64) -> String {
    let now = crate::node::now_unix();
    let mut open_channels = 0usize;
    let mut open_channel_zhu = 0u64;
    for ledger in state.channels.values() {
        open_channels = open_channels.saturating_add(1);
        open_channel_zhu = open_channel_zhu.saturating_add(
            ledger
                .left_balance_mei
                .as_millimeis()
                .saturating_add(ledger.right_balance_mei.as_millimeis())
                .saturating_mul(crate::readiness::ZHU_PER_MILLIMEI),
        );
    }
    let mut pending: Vec<&crate::storage::PersistedL1ChannelOpen> = state
        .l1_channel_opens
        .values()
        .filter(|operation| operation.status.reserves_admission())
        .collect();
    pending.sort_by(|left, right| {
        right
            .user_deposit_zhu
            .cmp(&left.user_deposit_zhu)
            .then_with(|| left.operation_id.cmp(&right.operation_id))
    });
    let mut sentence = format!("{current_tvl_zhu} zhu of that cap is already held");
    if open_channels > 0 {
        sentence.push_str(&format!(
            ": {open_channel_zhu} zhu by {open_channels} open channel(s)"
        ));
    }
    if pending.is_empty() {
        sentence.push('.');
        return sentence;
    }
    sentence.push_str(if open_channels > 0 { ", and " } else { ": " });
    sentence.push_str(&format!(
        "{} zhu by {} channel-open operation(s) that have not confirmed",
        pending.iter().fold(0u64, |total, operation| total
            .saturating_add(operation.user_deposit_zhu)),
        pending.len()
    ));
    for operation in pending.iter().take(4) {
        sentence.push_str(&format!(
            " [operation {} for {}, {} zhu, status {}, last progress {} seconds ago]",
            operation.operation_id,
            operation.user_address,
            operation.user_deposit_zhu,
            operation.status.public_name(),
            now.saturating_sub(operation.created_unix.max(operation.updated_unix))
        ));
    }
    if pending.len() > 4 {
        sentence.push_str(&format!(" and {} more", pending.len() - 4));
    }
    sentence.push('.');
    sentence
}

fn require_pilot_payment_admission(
    policy: &MainnetPilotAdmissionPolicy,
    payer: &str,
) -> HubResult<()> {
    if !policy.is_configured() || !policy.allows(payer) {
        return Err(HubError::Admission(
            "mainnet pilot payment payer is not allowlisted".into(),
        ));
    }
    Ok(())
}

pub struct HubState {
    pub name: String,
    pub hub_address: String,
    pub node: NodeClient,
    pub hub_fee_mei: HacAmount,
    hub_signer: Option<HubSigner>,
    inner: RwLock<HubPersistedState>,
    state_store: Option<StateStore>,
    journal: Option<AuthenticatedJournal>,
    recovery_required: AtomicBool,
    open_recovery_lock: tokio::sync::Mutex<()>,
    close_recovery_lock: tokio::sync::Mutex<()>,
    hvm_signing_lock: tokio::sync::Mutex<()>,
    /// The external monotonic rollback anchor. `None` means no anchor is
    /// configured, which reads as `external_rollback_anchor_ready = false` and
    /// never as "anchor not required".
    rollback_anchor: Option<crate::rollback_anchor::RollbackAnchorClient>,
    /// Serialises continuity declarations against each other.
    ///
    /// The declaration route is a public `GET` that reads the durable anchor
    /// record, talks to the witness twice and writes twice, across `await`
    /// points. Two of them running at once would each mint a request at the
    /// witness's current counter plus one, and the loser is refused a position
    /// that was taken while it was in flight.
    rollback_anchor_continuity_lock: tokio::sync::Mutex<()>,
    /// Set only by a startup probe that agreed with the witness on every
    /// channel this Hub holds. While it is false the anchor path refuses.
    rollback_anchor_probe_agreed: AtomicBool,
    /// Why the most recent startup probe did not agree, by the identifier
    /// `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` section 2 indexes its procedures
    /// by. `None` means the last probe agreed, or that none has run.
    ///
    /// In memory rather than in the durable state, and deliberately: this is a
    /// fact about this process's contact with the witness, not about the state
    /// the anchor guards, and it must clear the instant the witness answers
    /// again. It gates nothing. The gate is
    /// `rollback_anchor_probe_agreed`; this is only what the Hub *says* about
    /// it on `/v1/readiness/mainnet`, so an operator reading the endpoint of a
    /// Hub that is refusing to sign learns which procedure to open.
    rollback_anchor_probe_refusal: RwLock<Option<&'static str>>,
    deployment_profile: String,
    mainnet_max_payment_hac_zhu: u64,
    mainnet_max_channel_funding_hac_zhu: u64,
    mainnet_admission_policy: MainnetPilotAdmissionPolicy,
    _state_lock: Option<fs::File>,
}

impl HubState {
    pub fn new(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        state_path: Option<PathBuf>,
        hub_fee_millimeis: u64,
        hub_secret_hex: Option<String>,
    ) -> HubResult<Self> {
        let hub_signer = hub_secret_hex
            .as_deref()
            .map(HubSigner::from_secret_hex)
            .transpose()?;
        Self::new_with_signer(
            name,
            hub_address,
            node_url,
            state_path,
            hub_fee_millimeis,
            hub_signer,
        )
    }

    pub fn new_with_signer(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        state_path: Option<PathBuf>,
        hub_fee_millimeis: u64,
        hub_signer: Option<HubSigner>,
    ) -> HubResult<Self> {
        Self::initialize(
            name.into(),
            hub_address.into(),
            node_url.into(),
            None,
            state_path,
            hub_fee_millimeis,
            hub_signer,
            None,
            "development".into(),
            0,
            0,
            None,
            MainnetPilotAdmissionPolicy::default(),
        )
    }

    pub fn new_secure(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        state_path: PathBuf,
        hub_fee_millimeis: u64,
        hub_secret_hex: Option<String>,
        journal_storage_key_hex: &str,
    ) -> HubResult<Self> {
        let hub_signer = hub_secret_hex
            .as_deref()
            .map(HubSigner::from_secret_hex)
            .transpose()?;
        Self::new_secure_with_signer(
            name,
            hub_address,
            node_url,
            state_path,
            hub_fee_millimeis,
            hub_signer,
            journal_storage_key_hex,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_secure_with_signer(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        state_path: PathBuf,
        hub_fee_millimeis: u64,
        hub_signer: Option<HubSigner>,
        journal_storage_key_hex: &str,
    ) -> HubResult<Self> {
        Self::initialize(
            name.into(),
            hub_address.into(),
            node_url.into(),
            None,
            Some(state_path),
            hub_fee_millimeis,
            hub_signer,
            Some(journal_storage_key_hex),
            "development".into(),
            0,
            0,
            None,
            MainnetPilotAdmissionPolicy::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_secure_with_policy(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        node_api_token: Option<&str>,
        state_path: PathBuf,
        hub_secret_hex: String,
        journal_storage_key_hex: &str,
        state_encryption_key_hex: &str,
        deployment_profile: impl Into<String>,
        mainnet_max_payment_hac_zhu: u64,
        mainnet_max_channel_funding_hac_zhu: u64,
    ) -> HubResult<Self> {
        let hub_signer = HubSigner::from_secret_hex(&hub_secret_hex)?;
        Self::new_secure_with_signer_policy(
            name,
            hub_address,
            node_url,
            node_api_token,
            state_path,
            hub_signer,
            journal_storage_key_hex,
            state_encryption_key_hex,
            deployment_profile,
            mainnet_max_payment_hac_zhu,
            mainnet_max_channel_funding_hac_zhu,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_secure_with_signer_policy(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        node_api_token: Option<&str>,
        state_path: PathBuf,
        hub_signer: HubSigner,
        journal_storage_key_hex: &str,
        state_encryption_key_hex: &str,
        deployment_profile: impl Into<String>,
        mainnet_max_payment_hac_zhu: u64,
        mainnet_max_channel_funding_hac_zhu: u64,
    ) -> HubResult<Self> {
        Self::new_secure_with_mainnet_admission_signer(
            name,
            hub_address,
            node_url,
            node_api_token,
            state_path,
            hub_signer,
            journal_storage_key_hex,
            state_encryption_key_hex,
            deployment_profile,
            mainnet_max_payment_hac_zhu,
            mainnet_max_channel_funding_hac_zhu,
            MainnetPilotAdmissionPolicy::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_secure_with_mainnet_admission(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        node_api_token: Option<&str>,
        state_path: PathBuf,
        hub_secret_hex: String,
        journal_storage_key_hex: &str,
        state_encryption_key_hex: &str,
        deployment_profile: impl Into<String>,
        mainnet_max_payment_hac_zhu: u64,
        mainnet_max_channel_funding_hac_zhu: u64,
        mainnet_admission_policy: MainnetPilotAdmissionPolicy,
    ) -> HubResult<Self> {
        let hub_signer = HubSigner::from_secret_hex(&hub_secret_hex)?;
        Self::new_secure_with_mainnet_admission_signer(
            name,
            hub_address,
            node_url,
            node_api_token,
            state_path,
            hub_signer,
            journal_storage_key_hex,
            state_encryption_key_hex,
            deployment_profile,
            mainnet_max_payment_hac_zhu,
            mainnet_max_channel_funding_hac_zhu,
            mainnet_admission_policy,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_secure_with_mainnet_admission_signer(
        name: impl Into<String>,
        hub_address: impl Into<String>,
        node_url: impl Into<String>,
        node_api_token: Option<&str>,
        state_path: PathBuf,
        hub_signer: HubSigner,
        journal_storage_key_hex: &str,
        state_encryption_key_hex: &str,
        deployment_profile: impl Into<String>,
        mainnet_max_payment_hac_zhu: u64,
        mainnet_max_channel_funding_hac_zhu: u64,
        mainnet_admission_policy: MainnetPilotAdmissionPolicy,
    ) -> HubResult<Self> {
        Self::initialize(
            name.into(),
            hub_address.into(),
            node_url.into(),
            node_api_token,
            Some(state_path),
            0,
            Some(hub_signer),
            Some(journal_storage_key_hex),
            deployment_profile.into(),
            mainnet_max_payment_hac_zhu,
            mainnet_max_channel_funding_hac_zhu,
            Some(state_encryption_key_hex),
            mainnet_admission_policy,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn initialize(
        name: String,
        hub_address: String,
        node_url: String,
        node_api_token: Option<&str>,
        state_path: Option<PathBuf>,
        hub_fee_millimeis: u64,
        hub_signer: Option<HubSigner>,
        journal_storage_key_hex: Option<&str>,
        deployment_profile: String,
        mainnet_max_payment_hac_zhu: u64,
        mainnet_max_channel_funding_hac_zhu: u64,
        state_encryption_key_hex: Option<&str>,
        mainnet_admission_policy: MainnetPilotAdmissionPolicy,
    ) -> HubResult<Self> {
        if hub_fee_millimeis != 0 {
            return Err(HubError::State(
                "Fast Pay is fee-free; hub_fee_millimeis must be 0".into(),
            ));
        }
        if hub_address.trim().is_empty() {
            return Err(HubError::State("hub address is required".into()));
        }
        if !matches!(
            deployment_profile.as_str(),
            "development"
                | "testnet"
                | "local-pilot"
                | crate::readiness::MAINNET_PILOT_PROFILE
                | crate::readiness::MAINNET_BOUNDED_PILOT_PROFILE
        ) {
            return Err(HubError::State(
                "deployment profile must be development, testnet, local-pilot, mainnet-pilot, or mainnet-bounded-pilot".into(),
            ));
        }
        if is_mainnet_pilot_profile(&deployment_profile) {
            validate_mainnet_node_url(&node_url)?;
        }
        if let Some(signer) = &hub_signer
            && signer.address() != hub_address.trim()
        {
            return Err(HubError::State(format!(
                "hub secret key address {} does not match HACASH_HUB_ADDRESS {}",
                signer.address(),
                hub_address.trim()
            )));
        }

        if let (Some(journal_key), Some(state_key)) =
            (journal_storage_key_hex, state_encryption_key_hex)
            && journal_key.trim().eq_ignore_ascii_case(state_key.trim())
        {
            return Err(HubError::State(
                "journal and state encryption keys must be independent".into(),
            ));
        }
        if let Some(signer) = hub_signer.as_ref() {
            for (label, key) in [
                ("journal", journal_storage_key_hex),
                ("state encryption", state_encryption_key_hex),
            ] {
                if key.is_some_and(|key| signer.secret_matches_hex(key)) {
                    return Err(HubError::State(format!(
                        "Hub signer and {label} keys must be independent"
                    )));
                }
            }
        }
        if is_mainnet_pilot_profile(&deployment_profile) && state_encryption_key_hex.is_none() {
            return Err(HubError::State(
                "a mainnet profile requires an independent state encryption key".into(),
            ));
        }
        let state_store = state_path
            .map(|path| match state_encryption_key_hex {
                Some(key) => StateStore::sealed(path, key, &hub_address),
                None => Ok(StateStore::plaintext(path)),
            })
            .transpose()?;
        let state_lock = state_store
            .as_ref()
            .map(|store| acquire_state_lock(store.path()))
            .transpose()?;
        let mut persisted = state_store
            .as_ref()
            .map(StateStore::load)
            .transpose()?
            .unwrap_or_default();
        let journal = match (state_store.as_ref(), journal_storage_key_hex) {
            (Some(store), Some(key_hex)) => {
                let mut key = hex::decode(key_hex.trim())
                    .map_err(|_| HubError::State("journal storage key must be hex".into()))?;
                if key.len() != 32 {
                    key.zeroize();
                    return Err(HubError::State(
                        "journal storage key must decode to exactly 32 bytes".into(),
                    ));
                }
                let journal = AuthenticatedJournal::open(
                    store.path().with_extension("journal.jsonl"),
                    &key,
                    JournalBinding {
                        wallet_scope: format!("hub:{}", hub_address.trim()),
                        hub_or_provider_identity: hub_address.trim().to_owned(),
                        channel_id: None,
                    },
                );
                key.zeroize();
                Some(journal?)
            }
            (None, Some(_)) => {
                return Err(HubError::State(
                    "durable state path is required when journal authentication is enabled".into(),
                ));
            }
            _ => None,
        };

        if let (Some(store), Some(journal)) = (state_store.as_ref(), journal.as_ref()) {
            initialize_authenticated_state(store, &mut persisted, journal, &hub_address)?;
        }
        validate_terminal_l1_finality_evidence(&persisted)?;
        let recovery_required = persisted_state_requires_recovery(&persisted);
        if is_mainnet_pilot_profile(&deployment_profile)
            && (hub_signer.is_none()
                || !state_store.as_ref().is_some_and(StateStore::is_sealed)
                || journal.is_none())
        {
            return Err(HubError::State(
                "a mainnet profile requires a signer and durable authenticated storage".into(),
            ));
        }
        Ok(Self {
            name,
            hub_address,
            node: NodeClient::new(node_url)?.with_api_token(node_api_token)?,
            hub_fee_mei: HacAmount::ZERO,
            hub_signer,
            inner: RwLock::new(persisted),
            state_store,
            journal,
            recovery_required: AtomicBool::new(recovery_required),
            open_recovery_lock: tokio::sync::Mutex::new(()),
            close_recovery_lock: tokio::sync::Mutex::new(()),
            hvm_signing_lock: tokio::sync::Mutex::new(()),
            rollback_anchor: None,
            rollback_anchor_continuity_lock: tokio::sync::Mutex::new(()),
            rollback_anchor_probe_agreed: AtomicBool::new(false),
            rollback_anchor_probe_refusal: RwLock::new(None),
            deployment_profile,
            mainnet_max_payment_hac_zhu,
            mainnet_max_channel_funding_hac_zhu,
            mainnet_admission_policy,
            _state_lock: state_lock,
        })
    }

    fn settlement_ready(&self) -> bool {
        self.hub_signer.is_some()
            && self.state_store.is_some()
            && self.journal.is_some()
            && !self.recovery_required.load(Ordering::Acquire)
    }

    /// Publish the Hub's health from local state alone. This performs no node
    /// I/O, and the signature is synchronous so that it cannot acquire any.
    ///
    /// `/v1/health` is a cheap liveness endpoint. It is polled by every client
    /// on every network, so it must never make the Hub reach for the mainnet
    /// gate on a caller's behalf; `official_hub_contract` pins that by counting
    /// fullnode capability calls after a testnet `health()` and requiring zero.
    ///
    /// Because no measurement is available here, this endpoint publishes no
    /// capability-dependent guarantee at all. It used to publish them
    /// conservatively - `HubHardGuarantees::measure` handed `None`, every such
    /// flag falling to `false` - but a flag that is structurally always `false`
    /// cannot distinguish "no evidence" from "proven absent", and a wallet that
    /// gated on one could never be un-bricked by the guarantee arriving. The
    /// flags are gone from [`crate::api::HubHealth`] so that gating on them is a
    /// compile error rather than a convention.
    ///
    /// The authority for those guarantees is [`Self::mainnet_readiness`]
    /// (`/v1/readiness/mainnet`), which probes the fullnode, runs
    /// `HubHardGuarantees::measure` over the evidence, and publishes the result
    /// as `trustless_finality` / `unilateral_l1_enforceable`. That is also the
    /// endpoint the Hub's own money gate reads, so nothing can be advertised as
    /// ready that the gate has not measured.
    pub fn health(&self) -> crate::api::HubHealth {
        let settlement_ready = self.settlement_ready();
        crate::api::HubHealth {
            ok: true,
            version: crate::api::HUB_API_VERSION,
            name: Some(self.name.clone()),
            hub_address: Some(self.hub_address.clone()),
            hub_fee_mei: Some(format_amount_mei(self.hub_fee_mei)),
            settlement_ready,
            cross_channel_ready: settlement_ready,
            official_channelpay_ready: settlement_ready,
            trusted_bounded_pilot_ready: settlement_ready
                && self.deployment_profile == MAINNET_BOUNDED_PILOT_PROFILE,
            deployment_profile: Some(self.deployment_profile.clone()),
        }
    }

    /// The authority for every capability-dependent guarantee the Hub makes.
    ///
    /// This endpoint owns the measurement: it probes the fullnode and runs
    /// `HubHardGuarantees::measure` over the evidence it gets back. `health()`
    /// runs the same measurement without evidence and therefore reports those
    /// guarantees conservatively; a client that needs the real answer asks
    /// here, and so does the Hub's own mainnet money gate.
    pub async fn mainnet_readiness(&self) -> crate::readiness::MainnetReadinessV1 {
        let capabilities = self.node.capabilities().await;
        // The rollback anchor is measured the same way the fullnode is: by
        // probing it here and weighing what comes back. No witness configured,
        // an unreachable one, or one whose signed answer does not verify
        // against the pinned keys and this Hub's durable position all produce
        // `None`, and `None` reads false.
        let anchor = self.rollback_anchor_evidence().await;
        // The measurement itself, on the endpoint that pays for the evidence,
        // so the advertised guarantees and the enforced gate cannot disagree.
        let guarantees = crate::readiness::HubHardGuarantees::measure(
            &self.deployment_profile,
            self.settlement_ready(),
            capabilities.as_ref().ok(),
            anchor.as_ref(),
            crate::node::now_unix(),
        );
        let mut readiness = crate::readiness::MainnetReadinessV1::evaluate(
            &self.deployment_profile,
            self.mainnet_max_payment_hac_zhu,
            self.mainnet_max_channel_funding_hac_zhu,
            self.settlement_ready(),
            guarantees.external_rollback_anchor_ready,
            // The same evidence the flag above was measured from, published
            // verbatim: the posture and the operating entity travel with the
            // boolean rather than being computed and thrown away.
            anchor.as_ref(),
            guarantees.l1_dispute_path_ready,
            capabilities,
        );
        // A condemnation this Hub wrote into its own state file, read from
        // that file rather than from the anchor evidence above. The evidence
        // carries the same count, but it is `None` whenever no witness is
        // configured - so an operator who deleted the witness flags would
        // otherwise publish a clean document for a Hub holding a channel that
        // must never sign again. Zero for a Hub that never had an anchor.
        //
        // Ordered before `apply_mainnet_admission` so the blocker is in the
        // list that call recomputes `payments_enabled` from.
        readiness.block_on_latched_rollback_anchor_refusals(
            self.latched_rollback_anchor_refusal_count(),
        );
        // Why the startup probe has not agreed, by the identifier
        // `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` section 2 indexes its
        // procedures by. A Hub whose witness was unreachable at boot now
        // starts, refuses to sign, and says so here - where an operator can
        // read it - instead of failing to start, which under
        // `Restart=on-failure` is a crash loop that answers no endpoint and
        // names no identifier. Same ordering rule as the line above.
        readiness.note_rollback_anchor_probe_refusal(self.rollback_anchor_probe_refusal());
        // And, separately, whether the witness this Hub is configured with is
        // still the witness it pinned. Separate because it needs no probe: a
        // replacement witness that is itself unreachable would otherwise be
        // published only as the transient `rollback_anchor_witness_unreachable`,
        // which tells the operator to wait for a witness that is gone. Same
        // ordering rule as the two lines above.
        readiness.note_rollback_anchor_witness_identity_break(
            self.rollback_anchor_witness_identity_break(),
        );
        // And whether the pin that measurement rests on is durable at all.
        readiness.note_rollback_anchor_pin_is_not_durable(
            self.rollback_anchor.is_some()
                && (self.journal.is_none() || self.state_store.is_none()),
        );
        readiness.apply_mainnet_admission(
            &self.mainnet_admission_policy,
            self.aggregate_pilot_tvl_zhu(),
        );
        // The Hub-wide cooperative-close reservation. Published because it was
        // the one gate in this document with no field at all: `close_enabled`
        // read true and every Close but one was refused.
        readiness.note_cooperative_close_reservation(self.close_liquidity_reservation());
        readiness
    }

    fn close_liquidity_reservation(&self) -> Option<crate::readiness::CloseLiquidityReservation> {
        let guard = self.inner.read().ok()?;
        crate::state::close::close_liquidity_reservation(&guard)
    }

    fn aggregate_pilot_tvl_zhu(&self) -> HubResult<u64> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        aggregate_pilot_tvl_zhu(&guard)
    }

    fn require_mainnet_new_channel_admission(
        &self,
        state: &HubPersistedState,
        user_address: &str,
        new_deposit_zhu: u64,
    ) -> HubResult<()> {
        if !is_mainnet_pilot_profile(&self.deployment_profile) {
            return Ok(());
        }
        require_pilot_admission(
            &self.mainnet_admission_policy,
            state,
            user_address,
            new_deposit_zhu,
        )
    }

    pub(super) async fn cosign_channel_open_inner(
        &self,
        request: &L1ChannelOpenRequest,
    ) -> HubResult<L1ChannelOpenResponse> {
        self.ensure_settlement_ready()?;
        let initial_network = self
            .node
            .capabilities()
            .await?
            .l1_channel_network_binding()?;
        let request_commitment = l1_open_request_commitment(request)?;
        let existing = self.existing_l1_channel_open(request, &request_commitment)?;
        let recovering_existing = existing.is_some();
        let validation_time = existing
            .as_ref()
            .map_or_else(crate::node::now_unix, |operation| operation.created_unix);
        if let Some(existing) = existing.as_ref() {
            validate_channel_open(
                request,
                &self.hub_address,
                &initial_network,
                self.mainnet_max_channel_funding_hac_zhu,
                validation_time,
            )?;
            if existing.status.has_durable_signature() {
                return l1_channel_open_response(existing);
            }
        }

        let intent = validate_channel_open(
            request,
            &self.hub_address,
            &initial_network,
            self.mainnet_max_channel_funding_hac_zhu,
            validation_time,
        )?;
        if intent.user_deposit_zhu % crate::readiness::ZHU_PER_MILLIMEI != 0 {
            return Err(HubError::Payment(
                "channel-open deposit must be aligned to an exact millimei ledger unit".into(),
            ));
        }
        self.require_mainnet_channel_funding_ready(intent.user_deposit_zhu)
            .await?;
        self.require_open_funding(&intent).await?;

        require_channel_open_target(
            self.node.query_channel(&intent.channel_id).await,
            &intent,
            &self.hub_address,
        )?;

        // Release admission budget held by opens the chain says do not exist,
        // before measuring the budget this one needs. Without this, one
        // broadcast that never made it into a block holds its whole deposit
        // against the aggregate TVL cap for the life of the durable state, and
        // a pilot Hub whose cap is one channel wide never opens another
        // channel again. See `retire_unmined_channel_opens` for what a
        // retirement costs in evidence.
        //
        // Only on the path that is about to create a new operation: a resume of
        // an existing one changes no reservation and must not spend two chain
        // round trips per stale record on the way.
        if !recovering_existing {
            match self.retire_unmined_channel_opens().await {
                Ok(retired) if !retired.is_empty() => tracing::warn!(
                    retired = retired.len(),
                    operations = %retired.join(","),
                    "released pilot admission budget held by channel-opens the fullnode has neither mined nor holds pending"
                ),
                Ok(_) => {}
                // A sweep that cannot run leaves every reservation standing, so
                // the worst it can do is refuse this open the way it already
                // would have. It must never be the thing that fails the open.
                Err(error) => tracing::warn!(
                    error = %error,
                    "could not sweep unmined channel-opens; admission budget is measured as it stands"
                ),
            }
        }

        let operation = {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            if let Some(existing) =
                existing_l1_channel_open_from_state(&guard, request, &request_commitment)?
            {
                existing
            } else {
                open::require_new_open_admission(&guard, &intent.user_address)?;
                self.require_mainnet_new_channel_admission(
                    &guard,
                    &intent.user_address,
                    intent.user_deposit_zhu,
                )?;
                if guard.l1_channel_opens.values().any(|item| {
                    item.channel_id == intent.channel_id && item.status.reserves_admission()
                }) {
                    return Err(HubError::Channel(
                        "another L1 channel-open operation already owns this channel ID".into(),
                    ));
                }
                let operation = PersistedL1ChannelOpen {
                    operation_id: request.operation_id.clone(),
                    idempotency_key: request.idempotency_key.clone(),
                    request_commitment: request_commitment.clone(),
                    network: initial_network.network_kind.clone(),
                    chain_id: initial_network.chain_id,
                    mainnet: initial_network.mainnet,
                    block_1_hash: initial_network.block_1_hash.clone(),
                    node_profile_id: initial_network.node_profile_id.clone(),
                    network_instance_id: initial_network.network_instance_id.clone(),
                    transaction_format_version: initial_network.transaction_format_version,
                    channel_id: intent.channel_id.clone(),
                    reuse_version: intent.expected_reuse_version,
                    user_address: intent.user_address.clone(),
                    user_deposit_zhu: intent.user_deposit_zhu,
                    network_fee_zhu: intent.network_fee_zhu,
                    partial_transaction_hex: request.partial_transaction_hex.clone(),
                    partial_transaction_commitment: request.partial_transaction_commitment.clone(),
                    transaction_hash: intent.transaction_hash.clone(),
                    signed_transaction_hex: None,
                    signed_transaction_commitment: None,
                    confirmed_block_height: None,
                    broadcast_height: None,
                    observed_confirmations: 0,
                    status: L1ChannelOpenStatus::ValidatedBeforeSigning,
                    created_unix: request.created_unix,
                    expires_unix: request.expires_unix,
                    updated_unix: crate::node::now_unix(),
                    last_error: None,
                };
                let mut next_state = guard.clone();
                next_state.l1_channel_open_idempotency.insert(
                    operation.idempotency_key.clone(),
                    operation.operation_id.clone(),
                );
                next_state.l1_channel_open_commitments.insert(
                    operation.partial_transaction_commitment.clone(),
                    operation.operation_id.clone(),
                );
                next_state
                    .l1_channel_opens
                    .insert(operation.operation_id.clone(), operation.clone());
                self.commit_l1_channel_open_transition(
                    &mut guard,
                    next_state,
                    &operation,
                    JournalPhase::L1IntentValidated,
                )?;
                operation
            }
        };

        if operation.status.has_durable_signature() {
            return l1_channel_open_response(&operation);
        }
        if recovering_existing && operation.status == L1ChannelOpenStatus::ValidatedBeforeSigning {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let mut abandoned = guard
                .l1_channel_opens
                .get(&operation.operation_id)
                .cloned()
                .ok_or_else(|| {
                    HubError::State("durable channel-open operation disappeared".into())
                })?;
            if abandoned.status != L1ChannelOpenStatus::ValidatedBeforeSigning {
                return Err(HubError::State(
                    "RecoveryRequired: unsigned channel-open state changed during recovery".into(),
                ));
            }
            abandoned.status = L1ChannelOpenStatus::AbandonedUnsigned;
            abandoned.updated_unix = crate::node::now_unix();
            abandoned.last_error = Some(
                "Hub restart occurred before the durable signature-may-exist marker; create a fresh request"
                    .into(),
            );
            let mut next = guard.clone();
            next.l1_channel_opens
                .insert(abandoned.operation_id.clone(), abandoned.clone());
            self.commit_l1_channel_open_transition(
                &mut guard,
                next,
                &abandoned,
                JournalPhase::L1OpenAbandonedUnsigned,
            )?;
            return Err(HubError::State(
                "channel-open was proven unsigned and abandoned after restart; create a fresh request"
                    .into(),
            ));
        }
        self.require_mainnet_channel_funding_ready(operation.user_deposit_zhu)
            .await?;
        self.require_open_funding(&intent).await?;
        require_channel_open_target(
            self.node.query_channel(&operation.channel_id).await,
            &intent,
            &self.hub_address,
        )?;
        let signing_network = self
            .node
            .capabilities()
            .await?
            .l1_channel_network_binding()?;
        if signing_network != initial_network {
            return Err(HubError::Node(
                "fullnode network identity changed before channel-open signing".into(),
            ));
        }

        let operation = if operation.status == L1ChannelOpenStatus::ValidatedBeforeSigning {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let current = guard
                .l1_channel_opens
                .get(&operation.operation_id)
                .cloned()
                .ok_or_else(|| {
                    HubError::State("durable channel-open operation disappeared".into())
                })?;
            if current.request_commitment != operation.request_commitment
                || current.status != L1ChannelOpenStatus::ValidatedBeforeSigning
            {
                return Err(HubError::State(
                    "RecoveryRequired: channel-open operation changed before signing marker".into(),
                ));
            }
            let mut marked = current;
            marked.status = L1ChannelOpenStatus::SignatureMayExist;
            let mut next_state = guard.clone();
            next_state
                .l1_channel_opens
                .insert(marked.operation_id.clone(), marked.clone());
            self.commit_l1_channel_open_transition(
                &mut guard,
                next_state,
                &marked,
                JournalPhase::L1OpenSignatureMayExist,
            )?;
            marked
        } else {
            operation
        };
        if operation.status != L1ChannelOpenStatus::SignatureMayExist {
            return Err(HubError::State(
                "RecoveryRequired: channel-open is not in a signable durable state".into(),
            ));
        }
        if recovering_existing && operation.signed_transaction_hex.is_none() {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let mut blocked = guard
                .l1_channel_opens
                .get(&operation.operation_id)
                .cloned()
                .ok_or_else(|| {
                    HubError::State("durable channel-open operation disappeared".into())
                })?;
            blocked.status = L1ChannelOpenStatus::RecoveryRequired;
            blocked.updated_unix = crate::node::now_unix();
            blocked.last_error =
                Some("a Hub open signature may exist but its exact bytes are unavailable".into());
            let mut next = guard.clone();
            next.l1_channel_opens
                .insert(blocked.operation_id.clone(), blocked.clone());
            self.commit_l1_channel_open_transition(
                &mut guard,
                next,
                &blocked,
                JournalPhase::L1OpenRecoveryRequired,
            )?;
            return Err(HubError::State(
                "RecoveryRequired: a Hub open signature may exist but cannot be recreated".into(),
            ));
        }
        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("Hub L1 channel signer is not configured".into()))?;
        let signed = validate_and_cosign_channel_open(
            request,
            signer.account(),
            &signing_network,
            self.mainnet_max_channel_funding_hac_zhu,
            operation.created_unix,
        )?;
        if signed.channel_id != operation.channel_id
            || signed.user_address != operation.user_address
            || signed.user_deposit_zhu != operation.user_deposit_zhu
            || signed.network_fee_zhu != intent.network_fee_zhu
            || signed.transaction_hash != operation.transaction_hash
        {
            return Err(HubError::State(
                "RecoveryRequired: channel-open intent changed before Hub signing".into(),
            ));
        }

        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let current = guard
            .l1_channel_opens
            .get(&operation.operation_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable channel-open operation disappeared".into()))?;
        if current.request_commitment != operation.request_commitment
            || current.status != L1ChannelOpenStatus::SignatureMayExist
        {
            if current.status.has_durable_signature() {
                return l1_channel_open_response(&current);
            }
            return Err(HubError::State(
                "RecoveryRequired: channel-open operation changed during signing".into(),
            ));
        }
        let mut completed = current;
        completed.signed_transaction_hex = Some(signed.signed_transaction_hex);
        completed.signed_transaction_commitment = Some(signed.signed_transaction_commitment);
        completed.status = L1ChannelOpenStatus::Signed;
        let mut next_state = guard.clone();
        next_state
            .l1_channel_opens
            .insert(completed.operation_id.clone(), completed.clone());
        self.commit_l1_channel_open_transition(
            &mut guard,
            next_state,
            &completed,
            JournalPhase::L1SignatureProduced,
        )?;
        l1_channel_open_response(&completed)
    }

    async fn require_open_funding(
        &self,
        intent: &crate::l1_channel::ValidatedChannelOpenIntent,
    ) -> HubResult<()> {
        let required_zhu = u128::from(intent.user_deposit_zhu)
            .checked_add(u128::from(intent.network_fee_zhu))
            .ok_or_else(|| HubError::Payment("channel-open funding requirement overflow".into()))?;
        let available_zhu = self.node.query_balance_zhu(&intent.user_address).await?;
        if available_zhu < required_zhu {
            return Err(HubError::Payment(format!(
                "channel-open requires {required_zhu} zhu including network fee, but the user address has {available_zhu} zhu"
            )));
        }
        Ok(())
    }
    fn existing_l1_channel_open(
        &self,
        request: &L1ChannelOpenRequest,
        commitment: &str,
    ) -> HubResult<Option<PersistedL1ChannelOpen>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        existing_l1_channel_open_from_state(&guard, request, commitment)
    }

    fn commit_l1_channel_open_transition(
        &self,
        guard: &mut HubPersistedState,
        mut next_state: HubPersistedState,
        operation: &PersistedL1ChannelOpen,
        phase: JournalPhase,
    ) -> HubResult<()> {
        self.ensure_l1_open_recovery_allowed(guard, &operation.operation_id)?;
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| HubError::State("authenticated L2 journal is unavailable".into()))?;
        let store = self
            .state_store
            .as_ref()
            .ok_or_else(|| HubError::State("durable L2 state store is unavailable".into()))?;
        let previous_state_commitment = state_commitment(guard)?;
        next_state.schema_version = 1;
        let new_state_commitment = state_commitment(&next_state)?;
        let record = journal.append(JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: operation.channel_id.clone(),
            channel_reuse_version: operation.reuse_version,
            operation_id: operation.operation_id.clone(),
            operation_type: JournalOperationType::L1ChannelOpen,
            operation_phase: phase,
            amount_units: operation.user_deposit_zhu,
            sender: operation.user_address.clone(),
            recipient: self.hub_address.clone(),
            previous_state_commitment,
            new_state_commitment: new_state_commitment.clone(),
            idempotency_key: operation.idempotency_key.clone(),
            request_commitment: operation.request_commitment.clone(),
            expected_bill_number: None,
            unsigned_state_commitment: Some(operation.partial_transaction_commitment.clone()),
            created_at: unix_timestamp(),
        })?;
        next_state.journal_sequence = record.entry_sequence;
        next_state.journal_head = record.entry_hash.clone();
        next_state.state_commitment = new_state_commitment.clone();
        if let Err(error) = store.save(&next_state) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: L1 journal advanced but channel-open state was not durable: {error}"
            )));
        }
        let head = JournalHead {
            sequence: record.entry_sequence,
            entry_hash: record.entry_hash,
            state_commitment: new_state_commitment,
        };
        if let Err(error) = journal.write_checkpoint(&head) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: channel-open state persisted but checkpoint did not: {error}"
            )));
        }
        *guard = next_state;
        self.refresh_recovery_gate(guard);
        Ok(())
    }
    async fn require_mainnet_channel_funding_ready(&self, amount_zhu: u64) -> HubResult<()> {
        let readiness = self.mainnet_readiness().await;
        if readiness.mainnet_detected == Some(false)
            && !is_mainnet_pilot_profile(&self.deployment_profile)
        {
            return Ok(());
        }
        readiness.require_channel_funding_ready_zhu(amount_zhu)
    }

    pub(super) async fn require_mainnet_cooperative_close_ready(
        &self,
        requires_principal_transfer: bool,
    ) -> HubResult<()> {
        let readiness = self.mainnet_readiness().await;
        if readiness.mainnet_detected == Some(false)
            && !is_mainnet_pilot_profile(&self.deployment_profile)
        {
            return Ok(());
        }
        readiness.require_cooperative_close_ready(requires_principal_transfer)
    }

    async fn require_mainnet_payment_ready(&self, amount: HacAmount) -> HubResult<()> {
        let readiness = self.mainnet_readiness().await;
        if readiness.mainnet_detected == Some(false)
            && !is_mainnet_pilot_profile(&self.deployment_profile)
        {
            return Ok(());
        }
        readiness.require_payment_ready(amount)
    }

    fn require_mainnet_payment_admission(&self, payer: &str) -> HubResult<()> {
        if !is_mainnet_pilot_profile(&self.deployment_profile) {
            return Ok(());
        }
        require_pilot_payment_admission(&self.mainnet_admission_policy, payer)
    }

    pub fn payment_status(&self, payment_id: &str) -> Option<FastPayResponse> {
        let state = self.inner.read().ok()?;
        if let Some(payment) = state.payments.get(payment_id) {
            return Some(payment.clone());
        }
        let pending = state.pending.get(payment_id)?;
        if unix_timestamp().saturating_sub(pending.created_at) > PENDING_TTL_SECONDS {
            if pending.status.signature_may_exist() {
                let mut response = pending.response.clone();
                response.status = "recovery_required".into();
                response.summary = Some(
                    "Fast Pay has a durable signed reservation and requires reconciliation".into(),
                );
                return Some(response);
            }
            return Some(FastPayResponse {
                payment_id: payment_id.to_owned(),
                status: "expired".into(),
                bill_hex: None,
                summary: Some("Fast Pay expired before any signature was produced".into()),
            });
        }
        Some(pending.response.clone())
    }

    pub fn recipient_inbox(&self, payee: &str) -> Vec<FastPayInboxItem> {
        let now = unix_timestamp();
        let mut items = self
            .inner
            .read()
            .ok()
            .map(|state| {
                state
                    .pending
                    .iter()
                    .filter_map(|(payment_id, pending)| {
                        let payee_channel_id = pending.payee_channel_id.as_ref()?;
                        let bill_hex = pending.response.bill_hex.as_ref()?;
                        if pending.payee != payee
                            || pending.response.status != "awaiting_recipient"
                            || now.saturating_sub(pending.created_at) > PENDING_TTL_SECONDS
                        {
                            return None;
                        }
                        Some(FastPayInboxItem {
                            payment_id: payment_id.clone(),
                            idempotency_key: pending.idempotency_key.clone(),
                            payer: pending.payer.clone(),
                            payee: pending.payee.clone(),
                            amount: pending.amount.clone(),
                            channel_id: pending.channel_id.clone(),
                            payee_channel_id: payee_channel_id.clone(),
                            status: pending.response.status.clone(),
                            bill_hex: bill_hex.clone(),
                            summary: pending.response.summary.clone(),
                            created_at: pending.created_at,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        items.sort_by_key(|item| std::cmp::Reverse(item.created_at));
        items
    }

    pub async fn settle_fast_pay(
        &self,
        request: &crate::api::FastPayRequest,
    ) -> HubResult<FastPayResponse> {
        self.ensure_settlement_ready()?;
        validate_operation_identity(request)?;
        let amount_mei = parse_amount_mei(request.amount.trim())?;
        if amount_mei == HacAmount::ZERO {
            return Err(HubError::Payment("amount must be positive".into()));
        }
        // This is also required on crash recovery: no old persisted reservation
        // can regain signing authority after the fullnode readiness turns red.
        self.require_mainnet_payment_ready(amount_mei).await?;
        self.require_mainnet_payment_admission(request.payer.trim())?;
        let request_commitment = request_commitment(request);
        if let Some(response) = self
            .resume_persisted_before_signing(request, &request_commitment)
            .await?
        {
            return Ok(response);
        }
        if let Some(response) = self.idempotent_response(request, &request_commitment)? {
            return Ok(response);
        }
        let signer = self.hub_signer.as_ref().ok_or_else(|| {
            HubError::State(
                "hub settlement signer is not configured; refusing to prepare a payment".into(),
            )
        })?;
        let payer = request.payer.trim();
        let payee = request.payee.trim();
        let channel_id = request.channel_id.trim();
        if payer.is_empty() || payee.is_empty() || payer == payee {
            return Err(HubError::Payment(
                "payer and payee must be different valid addresses".into(),
            ));
        }
        if payer == self.hub_address {
            return Err(HubError::Payment(
                "the reference hub accepts customer-originated payments only".into(),
            ));
        }

        let payer_channel = self.node.query_channel(channel_id).await?;
        if !payer_channel.is_open() {
            return Err(HubError::Channel("payer channel is not open".into()));
        }
        if payer_channel.id != channel_id {
            return Err(HubError::Channel("payer channel id mismatch".into()));
        }
        let payer_side = payer_channel
            .party_side(payer)
            .ok_or_else(|| HubError::Payment(format!("payer {payer} not in payer channel")))?;
        let hub_side = payer_channel.party_side(&self.hub_address).ok_or_else(|| {
            HubError::Payment("payer channel is not connected to this hub".into())
        })?;
        if hub_side == payer_side {
            return Err(HubError::Payment(
                "payer and hub cannot occupy the same channel side".into(),
            ));
        }

        let payee_route = resolve_payee_route(
            &self.node,
            &self.hub_address,
            &payer_channel,
            channel_id,
            payee,
        )
        .await?;

        let payee_channel_l1 = match &payee_route {
            PayeeRoute::CrossChannel { channel_id, .. } => {
                let channel = self.node.query_channel(channel_id).await?;
                if !channel.is_open()
                    || channel.id != *channel_id
                    || channel.party_side(payee).is_none()
                    || channel.party_side(&self.hub_address).is_none()
                {
                    return Err(HubError::Payment(
                        "recipient Fast Pay channel is not open or is not connected to this hub"
                            .into(),
                    ));
                }
                Some(channel)
            }
            PayeeRoute::SameChannel { .. } => None,
        };

        let timestamp = unix_timestamp();
        let (mut documents, payment_id, summary, pending) = {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            if let Some(response) =
                idempotent_response_from_state(&guard, request, &request_commitment)?
            {
                return Ok(response);
            }
            let active_pending = guard
                .pending
                .values()
                .filter(|pending| !pending.status.is_terminal())
                .count();
            if active_pending >= MAX_PENDING_SETTLEMENTS {
                return Err(HubError::State(
                    "too many active settlements; retry after pending proposals expire".into(),
                ));
            }

            let payee_channel_id = payee_channel_l1.as_ref().map(|channel| channel.id.as_str());
            require_channels_accept_payments(
                &guard,
                &payer_channel,
                payee_channel_l1.as_ref(),
                &self.hub_address,
                is_mainnet_pilot_profile(&self.deployment_profile),
            )?;
            if guard.pending.values().any(|pending| {
                if pending.status.is_terminal() {
                    return false;
                }
                let pending_payee_channel = pending.payee_channel_id.as_deref();
                pending.channel_id == channel_id
                    || pending_payee_channel == Some(channel_id)
                    || payee_channel_id == Some(pending.channel_id.as_str())
                    || (payee_channel_id.is_some() && payee_channel_id == pending_payee_channel)
            }) {
                return Err(HubError::State(
                "channel has an active Fast Pay reservation; reconcile it before another payment"
                    .into(),
            ));
            }

            let initial_payer_ledger = channel_ledger_from_l1(&payer_channel)?;
            let base_ledger = guard
                .channels
                .get(channel_id)
                .cloned()
                .unwrap_or(initial_payer_ledger);
            if payer_available_mei(&base_ledger, payer_side) < amount_mei {
                return Err(HubError::Payment(format!(
                    "insufficient channel balance: need {amount_mei} HAC"
                )));
            }
            let mut next_ledger = base_ledger.clone();
            apply_debit(&mut next_ledger, payer_side, amount_mei)?;
            next_ledger.bill_auto_number = next_bill_auto_number(&base_ledger, &payer_channel)?;

            let (route_label, payee_channel_id, payee_base_ledger, payee_next_ledger, payee_side) =
                match &payee_route {
                    PayeeRoute::SameChannel { side } => {
                        apply_credit(&mut next_ledger, *side, amount_mei)?;
                        ("same_channel", None, None, None, None)
                    }
                    PayeeRoute::CrossChannel { channel_id, side } => {
                        apply_credit(&mut next_ledger, hub_side, amount_mei)?;
                        let payee_channel = payee_channel_l1
                            .as_ref()
                            .ok_or_else(|| HubError::State("recipient channel missing".into()))?;
                        let payee_hub_side =
                            payee_channel.party_side(&self.hub_address).ok_or_else(|| {
                                HubError::State("hub missing from recipient channel".into())
                            })?;
                        if payee_hub_side == *side {
                            return Err(HubError::Payment(
                                "recipient and hub cannot occupy the same channel side".into(),
                            ));
                        }
                        let initial_payee_ledger = channel_ledger_from_l1(payee_channel)?;
                        let base = guard
                            .channels
                            .get(channel_id)
                            .cloned()
                            .unwrap_or(initial_payee_ledger);
                        if payer_available_mei(&base, payee_hub_side) < amount_mei {
                            return Err(HubError::Payment(format!(
                                "hub has insufficient recipient-channel liquidity: need {amount_mei} HAC"
                            )));
                        }
                        let mut next = base.clone();
                        apply_debit(&mut next, payee_hub_side, amount_mei)?;
                        apply_credit(&mut next, *side, amount_mei)?;
                        next.bill_auto_number = next_bill_auto_number(&base, payee_channel)?;
                        (
                            "cross_channel",
                            Some(channel_id.clone()),
                            Some(base),
                            Some(next),
                            Some(*side),
                        )
                    }
                };

            let payer_wire = ChannelWireInput {
                channel: payer_channel.clone(),
                channel_id_hex: channel_id.to_owned(),
                left_balance_mei: next_ledger.left_balance_mei,
                right_balance_mei: next_ledger.right_balance_mei,
                left_satoshi: payer_channel.left.satoshi,
                right_satoshi: payer_channel.right.satoshi,
                bill_auto_number: next_ledger.bill_auto_number,
            };

            let documents = if route_label == "same_channel" {
                build_same_channel_bill(&payer_wire, payer_side, amount_mei, timestamp)?
            } else {
                let payee_channel = payee_channel_l1
                    .as_ref()
                    .ok_or_else(|| HubError::State("recipient channel missing".into()))?;
                let payee_channel_id = payee_channel_id
                    .as_ref()
                    .ok_or_else(|| HubError::State("recipient channel id missing".into()))?;
                let payee_ledger = payee_next_ledger
                    .as_ref()
                    .ok_or_else(|| HubError::State("recipient ledger missing".into()))?;
                let payee_wire = ChannelWireInput {
                    channel: payee_channel.clone(),
                    channel_id_hex: payee_channel_id.clone(),
                    left_balance_mei: payee_ledger.left_balance_mei,
                    right_balance_mei: payee_ledger.right_balance_mei,
                    left_satoshi: payee_channel.left.satoshi,
                    right_satoshi: payee_channel.right.satoshi,
                    bill_auto_number: payee_ledger.bill_auto_number,
                };
                build_cross_channel_bill(
                    &payer_wire,
                    payer_side,
                    amount_mei,
                    &payee_wire,
                    payee_side.ok_or_else(|| HubError::State("recipient side missing".into()))?,
                    amount_mei,
                    timestamp,
                )?
            };
            let payment_id = request.operation_id.clone();
            let unsigned_state_commitment = hex::encode(documents.chain_payment.sign_stuff_hash());
            let summary = if route_label == "same_channel" {
                format!("Fast Pay prepared {amount_mei} HAC to {payee} on-channel with no fee")
            } else {
                format!(
                    "Fast Pay prepared {amount_mei} HAC to {payee}; waiting for recipient confirmation with no fee"
                )
            };
            let unsigned_response = FastPayResponse {
                payment_id: payment_id.clone(),
                status: "persisted_before_signing".into(),
                bill_hex: Some(documents.to_bill_hex()),
                summary: Some(summary.clone()),
            };
            let pending = PendingSettlement {
                created_at: timestamp,
                operation_id: payment_id.clone(),
                idempotency_key: request.idempotency_key.clone(),
                request_commitment: request_commitment.clone(),
                status: ReservationStatus::PersistedBeforeSigning,
                unsigned_state_commitment: unsigned_state_commitment.clone(),
                payer: payer.to_owned(),
                payee: payee.to_owned(),
                amount: format_amount_mei(amount_mei),
                channel_id: channel_id.to_owned(),
                channel_reuse_version: payer_channel.reuse_version,
                base_ledger,
                next_ledger,
                payee_channel_id,
                payee_base_ledger,
                payee_next_ledger,
                response: unsigned_response,
            };

            let mut next_state = guard.clone();
            next_state.idempotency.insert(
                request.idempotency_key.clone(),
                IdempotencyRecord {
                    operation_id: payment_id.clone(),
                    request_commitment: request_commitment.clone(),
                    created_at: timestamp,
                },
            );
            next_state
                .pending
                .insert(payment_id.clone(), pending.clone());
            next_state
                .channels
                .entry(pending.channel_id.clone())
                .or_insert_with(|| pending.base_ledger.clone());
            if let (Some(channel_id), Some(base)) = (
                pending.payee_channel_id.clone(),
                pending.payee_base_ledger.clone(),
            ) {
                next_state.channels.entry(channel_id).or_insert(base);
            }
            self.commit_transition(
                &mut guard,
                next_state,
                &pending,
                JournalPhase::StatePersistedBeforeSigning,
            )?;
            (documents, payment_id, summary, pending)
        };

        // The write guard's lexical scope ended above. Re-fetch the
        // authoritative gate immediately before creating a signature.
        self.require_mainnet_payment_ready(amount_mei).await?;
        self.require_mainnet_payment_admission(payer)?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        // A close/open recovery transition uses the same write lock when it
        // raises the global gate. Rechecking while holding this guard closes
        // the last race between the authoritative readiness probe and signing.
        self.ensure_settlement_ready()?;
        let current = guard
            .pending
            .get(&payment_id)
            .ok_or_else(|| HubError::State("durable reservation disappeared".into()))?;
        if current.status != ReservationStatus::PersistedBeforeSigning
            || current.request_commitment != pending.request_commitment
            || current.unsigned_state_commitment != pending.unsigned_state_commitment
        {
            return Err(HubError::State(
                "RecoveryRequired: durable reservation changed before signing".into(),
            ));
        }

        // The exact reservation and unsigned sign hash are durable and the
        // authoritative mainnet gate was re-fetched immediately before signing.
        signer.sign_documents(&mut documents)?;
        if !documents
            .chain_payment
            .signature_verified_for_readable(&self.hub_address)
        {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(
                "hub failed to verify its own settlement signature".into(),
            ));
        }

        let response = FastPayResponse {
            payment_id: payment_id.clone(),
            status: "pending".into(),
            bill_hex: Some(documents.to_bill_hex()),
            summary: Some(summary),
        };
        let mut signed_pending = guard
            .pending
            .get(&payment_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable reservation disappeared".into()))?;
        signed_pending.status = ReservationStatus::Signed;
        signed_pending.response = response.clone();
        let mut signed_state = guard.clone();
        signed_state
            .pending
            .insert(payment_id, signed_pending.clone());
        self.commit_transition(
            &mut guard,
            signed_state,
            &signed_pending,
            JournalPhase::SignatureProduced,
        )?;
        Ok(response)
    }

    pub fn confirm_fast_pay(
        &self,
        payment_id: &str,
        idempotency_key: &str,
        signed_bill_hex: &str,
    ) -> HubResult<FastPayResponse> {
        self.ensure_settlement_ready()?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        if let Some(completed) = guard.payments.get(payment_id) {
            if guard
                .idempotency
                .get(idempotency_key)
                .is_none_or(|record| record.operation_id != payment_id)
            {
                return Err(HubError::Payment(
                    "idempotency conflict: confirmation key changed".into(),
                ));
            }
            let final_hex = completed
                .bill_hex
                .as_deref()
                .ok_or_else(|| HubError::State("completed payment bill missing".into()))?;
            let final_bill = ChannelPayCompleteDocuments::from_bill_hex(final_hex)?;
            let submitted = ChannelPayCompleteDocuments::from_bill_hex(signed_bill_hex)?;
            if final_bill.chain_payment.sign_stuff_hash()
                != submitted.chain_payment.sign_stuff_hash()
            {
                return Err(HubError::Payment(
                    "idempotency conflict: confirmation payload changed".into(),
                ));
            }
            return Ok(completed.clone());
        }
        let mut pending = guard
            .pending
            .get(payment_id)
            .cloned()
            .ok_or_else(|| HubError::NotFound(format!("pending payment {payment_id}")))?;
        if pending.idempotency_key != idempotency_key {
            return Err(HubError::Payment(
                "idempotency conflict: confirmation key changed".into(),
            ));
        }
        require_persisted_channels_accept_payments(
            &guard,
            &pending.channel_id,
            pending.payee_channel_id.as_deref(),
            is_mainnet_pilot_profile(&self.deployment_profile),
        )?;

        if unix_timestamp().saturating_sub(pending.created_at) > PENDING_TTL_SECONDS
            && pending.status.signature_may_exist()
        {
            pending.status = ReservationStatus::RecoveryRequired;
            pending.response.status = "recovery_required".into();
            pending.response.summary =
                Some("signed Fast Pay reservation expired and requires reconciliation".into());
            let mut next_state = guard.clone();
            next_state
                .pending
                .insert(payment_id.to_owned(), pending.clone());
            self.commit_transition(
                &mut guard,
                next_state,
                &pending,
                JournalPhase::RecoveryStarted,
            )?;
            return Err(HubError::State("RecoveryRequired".into()));
        }

        let expected_hex = pending
            .response
            .bill_hex
            .as_deref()
            .ok_or_else(|| HubError::State("pending settlement bill missing".into()))?;
        let mut expected = ChannelPayCompleteDocuments::from_bill_hex(expected_hex)?;
        let submitted = ChannelPayCompleteDocuments::from_bill_hex(signed_bill_hex)?;
        if !expected.prove_bindings_valid() || !submitted.prove_bindings_valid() {
            return Err(HubError::Payment(
                "settlement prove bodies do not match the signed channel checkers".into(),
            ));
        }
        if expected.chain_payment.sign_stuff_hash() != submitted.chain_payment.sign_stuff_hash() {
            return Err(HubError::Payment(
                "confirmed settlement does not match the prepared bill".into(),
            ));
        }
        expected
            .chain_payment
            .merge_verified_signatures(&submitted.chain_payment)?;

        if !expected
            .chain_payment
            .signature_verified_for_readable(&self.hub_address)
        {
            return Err(HubError::Payment(
                "confirmed settlement is missing the verified hub signature".into(),
            ));
        }
        if pending.payer.is_empty()
            || !expected
                .chain_payment
                .signature_verified_for_readable(&pending.payer)
        {
            return Err(HubError::Payment(
                "confirmed settlement is missing the verified payer signature".into(),
            ));
        }

        let merged_bill_hex = expected.to_bill_hex();
        let is_cross_channel = pending.payee_channel_id.is_some();
        if is_cross_channel && !expected.chain_payment.all_signatures_verified() {
            let mut awaiting = pending.clone();
            awaiting.response.status = "awaiting_recipient".into();
            awaiting.response.bill_hex = Some(merged_bill_hex);
            awaiting.response.summary = Some(format!(
                "Fast Pay {} HAC from {} is waiting for recipient confirmation",
                pending.amount, pending.payer
            ));
            awaiting.status = ReservationStatus::AwaitingRecipientConfirmation;
            let response = awaiting.response.clone();
            let mut next_state = guard.clone();
            next_state
                .pending
                .insert(payment_id.to_owned(), awaiting.clone());
            self.commit_transition(
                &mut guard,
                next_state,
                &awaiting,
                JournalPhase::RecipientConfirmed,
            )?;
            return Ok(response);
        }

        if !expected.chain_payment.all_signatures_verified() {
            return Err(HubError::Payment(
                "confirmed settlement is missing required verified signatures".into(),
            ));
        }
        if is_cross_channel
            && (pending.payee.is_empty()
                || !expected
                    .chain_payment
                    .signature_verified_for_readable(&pending.payee))
        {
            return Err(HubError::Payment(
                "confirmed routed settlement is missing the verified recipient signature".into(),
            ));
        }

        let payer_is_current = guard
            .channels
            .get(&pending.channel_id)
            .is_some_and(|ledger| ledger == &pending.base_ledger);
        let payee_is_current = match (
            pending.payee_channel_id.as_ref(),
            pending.payee_base_ledger.as_ref(),
        ) {
            (Some(channel_id), Some(base)) => guard
                .channels
                .get(channel_id)
                .is_some_and(|ledger| ledger == base),
            (None, None) => true,
            _ => false,
        };
        if !payer_is_current || !payee_is_current {
            let mut recovery = pending.clone();
            recovery.status = ReservationStatus::RecoveryRequired;
            recovery.response.status = "recovery_required".into();
            recovery.response.summary = Some(
                "prepared settlement conflicts with current channel state; reconciliation required"
                    .into(),
            );
            let mut next_state = guard.clone();
            next_state
                .pending
                .insert(payment_id.to_owned(), recovery.clone());
            self.commit_transition(
                &mut guard,
                next_state,
                &recovery,
                JournalPhase::RecoveryStarted,
            )?;
            return Err(HubError::State("ChannelStateRollbackDetected".into()));
        }

        let summary = if is_cross_channel {
            Some(format!(
                "Fast Pay settled {} HAC to {} with no fee",
                pending.amount, pending.payee
            ))
        } else {
            pending
                .response
                .summary
                .clone()
                .map(|summary| summary.replace("prepared", "settled"))
        };
        let response = FastPayResponse {
            payment_id: payment_id.to_owned(),
            status: "settled".into(),
            bill_hex: Some(merged_bill_hex),
            summary,
        };

        let mut next_state = guard.clone();
        next_state
            .channels
            .insert(pending.channel_id.clone(), pending.next_ledger.clone());
        if let (Some(channel_id), Some(next_ledger)) = (
            pending.payee_channel_id.clone(),
            pending.payee_next_ledger.clone(),
        ) {
            next_state.channels.insert(channel_id, next_ledger);
        }
        next_state.pending.remove(payment_id);
        next_state
            .payments
            .insert(payment_id.to_owned(), response.clone());
        next_state
            .completed_request_commitments
            .insert(payment_id.to_owned(), pending.request_commitment.clone());
        let mut committed = pending;
        committed.status = ReservationStatus::Committed;
        committed.response = response.clone();
        self.commit_transition(
            &mut guard,
            next_state,
            &committed,
            JournalPhase::PaymentCommitted,
        )?;
        Ok(response)
    }

    fn ensure_settlement_ready(&self) -> HubResult<()> {
        if self.recovery_required.load(Ordering::Acquire) {
            return Err(HubError::State("RecoveryRequired".into()));
        }
        if self.state_store.is_none() || self.journal.is_none() {
            return Err(HubError::State(
                "durable authenticated L2 storage is required before signing".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_l1_open_recovery_allowed(
        &self,
        state: &HubPersistedState,
        operation_id: &str,
    ) -> HubResult<()> {
        if !self.recovery_required.load(Ordering::Acquire) {
            return self.ensure_settlement_ready();
        }
        let matching_open = state.l1_channel_opens.values().any(|operation| {
            operation.operation_id == operation_id
                && operation.status == L1ChannelOpenStatus::RecoveryRequired
                && terminal_transaction_evidence_is_valid(
                    operation.signed_transaction_hex.as_deref(),
                    operation.signed_transaction_commitment.as_deref(),
                    Some(&operation.transaction_hash),
                )
        });
        let unrelated_recovery = state
            .pending
            .values()
            .any(|pending| pending.status == ReservationStatus::RecoveryRequired)
            || state.l1_channel_opens.values().any(|operation| {
                operation.operation_id != operation_id
                    && operation.status == L1ChannelOpenStatus::RecoveryRequired
            })
            || state.l1_channel_closes.values().any(|operation| {
                operation.status == crate::storage::L1ChannelCloseStatus::RecoveryRequired
            })
            || state.channel_lifecycle.values().any(|lifecycle| {
                lifecycle.status == crate::storage::ChannelLifecycleStatus::RecoveryRequired
            });
        if !matching_open || unrelated_recovery {
            return Err(HubError::State("RecoveryRequired".into()));
        }
        self.ensure_durable_storage_ready()
    }

    pub(super) fn ensure_l1_close_recovery_allowed(
        &self,
        state: &HubPersistedState,
        operation_id: &str,
    ) -> HubResult<()> {
        if !self.recovery_required.load(Ordering::Acquire) {
            return self.ensure_settlement_ready();
        }
        let matching_close = state.l1_channel_closes.values().any(|operation| {
            operation.operation_id == operation_id
                && operation.status == crate::storage::L1ChannelCloseStatus::RecoveryRequired
                && operation.final_ledger.is_some()
                && state.channels.get(&operation.channel_id) == operation.final_ledger.as_ref()
                && terminal_transaction_evidence_is_valid(
                    operation.signed_transaction_hex.as_deref(),
                    operation.signed_transaction_commitment.as_deref(),
                    operation.transaction_hash.as_deref(),
                )
                && state
                    .channel_lifecycle
                    .get(&operation.channel_id)
                    .is_some_and(|lifecycle| {
                        lifecycle.operation_id == operation.operation_id
                            && lifecycle.channel_id == operation.channel_id
                            && lifecycle.reuse_version == operation.reuse_version
                            && lifecycle.open_height == operation.open_height
                            && lifecycle.status
                                == crate::storage::ChannelLifecycleStatus::RecoveryRequired
                            && operation.final_ledger.as_ref().is_some_and(|ledger| {
                                close::ledger_commitment(ledger).is_ok_and(|commitment| {
                                    lifecycle.state_commitment == commitment
                                })
                            })
                    })
        });
        let unrelated_recovery = state
            .pending
            .values()
            .any(|pending| pending.status == ReservationStatus::RecoveryRequired)
            || state
                .l1_channel_opens
                .values()
                .any(|operation| operation.status == L1ChannelOpenStatus::RecoveryRequired)
            || state.l1_channel_closes.values().any(|operation| {
                operation.operation_id != operation_id
                    && operation.status == crate::storage::L1ChannelCloseStatus::RecoveryRequired
            })
            || state.channel_lifecycle.values().any(|lifecycle| {
                lifecycle.status == crate::storage::ChannelLifecycleStatus::RecoveryRequired
                    && lifecycle.operation_id != operation_id
            });
        if !matching_close || unrelated_recovery {
            return Err(HubError::State("RecoveryRequired".into()));
        }
        self.ensure_durable_storage_ready()
    }

    fn ensure_durable_storage_ready(&self) -> HubResult<()> {
        if self.state_store.is_none() || self.journal.is_none() {
            return Err(HubError::State(
                "durable authenticated L2 storage is required before recovery".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn refresh_recovery_gate(&self, state: &HubPersistedState) {
        self.recovery_required
            .store(persisted_state_requires_recovery(state), Ordering::Release);
    }

    async fn resume_persisted_before_signing(
        &self,
        request: &crate::api::FastPayRequest,
        commitment: &str,
    ) -> HubResult<Option<FastPayResponse>> {
        let pending = {
            let state = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let Some(response) = idempotent_response_from_state(&state, request, commitment)?
            else {
                return Ok(None);
            };
            let Some(pending) = state.pending.get(&response.payment_id) else {
                return Ok(None);
            };
            if pending.status != ReservationStatus::PersistedBeforeSigning {
                return Ok(None);
            }
            pending.clone()
        };

        if unix_timestamp().saturating_sub(pending.created_at) > PENDING_TTL_SECONDS {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            let current = guard
                .pending
                .get(&pending.operation_id)
                .cloned()
                .ok_or_else(|| HubError::State("durable reservation disappeared".into()))?;
            if current.status != ReservationStatus::PersistedBeforeSigning {
                return idempotent_response_from_state(&guard, request, commitment);
            }
            if current.request_commitment != pending.request_commitment
                || current.unsigned_state_commitment != pending.unsigned_state_commitment
            {
                return Err(HubError::State(
                    "RecoveryRequired: expired unsigned reservation changed".into(),
                ));
            }
            let response = FastPayResponse {
                payment_id: current.operation_id.clone(),
                status: "expired".into(),
                bill_hex: None,
                summary: Some("Fast Pay expired before any signature was produced".into()),
            };
            let mut expired = current;
            expired.status = ReservationStatus::Expired;
            expired.response = response.clone();
            let mut next_state = guard.clone();
            next_state
                .pending
                .insert(expired.operation_id.clone(), expired.clone());
            self.commit_transition(
                &mut guard,
                next_state,
                &expired,
                JournalPhase::PaymentExpired,
            )?;
            return Ok(Some(response));
        }

        let signer = self
            .hub_signer
            .as_ref()
            .ok_or_else(|| HubError::State("hub settlement signer is not configured".into()))?;
        let unsigned_hex =
            pending.response.bill_hex.as_deref().ok_or_else(|| {
                HubError::State("durable unsigned settlement bill is missing".into())
            })?;
        let mut documents = ChannelPayCompleteDocuments::from_bill_hex(unsigned_hex)?;
        if !documents.prove_bindings_valid()
            || hex::encode(documents.chain_payment.sign_stuff_hash())
                != pending.unsigned_state_commitment
        {
            return Err(HubError::State(
                "RecoveryRequired: durable unsigned settlement commitment is invalid".into(),
            ));
        }
        let amount = parse_amount_mei(&pending.amount)?;
        self.require_mainnet_payment_ready(amount).await?;
        self.require_mainnet_payment_admission(&pending.payer)?;
        signer.sign_documents(&mut documents)?;
        if !documents
            .chain_payment
            .signature_verified_for_readable(&self.hub_address)
        {
            return Err(HubError::State(
                "hub failed to verify its recovered settlement signature".into(),
            ));
        }

        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let current = guard
            .pending
            .get(&pending.operation_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable reservation disappeared".into()))?;
        if current.status != ReservationStatus::PersistedBeforeSigning {
            return idempotent_response_from_state(&guard, request, commitment);
        }
        if current.request_commitment != pending.request_commitment
            || current.unsigned_state_commitment != pending.unsigned_state_commitment
        {
            return Err(HubError::State(
                "RecoveryRequired: durable reservation changed during signature recovery".into(),
            ));
        }
        let response = FastPayResponse {
            payment_id: current.operation_id.clone(),
            status: "pending".into(),
            bill_hex: Some(documents.to_bill_hex()),
            summary: current.response.summary.clone(),
        };
        let mut signed = current;
        signed.status = ReservationStatus::Signed;
        signed.response = response.clone();
        let mut next_state = guard.clone();
        next_state
            .pending
            .insert(signed.operation_id.clone(), signed.clone());
        self.commit_transition(
            &mut guard,
            next_state,
            &signed,
            JournalPhase::SignatureProduced,
        )?;
        Ok(Some(response))
    }

    fn idempotent_response(
        &self,
        request: &crate::api::FastPayRequest,
        commitment: &str,
    ) -> HubResult<Option<FastPayResponse>> {
        let state = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        idempotent_response_from_state(&state, request, commitment)
    }

    fn commit_transition(
        &self,
        guard: &mut HubPersistedState,
        mut next_state: HubPersistedState,
        operation: &PendingSettlement,
        phase: JournalPhase,
    ) -> HubResult<()> {
        self.ensure_settlement_ready()?;
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| HubError::State("authenticated L2 journal is unavailable".into()))?;
        let store = self
            .state_store
            .as_ref()
            .ok_or_else(|| HubError::State("durable L2 state store is unavailable".into()))?;
        let previous_state_commitment = state_commitment(guard)?;
        next_state.schema_version = 1;
        let new_state_commitment = state_commitment(&next_state)?;
        let amount = parse_amount_mei(&operation.amount)?;
        let record = journal.append(JournalEvent {
            wallet_scope: format!("hub:{}", self.hub_address.trim()),
            hub_or_provider_identity: self.hub_address.trim().to_owned(),
            channel_id: operation.channel_id.clone(),
            channel_reuse_version: operation.channel_reuse_version,
            operation_id: operation.operation_id.clone(),
            operation_type: JournalOperationType::FastPay,
            operation_phase: phase,
            amount_units: amount.as_millimeis(),
            sender: operation.payer.clone(),
            recipient: operation.payee.clone(),
            previous_state_commitment,
            new_state_commitment: new_state_commitment.clone(),
            idempotency_key: operation.idempotency_key.clone(),
            request_commitment: operation.request_commitment.clone(),
            expected_bill_number: Some(operation.next_ledger.bill_auto_number),
            unsigned_state_commitment: Some(operation.unsigned_state_commitment.clone()),
            created_at: unix_timestamp(),
        })?;
        next_state.journal_sequence = record.entry_sequence;
        next_state.journal_head = record.entry_hash.clone();
        next_state.state_commitment = new_state_commitment.clone();
        if let Err(error) = store.save(&next_state) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: journal advanced but materialized state was not durable: {error}"
            )));
        }
        let head = JournalHead {
            sequence: record.entry_sequence,
            entry_hash: record.entry_hash,
            state_commitment: new_state_commitment,
        };
        if let Err(error) = journal.write_checkpoint(&head) {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(format!(
                "RecoveryRequired: state persisted but checkpoint did not: {error}"
            )));
        }
        *guard = next_state;
        // Every other commit path in this file already does this
        // (`commit_channel_close_transition`, the open path, the HVM paths).
        // The Fast Pay path did not, so the in-memory latch lagged the durable
        // state it is computed from: a reservation pushed to
        // `RecoveryRequired` here made the Hub refuse everything while
        // `/v1/health` went on reporting `settlement_ready: true` until some
        // unrelated call or a restart happened to recompute it. A surface that
        // reports healthy while the gate refuses everyone is the exact failure
        // this whole review exists to remove.
        self.refresh_recovery_gate(guard);
        Ok(())
    }
}

fn require_channel_open_target(
    observed: HubResult<crate::node::ChannelInfo>,
    intent: &crate::l1_channel::ValidatedChannelOpenIntent,
    _hub_address: &str,
) -> HubResult<()> {
    match observed {
        Ok(_) => Err(HubError::Channel(
            "mainnet pilot requires an unused deterministic channel ID; channel reuse is disabled"
                .into(),
        )),
        Err(HubError::NotFound(_)) if intent.expected_reuse_version == 1 => Ok(()),
        Err(HubError::NotFound(_)) => Err(HubError::Channel(
            "first channel incarnation must use reuse version 1".into(),
        )),
        Err(error) => Err(error),
    }
}

fn require_channels_accept_payments(
    state: &HubPersistedState,
    payer_channel: &crate::node::ChannelInfo,
    payee_channel: Option<&crate::node::ChannelInfo>,
    hub_address: &str,
    enforce_finality_anchor: bool,
) -> HubResult<()> {
    require_channel_ids_not_frozen(
        state,
        &payer_channel.id,
        payee_channel.map(|channel| channel.id.as_str()),
    )?;
    if enforce_finality_anchor {
        require_confirmed_open_anchor(state, payer_channel, hub_address)?;
        if let Some(channel) = payee_channel {
            require_confirmed_open_anchor(state, channel, hub_address)?;
        }
    }
    Ok(())
}

fn require_persisted_channels_accept_payments(
    state: &HubPersistedState,
    payer_channel_id: &str,
    payee_channel_id: Option<&str>,
    enforce_finality_anchor: bool,
) -> HubResult<()> {
    require_channel_ids_not_frozen(state, payer_channel_id, payee_channel_id)?;
    if !enforce_finality_anchor {
        return Ok(());
    }
    let channel_ids = std::iter::once(payer_channel_id).chain(payee_channel_id);
    for channel_id in channel_ids {
        let anchored = state.l1_channel_opens.values().any(|open| {
            open.channel_id.eq_ignore_ascii_case(channel_id)
                && open::confirmed_open_has_finality_evidence(open)
        });
        if !anchored || !state.channels.contains_key(channel_id) {
            return Err(HubError::Channel(
                "Fast Pay confirmation requires an HPAY channel-open with exact transaction evidence and six confirmations"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn require_channel_ids_not_frozen(
    state: &HubPersistedState,
    payer_channel_id: &str,
    payee_channel_id: Option<&str>,
) -> HubResult<()> {
    let frozen = state.channel_lifecycle.contains_key(payer_channel_id)
        || payee_channel_id
            .is_some_and(|channel_id| state.channel_lifecycle.contains_key(channel_id));
    if frozen {
        return Err(HubError::Channel(
            "channel is frozen or retired and cannot accept Fast Pay mutations".into(),
        ));
    }
    Ok(())
}

fn require_confirmed_open_anchor(
    state: &HubPersistedState,
    channel: &crate::node::ChannelInfo,
    hub_address: &str,
) -> HubResult<()> {
    let original = channel_ledger_from_l1(channel)?;
    let anchored = state.l1_channel_opens.values().any(|open| {
        open::confirmed_open_has_finality_evidence(open)
            && open.channel_id.eq_ignore_ascii_case(&channel.id)
            && open.reuse_version == channel.reuse_version
            && open.confirmed_block_height == Some(channel.open_height)
            && open.user_address == channel.left.address
            && channel.right.address == hub_address
            && open.user_deposit_zhu
                == original
                    .left_balance_mei
                    .as_millimeis()
                    .saturating_mul(crate::readiness::ZHU_PER_MILLIMEI)
            && original.right_balance_mei == HacAmount::ZERO
    });
    if !anchored || !state.channels.contains_key(&channel.id) {
        return Err(HubError::Channel(
            "Fast Pay requires an HPAY channel-open with exact transaction evidence and six confirmations"
                .into(),
        ));
    }
    Ok(())
}
fn existing_l1_channel_open_from_state(
    state: &HubPersistedState,
    request: &L1ChannelOpenRequest,
    commitment: &str,
) -> HubResult<Option<PersistedL1ChannelOpen>> {
    if let Some(operation) = state.l1_channel_opens.get(&request.operation_id) {
        if operation.request_commitment != commitment {
            return Err(HubError::Payment(
                "channel-open operation ID was already used for different request bytes".into(),
            ));
        }
        return Ok(Some(operation.clone()));
    }
    if let Some(operation_id) = state
        .l1_channel_open_idempotency
        .get(&request.idempotency_key)
    {
        let operation = state.l1_channel_opens.get(operation_id).ok_or_else(|| {
            HubError::State("channel-open idempotency index is inconsistent".into())
        })?;
        if operation.request_commitment != commitment {
            return Err(HubError::Payment(
                "idempotency key was already used for different channel-open bytes".into(),
            ));
        }
        return Ok(Some(operation.clone()));
    }
    if let Some(operation_id) = state
        .l1_channel_open_commitments
        .get(&request.partial_transaction_commitment)
    {
        let operation = state.l1_channel_opens.get(operation_id).ok_or_else(|| {
            HubError::State("channel-open commitment index is inconsistent".into())
        })?;
        if operation.request_commitment != commitment
            || operation.partial_transaction_hex != request.partial_transaction_hex
            || operation.channel_id != request.channel_id
        {
            return Err(HubError::Payment(
                "channel-open commitment maps to different request content".into(),
            ));
        }
        return Ok(Some(operation.clone()));
    }
    Ok(None)
}

fn l1_channel_open_response(
    operation: &PersistedL1ChannelOpen,
) -> HubResult<L1ChannelOpenResponse> {
    if !operation.status.has_durable_signature() {
        return Err(HubError::State(
            "channel-open signature is not durably available".into(),
        ));
    }
    Ok(L1ChannelOpenResponse {
        schema: L1_CHANNEL_OPEN_SCHEMA.to_owned(),
        operation_id: operation.operation_id.clone(),
        channel_id: operation.channel_id.clone(),
        status: "cosigned".to_owned(),
        signed_transaction_hex: operation
            .signed_transaction_hex
            .clone()
            .ok_or_else(|| HubError::State("durable channel-open signature is missing".into()))?,
        signed_transaction_commitment: operation
            .signed_transaction_commitment
            .clone()
            .ok_or_else(|| HubError::State("durable signed commitment is missing".into()))?,
        transaction_hash: operation.transaction_hash.clone(),
    })
}
fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn validate_terminal_l1_finality_evidence(state: &HubPersistedState) -> HubResult<()> {
    if state.l1_channel_opens.values().any(|operation| {
        operation.status == L1ChannelOpenStatus::Confirmed
            && !open::confirmed_open_has_finality_evidence(operation)
    }) {
        return Err(HubError::State(
            "RecoveryRequired: legacy confirmed channel-open lacks exact transaction finality evidence"
                .into(),
        ));
    }
    if state.l1_channel_closes.values().any(|operation| {
        operation.status == crate::storage::L1ChannelCloseStatus::Retired
            && !close::retired_close_has_finality_evidence(operation)
    }) {
        return Err(HubError::State(
            "RecoveryRequired: legacy retired channel-close lacks exact transaction finality evidence"
                .into(),
        ));
    }
    Ok(())
}

fn terminal_transaction_evidence_is_valid(
    signed_transaction_hex: Option<&str>,
    signed_transaction_commitment: Option<&str>,
    transaction_hash: Option<&str>,
) -> bool {
    let (Some(body_hex), Some(expected_commitment), Some(expected_hash)) = (
        signed_transaction_hex,
        signed_transaction_commitment,
        transaction_hash,
    ) else {
        return false;
    };
    let Ok(raw) = hex::decode(body_hex) else {
        return false;
    };
    if raw.is_empty() || raw.len() > crate::l1_channel::MAX_CHANNEL_TRANSACTION_BYTES {
        return false;
    }
    if !hex::encode(Sha256::digest(&raw)).eq_ignore_ascii_case(expected_commitment) {
        return false;
    }
    crate::protocol_registry::ensure_hacash_protocol_setup();
    let Ok((transaction, consumed)) = protocol::transaction::transaction_create(&raw) else {
        return false;
    };
    consumed == raw.len()
        && hex::encode(transaction.hash().as_bytes()).eq_ignore_ascii_case(expected_hash)
        && transaction.verify_signature().is_ok()
}

fn persisted_state_requires_recovery(state: &HubPersistedState) -> bool {
    state
        .pending
        .values()
        .any(|pending| pending.status == ReservationStatus::RecoveryRequired)
        || state
            .l1_channel_opens
            .values()
            .any(|operation| operation.status == L1ChannelOpenStatus::RecoveryRequired)
        || state.l1_channel_closes.values().any(|operation| {
            operation.status == crate::storage::L1ChannelCloseStatus::RecoveryRequired
        })
        || state.channel_lifecycle.values().any(|lifecycle| {
            lifecycle.status == crate::storage::ChannelLifecycleStatus::RecoveryRequired
        })
        || state.hvm_bill_progressions.values().any(|progression| {
            matches!(
                progression.status,
                crate::hvm_ledger::HvmBillProgressionStatus::HubSignatureMayExist
                    | crate::hvm_ledger::HvmBillProgressionStatus::RecoveryRequired
            )
        })
        || state.hvm_registry_progressions.values().any(|progression| {
            matches!(
                progression.status,
                crate::hvm_ledger::HvmBillProgressionStatus::HubSignatureMayExist
                    | crate::hvm_ledger::HvmBillProgressionStatus::RecoveryRequired
            )
        })
        || state.hvm_chain_operations.values().any(|operation| {
            matches!(
                operation.status,
                crate::storage::HvmChainOperationStatus::SignatureMayExist
                    | crate::storage::HvmChainOperationStatus::Signed
                    | crate::storage::HvmChainOperationStatus::SubmissionStarted
                    | crate::storage::HvmChainOperationStatus::Submitted
                    | crate::storage::HvmChainOperationStatus::RecoveryRequired
            )
        })
        // `Abandoned` is absent from this list on purpose, and it is the only
        // status other than `Confirmed` that is. Every status listed here
        // leaves a signed transaction whose fate is still open, which is
        // exactly what the latch exists to protect. An abandoned operation has
        // no such transaction: its bytes were proven inadmissible by a rule
        // block verification itself applies, so they are in no valid block and
        // never will be offered to a node again. Releasing the latch for it is
        // the whole point of the transition.
        || state
            .hvm_registry_chain_operations
            .values()
            .any(|operation| {
                matches!(
                    operation.status,
                    crate::storage::HvmChainOperationStatus::SignatureMayExist
                        | crate::storage::HvmChainOperationStatus::Signed
                        | crate::storage::HvmChainOperationStatus::SubmissionStarted
                        | crate::storage::HvmChainOperationStatus::Submitted
                        | crate::storage::HvmChainOperationStatus::RecoveryRequired
                )
            })
}

#[cfg(test)]
mod channel_lifecycle_tests {
    use super::*;
    use crate::storage::{ChannelLifecycleStatus, PersistedChannelLifecycle};

    fn lifecycle(channel_id: &str) -> PersistedChannelLifecycle {
        PersistedChannelLifecycle {
            operation_id: "close-operation".into(),
            channel_id: channel_id.into(),
            reuse_version: 1,
            open_height: 100,
            status: ChannelLifecycleStatus::FrozenBeforeSigning,
            state_commitment: "commitment".into(),
            updated_unix: 1_700_000_000,
        }
    }

    #[test]
    fn frozen_payer_or_payee_channel_rejects_every_fast_pay_mutation() {
        let mut state = HubPersistedState::default();
        assert!(require_channel_ids_not_frozen(&state, "payer", Some("payee")).is_ok());
        state
            .channel_lifecycle
            .insert("payer".into(), lifecycle("payer"));
        assert!(require_channel_ids_not_frozen(&state, "payer", Some("payee")).is_err());
        state.channel_lifecycle.clear();
        state
            .channel_lifecycle
            .insert("payee".into(), lifecycle("payee"));
        assert!(require_channel_ids_not_frozen(&state, "payer", Some("payee")).is_err());
    }
}

#[cfg(test)]
mod mainnet_admission_tests {
    use super::*;

    const ALLOWED_USER: &str = "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW";
    const OTHER_USER: &str = "18fT8iUWkcsJaKrQRVVad6BtRTt3GteZHa";

    fn pending_open(status: L1ChannelOpenStatus, deposit_zhu: u64) -> PersistedL1ChannelOpen {
        PersistedL1ChannelOpen {
            operation_id: "pending-open".into(),
            idempotency_key: "pending-open-idempotency".into(),
            request_commitment: "request".into(),
            network: String::new(),
            chain_id: 0,
            mainnet: false,
            block_1_hash: String::new(),
            node_profile_id: String::new(),
            network_instance_id: String::new(),
            transaction_format_version: 0,
            channel_id: "channel".into(),
            reuse_version: 1,
            user_address: ALLOWED_USER.into(),
            user_deposit_zhu: deposit_zhu,
            network_fee_zhu: 100_000,
            partial_transaction_hex: "00".into(),
            partial_transaction_commitment: "partial".into(),
            transaction_hash: "hash".into(),
            signed_transaction_hex: None,
            signed_transaction_commitment: None,
            confirmed_block_height: None,
            broadcast_height: None,
            observed_confirmations: 0,
            status,
            created_unix: 1,
            expires_unix: 2,
            updated_unix: 1,
            last_error: None,
        }
    }

    #[test]
    fn allowlist_and_aggregate_tvl_are_enforced_before_channel_admission() {
        let policy = MainnetPilotAdmissionPolicy::try_new([ALLOWED_USER], 100_000_000).unwrap();
        let mut state = HubPersistedState::default();
        state.channels.insert(
            "active".into(),
            ChannelLedger {
                left_balance_mei: HacAmount::from_millimeis(980),
                right_balance_mei: HacAmount::ZERO,
                bill_auto_number: 1,
            },
        );
        state.l1_channel_opens.insert(
            "pending-open".into(),
            pending_open(L1ChannelOpenStatus::Signed, 1_000_000),
        );

        assert_eq!(aggregate_pilot_tvl_zhu(&state).unwrap(), 99_000_000);
        require_pilot_admission(&policy, &state, ALLOWED_USER, 1_000_000).unwrap();
        assert!(
            require_pilot_admission(&policy, &state, ALLOWED_USER, 1_000_001)
                .unwrap_err()
                .to_string()
                .contains("aggregate Hub TVL cap exceeded")
        );
        assert!(
            require_pilot_admission(&policy, &state, OTHER_USER, 1_000_000)
                .unwrap_err()
                .to_string()
                .contains("not allowlisted")
        );
        assert!(
            require_pilot_admission(
                &MainnetPilotAdmissionPolicy::default(),
                &state,
                ALLOWED_USER,
                1_000_000,
            )
            .is_err()
        );
    }

    #[test]
    fn payment_payer_must_remain_allowlisted() {
        let policy = MainnetPilotAdmissionPolicy::try_new([ALLOWED_USER], 100_000_000).unwrap();
        require_pilot_payment_admission(&policy, ALLOWED_USER).unwrap();
        assert!(
            require_pilot_payment_admission(&policy, OTHER_USER)
                .unwrap_err()
                .to_string()
                .contains("not allowlisted")
        );
        assert!(
            require_pilot_payment_admission(&MainnetPilotAdmissionPolicy::default(), ALLOWED_USER,)
                .is_err()
        );
    }

    #[test]
    fn confirmed_open_is_not_double_counted_as_reserved_tvl() {
        let mut state = HubPersistedState::default();
        state.channels.insert(
            "active".into(),
            ChannelLedger {
                left_balance_mei: HacAmount::from_millimeis(10),
                right_balance_mei: HacAmount::ZERO,
                bill_auto_number: 0,
            },
        );
        state.l1_channel_opens.insert(
            "confirmed-open".into(),
            pending_open(L1ChannelOpenStatus::Confirmed, 1_000_000),
        );
        assert_eq!(aggregate_pilot_tvl_zhu(&state).unwrap(), 1_000_000);
    }

    #[test]
    fn terminal_l1_records_without_finality_evidence_fail_closed() {
        let mut state = HubPersistedState::default();
        let mut confirmed_open = pending_open(L1ChannelOpenStatus::Confirmed, 1_000_000);
        state
            .l1_channel_opens
            .insert("confirmed-open".into(), confirmed_open.clone());
        assert!(
            validate_terminal_l1_finality_evidence(&state)
                .unwrap_err()
                .to_string()
                .contains("legacy confirmed channel-open")
        );

        confirmed_open.confirmed_block_height = Some(100);
        confirmed_open.observed_confirmations = 6;
        state
            .l1_channel_opens
            .insert("confirmed-open".into(), confirmed_open.clone());
        assert!(validate_terminal_l1_finality_evidence(&state).is_err());
        state.l1_channel_opens.clear();

        let retired_close = crate::storage::PersistedL1ChannelClose {
            operation_id: "retired-close".into(),
            idempotency_key: "retired-close-idempotency".into(),
            request_commitment: "close-request".into(),
            network: String::new(),
            chain_id: 0,
            mainnet: false,
            block_1_hash: String::new(),
            node_profile_id: String::new(),
            network_instance_id: String::new(),
            transaction_format_version: 0,
            channel_id: "channel".into(),
            hub_address: "hub".into(),
            user_address: ALLOWED_USER.into(),
            reuse_version: 1,
            open_height: 100,
            original_ledger: ChannelLedger {
                left_balance_mei: HacAmount::from_millimeis(10),
                right_balance_mei: HacAmount::ZERO,
                bill_auto_number: 0,
            },
            final_ledger: Some(ChannelLedger {
                left_balance_mei: HacAmount::from_millimeis(10),
                right_balance_mei: HacAmount::ZERO,
                bill_auto_number: 0,
            }),
            partial_transaction_hex: "00".into(),
            partial_transaction_commitment: "partial-close".into(),
            authorization_public_key_hex: "11".into(),
            authorization_signature_hex: "22".into(),
            transaction_hash: Some("hash".into()),
            signed_transaction_hex: Some("33".into()),
            signed_transaction_commitment: Some("44".into()),
            confirmed_block_height: None,
            observed_confirmations: 0,
            status: crate::storage::L1ChannelCloseStatus::Retired,
            created_unix: 1,
            expires_unix: 2,
            updated_unix: 2,
            last_error: None,
        };
        state
            .l1_channel_closes
            .insert("retired-close".into(), retired_close.clone());
        assert!(
            validate_terminal_l1_finality_evidence(&state)
                .unwrap_err()
                .to_string()
                .contains("legacy retired channel-close")
        );

        let mut evidenced_close = retired_close.clone();
        evidenced_close.confirmed_block_height = Some(120);
        evidenced_close.observed_confirmations = 6;
        state
            .l1_channel_closes
            .insert("retired-close".into(), evidenced_close);
        assert!(validate_terminal_l1_finality_evidence(&state).is_err());

        state.l1_channel_opens.clear();
        state.l1_channel_closes.clear();
        assert!(!persisted_state_requires_recovery(&state));
        confirmed_open.status = L1ChannelOpenStatus::RecoveryRequired;
        state
            .l1_channel_opens
            .insert("recovery-open".into(), confirmed_open);
        assert!(persisted_state_requires_recovery(&state));
        state.l1_channel_opens.clear();
        let mut recovery_close = retired_close;
        recovery_close.status = crate::storage::L1ChannelCloseStatus::RecoveryRequired;
        state
            .l1_channel_closes
            .insert("recovery-close".into(), recovery_close);
        assert!(persisted_state_requires_recovery(&state));
    }
}
