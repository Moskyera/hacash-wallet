//! Authenticated, crash-safe lifecycle journal for the shared registry Local Pilot.
//!
//! This state is intentionally separate from both the production Hub state and
//! the legacy per-channel V1 pilot journal. It contains public evidence and
//! exact signed transaction bytes, but never a private key.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::path::PathBuf;

use field::{Address, Amount, Serialize as FieldSerialize};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use protocol::action::HacToTrs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sys::Account;
use zeroize::Zeroizing;

use crate::error::{HubError, HubResult};
use crate::hvm_pilot::{
    HvmLocalPilotNetwork, HvmPilotDeploymentTransaction, HvmPilotSignedTransaction,
    HvmPilotTransactionPhase, build_hvm_pilot_exact_transfer, validate_durable_pilot_transaction,
};
use crate::hvm_registry::HvmRegistryRecoveryBundleV2;
use crate::hvm_registry_pilot::{
    HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU, HvmRegistryPilotChannelParameters,
    HvmRegistryPilotFundingPreview, HvmRegistryPilotInitializationPreview,
    HvmRegistryPilotPrefundPreview, build_hvm_registry_pilot_channel_init,
    build_hvm_registry_pilot_deployment, build_hvm_registry_pilot_exact_funding,
    build_hvm_registry_pilot_recovery_bundle, preview_hvm_registry_pilot_deployment,
    preview_hvm_registry_pilot_funding, preview_hvm_registry_pilot_initialization,
    preview_hvm_registry_pilot_prefund, validate_hvm_registry_pilot_deployment_transaction,
    validate_hvm_registry_pilot_funding_transaction,
    validate_hvm_registry_pilot_initialization_transaction,
    validate_hvm_registry_pilot_prefund_transaction,
};
use crate::node::TransactionObservation;

const STATE_SCHEMA: &str = "hpay-hvm-registry-local-pilot-state/1";
const STATE_DOMAIN: &[u8] = b"HPAY/HVM-REGISTRY/LOCAL-PILOT/STATE/V1";
const REQUEST_COMMITMENT_DOMAIN: &[u8] = b"HPAY/HVM-REGISTRY/LOCAL-PILOT/EXACT-REQUEST/V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HvmRegistryLifecycleStage {
    HubPrefunding,
    Deployment,
    Initialization,
    Funding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvmRegistryPrepareProvenance {
    CreatedThisInvocation,
    Existing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HvmRegistrySubmissionAttemptState {
    LegacyUnknown,
    NeverAttempted,
    SubmissionStarted,
    Acknowledged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryConfirmationEvidence {
    pub block_height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    pub observed_confirmations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvmRegistryPrepared<T> {
    pub transaction: T,
    pub provenance: HvmRegistryPrepareProvenance,
    pub request_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvmRegistryLifecycleSnapshot {
    pub stage: HvmRegistryLifecycleStage,
    pub phase: HvmPilotTransactionPhase,
    pub transaction: HvmPilotSignedTransaction,
    pub attempt_state: HvmRegistrySubmissionAttemptState,
    pub active_confirmation: Option<HvmRegistryConfirmationEvidence>,
    pub confirmation_history: Vec<HvmRegistryConfirmationEvidence>,
    pub request_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvmRegistryLifecycleReview {
    pub stage: HvmRegistryLifecycleStage,
    pub network: HvmLocalPilotNetwork,
    pub source_address: String,
    pub destination_or_contract: Option<String>,
    pub amount_or_protocol_cost_zhu: Option<u64>,
    pub network_fee_zhu: u64,
    pub gas_max: u8,
    pub timestamp: u64,
    pub action_kinds: Vec<u16>,
    pub address_topology: Vec<String>,
    pub required_signers: Vec<String>,
    pub reviewed_preview_commitment: Option<String>,
    pub transaction_hash: String,
    pub signed_transaction_sha256: String,
    pub request_commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvmRegistryObservationOutcome {
    NeverAttempted,
    Pending,
    AwaitingConfirmations,
    Confirmed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransactionRecord<T> {
    phase: HvmPilotTransactionPhase,
    transaction: T,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmed_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_state: Option<HvmRegistrySubmissionAttemptState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_confirmation: Option<HvmRegistryConfirmationEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    confirmation_history: Vec<HvmRegistryConfirmationEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HvmRegistryPilotDurableState {
    schema: String,
    network: HvmLocalPilotNetwork,
    left_address: String,
    hub_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hub_prefunding: Option<TransactionRecord<HvmPilotSignedTransaction>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hub_prefunding_network_fee_zhu: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hub_prefunding_preview: Option<HvmRegistryPilotPrefundPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deployment: Option<TransactionRecord<HvmPilotDeploymentTransaction>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel_parameters: Option<HvmRegistryPilotChannelParameters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_bundle: Option<HvmRegistryRecoveryBundleV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initialization_preview: Option<HvmRegistryPilotInitializationPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initialization: Option<TransactionRecord<HvmPilotSignedTransaction>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    funding_preview: Option<HvmRegistryPilotFundingPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    funding: Option<TransactionRecord<HvmPilotSignedTransaction>>,
    authentication_tag: String,
}

#[derive(Serialize)]
struct StateBody<'a> {
    schema: &'a str,
    network: &'a HvmLocalPilotNetwork,
    left_address: &'a str,
    hub_address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hub_prefunding: &'a Option<TransactionRecord<HvmPilotSignedTransaction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hub_prefunding_network_fee_zhu: &'a Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hub_prefunding_preview: &'a Option<HvmRegistryPilotPrefundPreview>,
    deployment: &'a Option<TransactionRecord<HvmPilotDeploymentTransaction>>,
    channel_parameters: &'a Option<HvmRegistryPilotChannelParameters>,
    recovery_bundle: &'a Option<HvmRegistryRecoveryBundleV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    initialization_preview: &'a Option<HvmRegistryPilotInitializationPreview>,
    initialization: &'a Option<TransactionRecord<HvmPilotSignedTransaction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    funding_preview: &'a Option<HvmRegistryPilotFundingPreview>,
    funding: &'a Option<TransactionRecord<HvmPilotSignedTransaction>>,
}

pub struct HvmRegistryPilotStateStore {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    state: HvmRegistryPilotDurableState,
    created_this_invocation: BTreeSet<HvmRegistryLifecycleStage>,
    _lock: std::fs::File,
}

impl HvmRegistryPilotStateStore {
    pub fn open(
        path: impl Into<PathBuf>,
        state_key_hex: &str,
        network: HvmLocalPilotNetwork,
        left_address: &str,
        hub_address: &str,
    ) -> HubResult<Self> {
        network.validate()?;
        require_public_identity(left_address, "left")?;
        require_public_identity(hub_address, "Hub")?;
        if left_address == hub_address {
            return Err(HubError::State(
                "registry pilot identities must be independent".into(),
            ));
        }
        let path = path.into();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| HubError::State("registry pilot state path has no parent".into()))?;
        std::fs::create_dir_all(parent).map_err(|error| {
            HubError::State(format!(
                "cannot create registry pilot state directory: {error}"
            ))
        })?;
        crate::storage::ensure_not_symlink(parent, "registry pilot state directory")?;
        crate::storage::ensure_not_symlink(&path, "registry pilot state")?;
        let lock_path = path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| {
                HubError::State(format!("cannot open registry pilot state lock: {error}"))
            })?;
        lock.try_lock_exclusive()
            .map_err(|_| HubError::State("registry pilot state already has a live owner".into()))?;
        let key = decode_key(state_key_hex)?;
        let state = if path.is_file() {
            let bytes = std::fs::read(&path).map_err(|error| {
                HubError::State(format!("cannot read registry pilot state: {error}"))
            })?;
            if bytes.is_empty() || bytes.len() > 1_048_576 {
                return Err(HubError::State(
                    "registry pilot state size is invalid".into(),
                ));
            }
            let state: HvmRegistryPilotDurableState = serde_json::from_slice(&bytes)
                .map_err(|_| HubError::State("registry pilot state is malformed".into()))?;
            verify_tag(&state, key.as_ref())?;
            validate_state_identity(&state, &network, left_address, hub_address)?;
            state
        } else {
            HvmRegistryPilotDurableState {
                schema: STATE_SCHEMA.into(),
                network,
                left_address: left_address.to_owned(),
                hub_address: hub_address.to_owned(),
                hub_prefunding: None,
                hub_prefunding_network_fee_zhu: None,
                hub_prefunding_preview: None,
                deployment: None,
                channel_parameters: None,
                recovery_bundle: None,
                initialization_preview: None,
                initialization: None,
                funding_preview: None,
                funding: None,
                authentication_tag: String::new(),
            }
        };
        let mut store = Self {
            path,
            key,
            state,
            created_this_invocation: BTreeSet::new(),
            _lock: lock,
        };
        let migrated = store.migrate_authenticated_legacy_attempts();
        validate_state(
            &store.state,
            &store.state.network,
            &store.state.left_address,
            &store.state.hub_address,
        )?;
        if migrated {
            store.save()?;
        }
        Ok(store)
    }

    pub fn deployment(
        &self,
    ) -> Option<(
        &HvmPilotTransactionPhase,
        &HvmPilotDeploymentTransaction,
        Option<u64>,
    )> {
        self.state
            .deployment
            .as_ref()
            .map(|record| (&record.phase, &record.transaction, record.confirmed_height))
    }

    pub fn hub_prefunding(
        &self,
    ) -> Option<(
        &HvmPilotTransactionPhase,
        &HvmPilotSignedTransaction,
        Option<u64>,
    )> {
        self.state
            .hub_prefunding
            .as_ref()
            .map(|record| (&record.phase, &record.transaction, record.confirmed_height))
    }

    // Every argument names one field of the exact transaction being previewed,
    // and collapsing them into a struct would only move the same list somewhere
    // the compiler checks less.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_hub_prefunding(
        &mut self,
        left: &Account,
        network_fee_zhu: u64,
        timestamp: u64,
        valid_until_unix: u64,
        gas_max: u8,
        expected_preview_commitment: &str,
        now_unix: u64,
    ) -> HubResult<HvmRegistryPrepared<HvmPilotSignedTransaction>> {
        let preview = preview_hvm_registry_pilot_prefund(
            left.readable(),
            &self.state.hub_address,
            &self.state.network,
            network_fee_zhu,
            timestamp,
            valid_until_unix,
            gas_max,
        )?;
        preview.validate_for_signing(now_unix)?;
        if preview.unsigned_commitment != expected_preview_commitment {
            return Err(HubError::State(
                "registry prefund does not match the explicitly reviewed preview commitment".into(),
            ));
        }
        if let Some((_, transaction, _)) = self.hub_prefunding() {
            if self.state.hub_prefunding_network_fee_zhu != Some(network_fee_zhu)
                || self.state.hub_prefunding_preview.as_ref() != Some(&preview)
            {
                return Err(HubError::State(
                    "Hub prefunding retry changed the durable reviewed preview".into(),
                ));
            }
            return Ok(self.prepared_existing(
                HvmRegistryLifecycleStage::HubPrefunding,
                transaction.clone(),
            ));
        }
        if self.state.deployment.is_some() {
            return Err(HubError::State(
                "Hub prefunding cannot start after registry deployment".into(),
            ));
        }
        if left.readable() != self.state.left_address {
            return Err(HubError::State(
                "registry Hub prefunding signer changed".into(),
            ));
        }
        let transaction = build_hvm_pilot_exact_transfer(
            left,
            &self.state.hub_address,
            &self.state.network,
            HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU,
            network_fee_zhu,
            timestamp,
            gas_max,
        )?;
        self.state.hub_prefunding = Some(TransactionRecord {
            phase: HvmPilotTransactionPhase::Signed,
            transaction: transaction.clone(),
            confirmed_height: None,
            attempt_state: Some(HvmRegistrySubmissionAttemptState::NeverAttempted),
            active_confirmation: None,
            confirmation_history: Vec::new(),
        });
        self.state.hub_prefunding_network_fee_zhu = Some(network_fee_zhu);
        self.state.hub_prefunding_preview = Some(preview);
        self.created_this_invocation
            .insert(HvmRegistryLifecycleStage::HubPrefunding);
        self.save()?;
        Ok(self.prepared_created(HvmRegistryLifecycleStage::HubPrefunding, transaction))
    }

    pub fn initialization(
        &self,
    ) -> Option<(
        &HvmPilotTransactionPhase,
        &HvmPilotSignedTransaction,
        Option<u64>,
        &HvmRegistryPilotChannelParameters,
        &HvmRegistryRecoveryBundleV2,
    )> {
        let record = self.state.initialization.as_ref()?;
        Some((
            &record.phase,
            &record.transaction,
            record.confirmed_height,
            self.state.channel_parameters.as_ref()?,
            self.state.recovery_bundle.as_ref()?,
        ))
    }

    pub fn funding(
        &self,
    ) -> Option<(
        &HvmPilotTransactionPhase,
        &HvmPilotSignedTransaction,
        Option<u64>,
    )> {
        self.state
            .funding
            .as_ref()
            .map(|record| (&record.phase, &record.transaction, record.confirmed_height))
    }

    pub fn recovery_bundle(&self) -> Option<&HvmRegistryRecoveryBundleV2> {
        self.state.recovery_bundle.as_ref()
    }

    pub fn prepare_deployment(
        &mut self,
        hub: &Account,
        network_fee_zhu: u64,
        timestamp: u64,
        gas_max: u8,
        expected_preview_commitment: &str,
    ) -> HubResult<HvmRegistryPrepared<HvmPilotDeploymentTransaction>> {
        let preview = preview_hvm_registry_pilot_deployment(
            hub.readable(),
            &self.state.network,
            network_fee_zhu,
            gas_max,
        )?;
        if expected_preview_commitment != preview.unsigned_commitment {
            return Err(HubError::State(
                "registry deployment does not match the explicitly reviewed preview commitment"
                    .into(),
            ));
        }
        if let Some((_, transaction, _)) = self.deployment() {
            if transaction.contract_address != preview.contract_address
                || transaction.source_sha256 != preview.source_sha256
                || transaction.bytecode_sha3 != preview.bytecode_sha3
            {
                return Err(HubError::State(
                    "durable registry deployment no longer matches the reviewed preview".into(),
                ));
            }
            validate_hvm_registry_pilot_deployment_transaction(transaction, &preview)?;
            return Ok(
                self.prepared_existing(HvmRegistryLifecycleStage::Deployment, transaction.clone())
            );
        }
        if let Some((phase, _, _)) = self.hub_prefunding()
            && phase != &HvmPilotTransactionPhase::Confirmed
        {
            return Err(HubError::State(
                "registry deployment requires confirmed Hub prefunding".into(),
            ));
        }
        if hub.readable() != self.state.hub_address {
            return Err(HubError::State(
                "registry deployment signer is not the durable Hub".into(),
            ));
        }
        let transaction = build_hvm_registry_pilot_deployment(
            hub,
            &self.state.network,
            network_fee_zhu,
            timestamp,
            gas_max,
        )?;
        validate_hvm_registry_pilot_deployment_transaction(&transaction, &preview)?;
        self.state.deployment = Some(TransactionRecord {
            phase: HvmPilotTransactionPhase::Signed,
            transaction: transaction.clone(),
            confirmed_height: None,
            attempt_state: Some(HvmRegistrySubmissionAttemptState::NeverAttempted),
            active_confirmation: None,
            confirmation_history: Vec::new(),
        });
        self.created_this_invocation
            .insert(HvmRegistryLifecycleStage::Deployment);
        self.save()?;
        Ok(self.prepared_created(HvmRegistryLifecycleStage::Deployment, transaction))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_initialization(
        &mut self,
        left: &Account,
        hub: &Account,
        parameters: HvmRegistryPilotChannelParameters,
        network_fee_zhu: u64,
        timestamp: u64,
        gas_max: u8,
        expected_preview_commitment: &str,
    ) -> HubResult<HvmRegistryPrepared<HvmPilotSignedTransaction>> {
        let deployment = require_confirmed_deployment(&self.state)?;
        if left.readable() != self.state.left_address || hub.readable() != self.state.hub_address {
            return Err(HubError::State(
                "registry initialization signers changed".into(),
            ));
        }
        let preview = preview_hvm_registry_pilot_initialization(
            left.readable(),
            hub.readable(),
            &deployment.transaction.contract_address,
            &self.state.network,
            &parameters,
            network_fee_zhu,
            gas_max,
        )?;
        if expected_preview_commitment != preview.unsigned_commitment {
            return Err(HubError::State(
                "registry initialization does not match the explicitly reviewed preview commitment"
                    .into(),
            ));
        }
        if let Some((_, transaction, _, stored, _)) = self.initialization() {
            if stored != &parameters || self.state.initialization_preview.as_ref() != Some(&preview)
            {
                return Err(HubError::State(
                    "registry initialization retry changed its reviewed preview".into(),
                ));
            }
            validate_hvm_registry_pilot_initialization_transaction(transaction, &preview)?;
            return Ok(self.prepared_existing(
                HvmRegistryLifecycleStage::Initialization,
                transaction.clone(),
            ));
        }
        let transaction = build_hvm_registry_pilot_channel_init(
            left,
            hub,
            &deployment.transaction.contract_address,
            &self.state.network,
            &parameters,
            network_fee_zhu,
            timestamp,
            gas_max,
        )?;
        validate_hvm_registry_pilot_initialization_transaction(&transaction, &preview)?;
        let bundle = build_hvm_registry_pilot_recovery_bundle(
            left,
            hub,
            &deployment.transaction,
            deployment.confirmed_height.ok_or_else(|| {
                HubError::State("confirmed registry deployment lost its height".into())
            })?,
            &parameters,
        )?;
        self.state.channel_parameters = Some(parameters);
        self.state.recovery_bundle = Some(bundle);
        self.state.initialization_preview = Some(preview);
        self.state.initialization = Some(TransactionRecord {
            phase: HvmPilotTransactionPhase::Signed,
            transaction: transaction.clone(),
            confirmed_height: None,
            attempt_state: Some(HvmRegistrySubmissionAttemptState::NeverAttempted),
            active_confirmation: None,
            confirmation_history: Vec::new(),
        });
        self.created_this_invocation
            .insert(HvmRegistryLifecycleStage::Initialization);
        self.save()?;
        Ok(self.prepared_created(HvmRegistryLifecycleStage::Initialization, transaction))
    }

    pub fn prepare_funding(
        &mut self,
        left: &Account,
        network_fee_zhu: u64,
        timestamp: u64,
        gas_max: u8,
        expected_preview_commitment: &str,
    ) -> HubResult<HvmRegistryPrepared<HvmPilotSignedTransaction>> {
        require_confirmed_initialization(&self.state)?;
        if left.readable() != self.state.left_address {
            return Err(HubError::State("registry funding signer changed".into()));
        }
        let deployment = self
            .state
            .deployment
            .as_ref()
            .ok_or_else(|| HubError::State("registry deployment is missing".into()))?;
        let parameters = self
            .state
            .channel_parameters
            .as_ref()
            .ok_or_else(|| HubError::State("registry channel parameters are missing".into()))?;
        let preview = preview_hvm_registry_pilot_funding(
            left.readable(),
            &self.state.hub_address,
            &deployment.transaction.contract_address,
            &self.state.network,
            parameters.left_deposit_zhu,
            network_fee_zhu,
            gas_max,
        )?;
        if expected_preview_commitment != preview.unsigned_commitment {
            return Err(HubError::State(
                "registry funding does not match the explicitly reviewed preview commitment".into(),
            ));
        }
        if let Some((_, transaction, _)) = self.funding() {
            if self.state.funding_preview.as_ref() != Some(&preview) {
                return Err(HubError::State(
                    "registry funding retry changed its reviewed preview".into(),
                ));
            }
            validate_hvm_registry_pilot_funding_transaction(transaction, &preview)?;
            return Ok(
                self.prepared_existing(HvmRegistryLifecycleStage::Funding, transaction.clone())
            );
        }
        let transaction = build_hvm_registry_pilot_exact_funding(
            left,
            &self.state.hub_address,
            &deployment.transaction.contract_address,
            &self.state.network,
            parameters.left_deposit_zhu,
            network_fee_zhu,
            timestamp,
            gas_max,
        )?;
        validate_hvm_registry_pilot_funding_transaction(&transaction, &preview)?;
        self.state.funding_preview = Some(preview);
        self.state.funding = Some(TransactionRecord {
            phase: HvmPilotTransactionPhase::Signed,
            transaction: transaction.clone(),
            confirmed_height: None,
            attempt_state: Some(HvmRegistrySubmissionAttemptState::NeverAttempted),
            active_confirmation: None,
            confirmation_history: Vec::new(),
        });
        self.created_this_invocation
            .insert(HvmRegistryLifecycleStage::Funding);
        self.save()?;
        Ok(self.prepared_created(HvmRegistryLifecycleStage::Funding, transaction))
    }

    pub fn lifecycle_snapshot(
        &self,
        stage: HvmRegistryLifecycleStage,
    ) -> Option<HvmRegistryLifecycleSnapshot> {
        match stage {
            HvmRegistryLifecycleStage::HubPrefunding => self
                .state
                .hub_prefunding
                .as_ref()
                .map(|record| self.snapshot(stage, record)),
            HvmRegistryLifecycleStage::Deployment => self
                .state
                .deployment
                .as_ref()
                .map(|record| self.snapshot(stage, record)),
            HvmRegistryLifecycleStage::Initialization => self
                .state
                .initialization
                .as_ref()
                .map(|record| self.snapshot(stage, record)),
            HvmRegistryLifecycleStage::Funding => self
                .state
                .funding
                .as_ref()
                .map(|record| self.snapshot(stage, record)),
        }
    }

    pub fn lifecycle_review(
        &self,
        stage: HvmRegistryLifecycleStage,
    ) -> HubResult<Option<HvmRegistryLifecycleReview>> {
        let Some(snapshot) = self.lifecycle_snapshot(stage) else {
            return Ok(None);
        };
        let raw = hex::decode(&snapshot.transaction.signed_transaction_hex)
            .map_err(|_| HubError::State("registry durable transaction is not hex".into()))?;
        let (transaction, consumed) =
            protocol::transaction::transaction_create(&raw).map_err(|error| {
                HubError::State(format!(
                    "registry durable transaction decode failed: {error}"
                ))
            })?;
        if consumed != raw.len() {
            return Err(HubError::State(
                "registry durable transaction has trailing bytes".into(),
            ));
        }
        let network_fee_zhu = transaction.fee().to_zhu_u64().map_err(|error| {
            HubError::State(format!(
                "registry durable transaction fee is invalid: {error}"
            ))
        })?;
        let gas_max = transaction
            .gas_max_byte()
            .ok_or_else(|| HubError::State("registry durable transaction has no gas cap".into()))?;
        let timestamp = transaction.timestamp().uint();
        let action_kinds = transaction
            .actions()
            .iter()
            .map(|action| action.kind())
            .collect::<Vec<_>>();
        let (
            source_address,
            destination_or_contract,
            amount_or_protocol_cost_zhu,
            topology,
            signers,
            preview_commitment,
        ) = match stage {
            HvmRegistryLifecycleStage::HubPrefunding => (
                self.state.left_address.clone(),
                Some(self.state.hub_address.clone()),
                Some(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU),
                vec![
                    self.state.left_address.clone(),
                    self.state.hub_address.clone(),
                ],
                vec![self.state.left_address.clone()],
                self.state
                    .hub_prefunding_preview
                    .as_ref()
                    .map(|preview| preview.unsigned_commitment.clone()),
            ),
            HvmRegistryLifecycleStage::Deployment => {
                let deployment = self.state.deployment.as_ref().ok_or_else(|| {
                    HubError::State("registry deployment review disappeared".into())
                })?;
                let preview = preview_hvm_registry_pilot_deployment(
                    &self.state.hub_address,
                    &self.state.network,
                    network_fee_zhu,
                    gas_max,
                )?;
                (
                    self.state.hub_address.clone(),
                    Some(deployment.transaction.contract_address.clone()),
                    Some(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU),
                    vec![self.state.hub_address.clone()],
                    vec![self.state.hub_address.clone()],
                    Some(preview.unsigned_commitment),
                )
            }
            HvmRegistryLifecycleStage::Initialization => {
                let deployment = self.state.deployment.as_ref().ok_or_else(|| {
                    HubError::State("registry deployment review is missing".into())
                })?;
                let parameters = self.state.channel_parameters.as_ref().ok_or_else(|| {
                    HubError::State("registry initialization parameters are missing".into())
                })?;
                (
                    self.state.left_address.clone(),
                    Some(deployment.transaction.contract_address.clone()),
                    Some(parameters.left_deposit_zhu),
                    vec![
                        self.state.left_address.clone(),
                        deployment.transaction.contract_address.clone(),
                        self.state.hub_address.clone(),
                    ],
                    vec![
                        self.state.left_address.clone(),
                        self.state.hub_address.clone(),
                    ],
                    self.state
                        .initialization_preview
                        .as_ref()
                        .map(|preview| preview.unsigned_commitment.clone()),
                )
            }
            HvmRegistryLifecycleStage::Funding => {
                let deployment = self.state.deployment.as_ref().ok_or_else(|| {
                    HubError::State("registry deployment review is missing".into())
                })?;
                let parameters = self.state.channel_parameters.as_ref().ok_or_else(|| {
                    HubError::State("registry funding parameters are missing".into())
                })?;
                (
                    self.state.left_address.clone(),
                    Some(deployment.transaction.contract_address.clone()),
                    Some(parameters.left_deposit_zhu),
                    vec![
                        self.state.left_address.clone(),
                        deployment.transaction.contract_address.clone(),
                    ],
                    vec![self.state.left_address.clone()],
                    self.state
                        .funding_preview
                        .as_ref()
                        .map(|preview| preview.unsigned_commitment.clone()),
                )
            }
        };
        Ok(Some(HvmRegistryLifecycleReview {
            stage,
            network: self.state.network.clone(),
            source_address,
            destination_or_contract,
            amount_or_protocol_cost_zhu,
            network_fee_zhu,
            gas_max,
            timestamp,
            action_kinds,
            address_topology: topology,
            required_signers: signers,
            reviewed_preview_commitment: preview_commitment,
            transaction_hash: snapshot.transaction.transaction_hash,
            signed_transaction_sha256: hex::encode(Sha256::digest(raw)),
            request_commitment: snapshot.request_commitment,
        }))
    }

    /// Atomically records the ambiguity boundary before the first HTTP POST.
    /// This is permitted only for a record created by this store instance.
    pub fn begin_initial_submission(
        &mut self,
        stage: HvmRegistryLifecycleStage,
        expected_transaction_hash: &str,
        expected_request_commitment: &str,
        now_unix: u64,
    ) -> HubResult<HvmPilotSignedTransaction> {
        if !self.created_this_invocation.contains(&stage) {
            return Err(HubError::State(format!(
                "registry {} is preexisting; initial submit is forbidden",
                stage_label(stage)
            )));
        }
        self.require_exact_request(
            stage,
            expected_transaction_hash,
            expected_request_commitment,
        )?;
        if stage == HvmRegistryLifecycleStage::HubPrefunding {
            self.state
                .hub_prefunding_preview
                .as_ref()
                .ok_or_else(|| {
                    HubError::State(
                        "legacy Prefund has no fresh initial-submit authorization".into(),
                    )
                })?
                .validate_for_signing(now_unix)?;
        }
        let transaction = match stage {
            HvmRegistryLifecycleStage::HubPrefunding => begin_initial(
                self.state.hub_prefunding.as_mut(),
                expected_transaction_hash,
                "Hub prefunding",
            )?,
            HvmRegistryLifecycleStage::Deployment => begin_initial(
                self.state.deployment.as_mut(),
                expected_transaction_hash,
                "deployment",
            )?,
            HvmRegistryLifecycleStage::Initialization => begin_initial(
                self.state.initialization.as_mut(),
                expected_transaction_hash,
                "initialization",
            )?,
            HvmRegistryLifecycleStage::Funding => begin_initial(
                self.state.funding.as_mut(),
                expected_transaction_hash,
                "funding",
            )?,
        };
        self.created_this_invocation.remove(&stage);
        self.save()?;
        Ok(transaction)
    }

    /// Starts an explicit retry of the exact already-durable request. Both the
    /// transaction hash and displayed request commitment are required.
    pub fn begin_exact_resubmit(
        &mut self,
        stage: HvmRegistryLifecycleStage,
        expected_transaction_hash: &str,
        expected_request_commitment: &str,
    ) -> HubResult<HvmPilotSignedTransaction> {
        self.require_exact_request(
            stage,
            expected_transaction_hash,
            expected_request_commitment,
        )?;
        let transaction = match stage {
            HvmRegistryLifecycleStage::HubPrefunding => begin_resubmit(
                self.state.hub_prefunding.as_mut(),
                expected_transaction_hash,
                "Hub prefunding",
            )?,
            HvmRegistryLifecycleStage::Deployment => begin_resubmit(
                self.state.deployment.as_mut(),
                expected_transaction_hash,
                "deployment",
            )?,
            HvmRegistryLifecycleStage::Initialization => begin_resubmit(
                self.state.initialization.as_mut(),
                expected_transaction_hash,
                "initialization",
            )?,
            HvmRegistryLifecycleStage::Funding => begin_resubmit(
                self.state.funding.as_mut(),
                expected_transaction_hash,
                "funding",
            )?,
        };
        self.created_this_invocation.remove(&stage);
        self.save()?;
        Ok(transaction)
    }

    pub fn mark_submission_acknowledged(
        &mut self,
        stage: HvmRegistryLifecycleStage,
        expected_transaction_hash: &str,
    ) -> HubResult<()> {
        match stage {
            HvmRegistryLifecycleStage::HubPrefunding => acknowledge_submission(
                self.state.hub_prefunding.as_mut(),
                expected_transaction_hash,
                "Hub prefunding",
            )?,
            HvmRegistryLifecycleStage::Deployment => acknowledge_submission(
                self.state.deployment.as_mut(),
                expected_transaction_hash,
                "deployment",
            )?,
            HvmRegistryLifecycleStage::Initialization => acknowledge_submission(
                self.state.initialization.as_mut(),
                expected_transaction_hash,
                "initialization",
            )?,
            HvmRegistryLifecycleStage::Funding => acknowledge_submission(
                self.state.funding.as_mut(),
                expected_transaction_hash,
                "funding",
            )?,
        }
        self.save()
    }

    pub fn mark_submission_uncertain(
        &mut self,
        stage: HvmRegistryLifecycleStage,
        expected_transaction_hash: &str,
    ) -> HubResult<()> {
        match stage {
            HvmRegistryLifecycleStage::HubPrefunding => mark_uncertain(
                self.state.hub_prefunding.as_mut(),
                expected_transaction_hash,
                "Hub prefunding",
            )?,
            HvmRegistryLifecycleStage::Deployment => mark_uncertain(
                self.state.deployment.as_mut(),
                expected_transaction_hash,
                "deployment",
            )?,
            HvmRegistryLifecycleStage::Initialization => mark_uncertain(
                self.state.initialization.as_mut(),
                expected_transaction_hash,
                "initialization",
            )?,
            HvmRegistryLifecycleStage::Funding => mark_uncertain(
                self.state.funding.as_mut(),
                expected_transaction_hash,
                "funding",
            )?,
        }
        self.created_this_invocation.remove(&stage);
        self.save()
    }

    pub fn reconcile_observation_result(
        &mut self,
        stage: HvmRegistryLifecycleStage,
        observation: HubResult<Option<TransactionObservation>>,
        required_confirmations: u64,
    ) -> HubResult<HvmRegistryObservationOutcome> {
        let observation = observation?;
        self.reconcile_observation(stage, observation.as_ref(), required_confirmations)
    }

    pub fn reconcile_observation(
        &mut self,
        stage: HvmRegistryLifecycleStage,
        observation: Option<&TransactionObservation>,
        required_confirmations: u64,
    ) -> HubResult<HvmRegistryObservationOutcome> {
        if required_confirmations == 0 {
            return Err(HubError::State(
                "registry confirmation requirement is zero".into(),
            ));
        }
        let created_here = self.created_this_invocation.contains(&stage);
        let result = match stage {
            HvmRegistryLifecycleStage::HubPrefunding => reconcile_record(
                self.state.hub_prefunding.as_mut(),
                observation,
                required_confirmations,
                created_here,
                "Hub prefunding",
            ),
            HvmRegistryLifecycleStage::Deployment => reconcile_record(
                self.state.deployment.as_mut(),
                observation,
                required_confirmations,
                created_here,
                "deployment",
            ),
            HvmRegistryLifecycleStage::Initialization => reconcile_record(
                self.state.initialization.as_mut(),
                observation,
                required_confirmations,
                created_here,
                "initialization",
            ),
            HvmRegistryLifecycleStage::Funding => reconcile_record(
                self.state.funding.as_mut(),
                observation,
                required_confirmations,
                created_here,
                "funding",
            ),
        };
        match result {
            Ok((outcome, changed)) => {
                if changed {
                    self.save()?;
                }
                Ok(outcome)
            }
            Err(error) => {
                self.save()?;
                Err(error)
            }
        }
    }

    fn prepared_existing<T: ExactTransaction>(
        &self,
        stage: HvmRegistryLifecycleStage,
        transaction: T,
    ) -> HvmRegistryPrepared<T> {
        HvmRegistryPrepared {
            request_commitment: self.exact_request_commitment(stage, &transaction),
            transaction,
            provenance: HvmRegistryPrepareProvenance::Existing,
        }
    }

    fn prepared_created<T: ExactTransaction>(
        &self,
        stage: HvmRegistryLifecycleStage,
        transaction: T,
    ) -> HvmRegistryPrepared<T> {
        HvmRegistryPrepared {
            request_commitment: self.exact_request_commitment(stage, &transaction),
            transaction,
            provenance: HvmRegistryPrepareProvenance::CreatedThisInvocation,
        }
    }

    fn snapshot<T: ExactTransaction>(
        &self,
        stage: HvmRegistryLifecycleStage,
        record: &TransactionRecord<T>,
    ) -> HvmRegistryLifecycleSnapshot {
        HvmRegistryLifecycleSnapshot {
            stage,
            phase: record.phase.clone(),
            transaction: record.transaction.signed_transaction().clone(),
            attempt_state: effective_attempt_state(record),
            active_confirmation: record.active_confirmation.clone(),
            confirmation_history: record.confirmation_history.clone(),
            request_commitment: self.exact_request_commitment(stage, &record.transaction),
        }
    }

    fn require_exact_request(
        &self,
        stage: HvmRegistryLifecycleStage,
        expected_transaction_hash: &str,
        expected_request_commitment: &str,
    ) -> HubResult<String> {
        let snapshot = self.lifecycle_snapshot(stage).ok_or_else(|| {
            HubError::State(format!("registry {} is missing", stage_label(stage)))
        })?;
        if snapshot.transaction.transaction_hash != expected_transaction_hash {
            return Err(HubError::State(format!(
                "registry {} transaction hash changed",
                stage_label(stage)
            )));
        }
        if snapshot.request_commitment != expected_request_commitment {
            return Err(HubError::State(format!(
                "registry {} exact request commitment changed",
                stage_label(stage)
            )));
        }
        Ok(snapshot.request_commitment)
    }

    fn exact_request_commitment<T: ExactTransaction>(
        &self,
        stage: HvmRegistryLifecycleStage,
        transaction: &T,
    ) -> String {
        let transaction = transaction.signed_transaction();
        let mut digest = Sha256::new();
        digest.update(REQUEST_COMMITMENT_DOMAIN);
        digest.update(stage_label(stage).as_bytes());
        digest.update(self.state.network.network_instance_id.as_bytes());
        digest.update(self.state.network.chain_id.to_be_bytes());
        digest.update(self.state.left_address.as_bytes());
        digest.update(self.state.hub_address.as_bytes());
        digest.update(transaction.transaction_hash.as_bytes());
        digest.update(transaction.signed_transaction_hex.as_bytes());
        hex::encode(digest.finalize())
    }

    fn migrate_authenticated_legacy_attempts(&mut self) -> bool {
        let mut changed = false;
        changed |= migrate_record(self.state.hub_prefunding.as_mut());
        changed |= migrate_record(self.state.deployment.as_mut());
        changed |= migrate_record(self.state.initialization.as_mut());
        changed |= migrate_record(self.state.funding.as_mut());
        changed
    }

    fn save(&mut self) -> HubResult<()> {
        validate_state(
            &self.state,
            &self.state.network,
            &self.state.left_address,
            &self.state.hub_address,
        )?;
        self.state.authentication_tag = compute_tag(&self.state, self.key.as_ref())?;
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(|error| {
            HubError::State(format!("registry pilot state encode failed: {error}"))
        })?;
        crate::storage::save_bytes_atomic(&self.path, &bytes)
    }
}

fn require_confirmed_deployment(
    state: &HvmRegistryPilotDurableState,
) -> HubResult<&TransactionRecord<HvmPilotDeploymentTransaction>> {
    let deployment = state
        .deployment
        .as_ref()
        .ok_or_else(|| HubError::State("registry deployment is missing".into()))?;
    if deployment.phase != HvmPilotTransactionPhase::Confirmed
        || deployment.confirmed_height.is_none()
        || deployment
            .active_confirmation
            .as_ref()
            .and_then(|evidence| evidence.block_hash.as_ref())
            .is_none()
    {
        return Err(HubError::State(
            "registry initialization requires a confirmed deployment".into(),
        ));
    }
    Ok(deployment)
}

fn require_confirmed_initialization(state: &HvmRegistryPilotDurableState) -> HubResult<()> {
    let initialization = state
        .initialization
        .as_ref()
        .ok_or_else(|| HubError::State("registry initialization is missing".into()))?;
    if initialization.phase != HvmPilotTransactionPhase::Confirmed
        || initialization.confirmed_height.is_none()
        || initialization
            .active_confirmation
            .as_ref()
            .and_then(|evidence| evidence.block_hash.as_ref())
            .is_none()
    {
        return Err(HubError::State(
            "registry funding requires a confirmed initialization".into(),
        ));
    }
    Ok(())
}

fn begin_initial<T: ExactTransaction>(
    record: Option<&mut TransactionRecord<T>>,
    hash: &str,
    label: &str,
) -> HubResult<HvmPilotSignedTransaction> {
    let record = exact_record(record, hash, label)?;
    if record.phase != HvmPilotTransactionPhase::Signed
        || effective_attempt_state(record) != HvmRegistrySubmissionAttemptState::NeverAttempted
    {
        return Err(HubError::State(format!(
            "registry {label} is not eligible for an initial submit"
        )));
    }
    record.attempt_state = Some(HvmRegistrySubmissionAttemptState::SubmissionStarted);
    Ok(record.transaction.signed_transaction().clone())
}

fn begin_resubmit<T: ExactTransaction>(
    record: Option<&mut TransactionRecord<T>>,
    hash: &str,
    label: &str,
) -> HubResult<HvmPilotSignedTransaction> {
    let record = exact_record(record, hash, label)?;
    if record.phase != HvmPilotTransactionPhase::RecoveryRequired {
        return Err(HubError::State(format!(
            "registry {label} is not waiting for exact resubmit authorization"
        )));
    }
    record.attempt_state = Some(HvmRegistrySubmissionAttemptState::SubmissionStarted);
    Ok(record.transaction.signed_transaction().clone())
}

fn acknowledge_submission<T: ExactTransaction>(
    record: Option<&mut TransactionRecord<T>>,
    hash: &str,
    label: &str,
) -> HubResult<()> {
    let record = exact_record(record, hash, label)?;
    if effective_attempt_state(record) != HvmRegistrySubmissionAttemptState::SubmissionStarted
        || !matches!(
            record.phase,
            HvmPilotTransactionPhase::Signed | HvmPilotTransactionPhase::RecoveryRequired
        )
    {
        return Err(HubError::State(format!(
            "registry {label} has no durable submission-started boundary"
        )));
    }
    record.attempt_state = Some(HvmRegistrySubmissionAttemptState::Acknowledged);
    record.phase = HvmPilotTransactionPhase::Submitted;
    Ok(())
}

fn mark_uncertain<T: ExactTransaction>(
    record: Option<&mut TransactionRecord<T>>,
    hash: &str,
    label: &str,
) -> HubResult<()> {
    let record = exact_record(record, hash, label)?;
    if effective_attempt_state(record) != HvmRegistrySubmissionAttemptState::SubmissionStarted {
        return Err(HubError::State(format!(
            "registry {label} has no ambiguous submission to recover"
        )));
    }
    enter_recovery(record);
    Ok(())
}

fn reconcile_record<T: ExactTransaction>(
    record: Option<&mut TransactionRecord<T>>,
    observation: Option<&TransactionObservation>,
    required_confirmations: u64,
    created_here: bool,
    label: &str,
) -> HubResult<(HvmRegistryObservationOutcome, bool)> {
    let record = record.ok_or_else(|| HubError::State(format!("registry {label} is missing")))?;
    let Some(observation) = observation else {
        if created_here
            && record.phase == HvmPilotTransactionPhase::Signed
            && effective_attempt_state(record) == HvmRegistrySubmissionAttemptState::NeverAttempted
        {
            return Ok((HvmRegistryObservationOutcome::NeverAttempted, false));
        }
        enter_recovery(record);
        return Ok((HvmRegistryObservationOutcome::RecoveryRequired, true));
    };
    if !observation
        .hash
        .eq_ignore_ascii_case(record.transaction.transaction_hash())
        || !observation.body_hex.eq_ignore_ascii_case(
            &record
                .transaction
                .signed_transaction()
                .signed_transaction_hex,
        )
    {
        enter_recovery(record);
        return Err(HubError::State(format!(
            "registry {label} node evidence does not match the exact durable transaction"
        )));
    }
    if observation.pending {
        if record.phase == HvmPilotTransactionPhase::Confirmed
            || record.active_confirmation.is_some()
        {
            enter_recovery(record);
            return Ok((HvmRegistryObservationOutcome::RecoveryRequired, true));
        }
        record.attempt_state = Some(HvmRegistrySubmissionAttemptState::Acknowledged);
        record.phase = HvmPilotTransactionPhase::Submitted;
        return Ok((HvmRegistryObservationOutcome::Pending, true));
    }
    let height = observation.block_height.filter(|height| *height > 0);
    let block_hash = observation.block_hash.as_deref().and_then(canonical_hash);
    if height.is_none() || block_hash.is_none() {
        enter_recovery(record);
        return Err(HubError::State(format!(
            "registry {label} confirmation lacks an exact canonical block anchor"
        )));
    }
    let evidence = HvmRegistryConfirmationEvidence {
        block_height: height.expect("checked"),
        block_hash: block_hash.map(str::to_owned),
        observed_confirmations: observation.confirmations,
    };
    if observation.confirmations < required_confirmations {
        if record.phase == HvmPilotTransactionPhase::Confirmed
            || record.active_confirmation.is_some()
        {
            enter_recovery(record);
            return Ok((HvmRegistryObservationOutcome::RecoveryRequired, true));
        }
        record.attempt_state = Some(HvmRegistrySubmissionAttemptState::Acknowledged);
        record.phase = HvmPilotTransactionPhase::Submitted;
        return Ok((HvmRegistryObservationOutcome::AwaitingConfirmations, true));
    }
    if let Some(active) = record.active_confirmation.as_ref() {
        let legacy_unanchored = active.block_hash.is_none() && active.observed_confirmations == 0;
        let moved = active.block_height != evidence.block_height
            || !legacy_unanchored && active.block_hash != evidence.block_hash;
        if moved {
            enter_recovery(record);
            return Ok((HvmRegistryObservationOutcome::RecoveryRequired, true));
        }
    }
    if record.phase == HvmPilotTransactionPhase::Confirmed
        && record.active_confirmation.is_none()
        && record.confirmed_height != Some(evidence.block_height)
    {
        enter_recovery(record);
        return Ok((HvmRegistryObservationOutcome::RecoveryRequired, true));
    }
    record.attempt_state = Some(HvmRegistrySubmissionAttemptState::Acknowledged);
    record.phase = HvmPilotTransactionPhase::Confirmed;
    record.confirmed_height = Some(evidence.block_height);
    record.active_confirmation = Some(evidence);
    Ok((HvmRegistryObservationOutcome::Confirmed, true))
}

fn enter_recovery<T>(record: &mut TransactionRecord<T>) {
    if let Some(active) = record.active_confirmation.take() {
        if !record.confirmation_history.contains(&active) {
            record.confirmation_history.push(active);
        }
    } else if let Some(height) = record.confirmed_height {
        let legacy = HvmRegistryConfirmationEvidence {
            block_height: height,
            block_hash: None,
            observed_confirmations: 0,
        };
        if !record.confirmation_history.contains(&legacy) {
            record.confirmation_history.push(legacy);
        }
    }
    record.confirmed_height = None;
    record.phase = HvmPilotTransactionPhase::RecoveryRequired;
}

fn migrate_record<T>(record: Option<&mut TransactionRecord<T>>) -> bool {
    let Some(record) = record else {
        return false;
    };
    let mut changed = false;
    if record.attempt_state.is_none() {
        record.attempt_state = Some(match record.phase {
            HvmPilotTransactionPhase::Signed | HvmPilotTransactionPhase::RecoveryRequired => {
                HvmRegistrySubmissionAttemptState::LegacyUnknown
            }
            HvmPilotTransactionPhase::Submitted | HvmPilotTransactionPhase::Confirmed => {
                HvmRegistrySubmissionAttemptState::Acknowledged
            }
        });
        changed = true;
    }
    if record.phase == HvmPilotTransactionPhase::Confirmed
        && record.active_confirmation.is_none()
        && let Some(height) = record.confirmed_height
    {
        record.active_confirmation = Some(HvmRegistryConfirmationEvidence {
            block_height: height,
            block_hash: None,
            observed_confirmations: 0,
        });
        changed = true;
    }
    changed
}

fn effective_attempt_state<T>(record: &TransactionRecord<T>) -> HvmRegistrySubmissionAttemptState {
    record.attempt_state.unwrap_or(match record.phase {
        HvmPilotTransactionPhase::Signed | HvmPilotTransactionPhase::RecoveryRequired => {
            HvmRegistrySubmissionAttemptState::LegacyUnknown
        }
        HvmPilotTransactionPhase::Submitted | HvmPilotTransactionPhase::Confirmed => {
            HvmRegistrySubmissionAttemptState::Acknowledged
        }
    })
}

fn canonical_hash(value: &str) -> Option<&str> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

fn exact_record<'a, T: ExactTransaction>(
    record: Option<&'a mut TransactionRecord<T>>,
    hash: &str,
    label: &str,
) -> HubResult<&'a mut TransactionRecord<T>> {
    let record = record.ok_or_else(|| HubError::State(format!("registry {label} is missing")))?;
    if record.transaction.transaction_hash() != hash {
        return Err(HubError::State(format!(
            "registry {label} transaction hash changed"
        )));
    }
    Ok(record)
}

trait ExactTransaction {
    fn transaction_hash(&self) -> &str;
    fn signed_transaction(&self) -> &HvmPilotSignedTransaction;
}

impl ExactTransaction for HvmPilotSignedTransaction {
    fn transaction_hash(&self) -> &str {
        &self.transaction_hash
    }

    fn signed_transaction(&self) -> &HvmPilotSignedTransaction {
        self
    }
}

impl ExactTransaction for HvmPilotDeploymentTransaction {
    fn transaction_hash(&self) -> &str {
        &self.transaction.transaction_hash
    }

    fn signed_transaction(&self) -> &HvmPilotSignedTransaction {
        &self.transaction
    }
}

fn stage_label(stage: HvmRegistryLifecycleStage) -> &'static str {
    match stage {
        HvmRegistryLifecycleStage::HubPrefunding => "Hub prefunding",
        HvmRegistryLifecycleStage::Deployment => "deployment",
        HvmRegistryLifecycleStage::Initialization => "initialization",
        HvmRegistryLifecycleStage::Funding => "funding",
    }
}

fn validate_state(
    state: &HvmRegistryPilotDurableState,
    network: &HvmLocalPilotNetwork,
    left: &str,
    hub: &str,
) -> HubResult<()> {
    validate_state_identity(state, network, left, hub)?;
    validate_record(state.hub_prefunding.as_ref(), "Hub prefunding")?;
    if state.hub_prefunding.is_some() != state.hub_prefunding_network_fee_zhu.is_some()
        || matches!(state.hub_prefunding_network_fee_zhu, Some(0))
        || state.hub_prefunding_preview.is_some() && state.hub_prefunding.is_none()
    {
        return Err(HubError::State(
            "registry Hub prefunding fee evidence is incomplete".into(),
        ));
    }
    if let Some(prefunding) = state.hub_prefunding.as_ref() {
        let transaction = validate_durable_pilot_transaction(
            &prefunding.transaction,
            network.chain_id,
            &[0x0411, 1],
            1,
            &[left, hub],
        )?;
        let transfer = HacToTrs::downcast(&transaction.actions()[1]).ok_or_else(|| {
            HubError::State("registry Hub prefunding transfer is malformed".into())
        })?;
        let destination = Address::from_readable(hub)
            .map_err(|_| HubError::State("registry Hub address is malformed".into()))?;
        let expected = HacToTrs::create_by(
            destination,
            Amount::zhu(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU),
        );
        if transfer.serialize() != expected.serialize() {
            return Err(HubError::State(
                "registry Hub prefunding amount or destination changed".into(),
            ));
        }
        if let Some(preview) = state.hub_prefunding_preview.as_ref() {
            validate_hvm_registry_pilot_prefund_transaction(&prefunding.transaction, preview)?;
            if preview.source_address != state.left_address
                || preview.destination_address != state.hub_address
                || preview.network_fee_zhu != state.hub_prefunding_network_fee_zhu.unwrap_or(0)
            {
                return Err(HubError::State(
                    "registry durable prefund preview identity or fee changed".into(),
                ));
            }
        }
    }
    validate_record(state.deployment.as_ref(), "deployment")?;
    if state.hub_prefunding.is_some()
        && state.deployment.is_some()
        && !matches!(
            state.hub_prefunding.as_ref().map(|record| &record.phase),
            Some(HvmPilotTransactionPhase::Confirmed)
        )
    {
        return Err(HubError::State(
            "registry deployment exists before Hub prefunding confirmation".into(),
        ));
    }
    validate_record(state.initialization.as_ref(), "initialization")?;
    validate_record(state.funding.as_ref(), "funding")?;
    if state.initialization.is_some() != state.initialization_preview.is_some()
        || state.funding.is_some() != state.funding_preview.is_some()
    {
        return Err(HubError::State(
            "registry lifecycle preview evidence is incomplete".into(),
        ));
    }
    let lifecycle = [
        state.channel_parameters.is_some(),
        state.recovery_bundle.is_some(),
        state.initialization.is_some(),
    ];
    if lifecycle.iter().any(|value| *value) && !lifecycle.iter().all(|value| *value) {
        return Err(HubError::State(
            "registry initialization state is incomplete".into(),
        ));
    }
    if state.funding.is_some() && state.initialization.is_none() {
        return Err(HubError::State(
            "registry funding exists without initialization".into(),
        ));
    }
    if let (
        Some(deployment),
        Some(parameters),
        Some(bundle),
        Some(initialization_preview),
        Some(initialization),
    ) = (
        state.deployment.as_ref(),
        state.channel_parameters.as_ref(),
        state.recovery_bundle.as_ref(),
        state.initialization_preview.as_ref(),
        state.initialization.as_ref(),
    ) {
        parameters.validate()?;
        bundle.validate_crypto()?;
        initialization_preview.validate()?;
        validate_hvm_registry_pilot_initialization_transaction(
            &initialization.transaction,
            initialization_preview,
        )?;
        let binding = &bundle.binding;
        if binding.network_instance_id != network.network_instance_id
            || binding.chain_id != network.chain_id
            || binding.left_address != left
            || binding.right_hub_address != hub
            || binding.contract_address != deployment.transaction.contract_address
            || binding.deployment_tx_hash != deployment.transaction.transaction.transaction_hash
            || binding.deployment_height != deployment.confirmed_height.unwrap_or_default()
            || binding.channel_id != parameters.channel_id
            || binding.reuse_version != parameters.reuse_version
            || binding.left_deposit_zhu != parameters.left_deposit_zhu
            || binding.right_hub_deposit_zhu != parameters.right_hub_deposit_zhu
            || binding.challenge_blocks != parameters.challenge_blocks
            || initialization_preview.left_address != state.left_address
            || initialization_preview.hub_address != state.hub_address
            || initialization_preview.contract_address != deployment.transaction.contract_address
            || initialization_preview.parameters != *parameters
            || initialization.confirmed_height.is_none()
                && initialization.phase == HvmPilotTransactionPhase::Confirmed
        {
            return Err(HubError::State(
                "registry durable lifecycle evidence is inconsistent".into(),
            ));
        }
    }
    if let (Some(deployment), Some(parameters), Some(funding_preview), Some(funding)) = (
        state.deployment.as_ref(),
        state.channel_parameters.as_ref(),
        state.funding_preview.as_ref(),
        state.funding.as_ref(),
    ) {
        funding_preview.validate()?;
        validate_hvm_registry_pilot_funding_transaction(&funding.transaction, funding_preview)?;
        if funding_preview.left_address != state.left_address
            || funding_preview.hub_address != state.hub_address
            || funding_preview.contract_address != deployment.transaction.contract_address
            || funding_preview.amount_zhu != parameters.left_deposit_zhu
        {
            return Err(HubError::State(
                "registry durable funding preview is inconsistent".into(),
            ));
        }
    }
    Ok(())
}

fn validate_record<T>(record: Option<&TransactionRecord<T>>, label: &str) -> HubResult<()> {
    let Some(record) = record else {
        return Ok(());
    };
    if record.phase == HvmPilotTransactionPhase::Confirmed
        && (record.confirmed_height.is_none() || record.active_confirmation.is_none())
        || record.phase != HvmPilotTransactionPhase::Confirmed
            && (record.confirmed_height.is_some() || record.active_confirmation.is_some())
    {
        return Err(HubError::State(format!(
            "registry {label} phase and active confirmation evidence disagree"
        )));
    }
    let attempt = effective_attempt_state(record);
    if matches!(
        record.phase,
        HvmPilotTransactionPhase::Submitted | HvmPilotTransactionPhase::Confirmed
    ) && attempt != HvmRegistrySubmissionAttemptState::Acknowledged
    {
        return Err(HubError::State(format!(
            "registry {label} lacks an acknowledged durable submit attempt"
        )));
    }
    if record.phase == HvmPilotTransactionPhase::Signed
        && attempt == HvmRegistrySubmissionAttemptState::Acknowledged
    {
        return Err(HubError::State(format!(
            "registry {label} acknowledged attempt cannot remain signed"
        )));
    }
    if let Some(active) = record.active_confirmation.as_ref() {
        validate_confirmation_evidence(active, true, label)?;
        if record.confirmed_height != Some(active.block_height) {
            return Err(HubError::State(format!(
                "registry {label} active block evidence changed height"
            )));
        }
    }
    for evidence in &record.confirmation_history {
        validate_confirmation_evidence(evidence, false, label)?;
    }
    Ok(())
}

fn validate_state_identity(
    state: &HvmRegistryPilotDurableState,
    network: &HvmLocalPilotNetwork,
    left: &str,
    hub: &str,
) -> HubResult<()> {
    if state.schema != STATE_SCHEMA
        || &state.network != network
        || state.left_address != left
        || state.hub_address != hub
    {
        return Err(HubError::State(
            "registry pilot state identity or network changed".into(),
        ));
    }
    Ok(())
}

fn validate_confirmation_evidence(
    evidence: &HvmRegistryConfirmationEvidence,
    active: bool,
    label: &str,
) -> HubResult<()> {
    if evidence.block_height == 0
        || evidence
            .block_hash
            .as_deref()
            .is_some_and(|hash| canonical_hash(hash).is_none())
        || active && evidence.block_hash.is_none() && evidence.observed_confirmations != 0
    {
        return Err(HubError::State(format!(
            "registry {label} has malformed confirmation audit evidence"
        )));
    }
    Ok(())
}

fn require_public_identity(value: &str, label: &str) -> HubResult<()> {
    if value.trim().is_empty() || value.len() > 64 {
        return Err(HubError::State(format!(
            "registry pilot {label} identity is invalid"
        )));
    }
    Ok(())
}

fn state_body(state: &HvmRegistryPilotDurableState) -> StateBody<'_> {
    StateBody {
        schema: &state.schema,
        network: &state.network,
        left_address: &state.left_address,
        hub_address: &state.hub_address,
        hub_prefunding: &state.hub_prefunding,
        hub_prefunding_network_fee_zhu: &state.hub_prefunding_network_fee_zhu,
        hub_prefunding_preview: &state.hub_prefunding_preview,
        deployment: &state.deployment,
        channel_parameters: &state.channel_parameters,
        recovery_bundle: &state.recovery_bundle,
        initialization_preview: &state.initialization_preview,
        initialization: &state.initialization,
        funding_preview: &state.funding_preview,
        funding: &state.funding,
    }
}

fn compute_tag(state: &HvmRegistryPilotDurableState, key: &[u8]) -> HubResult<String> {
    let bytes = serde_json::to_vec(&state_body(state))
        .map_err(|error| HubError::State(format!("registry pilot state encode failed: {error}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| HubError::State("registry pilot state key is invalid".into()))?;
    mac.update(STATE_DOMAIN);
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_tag(state: &HvmRegistryPilotDurableState, key: &[u8]) -> HubResult<()> {
    let tag = hex::decode(&state.authentication_tag)
        .map_err(|_| HubError::State("registry pilot authentication tag is invalid".into()))?;
    let bytes = serde_json::to_vec(&state_body(state))
        .map_err(|error| HubError::State(format!("registry pilot state encode failed: {error}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| HubError::State("registry pilot state key is invalid".into()))?;
    mac.update(STATE_DOMAIN);
    mac.update(&bytes);
    mac.verify_slice(&tag)
        .map_err(|_| HubError::State("registry pilot state authentication failed".into()))
}

fn decode_key(value: &str) -> HubResult<Zeroizing<[u8; 32]>> {
    let bytes = hex::decode(value)
        .map_err(|_| HubError::State("registry pilot state key is invalid".into()))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| HubError::State("registry pilot state key must be 32 bytes".into()))?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, rngs::OsRng};
    use tempfile::{TempDir, tempdir};

    const FEE: u64 = 500_000;

    fn state_key() -> String {
        let mut raw_key = [0u8; 32];
        OsRng.fill_bytes(&mut raw_key);
        hex::encode(raw_key)
    }

    fn observation(
        transaction: &HvmPilotSignedTransaction,
        pending: bool,
        height: Option<u64>,
        block_hash: Option<&str>,
        confirmations: u64,
    ) -> TransactionObservation {
        TransactionObservation {
            hash: transaction.transaction_hash.clone(),
            body_hex: transaction.signed_transaction_hex.clone(),
            pending,
            block_height: height,
            block_hash: block_hash.map(str::to_owned),
            confirmations,
        }
    }

    fn open_store(
        dir: &TempDir,
        key: &str,
        network: &HvmLocalPilotNetwork,
        left: &Account,
        hub: &Account,
    ) -> HvmRegistryPilotStateStore {
        HvmRegistryPilotStateStore::open(
            dir.path().join("registry.json"),
            key,
            network.clone(),
            left.readable(),
            hub.readable(),
        )
        .unwrap()
    }

    fn prepare_prefund(
        store: &mut HvmRegistryPilotStateStore,
        left: &Account,
        hub: &Account,
        network: &HvmLocalPilotNetwork,
    ) -> HvmRegistryPrepared<HvmPilotSignedTransaction> {
        let preview = preview_hvm_registry_pilot_prefund(
            left.readable(),
            hub.readable(),
            network,
            FEE,
            99,
            199,
            u8::MAX,
        )
        .unwrap();
        store
            .prepare_hub_prefunding(
                left,
                FEE,
                99,
                199,
                u8::MAX,
                &preview.unsigned_commitment,
                99,
            )
            .unwrap()
    }

    fn initial_submit_and_confirm<T: ExactTransaction>(
        store: &mut HvmRegistryPilotStateStore,
        stage: HvmRegistryLifecycleStage,
        prepared: &HvmRegistryPrepared<T>,
        height: u64,
        block_hash: &str,
    ) {
        let transaction = prepared.transaction.signed_transaction();
        store
            .begin_initial_submission(
                stage,
                &transaction.transaction_hash,
                &prepared.request_commitment,
                99,
            )
            .unwrap();
        store
            .mark_submission_acknowledged(stage, &transaction.transaction_hash)
            .unwrap();
        assert_eq!(
            store
                .reconcile_observation(
                    stage,
                    Some(&observation(
                        transaction,
                        false,
                        Some(height),
                        Some(block_hash),
                        6,
                    )),
                    6,
                )
                .unwrap(),
            HvmRegistryObservationOutcome::Confirmed
        );
    }

    #[test]
    fn full_registry_lifecycle_is_authenticated_locked_and_restart_safe() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let dir = tempdir().unwrap();
        let network = HvmLocalPilotNetwork::canonical();
        let left = Account::create_by("registry-state-left").unwrap();
        let hub = Account::create_by("registry-state-hub").unwrap();
        let key = state_key();
        let mut store = open_store(&dir, &key, &network, &left, &hub);
        let prefunding = prepare_prefund(&mut store, &left, &hub, &network);
        assert_eq!(
            prefunding.provenance,
            HvmRegistryPrepareProvenance::CreatedThisInvocation
        );
        assert_eq!(
            store
                .reconcile_observation(HvmRegistryLifecycleStage::HubPrefunding, None, 6)
                .unwrap(),
            HvmRegistryObservationOutcome::NeverAttempted
        );
        initial_submit_and_confirm(
            &mut store,
            HvmRegistryLifecycleStage::HubPrefunding,
            &prefunding,
            9,
            &"11".repeat(32),
        );
        let preview_commitment =
            preview_hvm_registry_pilot_deployment(hub.readable(), &network, FEE, u8::MAX)
                .unwrap()
                .unsigned_commitment;
        assert!(
            store
                .prepare_deployment(&hub, FEE, 100, u8::MAX, &"00".repeat(32))
                .is_err()
        );
        let deployment = store
            .prepare_deployment(&hub, FEE, 100, u8::MAX, &preview_commitment)
            .unwrap();
        initial_submit_and_confirm(
            &mut store,
            HvmRegistryLifecycleStage::Deployment,
            &deployment,
            10,
            &"22".repeat(32),
        );
        let parameters = HvmRegistryPilotChannelParameters {
            channel_id: "66".repeat(16),
            reuse_version: 0,
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let initialization_preview = preview_hvm_registry_pilot_initialization(
            left.readable(),
            hub.readable(),
            &deployment.transaction.contract_address,
            &network,
            &parameters,
            FEE,
            u8::MAX,
        )
        .unwrap();
        assert!(
            store
                .prepare_initialization(
                    &left,
                    &hub,
                    parameters.clone(),
                    FEE,
                    101,
                    u8::MAX,
                    &"00".repeat(32),
                )
                .is_err()
        );
        let initialization = store
            .prepare_initialization(
                &left,
                &hub,
                parameters.clone(),
                FEE,
                101,
                u8::MAX,
                &initialization_preview.unsigned_commitment,
            )
            .unwrap();
        assert!(
            store
                .prepare_initialization(
                    &left,
                    &hub,
                    parameters.clone(),
                    FEE + 1,
                    102,
                    u8::MAX,
                    &initialization_preview.unsigned_commitment,
                )
                .is_err(),
            "initialization retry cannot change its reviewed fee"
        );
        initial_submit_and_confirm(
            &mut store,
            HvmRegistryLifecycleStage::Initialization,
            &initialization,
            11,
            &"33".repeat(32),
        );
        let funding_preview = preview_hvm_registry_pilot_funding(
            left.readable(),
            hub.readable(),
            &deployment.transaction.contract_address,
            &network,
            parameters.left_deposit_zhu,
            FEE,
            u8::MAX,
        )
        .unwrap();
        assert!(
            store
                .prepare_funding(&left, FEE, 102, u8::MAX, &"00".repeat(32))
                .is_err()
        );
        let funding = store
            .prepare_funding(
                &left,
                FEE,
                102,
                u8::MAX,
                &funding_preview.unsigned_commitment,
            )
            .unwrap();
        assert!(
            store
                .prepare_funding(
                    &left,
                    FEE + 1,
                    103,
                    u8::MAX,
                    &funding_preview.unsigned_commitment,
                )
                .is_err(),
            "funding retry cannot change its reviewed fee"
        );
        initial_submit_and_confirm(
            &mut store,
            HvmRegistryLifecycleStage::Funding,
            &funding,
            12,
            &"44".repeat(32),
        );
        assert!(store.recovery_bundle().is_some());
        assert!(
            HvmRegistryPilotStateStore::open(
                dir.path().join("registry.json"),
                &key,
                network.clone(),
                left.readable(),
                hub.readable(),
            )
            .is_err(),
            "the live owner must retain the exclusive journal lock"
        );
        drop(store);
        let reopened = open_store(&dir, &key, &network, &left, &hub);
        assert_eq!(
            reopened.hub_prefunding().map(|entry| entry.0),
            Some(&HvmPilotTransactionPhase::Confirmed)
        );
        assert_eq!(
            reopened.funding().map(|entry| entry.0),
            Some(&HvmPilotTransactionPhase::Confirmed)
        );
        let evidence = reopened
            .lifecycle_snapshot(HvmRegistryLifecycleStage::Funding)
            .and_then(|snapshot| snapshot.active_confirmation)
            .unwrap();
        assert_eq!(evidence.block_hash.as_deref(), Some(&*"44".repeat(32)));
    }

    #[test]
    fn restart_blocks_initial_submit_and_exact_resubmit_binds_hash_and_commitment() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let dir = tempdir().unwrap();
        let network = HvmLocalPilotNetwork::canonical();
        let left = Account::create_by("registry-restart-left").unwrap();
        let hub = Account::create_by("registry-restart-hub").unwrap();
        let key = state_key();
        let mut store = open_store(&dir, &key, &network, &left, &hub);
        let prepared = prepare_prefund(&mut store, &left, &hub, &network);
        let hash = prepared.transaction.transaction_hash.clone();
        let commitment = prepared.request_commitment.clone();
        drop(store);

        let mut reopened = open_store(&dir, &key, &network, &left, &hub);
        assert!(
            reopened
                .begin_initial_submission(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    &hash,
                    &commitment,
                    99,
                )
                .is_err()
        );
        assert_eq!(
            reopened
                .reconcile_observation(HvmRegistryLifecycleStage::HubPrefunding, None, 6)
                .unwrap(),
            HvmRegistryObservationOutcome::RecoveryRequired
        );
        assert!(
            reopened
                .begin_exact_resubmit(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    &"00".repeat(32),
                    &commitment,
                )
                .is_err()
        );
        assert!(
            reopened
                .begin_exact_resubmit(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    &hash,
                    &"00".repeat(32),
                )
                .is_err()
        );
        assert_eq!(
            reopened
                .begin_exact_resubmit(HvmRegistryLifecycleStage::HubPrefunding, &hash, &commitment,)
                .unwrap()
                .transaction_hash,
            hash
        );
        drop(reopened);

        let mut after_started = open_store(&dir, &key, &network, &left, &hub);
        assert_eq!(
            after_started
                .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
                .unwrap()
                .attempt_state,
            HvmRegistrySubmissionAttemptState::SubmissionStarted
        );
        assert_eq!(
            after_started
                .reconcile_observation(HvmRegistryLifecycleStage::HubPrefunding, None, 6)
                .unwrap(),
            HvmRegistryObservationOutcome::RecoveryRequired
        );
    }

    #[test]
    fn prefund_expiry_is_rechecked_at_submission_started_boundary() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let dir = tempdir().unwrap();
        let network = HvmLocalPilotNetwork::canonical();
        let left = Account::create_by("registry-expiry-left").unwrap();
        let hub = Account::create_by("registry-expiry-hub").unwrap();
        let key = state_key();
        let mut store = open_store(&dir, &key, &network, &left, &hub);
        let prepared = prepare_prefund(&mut store, &left, &hub, &network);
        assert!(
            store
                .begin_initial_submission(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    &prepared.transaction.transaction_hash,
                    &prepared.request_commitment,
                    200,
                )
                .is_err()
        );
        let snapshot = store
            .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
            .unwrap();
        assert_eq!(snapshot.phase, HvmPilotTransactionPhase::Signed);
        assert_eq!(
            snapshot.attempt_state,
            HvmRegistrySubmissionAttemptState::NeverAttempted
        );
        store
            .begin_initial_submission(
                HvmRegistryLifecycleStage::HubPrefunding,
                &prepared.transaction.transaction_hash,
                &prepared.request_commitment,
                199,
            )
            .unwrap();
    }

    #[test]
    fn observation_matrix_is_fail_closed_and_preserves_reorg_audit() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let dir = tempdir().unwrap();
        let network = HvmLocalPilotNetwork::canonical();
        let left = Account::create_by("registry-observe-left").unwrap();
        let hub = Account::create_by("registry-observe-hub").unwrap();
        let key = state_key();
        let mut store = open_store(&dir, &key, &network, &left, &hub);
        let prepared = prepare_prefund(&mut store, &left, &hub, &network);
        let transaction = prepared.transaction.clone();
        store
            .begin_initial_submission(
                HvmRegistryLifecycleStage::HubPrefunding,
                &transaction.transaction_hash,
                &prepared.request_commitment,
                99,
            )
            .unwrap();
        assert_eq!(
            store
                .reconcile_observation(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    Some(&observation(&transaction, true, None, None, 0)),
                    6,
                )
                .unwrap(),
            HvmRegistryObservationOutcome::Pending
        );
        assert_eq!(
            store
                .reconcile_observation(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    Some(&observation(
                        &transaction,
                        false,
                        Some(9),
                        Some(&"55".repeat(32)),
                        5,
                    )),
                    6,
                )
                .unwrap(),
            HvmRegistryObservationOutcome::AwaitingConfirmations
        );
        assert_eq!(
            store
                .reconcile_observation(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    Some(&observation(
                        &transaction,
                        false,
                        Some(9),
                        Some(&"55".repeat(32)),
                        6,
                    )),
                    6,
                )
                .unwrap(),
            HvmRegistryObservationOutcome::Confirmed
        );

        let before_error = store
            .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
            .unwrap();
        assert!(
            store
                .reconcile_observation_result(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    Err(HubError::Node("query unavailable".into())),
                    6,
                )
                .is_err()
        );
        assert_eq!(
            store
                .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
                .unwrap(),
            before_error
        );

        assert_eq!(
            store
                .reconcile_observation(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    Some(&observation(
                        &transaction,
                        false,
                        Some(9),
                        Some(&"66".repeat(32)),
                        6,
                    )),
                    6,
                )
                .unwrap(),
            HvmRegistryObservationOutcome::RecoveryRequired
        );
        let recovered = store
            .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
            .unwrap();
        assert!(recovered.active_confirmation.is_none());
        assert_eq!(recovered.confirmation_history.len(), 1);
        assert_eq!(
            recovered.confirmation_history[0].block_hash.as_deref(),
            Some(&*"55".repeat(32))
        );
        assert_eq!(
            store.hub_prefunding().unwrap().0,
            &HvmPilotTransactionPhase::RecoveryRequired
        );
        assert!(store.hub_prefunding().unwrap().2.is_none());
    }

    #[test]
    fn wrong_body_and_tip_rollback_require_recovery() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let dir = tempdir().unwrap();
        let network = HvmLocalPilotNetwork::canonical();
        let left = Account::create_by("registry-wrong-body-left").unwrap();
        let hub = Account::create_by("registry-wrong-body-hub").unwrap();
        let key = state_key();
        let mut store = open_store(&dir, &key, &network, &left, &hub);
        let prepared = prepare_prefund(&mut store, &left, &hub, &network);
        initial_submit_and_confirm(
            &mut store,
            HvmRegistryLifecycleStage::HubPrefunding,
            &prepared,
            9,
            &"77".repeat(32),
        );
        assert_eq!(
            store
                .reconcile_observation(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    Some(&observation(
                        &prepared.transaction,
                        false,
                        Some(9),
                        Some(&"77".repeat(32)),
                        5,
                    )),
                    6,
                )
                .unwrap(),
            HvmRegistryObservationOutcome::RecoveryRequired
        );
        let history_len = store
            .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
            .unwrap()
            .confirmation_history
            .len();
        let mut wrong = observation(
            &prepared.transaction,
            false,
            Some(9),
            Some(&"77".repeat(32)),
            6,
        );
        wrong.body_hex = "00".repeat(32);
        assert!(
            store
                .reconcile_observation(HvmRegistryLifecycleStage::HubPrefunding, Some(&wrong), 6,)
                .is_err()
        );
        assert_eq!(
            store
                .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
                .unwrap()
                .confirmation_history
                .len(),
            history_len
        );
    }

    #[test]
    fn authenticated_legacy_confirmed_record_is_migrated_without_inventing_block_hash() {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let dir = tempdir().unwrap();
        let network = HvmLocalPilotNetwork::canonical();
        let left = Account::create_by("registry-legacy-left").unwrap();
        let hub = Account::create_by("registry-legacy-hub").unwrap();
        let key = state_key();
        let mut store = open_store(&dir, &key, &network, &left, &hub);
        prepare_prefund(&mut store, &left, &hub, &network);
        let record = store.state.hub_prefunding.as_mut().unwrap();
        record.phase = HvmPilotTransactionPhase::Confirmed;
        record.confirmed_height = Some(7);
        record.attempt_state = None;
        record.active_confirmation = None;
        record.confirmation_history.clear();
        store.state.hub_prefunding_preview = None;
        store.state.authentication_tag = compute_tag(&store.state, store.key.as_ref()).unwrap();
        let legacy = serde_json::to_vec_pretty(&store.state).unwrap();
        crate::storage::save_bytes_atomic(&store.path, &legacy).unwrap();
        drop(store);

        let mut reopened = open_store(&dir, &key, &network, &left, &hub);
        let snapshot = reopened
            .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
            .unwrap();
        assert_eq!(
            snapshot.attempt_state,
            HvmRegistrySubmissionAttemptState::Acknowledged
        );
        let legacy_anchor = snapshot.active_confirmation.unwrap();
        assert_eq!(legacy_anchor.block_height, 7);
        assert!(legacy_anchor.block_hash.is_none());
        assert_eq!(legacy_anchor.observed_confirmations, 0);
        let transaction = snapshot.transaction;
        assert_eq!(
            reopened
                .reconcile_observation(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    Some(&observation(
                        &transaction,
                        false,
                        Some(7),
                        Some(&"88".repeat(32)),
                        6,
                    )),
                    6,
                )
                .unwrap(),
            HvmRegistryObservationOutcome::Confirmed
        );
        assert_eq!(
            reopened
                .lifecycle_snapshot(HvmRegistryLifecycleStage::HubPrefunding)
                .unwrap()
                .active_confirmation
                .unwrap()
                .block_hash
                .as_deref(),
            Some(&*"88".repeat(32))
        );
        assert_eq!(
            reopened
                .reconcile_observation(
                    HvmRegistryLifecycleStage::HubPrefunding,
                    Some(&observation(
                        &transaction,
                        false,
                        Some(8),
                        Some(&"99".repeat(32)),
                        6,
                    )),
                    6,
                )
                .unwrap(),
            HvmRegistryObservationOutcome::RecoveryRequired
        );
    }
}
