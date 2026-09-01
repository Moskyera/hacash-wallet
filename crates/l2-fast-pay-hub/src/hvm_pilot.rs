//! Exact transaction builders for the HPAY HVM Local Pilot lifecycle.
//!
//! This module is not a mainnet deployment switch. Every builder requires the
//! pinned chain-7 identity, embeds ChainAllow and rejects Hub-funded channels.

use std::fs::OpenOptions;
use std::path::PathBuf;

use basis::interface::{Transaction, TransactionRead};
use field::{
    AddrOrList, AddrOrPtr, Address, Amount, Field, Serialize as FieldSerialize, Sign, Uint1, Uint4,
};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use protocol::action::{ChainAllow, ChainIDList, HacToTrs, ReqSignList};
use protocol::transaction::TransactionType3;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sys::Account;
use vm::ContractAddress;
use vm::action::{ContractDeploy, ContractMainCall};

use crate::error::{HubError, HubResult};
use crate::hvm_channel::{
    HVM_CHANNEL_BILL_SCHEMA, HVM_CHANNEL_BINDING_SCHEMA, HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA,
    HvmChannelBillV1, HvmChannelBindingV1, HvmChannelRecoveryBundleV1,
};
use crate::hvm_ledger::HvmPaymentRequestV1;
use crate::node::HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE;
use crate::node::{FullnodeCapabilitiesV1, HPAY_CHANNEL_EXIT_BYTECODE_SHA3};

pub const HPAY_LOCAL_PILOT_CHAIN_ID: u32 = 7;
pub const HPAY_LOCAL_PILOT_NETWORK_KIND: &str = "local_pilot_v1";
pub const HPAY_LOCAL_PILOT_PROFILE_ID: &str = "hpay-local-pilot-chain-v1";
pub const HPAY_LOCAL_PILOT_BLOCK_ONE_HASH: &str =
    "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29";
pub const HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID: &str =
    "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3";
pub const HPAY_CHANNEL_EXIT_SOURCE_SHA256: &str =
    "c0a430eb9769d1d506641c379bb8aaf708c7bac7d03694b60a4be03fd001dd06";
/// Canonical HPAY fullnode mempool floor (unit-238 per canonical Type 3
/// billing byte). Type 3 computes its deterministic signer-set size before
/// signatures exist, so this can and must be enforced before key use.
pub const HVM_PILOT_MIN_FEE_PURITY: u64 = 1_000_000 / 166;

const CONTRACT_SOURCE: &str =
    include_str!("../../../../hacash-fullnodedev/vm/contracts/hpay_channel_exit_v1.fitsh");
const CONTRACT_PROTOCOL_COST_238: u64 = 2_000_000_000_000;
pub const HVM_PILOT_DEPLOY_PROTOCOL_COST_ZHU: u64 = CONTRACT_PROTOCOL_COST_238 / 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HvmPilotDeploymentPreview {
    pub contract_address: String,
    pub source_sha256: String,
    pub bytecode_sha3: String,
    pub protocol_cost_zhu: u64,
}

fn compile_canonical_hvm_pilot_contract() -> HubResult<(vm::contract::Contract, String, String)> {
    let compiled = vm::fitshc::compile(CONTRACT_SOURCE)
        .map_err(|error| {
            HubError::State(format!("canonical HVM contract compile failed: {error}"))
        })?
        .0;
    let source_sha256 = hex::encode(Sha256::digest(CONTRACT_SOURCE.as_bytes()));
    let bytecode_sha3 = hex::encode(sys::sha3(compiled.serialize()));
    if source_sha256 != HPAY_CHANNEL_EXIT_SOURCE_SHA256
        || bytecode_sha3 != HPAY_CHANNEL_EXIT_BYTECODE_SHA3
    {
        return Err(HubError::State(
            "canonical HVM source or bytecode hash drifted".into(),
        ));
    }
    Ok((compiled, source_sha256, bytecode_sha3))
}

fn derive_hvm_pilot_contract_address(deployer_address: &str) -> HubResult<String> {
    let deployer = Address::from_readable(deployer_address).map_err(|error| {
        HubError::State(format!("HVM pilot deployer address is invalid: {error}"))
    })?;
    Ok(ContractAddress::calculate(&deployer, &Uint4::from(0)).to_readable())
}

/// Derive and verify the canonical Local Pilot deployment without constructing
/// a transaction or touching a signing key.
pub fn preview_hvm_pilot_deployment(
    deployer_address: &str,
    network: &HvmLocalPilotNetwork,
) -> HubResult<HvmPilotDeploymentPreview> {
    network.validate()?;
    let (_, source_sha256, bytecode_sha3) = compile_canonical_hvm_pilot_contract()?;
    Ok(HvmPilotDeploymentPreview {
        contract_address: derive_hvm_pilot_contract_address(deployer_address)?,
        source_sha256,
        bytecode_sha3,
        protocol_cost_zhu: HVM_PILOT_DEPLOY_PROTOCOL_COST_ZHU,
    })
}

/// Build the exact left-signed, fee-free next bill used by the Local Pilot.
///
/// The caller must persist the returned request in the authenticated Hub state
/// before the Hub key is used. This helper cannot enable a public or mainnet
/// profile: the binding must match the pinned private chain-7 identity.
#[allow(clippy::too_many_arguments)]
pub fn build_hvm_pilot_payment_request(
    left: &Account,
    binding: &HvmChannelBindingV1,
    previous: &HvmChannelBillV1,
    operation_id: &str,
    idempotency_key: &str,
    recipient: &str,
    amount_zhu: u64,
    created_unix: u64,
    expires_unix: u64,
) -> HubResult<HvmPaymentRequestV1> {
    let network = HvmLocalPilotNetwork::canonical();
    network.validate()?;
    binding.validate()?;
    if binding.chain_id != network.chain_id
        || binding.network_instance_id != network.network_instance_id
        || binding.left_address != left.readable()
        || binding.right_hub_deposit_zhu != 0
    {
        return Err(HubError::Payment(
            "HVM Local Pilot payment binding is invalid".into(),
        ));
    }
    let mut request = HvmPaymentRequestV1::build_unsigned(
        binding,
        previous,
        operation_id,
        idempotency_key,
        recipient,
        amount_zhu,
        created_unix,
        expires_unix,
    )?;
    let hash = request.proposed_bill.signing_hash(binding)?;
    request.proposed_bill.left_signature_hex =
        hex::encode(Sign::create_by(left, &hash).serialize());
    request.validate_against(binding, previous, created_unix)?;
    Ok(request)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmLocalPilotNetwork {
    pub network_kind: String,
    pub node_profile_id: String,
    pub chain_id: u32,
    pub block_1_hash: String,
    pub network_instance_id: String,
    pub transaction_format_version: u64,
}

impl HvmLocalPilotNetwork {
    pub fn canonical() -> Self {
        Self {
            network_kind: HPAY_LOCAL_PILOT_NETWORK_KIND.into(),
            node_profile_id: HPAY_LOCAL_PILOT_PROFILE_ID.into(),
            chain_id: HPAY_LOCAL_PILOT_CHAIN_ID,
            block_1_hash: HPAY_LOCAL_PILOT_BLOCK_ONE_HASH.into(),
            network_instance_id: HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID.into(),
            transaction_format_version: 2,
        }
    }

    pub fn validate(&self) -> HubResult<()> {
        if self != &Self::canonical() {
            return Err(HubError::Node(
                "HVM pilot refuses every network except the pinned chain-7 Local Pilot".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_capabilities(&self, capabilities: &FullnodeCapabilitiesV1) -> HubResult<()> {
        self.validate()?;
        if capabilities.mainnet
            || capabilities.network_kind != self.network_kind
            || capabilities.node_profile_id != self.node_profile_id
            || capabilities.chain_id != self.chain_id
            || capabilities.block_1_hash != self.block_1_hash
            || capabilities.network_instance_id.as_deref()
                != Some(self.network_instance_id.as_str())
            || capabilities.transaction_format_version != self.transaction_format_version
            || capabilities.enabled_transactions.binary_search(&3).is_err()
            || ![1_u16, 14, 40, 41, 44, 0x0411, 0x0414]
                .into_iter()
                .all(|kind| capabilities.action_enabled(kind))
            || !capabilities.transaction_submit_bound
        {
            return Err(HubError::Node(
                "fullnode does not prove the exact HPAY HVM Local Pilot contract".into(),
            ));
        }
        Ok(())
    }
}

pub fn validate_hvm_pilot_node_url(node_url: &str) -> HubResult<()> {
    let parsed = reqwest::Url::parse(node_url)
        .map_err(|_| HubError::Node("HVM Local Pilot node URL is invalid".into()))?;
    let loopback = parsed.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if parsed.scheme() != "http"
        || !loopback
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(HubError::Node(
            "HVM Local Pilot accepts only a clean loopback HTTP node origin".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmPilotSignedTransaction {
    pub transaction_hash: String,
    pub signed_transaction_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmPilotDeploymentTransaction {
    pub contract_address: String,
    pub source_sha256: String,
    pub bytecode_sha3: String,
    pub transaction: HvmPilotSignedTransaction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HvmPilotTransactionPhase {
    Signed,
    Submitted,
    Confirmed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HvmPilotDurableState {
    schema: String,
    network: HvmLocalPilotNetwork,
    left_address: String,
    hub_address: String,
    deployment_phase: Option<HvmPilotTransactionPhase>,
    deployment: Option<HvmPilotDeploymentTransaction>,
    #[serde(default)]
    deployment_confirmed_height: Option<u64>,
    #[serde(default)]
    channel_parameters: Option<HvmPilotChannelParameters>,
    #[serde(default)]
    recovery_bundle: Option<HvmChannelRecoveryBundleV1>,
    #[serde(default)]
    initialization_phase: Option<HvmPilotTransactionPhase>,
    #[serde(default)]
    initialization: Option<HvmPilotSignedTransaction>,
    #[serde(default)]
    initialization_confirmed_height: Option<u64>,
    #[serde(default)]
    funding_phase: Option<HvmPilotTransactionPhase>,
    #[serde(default)]
    funding: Option<HvmPilotSignedTransaction>,
    #[serde(default)]
    funding_confirmed_height: Option<u64>,
    authentication_tag: String,
}

#[derive(Serialize)]
struct HvmPilotStateBody<'a> {
    schema: &'a str,
    network: &'a HvmLocalPilotNetwork,
    left_address: &'a str,
    hub_address: &'a str,
    deployment_phase: &'a Option<HvmPilotTransactionPhase>,
    deployment: &'a Option<HvmPilotDeploymentTransaction>,
    deployment_confirmed_height: &'a Option<u64>,
    channel_parameters: &'a Option<HvmPilotChannelParameters>,
    recovery_bundle: &'a Option<HvmChannelRecoveryBundleV1>,
    initialization_phase: &'a Option<HvmPilotTransactionPhase>,
    initialization: &'a Option<HvmPilotSignedTransaction>,
    initialization_confirmed_height: &'a Option<u64>,
    funding_phase: &'a Option<HvmPilotTransactionPhase>,
    funding: &'a Option<HvmPilotSignedTransaction>,
    funding_confirmed_height: &'a Option<u64>,
}

pub struct HvmPilotStateStore {
    path: PathBuf,
    key: zeroize::Zeroizing<[u8; 32]>,
    state: HvmPilotDurableState,
    _lock: std::fs::File,
}

impl HvmPilotStateStore {
    pub fn open(
        path: impl Into<PathBuf>,
        state_key_hex: &str,
        network: HvmLocalPilotNetwork,
        left_address: &str,
        hub_address: &str,
    ) -> HubResult<Self> {
        network.validate()?;
        let path = path.into();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| HubError::State("HVM pilot state path has no parent".into()))?;
        std::fs::create_dir_all(parent).map_err(|error| {
            HubError::State(format!("cannot create pilot state directory: {error}"))
        })?;
        crate::storage::ensure_not_symlink(parent, "HVM pilot state directory")?;
        crate::storage::ensure_not_symlink(&path, "HVM pilot state")?;
        let lock_path = path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| HubError::State(format!("cannot open HVM pilot lock: {error}")))?;
        lock.try_lock_exclusive()
            .map_err(|_| HubError::State("HVM pilot state already has a live owner".into()))?;
        let raw_key = hex::decode(state_key_hex)
            .map_err(|_| HubError::State("HVM pilot state key is invalid".into()))?;
        let key: [u8; 32] = raw_key
            .try_into()
            .map_err(|_| HubError::State("HVM pilot state key must be 32 bytes".into()))?;
        let key = zeroize::Zeroizing::new(key);
        let state = if path.exists() {
            let bytes = std::fs::read(&path).map_err(|error| {
                HubError::State(format!("cannot read HVM pilot state: {error}"))
            })?;
            if bytes.is_empty() || bytes.len() > 1_048_576 {
                return Err(HubError::State("HVM pilot state size is invalid".into()));
            }
            let state: HvmPilotDurableState = serde_json::from_slice(&bytes)
                .map_err(|_| HubError::State("HVM pilot state is malformed".into()))?;
            verify_state_tag(&state, key.as_ref())?;
            if state.schema != "hpay-hvm-local-pilot-state/3"
                || state.network != network
                || state.left_address != left_address
                || state.hub_address != hub_address
                || state.deployment.is_some() != state.deployment_phase.is_some()
                || (state.deployment_phase == Some(HvmPilotTransactionPhase::Confirmed)
                    && state.deployment_confirmed_height.is_none())
            {
                return Err(HubError::State(
                    "HVM pilot state identity or phase is inconsistent".into(),
                ));
            }
            if let Some(deployment) = state.deployment.as_ref() {
                validate_durable_deployment(deployment, left_address, network.chain_id)?;
            }
            validate_durable_lifecycle(&state)?;
            state
        } else {
            HvmPilotDurableState {
                schema: "hpay-hvm-local-pilot-state/3".into(),
                network,
                left_address: left_address.to_owned(),
                hub_address: hub_address.to_owned(),
                deployment_phase: None,
                deployment: None,
                deployment_confirmed_height: None,
                channel_parameters: None,
                recovery_bundle: None,
                initialization_phase: None,
                initialization: None,
                initialization_confirmed_height: None,
                funding_phase: None,
                funding: None,
                funding_confirmed_height: None,
                authentication_tag: String::new(),
            }
        };
        Ok(Self {
            path,
            key,
            state,
            _lock: lock,
        })
    }

    pub fn deployment(
        &self,
    ) -> Option<(&HvmPilotTransactionPhase, &HvmPilotDeploymentTransaction)> {
        self.state
            .deployment_phase
            .as_ref()
            .zip(self.state.deployment.as_ref())
    }

    pub fn deployment_confirmed_height(&self) -> Option<u64> {
        self.state.deployment_confirmed_height
    }

    pub fn prepare_deployment(
        &mut self,
        deployer: &Account,
        network_fee_zhu: u64,
        timestamp: u64,
        gas_max: u8,
    ) -> HubResult<HvmPilotDeploymentTransaction> {
        if let Some((_, deployment)) = self.deployment() {
            return Ok(deployment.clone());
        }
        if deployer.readable() != self.state.left_address {
            return Err(HubError::State(
                "HVM pilot deployer does not match durable left identity".into(),
            ));
        }
        let deployment = build_hvm_pilot_deployment(
            deployer,
            &self.state.network,
            network_fee_zhu,
            timestamp,
            gas_max,
        )?;
        self.state.deployment_phase = Some(HvmPilotTransactionPhase::Signed);
        self.state.deployment = Some(deployment.clone());
        self.save()?;
        Ok(deployment)
    }

    pub fn mark_deployment_submitted(&mut self, transaction_hash: &str) -> HubResult<()> {
        let deployment = self
            .state
            .deployment
            .as_ref()
            .ok_or_else(|| HubError::State("HVM pilot deployment is not signed".into()))?;
        if deployment.transaction.transaction_hash != transaction_hash {
            return Err(HubError::State(
                "HVM pilot node acknowledged a different deployment".into(),
            ));
        }
        match self.state.deployment_phase {
            Some(HvmPilotTransactionPhase::Signed | HvmPilotTransactionPhase::Submitted) => {
                self.state.deployment_phase = Some(HvmPilotTransactionPhase::Submitted);
            }
            Some(HvmPilotTransactionPhase::Confirmed) => {
                return Err(HubError::State(
                    "confirmed HVM deployment cannot be downgraded to submitted".into(),
                ));
            }
            Some(HvmPilotTransactionPhase::RecoveryRequired) => {
                return Err(HubError::State(
                    "HVM deployment requires explicit recovery before resubmission".into(),
                ));
            }
            None => {
                return Err(HubError::State("HVM pilot deployment has no phase".into()));
            }
        }
        self.save()
    }

    pub fn mark_deployment_confirmed(
        &mut self,
        transaction_hash: &str,
        block_height: u64,
    ) -> HubResult<()> {
        let deployment = self
            .state
            .deployment
            .as_ref()
            .ok_or_else(|| HubError::State("HVM pilot deployment is not signed".into()))?;
        if deployment.transaction.transaction_hash != transaction_hash {
            return Err(HubError::State(
                "HVM pilot node confirmed a different deployment".into(),
            ));
        }
        if block_height == 0 {
            return Err(HubError::State(
                "HVM pilot confirmed deployment height must be positive".into(),
            ));
        }
        self.state.deployment_phase = Some(HvmPilotTransactionPhase::Confirmed);
        self.state.deployment_confirmed_height = Some(block_height);
        self.save()
    }

    pub fn mark_deployment_recovery_required(&mut self, transaction_hash: &str) -> HubResult<()> {
        let deployment = self
            .state
            .deployment
            .as_ref()
            .ok_or_else(|| HubError::State("HVM pilot deployment is not signed".into()))?;
        if deployment.transaction.transaction_hash != transaction_hash {
            return Err(HubError::State(
                "HVM pilot recovery references a different deployment".into(),
            ));
        }
        self.state.deployment_phase = Some(HvmPilotTransactionPhase::RecoveryRequired);
        self.save()
    }

    pub fn initialization(
        &self,
    ) -> Option<(
        &HvmPilotTransactionPhase,
        &HvmPilotSignedTransaction,
        &HvmPilotChannelParameters,
        &HvmChannelRecoveryBundleV1,
    )> {
        Some((
            self.state.initialization_phase.as_ref()?,
            self.state.initialization.as_ref()?,
            self.state.channel_parameters.as_ref()?,
            self.state.recovery_bundle.as_ref()?,
        ))
    }

    pub fn initialization_confirmed_height(&self) -> Option<u64> {
        self.state.initialization_confirmed_height
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_initialization(
        &mut self,
        left: &Account,
        right_hub: &Account,
        parameters: HvmPilotChannelParameters,
        network_fee_zhu: u64,
        timestamp: u64,
        gas_max: u8,
    ) -> HubResult<HvmPilotSignedTransaction> {
        if let Some((_, transaction, stored_parameters, _)) = self.initialization() {
            if stored_parameters != &parameters {
                return Err(HubError::State(
                    "HVM pilot initialization retry changed channel parameters".into(),
                ));
            }
            return Ok(transaction.clone());
        }
        if self.state.deployment_phase != Some(HvmPilotTransactionPhase::Confirmed) {
            return Err(HubError::State(
                "HVM pilot initialization requires a confirmed deployment".into(),
            ));
        }
        let deployment_height = self
            .state
            .deployment_confirmed_height
            .ok_or_else(|| HubError::State("confirmed HVM deployment lost its height".into()))?;
        let deployment = self
            .state
            .deployment
            .as_ref()
            .ok_or_else(|| HubError::State("confirmed HVM deployment is missing".into()))?;
        if left.readable() != self.state.left_address
            || right_hub.readable() != self.state.hub_address
        {
            return Err(HubError::State(
                "HVM pilot initialization signers do not match durable identities".into(),
            ));
        }
        let transaction = build_hvm_pilot_channel_init(
            left,
            right_hub,
            &deployment.contract_address,
            &self.state.network,
            &parameters,
            network_fee_zhu,
            timestamp,
            gas_max,
        )?;
        let recovery_bundle = build_hvm_pilot_recovery_bundle(
            left,
            right_hub,
            deployment,
            deployment_height,
            &parameters,
        )?;
        self.state.channel_parameters = Some(parameters);
        self.state.recovery_bundle = Some(recovery_bundle);
        self.state.initialization_phase = Some(HvmPilotTransactionPhase::Signed);
        self.state.initialization = Some(transaction.clone());
        self.save()?;
        Ok(transaction)
    }

    pub fn mark_initialization_submitted(&mut self, transaction_hash: &str) -> HubResult<()> {
        advance_submitted(
            &mut self.state.initialization_phase,
            self.state.initialization.as_ref(),
            transaction_hash,
            "initialization",
        )?;
        self.save()
    }

    pub fn mark_initialization_confirmed(
        &mut self,
        transaction_hash: &str,
        block_height: u64,
    ) -> HubResult<()> {
        advance_confirmed(
            &mut self.state.initialization_phase,
            self.state.initialization.as_ref(),
            transaction_hash,
            block_height,
            "initialization",
        )?;
        self.state.initialization_confirmed_height = Some(block_height);
        self.save()
    }

    pub fn mark_initialization_recovery_required(
        &mut self,
        transaction_hash: &str,
    ) -> HubResult<()> {
        advance_recovery_required(
            &mut self.state.initialization_phase,
            self.state.initialization.as_ref(),
            transaction_hash,
            "initialization",
        )?;
        self.save()
    }

    pub fn funding(&self) -> Option<(&HvmPilotTransactionPhase, &HvmPilotSignedTransaction)> {
        self.state
            .funding_phase
            .as_ref()
            .zip(self.state.funding.as_ref())
    }

    pub fn funding_confirmed_height(&self) -> Option<u64> {
        self.state.funding_confirmed_height
    }

    pub fn prepare_funding(
        &mut self,
        left: &Account,
        network_fee_zhu: u64,
        timestamp: u64,
        gas_max: u8,
    ) -> HubResult<HvmPilotSignedTransaction> {
        if let Some((_, transaction)) = self.funding() {
            return Ok(transaction.clone());
        }
        if self.state.initialization_phase != Some(HvmPilotTransactionPhase::Confirmed) {
            return Err(HubError::State(
                "HVM pilot funding requires confirmed channel initialization".into(),
            ));
        }
        if left.readable() != self.state.left_address {
            return Err(HubError::State(
                "HVM pilot funding signer does not match durable left identity".into(),
            ));
        }
        let deployment = self
            .state
            .deployment
            .as_ref()
            .ok_or_else(|| HubError::State("HVM pilot deployment is missing".into()))?;
        let parameters =
            self.state.channel_parameters.as_ref().ok_or_else(|| {
                HubError::State("HVM pilot channel parameters are missing".into())
            })?;
        let transaction = build_hvm_pilot_exact_funding(
            left,
            &deployment.contract_address,
            &self.state.network,
            parameters.left_deposit_zhu,
            network_fee_zhu,
            timestamp,
            gas_max,
        )?;
        self.state.funding_phase = Some(HvmPilotTransactionPhase::Signed);
        self.state.funding = Some(transaction.clone());
        self.save()?;
        Ok(transaction)
    }

    pub fn mark_funding_submitted(&mut self, transaction_hash: &str) -> HubResult<()> {
        advance_submitted(
            &mut self.state.funding_phase,
            self.state.funding.as_ref(),
            transaction_hash,
            "funding",
        )?;
        self.save()
    }

    pub fn mark_funding_confirmed(
        &mut self,
        transaction_hash: &str,
        block_height: u64,
    ) -> HubResult<()> {
        advance_confirmed(
            &mut self.state.funding_phase,
            self.state.funding.as_ref(),
            transaction_hash,
            block_height,
            "funding",
        )?;
        self.state.funding_confirmed_height = Some(block_height);
        self.save()
    }

    pub fn mark_funding_recovery_required(&mut self, transaction_hash: &str) -> HubResult<()> {
        advance_recovery_required(
            &mut self.state.funding_phase,
            self.state.funding.as_ref(),
            transaction_hash,
            "funding",
        )?;
        self.save()
    }

    fn save(&mut self) -> HubResult<()> {
        self.state.authentication_tag = compute_state_tag(&self.state, self.key.as_ref())?;
        let bytes = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| HubError::State(format!("HVM pilot state encode failed: {error}")))?;
        crate::storage::save_bytes_atomic(&self.path, &bytes)
    }
}

fn advance_submitted(
    phase: &mut Option<HvmPilotTransactionPhase>,
    transaction: Option<&HvmPilotSignedTransaction>,
    transaction_hash: &str,
    label: &str,
) -> HubResult<()> {
    require_exact_pilot_transaction(transaction, transaction_hash, label)?;
    match phase {
        Some(HvmPilotTransactionPhase::Signed | HvmPilotTransactionPhase::Submitted) => {
            *phase = Some(HvmPilotTransactionPhase::Submitted);
            Ok(())
        }
        Some(HvmPilotTransactionPhase::Confirmed) => Err(HubError::State(format!(
            "confirmed HVM pilot {label} cannot be downgraded"
        ))),
        Some(HvmPilotTransactionPhase::RecoveryRequired) => Err(HubError::State(format!(
            "HVM pilot {label} requires explicit recovery"
        ))),
        None => Err(HubError::State(format!(
            "HVM pilot {label} has no durable phase"
        ))),
    }
}

fn advance_confirmed(
    phase: &mut Option<HvmPilotTransactionPhase>,
    transaction: Option<&HvmPilotSignedTransaction>,
    transaction_hash: &str,
    block_height: u64,
    label: &str,
) -> HubResult<()> {
    require_exact_pilot_transaction(transaction, transaction_hash, label)?;
    if block_height == 0 || *phase == Some(HvmPilotTransactionPhase::RecoveryRequired) {
        return Err(HubError::State(format!(
            "HVM pilot {label} confirmation is invalid or frozen"
        )));
    }
    *phase = Some(HvmPilotTransactionPhase::Confirmed);
    Ok(())
}

fn advance_recovery_required(
    phase: &mut Option<HvmPilotTransactionPhase>,
    transaction: Option<&HvmPilotSignedTransaction>,
    transaction_hash: &str,
    label: &str,
) -> HubResult<()> {
    require_exact_pilot_transaction(transaction, transaction_hash, label)?;
    *phase = Some(HvmPilotTransactionPhase::RecoveryRequired);
    Ok(())
}

fn require_exact_pilot_transaction(
    transaction: Option<&HvmPilotSignedTransaction>,
    transaction_hash: &str,
    label: &str,
) -> HubResult<()> {
    let transaction =
        transaction.ok_or_else(|| HubError::State(format!("HVM pilot {label} is not signed")))?;
    if transaction.transaction_hash != transaction_hash {
        return Err(HubError::State(format!("HVM pilot {label} hash changed")));
    }
    Ok(())
}

fn state_body(state: &HvmPilotDurableState) -> HvmPilotStateBody<'_> {
    HvmPilotStateBody {
        schema: &state.schema,
        network: &state.network,
        left_address: &state.left_address,
        hub_address: &state.hub_address,
        deployment_phase: &state.deployment_phase,
        deployment: &state.deployment,
        deployment_confirmed_height: &state.deployment_confirmed_height,
        channel_parameters: &state.channel_parameters,
        recovery_bundle: &state.recovery_bundle,
        initialization_phase: &state.initialization_phase,
        initialization: &state.initialization,
        initialization_confirmed_height: &state.initialization_confirmed_height,
        funding_phase: &state.funding_phase,
        funding: &state.funding,
        funding_confirmed_height: &state.funding_confirmed_height,
    }
}

fn compute_state_tag(state: &HvmPilotDurableState, key: &[u8]) -> HubResult<String> {
    let encoded = serde_json::to_vec(&state_body(state))
        .map_err(|error| HubError::State(format!("HVM pilot state encode failed: {error}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| HubError::State("HVM pilot authentication key is invalid".into()))?;
    mac.update(b"HPAY/HVM/LOCAL-PILOT/STATE/V3");
    mac.update(&encoded);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_state_tag(state: &HvmPilotDurableState, key: &[u8]) -> HubResult<()> {
    let tag = hex::decode(&state.authentication_tag)
        .map_err(|_| HubError::State("HVM pilot state authentication tag is invalid".into()))?;
    let encoded = serde_json::to_vec(&state_body(state))
        .map_err(|error| HubError::State(format!("HVM pilot state encode failed: {error}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| HubError::State("HVM pilot authentication key is invalid".into()))?;
    mac.update(b"HPAY/HVM/LOCAL-PILOT/STATE/V3");
    mac.update(&encoded);
    mac.verify_slice(&tag)
        .map_err(|_| HubError::State("HVM pilot state authentication failed".into()))
}

fn validate_durable_lifecycle(state: &HvmPilotDurableState) -> HubResult<()> {
    let init_presence = [
        state.channel_parameters.is_some(),
        state.recovery_bundle.is_some(),
        state.initialization_phase.is_some(),
        state.initialization.is_some(),
    ];
    if init_presence.iter().any(|present| *present) && !init_presence.iter().all(|present| *present)
    {
        return Err(HubError::State(
            "HVM pilot initialization state is incomplete".into(),
        ));
    }
    if state.initialization_confirmed_height.is_some()
        && !matches!(
            state.initialization_phase,
            Some(HvmPilotTransactionPhase::Confirmed | HvmPilotTransactionPhase::RecoveryRequired)
        )
    {
        return Err(HubError::State(
            "HVM pilot initialization height has no confirmed phase".into(),
        ));
    }
    if state.initialization_phase == Some(HvmPilotTransactionPhase::Confirmed)
        && state.initialization_confirmed_height.is_none()
    {
        return Err(HubError::State(
            "confirmed HVM pilot initialization lost its height".into(),
        ));
    }
    if state.funding.is_some() != state.funding_phase.is_some() {
        return Err(HubError::State(
            "HVM pilot funding state is incomplete".into(),
        ));
    }
    if state.funding_confirmed_height.is_some()
        && !matches!(
            state.funding_phase,
            Some(HvmPilotTransactionPhase::Confirmed | HvmPilotTransactionPhase::RecoveryRequired)
        )
    {
        return Err(HubError::State(
            "HVM pilot funding height has no confirmed phase".into(),
        ));
    }
    if state.funding_phase == Some(HvmPilotTransactionPhase::Confirmed)
        && state.funding_confirmed_height.is_none()
    {
        return Err(HubError::State(
            "confirmed HVM pilot funding lost its height".into(),
        ));
    }
    if let (Some(parameters), Some(bundle), Some(initialization)) = (
        state.channel_parameters.as_ref(),
        state.recovery_bundle.as_ref(),
        state.initialization.as_ref(),
    ) {
        let deployment = state
            .deployment
            .as_ref()
            .ok_or_else(|| HubError::State("HVM pilot initialization lost deployment".into()))?;
        let deployment_height = state.deployment_confirmed_height.ok_or_else(|| {
            HubError::State("HVM pilot initialization lost deployment height".into())
        })?;
        parameters.validate()?;
        bundle.validate_crypto()?;
        let binding = &bundle.binding;
        if binding.chain_id != state.network.chain_id
            || binding.network_instance_id != state.network.network_instance_id
            || binding.contract_address != deployment.contract_address
            || binding.deployment_tx_hash != deployment.transaction.transaction_hash
            || binding.deployment_height != deployment_height
            || binding.channel_id != parameters.channel_id
            || binding.reuse_version != parameters.reuse_version
            || binding.left_address != state.left_address
            || binding.right_hub_address != state.hub_address
            || binding.left_deposit_zhu != parameters.left_deposit_zhu
            || binding.right_hub_deposit_zhu != parameters.right_hub_deposit_zhu
            || binding.challenge_blocks != parameters.challenge_blocks
        {
            return Err(HubError::State(
                "HVM pilot recovery bundle changed the durable channel binding".into(),
            ));
        }
        validate_durable_pilot_transaction(
            initialization,
            state.network.chain_id,
            &[0x0411, 44, 0x0414],
            2,
            &[
                state.left_address.as_str(),
                deployment.contract_address.as_str(),
                state.hub_address.as_str(),
            ],
        )?;
    }
    if let Some(funding) = state.funding.as_ref() {
        if state.initialization_phase != Some(HvmPilotTransactionPhase::Confirmed) {
            return Err(HubError::State(
                "HVM pilot funding exists without confirmed initialization".into(),
            ));
        }
        let deployment = state
            .deployment
            .as_ref()
            .ok_or_else(|| HubError::State("HVM pilot funding lost deployment".into()))?;
        let parameters = state
            .channel_parameters
            .as_ref()
            .ok_or_else(|| HubError::State("HVM pilot funding lost parameters".into()))?;
        let transaction = validate_durable_pilot_transaction(
            funding,
            state.network.chain_id,
            &[0x0411, 1],
            1,
            &[
                state.left_address.as_str(),
                deployment.contract_address.as_str(),
            ],
        )?;
        let transfer = HacToTrs::downcast(&transaction.actions()[1])
            .ok_or_else(|| HubError::State("HVM pilot funding transfer is malformed".into()))?;
        let contract = Address::from_readable(&deployment.contract_address)
            .map_err(|_| HubError::State("HVM pilot contract address is malformed".into()))?;
        let mut expected = HacToTrs::new();
        expected.to = AddrOrPtr::from_addr(contract);
        expected.hacash = Amount::zhu(parameters.left_deposit_zhu);
        if transfer.serialize() != expected.serialize() {
            return Err(HubError::State(
                "HVM pilot funding amount or destination changed".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_durable_pilot_transaction(
    signed: &HvmPilotSignedTransaction,
    chain_id: u32,
    expected_actions: &[u16],
    expected_signatures: usize,
    expected_addresses: &[&str],
) -> HubResult<Box<dyn Transaction>> {
    crate::protocol_registry::ensure_hacash_protocol_setup();
    let raw = hex::decode(&signed.signed_transaction_hex)
        .map_err(|_| HubError::State("HVM pilot transaction bytes are invalid".into()))?;
    let (transaction, used) = protocol::transaction::transaction_create(&raw)
        .map_err(|_| HubError::State("HVM pilot transaction cannot be decoded".into()))?;
    let action_kinds = transaction
        .actions()
        .iter()
        .map(|action| action.kind())
        .collect::<Vec<_>>();
    let addresses = expected_addresses
        .iter()
        .map(|address| {
            Address::from_readable(address)
                .map_err(|_| HubError::State("HVM pilot durable address is invalid".into()))
        })
        .collect::<HubResult<Vec<_>>>()?;
    if used != raw.len()
        || transaction.ty() != 3
        || action_kinds != expected_actions
        || transaction.signs().len() != expected_signatures
        || transaction.addrs() != addresses
        || hex::encode(transaction.hash()) != signed.transaction_hash
        || transaction.verify_signature().is_err()
        || transaction.fee_purity() < HVM_PILOT_MIN_FEE_PURITY
    {
        return Err(HubError::State(
            "HVM pilot durable transaction topology changed".into(),
        ));
    }
    let guard = ChainAllow::downcast(&transaction.actions()[0])
        .ok_or_else(|| HubError::State("HVM pilot transaction guard is malformed".into()))?;
    let chains = guard.chains.as_list();
    if chains.len() != 1 || chains[0].uint() != chain_id {
        return Err(HubError::State(
            "HVM pilot transaction chain binding changed".into(),
        ));
    }
    Ok(transaction)
}

fn validate_durable_deployment(
    deployment: &HvmPilotDeploymentTransaction,
    left_address: &str,
    chain_id: u32,
) -> HubResult<()> {
    if deployment.source_sha256 != HPAY_CHANNEL_EXIT_SOURCE_SHA256
        || deployment.bytecode_sha3 != HPAY_CHANNEL_EXIT_BYTECODE_SHA3
    {
        return Err(HubError::State(
            "HVM pilot deployment artifact drifted".into(),
        ));
    }
    crate::protocol_registry::ensure_hacash_protocol_setup();
    let raw = hex::decode(&deployment.transaction.signed_transaction_hex)
        .map_err(|_| HubError::State("HVM pilot deployment bytes are invalid".into()))?;
    let (transaction, used) = protocol::transaction::transaction_create(&raw)
        .map_err(|_| HubError::State("HVM pilot deployment cannot be decoded".into()))?;
    if used != raw.len()
        || transaction.ty() != 3
        || transaction.actions().len() != 2
        || transaction.actions()[0].kind() != 0x0411
        || transaction.actions()[1].kind() != 40
        || transaction.signs().len() != 1
        || hex::encode(transaction.hash()) != deployment.transaction.transaction_hash
        || transaction.fee_purity() < HVM_PILOT_MIN_FEE_PURITY
    {
        return Err(HubError::State(
            "HVM pilot durable deployment topology changed".into(),
        ));
    }
    let guard = ChainAllow::downcast(&transaction.actions()[0])
        .ok_or_else(|| HubError::State("HVM pilot deployment guard is malformed".into()))?;
    let chains = guard.chains.as_list();
    let left = Address::from_readable(left_address)
        .map_err(|_| HubError::State("HVM pilot left address is invalid".into()))?;
    if chains.len() != 1
        || chains[0].uint() != chain_id
        || transaction.main() != left
        || transaction.verify_signature().is_err()
    {
        return Err(HubError::State(
            "HVM pilot durable deployment binding is invalid".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmPilotChannelParameters {
    pub network_instance_id: String,
    pub channel_id: String,
    pub reuse_version: u32,
    pub left_deposit_zhu: u64,
    pub right_hub_deposit_zhu: u64,
    pub challenge_blocks: u64,
}

pub fn build_hvm_pilot_recovery_bundle(
    left: &Account,
    right_hub: &Account,
    deployment: &HvmPilotDeploymentTransaction,
    deployment_height: u64,
    parameters: &HvmPilotChannelParameters,
) -> HubResult<HvmChannelRecoveryBundleV1> {
    parameters.validate()?;
    if deployment_height == 0 {
        return Err(HubError::State(
            "HVM pilot recovery bundle requires a confirmed deployment height".into(),
        ));
    }
    validate_durable_deployment(deployment, left.readable(), HPAY_LOCAL_PILOT_CHAIN_ID)?;
    let binding = HvmChannelBindingV1 {
        schema: HVM_CHANNEL_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: HPAY_LOCAL_PILOT_CHAIN_ID,
        network_instance_id: parameters.network_instance_id.clone(),
        contract_address: deployment.contract_address.clone(),
        deployment_tx_hash: deployment.transaction.transaction_hash.clone(),
        deployment_height,
        bytecode_sha3: deployment.bytecode_sha3.clone(),
        channel_id: parameters.channel_id.clone(),
        reuse_version: parameters.reuse_version,
        left_address: left.readable().to_owned(),
        right_hub_address: right_hub.readable().to_owned(),
        left_deposit_zhu: parameters.left_deposit_zhu,
        right_hub_deposit_zhu: parameters.right_hub_deposit_zhu,
        challenge_blocks: parameters.challenge_blocks,
    };
    let mut bill = HvmChannelBillV1 {
        schema: HVM_CHANNEL_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment()?,
        serial: 1,
        left_balance_zhu: binding.left_deposit_zhu,
        right_balance_zhu: binding.right_hub_deposit_zhu,
        left_signature_hex: String::new(),
        right_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(&binding)?;
    bill.left_signature_hex = hex::encode(Sign::create_by(left, &hash).serialize());
    bill.right_signature_hex = hex::encode(Sign::create_by(right_hub, &hash).serialize());
    let bundle = HvmChannelRecoveryBundleV1 {
        schema: HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA.into(),
        binding,
        initial_recovery_bill: bill,
    };
    bundle.validate_crypto()?;
    Ok(bundle)
}

impl HvmPilotChannelParameters {
    fn validate(&self) -> HubResult<()> {
        if self.network_instance_id != HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID
            || self.channel_id.len() != 32
            || !self
                .channel_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.reuse_version == 0
            || self.left_deposit_zhu == 0
            || self.right_hub_deposit_zhu != 0
            || self.challenge_blocks == 0
        {
            return Err(HubError::State(
                "HVM Local Pilot channel parameters are invalid or unsafe".into(),
            ));
        }
        Ok(())
    }
}

pub fn build_hvm_pilot_deployment(
    deployer: &Account,
    network: &HvmLocalPilotNetwork,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotDeploymentTransaction> {
    network.validate()?;
    let deployer_address = readable_address(deployer)?;
    let contract_address = derive_hvm_pilot_contract_address(deployer.readable())?;
    let (compiled, source_sha256, bytecode_sha3) = compile_canonical_hvm_pilot_contract()?;
    let mut action = ContractDeploy::new();
    action.nonce = Uint4::from(0);
    action.contract = compiled.into_sto();
    action.protocol_cost = Amount::unit238(CONTRACT_PROTOCOL_COST_238);
    let transaction = build_exact_pilot_type3(
        deployer,
        &[],
        network,
        vec![deployer_address],
        vec![Box::new(action)],
        network_fee_zhu,
        timestamp,
        gas_max,
    )?;
    Ok(HvmPilotDeploymentTransaction {
        contract_address,
        source_sha256,
        bytecode_sha3,
        transaction,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_hvm_pilot_channel_init(
    left: &Account,
    right_hub: &Account,
    contract_address: &str,
    network: &HvmLocalPilotNetwork,
    parameters: &HvmPilotChannelParameters,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotSignedTransaction> {
    network.validate()?;
    parameters.validate()?;
    let left_address = readable_address(left)?;
    let right_address = readable_address(right_hub)?;
    if left_address == right_address {
        return Err(HubError::State(
            "HVM pilot left and Hub identities must be independent".into(),
        ));
    }
    let contract = parse_contract_address(contract_address)?;
    let init = format!(
        "init(0x{}, 0x{}, {}, {}, {}, {}, {}, {}, {})",
        parameters.network_instance_id,
        parameters.channel_id,
        parameters.reuse_version,
        left_address.to_readable(),
        right_address.to_readable(),
        parameters.left_deposit_zhu,
        parameters.right_hub_deposit_zhu,
        parameters.challenge_blocks,
        100_u64,
    );
    let source = contract_call_source(&contract, &init);
    let codes = vm::lang::lang_to_bytecode(&source)
        .map_err(|error| HubError::State(format!("HVM init compilation failed: {error}")))?;
    let action = ContractMainCall::from_bytecode(codes)
        .map_err(|error| HubError::State(format!("HVM init Action 44 build failed: {error}")))?;
    build_exact_pilot_type3(
        left,
        &[right_hub],
        network,
        vec![left_address, contract.to_addr(), right_address],
        vec![Box::new(action)],
        network_fee_zhu,
        timestamp,
        gas_max,
    )
}

pub fn build_hvm_pilot_exact_funding(
    left: &Account,
    contract_address: &str,
    network: &HvmLocalPilotNetwork,
    left_deposit_zhu: u64,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotSignedTransaction> {
    network.validate()?;
    if left_deposit_zhu == 0 {
        return Err(HubError::State(
            "HVM pilot funding must be a positive exact amount".into(),
        ));
    }
    let left_address = readable_address(left)?;
    let contract = parse_contract_address(contract_address)?;
    build_hvm_pilot_exact_transfer_to_address(
        left,
        left_address,
        contract.to_addr(),
        network,
        left_deposit_zhu,
        network_fee_zhu,
        timestamp,
        gas_max,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_hvm_pilot_exact_transfer(
    payer: &Account,
    destination_address: &str,
    network: &HvmLocalPilotNetwork,
    amount_zhu: u64,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotSignedTransaction> {
    network.validate()?;
    if amount_zhu == 0 {
        return Err(HubError::State(
            "HVM pilot transfer must be a positive exact amount".into(),
        ));
    }
    let payer_address = readable_address(payer)?;
    let destination = Address::from_readable(destination_address)
        .map_err(|_| HubError::State("HVM pilot transfer destination is invalid".into()))?;
    build_hvm_pilot_exact_transfer_to_address(
        payer,
        payer_address,
        destination,
        network,
        amount_zhu,
        network_fee_zhu,
        timestamp,
        gas_max,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_hvm_pilot_exact_transfer_to_address(
    payer: &Account,
    payer_address: Address,
    destination: Address,
    network: &HvmLocalPilotNetwork,
    amount_zhu: u64,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotSignedTransaction> {
    let mut action = HacToTrs::new();
    action.to = AddrOrPtr::from_addr(destination);
    action.hacash = Amount::zhu(amount_zhu);
    build_exact_pilot_type3(
        payer,
        &[],
        network,
        vec![payer_address, destination],
        vec![Box::new(action)],
        network_fee_zhu,
        timestamp,
        gas_max,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_exact_pilot_type3(
    main_signer: &Account,
    extra_signers: &[&Account],
    network: &HvmLocalPilotNetwork,
    addresses: Vec<Address>,
    actions: Vec<Box<dyn basis::interface::Action>>,
    network_fee_zhu: u64,
    timestamp: u64,
    gas_max: u8,
) -> HubResult<HvmPilotSignedTransaction> {
    network.validate()?;
    crate::protocol_registry::ensure_hacash_protocol_setup();
    let main = readable_address(main_signer)?;
    if addresses.first() != Some(&main)
        || network_fee_zhu == 0
        || timestamp == 0
        || gas_max == 0
        || actions.len() != 1
    {
        return Err(HubError::State(
            "HVM pilot Type 3 transaction parameters are invalid".into(),
        ));
    }
    let mut transaction = TransactionType3::new_by(main, Amount::zhu(network_fee_zhu), timestamp);
    transaction.addrlist = AddrOrList::from_list(addresses)
        .map_err(|error| HubError::State(format!("HVM pilot address list failed: {error}")))?;
    transaction.gas_max = Uint1::from(gas_max);
    let mut allow = ChainAllow::new();
    allow.chains = ChainIDList::from_list(vec![Uint4::from(network.chain_id)])
        .map_err(|error| HubError::State(format!("HVM pilot ChainAllow failed: {error}")))?;
    transaction
        .push_action(Box::new(allow))
        .map_err(|error| HubError::State(format!("HVM pilot guard append failed: {error}")))?;
    for action in actions {
        transaction
            .push_action(action)
            .map_err(|error| HubError::State(format!("HVM pilot action append failed: {error}")))?;
    }
    let intrinsic = transaction
        .intrinsic_req_sign()
        .map_err(|error| HubError::State(format!("HVM pilot signer analysis failed: {error}")))?;
    let mut declared = Vec::new();
    for signer in extra_signers {
        let address = readable_address(signer)?;
        if address == main || declared.contains(&address) {
            return Err(HubError::State(
                "HVM pilot extra signer is duplicated".into(),
            ));
        }
        if !intrinsic.contains(&address) {
            declared.push(address);
        }
    }
    if !declared.is_empty() {
        let req = ReqSignList::create_by_addrs(declared)
            .map_err(|error| HubError::State(format!("HVM pilot ReqSignList failed: {error}")))?;
        transaction
            .push_action(Box::new(req))
            .map_err(|error| HubError::State(format!("HVM pilot signer guard failed: {error}")))?;
    }
    let billing_size = transaction
        .billing_size()
        .map_err(|error| HubError::State(format!("HVM pilot billing size failed: {error}")))?;
    let fee_purity = transaction.fee_purity();
    if fee_purity < HVM_PILOT_MIN_FEE_PURITY {
        let required_fee_238 = u128::from(HVM_PILOT_MIN_FEE_PURITY)
            .checked_mul(billing_size as u128)
            .ok_or_else(|| HubError::State("HVM pilot minimum fee overflow".into()))?;
        let unit_238_per_zhu = Amount::zhu(1)
            .to_238_u128()
            .map_err(|error| HubError::State(format!("HVM pilot fee unit failed: {error}")))?;
        let minimum_fee_zhu = required_fee_238
            .checked_add(unit_238_per_zhu.saturating_sub(1))
            .and_then(|value| value.checked_div(unit_238_per_zhu))
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| HubError::State("HVM pilot minimum Zhu fee overflow".into()))?;
        return Err(HubError::State(format!(
            "HVM pilot fee purity {fee_purity} is below the required {HVM_PILOT_MIN_FEE_PURITY} for {billing_size} canonical billing bytes; use at least {minimum_fee_zhu} Zhu"
        )));
    }
    transaction
        .fill_sign(main_signer)
        .map_err(|error| HubError::State(format!("HVM pilot primary signing failed: {error}")))?;
    for signer in extra_signers {
        transaction
            .fill_sign(signer)
            .map_err(|error| HubError::State(format!("HVM pilot co-signing failed: {error}")))?;
    }
    transaction
        .verify_signature()
        .map_err(|error| HubError::State(format!("HVM pilot signature check failed: {error}")))?;
    Ok(HvmPilotSignedTransaction {
        transaction_hash: hex::encode(transaction.hash()),
        signed_transaction_hex: hex::encode(transaction.serialize()),
    })
}

pub(crate) fn readable_address(account: &Account) -> HubResult<Address> {
    Address::from_readable(account.readable())
        .map_err(|error| HubError::State(format!("HVM pilot account address is invalid: {error}")))
}

pub(crate) fn parse_contract_address(value: &str) -> HubResult<ContractAddress> {
    let address = Address::from_readable(value).map_err(|error| {
        HubError::State(format!("HVM pilot contract address is invalid: {error}"))
    })?;
    ContractAddress::from_addr(address)
        .map_err(|_| HubError::State("HVM pilot target is not a contract address".into()))
}

pub(crate) fn contract_call_source(contract: &ContractAddress, call: &str) -> String {
    format!(
        "lib Channel = 1: {}\nvar result = Channel.{}\nassert result == 0\nend",
        contract.to_readable(),
        call
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NETWORK_FEE_ZHU: u64 = 1_000_000;

    fn parse(raw_hex: &str) -> Box<dyn basis::interface::Transaction> {
        let raw = hex::decode(raw_hex).unwrap();
        let (transaction, used) = protocol::transaction::transaction_create(&raw).unwrap();
        assert_eq!(used, raw.len());
        transaction
    }

    #[test]
    fn exact_builders_bind_chain_artifact_signers_and_zero_hub_deposit() {
        let left = Account::create_by("hpay-pilot-builder-left").unwrap();
        let right = Account::create_by("hpay-pilot-builder-right").unwrap();
        let network = HvmLocalPilotNetwork::canonical();
        let deploy =
            build_hvm_pilot_deployment(&left, &network, TEST_NETWORK_FEE_ZHU, 100, 255).unwrap();
        let preview = preview_hvm_pilot_deployment(left.readable(), &network).unwrap();
        assert_eq!(preview.contract_address, deploy.contract_address);
        assert_eq!(preview.source_sha256, deploy.source_sha256);
        assert_eq!(preview.bytecode_sha3, deploy.bytecode_sha3);
        assert_eq!(
            preview.protocol_cost_zhu,
            HVM_PILOT_DEPLOY_PROTOCOL_COST_ZHU
        );
        assert_eq!(deploy.source_sha256, HPAY_CHANNEL_EXIT_SOURCE_SHA256);
        assert_eq!(deploy.bytecode_sha3, HPAY_CHANNEL_EXIT_BYTECODE_SHA3);
        let deploy_tx = parse(&deploy.transaction.signed_transaction_hex);
        assert_eq!(deploy_tx.ty(), 3);
        assert_eq!(
            deploy_tx
                .actions()
                .iter()
                .map(|action| action.kind())
                .collect::<Vec<_>>(),
            vec![0x0411, 40]
        );
        assert_eq!(deploy_tx.signs().len(), 1);
        assert!(preview_hvm_pilot_deployment("not-an-address", &network).is_err());

        let parameters = HvmPilotChannelParameters {
            network_instance_id: HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID.into(),
            channel_id: "42".repeat(16),
            reuse_version: 1,
            left_deposit_zhu: 600_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let init = build_hvm_pilot_channel_init(
            &left,
            &right,
            &deploy.contract_address,
            &network,
            &parameters,
            TEST_NETWORK_FEE_ZHU,
            101,
            255,
        )
        .unwrap();
        let init_tx = parse(&init.signed_transaction_hex);
        assert_eq!(
            init_tx
                .actions()
                .iter()
                .map(|action| action.kind())
                .collect::<Vec<_>>(),
            vec![0x0411, 44, 0x0414]
        );
        assert_eq!(init_tx.signs().len(), 2);
        init_tx.verify_signature().unwrap();

        let funding = build_hvm_pilot_exact_funding(
            &left,
            &deploy.contract_address,
            &network,
            parameters.left_deposit_zhu,
            TEST_NETWORK_FEE_ZHU,
            102,
            255,
        )
        .unwrap();
        let funding_tx = parse(&funding.signed_transaction_hex);
        assert_eq!(
            funding_tx
                .actions()
                .iter()
                .map(|action| action.kind())
                .collect::<Vec<_>>(),
            vec![0x0411, 1]
        );
        assert_eq!(funding_tx.signs().len(), 1);
        let transfer = HacToTrs::downcast(&funding_tx.actions()[1]).unwrap();
        assert_eq!(transfer.hacash.to_zhu_u64().unwrap(), 600_000);

        let bundle =
            build_hvm_pilot_recovery_bundle(&left, &right, &deploy, 77, &parameters).unwrap();
        bundle.validate_crypto().unwrap();
        assert_eq!(bundle.binding.network_mode, "testnet");
        assert_eq!(bundle.binding.chain_id, HPAY_LOCAL_PILOT_CHAIN_ID);
        assert_eq!(bundle.binding.contract_address, deploy.contract_address);
        assert_eq!(
            bundle.binding.deployment_tx_hash,
            deploy.transaction.transaction_hash
        );
        assert_eq!(bundle.initial_recovery_bill.serial, 1);
        assert_eq!(
            bundle.initial_recovery_bill.left_balance_zhu,
            parameters.left_deposit_zhu
        );
        assert_eq!(bundle.initial_recovery_bill.right_balance_zhu, 0);

        let payment = build_hvm_pilot_payment_request(
            &left,
            &bundle.binding,
            &bundle.initial_recovery_bill,
            "pilot-payment-1",
            "pilot-payment-idempotency-1",
            "pilot-service",
            100_000,
            200,
            500,
        )
        .unwrap();
        payment
            .validate_against(&bundle.binding, &bundle.initial_recovery_bill, 200)
            .unwrap();
        assert_eq!(payment.hub_fee_zhu, 0);
        assert_eq!(payment.proposed_bill.serial, 2);
        assert_eq!(payment.proposed_bill.left_balance_zhu, 500_000);
        assert_eq!(payment.proposed_bill.right_balance_zhu, 100_000);
        assert!(
            build_hvm_pilot_payment_request(
                &right,
                &bundle.binding,
                &bundle.initial_recovery_bill,
                "wrong-signer",
                "wrong-signer",
                "pilot-service",
                1,
                200,
                500,
            )
            .is_err()
        );
        assert!(
            build_hvm_pilot_payment_request(
                &left,
                &bundle.binding,
                &bundle.initial_recovery_bill,
                "over-balance",
                "over-balance",
                "pilot-service",
                600_001,
                200,
                500,
            )
            .is_err()
        );
    }

    #[test]
    fn builders_reject_mainnet_hub_funding_and_zero_funding() {
        let left = Account::create_by("hpay-pilot-negative-left").unwrap();
        let right = Account::create_by("hpay-pilot-negative-right").unwrap();
        let mut wrong_network = HvmLocalPilotNetwork::canonical();
        wrong_network.chain_id = 0;
        assert!(build_hvm_pilot_deployment(&left, &wrong_network, 1, 1, 1).is_err());
        assert!(validate_hvm_pilot_node_url("https://nodeapi.hacash.org/").is_err());
        assert!(validate_hvm_pilot_node_url("http://127.0.0.1:8197").is_ok());
        let low_fee =
            build_hvm_pilot_deployment(&left, &HvmLocalPilotNetwork::canonical(), 1, 1, 1)
                .unwrap_err();
        assert!(low_fee.to_string().contains("fee purity"));
        let deploy = build_hvm_pilot_deployment(
            &left,
            &HvmLocalPilotNetwork::canonical(),
            TEST_NETWORK_FEE_ZHU,
            1,
            1,
        )
        .unwrap();
        let unsafe_parameters = HvmPilotChannelParameters {
            network_instance_id: HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID.into(),
            channel_id: "11".repeat(16),
            reuse_version: 1,
            left_deposit_zhu: 1,
            right_hub_deposit_zhu: 1,
            challenge_blocks: 1,
        };
        assert!(
            build_hvm_pilot_channel_init(
                &left,
                &right,
                &deploy.contract_address,
                &HvmLocalPilotNetwork::canonical(),
                &unsafe_parameters,
                1,
                2,
                1,
            )
            .is_err()
        );
        assert!(
            build_hvm_pilot_exact_funding(
                &left,
                &deploy.contract_address,
                &HvmLocalPilotNetwork::canonical(),
                0,
                1,
                3,
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn durable_deployment_reuses_exact_signature_and_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pilot-state.json");
        let left = Account::create_by("hpay-pilot-durable-left").unwrap();
        let hub = Account::create_by("hpay-pilot-durable-hub").unwrap();
        let key = "31".repeat(32);
        let network = HvmLocalPilotNetwork::canonical();
        let first = {
            let mut store = HvmPilotStateStore::open(
                &path,
                &key,
                network.clone(),
                left.readable(),
                hub.readable(),
            )
            .unwrap();
            let first = store
                .prepare_deployment(&left, TEST_NETWORK_FEE_ZHU, 200, 255)
                .unwrap();
            let retry = store.prepare_deployment(&left, 9_999, 999, 1).unwrap();
            assert_eq!(retry, first);
            assert_eq!(
                store.deployment().map(|(phase, _)| phase),
                Some(&HvmPilotTransactionPhase::Signed)
            );
            first
        };
        {
            let mut store = HvmPilotStateStore::open(
                &path,
                &key,
                network.clone(),
                left.readable(),
                hub.readable(),
            )
            .unwrap();
            assert_eq!(store.deployment().unwrap().1, &first);
            store
                .mark_deployment_submitted(&first.transaction.transaction_hash)
                .unwrap();
        }
        {
            let mut store =
                HvmPilotStateStore::open(&path, &key, network, left.readable(), hub.readable())
                    .unwrap();
            assert_eq!(
                store.deployment().map(|(phase, _)| phase),
                Some(&HvmPilotTransactionPhase::Submitted)
            );
            store
                .mark_deployment_confirmed(&first.transaction.transaction_hash, 77)
                .unwrap();
        }
        let mut store = HvmPilotStateStore::open(
            &path,
            &key,
            HvmLocalPilotNetwork::canonical(),
            left.readable(),
            hub.readable(),
        )
        .unwrap();
        assert_eq!(
            store.deployment().map(|(phase, _)| phase),
            Some(&HvmPilotTransactionPhase::Confirmed)
        );
        assert_eq!(store.deployment_confirmed_height(), Some(77));
        assert!(
            store
                .mark_deployment_submitted(&first.transaction.transaction_hash)
                .is_err()
        );
        store
            .mark_deployment_recovery_required(&first.transaction.transaction_hash)
            .unwrap();
        drop(store);
        let store = HvmPilotStateStore::open(
            &path,
            &key,
            HvmLocalPilotNetwork::canonical(),
            left.readable(),
            hub.readable(),
        )
        .unwrap();
        assert_eq!(
            store.deployment().map(|(phase, _)| phase),
            Some(&HvmPilotTransactionPhase::RecoveryRequired)
        );
    }

    #[test]
    fn durable_state_rejects_tamper_wrong_key_identity_and_parallel_owner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pilot-state.json");
        let left = Account::create_by("hpay-pilot-tamper-left").unwrap();
        let hub = Account::create_by("hpay-pilot-tamper-hub").unwrap();
        let key = "42".repeat(32);
        let mut store = HvmPilotStateStore::open(
            &path,
            &key,
            HvmLocalPilotNetwork::canonical(),
            left.readable(),
            hub.readable(),
        )
        .unwrap();
        store
            .prepare_deployment(&left, TEST_NETWORK_FEE_ZHU, 300, 255)
            .unwrap();
        assert!(
            HvmPilotStateStore::open(
                &path,
                &key,
                HvmLocalPilotNetwork::canonical(),
                left.readable(),
                hub.readable(),
            )
            .is_err()
        );
        drop(store);
        assert!(
            HvmPilotStateStore::open(
                &path,
                &"43".repeat(32),
                HvmLocalPilotNetwork::canonical(),
                left.readable(),
                hub.readable(),
            )
            .is_err()
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["deployment_phase"] = serde_json::json!("confirmed");
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(
            HvmPilotStateStore::open(
                &path,
                &key,
                HvmLocalPilotNetwork::canonical(),
                left.readable(),
                hub.readable(),
            )
            .is_err()
        );
    }

    #[test]
    fn initialization_and_funding_progress_exactly_and_restart_idempotently() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pilot-lifecycle.json");
        let left = Account::create_by("hpay-pilot-lifecycle-left").unwrap();
        let hub = Account::create_by("hpay-pilot-lifecycle-hub").unwrap();
        let key = "53".repeat(32);
        let network = HvmLocalPilotNetwork::canonical();
        let parameters = HvmPilotChannelParameters {
            network_instance_id: HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID.into(),
            channel_id: "ab".repeat(16),
            reuse_version: 1,
            left_deposit_zhu: 1_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let (deployment_hash, initialization) = {
            let mut store = HvmPilotStateStore::open(
                &path,
                &key,
                network.clone(),
                left.readable(),
                hub.readable(),
            )
            .unwrap();
            let deployment = store
                .prepare_deployment(&left, TEST_NETWORK_FEE_ZHU, 400, 255)
                .unwrap();
            store
                .mark_deployment_confirmed(&deployment.transaction.transaction_hash, 90)
                .unwrap();
            let initialization = store
                .prepare_initialization(
                    &left,
                    &hub,
                    parameters.clone(),
                    TEST_NETWORK_FEE_ZHU,
                    401,
                    255,
                )
                .unwrap();
            let retry = store
                .prepare_initialization(&left, &hub, parameters.clone(), 9_999, 999, 1)
                .unwrap();
            assert_eq!(retry, initialization);
            assert!(store.prepare_funding(&left, 1, 1, 1).is_err());
            store
                .mark_initialization_submitted(&initialization.transaction_hash)
                .unwrap();
            (deployment.transaction.transaction_hash, initialization)
        };
        let funding = {
            let mut store = HvmPilotStateStore::open(
                &path,
                &key,
                network.clone(),
                left.readable(),
                hub.readable(),
            )
            .unwrap();
            assert_eq!(
                store.initialization().map(|(phase, _, _, _)| phase),
                Some(&HvmPilotTransactionPhase::Submitted)
            );
            store
                .mark_initialization_confirmed(&initialization.transaction_hash, 91)
                .unwrap();
            let funding = store
                .prepare_funding(&left, TEST_NETWORK_FEE_ZHU, 402, 255)
                .unwrap();
            let retry = store.prepare_funding(&left, 8_888, 998, 1).unwrap();
            assert_eq!(retry, funding);
            store
                .mark_funding_submitted(&funding.transaction_hash)
                .unwrap();
            funding
        };
        let mut store =
            HvmPilotStateStore::open(&path, &key, network, left.readable(), hub.readable())
                .unwrap();
        store
            .mark_funding_confirmed(&funding.transaction_hash, 92)
            .unwrap();
        assert_eq!(
            store.funding().map(|(phase, _)| phase),
            Some(&HvmPilotTransactionPhase::Confirmed)
        );
        assert_eq!(store.initialization_confirmed_height(), Some(91));
        assert_eq!(store.funding_confirmed_height(), Some(92));
        let (_, _, stored_parameters, bundle) = store.initialization().unwrap();
        assert_eq!(stored_parameters, &parameters);
        assert_eq!(bundle.binding.deployment_tx_hash, deployment_hash);
        assert_eq!(bundle.binding.deployment_height, 90);
        bundle.validate_crypto().unwrap();
        assert!(
            store
                .mark_funding_submitted(&funding.transaction_hash)
                .is_err()
        );
    }
}
