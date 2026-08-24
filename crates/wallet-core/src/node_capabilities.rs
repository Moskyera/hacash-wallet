//! Typed contract for the Istanbul node capability endpoint and API failures.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};

pub const CAPABILITIES_API_VERSION: u32 = 1;
pub const HPAY_LOCAL_PILOT_NETWORK_KIND: &str = "local_pilot_v1";
pub const HPAY_LOCAL_PILOT_PROFILE_ID: &str = "hpay-local-pilot-chain-v1";
pub const HPAY_LOCAL_PILOT_CHAIN_ID: u32 = 7;
pub const HPAY_MAINNET_NETWORK_KIND: &str = "mainnet";
pub const HPAY_MAINNET_PROFILE_ID: &str = "hacash-mainnet";
pub const HPAY_MAINNET_MIN_SAFE_HEIGHT: u64 = 765_432;
pub(crate) const MAX_MAINNET_TIP_AGE_SECONDS: u64 = 3_600;
pub(crate) const MAX_FUTURE_TIP_SKEW_SECONDS: u64 = 120;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySource {
    #[default]
    Reported,
    LegacyType2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCapabilities {
    pub ret: i32,
    pub api_version: u32,
    pub node: NodeIdentity,
    pub chain: NodeChain,
    #[serde(default)]
    pub network: NodeNetworkCapabilities,
    #[serde(default)]
    pub sync: NodeSyncCapabilities,
    pub istanbul: IstanbulStatus,
    pub transactions: RegistrySet<u8>,
    pub actions: RegistrySet<u16>,
    pub features: NodeFeatures,
    #[serde(default)]
    pub api: NodeApiCapabilities,
    pub limits: NodeLimits,
    #[serde(default)]
    pub source: CapabilitySource,
}

/// Authenticated network identity reported by a node. Older nodes omit this
/// object and therefore remain usable for legacy read-only Personal Wallet
/// paths, but can never satisfy Agent Wallet payment readiness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NodeNetworkCapabilities {
    pub kind: String,
    pub node_profile_id: String,
    pub block_1_available: bool,
    pub block_1_hash: Option<String>,
    pub instance_id: Option<String>,
    pub funding_confirmed: bool,
    pub transaction_ready: bool,
    pub current_height: u64,
    pub transaction_format_version: u64,
}

/// Freshness evidence reported alongside the chain identity. Missing fields
/// remain readable for legacy Personal Wallet nodes, but can never authorize
/// Agent Wallet mainnet signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NodeSyncCapabilities {
    pub tip_timestamp_unix: u64,
    pub observed_unix: u64,
    pub tip_age_seconds: u64,
    pub max_tip_age_seconds: u64,
    pub fresh: bool,
}

/// Transaction API routes compiled into and registered by the reporting node.
/// Older payloads default to an unavailable contract so sensitive callers can
/// fail closed without breaking read-only legacy handling.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NodeApiCapabilities {
    pub balance_query: bool,
    pub transaction_submit: bool,
    #[serde(default)]
    pub transaction_submit_bound: bool,
    pub transaction_query: bool,
    pub reconciliation_by_tx_hash: bool,
}

impl NodeApiCapabilities {
    pub const fn supports_agent_payment(self) -> bool {
        self.balance_query
            && self.transaction_submit
            && self.transaction_submit_bound
            && self.transaction_query
            && self.reconciliation_by_tx_hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeIdentity {
    pub name: String,
    pub version: String,
    pub build_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeChain {
    pub id: u32,
    pub height: u64,
    pub next_height: u64,
    pub mainnet: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IstanbulStatus {
    pub activation_height: u64,
    pub evaluation_height: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrySet<T> {
    pub registered: Vec<T>,
    pub enabled: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeFeatures {
    pub action_guard: bool,
    pub tx_blob: bool,
    pub ast: bool,
    pub tex: bool,
    pub native_assets: bool,
    pub hip20: bool,
    #[serde(default)]
    pub hip20_primitives: bool,
    pub hvm: bool,
    pub p2sh: bool,
    pub account_abstraction: bool,
    pub intent: bool,
    pub contract_state_leasing: bool,
    pub ir_decompilation: bool,
    pub req_sign_list: bool,
    pub type4_mainnet: bool,
    pub exact_unsigned_simulation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeLimits {
    pub max_tx_size: usize,
    pub max_tx_actions: usize,
    pub max_type3_signers: usize,
    pub gas_max_byte: u8,
    pub gas_max: i64,
    pub ast_depth: usize,
}

impl NodeCapabilities {
    pub fn validate(mut self) -> WalletResult<Self> {
        if self.ret != 0 {
            return Err(WalletError::Node(format!(
                "capability endpoint failed (ret={})",
                self.ret
            )));
        }
        if self.api_version != CAPABILITIES_API_VERSION {
            return Err(WalletError::Node(format!(
                "unsupported node capability API version {}",
                self.api_version
            )));
        }
        if self.chain.mainnet != (self.chain.id == 0) {
            return Err(WalletError::Node(
                "node capability chain id/mainnet fields disagree".into(),
            ));
        }
        if self.chain.next_height != self.chain.height.saturating_add(1)
            || self.istanbul.evaluation_height != self.chain.next_height
        {
            return Err(WalletError::Node(
                "node capability evaluation height is inconsistent".into(),
            ));
        }
        self.validate_network_contract()?;
        self.validate_sync_contract()?;
        validate_registry("transaction", &self.transactions)?;
        validate_registry("action", &self.actions)?;
        if self.chain.mainnet
            && self.istanbul.active
            && self.chain.next_height < self.istanbul.activation_height
        {
            return Err(WalletError::Node(
                "node reports Istanbul active before its activation height".into(),
            ));
        }
        if self.istanbul.active && !self.supports_transaction(3) {
            return Err(WalletError::Node(
                "node reports Istanbul active without enabled Type 3".into(),
            ));
        }
        if self.supports_transaction(3) && !self.istanbul.active {
            return Err(WalletError::Node(
                "node enables Type 3 while Istanbul is inactive".into(),
            ));
        }
        if self.limits.max_tx_size == 0
            || self.limits.max_tx_actions == 0
            || self.limits.max_type3_signers == 0
            || self.limits.gas_max_byte == 0
            || self.limits.gas_max <= 0
            || self.limits.ast_depth == 0
        {
            return Err(WalletError::Node(
                "node capability limits are invalid".into(),
            ));
        }
        if protocol::context::decode_gas_budget(self.limits.gas_max_byte) != self.limits.gas_max {
            return Err(WalletError::Node(
                "node capability gas_max does not match gas_max_byte".into(),
            ));
        }
        if self.chain.mainnet && (self.features.type4_mainnet || self.supports_transaction(4)) {
            return Err(WalletError::Node(
                "node incorrectly advertises Type 4 mainnet support".into(),
            ));
        }
        if self.features.hip20 {
            return Err(WalletError::Node(
                "node advertises final HIP-20 semantics that this wallet contract does not define"
                    .into(),
            ));
        }
        if !self.features.hvm
            && (self.features.p2sh
                || self.features.account_abstraction
                || self.features.intent
                || self.features.contract_state_leasing
                || self.features.ir_decompilation)
        {
            return Err(WalletError::Node(
                "node advertises HVM-dependent features while HVM is disabled".into(),
            ));
        }
        self.validate_feature_contracts()?;

        // Clamp untrusted remote limits to the wallet's reviewed local bounds.
        self.limits.max_tx_size = self.limits.max_tx_size.min(256 * 1024);
        self.limits.max_tx_actions = self
            .limits
            .max_tx_actions
            .min(basis::component::TX_ACTIONS_MAX);
        self.limits.max_type3_signers = self
            .limits
            .max_type3_signers
            .min(protocol::params::MAX_TYPE3_SIGNERS);
        self.limits.gas_max_byte = self
            .limits
            .gas_max_byte
            .min(protocol::context::TX_GAS_BUDGET_CAP_BYTE);
        self.limits.gas_max = protocol::context::decode_gas_budget(self.limits.gas_max_byte);
        self.limits.ast_depth = self
            .limits
            .ast_depth
            .min(protocol::action::AST_TREE_DEPTH_MAX);
        Ok(self)
    }

    pub fn legacy_type2(node_name: impl Into<String>) -> Self {
        Self {
            ret: 0,
            api_version: CAPABILITIES_API_VERSION,
            node: NodeIdentity {
                name: node_name.into(),
                version: "legacy".into(),
                build_time: String::new(),
            },
            chain: NodeChain {
                id: 0,
                height: 0,
                next_height: 1,
                mainnet: true,
            },
            network: NodeNetworkCapabilities::default(),
            sync: NodeSyncCapabilities::default(),
            istanbul: IstanbulStatus {
                activation_height: 0,
                evaluation_height: 1,
                active: false,
            },
            transactions: RegistrySet {
                registered: vec![2],
                enabled: vec![2],
            },
            actions: RegistrySet {
                registered: vec![],
                enabled: vec![],
            },
            features: NodeFeatures::disabled(),
            api: NodeApiCapabilities::default(),
            limits: NodeLimits {
                max_tx_size: 256 * 1024,
                max_tx_actions: basis::component::TX_ACTIONS_MAX,
                max_type3_signers: 1,
                gas_max_byte: 1,
                gas_max: protocol::context::decode_gas_budget(1),
                ast_depth: 1,
            },
            source: CapabilitySource::LegacyType2,
        }
    }

    pub fn supports_transaction(&self, tx_type: u8) -> bool {
        self.transactions.enabled.binary_search(&tx_type).is_ok()
    }

    pub fn supports_action(&self, kind: u16) -> bool {
        self.actions.enabled.binary_search(&kind).is_ok()
    }

    pub fn supports_agent_local_pilot_payment(&self, expected_block_one: &str) -> bool {
        self.matches_agent_local_pilot_identity(expected_block_one)
            && self.network.funding_confirmed
            && self.network.transaction_ready
            && self.chain.height >= 2
    }

    /// Exact mainnet identity and freshness contract for Agent Fast Pay. This
    /// enables only the existing Type 2/channel API path; it does not alter
    /// Hacash consensus or claim Type 4 support.
    pub fn supports_agent_mainnet_payment(&self, expected_block_one: &str) -> bool {
        let expected_instance = network_instance_id(
            &self.network.kind,
            self.chain.id,
            self.chain.mainnet,
            expected_block_one,
            &self.network.node_profile_id,
            self.network.transaction_format_version,
        );
        self.source == CapabilitySource::Reported
            && self.chain.id == 0
            && self.chain.mainnet
            && self.chain.height >= HPAY_MAINNET_MIN_SAFE_HEIGHT
            && self.network.kind == HPAY_MAINNET_NETWORK_KIND
            && self.network.node_profile_id == HPAY_MAINNET_PROFILE_ID
            && self.network.block_1_available
            && self.network.block_1_hash.as_deref() == Some(expected_block_one)
            && self.network.instance_id.as_deref() == Some(expected_instance.as_str())
            && self.network.current_height == self.chain.height
            && self.network.transaction_format_version == 2
            && self.network.transaction_ready
            && self.sync.fresh
            && self.supports_transaction(2)
            && self.supports_action(1)
            && self.supports_action(2)
            && self.supports_action(3)
            && self.supports_action(14)
            && self.supports_action(0x0411)
            && self.api.supports_agent_payment()
    }

    /// Verify the immutable Local Pilot identity without claiming that the
    /// node, wallet funding or mobile witness is ready for a payment.
    pub fn matches_agent_local_pilot_identity(&self, expected_block_one: &str) -> bool {
        let expected_instance = network_instance_id(
            &self.network.kind,
            self.chain.id,
            self.chain.mainnet,
            expected_block_one,
            &self.network.node_profile_id,
            self.network.transaction_format_version,
        );
        self.source == CapabilitySource::Reported
            && self.chain.id == HPAY_LOCAL_PILOT_CHAIN_ID
            && !self.chain.mainnet
            && self.network.kind == HPAY_LOCAL_PILOT_NETWORK_KIND
            && self.network.node_profile_id == HPAY_LOCAL_PILOT_PROFILE_ID
            && self.network.block_1_available
            && self.network.block_1_hash.as_deref() == Some(expected_block_one)
            && self.network.instance_id.as_deref() == Some(expected_instance.as_str())
            && self.network.current_height == self.chain.height
            && self.chain.height >= 1
            && self.network.transaction_format_version == 2
            && self.supports_transaction(2)
            && self.supports_action(1)
            && self.supports_action(2)
            && self.supports_action(3)
            && self.supports_action(14)
            && self.supports_action(0x0411)
            && self.api.supports_agent_payment()
    }

    fn validate_network_contract(&self) -> WalletResult<()> {
        let network = &self.network;
        let omitted = network == &NodeNetworkCapabilities::default();
        if omitted {
            return Ok(());
        }
        if network.kind.is_empty()
            || network.node_profile_id.is_empty()
            || network.current_height != self.chain.height
            || network.transaction_format_version == 0
        {
            return Err(WalletError::Node(
                "node network capability identity is incomplete".into(),
            ));
        }
        if network.block_1_available
            != (network.block_1_hash.is_some() && network.instance_id.is_some())
        {
            return Err(WalletError::Node(
                "node block 1 availability fields disagree".into(),
            ));
        }
        if !network.block_1_available && network.transaction_ready {
            return Err(WalletError::Node(
                "node reports transaction readiness without block 1".into(),
            ));
        }
        if let (Some(block_one), Some(instance_id)) = (&network.block_1_hash, &network.instance_id)
        {
            validate_lowercase_sha256("block 1", block_one)?;
            validate_lowercase_sha256("network instance", instance_id)?;
            let expected = network_instance_id(
                &network.kind,
                self.chain.id,
                self.chain.mainnet,
                block_one,
                &network.node_profile_id,
                network.transaction_format_version,
            );
            if *instance_id != expected {
                return Err(WalletError::Node(
                    "node network instance id does not match its reported identity".into(),
                ));
            }
        }
        if network.transaction_ready {
            let valid_local_pilot = !self.chain.mainnet
                && self.chain.id == HPAY_LOCAL_PILOT_CHAIN_ID
                && self.chain.height >= 2
                && network.kind == HPAY_LOCAL_PILOT_NETWORK_KIND
                && network.node_profile_id == HPAY_LOCAL_PILOT_PROFILE_ID
                && network.funding_confirmed
                && network.transaction_format_version == 2;
            let valid_mainnet = self.chain.mainnet
                && self.chain.id == 0
                && self.chain.height >= HPAY_MAINNET_MIN_SAFE_HEIGHT
                && network.kind == HPAY_MAINNET_NETWORK_KIND
                && network.node_profile_id == HPAY_MAINNET_PROFILE_ID
                && network.transaction_format_version == 2
                && self.sync.fresh;
            if !valid_local_pilot && !valid_mainnet {
                return Err(WalletError::Node(
                    "node transaction readiness contradicts its reported network contract".into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_sync_contract(&self) -> WalletResult<()> {
        let sync = &self.sync;
        if sync == &NodeSyncCapabilities::default() {
            return Ok(());
        }
        let computed_age = sync.observed_unix.saturating_sub(sync.tip_timestamp_unix);
        let computed_fresh = self.chain.height > 0
            && sync.tip_timestamp_unix > 0
            && sync.tip_timestamp_unix
                <= sync
                    .observed_unix
                    .saturating_add(MAX_FUTURE_TIP_SKEW_SECONDS)
            && computed_age <= sync.max_tip_age_seconds;
        if sync.observed_unix == 0
            || sync.max_tip_age_seconds == 0
            || sync.max_tip_age_seconds > MAX_MAINNET_TIP_AGE_SECONDS
            || sync.tip_age_seconds != computed_age
            || sync.fresh != computed_fresh
        {
            return Err(WalletError::Node(
                "node sync freshness capability is inconsistent".into(),
            ));
        }
        Ok(())
    }

    fn validate_feature_contracts(&self) -> WalletResult<()> {
        self.validate_feature_action_set(&self.actions.registered, "registered")?;
        if self.istanbul.active {
            self.validate_feature_action_set(&self.actions.enabled, "enabled")?;
        }
        Ok(())
    }

    fn validate_feature_action_set(&self, available: &[u16], state: &str) -> WalletResult<()> {
        let requirements: [(&str, bool, &[u16]); 12] = [
            (
                "ActionGuard",
                self.features.action_guard,
                &[0x0411, 0x0412, 0x0413, 0x0414],
            ),
            ("TxBlob", self.features.tx_blob, &[0x0402]),
            ("AST", self.features.ast, &[25, 26]),
            ("TEX", self.features.tex, &[22]),
            ("native assets", self.features.native_assets, &[17, 18, 19]),
            (
                "HIP-20 primitives",
                self.features.hip20_primitives,
                &[16, 17, 18, 19],
            ),
            ("HVM", self.features.hvm, &[40, 41, 44]),
            ("P2SH", self.features.p2sh, &[46]),
            (
                "account abstraction",
                self.features.account_abstraction,
                &[40, 41, 44, 46],
            ),
            ("Intent", self.features.intent, &[40, 41, 44]),
            (
                "contract state leasing",
                self.features.contract_state_leasing,
                &[40, 41, 44],
            ),
            ("ReqSignList", self.features.req_sign_list, &[0x0414]),
        ];
        for (label, claimed, kinds) in requirements {
            if claimed
                && !kinds
                    .iter()
                    .all(|kind| available.binary_search(kind).is_ok())
            {
                return Err(WalletError::Node(format!(
                    "node advertises {label} without all required {state} action codecs"
                )));
            }
        }
        Ok(())
    }
}

fn validate_lowercase_sha256(label: &str, value: &str) -> WalletResult<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(WalletError::Node(format!(
            "node {label} fingerprint is not canonical lowercase SHA-256"
        )))
    }
}

fn push_identity_field(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

pub fn network_instance_id(
    network_kind: &str,
    chain_id: u32,
    mainnet: bool,
    block_one_hash: &str,
    node_profile_id: &str,
    transaction_format_version: u64,
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"HPAY/NETWORK-INSTANCE/V1");
    push_identity_field(&mut bytes, network_kind);
    bytes.extend_from_slice(&chain_id.to_be_bytes());
    bytes.push(u8::from(mainnet));
    push_identity_field(&mut bytes, block_one_hash);
    push_identity_field(&mut bytes, node_profile_id);
    bytes.extend_from_slice(&transaction_format_version.to_be_bytes());
    hex::encode(Sha256::digest(bytes))
}

impl NodeFeatures {
    fn disabled() -> Self {
        Self {
            action_guard: false,
            tx_blob: false,
            ast: false,
            tex: false,
            native_assets: false,
            hip20: false,
            hip20_primitives: false,
            hvm: false,
            p2sh: false,
            account_abstraction: false,
            intent: false,
            contract_state_leasing: false,
            ir_decompilation: false,
            req_sign_list: false,
            type4_mainnet: false,
            exact_unsigned_simulation: false,
        }
    }
}

fn validate_registry<T>(label: &str, registry: &RegistrySet<T>) -> WalletResult<()>
where
    T: Copy + Ord,
{
    if !strictly_sorted(&registry.registered) || !strictly_sorted(&registry.enabled) {
        return Err(WalletError::Node(format!(
            "node {label} capability arrays must be sorted and unique"
        )));
    }
    if registry
        .enabled
        .iter()
        .any(|item| registry.registered.binary_search(item).is_err())
    {
        return Err(WalletError::Node(format!(
            "node enabled {label} is not registered"
        )));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeApiError {
    pub ret: Option<i32>,
    pub code: Option<String>,
    pub stage: Option<String>,
    pub message: String,
    #[serde(default)]
    pub details: Map<String, Value>,
}

impl NodeApiError {
    pub fn from_value(value: &Value, fallback: impl Into<String>) -> Self {
        let object = value.as_object();
        let string = |key: &str| {
            object
                .and_then(|map| map.get(key))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let message = string("message")
            .or_else(|| string("error"))
            .or_else(|| string("err"))
            .unwrap_or_else(|| fallback.into());
        let mut details = object.cloned().unwrap_or_default();
        for key in ["ret", "code", "stage", "message", "error", "err"] {
            details.remove(key);
        }
        Self {
            ret: object
                .and_then(|map| map.get("ret"))
                .and_then(Value::as_i64)
                .and_then(|ret| i32::try_from(ret).ok()),
            code: string("code"),
            stage: string("stage"),
            message,
            details,
        }
    }
}

impl fmt::Display for NodeApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.code, &self.stage, self.ret) {
            (Some(code), Some(stage), Some(ret)) => {
                write!(
                    formatter,
                    "[{code}] {} at {stage} (ret={ret})",
                    self.message
                )
            }
            (Some(code), Some(stage), None) => {
                write!(formatter, "[{code}] {} at {stage}", self.message)
            }
            (Some(code), None, _) => write!(formatter, "[{code}] {}", self.message),
            (None, _, Some(ret)) => write!(formatter, "{} (ret={ret})", self.message),
            (None, _, None) => formatter.write_str(&self.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_capabilities() -> NodeCapabilities {
        NodeCapabilities {
            ret: 0,
            api_version: 1,
            node: NodeIdentity {
                name: "test".into(),
                version: "1.0.10".into(),
                build_time: "now".into(),
            },
            chain: NodeChain {
                id: 0,
                height: 99,
                next_height: 100,
                mainnet: true,
            },
            network: NodeNetworkCapabilities::default(),
            sync: NodeSyncCapabilities::default(),
            istanbul: IstanbulStatus {
                activation_height: 200,
                evaluation_height: 100,
                active: false,
            },
            transactions: RegistrySet {
                registered: vec![2, 3, 4],
                enabled: vec![2],
            },
            actions: RegistrySet {
                registered: vec![],
                enabled: vec![],
            },
            features: NodeFeatures::disabled(),
            api: NodeApiCapabilities {
                balance_query: true,
                transaction_submit: true,
                transaction_submit_bound: true,
                transaction_query: true,
                reconciliation_by_tx_hash: true,
            },
            limits: NodeLimits {
                max_tx_size: 1024,
                max_tx_actions: 10,
                max_type3_signers: 4,
                gas_max_byte: 17,
                gas_max: protocol::context::decode_gas_budget(17),
                ast_depth: 3,
            },
            source: CapabilitySource::Reported,
        }
    }

    fn local_pilot_capabilities() -> NodeCapabilities {
        const BLOCK_ONE: &str = "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";
        let mut capabilities = valid_capabilities();
        capabilities.chain = NodeChain {
            id: HPAY_LOCAL_PILOT_CHAIN_ID,
            height: 2,
            next_height: 3,
            mainnet: false,
        };
        capabilities.istanbul = IstanbulStatus {
            activation_height: 1,
            evaluation_height: 3,
            active: true,
        };
        capabilities.transactions = RegistrySet {
            registered: vec![2, 3],
            enabled: vec![2, 3],
        };
        capabilities.actions = RegistrySet {
            registered: vec![1, 2, 3, 14, 0x0411],
            enabled: vec![1, 2, 3, 14, 0x0411],
        };
        capabilities.network = NodeNetworkCapabilities {
            kind: HPAY_LOCAL_PILOT_NETWORK_KIND.into(),
            node_profile_id: HPAY_LOCAL_PILOT_PROFILE_ID.into(),
            block_1_available: true,
            block_1_hash: Some(BLOCK_ONE.into()),
            instance_id: Some(network_instance_id(
                HPAY_LOCAL_PILOT_NETWORK_KIND,
                HPAY_LOCAL_PILOT_CHAIN_ID,
                false,
                BLOCK_ONE,
                HPAY_LOCAL_PILOT_PROFILE_ID,
                2,
            )),
            funding_confirmed: true,
            transaction_ready: true,
            current_height: 2,
            transaction_format_version: 2,
        };
        capabilities
    }

    fn mainnet_agent_capabilities() -> NodeCapabilities {
        const BLOCK_ONE: &str = "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
        let mut capabilities = valid_capabilities();
        capabilities.chain = NodeChain {
            id: 0,
            height: HPAY_MAINNET_MIN_SAFE_HEIGHT,
            next_height: HPAY_MAINNET_MIN_SAFE_HEIGHT + 1,
            mainnet: true,
        };
        capabilities.istanbul = IstanbulStatus {
            activation_height: 700_000,
            evaluation_height: HPAY_MAINNET_MIN_SAFE_HEIGHT + 1,
            active: true,
        };
        capabilities.transactions = RegistrySet {
            registered: vec![2, 3],
            enabled: vec![2, 3],
        };
        capabilities.actions = RegistrySet {
            registered: vec![1, 2, 3, 14, 0x0411],
            enabled: vec![1, 2, 3, 14, 0x0411],
        };
        capabilities.network = NodeNetworkCapabilities {
            kind: HPAY_MAINNET_NETWORK_KIND.into(),
            node_profile_id: HPAY_MAINNET_PROFILE_ID.into(),
            block_1_available: true,
            block_1_hash: Some(BLOCK_ONE.into()),
            instance_id: Some(network_instance_id(
                HPAY_MAINNET_NETWORK_KIND,
                0,
                true,
                BLOCK_ONE,
                HPAY_MAINNET_PROFILE_ID,
                2,
            )),
            funding_confirmed: false,
            transaction_ready: true,
            current_height: HPAY_MAINNET_MIN_SAFE_HEIGHT,
            transaction_format_version: 2,
        };
        capabilities.sync = NodeSyncCapabilities {
            tip_timestamp_unix: 1_999_940,
            observed_unix: 2_000_000,
            tip_age_seconds: 60,
            max_tip_age_seconds: MAX_MAINNET_TIP_AGE_SECONDS,
            fresh: true,
        };
        capabilities
    }

    #[test]
    fn agent_mainnet_requires_exact_identity_freshness_and_channel_actions() {
        const BLOCK_ONE: &str = "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
        let capabilities = mainnet_agent_capabilities().validate().unwrap();
        assert!(capabilities.supports_agent_mainnet_payment(BLOCK_ONE));

        let mut stale = mainnet_agent_capabilities();
        stale.sync.fresh = false;
        assert!(stale.validate().is_err());

        let mut no_close = mainnet_agent_capabilities().validate().unwrap();
        no_close.actions.enabled.retain(|kind| *kind != 14);
        assert!(!no_close.supports_agent_mainnet_payment(BLOCK_ONE));

        let mut no_chain_guard = mainnet_agent_capabilities().validate().unwrap();
        no_chain_guard
            .actions
            .enabled
            .retain(|kind| *kind != 0x0411);
        assert!(!no_chain_guard.supports_agent_mainnet_payment(BLOCK_ONE));

        let mut no_bound_submit = mainnet_agent_capabilities().validate().unwrap();
        no_bound_submit.api.transaction_submit_bound = false;
        assert!(!no_bound_submit.supports_agent_mainnet_payment(BLOCK_ONE));

        let mut wrong_anchor = mainnet_agent_capabilities().validate().unwrap();
        wrong_anchor.network.block_1_hash = Some("11".repeat(32));
        assert!(!wrong_anchor.supports_agent_mainnet_payment(BLOCK_ONE));
    }

    #[test]
    fn local_pilot_requires_the_complete_stable_network_identity() {
        let capabilities = local_pilot_capabilities().validate().unwrap();
        let block_one = capabilities.network.block_1_hash.as_deref().unwrap();
        assert!(capabilities.matches_agent_local_pilot_identity(block_one));
        assert!(capabilities.supports_agent_local_pilot_payment(block_one));

        let mut identity_only = local_pilot_capabilities();
        identity_only.network.funding_confirmed = false;
        identity_only.network.transaction_ready = false;
        let identity_only = identity_only.validate().unwrap();
        assert!(identity_only.matches_agent_local_pilot_identity(block_one));
        assert!(!identity_only.supports_agent_local_pilot_payment(block_one));

        let mut different_instance = local_pilot_capabilities();
        different_instance.network.instance_id = Some("11".repeat(32));
        assert!(different_instance.validate().is_err());

        let mut height_one_claim = local_pilot_capabilities();
        height_one_claim.chain.height = 1;
        height_one_claim.chain.next_height = 2;
        height_one_claim.istanbul.evaluation_height = 2;
        height_one_claim.network.current_height = 1;
        assert!(height_one_claim.validate().is_err());

        let mut unfunded_claim = local_pilot_capabilities();
        unfunded_claim.network.funding_confirmed = false;
        assert!(unfunded_claim.validate().is_err());
    }

    #[test]
    fn legacy_payload_without_network_identity_stays_readable_but_never_agent_ready() {
        let capabilities = valid_capabilities().validate().unwrap();
        assert_eq!(capabilities.network, NodeNetworkCapabilities::default());
        assert!(!capabilities.supports_agent_local_pilot_payment(&"11".repeat(32)));
    }

    #[test]
    fn contradictions_fail_closed() {
        let mut active_without_type3 = valid_capabilities();
        active_without_type3.istanbul.active = true;
        active_without_type3.istanbul.activation_height = 100;
        assert!(active_without_type3.validate().is_err());

        let mut hvm_dependency = valid_capabilities();
        hvm_dependency.features.p2sh = true;
        hvm_dependency.actions.registered = vec![46];
        assert!(hvm_dependency.validate().is_err());

        let mut mainnet_type4 = valid_capabilities();
        mainnet_type4.transactions.enabled = vec![2, 4];
        assert!(mainnet_type4.validate().is_err());

        let mut active_claim_without_enabled_codec = valid_capabilities();
        active_claim_without_enabled_codec.istanbul.active = true;
        active_claim_without_enabled_codec
            .istanbul
            .activation_height = 100;
        active_claim_without_enabled_codec.transactions.enabled = vec![2, 3];
        active_claim_without_enabled_codec.features.tx_blob = true;
        active_claim_without_enabled_codec.actions.registered = vec![0x0402];
        assert!(active_claim_without_enabled_codec.validate().is_err());

        let mut inactive_with_enabled_type3 = valid_capabilities();
        inactive_with_enabled_type3.transactions.enabled = vec![2, 3];
        assert!(inactive_with_enabled_type3.validate().is_err());
    }

    #[test]
    fn unknown_fields_are_tolerated_but_unknown_api_versions_fail_closed() {
        let mut value = serde_json::to_value(valid_capabilities()).unwrap();
        value["future_field"] = json!({ "safe_to_ignore": true });
        let parsed: NodeCapabilities = serde_json::from_value(value).unwrap();
        assert!(parsed.validate().is_ok());

        let mut future = valid_capabilities();
        future.api_version = 2;
        assert!(future.validate().is_err());
    }

    #[test]
    fn structured_node_error_keeps_machine_fields_and_safe_display() {
        let value = json!({
            "ret": 1,
            "code": "create_transaction_invalid_gas_max",
            "stage": "parse_gas_max",
            "message": "gas_max exceeds cap",
            "field": "gas_max",
            "max": 99
        });
        let error = NodeApiError::from_value(&value, "fallback");
        assert_eq!(
            error.code.as_deref(),
            Some("create_transaction_invalid_gas_max")
        );
        assert_eq!(error.details["field"], "gas_max");
        assert_eq!(
            error.to_string(),
            "[create_transaction_invalid_gas_max] gas_max exceeds cap at parse_gas_max (ret=1)"
        );
    }

    #[test]
    fn duplicate_capability_items_fail_closed() {
        let registry = RegistrySet {
            registered: vec![2_u8, 2],
            enabled: vec![2],
        };
        assert!(validate_registry("transaction", &registry).is_err());
    }
}
