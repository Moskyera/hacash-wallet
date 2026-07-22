//! Typed contract for the Istanbul node capability endpoint and API failures.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{WalletError, WalletResult};

pub const CAPABILITIES_API_VERSION: u32 = 1;

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
    pub istanbul: IstanbulStatus,
    pub transactions: RegistrySet<u8>,
    pub actions: RegistrySet<u16>,
    pub features: NodeFeatures,
    pub limits: NodeLimits,
    #[serde(default)]
    pub source: CapabilitySource,
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
