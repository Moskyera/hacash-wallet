use std::time::Duration;

use hacash_wallet_core::node::NodeClient;
use hacash_wallet_core::node_discovery::MAINNET_BLOCK_ONE_HASH;
use hacash_wallet_core::settings::validate_signing_node_url;
#[cfg(feature = "agent-wallet-testnet-pilot")]
use hacash_wallet_core::{CapabilitySource, NodeCapabilities};
use serde::{Deserialize, Serialize};
#[cfg(feature = "agent-wallet-testnet-pilot")]
use sha2::{Digest, Sha256};

use crate::error::{AgentWalletError, AgentWalletResult};

const AGENT_NODE_PROBE_TIMEOUT: Duration = Duration::from_secs(6);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentNodeStatus {
    Unchecked,
    Verified,
    Offline,
    NetworkMismatch,
    CapabilityMismatch,
    BalanceError,
}

pub(crate) struct AgentNodeProbe {
    pub status: AgentNodeStatus,
    pub error: Option<String>,
    pub snapshot: Option<AgentNodeSnapshot>,
    client: Option<NodeClient>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentNodeSnapshot {
    pub node_name: String,
    pub node_version: String,
    pub network_kind: String,
    pub node_profile_id: String,
    pub node_profile_commitment: String,
    pub chain_id: u32,
    pub mainnet: bool,
    pub current_height: u64,
    pub block_one_fingerprint: String,
    pub network_instance_id: String,
    pub funding_confirmed: bool,
    pub transaction_ready: bool,
    pub transaction_format_version: u64,
}

pub(crate) struct VerifiedAgentNode {
    client: NodeClient,
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    snapshot: AgentNodeSnapshot,
}

impl std::ops::Deref for VerifiedAgentNode {
    type Target = NodeClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
impl VerifiedAgentNode {
    pub(crate) fn snapshot(&self) -> &AgentNodeSnapshot {
        &self.snapshot
    }

    pub(crate) fn node_profile_commitment(&self) -> &str {
        &self.snapshot.node_profile_commitment
    }

    pub(crate) const fn chain_id(&self) -> u32 {
        self.snapshot.chain_id
    }

    pub(crate) fn network_kind(&self) -> &str {
        &self.snapshot.network_kind
    }

    pub(crate) fn network_instance_id(&self) -> &str {
        &self.snapshot.network_instance_id
    }

    pub(crate) const fn transaction_format_version(&self) -> u64 {
        self.snapshot.transaction_format_version
    }
}

#[cfg(feature = "agent-wallet-testnet-pilot")]
fn validate_agent_capabilities(
    capabilities: &NodeCapabilities,
    network_mode: &str,
    expected_fingerprint: &str,
) -> AgentWalletResult<(String, String, String, u64)> {
    let network_matches = match network_mode {
        "testnet" => capabilities.supports_agent_local_pilot_payment(expected_fingerprint),
        "mainnet" if cfg!(feature = "agent-wallet-bounded-mainnet-pilot") => {
            capabilities.supports_agent_mainnet_payment(expected_fingerprint)
        }
        _ => false,
    };
    if capabilities.source != CapabilitySource::Reported
        || capabilities.node.name != "hacash-fullnode"
        || capabilities.node.version != "1.0.10"
        || !network_matches
    {
        return Err(AgentWalletError::NodeCapabilityMismatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"HPAY/AGENT/NODE-PROFILE/V1");
    hasher.update(capabilities.api_version.to_be_bytes());
    hasher.update((capabilities.node.name.len() as u64).to_be_bytes());
    hasher.update(capabilities.node.name.as_bytes());
    hasher.update((capabilities.node.version.len() as u64).to_be_bytes());
    hasher.update(capabilities.node.version.as_bytes());
    hasher.update(capabilities.chain.id.to_be_bytes());
    hasher.update([u8::from(capabilities.chain.mainnet)]);
    hasher.update((capabilities.network.kind.len() as u64).to_be_bytes());
    hasher.update(capabilities.network.kind.as_bytes());
    hasher.update((capabilities.network.node_profile_id.len() as u64).to_be_bytes());
    hasher.update(capabilities.network.node_profile_id.as_bytes());
    hasher.update((expected_fingerprint.len() as u64).to_be_bytes());
    hasher.update(expected_fingerprint.as_bytes());
    let network_instance_id = capabilities
        .network
        .instance_id
        .as_deref()
        .ok_or(AgentWalletError::NodeCapabilityMismatch)?;
    hasher.update((network_instance_id.len() as u64).to_be_bytes());
    hasher.update(network_instance_id.as_bytes());
    hasher.update(
        capabilities
            .network
            .transaction_format_version
            .to_be_bytes(),
    );
    for tx_type in &capabilities.transactions.enabled {
        hasher.update([*tx_type]);
    }
    for action_kind in &capabilities.actions.enabled {
        hasher.update(action_kind.to_be_bytes());
    }
    hasher.update([
        u8::from(capabilities.api.balance_query),
        u8::from(capabilities.api.transaction_submit),
        u8::from(capabilities.api.transaction_submit_bound),
        u8::from(capabilities.api.transaction_query),
        u8::from(capabilities.api.reconciliation_by_tx_hash),
    ]);
    Ok((
        hex::encode(hasher.finalize()),
        capabilities.network.kind.clone(),
        network_instance_id.to_owned(),
        capabilities.network.transaction_format_version,
    ))
}
pub(crate) fn anchor_for_new_wallet(
    network_mode: &str,
    supplied_fingerprint: Option<&str>,
) -> AgentWalletResult<String> {
    match network_mode {
        "mainnet" => match supplied_fingerprint {
            None => Ok(MAINNET_BLOCK_ONE_HASH.to_owned()),
            Some(fingerprint) if fingerprint == MAINNET_BLOCK_ONE_HASH => {
                Ok(MAINNET_BLOCK_ONE_HASH.to_owned())
            }
            Some(_) => Err(AgentWalletError::InvalidNodeAnchor),
        },
        "testnet" => {
            let fingerprint = supplied_fingerprint.ok_or(AgentWalletError::InvalidNodeAnchor)?;
            validate_lowercase_hash(fingerprint)?;
            if fingerprint == MAINNET_BLOCK_ONE_HASH {
                return Err(AgentWalletError::InvalidNodeAnchor);
            }
            Ok(fingerprint.to_owned())
        }
        _ => Err(AgentWalletError::InvalidPaymentRequest),
    }
}

pub(crate) fn validate_stored_anchor(
    network_mode: &str,
    fingerprint: &str,
) -> AgentWalletResult<()> {
    validate_lowercase_hash(fingerprint).map_err(|_| AgentWalletError::RecoveryRequired)?;
    match network_mode {
        "mainnet" if fingerprint == MAINNET_BLOCK_ONE_HASH => Ok(()),
        "testnet" if fingerprint != MAINNET_BLOCK_ONE_HASH => Ok(()),
        "mainnet" | "testnet" => Err(AgentWalletError::RecoveryRequired),
        _ => Err(AgentWalletError::RecoveryRequired),
    }
}

pub(crate) async fn probe_agent_node(
    node_url: &str,
    network_mode: &str,
    expected_fingerprint: &str,
) -> AgentNodeProbe {
    if validate_stored_anchor(network_mode, expected_fingerprint).is_err() {
        return AgentNodeProbe {
            status: AgentNodeStatus::NetworkMismatch,
            error: Some("Agent Wallet node anchor is missing or invalid".into()),
            snapshot: None,
            client: None,
        };
    }

    let node = match NodeClient::new(node_url) {
        Ok(node) => node,
        Err(_) => {
            return AgentNodeProbe {
                status: AgentNodeStatus::Offline,
                error: Some("Hacash node URL is invalid or unavailable".into()),
                snapshot: None,
                client: None,
            };
        }
    };
    let anchor = match tokio::time::timeout(AGENT_NODE_PROBE_TIMEOUT, node.block_intro(1)).await {
        Ok(Ok(anchor)) => anchor,
        Ok(Err(_)) => {
            return AgentNodeProbe {
                status: AgentNodeStatus::Offline,
                error: Some("Hacash node anchor query failed".into()),
                snapshot: None,
                client: None,
            };
        }
        Err(_) => {
            return AgentNodeProbe {
                status: AgentNodeStatus::Offline,
                error: Some("Hacash node anchor query timed out".into()),
                snapshot: None,
                client: None,
            };
        }
    };
    if anchor.height != 1
        || !is_hex_hash(&anchor.hash)
        || !anchor.hash.eq_ignore_ascii_case(expected_fingerprint)
    {
        AgentNodeProbe {
            status: AgentNodeStatus::NetworkMismatch,
            error: Some("Hacash node block 1 does not match this Agent Wallet".into()),
            snapshot: None,
            client: None,
        }
    } else {
        #[cfg(feature = "agent-wallet-testnet-pilot")]
        {
            let capabilities =
                match tokio::time::timeout(AGENT_NODE_PROBE_TIMEOUT, node.capabilities()).await {
                    Ok(Ok(capabilities)) => capabilities,
                    Ok(Err(_)) => {
                        return AgentNodeProbe {
                            status: AgentNodeStatus::CapabilityMismatch,
                            error: Some("Hacash node capability query failed".into()),
                            snapshot: None,
                            client: None,
                        };
                    }
                    Err(_) => {
                        return AgentNodeProbe {
                            status: AgentNodeStatus::CapabilityMismatch,
                            error: Some("Hacash node capability query timed out".into()),
                            snapshot: None,
                            client: None,
                        };
                    }
                };
            let identity_matches = match network_mode {
                "testnet" => capabilities.supports_agent_local_pilot_payment(expected_fingerprint),
                "mainnet" if cfg!(feature = "agent-wallet-bounded-mainnet-pilot") => {
                    capabilities.supports_agent_mainnet_payment(expected_fingerprint)
                }
                _ => false,
            };
            if capabilities.node.name != "hacash-fullnode"
                || capabilities.node.version != "1.0.10"
                || !identity_matches
            {
                return AgentNodeProbe {
                    status: AgentNodeStatus::CapabilityMismatch,
                    error: Some(
                        "Hacash node does not match the exact HPAY Agent network identity".into(),
                    ),
                    snapshot: None,
                    client: None,
                };
            }
            let (
                node_profile_commitment,
                network_kind,
                network_instance_id,
                transaction_format_version,
            ) = match validate_agent_capabilities(&capabilities, network_mode, expected_fingerprint)
            {
                Ok(binding) => binding,
                Err(_) => {
                    return AgentNodeProbe {
                        status: AgentNodeStatus::CapabilityMismatch,
                        error: Some("HPAY Agent node capability commitment is invalid".into()),
                        snapshot: None,
                        client: None,
                    };
                }
            };
            AgentNodeProbe {
                status: AgentNodeStatus::Verified,
                error: None,
                snapshot: Some(AgentNodeSnapshot {
                    node_name: capabilities.node.name,
                    node_version: capabilities.node.version,
                    network_kind,
                    node_profile_id: capabilities.network.node_profile_id,
                    node_profile_commitment,
                    chain_id: capabilities.chain.id,
                    mainnet: capabilities.chain.mainnet,
                    current_height: capabilities.chain.height,
                    block_one_fingerprint: expected_fingerprint.to_owned(),
                    network_instance_id,
                    funding_confirmed: capabilities.network.funding_confirmed,
                    transaction_ready: capabilities.network.transaction_ready,
                    transaction_format_version,
                }),
                client: Some(node),
            }
        }
        #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
        AgentNodeProbe {
            status: AgentNodeStatus::Verified,
            error: None,
            snapshot: None,
            client: Some(node),
        }
    }
}

pub(crate) async fn verified_agent_node(
    node_url: &str,
    network_mode: &str,
    expected_fingerprint: &str,
) -> AgentWalletResult<VerifiedAgentNode> {
    validate_signing_node_url(node_url, network_mode)
        .map_err(|_| AgentWalletError::SigningBlocked)?;
    let mut probe = probe_agent_node(node_url, network_mode, expected_fingerprint).await;
    match probe.status {
        AgentNodeStatus::Verified => {}
        AgentNodeStatus::NetworkMismatch | AgentNodeStatus::Unchecked => {
            return Err(AgentWalletError::NodeNetworkMismatch);
        }
        AgentNodeStatus::CapabilityMismatch => {
            return Err(AgentWalletError::NodeCapabilityMismatch);
        }
        AgentNodeStatus::Offline | AgentNodeStatus::BalanceError => {
            return Err(AgentWalletError::NodeRejected);
        }
    }
    let client = probe.client.take().ok_or(AgentWalletError::NodeRejected)?;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    {
        if network_mode != "testnet"
            && !(network_mode == "mainnet" && cfg!(feature = "agent-wallet-bounded-mainnet-pilot"))
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        let snapshot = probe
            .snapshot
            .take()
            .ok_or(AgentWalletError::NodeCapabilityMismatch)?;
        Ok(VerifiedAgentNode { client, snapshot })
    }
    #[cfg(not(feature = "agent-wallet-testnet-pilot"))]
    Ok(VerifiedAgentNode { client })
}
fn validate_lowercase_hash(fingerprint: &str) -> AgentWalletResult<()> {
    if fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(AgentWalletError::InvalidNodeAnchor)
    }
}

fn is_hex_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    use axum::http::StatusCode;
    use axum::{Json, Router, routing::get};
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    use hacash_wallet_core::{HPAY_LOCAL_PILOT_CHAIN_ID, HPAY_LOCAL_PILOT_NETWORK_KIND};
    use serde_json::{Value, json};

    const TESTNET_ANCHOR: &str = "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";
    const ARBITRARY_FORK: &str = "100008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";

    #[tokio::test]
    async fn remote_http_mainnet_node_is_rejected_before_probe() {
        assert!(matches!(
            verified_agent_node(
                hacash_wallet_core::settings::DEFAULT_NODE_URL,
                "mainnet",
                MAINNET_BLOCK_ONE_HASH,
            )
            .await,
            Err(AgentWalletError::SigningBlocked)
        ));
    }

    fn official_style_capabilities() -> Value {
        let instance_id = hacash_wallet_core::network_instance_id(
            hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
            hacash_wallet_core::HPAY_LOCAL_PILOT_CHAIN_ID,
            false,
            TESTNET_ANCHOR,
            hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
            2,
        );
        json!({
            "ret": 0,
            "api_version": 1,
            "node": { "name": "hacash-fullnode", "version": "1.0.10", "build_time": "test" },
            "chain": { "id": 7, "height": 10, "next_height": 11, "mainnet": false },
            "network": {
                "kind": hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
                "node_profile_id": hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
                "block_1_available": true,
                "block_1_hash": TESTNET_ANCHOR,
                "instance_id": instance_id,
                "funding_confirmed": true,
                "transaction_ready": true,
                "current_height": 10,
                "transaction_format_version": 2
            },
            "istanbul": { "activation_height": 1, "evaluation_height": 11, "active": true },
            "transactions": { "registered": [2, 3], "enabled": [2, 3] },
            "actions": { "registered": [1, 2, 3, 14, 1041], "enabled": [1, 2, 3, 14, 1041] },
            "features": {
                "action_guard": false, "tx_blob": false, "ast": false, "tex": false,
                "native_assets": false, "hip20": false, "hip20_primitives": false,
                "hvm": false, "p2sh": false, "account_abstraction": false,
                "intent": false, "contract_state_leasing": false,
                "ir_decompilation": false, "req_sign_list": false,
                "type4_mainnet": false, "exact_unsigned_simulation": false
            },
            "api": {
                "balance_query": true,
                "transaction_submit": true,
                "transaction_submit_bound": true,
                "transaction_query": true,
                "reconciliation_by_tx_hash": true
            },
            "limits": {
                "max_tx_size": 1024, "max_tx_actions": 8, "max_type3_signers": 2,
                "gas_max_byte": 1,
                "gas_max": protocol::context::decode_gas_budget(1),
                "ast_depth": 1
            }
        })
    }

    #[cfg(feature = "agent-wallet-bounded-mainnet-pilot")]
    fn mainnet_capabilities() -> Value {
        let instance_id = hacash_wallet_core::network_instance_id(
            hacash_wallet_core::HPAY_MAINNET_NETWORK_KIND,
            0,
            true,
            MAINNET_BLOCK_ONE_HASH,
            hacash_wallet_core::HPAY_MAINNET_PROFILE_ID,
            2,
        );
        json!({
            "ret": 0,
            "api_version": 1,
            "node": { "name": "hacash-fullnode", "version": "1.0.10", "build_time": "test" },
            "chain": { "id": 0, "height": 765432, "next_height": 765433, "mainnet": true },
            "network": {
                "kind": "mainnet",
                "node_profile_id": "hacash-mainnet",
                "block_1_available": true,
                "block_1_hash": MAINNET_BLOCK_ONE_HASH,
                "instance_id": instance_id,
                "funding_confirmed": false,
                "transaction_ready": true,
                "current_height": 765432,
                "transaction_format_version": 2
            },
            "sync": {
                "tip_timestamp_unix": 1999940,
                "observed_unix": 2000000,
                "tip_age_seconds": 60,
                "max_tip_age_seconds": 3600,
                "fresh": true
            },
            "istanbul": { "activation_height": 700000, "evaluation_height": 765433, "active": true },
            "transactions": { "registered": [2, 3], "enabled": [2, 3] },
            "actions": { "registered": [1, 2, 3, 14, 1041], "enabled": [1, 2, 3, 14, 1041] },
            "features": {
                "action_guard": false, "tx_blob": false, "ast": false, "tex": false,
                "native_assets": false, "hip20": false, "hip20_primitives": false,
                "hvm": false, "p2sh": false, "account_abstraction": false,
                "intent": false, "contract_state_leasing": false,
                "ir_decompilation": false, "req_sign_list": false,
                "type4_mainnet": false, "exact_unsigned_simulation": false
            },
            "api": {
                "balance_query": true,
                "transaction_submit": true,
                "transaction_submit_bound": true,
                "transaction_query": true,
                "reconciliation_by_tx_hash": true
            },
            "limits": {
                "max_tx_size": 1024, "max_tx_actions": 8, "max_type3_signers": 2,
                "gas_max_byte": 1,
                "gas_max": protocol::context::decode_gas_budget(1),
                "ast_depth": 1
            }
        })
    }

    async fn spawn_app(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), task)
    }

    fn anchor_router(hash: &'static str) -> Router {
        Router::new().route(
            "/query/block/intro",
            get(move || async move { Json(json!({ "ret": 0, "height": 1, "hash": hash })) }),
        )
    }

    async fn spawn_capability_node(
        hash: &'static str,
        capabilities: Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = anchor_router(hash).route(
            "/query/capabilities",
            get(move || {
                let capabilities = capabilities.clone();
                async move { Json(capabilities) }
            }),
        );
        spawn_app(app).await
    }

    async fn spawn_anchor_node(hash: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        spawn_capability_node(hash, official_style_capabilities()).await
    }
    #[test]
    fn mainnet_uses_only_the_canonical_block_one_hash() {
        assert_eq!(
            anchor_for_new_wallet("mainnet", None).unwrap(),
            MAINNET_BLOCK_ONE_HASH
        );
        assert_eq!(
            anchor_for_new_wallet("mainnet", Some(MAINNET_BLOCK_ONE_HASH)).unwrap(),
            MAINNET_BLOCK_ONE_HASH
        );
        assert_eq!(
            anchor_for_new_wallet("mainnet", Some(TESTNET_ANCHOR)),
            Err(AgentWalletError::InvalidNodeAnchor)
        );
    }

    #[test]
    fn testnet_requires_an_exact_operator_supplied_lowercase_hash() {
        assert_eq!(
            anchor_for_new_wallet("testnet", None),
            Err(AgentWalletError::InvalidNodeAnchor)
        );
        assert_eq!(
            anchor_for_new_wallet("testnet", Some(&TESTNET_ANCHOR.to_uppercase())),
            Err(AgentWalletError::InvalidNodeAnchor)
        );
        assert_eq!(
            anchor_for_new_wallet("testnet", Some(MAINNET_BLOCK_ONE_HASH)),
            Err(AgentWalletError::InvalidNodeAnchor)
        );
        assert_eq!(
            anchor_for_new_wallet("testnet", Some(TESTNET_ANCHOR)).unwrap(),
            TESTNET_ANCHOR
        );
    }

    #[tokio::test]
    async fn arbitrary_non_mainnet_fork_is_rejected() {
        let (node_url, task) = spawn_anchor_node(ARBITRARY_FORK).await;
        let probe = probe_agent_node(&node_url, "testnet", TESTNET_ANCHOR).await;
        assert_eq!(probe.status, AgentNodeStatus::NetworkMismatch);
        assert!(matches!(
            verified_agent_node(&node_url, "testnet", TESTNET_ANCHOR).await,
            Err(AgentWalletError::NodeNetworkMismatch)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn exact_testnet_anchor_is_verified() {
        let (node_url, task) = spawn_anchor_node(TESTNET_ANCHOR).await;
        let probe = probe_agent_node(&node_url, "testnet", TESTNET_ANCHOR).await;
        assert_eq!(probe.status, AgentNodeStatus::Verified);
        assert!(
            verified_agent_node(&node_url, "testnet", TESTNET_ANCHOR)
                .await
                .is_ok()
        );
        task.abort();
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn official_style_pilot_contract_is_accepted_and_bound_to_type2() {
        let (node_url, task) =
            spawn_capability_node(TESTNET_ANCHOR, official_style_capabilities()).await;
        let verified = verified_agent_node(&node_url, "testnet", TESTNET_ANCHOR)
            .await
            .unwrap();

        assert_eq!(verified.chain_id(), HPAY_LOCAL_PILOT_CHAIN_ID);
        assert_eq!(verified.network_kind(), HPAY_LOCAL_PILOT_NETWORK_KIND);
        assert_eq!(verified.network_instance_id().len(), 64);
        assert_eq!(verified.transaction_format_version(), 2);
        assert_eq!(verified.node_profile_commitment().len(), 64);
        assert!(
            verified
                .node_profile_commitment()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        // The mirror of the mainnet case below, and the reason the
        // `!node.funding_confirmed` term in `require_exact_node_binding` is
        // redundant on this rail: `supports_agent_local_pilot_payment` already
        // demands the flag, so a pilot node that reaches the close gate always
        // reports true, and one that reports false never gets a snapshot at
        // all. `same_chain_id_with_missing_or_unready_network_identity_is_rejected`
        // executes the false half.
        assert!(verified.snapshot().funding_confirmed);
        task.abort();
    }

    #[cfg(feature = "agent-wallet-bounded-mainnet-pilot")]
    #[tokio::test]
    async fn exact_fresh_mainnet_contract_is_accepted_and_bound_to_channel_type2() {
        let (node_url, task) =
            spawn_capability_node(MAINNET_BLOCK_ONE_HASH, mainnet_capabilities()).await;
        let verified = verified_agent_node(&node_url, "mainnet", MAINNET_BLOCK_ONE_HASH)
            .await
            .unwrap();
        assert_eq!(verified.chain_id(), 0);
        assert_eq!(verified.network_kind(), "mainnet");
        assert_eq!(verified.transaction_format_version(), 2);
        assert!(verified.snapshot().mainnet);
        // The node that opens a mainnet channel is accepted while reporting
        // `funding_confirmed: false`, which is what mainnet always reports.
        // `require_exact_node_binding` in `service/l2/verification.rs` refuses
        // exactly that node, so the open is reachable and the close is not.
        assert!(!verified.snapshot().funding_confirmed);
        task.abort();
    }

    /// The second hard equality on the mainnet path, and the one with a date on
    /// it: `validate_agent_capabilities` pins `node.version` to the literal
    /// "1.0.10". A real mainnet node that is upgraded stops matching, and every
    /// Agent Wallet path behind `verified_agent_node` closes at once - open,
    /// close, voucher and payment alike. This is not a defect today, because the
    /// owner's live node reports 1.0.10; it is asserted here so the pin is a
    /// stated decision with a known blast radius rather than an accident.
    #[cfg(feature = "agent-wallet-bounded-mainnet-pilot")]
    #[tokio::test]
    async fn a_mainnet_node_that_is_upgraded_past_the_pinned_version_is_refused() {
        let mut capabilities = mainnet_capabilities();
        capabilities["node"]["version"] = json!("1.0.11");
        let (node_url, task) = spawn_capability_node(MAINNET_BLOCK_ONE_HASH, capabilities).await;
        assert!(matches!(
            verified_agent_node(&node_url, "mainnet", MAINNET_BLOCK_ONE_HASH).await,
            Err(AgentWalletError::NodeCapabilityMismatch)
        ));
        task.abort();
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    async fn assert_capability_contract_rejected(capabilities: Value) {
        let (node_url, task) = spawn_capability_node(TESTNET_ANCHOR, capabilities).await;
        assert!(matches!(
            verified_agent_node(&node_url, "testnet", TESTNET_ANCHOR).await,
            Err(AgentWalletError::NodeCapabilityMismatch)
        ));
        task.abort();
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn missing_capability_route_rejects_legacy_type2_downgrade() {
        let (node_url, task) = spawn_app(anchor_router(TESTNET_ANCHOR)).await;
        assert!(matches!(
            verified_agent_node(&node_url, "testnet", TESTNET_ANCHOR).await,
            Err(AgentWalletError::NodeCapabilityMismatch)
        ));
        task.abort();
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn malformed_capability_response_is_rejected() {
        let app = anchor_router(TESTNET_ANCHOR).route(
            "/query/capabilities",
            get(|| async { (StatusCode::OK, "not-json") }),
        );
        let (node_url, task) = spawn_app(app).await;
        assert!(matches!(
            verified_agent_node(&node_url, "testnet", TESTNET_ANCHOR).await,
            Err(AgentWalletError::NodeCapabilityMismatch)
        ));
        task.abort();
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn unsupported_capability_api_version_is_rejected() {
        let mut capabilities = official_style_capabilities();
        capabilities["api_version"] = json!(2);
        assert_capability_contract_rejected(capabilities).await;
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn mainnet_capability_contract_is_rejected() {
        let mut capabilities = official_style_capabilities();
        capabilities["chain"]["id"] = json!(0);
        capabilities["chain"]["mainnet"] = json!(true);
        assert_capability_contract_rejected(capabilities).await;
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn wrong_non_mainnet_chain_id_is_rejected() {
        let mut capabilities = official_style_capabilities();
        capabilities["chain"]["id"] = json!(8);
        assert_capability_contract_rejected(capabilities).await;
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn same_chain_id_with_missing_or_unready_network_identity_is_rejected() {
        for field in [
            "block_1_available",
            "funding_confirmed",
            "transaction_ready",
        ] {
            let mut capabilities = official_style_capabilities();
            capabilities["network"][field] = json!(false);
            assert_capability_contract_rejected(capabilities).await;
        }
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn same_chain_id_with_different_block_one_contract_is_rejected() {
        let mut capabilities = official_style_capabilities();
        capabilities["network"]["block_1_hash"] = json!(ARBITRARY_FORK);
        assert_capability_contract_rejected(capabilities).await;
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn missing_transaction_api_contract_is_rejected() {
        let mut capabilities = official_style_capabilities();
        capabilities.as_object_mut().unwrap().remove("api");
        assert_capability_contract_rejected(capabilities).await;
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn incomplete_transaction_api_contract_is_rejected() {
        for field in [
            "balance_query",
            "transaction_submit",
            "transaction_submit_bound",
            "transaction_query",
            "reconciliation_by_tx_hash",
        ] {
            let mut capabilities = official_style_capabilities();
            capabilities["api"][field] = json!(false);
            assert_capability_contract_rejected(capabilities).await;
        }
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn capability_contract_without_type2_is_rejected() {
        let mut capabilities = official_style_capabilities();
        capabilities["transactions"]["enabled"] = json!([3]);
        assert_capability_contract_rejected(capabilities).await;
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn capability_contract_without_action1_is_rejected() {
        let mut capabilities = official_style_capabilities();
        capabilities["actions"]["registered"] = json!([]);
        capabilities["actions"]["enabled"] = json!([]);
        assert_capability_contract_rejected(capabilities).await;
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn capability_contract_without_any_channel_action_is_rejected() {
        for required in [2, 3, 14, 1041] {
            let mut capabilities = official_style_capabilities();
            capabilities["actions"]["enabled"] = json!(
                [1, 2, 3, 14, 1041]
                    .into_iter()
                    .filter(|kind| *kind != required)
                    .collect::<Vec<_>>()
            );
            assert_capability_contract_rejected(capabilities).await;
        }
    }

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    #[tokio::test]
    async fn reported_contract_cannot_claim_legacy_downgrade_source() {
        let mut capabilities = official_style_capabilities();
        capabilities["source"] = json!("legacy_type2");
        assert_capability_contract_rejected(capabilities).await;
    }
    #[tokio::test]
    async fn invalid_stored_anchor_fails_closed_without_network_io() {
        let probe = probe_agent_node("http://127.0.0.1:1", "testnet", "").await;
        assert_eq!(probe.status, AgentNodeStatus::NetworkMismatch);
        assert!(matches!(
            verified_agent_node("http://127.0.0.1:1", "testnet", "").await,
            Err(AgentWalletError::NodeNetworkMismatch)
        ));
    }
}
