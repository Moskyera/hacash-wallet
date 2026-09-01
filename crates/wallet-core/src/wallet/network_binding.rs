//! Fail-closed binding between wallet network settings and the selected node.

use std::time::{Duration, Instant};

use crate::error::{WalletError, WalletResult};
use crate::node_capabilities::{CapabilitySource, NodeChain};
use crate::node_discovery::{MAINNET_BLOCK_ONE_HASH, probe_node};
use crate::settings::{validate_l1_payment_node_url, validate_signing_node_url};
use crate::tx_binding::CanonicalTransaction;

use super::WalletService;

const NETWORK_BINDING_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub(super) struct CachedNetworkBinding {
    node_url: String,
    network_mode: String,
    verified_at: Instant,
    chain_id: Option<u32>,
    enabled_transactions: Vec<u8>,
}

impl CachedNetworkBinding {
    fn is_fresh_for(&self, node_url: &str, network_mode: &str) -> bool {
        self.node_url == node_url
            && self.network_mode == network_mode
            && self.verified_at.elapsed() <= NETWORK_BINDING_TTL
    }

    fn require_transaction(&self, tx_type: u8) -> WalletResult<Option<u32>> {
        if self.enabled_transactions.binary_search(&tx_type).is_err() {
            return Err(WalletError::Policy(format!(
                "node_network_transaction_unsupported: selected node does not enable Type {tx_type}"
            )));
        }
        Ok(self.chain_id)
    }
}

fn validate_reported_network(network_mode: &str, chain: &NodeChain) -> WalletResult<()> {
    let matched = match network_mode {
        "mainnet" => chain.mainnet && chain.id == 0,
        "testnet" => !chain.mainnet && chain.id != 0,
        _ => false,
    };
    if !matched {
        return Err(WalletError::Policy(format!(
            "node_network_mismatch: wallet is configured for {network_mode}, node reports chain id {} ({})",
            chain.id,
            if chain.mainnet { "mainnet" } else { "testnet" }
        )));
    }
    Ok(())
}

/// A node that reports a block 1 hash must report the network's own.
///
/// Reporting nothing is still allowed, because older nodes carry no such
/// field, and that case is covered by the anchor probe below. What this closes
/// is a node that names a block 1 and names a fabricated one: the capability
/// contract only ever checked that the hash and the instance id agreed with
/// each other, which is a property a forger controls both sides of.
fn require_reported_block_one(network_mode: &str, reported: Option<&str>) -> WalletResult<()> {
    let Some(reported) = reported else {
        return Ok(());
    };
    let is_mainnet_anchor = reported.eq_ignore_ascii_case(MAINNET_BLOCK_ONE_HASH);
    if is_mainnet_anchor == (network_mode == "mainnet") {
        return Ok(());
    }
    Err(WalletError::Policy(format!(
        "node_network_mismatch: wallet is configured for {network_mode}, node reports block 1 as {reported}"
    )))
}

impl WalletService {
    /// Refuse to let a remote plaintext endpoint influence online signing.
    /// Read-only balance and discovery requests may still use the legacy
    /// official HTTP API, but mainnet key use requires HTTPS or loopback.
    ///
    /// This is the strict rule and it does not move. Fast Pay channel opens
    /// and closes, dapp signing and the L2 rail all come through here.
    pub(crate) fn require_online_signing_transport(&self) -> WalletResult<()> {
        validate_signing_node_url(self.node.base_url(), &self.network_mode).map(|_| ())
    }

    /// The same rule for an ordinary on-chain payment, plus the one named
    /// exception for the official endpoint. See
    /// [`crate::settings::validate_l1_payment_node_url`].
    pub(crate) fn require_l1_payment_transport(&self) -> WalletResult<()> {
        validate_l1_payment_node_url(self.node.base_url(), &self.network_mode).map(|_| ())
    }

    /// True when this payment will cross the official plaintext connection.
    pub(crate) fn l1_payment_is_official_plaintext(&self) -> bool {
        crate::settings::l1_payment_uses_official_plaintext(
            self.node.base_url(),
            &self.network_mode,
        )
    }

    /// The disclosure to print beside this payment, or nothing to print.
    pub fn l1_payment_transport_disclosure(&self) -> Option<&'static str> {
        self.l1_payment_is_official_plaintext()
            .then_some(crate::settings::OFFICIAL_NODE_PLAINTEXT_DISCLOSURE)
    }

    pub(crate) fn invalidate_network_binding(&mut self) {
        self.network_binding = None;
    }

    async fn refresh_network_binding(&self) -> WalletResult<CachedNetworkBinding> {
        let node_url = self.node.base_url().to_owned();
        let network_mode = self.network_mode.clone();
        if !matches!(network_mode.as_str(), "mainnet" | "testnet") {
            return Err(WalletError::Policy(
                "node_network_mode_invalid: wallet network mode is not mainnet or testnet".into(),
            ));
        }

        let capabilities = self.node.capabilities().await?;
        let (chain_id, enabled_transactions) = match capabilities.source {
            CapabilitySource::Reported => {
                validate_reported_network(&network_mode, &capabilities.chain)?;
                (
                    Some(capabilities.chain.id),
                    capabilities.transactions.enabled.clone(),
                )
            }
            CapabilitySource::LegacyType2 => (None, vec![2]),
        };

        // A node that names block 1 must name the right one. This is cheap,
        // it runs before the probe, and it costs no extra request: the answer
        // is already in the capability document. The instance-id check next to
        // it only proves the node agrees with itself, which a forger arranges
        // for free.
        require_reported_block_one(&network_mode, capabilities.network.block_1_hash.as_deref())?;

        // EVERY remote node must match the canonical block-one anchor, the
        // official one included.
        //
        // This used to read `if !is_official_node_url(&node_url) ||
        // capabilities.source == CapabilitySource::LegacyType2`, and that was
        // the hole. Two things were wrong with it. The name in a URL string is
        // not a proof of anything on a plaintext connection, so anyone on the
        // path who could answer as that name got the one check that stops
        // chain substitution turned off for them. Worse, the second clause let
        // the attacker pick: answer 404 on /query/capabilities and the probe
        // fires, answer with a modern capability payload and it does not. A
        // check disabled on the say-so of the party it defends against is not
        // a check. Measured: the same forged block 1 on the same server was
        // refused when reached as http://127.0.0.1:19080 and signed when
        // reached by the official name, with the URL string the only
        // difference.
        //
        // The cost is two HTTP requests per binding refresh, at most one per
        // 30 seconds, against an endpoint discovery already probes this way.
        let status = probe_node(&node_url, &network_mode).await;
        if !status.online {
            return Err(WalletError::Node(format!(
                "node network binding failed: {}",
                status.error.unwrap_or_else(|| "node is offline".into())
            )));
        }
        if !status.network_match {
            return Err(WalletError::Policy(format!(
                "node_network_mismatch: {}",
                status
                    .error
                    .unwrap_or_else(|| "node does not match the configured network".into())
            )));
        }

        Ok(CachedNetworkBinding {
            node_url,
            network_mode,
            verified_at: Instant::now(),
            chain_id,
            enabled_transactions,
        })
    }

    async fn ensure_node_network_for_type(&mut self, tx_type: u8) -> WalletResult<Option<u32>> {
        if !matches!(tx_type, 2..=4) {
            return Err(WalletError::Policy(format!(
                "node_network_transaction_unsupported: wallet will not sign Type {tx_type}"
            )));
        }
        let node_url = self.node.base_url();
        if let Some(binding) = self.network_binding.as_ref()
            && binding.is_fresh_for(node_url, &self.network_mode)
        {
            return binding.require_transaction(tx_type);
        }
        let binding = self.refresh_network_binding().await?;
        let chain_id = binding.require_transaction(tx_type)?;
        self.network_binding = Some(binding);
        Ok(chain_id)
    }

    /// Bind a transaction body to the network it will be broadcast on.
    ///
    /// What binds it, and it is worth being exact because it is easy to
    /// overstate: a Type 3 carries a ChainAllow guard and the chain id is
    /// checked inside the signed bytes. A Type 2, which is what an ordinary
    /// HAC payment is, carries no such field, so nothing in the signed bytes
    /// names a chain. For a Type 2 the entire chain identity is the node's,
    /// and the only thing that makes the node's identity worth anything is the
    /// block 1 anchor proved in `refresh_network_binding` above. That is why
    /// the probe there runs for every node with no exception: for the payment
    /// a person actually makes, it is not one defence among several, it is the
    /// defence.
    pub(crate) async fn ensure_transaction_network_binding(
        &mut self,
        body_hex: &str,
    ) -> WalletResult<CanonicalTransaction> {
        let canonical = crate::tx_binding::decode_transaction(body_hex)?;
        let chain_id = self.ensure_node_network_for_type(canonical.tx_type).await?;
        if canonical.tx_type == 3 {
            let chain_id = chain_id.ok_or_else(|| {
                WalletError::Policy(
                    "node_network_type3_unbound: Type 3 requires a reported node chain id".into(),
                )
            })?;
            crate::tx_binding::inspect_transaction(body_hex, Some(chain_id))?;
        }
        Ok(canonical)
    }

    pub(crate) async fn sign_tx_for_network(&mut self, body_hex: &str) -> WalletResult<String> {
        self.require_online_signing_transport()?;
        self.ensure_transaction_network_binding(body_hex).await?;
        self.sign_tx_hex(body_hex)
    }

    /// The same, for an ordinary on-chain payment, under the payment rule.
    pub(crate) async fn sign_l1_payment_for_network(
        &mut self,
        body_hex: &str,
    ) -> WalletResult<String> {
        self.require_l1_payment_transport()?;
        self.ensure_transaction_network_binding(body_hex).await?;
        self.sign_tx_hex(body_hex)
    }
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, routing::get};

    use super::*;
    use crate::node_capabilities::{CapabilitySource, NodeCapabilities};
    use crate::test_support::IsolatedWalletData;

    fn reported_capabilities(mainnet: bool) -> NodeCapabilities {
        let mut capabilities = NodeCapabilities::legacy_type2("mock");
        capabilities.source = CapabilitySource::Reported;
        capabilities.chain.id = if mainnet { 0 } else { 1 };
        capabilities.chain.mainnet = mainnet;
        capabilities
    }

    async fn spawn_capability_node(
        capabilities: NodeCapabilities,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/query/capabilities",
            get(move || {
                let capabilities = capabilities.clone();
                async move { Json(capabilities) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    /// A node that answers everything the binding path asks, so a test can
    /// change one answer at a time. `spawn_capability_node` above serves only
    /// `/query/capabilities`, which was enough while the anchor probe was
    /// skipped on some paths and is not enough now that it never is.
    async fn spawn_forging_node(
        capabilities: NodeCapabilities,
        block_one_hash: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/query/capabilities",
                get(move || {
                    let capabilities = capabilities.clone();
                    async move { Json(capabilities) }
                }),
            )
            .route(
                "/query/latest",
                get(|| async {
                    Json(serde_json::json!({ "ret": 0, "height": 800000, "diamond": 5 }))
                }),
            )
            .route(
                "/query/block/intro",
                get(move || async move {
                    Json(serde_json::json!({ "ret": 0, "height": 1, "hash": block_one_hash }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), server)
    }

    #[tokio::test]
    async fn custom_node_network_mismatch_fails_closed_in_both_directions() {
        let _wallet_data = IsolatedWalletData::new();

        let (testnet_node, testnet_server) =
            spawn_capability_node(reported_capabilities(false)).await;
        let mut mainnet_wallet = WalletService::new(Some(testnet_node), None).unwrap();
        mainnet_wallet.network_mode = "mainnet".into();
        let error = mainnet_wallet
            .ensure_node_network_for_type(2)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("node_network_mismatch"));
        testnet_server.abort();

        let (mainnet_node, mainnet_server) =
            spawn_capability_node(reported_capabilities(true)).await;
        let mut testnet_wallet = WalletService::new(Some(mainnet_node), None).unwrap();
        testnet_wallet.network_mode = "testnet".into();
        let error = testnet_wallet
            .ensure_node_network_for_type(2)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("node_network_mismatch"));
        mainnet_server.abort();
    }

    #[test]
    fn reported_chain_contract_is_exact_for_mainnet_and_testnet() {
        let mainnet = reported_capabilities(true);
        let testnet = reported_capabilities(false);
        assert!(validate_reported_network("mainnet", &mainnet.chain).is_ok());
        assert!(validate_reported_network("testnet", &testnet.chain).is_ok());
        assert!(validate_reported_network("mainnet", &testnet.chain).is_err());
        assert!(validate_reported_network("testnet", &mainnet.chain).is_err());
    }

    #[test]
    fn online_signing_transport_rejects_remote_http_mainnet() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet =
            WalletService::new(Some(crate::settings::DEFAULT_NODE_URL.into()), None).unwrap();
        wallet.network_mode = "mainnet".into();
        let error = wallet.require_online_signing_transport().unwrap_err();
        assert!(error.to_string().contains("mainnet signing requires HTTPS"));

        let mut local = WalletService::new(Some("http://127.0.0.1:8080".into()), None).unwrap();
        local.network_mode = "mainnet".into();
        local.require_online_signing_transport().unwrap();

        wallet.network_mode = "testnet".into();
        wallet.require_online_signing_transport().unwrap();
    }

    /// The refusal must arrive BEFORE the review screen and the fingerprint
    /// prompt, not after.
    ///
    /// On a plain install - mainnet, `http://nodeapi.hacash.org` - the wallet
    /// could not sign anything, and only said so from `execute_prepared_*`,
    /// which runs after `authorizePreparedOperation` has already taken the
    /// biometric or passphrase. A person authenticated a spend and was then
    /// told the transport had never been eligible.
    ///
    /// The wallet here is LOCKED and has no address, so this also pins the
    /// ordering: the transport refusal precedes even `require_address`, which
    /// is the only way it can precede the ceremony.
    #[tokio::test]
    async fn prepare_refuses_an_ineligible_transport_before_any_ceremony() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet =
            WalletService::new(Some(crate::settings::DEFAULT_NODE_URL.into()), None).unwrap();
        wallet.network_mode = "mainnet".into();
        assert!(wallet.unlocked.is_none(), "the wallet must still be locked");

        // CHANNEL OPEN NO LONGER REACHES THE TRANSPORT CHECK ON MAINNET, and
        // this test's property is stronger for it, not weaker.
        //
        // A mainnet channel open is now refused outright, ahead of everything
        // else on the path, because this wallet has no way to leave a channel:
        // its three close paths all end at the Hub countersigning, and the
        // close voucher was only ever built for the Agent Wallet. So the
        // transport refusal is shadowed here by a stricter one.
        //
        // The ordering that matters is unchanged and is asserted below: the
        // wallet is LOCKED, so a refusal arriving at all proves it precedes
        // `require_address` and therefore the review screen and the
        // fingerprint prompt. What a person is told first is the fact they
        // cannot fix. Sending them off to configure HTTPS and only then
        // telling them the channel has no exit would be work that changes
        // nothing.
        //
        // The transport check itself is untouched and still first for every
        // other operation, which the close and send cases below still pin.
        let open = wallet
            .prepare_channel_open("1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW", "7", "0")
            .await
            .unwrap_err();
        assert!(
            open.to_string().contains("no way out of one"),
            "channel open must refuse at prepare, before the ceremony, with the \
             fact a person cannot fix, got: {open}"
        );

        let close = wallet.prepare_channel_close().await.unwrap_err();
        assert!(
            close.to_string().contains("mainnet signing requires HTTPS"),
            "channel close must refuse at prepare, got: {close}"
        );

        // An ordinary payment is the one thing that is NOT refused here any
        // more. The wallet ships pointed at this node, and a wallet whose own
        // default fails its own gate cannot send out of the box. It gets past
        // the transport check and stops at the locked keystore, which is the
        // next thing wrong with it and nothing to do with transport. No
        // request leaves this process: `require_address` runs before the first
        // await on the node.
        let send = wallet
            .prepare_send_hac(
                "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
                1.0,
                crate::send_options::SendOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(
            !send.to_string().contains("mainnet signing requires HTTPS"),
            "the official node must pass the payment transport check, got: {send}"
        );
        assert!(
            wallet.l1_payment_is_official_plaintext(),
            "and the payment must be marked as the plaintext one, so it is disclosed"
        );

        // The same wallet on a node on this same machine is NOT refused by
        // this check - it gets past it and fails later for want of a key. The
        // safest configuration must not be the one turned away.
        let mut local = WalletService::new(Some("http://127.0.0.1:8080".into()), None).unwrap();
        local.network_mode = "mainnet".into();
        let local_error = local.prepare_channel_close().await.unwrap_err().to_string();
        assert!(
            !local_error.contains("mainnet signing requires HTTPS"),
            "a loopback node must pass the transport check, got: {local_error}"
        );
    }

    /// THE FINDING THIS CHANGE EXISTS FOR.
    ///
    /// `refresh_network_binding` used to skip the block 1 anchor probe when
    /// the configured URL was the official one and the node answered
    /// `/query/capabilities` in the modern shape. Both halves of that were
    /// wrong. A hostname on a plaintext connection proves nothing about who
    /// answered, and the shape of the capability answer is the attacker's
    /// choice, so the check that stops chain substitution could be switched
    /// off by the party it defends against: answer 404 and the probe fires,
    /// answer a modern payload and it does not.
    ///
    /// A forged block 1 with a modern capability payload is now refused, which
    /// is the combination that used to pass. The capability document is told
    /// consistently here (the network object names the forgery and the
    /// instance id is recomputed over it), because self-consistency was the
    /// only thing the old code checked and it costs a forger nothing.
    #[tokio::test]
    async fn a_forged_block_one_is_refused_even_when_the_node_answers_as_a_modern_node() {
        let _wallet_data = IsolatedWalletData::new();
        const FORGERY: &str = "dead1111beef2222dead1111beef2222dead1111beef2222dead1111beef2222";

        let mut capabilities = reported_capabilities(true);
        capabilities.network.kind = "mainnet".into();
        capabilities.network.node_profile_id = "hacash-mainnet".into();
        capabilities.network.current_height = capabilities.chain.height;
        capabilities.network.transaction_format_version = 2;
        capabilities.network.block_1_available = true;
        capabilities.network.block_1_hash = Some(FORGERY.into());
        capabilities.network.instance_id = Some(crate::node_capabilities::network_instance_id(
            &capabilities.network.kind,
            capabilities.chain.id,
            capabilities.chain.mainnet,
            FORGERY,
            &capabilities.network.node_profile_id,
            capabilities.network.transaction_format_version,
        ));

        let (node_url, server) = spawn_forging_node(capabilities, FORGERY).await;
        let mut wallet = WalletService::new(Some(node_url), None).unwrap();
        wallet.network_mode = "mainnet".into();
        let error = wallet
            .ensure_node_network_for_type(2)
            .await
            .expect_err("a fabricated chain must never bind");
        assert!(
            error.to_string().contains("node_network_mismatch"),
            "the refusal must name the network, got: {error}"
        );
        server.abort();
    }

    /// The same node, telling the truth, still binds. A check that refuses
    /// everything is not a check, it is an outage.
    #[tokio::test]
    async fn the_real_anchor_still_binds_on_the_same_path() {
        let _wallet_data = IsolatedWalletData::new();
        let mut capabilities = reported_capabilities(true);
        capabilities.transactions.enabled = vec![2];
        let (node_url, server) = spawn_forging_node(capabilities, MAINNET_BLOCK_ONE_HASH).await;
        let mut wallet = WalletService::new(Some(node_url), None).unwrap();
        wallet.network_mode = "mainnet".into();
        wallet
            .ensure_node_network_for_type(2)
            .await
            .expect("a node on the real chain must bind");
        server.abort();
    }

    /// A node may omit block 1 (older builds do). It may not name the wrong
    /// one. This half of the fix runs before any request and costs nothing.
    #[test]
    fn a_named_block_one_must_be_the_networks_own() {
        assert!(require_reported_block_one("mainnet", None).is_ok());
        assert!(require_reported_block_one("testnet", None).is_ok());
        assert!(require_reported_block_one("mainnet", Some(MAINNET_BLOCK_ONE_HASH)).is_ok());
        assert!(
            require_reported_block_one("mainnet", Some(&MAINNET_BLOCK_ONE_HASH.to_uppercase()))
                .is_ok(),
            "hex case is not identity"
        );
        assert!(require_reported_block_one("testnet", Some(MAINNET_BLOCK_ONE_HASH)).is_err());
        assert!(
            require_reported_block_one(
                "mainnet",
                Some("dead1111beef2222dead1111beef2222dead1111beef2222dead1111beef2222")
            )
            .is_err()
        );
    }

    /// No branch in this file may turn the anchor probe off for a named host.
    ///
    /// This reads the file it lives in, which is unusual, and it is deliberate.
    /// The bug was not a wrong value, it was the existence of a branch keyed on
    /// a URL string, and the only thing that pins "there is no such branch" is
    /// the absence of the name. A behavioural test cannot see the difference
    /// without overriding DNS, because the two paths differ only in the host
    /// that was dialled.
    #[test]
    fn nothing_in_the_binding_path_is_keyed_on_the_node_being_official() {
        const SOURCE: &str = include_str!("network_binding.rs");
        let refresh = SOURCE
            .split_once("async fn refresh_network_binding")
            .expect("the function is still here")
            .1
            .split_once(
                "
    async fn ensure_node_network_for_type",
            )
            .expect("and still ends where it did")
            .0;
        // Comments are stripped: the removed branch is quoted verbatim in one
        // just above the probe, and a test that cannot tell code from the
        // description of code would forbid explaining the bug.
        let code: String = refresh
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("is_official_node_url"),
            "the anchor probe must not be skipped for a host name"
        );
        assert!(
            code.contains("probe_node(&node_url, &network_mode).await"),
            "and the probe must still be here at all"
        );
    }
}
