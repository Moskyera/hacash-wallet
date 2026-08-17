use serde::{Deserialize, Serialize};

use crate::account::WalletAccount;
use crate::bills::BillStore;
use crate::channel::{CHANNEL_STATUS_OPENING, ChannelInfo, query_channel};
use crate::error::{WalletError, WalletResult};
use crate::hip23::format_mei_for_node;
use crate::l1_fee::{L1FeeTierQuote, estimate_hac_l1_fee_tiers, format_l1_fee_label};
use crate::l2_hub::{FastPayExecution, FastPayRequest, L2HubClient};
use crate::node::NodeClient;
use crate::send_options::{
    SendFeeBreakdown, SendOptions, apply_service_fee, fast_pay_fee_breakdown,
};
use crate::settings::WalletSettings;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentRail {
    L2Fast,
    L1OnChain,
    QuantumType4,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentPlan {
    pub rail: PaymentRail,
    pub summary: String,
    pub estimated_fee: String,
    pub channel_id: Option<String>,
    /// Short label for UI, e.g. "Instant (Fast Pay)".
    pub rail_label: String,
    /// One-line explanation shown under the label.
    pub rail_detail: String,
    pub fee_breakdown: SendFeeBreakdown,
    #[serde(default)]
    pub l1_fee_tiers: Vec<L1FeeTierQuote>,
    /// Why this send is falling back to a paid blockchain transaction, when the
    /// wallet had a Fast Pay route set up and declined to use it.
    ///
    /// The fallback itself is right - refusing to pay at all because the Hub is
    /// unavailable would be worse. What was wrong was that it happened in
    /// silence. A user who had ticked the mainnet pilot consent box, opened a
    /// channel and funded it would tap Send and simply be charged a fee, with
    /// the wallet holding a precise reason it never showed anyone. `None` means
    /// Fast Pay was never in play for this send (no provider, no channel), and
    /// there is nothing to explain.
    pub fast_pay_declined: Option<String>,
}

/// The Fast Pay routing decision for one send.
enum L2Routing {
    Planned(Box<PaymentPlan>),
    /// Fast Pay is not carrying this send, with the reason to show the user
    /// when there is one worth showing.
    Declined(Option<String>),
}

impl L2Routing {
    fn declined(reason: impl Into<String>) -> Self {
        Self::Declined(Some(reason.into()))
    }
}

pub struct PaymentRouter {
    node: NodeClient,
    settings: WalletSettings,
    bills: BillStore,
}

impl PaymentRouter {
    pub fn new(node: NodeClient, settings: WalletSettings, bills: BillStore) -> Self {
        Self {
            node,
            settings,
            bills,
        }
    }

    pub fn has_l2_hub(&self) -> bool {
        self.settings.l2_hub_url.is_some()
    }

    pub fn settings(&self) -> &WalletSettings {
        &self.settings
    }

    pub fn bills(&self) -> &BillStore {
        &self.bills
    }

    pub fn replace_bills(&mut self, bills: BillStore) {
        self.bills = bills;
    }
    pub fn update_settings(&mut self, node: NodeClient, settings: WalletSettings) {
        debug_assert_eq!(settings.node_url, node.base_url());
        self.node = node;
        self.settings = settings;
    }

    pub async fn plan_send(
        &self,
        from: &str,
        to: &str,
        amount_mei: f64,
        options: &SendOptions,
    ) -> WalletResult<PaymentPlan> {
        crate::hip23::validate_hac_amount_mei(amount_mei)?;
        options.validate()?;
        crate::address::require_address_for_network(from, &self.settings.network_mode)?;
        crate::address::require_address_for_network(to, &self.settings.network_mode)?;
        let mut fast_pay_declined = None;
        if !options.force_l1 {
            match self.try_l2_plan(from, to, amount_mei).await? {
                L2Routing::Planned(plan) => return Ok(*plan),
                L2Routing::Declined(reason) => fast_pay_declined = reason,
            }
        }
        let _ = self.node.balance_mei(from).await?;
        let amount_wire = format_mei_for_node(amount_mei);
        let tier_set = estimate_hac_l1_fee_tiers(
            &self.node,
            from,
            to,
            &amount_wire,
            amount_mei,
            options.l1_fee_speed,
        )
        .await?;
        let fee_est = tier_set.selected;
        let mut fee_breakdown = SendFeeBreakdown {
            payer_debit_mei: amount_mei + fee_est.fee_mei,
            recipient_credit_mei: amount_mei,
            hub_fee_mei: None,
            hub_fee_payer: options.hub_fee_payer,
            l1_fee_wire: Some(fee_est.fee_wire.clone()),
            l1_fee_mei: Some(fee_est.fee_mei),
            service_fee_mei: None,
            service_fee_rate: None,
            service_fee_treasury: None,
        };
        apply_service_fee(&mut fee_breakdown, amount_mei);
        Ok(PaymentPlan {
            rail: PaymentRail::L1OnChain,
            summary: format!("Send {amount_mei} HAC to {to}"),
            estimated_fee: format_l1_fee_label(&fee_est),
            channel_id: None,
            rail_label: crate::fast_pay::rail_label(PaymentRail::L1OnChain).into(),
            rail_detail: crate::fast_pay::rail_detail(PaymentRail::L1OnChain).into(),
            fee_breakdown,
            l1_fee_tiers: tier_set.tiers,
            fast_pay_declined,
        })
    }

    async fn try_l2_plan(&self, from: &str, to: &str, amount_mei: f64) -> WalletResult<L2Routing> {
        // Read the wallet's own Fast Pay configuration first. Everything below
        // this point is a reason the user deserves to see; everything above it
        // is "the user never set Fast Pay up", which is not a fallback to
        // explain.
        let hub_url = match &self.settings.l2_hub_url {
            Some(u) => u.clone(),
            None => return Ok(L2Routing::Declined(None)),
        };
        let channel_id = match &self.settings.channel_id_hex {
            Some(id) => id.clone(),
            None => return Ok(L2Routing::Declined(None)),
        };

        let from_address = crate::address::parse_address(from, &self.settings.network_mode)?;
        let to_address = crate::address::parse_address(to, &self.settings.network_mode)?;
        if !from_address.fast_pay_eligible || !to_address.fast_pay_eligible {
            // Fast Pay v0 is passive-only. Contracts, P2SH and quantum addresses stay on L1.
            return Ok(L2Routing::declined(
                "Fast Pay carries only plain v0 addresses, and this send uses a contract, \
                 script or quantum address.",
            ));
        }

        let hub = L2HubClient::new_for_wallet_policy(
            hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        let health = match hub.health().await {
            Ok(health) => health,
            Err(_) => {
                return Ok(L2Routing::declined(
                    "Your Fast Pay provider could not be reached.",
                ));
            }
        };
        if !health.ok {
            return Ok(L2Routing::declined(
                "Your Fast Pay provider reports it is not healthy.",
            ));
        }
        if health.version < 3
            || !health.settlement_ready
            || !crate::l2_hub::hub_fee_is_zero(&health)
        {
            // Fast Pay is fee-free and must produce a dispute-ready settlement bill.
            return Ok(L2Routing::declined(
                "Your Fast Pay provider cannot produce a fee-free, dispute-ready settlement bill.",
            ));
        }
        if self.settings.network_mode == "mainnet" {
            let amount_wire = format_mei_for_node(amount_mei);
            // The reason travels with the fallback. This gate refusing used to
            // be the whole of what the user was told - which was nothing.
            if let Err(error) = hub.require_mainnet_payment_ready(Some(&amount_wire)).await {
                return Ok(L2Routing::declined(crate::fast_pay::user_facing_reason(
                    &error,
                )));
            }
        }
        let same_channel_payee = health.hub_address.as_deref() == Some(to);
        if !same_channel_payee && !health.cross_channel_ready {
            return Ok(L2Routing::declined(
                "Your Fast Pay provider cannot route to this recipient.",
            ));
        }

        let channel = query_channel(&self.node, &channel_id).await?;
        if !channel_is_ready(&channel, from) {
            return Ok(L2Routing::declined(
                "Your Fast Pay channel is not open and usable for this sender.",
            ));
        }

        let fee_breakdown = fast_pay_fee_breakdown(amount_mei)?;
        Ok(L2Routing::Planned(Box::new(PaymentPlan {
            rail: PaymentRail::L2Fast,
            summary: format!("Send {amount_mei} HAC to {to}"),
            estimated_fee: "0 HAC".into(),
            channel_id: Some(channel_id),
            rail_label: crate::fast_pay::rail_label(PaymentRail::L2Fast).into(),
            rail_detail: crate::fast_pay::rail_detail(PaymentRail::L2Fast).into(),
            fee_breakdown,
            l1_fee_tiers: Vec::new(),
            fast_pay_declined: None,
        })))
    }

    pub async fn execute_l2(
        &mut self,
        from: &str,
        to: &str,
        amount_wire: &str,
        payer_account: &WalletAccount,
    ) -> WalletResult<FastPayExecution> {
        let payer = crate::address::require_address_for_network(from, &self.settings.network_mode)?;
        let payee = crate::address::require_address_for_network(to, &self.settings.network_mode)?;
        if !payer.fast_pay_eligible || !payee.fast_pay_eligible {
            return Err(WalletError::L2(
                "Fast Pay v0 supports only passive v0 sender and recipient addresses".into(),
            ));
        }

        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("L2 hub not configured".into()))?;
        let channel_id = self
            .settings
            .channel_id_hex
            .clone()
            .ok_or_else(|| WalletError::L2("channel not configured".into()))?;

        let hub = L2HubClient::new_for_wallet_policy(
            hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        let health = hub.health().await?;
        let hub_address = health.hub_address.clone().ok_or_else(|| {
            WalletError::L2("Fast Pay provider did not publish its hub address".into())
        })?;
        let same_channel_payee = hub_address == to;
        if !health.ok
            || health.version < 3
            || !health.settlement_ready
            || !crate::l2_hub::hub_fee_is_zero(&health)
            || (!same_channel_payee && !health.cross_channel_ready)
        {
            return Err(WalletError::L2(
                "Fast Pay provider is not ready for a safe, fee-free settlement to this recipient"
                    .into(),
            ));
        }
        if payer_account.address() != from {
            return Err(WalletError::L2(format!(
                "payer account {} does not match from {}",
                payer_account.address(),
                from
            )));
        }
        if self.settings.network_mode == "mainnet" {
            // Early user-facing failure. execute_and_store_bill repeats this
            // check at the exact signing boundary to close preview races.
            hub.require_mainnet_payment_ready(Some(amount_wire)).await?;
        }
        let payer_channel = query_channel(&self.node, &channel_id).await?;
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(amount_wire)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let mut safety = crate::l2_safety::ClientL2Safety::open_for_network(
            payer_account,
            &self.settings.network_mode,
            &hub_address,
            &channel_id,
        )?;
        let operation = safety.begin_or_resume(
            from,
            to,
            amount_wire,
            amount.as_millimeis(),
            payer_channel.reuse_version,
        )?;
        let req = FastPayRequest {
            operation_id: operation.operation_id,
            idempotency_key: operation.idempotency_key,
            payer: from.to_owned(),
            payee: to.to_owned(),
            amount: amount_wire.to_owned(),
            channel_id,
            fee_payer: Some("sender".to_owned()),
        };
        hub.execute_and_store_bill(
            &req,
            &mut self.bills,
            &mut safety,
            payer_account,
            &payer_channel,
            &hub_address,
        )
        .await
    }
}

fn channel_is_ready(channel: &ChannelInfo, user_address: &str) -> bool {
    channel.status == CHANNEL_STATUS_OPENING
        && (channel.user_is_left(user_address) || channel.user_is_right(user_address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unreachable_hub_is_only_a_pre_sign_l1_fallback() {
        let payer = WalletAccount::create("payment-router-offline-hub-payer").unwrap();
        let payee = WalletAccount::create("payment-router-offline-hub-payee").unwrap();
        let settings = WalletSettings {
            l2_hub_url: Some("http://127.0.0.1:1".into()),
            channel_id_hex: Some("00112233445566778899aabbccddeeff".into()),
            ..WalletSettings::default()
        };
        let router = PaymentRouter::new(
            NodeClient::new("http://127.0.0.1:2").unwrap(),
            settings,
            BillStore::default(),
        );

        let routing = router
            .try_l2_plan(&payer.address(), &payee.address(), 1.0)
            .await
            .unwrap();
        let L2Routing::Declined(reason) = routing else {
            panic!("an unreachable hub must not produce a Fast Pay plan");
        };
        // Falling back is right; falling back in silence is not.
        assert_eq!(
            reason.as_deref(),
            Some("Your Fast Pay provider could not be reached."),
            "the L1 fallback must carry the reason Fast Pay was not used"
        );
    }

    /// The exact `/v1/readiness/mainnet` bytes a `mainnet-bounded-pilot` Hub
    /// serves when it is pointed at the real Hacash mainnet fullnode.
    ///
    /// Captured with `curl` from a Hub built from this tree against the live
    /// Hacash mainnet node on `http://127.0.0.1:8080` (chain id 0, height
    /// 774025, `block_1_hash` 001e231c...db56), with no rollback witness
    /// configured. It is the served response, byte for byte, not a Rust struct
    /// re-serialised: only the four clock-dependent numbers are re-stamped,
    /// because the wallet correctly refuses a stale snapshot.
    ///
    /// Every honest `false` that Hub publishes survives here -
    /// `trustless_finality`, `unilateral_l1_enforceable`,
    /// `channel_unilateral_exit`, `deployment_verified` - so this fixture can
    /// never pass by being greener than the Hub it came from.
    const LIVE_BOUNDED_PILOT_READINESS_BODY: &str = r#"{"schema":"hpay-fast-pay-mainnet-readiness/1","evaluated_unix":$EVALUATED$,"valid_until_unix":$VALID_UNTIL$,"profile":"mainnet-bounded-pilot","payments_enabled":true,"close_enabled":true,"mainnet_detected":true,"fullnode_capabilities":{"observed_unix":$EVALUATED$,"api_version":1,"chain_id":0,"height":774025,"next_height":774026,"mainnet":true,"network_kind":"mainnet","node_profile_id":"hacash-mainnet","block_1_hash":"001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56","network_instance_id":"5a310ec0f487a37156a182c67778495f66e5c7502f9871829edc790023b123cf","transaction_format_version":2,"tip_timestamp_unix":$TIP$,"tip_age_seconds":$TIP_AGE$,"registered_actions":[1,2,3,4,5,6,7,8,10,11,12,13,14,16,17,18,19,22,25,26,32,33,34,35,36,40,41,44,46,1025,1026,1041,1042,1043,1044,1537,1538,1545,1553,1554,1555,1556,1793,1794,1795],"enabled_actions":[1,2,3,4,5,6,7,8,10,11,12,13,14,16,17,18,19,22,25,26,32,33,34,35,36,40,41,44,46,1025,1026,1041,1042,1043,1044,1537,1538,1545,1553,1554,1555,1556,1793,1794,1795],"enabled_transactions":[0,1,2,3],"transaction_submit_bound":true,"hpay_channel_registry_query":false,"channel_unilateral_exit":false,"channel_unilateral_exit_evidence":{"schema":"hpay-hvm-channel-exit-evidence/1","manifest_valid":true,"contract_name":"HPAYChannelExitV1","protocol_domain":"HPAY/HVM-CHANNEL/V1","settlement_profile":"hpay-hvm-channel-v1","source_sha256":"c0a430eb9769d1d506641c379bb8aaf708c7bac7d03694b60a4be03fd001dd06","bytecode_sha3":"11a2efc27a0c951bbc6977186eb58bd076dd331a785f3c57242cf54a72238349","required_action_kinds":[40,41,44],"funding_model":{"left_deposit":"positive","right_hub_deposit":"exactly_zero"},"storage_key_count":18,"must_renew_every_storage_key":true,"deployment":{"enabled":false,"contract_address":null,"deployment_tx_hash":null,"deployment_height":null,"independently_verified":false},"on_chain_verification":{"observed_height":null,"confirmed_tx_height":null,"deployment_tx_confirmed":false,"contract_code_sha3":null,"contract_code_matches":false},"deployment_verified":false}},"rollback_anchor":null,"max_payment_hac_zhu":1000000,"max_channel_funding_hac_zhu":10000000,"allowlist_configured":true,"aggregate_tvl_within_limit":true,"max_aggregate_tvl_hac_zhu":100000000,"max_payment_satoshi":0,"wallet_fee_hac":"0","trustless_finality":false,"unilateral_l1_enforceable":false,"trusted_bounded_pilot":true,"settlement_model":"official Hacash ChannelPay bills with hub-coordinated bounded mainnet pilot","blockers":[],"close_blockers":[],"limitations":["settled does not mean unilateral L1 finality","the active Hacash mainnet exposes cooperative original-funding close action 3","pilot exposure must remain inside the configured payment and channel caps","new channels require an allowlisted user and aggregate Hub TVL at or below 100000000 zhu"]}"#;

    fn live_bounded_pilot_readiness_body() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let tip_age = 443_u64;
        LIVE_BOUNDED_PILOT_READINESS_BODY
            .replace("$EVALUATED$", &now.to_string())
            .replace("$VALID_UNTIL$", &(now + 60).to_string())
            .replace("$TIP$", &now.saturating_sub(tip_age).to_string())
            .replace("$TIP_AGE$", &tip_age.to_string())
    }

    /// The same Hub's `/v1/health`, likewise verbatim from the wire.
    fn live_bounded_pilot_health_json(hub_address: &str) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "version": 7,
            "name": "HPAY Fast Pay Hub",
            "hub_address": hub_address,
            "hub_fee_mei": "0",
            "settlement_ready": true,
            "cross_channel_ready": true,
            "official_channelpay_ready": true,
            "trusted_bounded_pilot_ready": true,
            "deployment_profile": "mainnet-bounded-pilot"
        })
    }

    /// A mainnet Hub that publishes the bounded pilot profile, and a wallet
    /// whose owner ticked the bounded-pilot consent box, must route Fast Pay.
    ///
    /// Both halves matter and neither may be dropped:
    ///
    /// * consent withheld (the fail-closed default): no L2 plan. The bounded
    ///   profile alone must never be enough.
    /// * consent given: the L2 plan appears, against a Hub document that still
    ///   reports `trustless_finality: false` and `unilateral_l1_enforceable:
    ///   false`, which is exactly what the bounded pilot is and exactly what the
    ///   user consented to.
    ///
    /// This is a Send-screen test on purpose. The old failure was silent: the
    /// client was built with the trustless-only policy regardless of consent,
    /// `require_mainnet_payment_ready` refused, `try_l2_plan` returned `None`,
    /// and the user simply got a paid L1 transaction with no explanation.
    #[tokio::test]
    async fn mainnet_bounded_pilot_consent_reaches_the_send_screen() {
        use axum::{Json, Router, routing::get};

        const CHANNEL_ID: &str = "00112233445566778899aabbccddeeff";
        let payer = WalletAccount::create("bounded-pilot-send-payer").unwrap();
        let payee = WalletAccount::create("bounded-pilot-send-payee").unwrap();
        let hub_account = WalletAccount::create("bounded-pilot-send-hub").unwrap();
        let hub_address = hub_account.address();
        let payer_address = payer.address();

        let hub_app = Router::new()
            .route(
                "/v1/health",
                get(move || {
                    let body = live_bounded_pilot_health_json(&hub_address);
                    async move { Json(body) }
                }),
            )
            .route(
                "/v1/readiness/mainnet",
                get(|| async { live_bounded_pilot_readiness_body() }),
            );
        let hub_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub_url = format!("http://{}", hub_listener.local_addr().unwrap());
        let hub_server = tokio::spawn(async move {
            axum::serve(hub_listener, hub_app).await.unwrap();
        });

        let channel_left = payer_address.clone();
        let channel_right = hub_account.address();
        let node_app = Router::new().route(
            "/query/channel",
            get(move || {
                let body = serde_json::json!({
                    "ret": 0,
                    "id": CHANNEL_ID,
                    "status": 0,
                    "open_height": 774_000,
                    "close_height": 0,
                    "reuse_version": 1,
                    "arbitration_lock": 5,
                    "left": { "address": channel_left, "hacash": "0.01", "satoshi": 0 },
                    "right": { "address": channel_right, "hacash": "0", "satoshi": 0 }
                });
                async move { Json(body) }
            }),
        );
        let node_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_url = format!("http://{}", node_listener.local_addr().unwrap());
        let node_server = tokio::spawn(async move {
            axum::serve(node_listener, node_app).await.unwrap();
        });

        let settings_for = |consented: bool| WalletSettings {
            node_url: node_url.clone(),
            network_mode: "mainnet".into(),
            l2_hub_url: Some(hub_url.clone()),
            trusted_mainnet_fast_pay_pilot: consented,
            channel_id_hex: Some(CHANNEL_ID.into()),
            ..WalletSettings::default()
        };

        let without_consent = PaymentRouter::new(
            NodeClient::new(&node_url).unwrap(),
            settings_for(false),
            BillStore::default(),
        );
        let refused = without_consent
            .try_l2_plan(&payer.address(), &payee.address(), 0.005)
            .await
            .unwrap();
        let L2Routing::Declined(reason) = refused else {
            panic!(
                "a bounded-pilot Hub must not be used without the wallet owner's explicit consent"
            );
        };
        // The refusal is correct and it must also be legible. This is the
        // fallback that used to happen in silence: same wallet, same Hub, and
        // the user is charged an L1 fee with no statement of why.
        let reason = reason.expect("the L1 fallback must say why Fast Pay was not used");
        assert!(
            reason.contains("trustless settlement only")
                && reason.contains("mainnet-bounded-pilot"),
            "the reason must name this wallet's policy and the Hub's profile, got: {reason}"
        );

        let with_consent = PaymentRouter::new(
            NodeClient::new(&node_url).unwrap(),
            settings_for(true),
            BillStore::default(),
        );
        let L2Routing::Planned(plan) = with_consent
            .try_l2_plan(&payer.address(), &payee.address(), 0.005)
            .await
            .unwrap()
        else {
            panic!("consented bounded mainnet pilot must produce a Fast Pay plan");
        };
        assert_eq!(plan.rail, PaymentRail::L2Fast);
        assert_eq!(plan.channel_id.as_deref(), Some(CHANNEL_ID));
        assert!(plan.fast_pay_declined.is_none());

        // The channel-open gate, against the same served document. The two
        // channel-open call sites in `authorization_service` build their client
        // from exactly these three settings values, so this is what they now
        // ask the Hub. It is stated in both directions for the same reason as
        // above: consent is what opens it, and the bounded profile alone is not.
        let open_gate = |consented: bool| {
            let settings = settings_for(consented);
            crate::l2_hub::L2HubClient::new_for_wallet_policy(
                settings.l2_hub_url.clone().unwrap(),
                &settings.network_mode,
                settings.trusted_mainnet_fast_pay_pilot,
            )
        };
        assert!(
            open_gate(false)
                .require_channel_open_ready(&hub_account.address(), "0.05")
                .await
                .is_err(),
            "channel funding must not bind to a bounded-pilot Hub without explicit consent"
        );
        open_gate(true)
            .require_channel_open_ready(&hub_account.address(), "0.05")
            .await
            .expect("consented bounded mainnet pilot must accept a capped channel open");

        hub_server.abort();
        node_server.abort();
    }
}
