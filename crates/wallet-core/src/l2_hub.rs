//! L2 Fast Pay hub client (HPAY Wallet Hub API v7).
//!
//! CSP operators implement:
//! - `GET /v1/health`
//! - `POST /v1/fast-pay`. initiate synchronous channel-chain payment
//! - `GET /v1/fast-pay/{payment_id}`. poll status
//! - `GET /v1/fast-pay/inbox/{payee}`. recipient signature requests
//!
//! Off-chain wire format follows `github.com/hacash/core/channel`.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::account::WalletAccount;
use crate::bills::BillStore;
use crate::channel::ChannelInfo;
use crate::error::{WalletError, WalletResult};
use crate::l2_bill::{
    cosign_bill_hex, summarize_bill, trusted_channel_state, validate_recipient_bill,
    validate_sender_bill,
};

/// The `/v1/health` payload: a cheap liveness/identity answer.
///
/// The Hub serves this without any fullnode I/O, so it carries no
/// capability-dependent guarantee and this struct deliberately has no field
/// that could be mistaken for one. Everything a mainnet money gate needs -
/// `trustless_finality`, `unilateral_l1_enforceable` - lives on
/// [`HubMainnetReadiness`] (`/v1/readiness/mainnet`), the endpoint that pays
/// for the evidence. Re-adding a guarantee flag here would recreate a document
/// that can only ever under-report, which is why none exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubHealth {
    pub ok: bool,
    pub version: u32,
    pub name: Option<String>,
    /// CSP on-chain address published by the hub.
    #[serde(default)]
    pub hub_address: Option<String>,
    /// Per-payment hub fee in HAC (mei), when advertised by the hub.
    #[serde(default)]
    pub hub_fee_mei: Option<serde_json::Value>,
    /// Hub can sign settlement bills and is safe to use for supported routes.
    #[serde(default)]
    pub settlement_ready: bool,
    /// Hub has a complete recipient-signature exchange for routed payments.
    #[serde(default)]
    pub cross_channel_ready: bool,
    /// Provider speaks an authenticated Official ChannelPay session.
    #[serde(default)]
    pub official_channelpay_ready: bool,
    /// Explicit bounded pilot that remains dependent on Hub availability.
    ///
    /// Not capability-dependent: the Hub can answer this from its own
    /// configuration and signing key without touching a fullnode.
    #[serde(default)]
    pub trusted_bounded_pilot_ready: bool,
    /// Truthful transport/deployment label.
    #[serde(default)]
    pub deployment_profile: Option<String>,
}

/// Authoritative, fail-closed payment decision published by HPAY Fast Pay Hub.
///
/// The health route is only a liveness/capability signal. Mainnet payment
/// authority comes exclusively from /v1/readiness/mainnet and is re-checked at
/// the signing boundary so an earlier green preview grants no later authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubMainnetReadiness {
    pub schema: String,
    pub evaluated_unix: u64,
    pub valid_until_unix: u64,
    pub profile: String,
    pub payments_enabled: bool,
    #[serde(default)]
    pub close_enabled: bool,
    pub mainnet_detected: Option<bool>,
    pub fullnode_capabilities: Option<HubFullnodeCapabilities>,
    pub max_payment_hac_zhu: u64,
    pub max_channel_funding_hac_zhu: u64,
    pub max_payment_satoshi: u64,
    pub wallet_fee_hac: String,
    pub trustless_finality: bool,
    pub unilateral_l1_enforceable: bool,
    #[serde(default)]
    pub trusted_bounded_pilot: bool,
    pub settlement_model: String,
    pub blockers: Vec<String>,
    #[serde(default)]
    pub close_blockers: Vec<String>,
    pub limitations: Vec<String>,
    /// Published by a Hub whose one rollback-anchor witness is no longer the
    /// durable store it pinned.
    ///
    /// Kept on this side of the wire deliberately. Without it the wallet sees
    /// only `payments_enabled = false` plus a blocker string, which is exactly
    /// what a witness that is merely *unreachable* looks like - and the whole
    /// reason the Hub measures this without a probe is that the two need
    /// telling apart: one clears by itself in thirty seconds, the other never
    /// clears and is the only condition under which asking the Hub for a
    /// continuity declaration is the right move. Dropping the field here threw
    /// away that distinction at the last hop, in the party it was written for.
    ///
    /// `None` for every healthy Hub and for every Hub that never had an
    /// anchor, because the Hub skips the field when it is absent.
    #[serde(default)]
    pub rollback_anchor_witness_identity_break:
        Option<l2_fast_pay_hub::rollback_anchor::WitnessIdentityBreakV1>,
}

impl HubMainnetReadiness {
    /// Is this Hub refusing because its one witness is gone, rather than
    /// because it cannot currently be reached?
    ///
    /// `true` means the refusal is permanent on the Hub's own account and a
    /// continuity declaration is the only thing that will tell this wallet
    /// anything further. `false` includes "temporarily unreachable", which is
    /// a thing to wait out and not a thing to adjudicate.
    pub fn witness_identity_is_broken(&self) -> bool {
        self.rollback_anchor_witness_identity_break.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubFullnodeCapabilities {
    pub observed_unix: u64,
    pub api_version: u64,
    pub chain_id: u32,
    pub height: u64,
    pub next_height: u64,
    pub mainnet: bool,
    pub tip_timestamp_unix: u64,
    pub tip_age_seconds: u64,
    pub enabled_actions: Vec<u16>,
    /// Exact node capability, not an operator assertion.
    #[serde(default)]
    pub channel_unilateral_exit: bool,
    #[serde(default)]
    pub channel_unilateral_exit_evidence:
        Option<l2_fast_pay_hub::node::ChannelUnilateralExitEvidence>,
}

const MAINNET_READINESS_SCHEMA: &str = "hpay-fast-pay-mainnet-readiness/1";
const MAINNET_PILOT_PROFILE: &str = "mainnet-pilot";
const MAINNET_BOUNDED_PILOT_PROFILE: &str = "mainnet-bounded-pilot";
const MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU: u64 = 100_000_000;
const MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU: u64 = 1_000_000_000;
const ZHU_PER_MILLIMEI: u64 = 100_000;
const MAINNET_MIN_SAFE_HEIGHT: u64 = 765_432;
const MAX_TIP_AGE_SECONDS: u64 = 3_600;
const MAX_FUTURE_SKEW_SECONDS: u64 = 120;
const MAX_READINESS_VALIDITY_SECONDS: u64 = 330;
const REQUIRED_CHANNEL_OPEN_ACTION: u16 = 2;
const REQUIRED_COOPERATIVE_CLOSE_ACTION: u16 = 3;
const REQUIRED_CLOSE_PRINCIPAL_TRANSFER_ACTION: u16 = 14;

impl HubMainnetReadiness {
    pub fn require_payment_ready(&self, amount_wire: Option<&str>) -> WalletResult<()> {
        self.require_payment_ready_for_policy(amount_wire, MainnetFastPayPolicy::TrustlessOnly)
    }

    fn require_payment_ready_for_policy(
        &self,
        amount_wire: Option<&str>,
        policy: MainnetFastPayPolicy,
    ) -> WalletResult<()> {
        let settlement_contract_ready = match policy {
            MainnetFastPayPolicy::TrustlessOnly => {
                self.profile == MAINNET_PILOT_PROFILE
                    && self.trustless_finality
                    && self.unilateral_l1_enforceable
                    && !self.trusted_bounded_pilot
            }
            MainnetFastPayPolicy::TrustedBoundedPilot => {
                self.profile == MAINNET_BOUNDED_PILOT_PROFILE && self.trusted_bounded_pilot
            }
        };
        if self.schema != MAINNET_READINESS_SCHEMA
            || !self.payments_enabled
            || self.mainnet_detected != Some(true)
            || !settlement_contract_ready
            || !self.blockers.is_empty()
        {
            return Err(WalletError::L2(
                "Fast Pay mainnet readiness is not green; payment signing is blocked".into(),
            ));
        }
        let now = unix_now();
        let validity = self
            .valid_until_unix
            .checked_sub(self.evaluated_unix)
            .filter(|seconds| *seconds <= MAX_READINESS_VALIDITY_SECONDS);
        if validity.is_none()
            || self.evaluated_unix > now.saturating_add(MAX_FUTURE_SKEW_SECONDS)
            || now > self.valid_until_unix
        {
            return Err(WalletError::L2(
                "Fast Pay mainnet readiness snapshot is invalid, expired, or from the future"
                    .into(),
            ));
        }
        if !l2_fast_pay_hub::amount::parse_amount_mei(&self.wallet_fee_hac)
            .is_ok_and(|amount| amount == l2_fast_pay_hub::amount::HacAmount::ZERO)
        {
            return Err(WalletError::L2(
                "Fast Pay Hub did not explicitly declare a zero wallet fee".into(),
            ));
        }
        if self.max_payment_hac_zhu < ZHU_PER_MILLIMEI
            || self.max_payment_hac_zhu > MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU
            || self.max_channel_funding_hac_zhu < ZHU_PER_MILLIMEI
            || self.max_channel_funding_hac_zhu > MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU
        {
            return Err(WalletError::L2(
                "Fast Pay mainnet payment or channel-funding cap is missing, below wallet precision, or exceeds the HPAY pilot limit"
                    .into(),
            ));
        }
        let capabilities = self.fullnode_capabilities.as_ref().ok_or_else(|| {
            WalletError::L2("Fast Pay Hub did not publish verified fullnode capabilities".into())
        })?;
        let expected_next_height = capabilities.height.checked_add(1);
        let reported_tip_age = capabilities
            .observed_unix
            .saturating_sub(capabilities.tip_timestamp_unix);
        let local_tip_age = now.saturating_sub(capabilities.tip_timestamp_unix);
        if capabilities.observed_unix != self.evaluated_unix
            || capabilities.api_version != 1
            || capabilities.chain_id != 0
            || !capabilities.mainnet
            || capabilities.height < MAINNET_MIN_SAFE_HEIGHT
            || expected_next_height != Some(capabilities.next_height)
            || capabilities.tip_timestamp_unix
                > capabilities
                    .observed_unix
                    .saturating_add(MAX_FUTURE_SKEW_SECONDS)
            || capabilities.tip_age_seconds != reported_tip_age
            || capabilities.tip_age_seconds > MAX_TIP_AGE_SECONDS
            || local_tip_age > MAX_TIP_AGE_SECONDS
            || !capabilities
                .enabled_actions
                .contains(&REQUIRED_CHANNEL_OPEN_ACTION)
            || !capabilities
                .enabled_actions
                .contains(&REQUIRED_COOPERATIVE_CLOSE_ACTION)
            || (matches!(policy, MainnetFastPayPolicy::TrustlessOnly)
                && (!capabilities.channel_unilateral_exit
                    || !capabilities
                        .channel_unilateral_exit_evidence
                        .as_ref()
                        .is_some_and(
                            l2_fast_pay_hub::node::ChannelUnilateralExitEvidence::is_verified_mainnet_deployment,
                        )))
        {
            return Err(WalletError::L2(
                "Fast Pay Hub fullnode capabilities are incompatible or stale".into(),
            ));
        }
        if let Some(amount_wire) = amount_wire {
            let amount = l2_fast_pay_hub::amount::parse_amount_mei(amount_wire)
                .map_err(|error| WalletError::L2(error.to_string()))?;
            let amount_zhu = amount
                .as_millimeis()
                .checked_mul(ZHU_PER_MILLIMEI)
                .ok_or_else(|| WalletError::L2("Fast Pay amount exceeds mainnet limits".into()))?;
            if amount_zhu > self.max_payment_hac_zhu {
                return Err(WalletError::L2(format!(
                    "Fast Pay amount exceeds this Hub's mainnet pilot cap of {} zhu",
                    self.max_payment_hac_zhu
                )));
            }
        }
        Ok(())
    }

    pub fn require_cooperative_close_ready(
        &self,
        requires_principal_transfer: bool,
    ) -> WalletResult<()> {
        if self.schema != MAINNET_READINESS_SCHEMA
            || !matches!(
                self.profile.as_str(),
                MAINNET_PILOT_PROFILE | MAINNET_BOUNDED_PILOT_PROFILE
            )
            || !self.close_enabled
            || self.mainnet_detected != Some(true)
            || !self.close_blockers.is_empty()
        {
            return Err(WalletError::L2(
                "Fast Pay mainnet cooperative-close readiness is not green".into(),
            ));
        }
        let now = unix_now();
        let validity = self
            .valid_until_unix
            .checked_sub(self.evaluated_unix)
            .filter(|seconds| *seconds <= MAX_READINESS_VALIDITY_SECONDS);
        if validity.is_none()
            || self.evaluated_unix > now.saturating_add(MAX_FUTURE_SKEW_SECONDS)
            || now > self.valid_until_unix
        {
            return Err(WalletError::L2(
                "Fast Pay close readiness snapshot is invalid, expired, or from the future".into(),
            ));
        }
        if !l2_fast_pay_hub::amount::parse_amount_mei(&self.wallet_fee_hac)
            .is_ok_and(|amount| amount == l2_fast_pay_hub::amount::HacAmount::ZERO)
        {
            return Err(WalletError::L2(
                "Fast Pay Hub did not explicitly declare a zero wallet fee for close".into(),
            ));
        }
        let capabilities = self.fullnode_capabilities.as_ref().ok_or_else(|| {
            WalletError::L2("Fast Pay Hub did not publish verified fullnode capabilities".into())
        })?;
        let expected_next_height = capabilities.height.checked_add(1);
        let reported_tip_age = capabilities
            .observed_unix
            .saturating_sub(capabilities.tip_timestamp_unix);
        let local_tip_age = now.saturating_sub(capabilities.tip_timestamp_unix);
        if capabilities.observed_unix != self.evaluated_unix
            || capabilities.api_version != 1
            || capabilities.chain_id != 0
            || !capabilities.mainnet
            || capabilities.height < MAINNET_MIN_SAFE_HEIGHT
            || expected_next_height != Some(capabilities.next_height)
            || capabilities.tip_timestamp_unix
                > capabilities
                    .observed_unix
                    .saturating_add(MAX_FUTURE_SKEW_SECONDS)
            || capabilities.tip_age_seconds != reported_tip_age
            || capabilities.tip_age_seconds > MAX_TIP_AGE_SECONDS
            || local_tip_age > MAX_TIP_AGE_SECONDS
            || !capabilities
                .enabled_actions
                .contains(&REQUIRED_COOPERATIVE_CLOSE_ACTION)
            || (requires_principal_transfer
                && !capabilities
                    .enabled_actions
                    .contains(&REQUIRED_CLOSE_PRINCIPAL_TRANSFER_ACTION))
        {
            return Err(WalletError::L2(
                "Fast Pay Hub close fullnode capabilities are incompatible or stale".into(),
            ));
        }
        Ok(())
    }
    /// The hard-guarantee gate for putting new money behind a channel binding.
    ///
    /// This is the authority for `trustless_finality` and
    /// `unilateral_l1_enforceable`. `/v1/health` cannot answer either one: it
    /// performs no fullnode I/O, so an honest Hub reports every
    /// capability-dependent guarantee `false` there by construction, and a gate
    /// reading those flags could never open even once the guarantee exists.
    /// `/v1/readiness/mainnet` publishes the same `HubHardGuarantees::measure`
    /// result the Hub's own money gate enforces, so this reads it instead.
    ///
    /// Correct in both eras with no further edit: while the external rollback
    /// anchor is absent the Hub measures `trustless_finality: false` and this
    /// denies, naming the missing guarantee; once the anchor lands and the Hub
    /// measures it `true`, this allows.
    fn require_channel_binding_guarantees(&self, policy: MainnetFastPayPolicy) -> WalletResult<()> {
        if self.schema != MAINNET_READINESS_SCHEMA {
            return Err(WalletError::L2(
                "Fast Pay mainnet readiness document is not the expected schema; new funding is blocked"
                    .into(),
            ));
        }
        match policy {
            MainnetFastPayPolicy::TrustlessOnly => {
                if self.profile != MAINNET_PILOT_PROFILE || self.trusted_bounded_pilot {
                    return Err(WalletError::L2(
                        "Fast Pay Hub does not publish the trustless mainnet pilot profile; new funding is blocked"
                            .into(),
                    ));
                }
                let mut missing = Vec::new();
                if !self.trustless_finality {
                    missing.push("trustless_finality");
                }
                if !self.unilateral_l1_enforceable {
                    missing.push("unilateral_l1_enforceable");
                }
                if !missing.is_empty() {
                    return Err(WalletError::L2(format!(
                        "Fast Pay Hub mainnet readiness does not report the required hard guarantee: {}; new funding is blocked",
                        missing.join(" and ")
                    )));
                }
            }
            MainnetFastPayPolicy::TrustedBoundedPilot => {
                if self.profile != MAINNET_BOUNDED_PILOT_PROFILE || !self.trusted_bounded_pilot {
                    return Err(WalletError::L2(
                        "Fast Pay Hub mainnet readiness does not report the required hard guarantee: trusted_bounded_pilot; new funding is blocked"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The full payment gate plus this Hub's channel-funding cap.
    ///
    /// The policy is an argument for the same reason it is one on
    /// `require_payment_ready_for_policy`: it is the wallet owner's explicit
    /// choice, and it must never be inferred from the document being judged. A
    /// Hub that declares itself `mainnet-bounded-pilot` cannot promote itself
    /// into that policy; only a user who ticked the consent box can. Passing it
    /// in also stops the funding gate silently re-judging under a policy the
    /// caller already decided against - which is what it used to do, refusing
    /// every consented bounded-pilot channel open one line after the same
    /// document had passed the identical check under the right policy.
    pub(crate) fn require_channel_funding_ready_for_policy(
        &self,
        amount_mei: &str,
        policy: MainnetFastPayPolicy,
    ) -> WalletResult<()> {
        self.require_payment_ready_for_policy(None, policy)?;
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(amount_mei)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let amount_zhu = amount
            .as_millimeis()
            .checked_mul(ZHU_PER_MILLIMEI)
            .ok_or_else(|| {
                WalletError::L2("Fast Pay channel funding exceeds mainnet limits".into())
            })?;
        if amount_zhu > self.max_channel_funding_hac_zhu {
            return Err(WalletError::L2(format!(
                "Fast Pay channel funding exceeds this Hub's mainnet pilot cap of {} zhu",
                self.max_channel_funding_hac_zhu
            )));
        }
        Ok(())
    }

    pub(crate) fn max_channel_funding_millimeis(&self) -> u64 {
        self.max_channel_funding_hac_zhu / ZHU_PER_MILLIMEI
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayRequest {
    pub operation_id: String,
    pub idempotency_key: String,
    pub payer: String,
    pub payee: String,
    pub amount: String,
    pub channel_id: String,
    /// `sender` (default) or `recipient`. who pays the hub routing fee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayResponse {
    pub payment_id: String,
    pub status: String,
    pub bill_hex: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayInboxItem {
    pub payment_id: String,
    pub idempotency_key: String,
    pub payer: String,
    pub payee: String,
    pub amount: String,
    pub channel_id: String,
    pub payee_channel_id: String,
    pub status: String,
    pub bill_hex: String,
    #[serde(default)]
    pub summary: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastPayExecution {
    pub payment_id: String,
    pub status: String,
    pub summary: String,
}
#[derive(Debug, Clone, Serialize)]
struct ConfirmFastPayRequest<'a> {
    idempotency_key: &'a str,
    bill_hex: &'a str,
}

pub fn hub_fee_is_zero(health: &HubHealth) -> bool {
    match health.hub_fee_mei.as_ref() {
        None => false,
        Some(serde_json::Value::String(value)) => l2_fast_pay_hub::amount::parse_amount_mei(value)
            .is_ok_and(|amount| amount == l2_fast_pay_hub::amount::HacAmount::ZERO),
        Some(serde_json::Value::Number(value)) => {
            value.as_u64() == Some(0) || value.as_i64() == Some(0) || value.as_f64() == Some(0.0)
        }
        _ => false,
    }
}

pub fn hub_fee_label(health: &HubHealth) -> Option<String> {
    health.hub_fee_mei.as_ref().map(|value| match value {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

const MAX_HUB_JSON_BYTES: usize = 2 * 1024 * 1024;

pub struct L2HubClient {
    base_url: String,
    http: Result<reqwest::Client, String>,
    mainnet: bool,
    mainnet_policy: MainnetFastPayPolicy,
}

/// Deliberately not `pub`: only this crate may name a mainnet policy, and only
/// `new_for_wallet_policy` may derive one from the wallet owner's consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MainnetFastPayPolicy {
    TrustlessOnly,
    TrustedBoundedPilot,
}

impl L2HubClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::new_for_network(base_url, "testnet")
    }

    pub fn new_for_network(base_url: impl Into<String>, network_mode: &str) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: crate::http_client::shared_http_client().cloned(),
            mainnet: network_mode == "mainnet",
            mainnet_policy: MainnetFastPayPolicy::TrustlessOnly,
        }
    }

    pub fn new_for_trusted_bounded_mainnet_pilot(
        base_url: impl Into<String>,
        network_mode: &str,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: crate::http_client::shared_http_client().cloned(),
            mainnet: network_mode == "mainnet",
            mainnet_policy: MainnetFastPayPolicy::TrustedBoundedPilot,
        }
    }

    pub fn new_for_wallet_policy(
        base_url: impl Into<String>,
        network_mode: &str,
        trusted_mainnet_fast_pay_pilot: bool,
    ) -> Self {
        if network_mode == "mainnet" && trusted_mainnet_fast_pay_pilot {
            Self::new_for_trusted_bounded_mainnet_pilot(base_url, network_mode)
        } else {
            Self::new_for_network(base_url, network_mode)
        }
    }

    fn http(&self) -> WalletResult<&reqwest::Client> {
        self.http
            .as_ref()
            .map_err(|error| WalletError::L2(error.clone()))
    }

    pub async fn health(&self) -> WalletResult<HubHealth> {
        let url = format!("{}/v1/health", self.base_url);
        let response = self
            .http()?
            .get(&url)
            .send()
            .await
            .map_err(|error| WalletError::L2(format!("hub unreachable: {error}")))?;
        Self::read_hub_json(response, "hub health").await
    }

    pub async fn mainnet_readiness(&self) -> WalletResult<HubMainnetReadiness> {
        let url = format!("{}/v1/readiness/mainnet", self.base_url);
        let response = self
            .http()?
            .get(&url)
            .send()
            .await
            .map_err(|error| WalletError::L2(format!("hub readiness unavailable: {error}")))?;
        Self::read_hub_json(response, "hub mainnet readiness").await
    }

    /// Submit one exact Agent-signed HVM payment proposal for Hub co-signing.
    /// Mainnet remains explicitly unavailable until the separate HVM
    /// deployment/watchtower production gate is enabled in both wallet and Hub.
    ///
    /// The rollback-anchor ratchet runs inside this function, before the bill
    /// is returned, so no caller can obtain a co-signed bill that skipped it.
    /// The check is deliberately not reported as a verdict alongside the bill:
    /// a caller that ignores a verdict is one `let _ =` away from a silent
    /// accept.
    pub async fn cosign_hvm_payment(
        &self,
        request: &l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1,
        safety: &mut crate::l2_safety::ClientL2Safety,
        hub_identity: &str,
        independent_serial_floor: u64,
    ) -> WalletResult<l2_fast_pay_hub::hvm_channel::HvmChannelBillV1> {
        if self.mainnet {
            return Err(WalletError::L2(
                "Agent HVM Fast Pay is not enabled for mainnet".into(),
            ));
        }
        let url = format!("{}/v1/hvm/payment", self.base_url);
        let response = self
            .http()?
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|error| WalletError::L2(format!("Hub HVM payment unavailable: {error}")))?;
        let cosigned: l2_fast_pay_hub::hvm_ledger::HvmCosignedBillV1 =
            Self::read_hub_json(response, "Hub HVM payment").await?;
        // The receipt commits to the payer-signed, Hub-UNSIGNED bill: the Hub
        // fills its own signature in afterwards and the commitment covers the
        // whole struct including signatures. Compare against the proposal this
        // wallet sent, never against the fully signed bill that came back.
        let proposed_bill_commitment = request
            .proposed_bill
            .commitment()
            .map_err(|error| WalletError::L2(error.to_string()))?;
        safety.accept_anchored_bill(
            &request.binding_commitment,
            hub_identity,
            &proposed_bill_commitment,
            request.proposed_bill.serial,
            &cosigned.anchor_receipts,
            independent_serial_floor,
        )?;
        Ok(cosigned.bill)
    }

    /// Reconcile one exact HVM payment against the Hub that holds it.
    ///
    /// This is the *second* way a wallet learns that a bill was co-signed, and
    /// it exists because the first one can be taken away: the Hub co-signs,
    /// persists, and then answers the POST with a 503 or a truncated body, and
    /// [`Self::cosign_hvm_payment`] fails closed without ever reaching the
    /// ratchet. Whoever chooses which path the wallet takes must not be able
    /// to choose a path with no ratchet on it, so the ratchet runs here too,
    /// inside the function that produces the bill, against the receipts the
    /// Hub publishes beside it.
    ///
    /// The status is returned only after the check has passed. A refusal
    /// returns `Err` and the fully signed bill never reaches the caller.
    pub async fn reconcile_hvm_payment(
        &self,
        operation_id: &str,
        request: &l2_fast_pay_hub::hvm_ledger::HvmPaymentRequestV1,
        safety: &mut crate::l2_safety::ClientL2Safety,
        hub_identity: &str,
        independent_serial_floor: u64,
    ) -> WalletResult<l2_fast_pay_hub::hvm_ledger::HvmPaymentStatusV1> {
        let status = self.hvm_payment_status(operation_id).await?;
        if status.fully_signed_bill.is_none() {
            // Nothing was signed, so there is nothing to accept and nothing to
            // ratchet. The caller still has to handle the status it got.
            return Ok(status);
        }
        // The Hub answering about a different request is refused before the
        // ratchet runs, so a mismatched status can never write anything.
        if status.request != *request
            || status.request_commitment
                != request
                    .commitment()
                    .map_err(|error| WalletError::L2(error.to_string()))?
        {
            return Err(WalletError::L2(
                "Hub HVM payment status is for a different request than this wallet signed".into(),
            ));
        }
        let proposed_bill_commitment = request
            .proposed_bill
            .commitment()
            .map_err(|error| WalletError::L2(error.to_string()))?;
        safety.accept_anchored_bill(
            &request.binding_commitment,
            hub_identity,
            &proposed_bill_commitment,
            request.proposed_bill.serial,
            &status.anchor_receipts,
            independent_serial_floor,
        )?;
        Ok(status)
    }

    /// The raw status document, with no ratchet.
    ///
    /// Private on purpose. A wallet that reads a fully signed bill out of this
    /// and commits it has walked around the counterparty ratchet, which is the
    /// one check the Hub cannot satisfy by choosing its own witnesses. Callers
    /// use [`Self::reconcile_hvm_payment`].
    async fn hvm_payment_status(
        &self,
        operation_id: &str,
    ) -> WalletResult<l2_fast_pay_hub::hvm_ledger::HvmPaymentStatusV1> {
        if operation_id.trim().is_empty() || operation_id.len() > 256 {
            return Err(WalletError::L2("HVM operation id is invalid".into()));
        }
        let url = format!("{}/v1/hvm/payment/{operation_id}", self.base_url);
        let response = self
            .http()?
            .get(url)
            .send()
            .await
            .map_err(|error| WalletError::L2(format!("Hub HVM status unavailable: {error}")))?;
        Self::read_hub_json(response, "Hub HVM payment status").await
    }

    /// Fetch public activation and ledger evidence for one exact HVM channel.
    /// Callers must independently verify the returned bundle against the live
    /// pinned node and the expected Hub identity before using it.
    pub async fn hvm_channel_status(
        &self,
        binding_commitment: &str,
    ) -> WalletResult<l2_fast_pay_hub::hvm_ledger::HvmChannelStatusV1> {
        if binding_commitment.len() != 64
            || !binding_commitment
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WalletError::L2(
                "HVM binding commitment must be canonical lowercase SHA-256 hex".into(),
            ));
        }
        let url = format!("{}/v1/hvm/channel/{binding_commitment}", self.base_url);
        let response =
            self.http()?.get(url).send().await.map_err(|error| {
                WalletError::L2(format!("Hub HVM channel unavailable: {error}"))
            })?;
        let status: l2_fast_pay_hub::hvm_ledger::HvmChannelStatusV1 =
            Self::read_hub_json(response, "Hub HVM channel status").await?;
        if status.schema != l2_fast_pay_hub::hvm_ledger::HVM_CHANNEL_STATUS_SCHEMA
            || status.binding_commitment != binding_commitment
            || status
                .recovery_bundle
                .binding
                .commitment()
                .map_err(|error| {
                    WalletError::L2(format!("Hub HVM channel binding is invalid: {error}"))
                })?
                != binding_commitment
        {
            return Err(WalletError::L2(
                "Hub HVM channel status does not match the requested binding".into(),
            ));
        }
        status
            .latest_fully_signed_bill
            .validate_fully_signed(&status.recovery_bundle.binding)
            .map_err(|error| WalletError::L2(format!("Hub HVM latest bill is invalid: {error}")))?;
        Ok(status)
    }

    /// Submit one exact Agent-signed payment for the shared HVM registry V2.
    /// Mainnet remains fail-closed until independently verified deployment
    /// evidence and the production watchtower gates are enabled.
    ///
    /// As with [`Self::cosign_hvm_payment`], the rollback-anchor ratchet runs
    /// here, inside the function that produces the bill.
    pub async fn cosign_hvm_registry_payment(
        &self,
        request: &l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2,
        safety: &mut crate::l2_safety::ClientL2Safety,
        hub_identity: &str,
        independent_serial_floor: u64,
    ) -> WalletResult<l2_fast_pay_hub::hvm_registry::HvmRegistryBillV2> {
        if self.mainnet {
            return Err(WalletError::L2(
                "shared HVM registry Fast Pay is not enabled for mainnet".into(),
            ));
        }
        let url = format!("{}/v2/hvm-registry/payment", self.base_url);
        let response = self
            .http()?
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|error| {
                WalletError::L2(format!("Hub registry payment unavailable: {error}"))
            })?;
        let cosigned: l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryCosignedBillV2 =
            Self::read_hub_json(response, "Hub registry payment").await?;
        let proposed_bill_commitment = request
            .proposed_bill
            .commitment()
            .map_err(|error| WalletError::L2(error.to_string()))?;
        safety.accept_anchored_bill(
            &request.binding_commitment,
            hub_identity,
            &proposed_bill_commitment,
            request.proposed_bill.serial,
            &cosigned.anchor_receipts,
            independent_serial_floor,
        )?;
        Ok(cosigned.bill)
    }

    /// The registry twin of [`Self::reconcile_hvm_payment`], and the same
    /// reasoning: the Hub must not be able to pick the path with no ratchet on
    /// it by dropping the co-sign response.
    pub async fn reconcile_hvm_registry_payment(
        &self,
        operation_id: &str,
        request: &l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2,
        safety: &mut crate::l2_safety::ClientL2Safety,
        hub_identity: &str,
        independent_serial_floor: u64,
    ) -> WalletResult<l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentStatusV2> {
        let status = self.hvm_registry_payment_status(operation_id).await?;
        if status.fully_signed_bill.is_none() {
            return Ok(status);
        }
        if status.request != *request
            || status.request_commitment
                != request
                    .commitment()
                    .map_err(|error| WalletError::L2(error.to_string()))?
        {
            return Err(WalletError::L2(
                "Hub registry payment status is for a different request than this wallet signed"
                    .into(),
            ));
        }
        let proposed_bill_commitment = request
            .proposed_bill
            .commitment()
            .map_err(|error| WalletError::L2(error.to_string()))?;
        safety.accept_anchored_bill(
            &request.binding_commitment,
            hub_identity,
            &proposed_bill_commitment,
            request.proposed_bill.serial,
            &status.anchor_receipts,
            independent_serial_floor,
        )?;
        Ok(status)
    }

    /// Private for the same reason as [`Self::hvm_payment_status`].
    async fn hvm_registry_payment_status(
        &self,
        operation_id: &str,
    ) -> WalletResult<l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentStatusV2> {
        if operation_id.trim().is_empty() || operation_id.len() > 256 {
            return Err(WalletError::L2(
                "HVM registry operation id is invalid".into(),
            ));
        }
        let url = format!("{}/v2/hvm-registry/payment/{operation_id}", self.base_url);
        let response = self.http()?.get(url).send().await.map_err(|error| {
            WalletError::L2(format!("Hub registry payment status unavailable: {error}"))
        })?;
        Self::read_hub_json(response, "Hub registry payment status").await
    }

    /// Fetch authenticated public evidence for one exact shared registry
    /// channel. The caller must still re-probe its pinned full node before any
    /// private key is used.
    pub async fn hvm_registry_channel_status(
        &self,
        binding_commitment: &str,
    ) -> WalletResult<l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryChannelStatusV2> {
        require_lower_commitment(binding_commitment, "HVM registry binding")?;
        let url = format!(
            "{}/v2/hvm-registry/channel/{binding_commitment}",
            self.base_url
        );
        let response = self.http()?.get(url).send().await.map_err(|error| {
            WalletError::L2(format!("Hub registry channel unavailable: {error}"))
        })?;
        let status: l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryChannelStatusV2 =
            Self::read_hub_json(response, "Hub registry channel status").await?;
        if status.schema != l2_fast_pay_hub::hvm_registry_ledger::HVM_REGISTRY_CHANNEL_STATUS_SCHEMA
            || status.binding_commitment != binding_commitment
            || status
                .recovery_bundle
                .binding
                .commitment()
                .map_err(|error| {
                    WalletError::L2(format!("Hub registry binding is invalid: {error}"))
                })?
                != binding_commitment
        {
            return Err(WalletError::L2(
                "Hub registry status does not match the requested binding".into(),
            ));
        }
        status
            .latest_fully_signed_bill
            .validate_fully_signed(&status.recovery_bundle.binding)
            .map_err(|error| {
                WalletError::L2(format!("Hub registry latest bill is invalid: {error}"))
            })?;
        Ok(status)
    }

    /// Fetch this Hub's continuity declaration for one channel and adjudicate
    /// it against this wallet's own anchor memory.
    ///
    /// # What this is for
    ///
    /// A Hub has exactly one rollback-anchor witness. If that witness's durable
    /// store is replaced - the witness operator rebuilds it, or the Hub's
    /// operator has to move to a different witness entirely - the Hub's pin no
    /// longer matches, its startup probe can never agree again, and it refuses
    /// to sign every bill from then on. From this wallet's side that is
    /// indistinguishable from a Hub that has simply gone quiet, and quiet is
    /// exactly what an operator swapping the witness in order to re-sign
    /// history would also look like.
    ///
    /// So the Hub publishes the head *this wallet already holds* - same serial,
    /// same bill commitment - re-anchored under the witness answering now, and
    /// this runs it through the ordinary overlap rule. Nothing new was signed
    /// by the Hub to produce it, which is the point: a Hub that had to sign
    /// something in order to prove itself would be signing under a witness it
    /// had just chosen.
    ///
    /// # What comes back
    ///
    /// * `Ok(())` - the declaration re-affirmed the recorded head and every
    ///   witness this wallet remembers is still covering it. Nothing changed
    ///   and nothing needs deciding, which for a genuine break is not the
    ///   expected answer.
    /// * `Err` prefixed [`crate::l2_safety::ANCHOR_WITNESS_DECISION_REQUIRED`] -
    ///   the expected answer. The witness this wallet recorded is gone, the
    ///   change is now parked durably in this wallet's own store, and a human
    ///   picks: adopt the new witness set, or close the channel on the last
    ///   accepted head. With one witness the swap is always total, so this is
    ///   the strong zero-overlap prompt.
    /// * any other `Err` - a hard refusal. A declaration whose serial is below
    ///   this wallet's accepted head, whose receipts do not verify, or that is
    ///   bound to another bill, channel or Hub is refused outright and is never
    ///   a user choice. That is the case a rolled-back Hub lands in.
    ///
    /// The Hub's own claim about the break travels in the document and is
    /// deliberately not trusted for anything: the decision is made from the
    /// receipts, which are signed by a party the Hub cannot forge, against
    /// memory the Hub cannot reach.
    pub async fn adjudicate_anchor_continuity(
        &self,
        binding_commitment: &str,
        safety: &mut crate::l2_safety::ClientL2Safety,
        hub_identity: &str,
        independent_serial_floor: u64,
    ) -> WalletResult<()> {
        require_lower_commitment(binding_commitment, "HVM registry binding")?;
        let url = format!(
            "{}/v2/hvm-registry/channel/{binding_commitment}/anchor-continuity",
            self.base_url
        );
        let response = self.http()?.get(url).send().await.map_err(|error| {
            WalletError::L2(format!("Hub anchor continuity unavailable: {error}"))
        })?;
        let declaration: l2_fast_pay_hub::rollback_anchor::AnchorContinuityDeclarationV1 =
            Self::read_hub_json(response, "Hub anchor continuity declaration").await?;
        if declaration.schema
            != l2_fast_pay_hub::rollback_anchor::ANCHOR_CONTINUITY_DECLARATION_SCHEMA
            || declaration.binding_commitment != binding_commitment
            || declaration.hub_identity != hub_identity
        {
            return Err(WalletError::L2(
                "Hub anchor continuity declaration is for a different channel, Hub or schema"
                    .into(),
            ));
        }
        if declaration.receipts.is_empty() {
            // An empty list is not "no anchor to show". It is the Hub asking
            // this wallet to record that every witness it remembers was
            // dropped, on a document the Hub chose to serve - which would let a
            // Hub reset the ratchet by publishing nothing at all. A declaration
            // is a re-anchor or it is not a declaration.
            return Err(WalletError::L2(
                "Hub anchor continuity declaration carries no witness receipt, so it re-anchors \
                 nothing and proves nothing"
                    .into(),
            ));
        }
        // The declaration must be of the head **this wallet already holds**.
        //
        // Everything else on this path describes it as a re-affirmation, and
        // until this check existed nothing enforced it. `serial` and
        // `bill_commitment` arrive chosen by the Hub; the witness receipts a
        // *position*, copying whatever `proposed_bill_commitment` it was
        // handed, so a genuine witness signature proves nothing about which
        // bill it is; and no bill travels with a declaration, so
        // `validate_fully_signed` - which every other acceptance path runs -
        // has nothing to run on. Every other caller of `accept_anchored_bill`
        // derives both values from a proposal this wallet itself signed
        // (`request.proposed_bill.commitment()`); this one is the only place a
        // counterparty ever chose them.
        //
        // Unchecked, a Hub serves serial N+1000 with a commitment this wallet
        // has never seen, and the ratchet - which only ever moves the head
        // *up* - either advances silently (when the offered set still covers
        // the remembered witnesses) or advances on one click of the prompt.
        // Either way the wallet's durable record of its own head is replaced
        // by a bill that does not exist, every genuine bill afterwards is
        // refused `rollback_anchor_witness_behind_hub`, and the value a
        // cooperative close is defined against is a commitment the wallet
        // cannot produce. That is not a re-anchor; it is the Hub writing the
        // wallet's memory.
        let Some(memory) = safety.anchor_memory(binding_commitment) else {
            // No memory at all. The floor is what tells a genuinely new channel
            // apart from a store that lost its memory, exactly as it does
            // inside `accept_anchored_bill`, and the lost-memory case keeps the
            // identifier the recovery document indexes so the diagnosis does
            // not get quieter for being caught one layer earlier.
            if independent_serial_floor > 0 {
                return Err(WalletError::L2(format!(
                    "{}: this wallet's own payment history reaches serial \
                     {independent_serial_floor} on this channel, but its rollback-anchor memory \
                     for the channel is gone. A continuity declaration re-anchors a head this \
                     wallet already accepted; accepting one into an empty memory would hand the \
                     Hub the witness set and the head of its choice. Nothing was accepted",
                    crate::l2_safety::REFUSAL_ANCHOR_MEMORY_BEHIND_WALLET
                )));
            }
            return Err(WalletError::L2(
                "this wallet holds no rollback-anchor memory for this channel, so there is no \
                 recorded head for a continuity declaration to re-affirm. A declaration re-anchors \
                 a head this wallet already accepted; it can never establish the first one"
                    .into(),
            ));
        };
        if declaration.serial != memory.accepted_serial
            || declaration.bill_commitment != memory.accepted_bill_commitment
        {
            return Err(WalletError::L2(format!(
                "Hub anchor continuity declaration is not this wallet's recorded head: it declares \
                 serial {} with bill commitment {}, and this wallet accepted serial {} with bill \
                 commitment {}. A continuity declaration re-anchors the head the counterparty \
                 already holds and nothing else. Nothing was accepted",
                declaration.serial,
                declaration.bill_commitment,
                memory.accepted_serial,
                memory.accepted_bill_commitment
            )));
        }
        safety.accept_anchored_bill(
            binding_commitment,
            hub_identity,
            &declaration.bill_commitment,
            declaration.serial,
            &declaration.receipts,
            independent_serial_floor,
        )
    }

    pub async fn require_mainnet_payment_ready(
        &self,
        amount_wire: Option<&str>,
    ) -> WalletResult<HubMainnetReadiness> {
        let readiness = self.mainnet_readiness().await?;
        readiness.require_payment_ready_for_policy(amount_wire, self.mainnet_policy)?;
        Ok(readiness)
    }

    /// Judge a channel deposit against a readiness document already in hand,
    /// under this client's mainnet policy.
    ///
    /// Callers hold the document, not the policy: the policy came from the
    /// wallet owner's consent when this client was built, and this is how it
    /// reaches a gate that would otherwise have to guess.
    pub(crate) fn require_channel_funding_ready(
        &self,
        readiness: &HubMainnetReadiness,
        amount_mei: &str,
    ) -> WalletResult<()> {
        readiness.require_channel_funding_ready_for_policy(amount_mei, self.mainnet_policy)
    }

    /// Re-read the readiness document and require the hard guarantees this
    /// client's mainnet policy depends on, naming whichever one is missing.
    ///
    /// For callers that hold a `HubHealth` and used to re-check the guarantee
    /// flags that lived on it. Those flags are gone: `/v1/health` does no
    /// fullnode I/O and could only ever under-report them, so the check has to
    /// come from `/v1/readiness/mainnet`. Fails closed when the document cannot
    /// be obtained or does not parse.
    pub async fn require_mainnet_hard_guarantees(&self) -> WalletResult<HubMainnetReadiness> {
        let readiness = self.mainnet_readiness().await?;
        readiness.require_channel_binding_guarantees(self.mainnet_policy)?;
        Ok(readiness)
    }

    /// Verify the provider contract used by a wallet-funded channel open.
    ///
    /// This check is intentionally performed at both preparation and execution.
    /// A prepared transaction must not remain authorized if the provider changes
    /// its address, fee policy, routing support, readiness, or funding cap.
    pub async fn require_channel_open_ready(
        &self,
        expected_hub_address: &str,
        user_deposit_mei: &str,
    ) -> WalletResult<HubHealth> {
        self.require_channel_binding_ready(expected_hub_address, user_deposit_mei)
            .await
    }

    /// Verify the live provider contract for an existing channel binding.
    ///
    /// This intentionally shares the exact identity, fee and funding policy
    /// used when opening a channel, so adopting an existing Agent channel can
    /// never bypass the mainnet exposure cap.
    pub async fn require_channel_binding_ready(
        &self,
        expected_hub_address: &str,
        user_deposit_mei: &str,
    ) -> WalletResult<HubHealth> {
        let health = self.health().await?;
        if !health.ok
            || health.version < 7
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !hub_fee_is_zero(&health)
        {
            return Err(WalletError::L2(
                "Fast Pay provider is not ready for safe, fee-free routed settlement".into(),
            ));
        }
        let published_address = health
            .hub_address
            .as_deref()
            .filter(|address| !address.is_empty())
            .ok_or_else(|| {
                WalletError::L2("Fast Pay provider did not publish its address".into())
            })?;
        if published_address != expected_hub_address {
            return Err(WalletError::L2(
                "Fast Pay provider address changed; review the channel again".into(),
            ));
        }
        if self.mainnet {
            // Liveness-only facts, answerable without fullnode I/O: which
            // profile the provider says it is running, and (for the bounded
            // pilot) that it is configured and keyed for it. No hard guarantee
            // is read here - `/v1/health` cannot measure one.
            let health_profile_matches = match self.mainnet_policy {
                MainnetFastPayPolicy::TrustlessOnly => {
                    health.deployment_profile.as_deref() == Some(MAINNET_PILOT_PROFILE)
                }
                MainnetFastPayPolicy::TrustedBoundedPilot => {
                    health.trusted_bounded_pilot_ready
                        && health.deployment_profile.as_deref()
                            == Some(MAINNET_BOUNDED_PILOT_PROFILE)
                }
            };
            if !health_profile_matches {
                return Err(WalletError::L2(
                    "Fast Pay provider does not match the explicitly selected mainnet settlement policy; new funding is blocked"
                        .into(),
                ));
            }
            // One fetch of the authority, on a path that already paid for it.
            // A missing, malformed, expired or unreachable document errors out
            // of `mainnet_readiness()` and this gate stays shut.
            let readiness = self.mainnet_readiness().await?;
            readiness.require_channel_binding_guarantees(self.mainnet_policy)?;
            // Runs the whole payment gate under this client's policy before it
            // looks at the funding cap, so there is nothing left to repeat here.
            readiness
                .require_channel_funding_ready_for_policy(user_deposit_mei, self.mainnet_policy)?;
        }
        Ok(health)
    }

    pub async fn open_channel(
        &self,
        request: &l2_fast_pay_hub::l1_channel::L1ChannelOpenRequest,
    ) -> WalletResult<l2_fast_pay_hub::l1_channel::L1ChannelOpenStatusResponse> {
        let binding = l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
            network_kind: request.network.clone(),
            chain_id: request.chain_id,
            mainnet: request.mainnet,
            block_1_hash: request.block_1_hash.clone(),
            node_profile_id: request.node_profile_id.clone(),
            network_instance_id: request.network_instance_id.clone(),
            transaction_format_version: request.transaction_format_version,
        };
        if binding.validate().is_err() || request.mainnet != self.mainnet {
            return Err(WalletError::L2(
                "L1 channel-open request does not match this Hub client's exact network".into(),
            ));
        }
        let url = format!("{}/v1/l1/channel/open", self.base_url);
        let response = self
            .http()?
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|error| WalletError::L2(format!("Hub channel open unavailable: {error}")))?;
        Self::read_hub_json(response, "Hub channel open").await
    }
    pub async fn require_channel_close_ready(
        &self,
        expected_hub_address: &str,
        requires_principal_transfer: bool,
    ) -> WalletResult<HubHealth> {
        let health = self.health().await?;
        if !health.ok
            || health.version < 7
            || !health.settlement_ready
            || !health.official_channelpay_ready
            || !hub_fee_is_zero(&health)
            || health.hub_address.as_deref() != Some(expected_hub_address)
        {
            return Err(WalletError::L2(
                "Fast Pay Hub is not ready for an authenticated fee-free channel close".into(),
            ));
        }
        if self.mainnet {
            self.mainnet_readiness()
                .await?
                .require_cooperative_close_ready(requires_principal_transfer)?;
        }
        Ok(health)
    }

    pub async fn close_channel(
        &self,
        request: &l2_fast_pay_hub::l1_channel_close::L1ChannelCloseRequest,
    ) -> WalletResult<l2_fast_pay_hub::l1_channel_close::L1ChannelCloseResponse> {
        let binding = l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
            network_kind: request.network.clone(),
            chain_id: request.chain_id,
            mainnet: request.mainnet,
            block_1_hash: request.block_1_hash.clone(),
            node_profile_id: request.node_profile_id.clone(),
            network_instance_id: request.network_instance_id.clone(),
            transaction_format_version: request.transaction_format_version,
        };
        if binding.validate().is_err() || request.mainnet != self.mainnet {
            return Err(WalletError::L2(
                "L1 channel-close request does not match this Hub client's exact network".into(),
            ));
        }
        let url = format!("{}/v1/l1/channel/close", self.base_url);
        let response = self
            .http()?
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|error| WalletError::L2(format!("Hub channel close unavailable: {error}")))?;
        Self::read_hub_json(response, "Hub channel close").await
    }

    pub async fn payment_status(&self, payment_id: &str) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay/{payment_id}", self.base_url);
        let response = self
            .http()?
            .get(url)
            .send()
            .await
            .map_err(|error| WalletError::L2(error.to_string()))?;
        Self::read_hub_json(response, "hub payment status").await
    }

    pub async fn recipient_inbox(&self, payee: &str) -> WalletResult<Vec<FastPayInboxItem>> {
        let url = format!("{}/v1/fast-pay/inbox/{payee}", self.base_url);
        let response = self
            .http()?
            .get(url)
            .send()
            .await
            .map_err(|error| WalletError::L2(error.to_string()))?;
        Self::read_hub_json(response, "hub recipient inbox").await
    }

    pub async fn fast_pay(&self, req: &FastPayRequest) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay", self.base_url);
        let response = self
            .http()?
            .post(url)
            .json(req)
            .send()
            .await
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let body: FastPayResponse =
            Self::read_hub_json(response, "hub payment preparation").await?;
        if body.status != "settled" && body.status != "pending" {
            return Err(WalletError::L2(format!(
                "hub payment status: {}",
                body.status
            )));
        }
        Ok(body)
    }

    pub async fn confirm_fast_pay(
        &self,
        payment_id: &str,
        idempotency_key: &str,
        signed_bill_hex: &str,
    ) -> WalletResult<FastPayResponse> {
        let url = format!("{}/v1/fast-pay/{payment_id}/confirm", self.base_url);
        let response = self
            .http()?
            .post(url)
            .json(&ConfirmFastPayRequest {
                idempotency_key,
                bill_hex: signed_bill_hex,
            })
            .send()
            .await
            .map_err(|error| WalletError::L2(error.to_string()))?;
        Self::read_hub_json(response, "hub settlement confirmation").await
    }

    pub async fn execute_and_store_bill(
        &self,
        req: &FastPayRequest,
        bills: &mut BillStore,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_signer: &dyn crate::l2_signer::FastPayBillSigner,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        if payer_signer.fast_pay_address() != req.payer {
            return Err(WalletError::Policy(
                "Fast Pay payer account does not match the request".into(),
            ));
        }
        self.prepare_and_persist_sender_bill(req, bills, safety, payer_channel, hub_address)
            .await?;
        // Personal Wallet preserves its existing final mainnet readiness
        // re-check. Agent Wallet uses the staged API directly so it can also
        // repeat its owner, emergency, node, Hub and channel checks here.
        if self.mainnet {
            self.require_mainnet_payment_ready(Some(&req.amount))
                .await?;
        }
        self.revalidate_persisted_sender_bill(req, bills, safety, payer_channel, hub_address)?;
        self.sign_and_persist_prepared_sender_bill(safety, payer_signer, &req.operation_id)?;
        self.submit_signed_sender_bill(req, bills, safety, payer_channel, hub_address)
            .await
    }

    /// Requests, validates and durably stores the exact unsigned Hub bill.
    /// This stage never receives a signing key and can safely be followed by
    /// caller-specific live re-verification before any secret is used.
    pub async fn prepare_and_persist_sender_bill(
        &self,
        req: &FastPayRequest,
        bills: &BillStore,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<crate::l2_safety::ClientL2Operation> {
        if req.fee_payer.as_deref() != Some("sender") {
            return Err(WalletError::Policy(
                "Fast Pay request must explicitly bind fee_payer=sender".into(),
            ));
        }
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&req.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let before_prepare = safety.require_exact_sender_request(
            &req.operation_id,
            &req.idempotency_key,
            &req.payer,
            &req.payee,
            &req.amount,
            amount.as_millimeis(),
            &req.channel_id,
            payer_channel.reuse_version,
            hub_address,
        )?;
        if before_prepare.status.requires_explicit_reconciliation() {
            return Err(WalletError::L2(
                "RecoveryRequired: this Fast Pay operation may already have reached the hub; automatic retry and L1 fallback are disabled".into(),
            ));
        }
        match before_prepare.status {
            crate::l2_safety::ClientOperationStatus::PaymentIntentCreated => {}
            crate::l2_safety::ClientOperationStatus::PersistedBeforeSigning => {
                return Ok(before_prepare);
            }
            _ => {
                return Err(WalletError::L2(
                    "Fast Pay preparation cannot resume from this durable operation state".into(),
                ));
            }
        }
        let pay = self.fast_pay(req).await?;
        if pay.payment_id != req.operation_id {
            return Err(WalletError::Policy(
                "hub changed the durable Fast Pay operation id".into(),
            ));
        }
        let bill_hex = pay.bill_hex.as_deref().ok_or_else(|| {
            WalletError::L2(format!(
                "payment {} did not include a settlement bill",
                pay.payment_id
            ))
        })?;
        let trusted = trusted_channel_state(bills, payer_channel)?;
        validate_sender_bill(
            &pay.payment_id,
            bill_hex,
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        )?;

        // Re-fetch after validating the exact bill and before creating or
        // persisting any local signature. Preview readiness grants no authority.
        if self.mainnet {
            self.require_mainnet_payment_ready(Some(&req.amount))
                .await?;
        }
        safety.persist_before_signing(&req.operation_id, bill_hex)
    }

    /// Rebuilds the trusted off-chain balance from the latest fully signed
    /// local bill and proves that the durable unsigned Hub bill is still the
    /// exact next transition. Call this immediately before key use.
    pub fn revalidate_persisted_sender_bill(
        &self,
        req: &FastPayRequest,
        bills: &BillStore,
        safety: &crate::l2_safety::ClientL2Safety,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<crate::l2_safety::ClientL2Operation> {
        if req.fee_payer.as_deref() != Some("sender") {
            return Err(WalletError::Policy(
                "Fast Pay request must explicitly bind fee_payer=sender".into(),
            ));
        }
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&req.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let prepared = safety.require_exact_sender_request(
            &req.operation_id,
            &req.idempotency_key,
            &req.payer,
            &req.payee,
            &req.amount,
            amount.as_millimeis(),
            &req.channel_id,
            payer_channel.reuse_version,
            hub_address,
        )?;
        if prepared.status != crate::l2_safety::ClientOperationStatus::PersistedBeforeSigning {
            return Err(WalletError::L2(
                "Fast Pay signing revalidation requires a durable unsigned bill".into(),
            ));
        }
        let unsigned_bill_hex = prepared
            .unsigned_bill_hex
            .as_deref()
            .ok_or_else(|| WalletError::L2("Fast Pay durable unsigned bill is missing".into()))?;
        let trusted = trusted_channel_state(bills, payer_channel)?;
        validate_sender_bill(
            &req.operation_id,
            unsigned_bill_hex,
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        )?;
        Ok(prepared)
    }

    /// Adds exactly one local signature to an already durable unsigned bill
    /// and persists the signed bytes before returning them to the caller.
    pub fn sign_and_persist_prepared_sender_bill(
        &self,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_signer: &dyn crate::l2_signer::FastPayBillSigner,
        operation_id: &str,
    ) -> WalletResult<String> {
        let prepared = safety.operation(operation_id)?;
        if payer_signer.fast_pay_address() != prepared.payer {
            return Err(WalletError::Policy(
                "Fast Pay payer account does not match the durable operation".into(),
            ));
        }
        let authorization =
            crate::l2_signer::FastPaySigningAuthorization::from_persisted(&prepared)?;
        let signed = payer_signer.cosign_authorized_fast_pay_bill(&authorization)?;
        safety.persist_signature(operation_id, &signed)?;
        Ok(signed)
    }

    /// Proves that the exact durable signed bytes still match the current
    /// trusted L2 balance immediately before recording Submitted.
    pub fn revalidate_persisted_signed_sender_bill(
        &self,
        req: &FastPayRequest,
        bills: &BillStore,
        safety: &crate::l2_safety::ClientL2Safety,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<crate::l2_safety::ClientL2Operation> {
        if req.fee_payer.as_deref() != Some("sender") {
            return Err(WalletError::Policy(
                "Fast Pay request must explicitly bind fee_payer=sender".into(),
            ));
        }
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&req.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let signed = safety.require_exact_sender_request(
            &req.operation_id,
            &req.idempotency_key,
            &req.payer,
            &req.payee,
            &req.amount,
            amount.as_millimeis(),
            &req.channel_id,
            payer_channel.reuse_version,
            hub_address,
        )?;
        if signed.status != crate::l2_safety::ClientOperationStatus::Signed {
            return Err(WalletError::L2(
                "RecoveryRequired: Fast Pay submission requires one durably persisted signature"
                    .into(),
            ));
        }
        let signed_bill_hex = signed.signed_bill_hex.as_deref().ok_or_else(|| {
            WalletError::L2("Fast Pay signed bytes are missing from durable storage".into())
        })?;
        let trusted = trusted_channel_state(bills, payer_channel)?;
        validate_sender_bill(
            &req.operation_id,
            signed_bill_hex,
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        )?;
        Ok(signed)
    }

    /// Submits only previously persisted signed bytes. Any unknown outcome is
    /// frozen for explicit reconciliation and can never fall back to L1.
    pub async fn submit_signed_sender_bill(
        &self,
        req: &FastPayRequest,
        bills: &mut BillStore,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        self.revalidate_persisted_signed_sender_bill(
            req,
            bills,
            safety,
            payer_channel,
            hub_address,
        )?;
        safety.mark_submitted(&req.operation_id)?;
        self.confirm_submitted_sender_bill(req, bills, safety, payer_channel, hub_address)
            .await
    }

    /// Confirms an operation only after the caller has durably recorded the
    /// exact Submitted intent. This is the network boundary used by Agent
    /// Wallet after mirroring Submitted in its own authenticated journal.
    pub async fn confirm_submitted_sender_bill(
        &self,
        req: &FastPayRequest,
        bills: &mut BillStore,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        if req.fee_payer.as_deref() != Some("sender") {
            return Err(WalletError::Policy(
                "Fast Pay request must explicitly bind fee_payer=sender".into(),
            ));
        }
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&req.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let submitted = safety.require_exact_sender_request(
            &req.operation_id,
            &req.idempotency_key,
            &req.payer,
            &req.payee,
            &req.amount,
            amount.as_millimeis(),
            &req.channel_id,
            payer_channel.reuse_version,
            hub_address,
        )?;
        if submitted.status != crate::l2_safety::ClientOperationStatus::Submitted {
            return Err(WalletError::L2(
                "RecoveryRequired: Hub confirmation requires a durable Submitted intent".into(),
            ));
        }
        let signed_hex = submitted.signed_bill_hex.ok_or_else(|| {
            WalletError::L2("Fast Pay signed bytes are missing from durable storage".into())
        })?;
        let trusted = match trusted_channel_state(bills, payer_channel) {
            Ok(trusted) => trusted,
            Err(error) => {
                let _ = safety.mark_recovery_required(&req.operation_id);
                return Err(error);
            }
        };
        if let Err(error) = validate_sender_bill(
            &req.operation_id,
            &signed_hex,
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        ) {
            let _ = safety.mark_recovery_required(&req.operation_id);
            return Err(error);
        }
        let response = match self
            .confirm_fast_pay(&req.operation_id, &req.idempotency_key, &signed_hex)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let _ = safety.mark_recovery_required(&req.operation_id);
                return Err(WalletError::L2(format!(
                    "Fast Pay outcome is uncertain; automatic retry and L1 fallback are disabled: {error}"
                )));
            }
        };
        if response.payment_id != req.operation_id {
            safety.mark_recovery_required(&req.operation_id)?;
            return Err(WalletError::Policy(
                "hub confirmation changed the Fast Pay payment id".into(),
            ));
        }
        let confirmed_hex = response.bill_hex.as_deref().unwrap_or(&signed_hex);
        if let Err(error) = validate_sender_bill(
            &req.operation_id,
            confirmed_hex,
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        ) {
            let _ = safety.mark_recovery_required(&req.operation_id);
            return Err(error);
        }
        if response.status == "awaiting_recipient" {
            let summary = match summarize_bill(&req.operation_id, confirmed_hex) {
                Ok(summary) => summary,
                Err(error) => {
                    let _ = safety.mark_recovery_required(&req.operation_id);
                    return Err(error);
                }
            };
            if !summary
                .signatures
                .iter()
                .any(|signature| signature.address == req.payer && signature.verified)
            {
                safety.mark_recovery_required(&req.operation_id)?;
                return Err(WalletError::Policy(
                    "hub did not retain the verified payer signature".into(),
                ));
            }
            safety.mark_awaiting_recipient(&req.operation_id)?;
            return Ok(FastPayExecution {
                payment_id: req.operation_id.clone(),
                status: response.status,
                summary: response
                    .summary
                    .unwrap_or_else(|| "Fast Pay is waiting for the recipient signature".into()),
            });
        }
        if response.status != "settled" {
            safety.mark_recovery_required(&req.operation_id)?;
            return Err(WalletError::L2(format!(
                "hub returned unsupported Fast Pay status {}",
                response.status
            )));
        }
        let summary = match summarize_bill(&req.operation_id, confirmed_hex) {
            Ok(summary) => summary,
            Err(error) => {
                let _ = safety.mark_recovery_required(&req.operation_id);
                return Err(error);
            }
        };
        if !summary.dispute_ready {
            safety.mark_recovery_required(&req.operation_id)?;
            return Err(WalletError::L2(format!(
                "payment {} is missing required verified signatures",
                req.operation_id
            )));
        }
        if let Err(error) = bills.store_bill(&req.operation_id, confirmed_hex) {
            let _ = safety.mark_recovery_required(&req.operation_id);
            return Err(error);
        }
        safety.mark_committed(&req.operation_id)?;
        Ok(FastPayExecution {
            payment_id: req.operation_id.clone(),
            status: response.status,
            summary: response
                .summary
                .unwrap_or_else(|| "Fast Pay settled with no fee".into()),
        })
    }

    /// Queries the exact Hub operation and reconciles only cryptographically
    /// validated states. It never signs, creates a new id, or resubmits bytes.
    pub async fn reconcile_sender_bill(
        &self,
        req: &FastPayRequest,
        bills: &mut BillStore,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        if req.fee_payer.as_deref() != Some("sender") {
            return Err(WalletError::Policy(
                "Fast Pay request must explicitly bind fee_payer=sender".into(),
            ));
        }
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&req.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let local = safety.require_exact_sender_request(
            &req.operation_id,
            &req.idempotency_key,
            &req.payer,
            &req.payee,
            &req.amount,
            amount.as_millimeis(),
            &req.channel_id,
            payer_channel.reuse_version,
            hub_address,
        )?;
        if !matches!(
            local.status,
            crate::l2_safety::ClientOperationStatus::Signed
                | crate::l2_safety::ClientOperationStatus::Submitted
                | crate::l2_safety::ClientOperationStatus::AwaitingRecipient
                | crate::l2_safety::ClientOperationStatus::RecoveryRequired
        ) || local.signed_bill_hex.is_none()
        {
            return Err(WalletError::L2(
                "Fast Pay reconciliation requires exact durable signed bytes".into(),
            ));
        }
        let response = match self.payment_status(&req.operation_id).await {
            Ok(response) => response,
            Err(error) => {
                let _ = safety.mark_recovery_required(&req.operation_id);
                return Err(WalletError::L2(format!(
                    "Fast Pay reconciliation could not determine the Hub outcome: {error}"
                )));
            }
        };
        if response.payment_id != req.operation_id {
            let _ = safety.mark_recovery_required(&req.operation_id);
            return Err(WalletError::Policy(
                "hub reconciliation changed the Fast Pay payment id".into(),
            ));
        }
        let Some(hub_bill) = response.bill_hex.as_deref() else {
            let _ = safety.mark_recovery_required(&req.operation_id);
            return Err(WalletError::L2(
                "Hub reconciliation did not return the exact payment bill".into(),
            ));
        };
        let trusted = match trusted_channel_state(bills, payer_channel) {
            Ok(trusted) => trusted,
            Err(error) => {
                let _ = safety.mark_recovery_required(&req.operation_id);
                return Err(error);
            }
        };
        match response.status.as_str() {
            "pending" => {
                if local.unsigned_bill_hex.as_deref() != Some(hub_bill) {
                    let _ = safety.mark_recovery_required(&req.operation_id);
                    return Err(WalletError::Policy(
                        "Hub pending bill differs from the durable unsigned bill".into(),
                    ));
                }
                let _ = safety.mark_recovery_required(&req.operation_id);
                Ok(FastPayExecution {
                    payment_id: req.operation_id.clone(),
                    status: response.status,
                    summary: "Hub holds the exact pending bill; explicit exact retry is required"
                        .into(),
                })
            }
            "awaiting_recipient" => {
                if let Err(error) = validate_sender_bill(
                    &req.operation_id,
                    hub_bill,
                    &req.payer,
                    &req.payee,
                    &req.amount,
                    hub_address,
                    &req.channel_id,
                    &trusted,
                ) {
                    let _ = safety.mark_recovery_required(&req.operation_id);
                    return Err(error);
                }
                if local.status == crate::l2_safety::ClientOperationStatus::RecoveryRequired {
                    safety.mark_reconciled_awaiting_recipient(&req.operation_id)?;
                } else {
                    safety.mark_awaiting_recipient(&req.operation_id)?;
                }
                Ok(FastPayExecution {
                    payment_id: req.operation_id.clone(),
                    status: response.status,
                    summary: response.summary.unwrap_or_else(|| {
                        "Fast Pay is waiting for the recipient signature".into()
                    }),
                })
            }
            "settled" => {
                let summary = match validate_sender_bill(
                    &req.operation_id,
                    hub_bill,
                    &req.payer,
                    &req.payee,
                    &req.amount,
                    hub_address,
                    &req.channel_id,
                    &trusted,
                ) {
                    Ok(summary) => summary,
                    Err(error) => {
                        let _ = safety.mark_recovery_required(&req.operation_id);
                        return Err(error);
                    }
                };
                if !summary.dispute_ready {
                    let _ = safety.mark_recovery_required(&req.operation_id);
                    return Err(WalletError::L2(
                        "reconciled Fast Pay bill is not dispute-ready".into(),
                    ));
                }
                if let Err(error) = bills.store_bill(&req.operation_id, hub_bill) {
                    let _ = safety.mark_recovery_required(&req.operation_id);
                    return Err(error);
                }
                safety.mark_committed(&req.operation_id)?;
                Ok(FastPayExecution {
                    payment_id: req.operation_id.clone(),
                    status: response.status,
                    summary: response
                        .summary
                        .unwrap_or_else(|| "Fast Pay settlement reconciled".into()),
                })
            }
            _ => {
                let _ = safety.mark_recovery_required(&req.operation_id);
                Err(WalletError::L2(format!(
                    "Hub reconciliation returned unsupported status {}",
                    response.status
                )))
            }
        }
    }

    /// Recovers a preparation whose Hub response was lost before any signature
    /// was stored. The Hub is queried by the already durable operation id; this
    /// method never signs, submits, changes identifiers, or falls back to L1.
    pub async fn reconcile_unsigned_sender_bill(
        &self,
        req: &FastPayRequest,
        bills: &BillStore,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<crate::l2_safety::ClientL2Operation> {
        if req.fee_payer.as_deref() != Some("sender") {
            return Err(WalletError::Policy(
                "Fast Pay request must explicitly bind fee_payer=sender".into(),
            ));
        }
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&req.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let local = safety.require_exact_sender_request(
            &req.operation_id,
            &req.idempotency_key,
            &req.payer,
            &req.payee,
            &req.amount,
            amount.as_millimeis(),
            &req.channel_id,
            payer_channel.reuse_version,
            hub_address,
        )?;
        if !matches!(
            local.status,
            crate::l2_safety::ClientOperationStatus::RecoveryRequired
                | crate::l2_safety::ClientOperationStatus::PersistedBeforeSigning
        ) || local.signed_bill_hex.is_some()
        {
            return Err(WalletError::L2(
                "Fast Pay unsigned recovery requires an operation with no durable signature".into(),
            ));
        }
        let response = self.payment_status(&req.operation_id).await?;
        if response.payment_id != req.operation_id || response.status != "pending" {
            let _ = safety.mark_recovery_required(&req.operation_id);
            return Err(WalletError::L2(
                "Hub did not report the exact unsigned Fast Pay operation as pending".into(),
            ));
        }
        let hub_bill = response.bill_hex.as_deref().ok_or_else(|| {
            WalletError::L2("Hub unsigned reconciliation did not return the payment bill".into())
        })?;
        if local
            .unsigned_bill_hex
            .as_deref()
            .is_some_and(|stored| stored != hub_bill)
        {
            let _ = safety.mark_recovery_required(&req.operation_id);
            return Err(WalletError::Policy(
                "Hub unsigned bill differs from the durable local bill".into(),
            ));
        }
        let trusted = trusted_channel_state(bills, payer_channel)?;
        validate_sender_bill(
            &req.operation_id,
            hub_bill,
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        )?;
        safety.persist_reconciled_before_signing(&req.operation_id, hub_bill)
    }

    /// Explicitly retries only the same durable signed bytes after the bound
    /// Hub proves that it still holds the exact unsigned pending bill.
    pub async fn retry_reconciled_sender_bill(
        &self,
        req: &FastPayRequest,
        bills: &mut BillStore,
        safety: &mut crate::l2_safety::ClientL2Safety,
        payer_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&req.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let local = safety.require_exact_sender_request(
            &req.operation_id,
            &req.idempotency_key,
            &req.payer,
            &req.payee,
            &req.amount,
            amount.as_millimeis(),
            &req.channel_id,
            payer_channel.reuse_version,
            hub_address,
        )?;
        if req.fee_payer.as_deref() != Some("sender")
            || local.status != crate::l2_safety::ClientOperationStatus::RecoveryRequired
            || local.signed_bill_hex.is_none()
        {
            return Err(WalletError::L2(
                "Fast Pay exact retry requires fee_payer=sender and RecoveryRequired signed bytes"
                    .into(),
            ));
        }
        let response = self.payment_status(&req.operation_id).await?;
        if response.payment_id != req.operation_id
            || response.status != "pending"
            || response.bill_hex.as_deref() != local.unsigned_bill_hex.as_deref()
        {
            return Err(WalletError::L2(
                "Fast Pay exact retry requires an exact pending Hub bill; reconcile again".into(),
            ));
        }
        let trusted = trusted_channel_state(bills, payer_channel)?;
        validate_sender_bill(
            &req.operation_id,
            local.signed_bill_hex.as_deref().unwrap_or_default(),
            &req.payer,
            &req.payee,
            &req.amount,
            hub_address,
            &req.channel_id,
            &trusted,
        )?;
        safety.mark_reconciled_submitted(&req.operation_id)?;
        self.confirm_submitted_sender_bill(req, bills, safety, payer_channel, hub_address)
            .await
    }

    pub async fn accept_inbox_item(
        &self,
        item: &FastPayInboxItem,
        bills: &mut BillStore,
        recipient_account: &WalletAccount,
        recipient_channel: &ChannelInfo,
        hub_address: &str,
    ) -> WalletResult<FastPayExecution> {
        if recipient_account.address() != item.payee {
            return Err(WalletError::Policy(
                "Fast Pay recipient account does not match the inbox request".into(),
            ));
        }
        let trusted = trusted_channel_state(bills, recipient_channel)?;
        validate_recipient_bill(
            &item.payment_id,
            &item.bill_hex,
            &item.payer,
            &item.payee,
            &item.amount,
            hub_address,
            &item.channel_id,
            &item.payee_channel_id,
            &trusted,
        )?;
        let amount = l2_fast_pay_hub::amount::parse_amount_mei(&item.amount)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let mut safety = crate::l2_safety::ClientL2Safety::open_for_network(
            recipient_account,
            if self.mainnet { "mainnet" } else { "testnet" },
            hub_address,
            &item.payee_channel_id,
        )?;
        let imported =
            safety.import_recipient_operation(crate::l2_safety::RecipientOperationInput {
                operation_id: &item.payment_id,
                idempotency_key: &item.idempotency_key,
                payer: &item.payer,
                payee: &item.payee,
                amount: &item.amount,
                amount_units: amount.as_millimeis(),
                channel_reuse_version: recipient_channel.reuse_version,
            })?;
        if imported.status.requires_explicit_reconciliation() {
            return Err(WalletError::L2(
                "RecoveryRequired: this Fast Pay receipt may already have reached the hub; automatic retry is disabled".into(),
            ));
        }
        // Recipient confirmation is a signing boundary too. Re-fetch after
        // validating and importing the exact inbox item.
        if self.mainnet {
            self.require_mainnet_payment_ready(Some(&item.amount))
                .await?;
        }
        let prepared = safety.persist_before_signing(&item.payment_id, &item.bill_hex)?;
        let signed_hex = match prepared.signed_bill_hex {
            Some(existing) => existing,
            None => {
                let signed = cosign_bill_hex(&item.bill_hex, recipient_account)?;
                safety.persist_signature(&item.payment_id, &signed)?;
                signed
            }
        };
        safety.mark_submitted(&item.payment_id)?;
        let settled = match self
            .confirm_fast_pay(&item.payment_id, &item.idempotency_key, &signed_hex)
            .await
        {
            Ok(settled) => settled,
            Err(error) => {
                let _ = safety.mark_recovery_required(&item.payment_id);
                return Err(WalletError::L2(format!(
                    "Fast Pay receipt is uncertain; automatic retry is disabled: {error}"
                )));
            }
        };
        if settled.payment_id != item.payment_id || settled.status != "settled" {
            safety.mark_recovery_required(&item.payment_id)?;
            return Err(WalletError::L2(
                "hub did not atomically settle both Fast Pay channels".into(),
            ));
        }
        let settled_hex = settled.bill_hex.as_deref().unwrap_or(&signed_hex);
        validate_recipient_bill(
            &item.payment_id,
            settled_hex,
            &item.payer,
            &item.payee,
            &item.amount,
            hub_address,
            &item.channel_id,
            &item.payee_channel_id,
            &trusted,
        )?;
        let summary = summarize_bill(&item.payment_id, settled_hex)?;
        if !summary.dispute_ready {
            safety.mark_recovery_required(&item.payment_id)?;
            return Err(WalletError::L2(
                "settled Fast Pay bill is not dispute-ready".into(),
            ));
        }
        if let Err(error) = bills.store_bill(&item.payment_id, settled_hex) {
            let _ = safety.mark_recovery_required(&item.payment_id);
            return Err(error);
        }
        safety.mark_committed(&item.payment_id)?;
        Ok(FastPayExecution {
            payment_id: item.payment_id.clone(),
            status: settled.status,
            summary: settled
                .summary
                .unwrap_or_else(|| "Fast Pay received with no fee".into()),
        })
    }

    async fn read_hub_json<T: DeserializeOwned>(
        mut response: reqwest::Response,
        label: &str,
    ) -> WalletResult<T> {
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_HUB_JSON_BYTES as u64)
        {
            return Err(WalletError::L2(format!(
                "{label} response exceeds {MAX_HUB_JSON_BYTES} bytes"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| WalletError::L2(format!("{label} response read failed: {error}")))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_HUB_JSON_BYTES {
                return Err(WalletError::L2(format!(
                    "{label} response exceeds {MAX_HUB_JSON_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let detail = String::from_utf8_lossy(&body);
            return Err(WalletError::L2(format!("{label} HTTP {status}: {detail}")));
        }
        serde_json::from_slice(&body)
            .map_err(|error| WalletError::L2(format!("{label} returned invalid JSON: {error}")))
    }
}

fn require_lower_commitment(value: &str, label: &str) -> WalletResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WalletError::L2(format!(
            "{label} must be canonical lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod transport_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use axum::routing::get;
    use axum::{Json, Router, extract::State};

    use super::*;

    fn readiness_json(enabled: bool, blockers: Vec<&str>, cap_zhu: u64) -> serde_json::Value {
        let now = unix_now();
        serde_json::json!({
            "schema": "hpay-fast-pay-mainnet-readiness/1",
            "evaluated_unix": now,
            "valid_until_unix": now + 60,
            "profile": "mainnet-pilot",
            "payments_enabled": enabled,
            "close_enabled": true,
            "mainnet_detected": true,
            "fullnode_capabilities": {
                "observed_unix": now,
                "api_version": 1,
                "chain_id": 0,
                "height": 900000,
                "next_height": 900001,
                "mainnet": true,
                "tip_timestamp_unix": now,
                "tip_age_seconds": 0,
                "enabled_actions": [1, 2, 3],
                "channel_unilateral_exit": true,
                "channel_unilateral_exit_evidence": {
                    "schema": l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA,
                    "manifest_valid": true,
                    "contract_name": l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_CONTRACT_NAME,
                    "protocol_domain": l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN,
                    "settlement_profile": l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
                    "source_sha256": "11".repeat(32),
                    "bytecode_sha3": l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
                    "required_action_kinds": l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_ACTION_KINDS,
                    "funding_model": {
                        "left_deposit": "positive",
                        "right_hub_deposit": "exactly_zero"
                    },
                    "storage_key_count": l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT,
                    "must_renew_every_storage_key": true,
                    "deployment": {
                        "enabled": true,
                        "contract_address":
                            vm::ContractAddress::from_unchecked(
                                field::Address::create_contract([7_u8; 20]),
                            )
                            .to_readable(),
                        "deployment_tx_hash": "22".repeat(32),
                        "deployment_height": MAINNET_MIN_SAFE_HEIGHT,
                        "independently_verified": true
                    },
                    "on_chain_verification": {
                        "observed_height": 900000,
                        "confirmed_tx_height": MAINNET_MIN_SAFE_HEIGHT,
                        "deployment_tx_confirmed": true,
                        "contract_code_sha3": l2_fast_pay_hub::node::HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
                        "contract_code_matches": true
                    },
                    "deployment_verified": true
                }
            },
            "max_payment_hac_zhu": cap_zhu,
            "max_channel_funding_hac_zhu": cap_zhu.min(MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU),
            "max_payment_satoshi": 0,
            "wallet_fee_hac": "0",
            "trustless_finality": true,
            "unilateral_l1_enforceable": true,
            "trusted_bounded_pilot": false,
            "settlement_model": "hub-coordinated ordered signatures with durable recovery",
            "blockers": blockers,
            "close_blockers": [],
            "limitations": ["settled is not unilateral L1 finality"]
        })
    }

    fn health_json(hub_address: &str) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "version": 7,
            "name": "Test Fast Pay Hub",
            "hub_address": hub_address,
            "hub_fee_mei": "0",
            "settlement_ready": true,
            "cross_channel_ready": true,
            // Still served by hubs that have not upgraded. The wallet must
            // ignore them, not gate on them.
            "external_rollback_anchor_ready": true,
            "l1_dispute_path_ready": true,
            "official_channelpay_ready": true,
            "production_mainnet_ready": true,
            "trusted_bounded_pilot_ready": false,
            "deployment_profile": "mainnet-pilot"
        })
    }

    /// The readiness document an honest Hub publishes today: no external
    /// monotonic rollback anchor exists, so `trustless_finality` is measured
    /// `false` and the blocker is listed.
    fn anchorless_readiness_json(unilateral_l1_enforceable: bool) -> serde_json::Value {
        let mut blockers = vec!["external_monotonic_rollback_anchor_is_not_ready"];
        if !unilateral_l1_enforceable {
            blockers.push("unilateral_l1_dispute_path_is_not_ready");
        }
        let mut value = readiness_json(false, blockers, 500_000);
        value["trustless_finality"] = serde_json::json!(false);
        value["unilateral_l1_enforceable"] = serde_json::json!(unilateral_l1_enforceable);
        value
    }

    async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), server)
    }

    const GATE_HUB_ADDRESS: &str = "1Luek83YChwrkRYGUGpHmYVeC55tQz49Jo";

    /// The channel-binding gate must follow `/v1/readiness/mainnet`, and only
    /// `/v1/readiness/mainnet`, in both directions.
    ///
    /// One mock Hub, one client, one unedited gate. `/v1/health` advertises the
    /// retired guarantee flags as `true` for the whole test and is ignored - the
    /// wallet has no field to deserialize them into. Only the readiness document
    /// moves, and the gate moves with it:
    ///
    /// * anchor not reported: the Hub measures `trustless_finality: false` and
    ///   the wallet refuses, naming the guarantee it did not get.
    /// * anchor reported: the Hub publishes both guarantees and the same gate
    ///   opens, with no code change between the two halves of this test.
    #[tokio::test]
    async fn channel_binding_follows_the_readiness_document_in_both_directions() {
        let anchored = Arc::new(AtomicBool::new(false));
        let app = Router::new()
            .route(
                "/v1/health",
                get(|| async { Json(health_json(GATE_HUB_ADDRESS)) }),
            )
            .route(
                "/v1/readiness/mainnet",
                get(|State(anchored): State<Arc<AtomicBool>>| async move {
                    Json(if anchored.load(Ordering::SeqCst) {
                        readiness_json(true, vec![], 500_000)
                    } else {
                        anchorless_readiness_json(false)
                    })
                }),
            )
            .with_state(anchored.clone());
        let (url, server) = serve(app).await;
        let client = L2HubClient::new_for_network(url, "mainnet");

        let refusal = client
            .require_channel_open_ready(GATE_HUB_ADDRESS, "0.005")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            refusal,
            "l2: Fast Pay Hub mainnet readiness does not report the required hard guarantee: \
             trustless_finality and unilateral_l1_enforceable; new funding is blocked",
            "the refusal must name the guarantees that are missing"
        );

        anchored.store(true, Ordering::SeqCst);
        client
            .require_channel_open_ready(GATE_HUB_ADDRESS, "0.005")
            .await
            .unwrap();
        server.abort();
    }

    /// The refusal must name the guarantee that is actually absent, not a
    /// blanket "not ready".
    ///
    /// This is the exact shape of a Hub whose fullnode proves a verified
    /// unilateral-exit deployment while the external rollback anchor still does
    /// not exist: `unilateral_l1_enforceable` is measured `true`,
    /// `trustless_finality` is measured `false`, and only the second may appear
    /// in the refusal.
    #[tokio::test]
    async fn channel_binding_names_only_the_hard_guarantee_that_is_missing() {
        let app = Router::new()
            .route(
                "/v1/health",
                get(|| async { Json(health_json(GATE_HUB_ADDRESS)) }),
            )
            .route(
                "/v1/readiness/mainnet",
                get(|| async { Json(anchorless_readiness_json(true)) }),
            );
        let (url, server) = serve(app).await;
        let refusal = L2HubClient::new_for_network(url, "mainnet")
            .require_channel_open_ready(GATE_HUB_ADDRESS, "0.005")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("trustless_finality"),
            "the missing guarantee must be named, got: {refusal}"
        );
        assert!(
            !refusal.contains("unilateral_l1_enforceable"),
            "a guarantee the Hub did report must not be blamed, got: {refusal}"
        );
        server.abort();
    }

    /// A readiness document that cannot be obtained is not a green one.
    ///
    /// `/v1/health` is fully green in every case here, including the retired
    /// guarantee flags, so the only thing that can hold the gate shut is the
    /// wallet's refusal to proceed without the authority.
    #[tokio::test]
    async fn channel_binding_fails_closed_without_a_usable_readiness_document() {
        let missing = Router::new().route(
            "/v1/health",
            get(|| async { Json(health_json(GATE_HUB_ADDRESS)) }),
        );
        let malformed = Router::new()
            .route(
                "/v1/health",
                get(|| async { Json(health_json(GATE_HUB_ADDRESS)) }),
            )
            .route("/v1/readiness/mainnet", get(|| async { "not-json" }));
        let wrong_schema = Router::new()
            .route(
                "/v1/health",
                get(|| async { Json(health_json(GATE_HUB_ADDRESS)) }),
            )
            .route(
                "/v1/readiness/mainnet",
                get(|| async {
                    let mut value = readiness_json(true, vec![], 500_000);
                    value["schema"] = serde_json::json!("hpay-fast-pay-mainnet-readiness/2");
                    Json(value)
                }),
            );

        for (label, app) in [
            ("missing", missing),
            ("malformed", malformed),
            ("wrong schema", wrong_schema),
        ] {
            let (url, server) = serve(app).await;
            let error = L2HubClient::new_for_network(url, "mainnet")
                .require_channel_open_ready(GATE_HUB_ADDRESS, "0.005")
                .await
                .unwrap_err();
            assert!(
                !error.to_string().is_empty(),
                "the {label} readiness document must not open the gate"
            );
            server.abort();
        }

        // Unreachable Hub: nothing answers at all.
        assert!(
            L2HubClient::new_for_network("http://127.0.0.1:1", "mainnet")
                .require_channel_open_ready(GATE_HUB_ADDRESS, "0.005")
                .await
                .is_err()
        );
    }

    fn bounded_readiness_json() -> serde_json::Value {
        let mut value = readiness_json(true, vec![], MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU);
        value["profile"] = serde_json::json!(MAINNET_BOUNDED_PILOT_PROFILE);
        value["trustless_finality"] = serde_json::json!(false);
        value["unilateral_l1_enforceable"] = serde_json::json!(false);
        value["trusted_bounded_pilot"] = serde_json::json!(true);
        value["max_channel_funding_hac_zhu"] =
            serde_json::json!(MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU);
        value
    }
    #[test]
    fn health_fee_parser_accepts_only_exact_zero() {
        let mut health = HubHealth {
            ok: true,
            version: 4,
            name: None,
            hub_address: None,
            hub_fee_mei: Some(serde_json::json!("0")),
            settlement_ready: true,
            cross_channel_ready: true,
            official_channelpay_ready: false,
            trusted_bounded_pilot_ready: false,
            deployment_profile: Some("legacy_wallet_hub_v4_development".into()),
        };
        assert!(hub_fee_is_zero(&health));
        health.hub_fee_mei = Some(serde_json::json!("0.001"));
        assert!(!hub_fee_is_zero(&health));
        health.hub_fee_mei = Some(serde_json::json!(0));
        assert!(hub_fee_is_zero(&health));
        health.hub_fee_mei = Some(serde_json::json!(0.0001));
        assert!(!hub_fee_is_zero(&health));
        health.hub_fee_mei = None;
        assert!(!hub_fee_is_zero(&health));
    }

    #[test]
    fn authoritative_readiness_fails_closed_and_enforces_the_hac_cap() {
        let green: HubMainnetReadiness =
            serde_json::from_value(readiness_json(true, vec![], 1_000_000)).unwrap();
        green.require_payment_ready(Some("0.01")).unwrap();
        assert_eq!(green.max_channel_funding_millimeis(), 10);
        assert!(green.require_payment_ready(Some("0.011")).is_err());

        let mut lower_channel_cap = green.clone();
        lower_channel_cap.max_channel_funding_hac_zhu = 500_000;
        lower_channel_cap
            .require_payment_ready(Some("0.007"))
            .unwrap();
        lower_channel_cap
            .require_channel_funding_ready_for_policy("0.005", MainnetFastPayPolicy::TrustlessOnly)
            .unwrap();
        assert!(
            lower_channel_cap
                .require_channel_funding_ready_for_policy(
                    "0.006",
                    MainnetFastPayPolicy::TrustlessOnly,
                )
                .is_err()
        );

        let mut expired = green.clone();
        expired.valid_until_unix = unix_now().saturating_sub(1);
        assert!(expired.require_payment_ready(Some("0.001")).is_err());

        let mut stale = green.clone();
        let old_tip = unix_now().saturating_sub(MAX_TIP_AGE_SECONDS + 1);
        {
            let capabilities = stale.fullnode_capabilities.as_mut().unwrap();
            capabilities.tip_timestamp_unix = old_tip;
            capabilities.tip_age_seconds = capabilities.observed_unix.saturating_sub(old_tip);
        }
        assert!(stale.require_payment_ready(Some("0.001")).is_err());

        let mut mismatched_snapshot = green.clone();
        mismatched_snapshot
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .observed_unix -= 1;
        assert!(
            mismatched_snapshot
                .require_payment_ready(Some("0.001"))
                .is_err()
        );

        let mut nonzero_fee = green.clone();
        nonzero_fee.wallet_fee_hac = "0.001".into();
        assert!(nonzero_fee.require_payment_ready(Some("0.001")).is_err());

        let mut invalid_height = green.clone();
        invalid_height
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .next_height += 1;
        assert!(invalid_height.require_payment_ready(Some("0.001")).is_err());

        let mut missing_action = green.clone();
        missing_action
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .enabled_actions = vec![1, 2];
        assert!(missing_action.require_payment_ready(Some("0.001")).is_err());

        let mut missing_unilateral_exit = green.clone();
        missing_unilateral_exit
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .channel_unilateral_exit = false;
        assert!(
            missing_unilateral_exit
                .require_payment_ready(Some("0.001"))
                .is_err()
        );

        let mut missing_exit_evidence = green.clone();
        missing_exit_evidence
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .channel_unilateral_exit_evidence = None;
        assert!(
            missing_exit_evidence
                .require_payment_ready(Some("0.001"))
                .is_err()
        );

        let mut tampered_exit_evidence = green.clone();
        tampered_exit_evidence
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .channel_unilateral_exit_evidence
            .as_mut()
            .unwrap()
            .bytecode_sha3 = "33".repeat(32);
        assert!(
            tampered_exit_evidence
                .require_payment_ready(Some("0.001"))
                .is_err()
        );

        let mut tampered_live_evidence = green.clone();
        tampered_live_evidence
            .fullnode_capabilities
            .as_mut()
            .unwrap()
            .channel_unilateral_exit_evidence
            .as_mut()
            .unwrap()
            .on_chain_verification
            .contract_code_matches = false;
        assert!(
            tampered_live_evidence
                .require_payment_ready(Some("0.001"))
                .is_err()
        );

        let blocked: HubMainnetReadiness = serde_json::from_value(readiness_json(
            false,
            vec!["fullnode_capability_probe_failed"],
            1_000_000,
        ))
        .unwrap();
        assert!(blocked.require_payment_ready(Some("0.001")).is_err());

        let unsafe_cap: HubMainnetReadiness = serde_json::from_value(readiness_json(
            true,
            vec![],
            MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU + 1,
        ))
        .unwrap();
        assert!(unsafe_cap.require_payment_ready(Some("0.001")).is_err());

        let mut unsafe_channel_cap = green.clone();
        unsafe_channel_cap.max_channel_funding_hac_zhu =
            MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU + 1;
        assert!(
            unsafe_channel_cap
                .require_payment_ready(Some("0.001"))
                .is_err()
        );

        let unusable_cap: HubMainnetReadiness =
            serde_json::from_value(readiness_json(true, vec![], ZHU_PER_MILLIMEI - 1)).unwrap();
        assert!(unusable_cap.require_payment_ready(Some("0.001")).is_err());
    }

    #[tokio::test]
    async fn bounded_mainnet_requires_the_explicit_wallet_policy() {
        let app = Router::new().route(
            "/v1/readiness/mainnet",
            get(|| async { Json(bounded_readiness_json()) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let url = format!("http://{address}");

        let default_client = L2HubClient::new_for_network(url.clone(), "mainnet");
        assert!(
            default_client
                .require_mainnet_payment_ready(Some("1"))
                .await
                .is_err()
        );

        let bounded_client = L2HubClient::new_for_trusted_bounded_mainnet_pilot(url, "mainnet");
        bounded_client
            .require_mainnet_payment_ready(Some("1"))
            .await
            .unwrap();
        assert!(
            bounded_client
                .require_mainnet_payment_ready(Some("1.001"))
                .await
                .is_err()
        );
        let bounded_close: HubMainnetReadiness =
            serde_json::from_value(bounded_readiness_json()).unwrap();
        bounded_close
            .require_cooperative_close_ready(false)
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn channel_open_rechecks_address_and_mainnet_funding_cap() {
        const HUB_ADDRESS: &str = "1Luek83YChwrkRYGUGpHmYVeC55tQz49Jo";
        let app = Router::new()
            .route(
                "/v1/health",
                get(|| async { Json(health_json(HUB_ADDRESS)) }),
            )
            .route(
                "/v1/readiness/mainnet",
                get(|| async { Json(readiness_json(true, vec![], 500_000)) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = L2HubClient::new_for_network(format!("http://{address}"), "mainnet");

        client
            .require_channel_open_ready(HUB_ADDRESS, "0.005")
            .await
            .unwrap();
        assert!(
            client
                .require_channel_open_ready("1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW", "0.005")
                .await
                .unwrap_err()
                .to_string()
                .contains("address changed")
        );
        assert!(
            client
                .require_channel_open_ready(HUB_ADDRESS, "0.006")
                .await
                .unwrap_err()
                .to_string()
                .contains("funding exceeds")
        );
        server.abort();
    }
    #[tokio::test]
    async fn invalid_readiness_response_is_never_treated_as_green() {
        let app = Router::new().route("/v1/readiness/mainnet", get(|| async { "not-json" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let error = L2HubClient::new(format!("http://{address}"))
            .require_mainnet_payment_ready(Some("0.001"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid JSON"));
        server.abort();
    }

    #[tokio::test]
    async fn missing_readiness_endpoint_is_never_treated_as_green() {
        let app = Router::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let error = L2HubClient::new(format!("http://{address}"))
            .require_mainnet_payment_ready(Some("0.001"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("404"));
        server.abort();
    }

    #[tokio::test]
    async fn readiness_is_refetched_and_a_downgrade_blocks_later_authority() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/v1/readiness/mainnet",
                get(|State(calls): State<Arc<AtomicUsize>>| async move {
                    let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                    Json(if first {
                        readiness_json(true, vec![], 1_000_000)
                    } else {
                        readiness_json(false, vec!["fullnode_capability_probe_failed"], 1_000_000)
                    })
                }),
            )
            .with_state(calls);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = L2HubClient::new(format!("http://{address}"));
        client
            .require_mainnet_payment_ready(Some("0.001"))
            .await
            .unwrap();
        assert!(
            client
                .require_mainnet_payment_ready(Some("0.001"))
                .await
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn oversized_hub_json_is_rejected() {
        let body = "x".repeat(MAX_HUB_JSON_BYTES + 1);
        let app = Router::new().route(
            "/v1/health",
            get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let error = L2HubClient::new(format!("http://{address}"))
            .health()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("response exceeds"));
        server.abort();
    }
}
