mod authorization_service;
mod dapp_service;
mod network_binding;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use protocol::transaction;
use sys::ToHex;
use zeroize::Zeroize;

use crate::account::WalletAccount;
use crate::airgap::{
    AIRGAP_CLASSIC_L1_TX_TYPE, AIRGAP_VERSION, AirgapEnvelope, AirgapInspection, AirgapParseResult,
    AirgapPrepareResult, AirgapSignResult, AirgapSigned, AirgapUnsigned, canonical_airgap_summary,
    canonical_airgap_tx_type, canonicalize_airgap_amount, encode_envelope_qr,
    parse_airgap_qr_parts, parse_airgap_qr_text,
};
pub use crate::assets::AssetSummary;
use crate::assets::{AssetService, DiamondMetadataReader};
use crate::bills::{BillEntry, BillStore};
use crate::channel::{ChannelInfo, derive_channel_id, query_channel};
use crate::error::{WalletError, WalletResult};
use crate::hardware::{HardwareSigningMode, SigningContext, check_signing_allowed_in_context};
use crate::hip23::{
    BalanceFloorInput, HeightScopeInput, Hip23PatternCheck, Hip23SendCheck, Type3CheckInput,
    is_valid_hacash_address, validate_all_patterns, validate_simple_l1_send,
};

use crate::dapp::DappSession;
use crate::dust_whisper::{
    DustWhisperSettings, RelayHealthStatus, relay_health as whisper_relay_health,
    submit_tx_hex as whisper_submit_tx_hex, whisper_fallback_notice,
};
use crate::fast_pay::{
    DEFAULT_CHANNEL_DEPOSIT_MEI, FastPayStatus, HubDiscoveryReport, apply_discovered_hub,
    discover_all_hubs, discover_healthy_hub, evaluate_fast_pay,
};
use crate::history::{TxHistory, TxRecord, TxStatus};
use crate::l2_hub::{FastPayExecution, FastPayInboxItem, HubHealth, L2HubClient};
use crate::node::NodeClient;
use crate::node_discovery::{NodeDiscoveryReport, NodeDiscoverySnapshot, discover_node_snapshot};
use crate::payment::{PaymentPlan, PaymentRail, PaymentRouter};
use crate::privacy::{PrivacySettings, mask_address, mask_amount, mask_hash};
use crate::security::{SecurityProfile, UnlockContext, check_send_policy};
use crate::settings::WalletSettings;
use crate::unlock_guard::UnlockGuard;
use crate::vault::{EncryptedVault, VaultMetaSnapshot, default_vault_path};
use crate::webauthn::WebAuthnGate;

const MAX_UNLOCK_LIFETIME: Duration = Duration::from_secs(15 * 60);
const COLD_VAULT_UNLOCK_LIFETIME: Duration = Duration::from_secs(2 * 60);
/// How long the outgoing authenticator's approval of its own replacement stays
/// usable. Short enough that it cannot be harvested and used much later.
const WEBAUTHN_REPLACEMENT_APPROVAL_TTL: Duration = Duration::from_secs(120);

pub struct WalletService {
    vault_path: PathBuf,
    vault_cache: Option<EncryptedVault>,
    vault_meta: Option<VaultMetaSnapshot>,
    node: NodeClient,
    network_binding: Option<network_binding::CachedNetworkBinding>,
    network_mode: String,
    router: PaymentRouter,
    profile: SecurityProfile,
    settings: WalletSettings,
    bills: BillStore,
    history: TxHistory,
    webauthn: WebAuthnGate,
    unlock_guard: UnlockGuard,
    /// Separate backoff for keystore-password attempts, so the wallet can never
    /// be used as a fast offline oracle against a Quantum keystore file.
    quantum_keystore_guard: UnlockGuard,
    /// Set only by a verified assertion from the *currently registered*
    /// authenticator, and consumed by the next registration. Replacing a second
    /// factor is otherwise a way to swap the factor out with the passphrase only.
    webauthn_replacement_approved_at: Option<Instant>,
    assets: AssetService,
    quantum_keystore_mem: Option<String>,
    unlocked: Option<UnlockedSession>,
    dapp_session: DappSession,
}

enum SessionKey {
    Signing(WalletAccount),
    /// Address-only presentation state after a cold signing attempt. No secret
    /// or signing capability remains; explicit unlock is required to sign again.
    Exhausted,
    WatchOnly,
}

struct UnlockedSession {
    address: String,
    key: SessionKey,
    /// Last accepted activity for the idle timeout.
    unlocked_at: Instant,
    /// Hard upper bound. Renderer activity can never move this deadline.
    absolute_deadline: Instant,
    /// Set only by `webauthn_auth_finish`. never trusted from IPC/UI flags.
    webauthn_verified: bool,
    /// Set only by `finish_native_biometric` after OS verification.
    biometric_verified: bool,
    pending_biometric_nonce: Option<String>,
    authorization: authorization_service::SessionAuthorization,
    quantum_file_key: Option<crate::quantum_vault::QuantumFileKey>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletStatus {
    pub has_wallet: bool,
    pub locked: bool,
    pub signing_available: bool,
    pub address: Option<String>,
    pub security_profile: String,
    pub node_url: String,
    pub network_mode: String,
    pub l2_enabled: bool,
    pub l2_hub_url: Option<String>,
    pub channel_id: Option<String>,
    pub webauthn_enabled: bool,
    pub l2_bill_count: usize,
    pub auto_lock_secs: u64,
    pub seconds_until_lock: Option<u64>,
    pub hardware_signing_mode: String,
    /// The amount at or above which a signature needs a second factor, already
    /// combined with the user's preference. The interface must display this rather
    /// than a constant of its own, or it will state the rule wrongly whenever the
    /// profile or the preference is not the default.
    pub require_second_factor_above_mei: u64,
    pub watch_only: bool,
    pub privacy: PrivacySettings,
    pub dust_whisper: DustWhisperSettings,
    pub fast_pay_state: String,
    pub fast_pay_message: String,
    /// `Some` when the key was derived from a guessable phrase. The UI must warn
    /// permanently and must not present this wallet as protected custody.
    pub legacy_key_derivation: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SendPreview {
    pub plan: PaymentPlan,
    pub from: String,
    pub to: String,
    pub amount_mei: f64,
    pub amount_wire: String,
    pub fee: String,
    pub hip23: Hip23SendCheck,
    pub fast_pay: FastPayStatus,
    pub send_options: crate::send_options::SendOptions,
}

/// The security-relevant fields the user reviewed before an unprepared Fast Pay send.
///
/// Decimal display values are deliberately excluded. `amount_wire` is the canonical
/// protocol amount produced by wallet-core, so the comparison cannot be changed by
/// renderer rounding or locale formatting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ReviewedSendExpectation {
    pub from: String,
    pub to: String,
    pub amount_wire: String,
    pub rail: PaymentRail,
    pub channel_id: Option<String>,
}

impl ReviewedSendExpectation {
    fn from_preview(preview: &SendPreview) -> Self {
        Self {
            from: preview.from.clone(),
            to: preview.to.clone(),
            amount_wire: preview.amount_wire.clone(),
            rail: preview.plan.rail,
            channel_id: preview.plan.channel_id.clone(),
        }
    }
}

fn require_exact_review(
    reviewed: &ReviewedSendExpectation,
    preview: &SendPreview,
) -> WalletResult<()> {
    let actual = ReviewedSendExpectation::from_preview(preview);
    require_exact_review_snapshot(reviewed, &actual)
}

fn require_exact_review_snapshot(
    reviewed: &ReviewedSendExpectation,
    actual: &ReviewedSendExpectation,
) -> WalletResult<()> {
    if reviewed.rail != PaymentRail::L2Fast || actual.rail != PaymentRail::L2Fast {
        return Err(WalletError::Policy(
            "the direct reviewed-send path is restricted to Fast Pay".into(),
        ));
    }
    if reviewed != actual {
        return Err(WalletError::Policy(
            "payment details or Fast Pay route changed after review; review the payment again"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod reviewed_send_tests {
    use super::*;

    fn fast_review() -> ReviewedSendExpectation {
        ReviewedSendExpectation {
            from: "1From".into(),
            to: "1To".into(),
            amount_wire: "12:248".into(),
            rail: PaymentRail::L2Fast,
            channel_id: Some("channel-1".into()),
        }
    }

    #[test]
    fn exact_fast_pay_review_is_accepted() {
        let reviewed = fast_review();
        assert!(require_exact_review_snapshot(&reviewed, &reviewed).is_ok());
    }

    #[test]
    fn recipient_amount_wallet_and_channel_drift_fail_closed() {
        let reviewed = fast_review();

        let mut different_from = reviewed.clone();
        different_from.from = "1OtherFrom".into();
        let mut different_to = reviewed.clone();
        different_to.to = "1OtherTo".into();
        let mut different_amount = reviewed.clone();
        different_amount.amount_wire = "13:248".into();
        let mut different_channel = reviewed.clone();
        different_channel.channel_id = Some("channel-2".into());

        for changed in [
            different_from,
            different_to,
            different_amount,
            different_channel,
        ] {
            let error = require_exact_review_snapshot(&reviewed, &changed)
                .expect_err("review drift must be rejected");
            assert!(error.to_string().contains("changed after review"));
        }
    }

    #[test]
    fn direct_reviewed_path_rejects_a_rail_change() {
        let reviewed = fast_review();
        let mut on_chain = reviewed.clone();
        on_chain.rail = PaymentRail::L1OnChain;

        let error = require_exact_review_snapshot(&reviewed, &on_chain)
            .expect_err("Fast Pay review must not authorize on-chain execution");
        assert!(error.to_string().contains("restricted to Fast Pay"));

        let error = require_exact_review_snapshot(&on_chain, &on_chain)
            .expect_err("the direct path must not accept an L1 expectation");
        assert!(error.to_string().contains("restricted to Fast Pay"));
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SendResult {
    pub rail: PaymentRail,
    pub tx_hash: String,
    pub summary: String,
    pub pending: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelSetupPreview {
    pub channel_id: String,
    pub reuse_version: u64,
    pub left_address: String,
    pub right_address: String,
    pub left_deposit: String,
    pub right_deposit: String,
}

impl WalletService {
    pub fn new(node_url: Option<String>, l2_hub_url: Option<String>) -> WalletResult<Self> {
        crate::protocol_init::ensure_protocol_setup();
        let vault_path = default_vault_path();
        crate::vault::recover_wallet_migration(
            &vault_path,
            &crate::paths::quantum_keystore_path(),
            &crate::paths::settings_path(),
        )?;
        let mut settings = WalletSettings::load().unwrap_or_default();
        if let Some(url) = node_url {
            settings.node_url = url;
        }
        if let Some(hub) = l2_hub_url {
            settings.l2_hub_url = Some(hub);
        }
        settings.validate_and_normalize()?;
        let network_mode = std::env::var("HACASH_WALLET_NETWORK")
            .ok()
            .filter(|mode| matches!(mode.as_str(), "mainnet" | "testnet"))
            .unwrap_or_else(|| settings.network_mode.clone());
        // Keep one authoritative in-memory network. A runtime override must
        // reach the router and every signing boundary, not only status output.
        settings.network_mode = network_mode.clone();
        let profile = SecurityProfile::from_name(&settings.security_profile);
        let node = NodeClient::new(settings.node_url.clone())?;
        // L2 bills are authoritative recovery/dispute evidence. A corrupt or
        // unreadable store must stop wallet initialization instead of silently
        // falling back to the on-chain funding distribution.
        let bills = BillStore::load()?;
        let history = TxHistory::load().unwrap_or_default();
        let router = PaymentRouter::new(node.clone(), settings.clone(), bills.clone());
        Ok(Self {
            vault_path,
            vault_cache: None,
            vault_meta: None,
            node,
            network_binding: None,
            network_mode,
            router,
            profile,
            settings,
            bills,
            history,
            webauthn: WebAuthnGate::new()?,
            unlock_guard: UnlockGuard::default(),
            quantum_keystore_guard: UnlockGuard::default(),
            webauthn_replacement_approved_at: None,
            assets: AssetService::default(),
            quantum_keystore_mem: None,
            unlocked: None,
            dapp_session: DappSession::new(),
        })
    }

    pub fn status(&mut self) -> WalletStatus {
        // Status is a security boundary, not a passive snapshot. Enforce the
        // deadline before exposing any session-derived state to IPC callers.
        self.touch_auto_lock();
        let signing_vault = self.vault_path.exists();
        let has_wallet = signing_vault || self.settings.watch_only_address.is_some();
        let meta = self
            .vault_meta
            .as_ref()
            .cloned()
            .or_else(|| self.read_vault().ok().map(|v| v.meta_snapshot()));
        let (effective_profile, effective_hardware_mode, vault_webauthn) =
            effective_policy_for_status(meta.as_ref(), signing_vault);
        let watch_only = if signing_vault {
            false
        } else {
            effective_hardware_mode == HardwareSigningMode::WatchOnly.as_str()
                || self.settings.watch_only_address.is_some()
        };
        let now = Instant::now();
        let seconds_until_lock = self.unlocked.as_ref().and_then(|session| {
            if matches!(session.key, SessionKey::Exhausted) {
                return None;
            }
            let idle_remaining = effective_profile
                .auto_lock_secs
                .saturating_sub(now.saturating_duration_since(session.unlocked_at).as_secs());
            let absolute_remaining = session
                .absolute_deadline
                .saturating_duration_since(now)
                .as_secs();
            Some(idle_remaining.min(absolute_remaining))
        });
        let fast_pay = self.fast_pay_status_sync();
        WalletStatus {
            has_wallet,
            locked: self.unlocked.is_none(),
            signing_available: self
                .unlocked
                .as_ref()
                .is_some_and(|session| matches!(session.key, SessionKey::Signing(_))),
            address: self
                .unlocked
                .as_ref()
                .map(|s| s.address.clone())
                .or_else(|| meta.as_ref().map(|m| m.address.clone()))
                .or_else(|| self.settings.watch_only_address.clone()),
            security_profile: effective_profile.name.clone(),
            // The ceiling comes from the vault-authenticated profile, not from
            // self.profile, so a tampered settings file cannot inflate the number the
            // user is shown. Same formula as enforcement.
            require_second_factor_above_mei: crate::security::effective_second_factor_threshold(
                effective_profile.require_second_factor_above_mei,
                self.settings.require_second_factor_above_mei,
            ),
            node_url: self.node.base_url().to_string(),
            network_mode: self.network_mode.clone(),
            l2_enabled: self.router.has_l2_hub(),
            l2_hub_url: self.settings.l2_hub_url.clone(),
            channel_id: self.settings.channel_id_hex.clone(),
            webauthn_enabled: vault_webauthn,
            l2_bill_count: self.bills.count(),
            auto_lock_secs: effective_profile.auto_lock_secs,
            seconds_until_lock,
            hardware_signing_mode: effective_hardware_mode,
            watch_only,
            privacy: self.settings.privacy.clone(),
            dust_whisper: self.settings.dust_whisper.clone(),
            fast_pay_state: fast_pay.state.as_str().to_string(),
            fast_pay_message: fast_pay.message,
            legacy_key_derivation: meta.as_ref().and_then(|m| m.legacy_key_derivation.clone()),
        }
    }

    fn fast_pay_status_sync(&self) -> FastPayStatus {
        if self.settings.l2_hub_url.is_some() {
            return FastPayStatus::checking();
        }
        FastPayStatus::no_provider()
    }

    pub fn get_settings(&self) -> WalletSettings {
        let mut settings = self.settings.clone();
        if self.vault_path.exists() {
            let meta = self.read_vault().ok().map(|vault| vault.meta_snapshot());
            let (profile, hardware_mode, webauthn_enabled) =
                effective_policy_for_status(meta.as_ref(), true);
            settings.security_profile = profile.name;
            settings.hardware_signing_mode = hardware_mode;
            settings.webauthn_enabled = webauthn_enabled;
            settings.watch_only_address = None;
            if settings.hardware_signing_mode == HardwareSigningMode::AirgapOnly.as_str() {
                settings.biometric_unlock_enabled = false;
            }
        }
        settings
    }

    pub async fn ping_node(&self) -> WalletResult<serde_json::Value> {
        self.node.ping().await
    }

    pub fn node_discovery_snapshot(&self) -> NodeDiscoverySnapshot {
        let active_node = self.node.base_url().to_owned();
        let network_mode = self.network_mode.clone();
        let mut settings = self.settings.clone();
        settings.node_url = active_node.clone();
        settings.network_mode = network_mode.clone();
        NodeDiscoverySnapshot::new(settings, active_node, network_mode)
    }

    pub async fn discover_nodes(&self) -> NodeDiscoveryReport {
        discover_node_snapshot(&self.node_discovery_snapshot()).await
    }

    /// Commit failover from a completed discovery only when its full node
    /// configuration is still current. A user settings change always wins a
    /// race with an older background probe.
    pub fn commit_node_discovery(
        &mut self,
        snapshot: &NodeDiscoverySnapshot,
        mut report: NodeDiscoveryReport,
    ) -> WalletResult<NodeDiscoveryReport> {
        let config_unchanged = self.node.base_url() == snapshot.active_node
            && self.network_mode == snapshot.network_mode
            && self.settings.node_url == snapshot.settings.node_url
            && self.settings.node_fallback_urls == snapshot.settings.node_fallback_urls
            && self.settings.auto_node_failover == snapshot.settings.auto_node_failover;
        if !config_unchanged {
            report.active_node = self.node.base_url().to_owned();
            report.network_mode = self.network_mode.clone();
            report.switched = false;
            return Ok(report);
        }

        let current_ok = report
            .candidates
            .iter()
            .find(|candidate| candidate.url == snapshot.active_node)
            .is_some_and(|candidate| candidate.online && candidate.network_match);
        if current_ok || !snapshot.settings.auto_node_failover {
            return Ok(report);
        }

        let Some(next) = report
            .candidates
            .iter()
            .find(|candidate| candidate.online && candidate.network_match)
            .map(|candidate| candidate.url.clone())
        else {
            return Ok(report);
        };
        if next == snapshot.active_node {
            return Ok(report);
        }
        let next_node = NodeClient::new(next.clone())?;

        let previous = self.settings.node_url.clone();
        if !self.settings.node_fallback_urls.contains(&previous) {
            self.settings.node_fallback_urls.insert(0, previous);
            self.settings.node_fallback_urls.truncate(8);
        }
        self.settings.node_fallback_urls.retain(|url| url != &next);
        self.settings.node_url = next.clone();
        self.invalidate_network_binding();
        self.settings.save()?;
        self.node = next_node;
        self.assets.clear_cache();
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
        report.active_node = next;
        report.switched = true;
        Ok(report)
    }

    /// Select a verified fallback only when the active node is unavailable or on the wrong chain.
    pub async fn find_active_node(&mut self) -> WalletResult<NodeDiscoveryReport> {
        let snapshot = self.node_discovery_snapshot();
        let report = discover_node_snapshot(&snapshot).await;
        self.commit_node_discovery(&snapshot, report)
    }

    pub fn update_settings(&mut self, mut settings: WalletSettings) -> WalletResult<()> {
        if self.cold_vault_configured()? {
            self.profile = SecurityProfile::paranoid();
            self.settings.security_profile = self.profile.name.clone();
            self.settings.hardware_signing_mode = HardwareSigningMode::AirgapOnly.as_str().into();
            self.settings.biometric_unlock_enabled = false;
        }
        if settings.quantum_keystore_json.is_some() {
            return Err(WalletError::Policy(
                "quantum key material cannot be submitted through generic settings".into(),
            ));
        }
        let current = &self.settings;
        let sensitive_change = settings.security_profile != current.security_profile
            // Raising the threshold loosens the policy within the band the profile
            // allows, so it needs the same authority as changing the profile itself.
            || settings.require_second_factor_above_mei != current.require_second_factor_above_mei
            || settings.hardware_signing_mode != current.hardware_signing_mode
            || settings.webauthn_enabled != current.webauthn_enabled
            || settings.biometric_send_enabled != current.biometric_send_enabled
            || settings.biometric_unlock_enabled != current.biometric_unlock_enabled
            || settings.watch_only_address != current.watch_only_address
            || settings.channel_id_hex != current.channel_id_hex
            // Turning the bounded mainnet pilot ON chooses a settlement model in
            // which the money is only as safe as one Hub. That is the same class
            // of decision as changing the security profile, and it was the only
            // money-policy field on this struct that any unauthenticated caller
            // could flip - while changing a channel id, which decides far less,
            // already needed the authenticated path. Withdrawing consent is a
            // strict tightening and stays available here, so a user can always
            // step back out from a screen that cannot ask for a passphrase.
            || (settings.trusted_mainnet_fast_pay_pilot
                && !current.trusted_mainnet_fast_pay_pilot)
            || settings.quantum_mode != current.quantum_mode
            || settings.quantum_meta != current.quantum_meta;
        if sensitive_change {
            return Err(WalletError::Policy(
                "security and key settings require their dedicated authenticated command".into(),
            ));
        }

        // The IPC representation is intentionally redacted. Preserve any legacy value until the
        // authenticated unlock migration has moved it into quantum.keystore.enc.
        settings.quantum_keystore_json = current.quantum_keystore_json.clone();
        settings.validate_and_normalize()?;
        let node = NodeClient::new(settings.node_url.clone())?;
        settings.save()?;
        self.invalidate_network_binding();
        self.node = node;
        self.assets.clear_cache();
        if std::env::var("HACASH_WALLET_NETWORK").is_err() {
            self.network_mode = settings.network_mode.clone();
        }
        settings.network_mode = self.network_mode.clone();
        self.settings = settings;
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
        Ok(())
    }

    /// Wipe all local wallet data so a new wallet can be created on this device.
    pub fn reset_wallet(&mut self) -> WalletResult<()> {
        self.lock();
        crate::vault::discard_wallet_migration(
            &self.vault_path,
            &crate::paths::quantum_keystore_path(),
            &crate::paths::settings_path(),
        )?;
        let paths = [
            self.vault_path.clone(),
            crate::paths::settings_path(),
            crate::paths::bills_path(),
            crate::paths::history_path(),
            crate::paths::messenger_path(),
            crate::paths::quantum_keystore_path(),
            crate::paths::biometric_unlock_path(),
        ];
        for path in paths {
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| {
                    WalletError::Vault(format!("failed to remove {}: {e}", path.display()))
                })?;
            }
        }
        self.vault_cache = None;
        self.vault_meta = None;
        self.assets.clear_cache();
        self.quantum_keystore_mem = None;
        self.settings = WalletSettings::default();
        self.settings.save()?;
        self.bills = BillStore::default();
        self.history = TxHistory::default();
        self.invalidate_network_binding();
        self.node = NodeClient::new(self.settings.node_url.clone())?;
        self.network_mode = std::env::var("HACASH_WALLET_NETWORK")
            .ok()
            .filter(|mode| matches!(mode.as_str(), "mainnet" | "testnet"))
            .unwrap_or_else(|| self.settings.network_mode.clone());
        self.settings.network_mode = self.network_mode.clone();
        self.profile = SecurityProfile::from_name(&self.settings.security_profile);
        self.router =
            PaymentRouter::new(self.node.clone(), self.settings.clone(), self.bills.clone());
        Ok(())
    }

    pub fn create_wallet(&mut self, passphrase: &str) -> WalletResult<String> {
        if self.vault_path.exists() {
            return Err(WalletError::Vault("wallet already exists".into()));
        }
        validate_new_passphrase(passphrase)?;

        let account = WalletAccount::create_random()?;
        let address = account.address();
        let mut secret = account.secret_hex();
        let vault = EncryptedVault::encrypt(&secret, &address, passphrase, &self.profile.name)?;
        secret.zeroize();
        self.persist_vault(vault)?;
        self.settings.save()?;
        self.unlock(passphrase)?;
        Ok(address)
    }

    /// Import a 32-byte secret key.
    ///
    /// `expected_address` is required because a mistyped key is usually still a
    /// perfectly valid key, just a different one. Length checks cannot catch that:
    /// change one digit of a 64-character key and you silently land on someone
    /// else's empty address and conclude your funds are gone. Anyone importing a
    /// key is recovering a specific wallet and knows which.
    pub fn import_wallet(
        &mut self,
        seed: &str,
        passphrase: &str,
        expected_address: &str,
    ) -> WalletResult<String> {
        if self.vault_path.exists() {
            return Err(WalletError::Vault(
                "wallet already exists. remove vault first".into(),
            ));
        }
        if seed.trim().is_empty() {
            return Err(WalletError::Vault("seed is required".into()));
        }
        validate_new_passphrase(passphrase)?;
        // Whitespace cannot be part of a hex key, so ignoring it is unambiguous and
        // lets a key pasted across lines work instead of failing confusingly.
        let compact: String = seed.chars().filter(|c| !c.is_whitespace()).collect();
        let all_hex = compact.chars().all(|c| c.is_ascii_hexdigit());
        // Report a near-miss key as a near-miss key. Calling it a brainwallet phrase
        // would push the user toward hashing it, which silently produces a valid
        // wallet at a different address than the one they are trying to recover.
        if all_hex && compact.chars().count() != 64 {
            return Err(WalletError::Vault(format!(
                "a private key must be exactly 64 hex characters; this is {}. check for missing or extra characters",
                compact.chars().count()
            )));
        }
        // Anything else would previously fall through to a single unsalted SHA-256
        // of the text, producing a brainwallet: a key anyone who guesses the phrase
        // can reproduce. That derivation is no longer reachable from this wallet at
        // all, so say plainly what is required instead of offering an alternative.
        if !all_hex {
            return Err(WalletError::Vault(
                "a private key is exactly 64 hex characters. this wallet cannot derive a key from a phrase or passphrase"
                    .into(),
            ));
        }
        let expected_address = expected_address.trim();
        if expected_address.is_empty() {
            return Err(WalletError::Vault(
                "the address of the wallet you are importing is required".into(),
            ));
        }
        crate::address::require_address_for_network(expected_address, &self.network_mode)?;
        let account = WalletAccount::from_secret_hex(&compact)?;
        let address = account.address();
        if address != expected_address {
            return Err(WalletError::Vault(
                "this private key does not belong to that address. check both for typos".into(),
            ));
        }
        let mut secret = account.secret_hex();
        let vault = EncryptedVault::encrypt(&secret, &address, passphrase, &self.profile.name)?;
        secret.zeroize();
        self.persist_vault(vault)?;
        self.settings.save()?;
        self.unlock(passphrase)?;
        Ok(address)
    }

    /// `Some(marker)` when this wallet's key came from a guessable phrase.
    pub fn legacy_key_derivation(&self) -> Option<String> {
        if let Some(meta) = self.vault_meta.as_ref() {
            return meta.legacy_key_derivation.clone();
        }
        if !self.vault_path.exists() {
            return None;
        }
        self.read_vault()
            .ok()
            .and_then(|vault| vault.legacy_key_derivation().map(str::to_owned))
    }

    pub fn export_backup(&self, passphrase: &str) -> WalletResult<String> {
        if !self.vault_path.exists() {
            return Err(WalletError::NoWallet);
        }
        let vault = self.read_vault()?;
        let mut secret = vault.decrypt_verified_secret(passphrase)?;
        secret.zeroize();
        vault.export_json()
    }

    /// Restore wallet from an encrypted backup JSON export (same passphrase as at export time).
    pub fn import_backup(&mut self, json: &str, passphrase: &str) -> WalletResult<String> {
        if self.vault_path.exists() {
            return Err(WalletError::Vault(
                "wallet already exists. remove vault first".into(),
            ));
        }
        if json.trim().is_empty() || passphrase.len() < 8 {
            return Err(WalletError::Vault(
                "backup JSON and passphrase (min 8 chars) required".into(),
            ));
        }
        let vault = EncryptedVault::from_export_json(json.trim())?;
        let mut secret = vault
            .decrypt_verified_secret(passphrase)
            .map_err(|_| WalletError::InvalidPassphrase)?;
        secret.zeroize();
        let snap = vault.meta_snapshot();
        let address = snap.address.clone();
        self.profile = SecurityProfile::from_name(&snap.security_profile);
        self.settings.security_profile = snap.security_profile;
        self.settings.hardware_signing_mode = snap.hardware_signing_mode;
        self.settings.webauthn_enabled = snap.webauthn_credential_b64.is_some();
        if self.settings.hardware_signing_mode == HardwareSigningMode::AirgapOnly.as_str() {
            self.settings.biometric_unlock_enabled = false;
        }
        self.persist_vault(vault)?;
        self.settings.save()?;
        self.unlock(passphrase)?;
        Ok(address)
    }

    pub fn biometric_unlock_configured(&self) -> bool {
        !self.cold_vault_configured().unwrap_or(true) && crate::biometric_unlock::is_configured()
    }

    pub fn verify_wallet_passphrase(&mut self, passphrase: &str) -> WalletResult<()> {
        self.unlock_guard.check_allowed()?;
        let vault = self.vault_snapshot()?;
        match vault.decrypt_verified_secret(passphrase) {
            Ok(mut secret) => {
                secret.zeroize();
                self.unlock_guard.record_success();
                Ok(())
            }
            Err(error) => {
                self.unlock_guard.record_failure();
                Err(error)
            }
        }
    }

    pub fn set_biometric_unlock_enabled(&mut self, enabled: bool) -> WalletResult<()> {
        if enabled && self.cold_vault_configured()? {
            return Err(WalletError::Policy(
                "cold vault cannot store a biometric unlock secret".into(),
            ));
        }
        if !enabled {
            crate::biometric_unlock::clear()?;
        }
        self.settings.biometric_unlock_enabled = enabled;
        self.settings.save()
    }

    pub fn enable_biometric_unlock(&mut self, _passphrase: &str) -> WalletResult<()> {
        Err(WalletError::Policy(
            "biometric unlock secrets must be stored by the operating-system keystore".into(),
        ))
    }

    pub fn disable_biometric_unlock(&mut self) -> WalletResult<()> {
        crate::biometric_unlock::clear()?;
        self.settings.biometric_unlock_enabled = false;
        self.settings.save()?;
        Ok(())
    }

    pub fn unlock_passphrase_for_biometric(&self) -> WalletResult<String> {
        Err(WalletError::Policy(
            "biometric unlock secrets must be loaded by the operating-system keystore".into(),
        ))
    }

    pub fn change_passphrase(
        &mut self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> WalletResult<()> {
        validate_new_passphrase(new_passphrase)?;

        self.verify_wallet_passphrase(old_passphrase)?;
        let current_vault = self.vault_snapshot()?;
        let target_profile =
            SecurityProfile::from_name(&current_vault.security_profile_for_migration());
        let (hardware_mode, credential) = current_vault.policy_for_migration()?;
        self.migrate_vault_encryption(
            old_passphrase,
            new_passphrase,
            target_profile,
            HardwareSigningMode::from_name(&hardware_mode),
            credential.as_deref(),
            true,
        )
    }

    /// Choose the amount at or above which a signature needs a second factor.
    ///
    /// `chosen` of `None` restores the profile's own value. Anything above the profile
    /// ceiling is stored as given but has no effect, because
    /// [`Self::second_factor_threshold_mei`] takes the minimum; that is deliberate, so a
    /// stricter profile cannot be silently loosened by a stale preference.
    ///
    /// This needs the passphrase for the same reason changing the profile does: raising
    /// the amount widens the range of payments that need no confirmation. `update_settings`
    /// refuses the change so it can only happen here.
    pub fn set_second_factor_threshold(
        &mut self,
        current_passphrase: &str,
        chosen: Option<u64>,
    ) -> WalletResult<()> {
        if !self.vault_path.exists() {
            return Err(WalletError::NoWallet);
        }
        if chosen == Some(0) {
            return Err(WalletError::Policy(
                "the second-factor amount must be at least 1 HAC; every smaller amount already rounds up to it"
                    .into(),
            ));
        }
        self.verify_wallet_passphrase(current_passphrase)?;
        self.settings.require_second_factor_above_mei = chosen;
        self.settings.save()?;
        // A ticket prepared a moment ago carries the requirement computed under the old
        // threshold. Tightening the policy must not leave an already-authorized, or
        // authorization-free, operation waiting to execute under the looser rule.
        self.clear_prepared_operation();
        Ok(())
    }

    /// Give or withdraw consent to the bounded mainnet Fast Pay pilot.
    ///
    /// Its own authenticated command, because `update_settings` refuses to turn
    /// this on: it selects the settlement model every later mainnet payment and
    /// channel open is judged under, and the wallet asks for at least as much
    /// authority to change that as it does to change a channel id.
    pub fn set_trusted_mainnet_fast_pay_pilot(
        &mut self,
        current_passphrase: &str,
        consented: bool,
    ) -> WalletResult<()> {
        if !self.vault_path.exists() {
            return Err(WalletError::NoWallet);
        }
        self.verify_wallet_passphrase(current_passphrase)?;
        self.settings.trusted_mainnet_fast_pay_pilot = consented;
        self.settings.save()?;
        // The router holds its own copy of the settings and is what the Send
        // screen asks for a rail. Saving the file without refreshing it here
        // would leave the consent decided and unread until the next restart -
        // the exact shape of the bug this release was written to fix.
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
        // A ticket prepared a moment ago was reviewed under the old settlement
        // policy. Changing the policy must not leave an already-authorized
        // operation waiting to execute under the other one.
        self.clear_prepared_operation();
        Ok(())
    }

    pub fn change_security_profile(
        &mut self,
        current_passphrase: &str,
        requested_profile: SecurityProfile,
    ) -> WalletResult<()> {
        if !matches!(requested_profile.name.as_str(), "balanced" | "paranoid") {
            return Err(WalletError::Policy("unknown security profile".into()));
        }
        if !self.vault_path.exists() {
            return Err(WalletError::NoWallet);
        }
        self.verify_wallet_passphrase(current_passphrase)?;
        let target_profile = SecurityProfile::from_name(&requested_profile.name);
        let current_vault = self.vault_snapshot()?;
        let (hardware_mode, credential) = current_vault.policy_for_migration()?;
        let hardware_mode = HardwareSigningMode::from_name(&hardware_mode);
        if hardware_mode == HardwareSigningMode::AirgapOnly
            && target_profile.name != SecurityProfile::paranoid().name
        {
            return Err(WalletError::Policy(
                "cold vault security profile cannot be downgraded".into(),
            ));
        }
        self.migrate_vault_encryption(
            current_passphrase,
            current_passphrase,
            target_profile,
            hardware_mode,
            credential.as_deref(),
            false,
        )
    }

    fn migrate_vault_encryption(
        &mut self,
        current_passphrase: &str,
        new_passphrase: &str,
        mut target_profile: SecurityProfile,
        target_hardware_mode: HardwareSigningMode,
        target_webauthn_credential: Option<&str>,
        disable_biometric_unlock: bool,
    ) -> WalletResult<()> {
        let current_vault = self.vault_snapshot()?;
        let (current_hardware_mode, _) = current_vault.policy_for_migration()?;
        let current_is_cold = current_hardware_mode == HardwareSigningMode::AirgapOnly.as_str();
        let target_is_cold = target_hardware_mode == HardwareSigningMode::AirgapOnly;
        if current_is_cold && !target_is_cold {
            return Err(WalletError::Policy(
                "cold vault mode is irreversible for this vault".into(),
            ));
        }
        if target_is_cold {
            target_profile = SecurityProfile::paranoid();
        }
        let disable_biometric_unlock = disable_biometric_unlock || target_is_cold;
        let replacement_vault = current_vault.reencrypted_with_policy(
            current_passphrase,
            new_passphrase,
            &target_profile.name,
            target_hardware_mode.as_str(),
            target_webauthn_credential,
        )?;

        let quantum_path = crate::paths::quantum_keystore_path();
        // Once a vault is cold, its legacy Quantum sidecar is quarantined. Wallet
        // passphrase/profile changes must never derive its file key or decrypt it.
        let quantum_json = if current_is_cold {
            None
        } else if quantum_path.exists() {
            let current_quantum_key = crate::quantum_vault::QuantumFileKey::derive(
                current_passphrase,
                current_vault.salt(),
            )?;
            Some(
                crate::quantum_vault::load_encrypted(&current_quantum_key)?
                    .ok_or_else(|| WalletError::Vault("quantum keystore disappeared".into()))?,
            )
        } else {
            self.settings.quantum_keystore_json.clone()
        };

        let replacement_quantum_key = if current_is_cold {
            None
        } else {
            Some(crate::quantum_vault::QuantumFileKey::derive(
                new_passphrase,
                replacement_vault.salt(),
            )?)
        };
        let replacement_quantum = match (quantum_json.as_deref(), &replacement_quantum_key) {
            (Some(json), Some(key)) => Some(crate::quantum_vault::encode_encrypted(key, json)?),
            _ => None,
        };

        let mut replacement_settings = self.settings.clone();
        replacement_settings.security_profile = target_profile.name.clone();
        replacement_settings.hardware_signing_mode = target_hardware_mode.as_str().into();
        replacement_settings.webauthn_enabled = target_webauthn_credential.is_some();
        replacement_settings.watch_only_address = None;
        if target_is_cold
            && let Some(mut legacy_secret) = replacement_settings.quantum_keystore_json.take()
        {
            legacy_secret.zeroize();
        }
        if quantum_json.is_some() {
            replacement_settings.quantum_keystore_json = None;
            if let Some(meta) = quantum_json
                .as_deref()
                .and_then(crate::quantum::quantum_meta_from_json)
            {
                replacement_settings.quantum_meta = Some(meta);
            }
        }
        if disable_biometric_unlock {
            // Removing the retired local cache before commit is fail-safe. A failed migration may
            // require biometric setup again, but can never leave an old passphrase recoverable.
            crate::biometric_unlock::clear()?;
            replacement_settings.biometric_unlock_enabled = false;
        }
        replacement_settings.validate_and_normalize()?;
        let replacement_settings_bytes = serde_json::to_vec(&replacement_settings)
            .map_err(|error| WalletError::Vault(error.to_string()))?;

        let commit_result = crate::vault::commit_wallet_migration(
            &self.vault_path,
            &replacement_vault,
            &quantum_path,
            replacement_quantum.as_deref(),
            &crate::paths::settings_path(),
            Some(&replacement_settings_bytes),
        );
        if let Err(error) = commit_result {
            // If the filesystem could not complete or roll back, discard every in-memory key.
            // Startup recovery will finish the journal before any wallet state is loaded again.
            self.lock();
            self.vault_cache = None;
            self.vault_meta = None;
            return Err(error);
        }

        if let Some(legacy_secret) = self.settings.quantum_keystore_json.as_mut() {
            legacy_secret.zeroize();
        }
        self.vault_meta = Some(replacement_vault.meta_snapshot());
        self.vault_cache = Some(replacement_vault);
        self.settings = replacement_settings;
        self.profile = target_profile;
        let exhausted = self
            .unlocked
            .as_ref()
            .is_some_and(|session| matches!(session.key, SessionKey::Exhausted));
        self.quantum_keystore_mem = if exhausted || target_is_cold {
            None
        } else {
            quantum_json
        };
        if let Some(session) = &mut self.unlocked {
            if exhausted || target_is_cold {
                session.quantum_file_key = None;
            } else {
                session.quantum_file_key = replacement_quantum_key;
            }
            let now = Instant::now();
            session.unlocked_at = now;
            if target_is_cold {
                let cold_deadline = now + COLD_VAULT_UNLOCK_LIFETIME;
                session.absolute_deadline = session.absolute_deadline.min(cold_deadline);
            }
            session.webauthn_verified = false;
            session.biometric_verified = false;
            session.pending_biometric_nonce = None;
            session.authorization.clear();
        }
        self.dapp_session.clear();
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
        Ok(())
    }

    pub fn unlock(&mut self, passphrase: &str) -> WalletResult<String> {
        if self
            .unlocked
            .as_ref()
            .is_some_and(|session| matches!(session.key, SessionKey::Exhausted))
        {
            self.unlocked = None;
        } else if self.unlocked.is_some() {
            return Err(WalletError::AlreadyUnlocked);
        }
        self.unlock_guard.check_allowed()?;
        let mut vault = self.vault_snapshot()?;
        let decrypt_result = vault.decrypt_verified_secret(passphrase);
        if decrypt_result.is_err() {
            self.unlock_guard.record_failure();
            return Err(WalletError::InvalidPassphrase);
        }
        self.unlock_guard.record_success();
        let mut secret = decrypt_result?;
        let account = WalletAccount::from_secret_hex(&secret)?;
        secret.zeroize();
        let address = account.address();
        if vault.metadata.version < crate::vault::VAULT_VERSION_LATEST {
            let target_profile =
                SecurityProfile::from_name(&vault.security_profile_for_migration());
            self.migrate_vault_encryption(
                passphrase,
                passphrase,
                target_profile,
                HardwareSigningMode::WebAuthnGate,
                None,
                false,
            )?;
            vault = self.vault_snapshot()?;
        }
        vault.validate_authenticated_policy()?;
        self.profile = SecurityProfile::from_name(&vault.metadata.security_profile);
        self.settings.security_profile = vault.metadata.security_profile.clone();
        self.settings.hardware_signing_mode = vault.metadata.hardware_signing_mode.clone();
        self.settings.webauthn_enabled = vault.metadata.webauthn_credential_b64.is_some();
        self.settings.watch_only_address = None;
        let signing_mode = HardwareSigningMode::from_name(&vault.metadata.hardware_signing_mode);
        if signing_mode == HardwareSigningMode::AirgapOnly {
            if let Some(legacy_secret) = self.settings.quantum_keystore_json.as_mut() {
                legacy_secret.zeroize();
            }
            self.settings.quantum_keystore_json = None;
            crate::biometric_unlock::clear()?;
            self.settings.biometric_unlock_enabled = false;
        }
        self.settings.save()?;
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
        self.assets.clear_cache();
        let (qkey, qks) = if signing_mode == HardwareSigningMode::AirgapOnly {
            // Cold Vault is intentionally a classic Type 2 signer. Do not even
            // derive the Quantum sidecar key, much less read/decrypt the file.
            (None, None)
        } else {
            let qkey = crate::quantum_vault::QuantumFileKey::derive(passphrase, vault.salt())?;
            let mut qks = crate::quantum_vault::load_encrypted(&qkey)?;
            if qks.is_none()
                && let Some(legacy) = self.settings.quantum_keystore_json.take()
            {
                crate::quantum_vault::save_encrypted(&qkey, &legacy)?;
                if let Some(meta) = crate::quantum::quantum_meta_from_json(&legacy) {
                    self.settings.quantum_meta = Some(meta);
                }
                self.settings.save()?;
                qks = Some(legacy);
            }
            (Some(qkey), qks)
        };
        self.quantum_keystore_mem = qks;
        let now = Instant::now();
        self.unlocked = Some(UnlockedSession {
            address: address.clone(),
            key: SessionKey::Signing(account),
            unlocked_at: now,
            absolute_deadline: now + maximum_unlock_lifetime(signing_mode),
            webauthn_verified: false,
            biometric_verified: false,
            pending_biometric_nonce: None,
            authorization: authorization_service::SessionAuthorization::default(),
            quantum_file_key: qkey,
        });
        Ok(address)
    }

    /// Import a watch-only wallet (Sparrow-style). monitor balance, no local signing.
    pub fn import_watch_only(&mut self, address: &str) -> WalletResult<String> {
        let addr = address.trim();
        if !is_valid_hacash_address(addr) {
            return Err(WalletError::Vault("invalid Hacash address".into()));
        }
        if self.vault_path.exists() {
            return Err(WalletError::Vault(
                "signing wallet exists. remove vault before watch-only import".into(),
            ));
        }
        self.settings.watch_only_address = Some(addr.to_owned());
        self.settings.hardware_signing_mode = HardwareSigningMode::WatchOnly.as_str().into();
        self.settings.save()?;
        self.open_watch_only()
    }

    /// Open watch-only session (no passphrase).
    pub fn open_watch_only(&mut self) -> WalletResult<String> {
        if self.unlocked.is_some() {
            return Err(WalletError::AlreadyUnlocked);
        }
        let address = self
            .settings
            .watch_only_address
            .clone()
            .ok_or(WalletError::NoWallet)?;
        let now = Instant::now();
        self.unlocked = Some(UnlockedSession {
            address: address.clone(),
            key: SessionKey::WatchOnly,
            unlocked_at: now,
            absolute_deadline: now + maximum_unlock_lifetime(HardwareSigningMode::WatchOnly),
            webauthn_verified: false,
            biometric_verified: false,
            pending_biometric_nonce: None,
            authorization: authorization_service::SessionAuthorization::default(),
            quantum_file_key: None,
        });
        Ok(address)
    }

    pub fn set_hardware_signing_mode(&mut self, mode: HardwareSigningMode) -> WalletResult<()> {
        if self.vault_path.exists() {
            let vault = self.read_vault()?;
            if vault.metadata.version >= crate::vault::VAULT_VERSION_LATEST
                && vault.metadata.hardware_signing_mode == mode.as_str()
            {
                self.settings.hardware_signing_mode = mode.as_str().into();
                if mode == HardwareSigningMode::AirgapOnly {
                    crate::biometric_unlock::clear()?;
                    self.profile = SecurityProfile::paranoid();
                    self.settings.security_profile = self.profile.name.clone();
                    self.settings.biometric_unlock_enabled = false;
                    self.clear_session_authorizations();
                }
                self.settings.save()?;
                return Ok(());
            }
            return Err(WalletError::Policy(
                "changing a signing wallet hardware mode requires current-passphrase authentication"
                    .into(),
            ));
        }
        if mode == HardwareSigningMode::AirgapOnly {
            return Err(WalletError::Policy(
                "cold vault mode requires an existing signing vault and passphrase authentication"
                    .into(),
            ));
        }
        if mode == HardwareSigningMode::WatchOnly && self.settings.watch_only_address.is_none() {
            return Err(WalletError::Vault(
                "watch-only mode requires a watch-only imported address".into(),
            ));
        }
        self.settings.hardware_signing_mode = mode.as_str().into();
        self.settings.save()?;
        Ok(())
    }

    pub fn change_hardware_signing_mode(
        &mut self,
        current_passphrase: &str,
        mode: HardwareSigningMode,
    ) -> WalletResult<()> {
        if !self.vault_path.exists() {
            return self.set_hardware_signing_mode(mode);
        }
        if mode == HardwareSigningMode::WatchOnly {
            return Err(WalletError::Policy(
                "a signing vault cannot be converted to watch-only mode".into(),
            ));
        }
        if mode == HardwareSigningMode::AirgapOnly {
            // Irreversible, so a correct passphrase alone is never enough: route
            // through the prepared ticket that a fresh platform ceremony binds to
            // this exact activation.
            return Err(WalletError::Policy(
                "cold vault activation requires a prepared, freshly authorized activation ticket"
                    .into(),
            ));
        }
        self.verify_wallet_passphrase(current_passphrase)?;
        let current_vault = self.vault_snapshot()?;
        let (current_mode, credential) = current_vault.policy_for_migration()?;
        if current_mode == HardwareSigningMode::AirgapOnly.as_str()
            && mode != HardwareSigningMode::AirgapOnly
        {
            return Err(WalletError::Policy(
                "cold vault mode is irreversible for this vault".into(),
            ));
        }
        let target_profile = if mode == HardwareSigningMode::AirgapOnly {
            SecurityProfile::paranoid()
        } else {
            SecurityProfile::from_name(&current_vault.security_profile_for_migration())
        };
        self.migrate_vault_encryption(
            current_passphrase,
            current_passphrase,
            target_profile,
            mode,
            credential.as_deref(),
            false,
        )
    }

    /// Begin OS-native biometric ceremony (Windows Hello). Returns nonce for platform UI.
    pub fn begin_native_biometric(&mut self) -> WalletResult<String> {
        self.reject_cold_vault_key_access("generic native biometric authorization")?;
        let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
        session.authorization.clear();
        let nonce = random_biometric_nonce();
        session.pending_biometric_nonce = Some(nonce.clone());
        Ok(nonce)
    }

    /// Complete OS-native biometric ceremony after platform verifier succeeds.
    pub fn finish_native_biometric(&mut self, nonce: &str) -> WalletResult<()> {
        self.reject_cold_vault_key_access("generic native biometric authorization")?;
        let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
        match &session.pending_biometric_nonce {
            Some(expected) if expected == nonce => {
                session.biometric_verified = true;
                session.pending_biometric_nonce = None;
                Ok(())
            }
            _ => Err(WalletError::Policy(
                "invalid or expired native biometric ceremony".into(),
            )),
        }
    }

    /// Test helper that drives the real prepared activation ceremony.
    ///
    /// It is not a bypass: it calls the same begin/finish pair the shell calls,
    /// and the shell is what interposes the OS verification between them. The
    /// nonce is already returned to the in-process caller in production, so this
    /// grants nothing that `begin_prepared_native_authorization` does not.
    #[doc(hidden)]
    pub fn audit_activate_cold_vault(&mut self, current_passphrase: &str) -> WalletResult<()> {
        let prepared = self.prepare_cold_vault_activation()?;
        if prepared.webauthn_required {
            return Err(WalletError::Policy(
                "this vault requires a WebAuthn ceremony to activate the cold vault".into(),
            ));
        }
        let challenge = self.begin_prepared_native_authorization(&prepared.id)?;
        self.finish_prepared_native_authorization(&prepared.id, &challenge.nonce)?;
        self.execute_prepared_cold_vault_activation(&prepared.id, current_passphrase)
    }

    /// Test-only bypass. production apps must use `finish_native_biometric`.
    #[doc(hidden)]
    pub fn confirm_biometric_for_send(&mut self) -> WalletResult<()> {
        self.reject_cold_vault_key_access("test biometric authorization bypass")?;
        let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
        session.biometric_verified = true;
        Ok(())
    }

    pub fn lock(&mut self) {
        let _ = self.webauthn.clear_pending();
        self.webauthn_replacement_approved_at = None;
        self.unlocked = None;
        self.assets.clear_cache();
        self.quantum_keystore_mem = None;
        self.dapp_session.clear();
    }

    pub fn touch_auto_lock(&mut self) {
        let now = Instant::now();
        if let Some(session) = &self.unlocked
            && !matches!(session.key, SessionKey::Exhausted)
            && (now.saturating_duration_since(session.unlocked_at)
                >= Duration::from_secs(self.profile.auto_lock_secs)
                || now >= session.absolute_deadline)
        {
            self.lock();
        }
    }

    /// Resets the auto-lock idle timer while the wallet stays unlocked.
    pub fn bump_unlock_activity(&mut self) {
        // UI activity that arrives after the deadline cannot revive an expired
        // session. Enforce the deadline before moving it forward.
        self.touch_auto_lock();
        let may_extend_idle = match self.authenticated_signing_mode() {
            Ok(HardwareSigningMode::AirgapOnly) | Err(_) => false,
            Ok(_) => true,
        };
        if may_extend_idle && let Some(session) = &mut self.unlocked {
            session.unlocked_at = Instant::now();
        }
    }

    pub fn webauthn_register_begin(&self, client_origin: Option<&str>) -> WalletResult<String> {
        let address = self.require_address()?;
        self.webauthn.begin_register(&address, client_origin)
    }

    /// Begin the ceremony that lets the *current* authenticator approve its own
    /// replacement. Without this, a stolen passphrase would be enough to swap the
    /// second factor for one the attacker controls.
    pub fn webauthn_replacement_auth_begin(
        &mut self,
        client_origin: Option<&str>,
    ) -> WalletResult<String> {
        self.webauthn_replacement_approved_at = None;
        let credential = self.load_webauthn_credential()?.ok_or_else(|| {
            WalletError::Policy(
                "no WebAuthn authenticator is registered; register one instead of replacing".into(),
            )
        })?;
        let credential_id = crate::webauthn::credential_id_from_store(&credential)?;
        self.webauthn.begin_auth(&credential_id, client_origin)
    }

    /// Record that the outgoing authenticator approved being replaced.
    ///
    /// Deliberately does not set `webauthn_verified`: approving a key rotation is
    /// not consent to sign a transaction.
    pub fn webauthn_replacement_auth_finish(&mut self, assertion_json: &str) -> WalletResult<()> {
        let stored = self
            .load_webauthn_credential()?
            .ok_or_else(|| WalletError::Policy("no WebAuthn authenticator is registered".into()))?;
        let updated = match self.webauthn.finish_auth(assertion_json, Some(&stored)) {
            Ok(updated) => updated,
            Err(error) => {
                self.webauthn_replacement_approved_at = None;
                return Err(error);
            }
        };
        let mut vault = self.vault_snapshot()?;
        vault.update_webauthn_counter_credential(&updated)?;
        self.persist_vault(vault)?;
        self.webauthn_replacement_approved_at = Some(Instant::now());
        Ok(())
    }

    fn take_webauthn_replacement_approval(&mut self) -> WalletResult<()> {
        let approved_at = self.webauthn_replacement_approved_at.take().ok_or_else(|| {
            WalletError::Policy(
                "replacing a registered WebAuthn authenticator requires approval from the current authenticator"
                    .into(),
            )
        })?;
        if approved_at.elapsed() > WEBAUTHN_REPLACEMENT_APPROVAL_TTL {
            return Err(WalletError::Policy(
                "the current authenticator's approval expired; approve the replacement again"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn webauthn_register_finish(
        &mut self,
        credential_json: &str,
        current_passphrase: &str,
    ) -> WalletResult<()> {
        self.verify_wallet_passphrase(current_passphrase)?;
        // Registering the first authenticator is a pure upgrade. Replacing an
        // existing one is a downgrade risk, so the outgoing key must consent.
        if self.load_webauthn_credential()?.is_some() {
            self.take_webauthn_replacement_approval()?;
        }
        let credential = self.webauthn.finish_register(credential_json)?;
        let current_vault = self.vault_snapshot()?;
        let target_profile =
            SecurityProfile::from_name(&current_vault.security_profile_for_migration());
        let (hardware_mode, _) = current_vault.policy_for_migration()?;
        self.migrate_vault_encryption(
            current_passphrase,
            current_passphrase,
            target_profile,
            HardwareSigningMode::from_name(&hardware_mode),
            Some(&credential),
            false,
        )
    }

    pub fn webauthn_auth_begin(&self, client_origin: Option<&str>) -> WalletResult<String> {
        self.reject_cold_vault_key_access("generic WebAuthn authorization")?;
        let cred = self
            .load_webauthn_credential()?
            .ok_or_else(|| WalletError::Policy("WebAuthn not registered".into()))?;
        let cred_id = crate::webauthn::credential_id_from_store(&cred)?;
        self.webauthn.begin_auth(&cred_id, client_origin)
    }

    pub fn webauthn_auth_finish(&mut self, assertion_json: &str) -> WalletResult<()> {
        self.reject_cold_vault_key_access("generic WebAuthn authorization")?;
        let stored = self.load_webauthn_credential()?;
        let updated = self
            .webauthn
            .finish_auth(assertion_json, stored.as_deref())?;
        let mut vault = self.vault_snapshot()?;
        vault.update_webauthn_counter_credential(&updated)?;
        self.persist_vault(vault)?;
        if let Some(session) = &mut self.unlocked {
            session.webauthn_verified = true;
        }
        Ok(())
    }

    pub async fn balance_mei(&mut self) -> WalletResult<f64> {
        self.touch_auto_lock();
        let address = self.require_address()?;
        self.assets.balance_mei(&self.node, &address).await
    }

    pub async fn asset_summary(&mut self) -> WalletResult<AssetSummary> {
        self.touch_auto_lock();
        let address = self.require_address()?;
        let snapshot = self.assets.snapshot(&self.node, &address).await?;
        let mut btc_channel_satoshi = 0u64;
        if let Some(channel) = self.channel_info().await? {
            if channel.user_is_left(&address) {
                btc_channel_satoshi = channel.left.satoshi;
            } else if channel.user_is_right(&address) {
                btc_channel_satoshi = channel.right.satoshi;
            }
        }
        let hacd_count = snapshot.hacd_names.len();
        Ok(AssetSummary {
            hac_mei: snapshot.hac_mei,
            hacd_count,
            hacd_names: snapshot.hacd_names.into_iter().take(8).collect(),
            btc_wallet_satoshi: snapshot.btc_wallet_satoshi,
            btc_channel_satoshi,
            native_assets: snapshot.native_assets,
        })
    }

    pub async fn list_owned_diamonds(&mut self) -> WalletResult<Vec<String>> {
        self.touch_auto_lock();
        let address = self.require_address()?;
        self.assets.list_owned_diamonds(&self.node, &address).await
    }

    pub async fn preview_send_hacd(
        &mut self,
        to: &str,
        diamond_names: &[String],
    ) -> WalletResult<crate::hacd_send::HacdSendPreview> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        self.require_l1_recipient(to)?;
        crate::hacd_send::preview_hacd_send(&self.node, &from, to, diamond_names).await
    }

    pub async fn preview_send_native_asset(
        &mut self,
        to: &str,
        serial: &str,
        amount: &str,
    ) -> WalletResult<crate::native_asset_send::NativeAssetSendPreview> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        self.require_l1_recipient(to)?;
        crate::native_asset_send::preview_native_asset_send(&self.node, &from, to, serial, amount)
            .await
    }

    pub async fn preview_send_btc(
        &mut self,
        to: &str,
        satoshi: u64,
    ) -> WalletResult<crate::btc_send::BtcSendPreview> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        self.require_l1_recipient(to)?;
        crate::btc_send::preview_btc_send(&self.node, &from, to, satoshi).await
    }

    pub async fn send_btc(&mut self, to: &str, satoshi: u64) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        let unlock_ctx = self.second_factor_from_session()?;
        // BTC has no HAC-denominated amount, so require the profile's second
        // factor at the signing boundary for every bridged-BTC transfer.
        check_send_policy(
            &self.effective_profile(),
            self.second_factor_threshold_mei(),
            &unlock_ctx,
        )?;
        if self.profile.yubikey_required {
            let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
            if !session.webauthn_verified {
                return Err(WalletError::Policy(
                    "WebAuthn (YubiKey/Windows Hello) required. complete ceremony first".into(),
                ));
            }
        }
        self.clear_second_factor();
        let from = self.require_address()?;
        let preview = self.preview_send_btc(to, satoshi).await?;
        if !preview.hip23.ok {
            return Err(WalletError::Policy(preview.hip23.errors.join("; ")));
        }
        let pending_key = self.begin_pending_history(PaymentRail::L1OnChain, &from, to, 0.0)?;
        let send_result: WalletResult<SendResult> = async {
            let transfers = [
                (to, preview.satoshi),
                (
                    crate::send_options::WALLET_TREASURY_ADDRESS,
                    preview.service_fee_satoshi,
                ),
            ];
            let built = self
                .node
                .build_send_btc_tx_actions(&from, &preview.fee_wire, &transfers)
                .await?;
            let body_hex = built
                .body
                .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
            crate::tx_binding::verify_satoshi_transfers(
                &body_hex,
                &from,
                &preview.fee_wire,
                &transfers,
            )?;
            let signed_hex = self.sign_tx_for_network(&body_hex).await?;
            let submitted = self.submit_signed_tx(&signed_hex).await?;
            let summary = self.summary_with_whisper_notice(preview.summary.clone(), &submitted);
            let hash = submitted
                .hash
                .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
            Ok(SendResult {
                rail: PaymentRail::L1OnChain,
                tx_hash: hash,
                summary,
                pending: false,
            })
        }
        .await;
        match send_result {
            Ok(result) => {
                self.resolve_pending_history(
                    pending_key,
                    &result.tx_hash,
                    &result.summary,
                    TxStatus::Confirmed,
                )?;
                Ok(result)
            }
            Err(e) => {
                let _ = self.fail_pending_history(pending_key);
                Err(e)
            }
        }
    }

    pub async fn send_hacd(
        &mut self,
        to: &str,
        diamond_names: &[String],
    ) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        let unlock_ctx = self.second_factor_from_session()?;
        check_send_policy(
            &self.effective_profile(),
            self.second_factor_threshold_mei(),
            &unlock_ctx,
        )?;
        if self.profile.yubikey_required {
            let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
            if !session.webauthn_verified {
                return Err(WalletError::Policy(
                    "WebAuthn (YubiKey/Windows Hello) required. complete ceremony first".into(),
                ));
            }
        }
        self.clear_second_factor();
        let from = self.require_address()?;
        let preview = self.preview_send_hacd(to, diamond_names).await?;
        if !preview.hip23.ok {
            return Err(WalletError::Policy(preview.hip23.errors.join("; ")));
        }
        let pending_key = self.begin_pending_history(PaymentRail::L1OnChain, &from, to, 0.0)?;
        let send_result: WalletResult<SendResult> = async {
            let service_fee =
                crate::send_options::format_service_fee_amount_wire(preview.service_fee_mei);
            let built = self
                .node
                .build_send_diamond_tx_with_service_fee(
                    &from,
                    to,
                    &preview.diamond_names,
                    &service_fee,
                    &preview.fee_wire,
                )
                .await?;
            let body_hex = built
                .body
                .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
            crate::tx_binding::verify_hacd_transfer_with_service_fee(
                &body_hex,
                &from,
                &preview.fee_wire,
                to,
                &preview.diamond_names,
                &service_fee,
            )?;
            let signed_hex = self.sign_tx_for_network(&body_hex).await?;
            let submitted = self.submit_signed_tx(&signed_hex).await?;
            let summary = self.summary_with_whisper_notice(preview.summary.clone(), &submitted);
            let hash = submitted
                .hash
                .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
            Ok(SendResult {
                rail: PaymentRail::L1OnChain,
                tx_hash: hash,
                summary,
                pending: false,
            })
        }
        .await;
        match send_result {
            Ok(result) => {
                self.resolve_pending_history(
                    pending_key,
                    &result.tx_hash,
                    &result.summary,
                    TxStatus::Confirmed,
                )?;
                Ok(result)
            }
            Err(e) => {
                let _ = self.fail_pending_history(pending_key);
                Err(e)
            }
        }
    }

    /// Snapshot a read-only metadata reader for use outside the wallet mutex.
    pub fn diamond_metadata_reader(&self) -> DiamondMetadataReader {
        DiamondMetadataReader::new(self.node.clone())
    }

    pub async fn hub_health(&self) -> WalletResult<Option<HubHealth>> {
        let hub_url = match &self.settings.l2_hub_url {
            Some(u) => u.clone(),
            None => return Ok(None),
        };
        Ok(Some(
            L2HubClient::new_for_wallet_policy(
                hub_url,
                &self.settings.network_mode,
                self.settings.trusted_mainnet_fast_pay_pilot,
            )
            .health()
            .await?,
        ))
    }

    /// Discover a public CSP, persist hub settings, and open a channel when needed.
    pub async fn enable_fast_pay(
        &mut self,
        deposit_mei: Option<f64>,
    ) -> WalletResult<FastPayStatus> {
        self.touch_auto_lock();
        let mut deposit = deposit_mei.unwrap_or(DEFAULT_CHANNEL_DEPOSIT_MEI);

        if self.settings.l2_hub_url.is_none()
            && let Some(discovered) = discover_healthy_hub().await
        {
            apply_discovered_hub(&mut self.settings, &discovered);
        }

        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("Fast Pay provider is not configured".into()))?;
        let client = L2HubClient::new_for_wallet_policy(
            hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        let health = client.health().await?;
        if !health.ok
            || health.version < 3
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !crate::l2_hub::hub_fee_is_zero(&health)
        {
            return Err(WalletError::L2(
                "Provider is not ready for safe, fee-free routed Fast Pay. No channel was opened."
                    .into(),
            ));
        }

        if self.settings.network_mode == "mainnet" {
            // Opening a funded channel is irreversible L1 work. Bind its
            // exposure to the same explicitly selected, capped mainnet policy as payments.
            let readiness = client.require_mainnet_payment_ready(None).await?;
            if deposit_mei.is_none() {
                deposit = (readiness.max_channel_funding_millimeis() as f64 / 1_000.0)
                    .min(DEFAULT_CHANNEL_DEPOSIT_MEI);
            }
            let deposit_wire = format_amount_mei(deposit);
            client.require_channel_funding_ready(&readiness, &deposit_wire)?;
        }

        match self.settings.hub_right_address.clone() {
            Some(a) if !a.is_empty() => a,
            _ => health
                .hub_address
                .filter(|address| !address.is_empty())
                .inspect(|address| {
                    self.settings.hub_right_address = Some(address.clone());
                })
                .ok_or_else(|| {
                    WalletError::L2(
                        "Hub address missing. Set it in the Fast Pay network settings.".into(),
                    )
                })?,
        };

        // Provider discovery and configuration are reversible. Opening a funded
        // L1 channel is not, so it is only allowed through the exact prepared
        // operation ceremony used by the mobile and desktop review screens.
        self.settings.save()?;
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
        if self.settings.channel_id_hex.is_none() {
            return Ok(FastPayStatus::needs_channel(
                health.name.unwrap_or_else(|| "your provider".into()),
                deposit,
            ));
        }
        self.fast_pay_status().await
    }

    pub async fn fast_pay_status(&self) -> WalletResult<FastPayStatus> {
        let user = self.unlocked.as_ref().map(|s| s.address.as_str());
        evaluate_fast_pay(&self.node, &self.settings, user).await
    }

    pub async fn fast_pay_inbox(&mut self) -> WalletResult<Vec<FastPayInboxItem>> {
        let address = self.require_address()?;
        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("Fast Pay provider is not configured".into()))?;
        let client = L2HubClient::new_for_wallet_policy(
            hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        let health = client.health().await?;
        if !health.ok
            || health.version < 4
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !crate::l2_hub::hub_fee_is_zero(&health)
        {
            return Err(WalletError::L2(
                "Fast Pay provider does not support safe recipient confirmation".into(),
            ));
        }
        self.sync_pending_fast_pay(&client, &health).await?;
        client.recipient_inbox(&address).await
    }

    async fn sync_pending_fast_pay(
        &mut self,
        client: &L2HubClient,
        health: &HubHealth,
    ) -> WalletResult<()> {
        let records = self.history.pending_fast_pay_records();
        if records.is_empty() {
            return Ok(());
        }

        let hub_address = health.hub_address.as_deref().ok_or_else(|| {
            WalletError::L2("Fast Pay provider did not publish its hub address".into())
        })?;
        let channel_id = self
            .settings
            .channel_id_hex
            .as_deref()
            .ok_or_else(|| WalletError::L2("Fast Pay channel is not configured".into()))?;

        for record in records {
            let response = match client.payment_status(&record.tx_hash).await {
                Ok(response) => response,
                Err(_) => continue,
            };
            if response.status == "expired" {
                self.history.resolve_pending(
                    &record.tx_hash,
                    &record.tx_hash,
                    response
                        .summary
                        .as_deref()
                        .unwrap_or("Fast Pay expired before recipient acceptance"),
                    TxStatus::Failed,
                )?;
                continue;
            }
            if response.status != "settled" {
                continue;
            }
            let bill_hex = response.bill_hex.as_deref().ok_or_else(|| {
                WalletError::L2(format!(
                    "settled Fast Pay payment {} did not include its signed bill",
                    record.tx_hash
                ))
            })?;
            let channel = query_channel(&self.node, channel_id).await?;
            let trusted = crate::l2_bill::trusted_channel_state(&self.bills, &channel)?;
            let summary = crate::l2_bill::validate_sender_bill(
                &record.tx_hash,
                bill_hex,
                &record.from,
                &record.to,
                &format_amount_mei(record.amount_mei),
                hub_address,
                channel_id,
                &trusted,
            )?;
            if !summary.dispute_ready {
                return Err(WalletError::Policy(format!(
                    "settled Fast Pay payment {} is not dispute-ready",
                    record.tx_hash
                )));
            }
            self.bills.store_bill(&record.tx_hash, bill_hex)?;
            self.history.resolve_pending(
                &record.tx_hash,
                &record.tx_hash,
                response
                    .summary
                    .as_deref()
                    .unwrap_or("Fast Pay settled with no fee"),
                TxStatus::Confirmed,
            )?;
        }
        self.router.replace_bills(self.bills.clone());
        Ok(())
    }

    pub async fn accept_fast_pay(&mut self, payment_id: &str) -> WalletResult<FastPayExecution> {
        self.touch_auto_lock();
        self.reject_cold_vault_key_access("Fast Pay recipient bill signing")?;
        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("Fast Pay provider is not configured".into()))?;
        let configured_channel_id = self
            .settings
            .channel_id_hex
            .clone()
            .ok_or_else(|| WalletError::L2("Fast Pay channel is not configured".into()))?;
        let client = L2HubClient::new_for_wallet_policy(
            hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        let health = client.health().await?;
        let hub_address = health.hub_address.clone().ok_or_else(|| {
            WalletError::L2("Fast Pay provider did not publish its hub address".into())
        })?;
        if !health.ok
            || health.version < 4
            || !health.settlement_ready
            || !health.cross_channel_ready
            || !crate::l2_hub::hub_fee_is_zero(&health)
        {
            return Err(WalletError::L2(
                "Fast Pay provider is not ready for safe recipient confirmation".into(),
            ));
        }

        let address = self.require_address()?;
        let item = client
            .recipient_inbox(&address)
            .await?
            .into_iter()
            .find(|item| item.payment_id == payment_id)
            .ok_or_else(|| {
                WalletError::L2(format!(
                    "Fast Pay request {payment_id} is not awaiting this wallet"
                ))
            })?;
        let amount_mei = item
            .amount
            .parse::<f64>()
            .map_err(|_| WalletError::Policy("Fast Pay inbox returned an invalid amount".into()))?;
        self.protected_unprepared_signing_block(
            "Fast Pay recipient bill signing",
            crate::hip23::policy_amount_mei_ceil(amount_mei)?,
        )?;
        if !item
            .payee_channel_id
            .eq_ignore_ascii_case(&configured_channel_id)
        {
            return Err(WalletError::Policy(
                "Fast Pay request targets a different recipient channel".into(),
            ));
        }
        let channel = query_channel(&self.node, &item.payee_channel_id).await?;
        let channel_has_wallet = channel.user_is_left(&address) || channel.user_is_right(&address);
        let channel_has_hub =
            channel.user_is_left(&hub_address) || channel.user_is_right(&hub_address);
        if !channel.is_open() || !channel_has_wallet || !channel_has_hub {
            return Err(WalletError::Policy(
                "Fast Pay recipient channel is not open between this wallet and the hub".into(),
            ));
        }

        let account = match &self.unlocked.as_ref().ok_or(WalletError::Locked)?.key {
            SessionKey::Signing(account) => account,
            SessionKey::WatchOnly => {
                return Err(WalletError::Policy(
                    "watch-only wallet cannot accept Fast Pay bills".into(),
                ));
            }
            SessionKey::Exhausted => {
                return Err(WalletError::Policy(
                    "cold vault signing session is exhausted; unlock again".into(),
                ));
            }
        };
        let result = client
            .accept_inbox_item(&item, &mut self.bills, account, &channel, &hub_address)
            .await?;
        self.router.replace_bills(self.bills.clone());

        self.append_history_if_enabled(
            PaymentRail::L2Fast,
            &result.payment_id,
            &item.payer,
            &item.payee,
            amount_mei,
            &result.summary,
        )?;
        Ok(result)
    }

    pub async fn discover_hubs(&self) -> WalletResult<HubDiscoveryReport> {
        let extra = self
            .settings
            .l2_hub_url
            .clone()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(discover_all_hubs(&extra).await)
    }

    async fn maybe_discover_hub(&mut self) -> WalletResult<()> {
        if self.settings.l2_hub_url.is_some() {
            return Ok(());
        }
        if let Some(discovered) = discover_healthy_hub().await {
            apply_discovered_hub(&mut self.settings, &discovered);
            self.settings.save()?;
            self.router
                .update_settings(self.node.clone(), self.settings.clone());
        }
        Ok(())
    }

    pub fn list_bills(&self) -> Vec<BillEntry> {
        self.bills.list()
    }

    pub fn list_bill_summaries(&self) -> WalletResult<Vec<crate::l2_bill::BillSummary>> {
        self.bills
            .list()
            .iter()
            .map(|e| crate::l2_bill::summarize_bill(&e.payment_id, &e.bill_hex))
            .collect()
    }

    pub fn export_bill_json(&self, payment_id: &str) -> WalletResult<String> {
        let entry = self
            .bills
            .list()
            .into_iter()
            .find(|e| e.payment_id == payment_id)
            .ok_or_else(|| WalletError::L2(format!("bill {payment_id} not found")))?;
        crate::l2_bill::export_bill_json(&entry)
    }

    pub fn export_all_bills_json(&self) -> WalletResult<String> {
        crate::l2_bill::export_all_bills_json(&self.bills.list())
    }

    pub fn get_bill_hex(&self, payment_id: &str) -> WalletResult<String> {
        self.bills
            .get_bill(payment_id)
            .map(|s| s.to_owned())
            .ok_or_else(|| WalletError::L2(format!("bill {payment_id} not found")))
    }

    pub fn tx_history(&self) -> Vec<TxRecord> {
        let rows = self.history.list().to_vec();
        self.redact_history(rows)
    }

    pub fn clear_tx_history(&mut self) -> WalletResult<()> {
        self.history = TxHistory::default();
        self.history.save()
    }

    pub fn update_privacy_settings(&mut self, privacy: PrivacySettings) -> WalletResult<()> {
        self.settings.privacy = privacy;
        self.settings.save()
    }

    pub fn privacy_settings(&self) -> PrivacySettings {
        self.settings.privacy.clone()
    }

    pub fn update_dust_whisper_settings(
        &mut self,
        dust_whisper: DustWhisperSettings,
    ) -> WalletResult<()> {
        self.settings.dust_whisper = dust_whisper;
        self.settings.save()
    }

    pub fn dust_whisper_settings(&self) -> DustWhisperSettings {
        self.settings.dust_whisper.clone()
    }

    pub async fn whisper_relay_health(&self) -> Vec<RelayHealthStatus> {
        whisper_relay_health(&self.node, &self.settings.dust_whisper).await
    }

    pub fn messenger_threads(&self) -> WalletResult<Vec<crate::messenger::ChatThread>> {
        let my = self.require_address()?;
        let account = self.require_signing_account()?;
        crate::messenger::messenger_threads(account, &my)
    }

    pub fn messenger_messages(
        &self,
        peer: &str,
    ) -> WalletResult<Vec<crate::messenger::ChatMessage>> {
        let my = self.require_address()?;
        let account = self.require_signing_account()?;
        crate::messenger::messenger_messages(account, &my, peer)
    }

    pub fn messenger_mark_read(&self, peer: &str) -> WalletResult<()> {
        let my = self.require_address()?;
        let account = self.require_signing_account()?;
        crate::messenger::messenger_mark_read(account, &my, peer)
    }

    /// What is true about this conversation's privacy, for the screen to repeat.
    ///
    /// The messenger screen asks this before it tells the person anything about
    /// privacy, so the sentence on screen matches both what the next send will
    /// do and what the messages already on screen actually were.
    pub fn messenger_peer_security(
        &self,
        peer: &str,
    ) -> WalletResult<crate::messenger::MessengerPeerSecurity> {
        let my = self.require_address()?;
        let account = self.require_signing_account()?;
        crate::messenger::messenger_peer_security(account, &my, peer)
    }

    pub async fn messenger_send(
        &self,
        peer: &str,
        body: &str,
        peer_pubkey_hex: Option<&str>,
    ) -> WalletResult<crate::messenger::ChatMessage> {
        let my = self.require_address()?;
        let account = self.require_signing_account()?;
        let relays = self.settings.dust_whisper.trimmed_relay_urls();
        if relays.is_empty() {
            return Err(WalletError::Other(
                "configure at least one DUST Whisper relay URL for messenger. Somebody has to run a relay, and it can be you: docs/RUNNING-A-RELAY.md".into(),
            ));
        }
        crate::messenger::messenger_send(
            self.node.http(),
            account,
            &my,
            peer,
            body,
            &relays,
            peer_pubkey_hex,
        )
        .await
    }

    pub async fn messenger_poll_inbox(
        &self,
    ) -> WalletResult<crate::messenger::MessengerPollOutcome> {
        let my = self.require_address()?;
        let account = self.require_signing_account()?;
        let relays = self.settings.dust_whisper.trimmed_relay_urls();
        if relays.is_empty() {
            // An all-zero outcome with nothing tried. The screen reads
            // `relays_tried` and says no relay is configured, rather than
            // reporting an empty inbox nobody looked in.
            return Ok(crate::messenger::MessengerPollOutcome::default());
        }
        crate::messenger::messenger_poll_inbox(self.node.http(), account, &my, &relays).await
    }

    pub(crate) async fn submit_signed_tx(
        &mut self,
        signed_hex: &str,
    ) -> WalletResult<crate::node::SubmitTxResponse> {
        self.ensure_transaction_network_binding(signed_hex).await?;
        whisper_submit_tx_hex(&self.node, &self.settings.dust_whisper, signed_hex).await
    }

    fn summary_with_whisper_notice(
        &self,
        summary: String,
        submitted: &crate::node::SubmitTxResponse,
    ) -> String {
        match whisper_fallback_notice(&submitted.message) {
            Some(notice) => format!("{summary}. {notice}"),
            None => summary,
        }
    }

    pub fn validate_hip23_patterns(
        &self,
        universal: Type3CheckInput,
        p2: Option<HeightScopeInput>,
        p3: Option<BalanceFloorInput>,
    ) -> Vec<Hip23PatternCheck> {
        validate_all_patterns(&universal, p2.as_ref(), p3.as_ref())
    }

    pub async fn channel_info(&mut self) -> WalletResult<Option<ChannelInfo>> {
        self.touch_auto_lock();
        let channel_id = match &self.settings.channel_id_hex {
            Some(id) => id.clone(),
            None => return Ok(None),
        };
        Ok(Some(query_channel(&self.node, &channel_id).await?))
    }

    pub async fn preview_channel_open(
        &mut self,
        hub_address: &str,
        user_deposit_mei: &str,
        hub_deposit_mei: &str,
    ) -> WalletResult<ChannelSetupPreview> {
        self.touch_auto_lock();
        let user_deposit = exact_channel_deposit(user_deposit_mei, false)?;
        let hub_deposit = exact_channel_deposit(hub_deposit_mei, true)?;
        if !crate::hip23::is_valid_hacash_address(hub_address) {
            return Err(WalletError::Policy("invalid Fast Pay hub address".into()));
        }

        let user = self.require_address()?;
        // Hacash reuses the original deterministic ID and increments the
        // on-chain incarnation counter after an agreement close.
        let channel_id = derive_channel_id(&user, hub_address, 1);
        let reuse_version =
            crate::channel::next_channel_reuse_version(&self.node, &channel_id, &user, hub_address)
                .await?;
        if reuse_version != 1 {
            return Err(WalletError::Policy(
                "Mainnet Fast Pay pilot channels are one-use only. This channel was already closed and cannot be reopened. Use a different approved Hub address."
                    .into(),
            ));
        }
        Ok(ChannelSetupPreview {
            channel_id,
            reuse_version,
            left_address: user,
            right_address: hub_address.to_owned(),
            left_deposit: user_deposit,
            right_deposit: hub_deposit,
        })
    }

    pub async fn open_channel(
        &mut self,
        _hub_address: &str,
        _user_deposit_mei: f64,
        _hub_deposit_mei: f64,
    ) -> WalletResult<String> {
        Err(WalletError::Policy(
            "direct channel open is disabled; use the reviewed prepared Hub co-sign flow".into(),
        ))
    }
    pub async fn close_channel(&mut self) -> WalletResult<String> {
        Err(WalletError::Policy(
            "direct channel close is disabled; use the reviewed prepared Hub co-sign flow".into(),
        ))
    }
    pub async fn preview_send(
        &mut self,
        to: &str,
        amount_mei: f64,
        options: &crate::send_options::SendOptions,
    ) -> WalletResult<SendPreview> {
        self.touch_auto_lock();
        crate::hip23::validate_hac_amount_mei(amount_mei)?;
        options.validate()?;
        let mut options = options.clone();
        options.enforce_mandatory_service_fee();
        self.maybe_discover_hub().await?;
        let from = self.require_address()?;
        let amount_wire = format_amount_mei(amount_mei);
        let balance = self.node.balance_mei(&from).await?;
        let fast_pay = evaluate_fast_pay(&self.node, &self.settings, Some(&from)).await?;
        let plan = self
            .router
            .plan_send(&from, to, amount_mei, &options)
            .await?;
        let fee_for_hip23 =
            plan.fee_breakdown.payer_debit_mei - plan.fee_breakdown.recipient_credit_mei;
        let hip23 = validate_simple_l1_send(to, amount_mei, balance, fee_for_hip23)?;
        let fee = plan
            .fee_breakdown
            .l1_fee_mei
            .map(crate::hip23::format_l1_fee_mei_for_node)
            .or_else(|| {
                plan.fee_breakdown
                    .l1_fee_wire
                    .as_ref()
                    .map(|w| crate::hip23::wire_mei_for_node(w))
            })
            .unwrap_or_else(|| crate::hip23::wire_mei_for_node("1:244"));
        Ok(SendPreview {
            plan,
            from,
            to: to.to_owned(),
            amount_mei,
            amount_wire: amount_wire.clone(),
            fee,
            hip23,
            fast_pay,
            send_options: options,
        })
    }

    /// Build an unsigned L1 send for air-gapped signing (watch-only or online coordinator).
    pub async fn prepare_airgap_l1_send(
        &mut self,
        to: &str,
        amount_mei: f64,
    ) -> WalletResult<AirgapPrepareResult> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        let amount = canonicalize_airgap_amount(amount_mei)?;
        let preview = self
            .preview_send(
                to,
                amount.amount_mei,
                &crate::send_options::SendOptions::default(),
            )
            .await?;
        if preview.plan.rail != PaymentRail::L1OnChain {
            return Err(WalletError::Policy(
                "air-gap QR supports L1 on-chain sends only (disable L2 route)".into(),
            ));
        }
        if !preview.hip23.ok {
            return Err(WalletError::Policy(
                "HIP-23 checks failed. cannot prepare air-gap send".into(),
            ));
        }
        let transfer_pairs = crate::send_options::hac_send_transfer_pairs(
            to,
            &preview.amount_wire,
            &preview.plan.fee_breakdown,
        );
        let transfers: Vec<(&str, &str)> = transfer_pairs
            .iter()
            .map(|(address, amount)| (address.as_str(), amount.as_str()))
            .collect();
        let built = self
            .node
            .build_send_hac_tx_actions(&from, &preview.fee, &transfers)
            .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
        let canonical =
            crate::tx_binding::verify_hac_transfers(&body_hex, &from, &preview.fee, &transfers)?;
        if canonical.tx_type != AIRGAP_CLASSIC_L1_TX_TYPE {
            return Err(WalletError::Policy(format!(
                "classic air-gap send requires consensus transaction type {AIRGAP_CLASSIC_L1_TX_TYPE}, node built type {}",
                canonical.tx_type
            )));
        }
        let summary =
            canonical_airgap_summary(canonical.tx_type, &preview.to, &preview.amount_wire)?;
        let unsigned = AirgapUnsigned {
            v: AIRGAP_VERSION,
            from: from.clone(),
            to: preview.to.clone(),
            amount_mei: preview.amount_mei,
            amount_wire: preview.amount_wire,
            fee: preview.fee,
            service_fee_mei: preview.plan.fee_breakdown.service_fee_mei.unwrap_or(0.0),
            service_fee_treasury: preview.plan.fee_breakdown.service_fee_treasury,
            body_hex,
            summary,
            tx_type: canonical.tx_type,
        };
        let envelope = AirgapEnvelope::Unsigned(unsigned.clone());
        let qr_parts = encode_envelope_qr(&envelope)?;
        let inspection = self.inspect_airgap_envelope(&envelope)?;
        Ok(AirgapPrepareResult {
            envelope: unsigned,
            inspection,
            qr_parts,
        })
    }

    /// Decode and bind every fact displayed before an air-gap signature or
    /// broadcast. The envelope summary is never trusted as a source of truth.
    pub fn inspect_airgap_envelope(
        &self,
        envelope: &AirgapEnvelope,
    ) -> WalletResult<AirgapInspection> {
        let (
            kind,
            version,
            declared_tx_type,
            from,
            to,
            amount_mei,
            amount_wire,
            fee,
            service_fee_mei,
            service_fee_treasury,
            transaction_hex,
        ) = match envelope {
            AirgapEnvelope::Unsigned(value) => (
                "unsigned",
                value.v,
                value.tx_type,
                value.from.as_str(),
                value.to.as_str(),
                value.amount_mei,
                value.amount_wire.as_str(),
                value.fee.as_str(),
                value.service_fee_mei,
                value.service_fee_treasury.as_deref(),
                value.body_hex.as_str(),
            ),
            AirgapEnvelope::Signed(value) => (
                "signed",
                value.v,
                value.tx_type,
                value.from.as_str(),
                value.to.as_str(),
                value.amount_mei,
                value.amount_wire.as_str(),
                value.fee.as_str(),
                value.service_fee_mei,
                value.service_fee_treasury.as_deref(),
                value.signed_hex.as_str(),
            ),
        };
        let tx_type = canonical_airgap_tx_type(version, declared_tx_type)
            .map_err(|error| WalletError::Policy(format!("air-gap type policy: {error}")))?;
        if tx_type == 4 {
            self.require_quantum_testnet()?;
        }
        crate::address::require_address_for_network(from, &self.network_mode)?;
        crate::address::require_address_for_network(to, &self.network_mode)?;
        let amount = crate::airgap::validate_airgap_amount_binding(amount_mei, amount_wire)?;
        let summary = canonical_airgap_summary(tx_type, to, &amount.amount_wire)?;
        let expected_wallet_fee = crate::send_options::compute_service_fee_mei(amount.amount_mei);
        let wallet_fee_wire =
            crate::send_options::format_service_fee_amount_wire(expected_wallet_fee);
        if service_fee_mei.to_bits() != expected_wallet_fee.to_bits()
            || service_fee_treasury != Some(crate::send_options::WALLET_TREASURY_ADDRESS)
        {
            return Err(WalletError::Policy(
                "air-gap envelope has an incorrect mandatory wallet fee".into(),
            ));
        }
        let canonical = crate::tx_binding::verify_hac_transfers(
            transaction_hex,
            from,
            fee,
            &[
                (to, amount.amount_wire.as_str()),
                (
                    crate::send_options::WALLET_TREASURY_ADDRESS,
                    wallet_fee_wire.as_str(),
                ),
            ],
        )?;
        if canonical.tx_type != tx_type {
            return Err(WalletError::Policy(format!(
                "air-gap transaction type mismatch: envelope represents type {tx_type}, body has type {}",
                canonical.tx_type
            )));
        }
        Ok(AirgapInspection {
            kind: kind.into(),
            tx_type,
            network_mode: self.network_mode.clone(),
            from: from.into(),
            to: to.into(),
            amount_mei: amount.amount_mei,
            amount_wire: amount.amount_wire,
            network_fee: fee.into(),
            wallet_fee_mei: expected_wallet_fee,
            wallet_fee_wire,
            wallet_fee_treasury: crate::send_options::WALLET_TREASURY_ADDRESS.into(),
            body_sha256: canonical.body_sha256,
            summary,
        })
    }

    /// Offline signer: sign an unsigned air-gap envelope and return signed QR payload(s).
    pub fn sign_airgap_unsigned(
        &mut self,
        unsigned: &AirgapUnsigned,
    ) -> WalletResult<AirgapSignResult> {
        self.sign_airgap_unsigned_in_context(unsigned, SigningContext::Online)
    }

    fn sign_prepared_airgap_unsigned(
        &mut self,
        unsigned: &AirgapUnsigned,
        _permit: authorization_service::PreparedAirgapSigningPermit,
    ) -> WalletResult<AirgapSignResult> {
        self.sign_airgap_unsigned_in_context(unsigned, SigningContext::PreparedAirgap)
    }

    fn sign_airgap_unsigned_in_context(
        &mut self,
        unsigned: &AirgapUnsigned,
        context: SigningContext,
    ) -> WalletResult<AirgapSignResult> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        if unsigned.from != from {
            return Err(WalletError::Policy(format!(
                "offline signer address {from} does not match unsigned tx from {}",
                unsigned.from
            )));
        }
        if self
            .unlocked
            .as_ref()
            .is_some_and(|session| matches!(session.key, SessionKey::WatchOnly))
        {
            return Err(WalletError::Policy(
                "watch-only wallet cannot sign transactions".into(),
            ));
        }
        let inspection =
            self.inspect_airgap_envelope(&AirgapEnvelope::Unsigned(unsigned.clone()))?;
        if inspection.tx_type != AIRGAP_CLASSIC_L1_TX_TYPE {
            return Err(WalletError::Policy(
                "Type 4 air-gap transactions require the Quantum Lab signer".into(),
            ));
        }
        if context == SigningContext::Online {
            let unlock_ctx = self.second_factor_from_session()?;
            let policy_amount = crate::hip23::policy_amount_mei_ceil(inspection.amount_mei)?;
            check_send_policy(&self.effective_profile(), policy_amount, &unlock_ctx)?;
        }
        let expected_service_fee =
            crate::send_options::compute_service_fee_mei(inspection.amount_mei);
        if (unsigned.service_fee_mei - expected_service_fee).abs() > 0.000_000_1
            || unsigned.service_fee_treasury.as_deref()
                != Some(crate::send_options::WALLET_TREASURY_ADDRESS)
        {
            return Err(WalletError::Policy(
                "air-gap envelope has a missing or incorrect mandatory wallet fee".into(),
            ));
        }
        let service_fee_wire =
            crate::send_options::format_service_fee_amount_wire(expected_service_fee);
        let transfers = [
            (unsigned.to.as_str(), unsigned.amount_wire.as_str()),
            (
                crate::send_options::WALLET_TREASURY_ADDRESS,
                service_fee_wire.as_str(),
            ),
        ];
        let canonical = crate::tx_binding::verify_hac_transfers(
            &unsigned.body_hex,
            &unsigned.from,
            &unsigned.fee,
            &transfers,
        )?;
        let envelope_tx_type =
            canonical_airgap_tx_type(unsigned.v, unsigned.tx_type).map_err(|error| {
                WalletError::Policy(format!("air-gap transaction type policy: {error}"))
            })?;
        if canonical.tx_type != envelope_tx_type {
            return Err(WalletError::Policy(format!(
                "air-gap transaction type mismatch: envelope represents type {envelope_tx_type}, body has type {}",
                canonical.tx_type
            )));
        }
        let signed_hex = self.sign_tx_hex_in_context(&unsigned.body_hex, context)?;
        self.clear_second_factor();
        let signed = AirgapSigned {
            v: AIRGAP_VERSION,
            tx_type: inspection.tx_type,
            from: inspection.from,
            to: inspection.to,
            amount_mei: inspection.amount_mei,
            amount_wire: inspection.amount_wire,
            fee: inspection.network_fee,
            service_fee_mei: inspection.wallet_fee_mei,
            service_fee_treasury: Some(inspection.wallet_fee_treasury),
            signed_hex,
            summary: inspection.summary,
        };
        let envelope = AirgapEnvelope::Signed(signed.clone());
        let qr_parts = encode_envelope_qr(&envelope)?;
        let inspection = self.inspect_airgap_envelope(&envelope)?;
        Ok(AirgapSignResult {
            envelope: signed,
            inspection,
            qr_parts,
        })
    }

    /// Online coordinator: broadcast a signed tx from air-gap QR without local signing.
    pub async fn broadcast_airgap_signed(
        &mut self,
        signed: &AirgapSigned,
    ) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        let inspection = self.inspect_airgap_envelope(&AirgapEnvelope::Signed(signed.clone()))?;
        let envelope_tx_type = inspection.tx_type;
        if envelope_tx_type == 4 {
            self.require_quantum_testnet()?;
        }
        let expected_service_fee = crate::send_options::compute_service_fee_mei(signed.amount_mei);
        if signed.amount_wire.is_empty()
            || signed.fee.is_empty()
            || (signed.service_fee_mei - expected_service_fee).abs() > 0.000_000_1
            || signed.service_fee_treasury.as_deref()
                != Some(crate::send_options::WALLET_TREASURY_ADDRESS)
        {
            return Err(WalletError::Policy(
                "signed air-gap envelope is missing the mandatory wallet fee binding".into(),
            ));
        }
        let service_fee_wire =
            crate::send_options::format_service_fee_amount_wire(expected_service_fee);
        let canonical = crate::tx_binding::verify_hac_transfers(
            &signed.signed_hex,
            &signed.from,
            &signed.fee,
            &[
                (signed.to.as_str(), signed.amount_wire.as_str()),
                (
                    crate::send_options::WALLET_TREASURY_ADDRESS,
                    service_fee_wire.as_str(),
                ),
            ],
        )?;
        if canonical.tx_type != envelope_tx_type {
            return Err(WalletError::Policy(
                "air-gap transaction type mismatch".into(),
            ));
        }
        if envelope_tx_type == 4 {
            let expected = self
                .quantum_settings()
                .active_account
                .map(|a| a.address)
                .ok_or_else(|| WalletError::Other("no quantum account".into()))?;
            if signed.from != expected {
                return Err(WalletError::Policy(
                    "signed type 4 tx sender does not match active quantum account".into(),
                ));
            }
            let submitted = self.submit_signed_tx(&signed.signed_hex).await?;
            let hash = submitted
                .hash
                .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
            let summary = inspection.summary.clone();
            let _ = self.append_quantum_history(
                &hash,
                &inspection.from,
                &inspection.to,
                inspection.amount_mei,
                &summary,
            );
            return Ok(SendResult {
                rail: PaymentRail::QuantumType4,
                tx_hash: hash,
                summary,
                pending: false,
            });
        }
        let coordinator = self.require_address()?;
        if coordinator != signed.from {
            return Err(WalletError::Policy(
                "signed tx sender does not match this wallet address".into(),
            ));
        }
        let submitted = self.submit_signed_tx(&signed.signed_hex).await?;
        let hash = submitted
            .hash
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
        let result = SendResult {
            rail: PaymentRail::L1OnChain,
            tx_hash: hash,
            summary: inspection.summary.clone(),
            pending: false,
        };
        self.append_history_if_enabled(
            result.rail,
            &result.tx_hash,
            &inspection.from,
            &inspection.to,
            inspection.amount_mei,
            &result.summary,
        )?;
        Ok(result)
    }

    pub fn parse_airgap_qr(&mut self, text: &str) -> WalletResult<AirgapParseResult> {
        self.touch_auto_lock();
        let parsed = parse_airgap_qr_text(text)?;
        self.attach_airgap_inspection(parsed)
    }

    pub fn parse_airgap_qr_batch(&mut self, parts: &[String]) -> WalletResult<AirgapParseResult> {
        self.touch_auto_lock();
        let parsed = parse_airgap_qr_parts(parts)?;
        self.attach_airgap_inspection(parsed)
    }

    fn attach_airgap_inspection(
        &self,
        mut parsed: AirgapParseResult,
    ) -> WalletResult<AirgapParseResult> {
        if let Some(envelope) = parsed.envelope.as_ref() {
            parsed.inspection = Some(self.inspect_airgap_envelope(envelope)?);
        }
        Ok(parsed)
    }

    pub async fn send_hac(
        &mut self,
        to: &str,
        amount_mei: f64,
        options: crate::send_options::SendOptions,
    ) -> WalletResult<SendResult> {
        self.send_hac_inner(to, amount_mei, options, None).await
    }

    pub async fn send_hac_reviewed(
        &mut self,
        to: &str,
        amount_mei: f64,
        options: crate::send_options::SendOptions,
        reviewed: ReviewedSendExpectation,
    ) -> WalletResult<SendResult> {
        self.send_hac_inner(to, amount_mei, options, Some(reviewed))
            .await
    }

    async fn send_hac_inner(
        &mut self,
        to: &str,
        amount_mei: f64,
        options: crate::send_options::SendOptions,
        reviewed: Option<ReviewedSendExpectation>,
    ) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        self.reject_cold_vault_key_access("online HAC and Fast Pay signing")?;
        let unlock_ctx = self.second_factor_from_session()?;
        let policy_amount = crate::hip23::policy_amount_mei_ceil(amount_mei)?;
        check_send_policy(&self.effective_profile(), policy_amount, &unlock_ctx)?;
        if self.profile.yubikey_required {
            let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
            if !session.webauthn_verified {
                return Err(WalletError::Policy(
                    "WebAuthn (YubiKey/Windows Hello) required. complete ceremony first".into(),
                ));
            }
        }
        // Single-use second factor: consumed before signing (enterprise per-tx model).
        self.clear_second_factor();
        // Both UIs use this unprepared command only for the Fast Pay rail, and that rail
        // hands the account to the hub router, which cosigns the settlement bill itself.
        // It therefore never reaches sign_tx_hex_in_context and never hits
        // check_signing_allowed_in_context, the only place that enforces the hardware
        // signing mode for a signature. Without this barrier a webauthn_gate wallet
        // signs an L2 bill with no ceremony while promising one for every payment, and a
        // balanced wallet accepts a session-level biometric for a large send instead of
        // one bound to that exact bill. Anything that needs a factor must go through the
        // prepared ceremony, which is what the three sibling call sites already require.
        self.protected_unprepared_signing_block("HAC send", policy_amount)?;
        let from = self.require_address()?;
        let preview = self.preview_send(to, amount_mei, &options).await?;
        if let Some(reviewed) = reviewed.as_ref() {
            require_exact_review(reviewed, &preview)?;
        }
        let pending_key = self.begin_pending_history(preview.plan.rail, &from, to, amount_mei)?;

        let send_result: WalletResult<SendResult> = match preview.plan.rail {
            PaymentRail::L2Fast => {
                self.require_online_signing_transport()?;
                match &self.unlocked.as_ref().ok_or(WalletError::Locked)?.key {
                    SessionKey::Signing(acc) => {
                        let execution = self
                            .router
                            .execute_l2(&from, to, &preview.amount_wire, acc)
                            .await?;
                        self.bills = self.router.bills().clone();
                        Ok(SendResult {
                            rail: PaymentRail::L2Fast,
                            tx_hash: execution.payment_id,
                            summary: execution.summary,
                            pending: execution.status != "settled",
                        })
                    }
                    SessionKey::WatchOnly => Err(WalletError::Policy(
                        "watch-only wallet cannot sign L2 bills".into(),
                    )),
                    SessionKey::Exhausted => Err(WalletError::Policy(
                        "cold vault signing session is exhausted; unlock again".into(),
                    )),
                }
            }
            PaymentRail::L1OnChain => {
                let transfer_pairs = crate::send_options::hac_send_transfer_pairs(
                    to,
                    &preview.amount_wire,
                    &preview.plan.fee_breakdown,
                );
                let transfers: Vec<(&str, &str)> = transfer_pairs
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect();
                let built = self
                    .node
                    .build_send_hac_tx_actions(&from, &preview.fee, &transfers)
                    .await?;
                let body_hex = built
                    .body
                    .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
                crate::tx_binding::verify_hac_transfers(
                    &body_hex,
                    &from,
                    &preview.fee,
                    &transfers,
                )?;
                let signed_hex = self.sign_tx_for_network(&body_hex).await?;
                let submitted = self.submit_signed_tx(&signed_hex).await?;
                let summary = self.summary_with_whisper_notice(preview.plan.summary, &submitted);
                let hash = submitted
                    .hash
                    .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
                Ok(SendResult {
                    rail: PaymentRail::L1OnChain,
                    tx_hash: hash,
                    summary,
                    pending: false,
                })
            }
            PaymentRail::QuantumType4 => Err(WalletError::Policy(
                "Type 4 quantum sends use the Quantum tab. not legacy Send".into(),
            )),
        };

        match send_result {
            Ok(result) => {
                self.resolve_pending_history(
                    pending_key,
                    &result.tx_hash,
                    &result.summary,
                    if result.pending {
                        TxStatus::Pending
                    } else {
                        TxStatus::Confirmed
                    },
                )?;
                Ok(result)
            }
            Err(e) => {
                let _ = self.fail_pending_history(pending_key);
                Err(e)
            }
        }
    }

    /// The amount, in HAC, at or above which a signature needs a second factor.
    ///
    /// The authenticated security profile sets the ceiling, and it is bound to the vault
    /// through the profile name. A user preference may lower that ceiling but can never
    /// raise it, because this takes the minimum of the two. That single property is what
    /// makes the preference safe to keep in the settings file, which is not
    /// cryptographically bound: someone who edits or replaces that file can only make
    /// the policy stricter than the profile allows, never weaker.
    ///
    /// Every policy decision must read the threshold from here. Nothing outside this
    /// method and [`Self::effective_profile`] may read
    /// `SecurityProfile::require_second_factor_above_mei` directly, or a preference the
    /// user set would silently not apply on that path.
    ///
    /// An audit test in `tests/second_factor_threshold.rs` checks two shapes of that
    /// mistake: a direct field read, and handing the raw profile to a policy helper such
    /// as `check_send_policy`. It is a text walker, so it cannot see every possible
    /// aliasing of the field, and it is not a substitute for reading the code. An earlier
    /// version of this note said the test enforces the rule, which claimed more than the
    /// test delivers.
    pub fn second_factor_threshold_mei(&self) -> u64 {
        crate::security::effective_second_factor_threshold(
            self.profile.require_second_factor_above_mei,
            self.settings.require_second_factor_above_mei,
        )
    }

    /// The active profile with its threshold replaced by the effective one.
    ///
    /// For the policy helpers that take a whole `SecurityProfile`. Same rule as
    /// [`Self::second_factor_threshold_mei`]: the clone never reaches the vault, which
    /// stores only the profile name, so this cannot weaken what the vault authenticates.
    pub(crate) fn effective_profile(&self) -> SecurityProfile {
        let mut profile = self.profile.clone();
        profile.require_second_factor_above_mei = self.second_factor_threshold_mei();
        profile
    }

    pub fn set_security_profile(&mut self, profile: SecurityProfile) -> WalletResult<()> {
        if !matches!(profile.name.as_str(), "balanced" | "paranoid") {
            return Err(WalletError::Policy("unknown security profile".into()));
        }
        let normalized = SecurityProfile::from_name(&profile.name);
        if self.vault_path.exists() {
            let vault = self.read_vault()?;
            if vault.metadata.security_profile == normalized.name
                && self.settings.security_profile == normalized.name
            {
                self.profile = normalized;
                return Ok(());
            }
            return Err(WalletError::Policy(
                "changing a signing wallet security profile requires current-passphrase authentication"
                    .into(),
            ));
        }

        self.settings.security_profile = normalized.name.clone();
        self.settings.save()?;
        self.profile = normalized;
        Ok(())
    }

    /// Security-audit helper: append history respecting privacy storage flag.
    #[doc(hidden)]
    pub fn audit_append_history_if_enabled(
        &mut self,
        rail: PaymentRail,
        tx_hash: &str,
        from: &str,
        to: &str,
        amount_mei: f64,
        summary: &str,
    ) -> WalletResult<()> {
        self.append_history_if_enabled(rail, tx_hash, from, to, amount_mei, summary)
    }

    /// Security-audit helper: sign a raw tx body when unlocked.
    #[doc(hidden)]
    pub fn audit_sign_tx_body(&self, body_hex: &str) -> WalletResult<String> {
        self.sign_tx_hex(body_hex)
    }

    /// Security-audit helper: read session-bound second factor state (never from IPC).
    #[doc(hidden)]
    pub fn audit_second_factor_snapshot(&self) -> WalletResult<UnlockContext> {
        self.second_factor_from_session()
    }

    fn second_factor_from_session(&self) -> WalletResult<UnlockContext> {
        let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        Ok(UnlockContext {
            biometric_ok: session.biometric_verified,
            yubikey_ok: session.webauthn_verified,
        })
    }

    pub(crate) fn clear_second_factor(&mut self) {
        if let Some(session) = &mut self.unlocked {
            session.webauthn_verified = false;
            session.biometric_verified = false;
        }
    }

    pub(crate) fn sign_tx_hex(&self, body_hex: &str) -> WalletResult<String> {
        self.sign_tx_hex_in_context(body_hex, SigningContext::Online)
    }

    fn sign_tx_hex_in_context(
        &self,
        body_hex: &str,
        context: SigningContext,
    ) -> WalletResult<String> {
        let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        let watch_only = matches!(session.key, SessionKey::WatchOnly);
        check_signing_allowed_in_context(
            self.authenticated_signing_mode()?,
            watch_only,
            session.webauthn_verified,
            context,
        )?;
        let account = match &session.key {
            SessionKey::Signing(acc) => acc,
            SessionKey::WatchOnly => {
                return Err(WalletError::Policy(
                    "watch-only wallet cannot sign transactions".into(),
                ));
            }
            SessionKey::Exhausted => {
                return Err(WalletError::Policy(
                    "cold vault signing session is exhausted; unlock again".into(),
                ));
            }
        };
        let body = hex::decode(body_hex).map_err(|e| WalletError::Transaction(e.to_string()))?;
        let (mut tx, _) = transaction::transaction_create(&body)
            .map_err(|e| WalletError::Transaction(e.to_string()))?;
        tx.fill_sign(account.inner())
            .map_err(|e| WalletError::Transaction(e.to_string()))?;
        Ok(tx.serialize().to_hex())
    }

    fn append_history_if_enabled(
        &mut self,
        rail: PaymentRail,
        tx_hash: &str,
        from: &str,
        to: &str,
        amount_mei: f64,
        summary: &str,
    ) -> WalletResult<()> {
        if !self.settings.privacy.store_tx_history {
            return Ok(());
        }
        self.history
            .append(rail, tx_hash, from, to, amount_mei, summary)
    }
    fn begin_pending_history(
        &mut self,
        rail: PaymentRail,
        from: &str,
        to: &str,
        amount_mei: f64,
    ) -> WalletResult<Option<String>> {
        if !self.settings.privacy.store_tx_history {
            return Ok(None);
        }
        Ok(Some(
            self.history.begin_pending(rail, from, to, amount_mei)?,
        ))
    }

    fn resolve_pending_history(
        &mut self,
        pending_key: Option<String>,
        tx_hash: &str,
        summary: &str,
        status: TxStatus,
    ) -> WalletResult<()> {
        let Some(key) = pending_key else {
            return Ok(());
        };
        self.history.resolve_pending(&key, tx_hash, summary, status)
    }

    fn fail_pending_history(&mut self, pending_key: Option<String>) -> WalletResult<()> {
        let Some(key) = pending_key else {
            return Ok(());
        };
        self.history.mark_failed(&key)
    }

    fn redact_history(&self, rows: Vec<TxRecord>) -> Vec<TxRecord> {
        let p = &self.settings.privacy;
        if !p.hide_addresses && !p.hide_balances {
            return rows;
        }
        rows.into_iter()
            .map(|mut r| {
                if p.hide_addresses {
                    r.from = mask_address(&r.from);
                    r.to = mask_address(&r.to);
                    r.tx_hash = mask_hash(&r.tx_hash);
                }
                if p.hide_balances {
                    r.amount_mei = 0.0;
                    r.summary = mask_amount(1.0);
                }
                r
            })
            .collect()
    }

    fn require_address(&self) -> WalletResult<String> {
        self.unlocked
            .as_ref()
            .map(|s| s.address.clone())
            .ok_or(WalletError::Locked)
    }

    fn require_l1_recipient(&self, address: &str) -> WalletResult<()> {
        crate::address::require_address_for_network(address, &self.network_mode)?;
        Ok(())
    }

    fn require_signing_account(&self) -> WalletResult<&WalletAccount> {
        self.reject_cold_vault_key_access("messenger account access")?;
        let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        match &session.key {
            SessionKey::Signing(acc) => Ok(acc),
            SessionKey::WatchOnly => Err(WalletError::Policy(
                "watch-only wallet cannot access messenger".into(),
            )),
            SessionKey::Exhausted => Err(WalletError::Policy(
                "cold vault signing session is exhausted; unlock again".into(),
            )),
        }
    }

    fn load_webauthn_credential(&self) -> WalletResult<Option<String>> {
        let vault = self.read_vault()?;
        if vault.metadata.version < crate::vault::VAULT_VERSION_LATEST {
            return Err(WalletError::Policy(
                "legacy WebAuthn metadata is unauthenticated; unlock to migrate and re-register"
                    .into(),
            ));
        }
        vault.validate_authenticated_policy()?;
        Ok(vault.metadata.webauthn_credential_b64.clone())
    }

    pub(crate) fn reject_cold_vault_key_access(&self, operation: &str) -> WalletResult<()> {
        if self.cold_vault_configured()? {
            return Err(WalletError::Policy(format!(
                "cold vault blocks {operation}; use a freshly authorized prepared Type 2 air-gap operation"
            )));
        }
        Ok(())
    }

    fn cold_vault_configured(&self) -> WalletResult<bool> {
        if !self.vault_path.exists() {
            return Ok(false);
        }
        let vault = self.read_vault()?;
        Ok(vault.metadata.version >= crate::vault::VAULT_VERSION_LATEST
            && vault.metadata.hardware_signing_mode == HardwareSigningMode::AirgapOnly.as_str())
    }

    fn exhaust_cold_signing_session(&mut self) {
        let _ = self.webauthn.clear_pending();
        self.dapp_session.clear();
        self.quantum_keystore_mem = None;
        let Some(session) = self.unlocked.take() else {
            return;
        };
        let address = session.address.clone();
        drop(session);
        let now = Instant::now();
        self.unlocked = Some(UnlockedSession {
            address,
            key: SessionKey::Exhausted,
            unlocked_at: now,
            absolute_deadline: now,
            webauthn_verified: false,
            biometric_verified: false,
            pending_biometric_nonce: None,
            authorization: authorization_service::SessionAuthorization::default(),
            quantum_file_key: None,
        });
    }

    fn clear_session_authorizations(&mut self) {
        self.webauthn_replacement_approved_at = None;
        if let Some(session) = &mut self.unlocked {
            session.webauthn_verified = false;
            session.biometric_verified = false;
            session.pending_biometric_nonce = None;
            session.authorization.clear();
        }
        self.dapp_session.clear();
        let _ = self.webauthn.clear_pending();
    }

    fn authenticated_signing_mode(&self) -> WalletResult<HardwareSigningMode> {
        let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        if matches!(session.key, SessionKey::WatchOnly) {
            return Ok(HardwareSigningMode::WatchOnly);
        }
        let vault = self.read_vault()?;
        vault.validate_authenticated_policy()?;
        match vault.metadata.hardware_signing_mode.as_str() {
            "software" => Ok(HardwareSigningMode::Software),
            "webauthn_gate" => Ok(HardwareSigningMode::WebAuthnGate),
            "airgap_only" => Ok(HardwareSigningMode::AirgapOnly),
            _ => Err(WalletError::Policy(
                "authenticated vault hardware mode is invalid".into(),
            )),
        }
    }

    fn read_vault(&self) -> WalletResult<EncryptedVault> {
        if let Some(v) = &self.vault_cache {
            return Ok(v.clone());
        }
        if !self.vault_path.exists() {
            return Err(WalletError::NoWallet);
        }
        EncryptedVault::load(&self.vault_path)
    }

    fn vault_snapshot(&mut self) -> WalletResult<EncryptedVault> {
        if let Some(v) = &self.vault_cache {
            return Ok(v.clone());
        }
        if !self.vault_path.exists() {
            return Err(WalletError::NoWallet);
        }
        let vault = EncryptedVault::load(&self.vault_path)?;
        self.vault_meta = Some(vault.meta_snapshot());
        self.vault_cache = Some(vault.clone());
        Ok(vault)
    }

    fn persist_vault(&mut self, vault: EncryptedVault) -> WalletResult<()> {
        vault.save(&self.vault_path)?;
        self.vault_meta = Some(vault.meta_snapshot());
        self.vault_cache = Some(vault);
        Ok(())
    }

    /// Warm vault metadata cache (faster first `status()` after app start).
    pub fn warm_vault_cache(&mut self) -> WalletResult<()> {
        if self.vault_path.exists() && self.vault_cache.is_none() {
            let vault = self.vault_snapshot()?;
            let meta = vault.meta_snapshot();
            let (profile, hardware_mode, webauthn_enabled) =
                effective_policy_for_status(Some(&meta), true);
            self.profile = profile;
            self.settings.security_profile = self.profile.name.clone();
            self.settings.hardware_signing_mode = hardware_mode;
            self.settings.webauthn_enabled = webauthn_enabled;
            self.settings.watch_only_address = None;
            if self.settings.hardware_signing_mode == HardwareSigningMode::AirgapOnly.as_str() {
                self.settings.biometric_unlock_enabled = false;
            }
        }
        Ok(())
    }
}

fn effective_policy_for_status(
    metadata: Option<&VaultMetaSnapshot>,
    signing_vault_exists: bool,
) -> (SecurityProfile, String, bool) {
    if let Some(metadata) = metadata {
        let profile = if metadata.version >= 2
            && metadata.hardware_signing_mode != HardwareSigningMode::AirgapOnly.as_str()
        {
            SecurityProfile::from_name(&metadata.security_profile)
        } else {
            SecurityProfile::paranoid()
        };
        if metadata.version >= crate::vault::VAULT_VERSION_LATEST {
            return (
                profile,
                metadata.hardware_signing_mode.clone(),
                metadata.webauthn_credential_b64.is_some()
                    && metadata.webauthn_credential_binding_sha256.is_some(),
            );
        }
        return (
            profile,
            HardwareSigningMode::WebAuthnGate.as_str().into(),
            false,
        );
    }
    if signing_vault_exists {
        return (
            SecurityProfile::paranoid(),
            HardwareSigningMode::WebAuthnGate.as_str().into(),
            false,
        );
    }
    (
        SecurityProfile::from_name("balanced"),
        HardwareSigningMode::Software.as_str().into(),
        false,
    )
}
fn maximum_unlock_lifetime(mode: HardwareSigningMode) -> Duration {
    if mode == HardwareSigningMode::AirgapOnly {
        COLD_VAULT_UNLOCK_LIFETIME
    } else {
        MAX_UNLOCK_LIFETIME
    }
}

fn validate_new_passphrase(passphrase: &str) -> WalletResult<()> {
    const MIN_CHARS: usize = 15;
    const MAX_CHARS: usize = 1024;
    let count = passphrase.chars().count();
    if !(MIN_CHARS..=MAX_CHARS).contains(&count) {
        return Err(WalletError::Vault(format!(
            "new wallet passphrase must contain {MIN_CHARS} to {MAX_CHARS} characters"
        )));
    }
    Ok(())
}
fn format_amount_mei(amount_mei: f64) -> String {
    crate::hip23::format_mei_for_node(amount_mei)
}

fn exact_channel_deposit(value: &str, allow_zero: bool) -> WalletResult<String> {
    if value.trim() != value {
        return Err(WalletError::Policy(
            "channel deposit must not contain leading or trailing whitespace".into(),
        ));
    }
    let amount = l2_fast_pay_hub::amount::parse_amount_mei(value)
        .map_err(|error| WalletError::Policy(error.to_string()))?;
    if !allow_zero && amount == l2_fast_pay_hub::amount::HacAmount::ZERO {
        return Err(WalletError::Policy(
            "your channel deposit must be greater than zero".into(),
        ));
    }
    Ok(l2_fast_pay_hub::amount::format_amount_mei(amount))
}

#[cfg(test)]
mod exact_channel_deposit_tests {
    use super::exact_channel_deposit;

    #[test]
    fn canonical_channel_deposit_never_rounds_or_accepts_float_syntax() {
        assert_eq!(exact_channel_deposit("1.230", false).unwrap(), "1.23");
        assert_eq!(exact_channel_deposit("0", true).unwrap(), "0");
        for invalid in ["0", " 1", "1 ", "1e3", "+1", "1.0004", "NaN"] {
            assert!(exact_channel_deposit(invalid, false).is_err(), "{invalid}");
        }
    }
}

fn random_biometric_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

impl WalletService {
    /// Type 4 support is an experimental Quantum Lab feature. Keep this guard
    /// at the core boundary so direct IPC calls cannot enable it on mainnet.
    /// A live signing session is required. `Exhausted` and watch-only sessions
    /// hold no key, so they must not reach key-material code paths either.
    pub(crate) fn require_unlocked_signing_session(&self) -> WalletResult<()> {
        let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        match session.key {
            SessionKey::Signing(_) => Ok(()),
            SessionKey::WatchOnly => Err(WalletError::Policy(
                "watch-only wallet cannot access key material".into(),
            )),
            SessionKey::Exhausted => Err(WalletError::Policy(
                "signing session is exhausted; unlock again".into(),
            )),
        }
    }

    /// Exponential backoff shared by every keystore-password attempt. Callers
    /// must report the outcome with [`Self::record_quantum_keystore_attempt`].
    pub(crate) fn check_quantum_keystore_attempt_allowed(&self) -> WalletResult<()> {
        self.quantum_keystore_guard.check_allowed()
    }

    pub(crate) fn record_quantum_keystore_attempt(&mut self, accepted: bool) {
        if accepted {
            self.quantum_keystore_guard.record_success();
        } else {
            self.quantum_keystore_guard.record_failure();
        }
    }

    #[doc(hidden)]
    pub fn audit_quantum_keystore_failures(&self) -> u32 {
        self.quantum_keystore_guard.audit_failures()
    }

    pub(crate) fn require_quantum_testnet(&self) -> WalletResult<()> {
        if self.network_mode == "testnet" {
            return Ok(());
        }
        Err(WalletError::Policy(
            "Quantum Lab Type 4 transactions are testnet only and cannot be used on mainnet".into(),
        ))
    }

    pub(crate) fn quantum_mode_enabled(&self) -> bool {
        self.settings.quantum_mode
    }

    pub(crate) fn quantum_meta_snapshot(&self) -> Option<crate::settings::QuantumMeta> {
        self.settings.quantum_meta.clone()
    }

    pub(crate) fn quantum_keystore_json(&self) -> WalletResult<Option<String>> {
        self.reject_cold_vault_key_access("reading Quantum key material")?;
        if let Some(mem) = &self.quantum_keystore_mem {
            return Ok(Some(mem.clone()));
        }
        Ok(self.settings.quantum_keystore_json.clone())
    }

    pub(crate) fn ensure_quantum_signing_policy(&self, amount_mei: f64) -> WalletResult<()> {
        let watch_only = self
            .unlocked
            .as_ref()
            .map(|s| matches!(s.key, SessionKey::WatchOnly))
            .unwrap_or(true);
        let webauthn_verified = self
            .unlocked
            .as_ref()
            .map(|s| s.webauthn_verified)
            .unwrap_or(false);
        crate::hardware::check_signing_allowed(
            self.authenticated_signing_mode()?,
            watch_only,
            webauthn_verified,
        )?;
        let unlock_ctx = self.second_factor_from_session()?;
        let policy_amount = crate::hip23::policy_amount_mei_ceil(amount_mei)?;
        check_send_policy(&self.effective_profile(), policy_amount, &unlock_ctx)?;
        if self.profile.yubikey_required {
            let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
            if !session.webauthn_verified {
                return Err(WalletError::Policy(
                    "WebAuthn (YubiKey/Windows Hello) required. complete ceremony first".into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn append_quantum_history(
        &mut self,
        tx_hash: &str,
        from: &str,
        to: &str,
        amount_mei: f64,
        summary: &str,
    ) -> WalletResult<()> {
        self.append_history_if_enabled(
            PaymentRail::QuantumType4,
            tx_hash,
            from,
            to,
            amount_mei,
            summary,
        )
    }

    pub(crate) fn set_quantum_mode_flag(&mut self, enabled: bool) -> WalletResult<()> {
        self.bump_unlock_activity();
        self.settings.quantum_mode = enabled;
        self.settings.save()?;
        Ok(())
    }

    pub fn store_quantum_keystore_json(&mut self, json: String) -> WalletResult<()> {
        self.reject_cold_vault_key_access("storing Quantum key material")?;
        if self
            .unlocked
            .as_ref()
            .is_some_and(|session| matches!(session.key, SessionKey::Exhausted))
        {
            return Err(WalletError::Policy(
                "cold vault signing session is exhausted; unlock before storing key material"
                    .into(),
            ));
        }
        self.bump_unlock_activity();
        if let Some(meta) = crate::quantum::quantum_meta_from_json(&json) {
            self.settings.quantum_meta = Some(meta);
        }
        self.settings.quantum_keystore_json = None;
        self.settings.quantum_mode = true;
        self.quantum_keystore_mem = Some(json.clone());
        if let Some(session) = self.unlocked.as_mut()
            && let Some(key) = session.quantum_file_key.as_ref()
        {
            crate::quantum_vault::save_encrypted(key, &json)?;
        }
        self.settings.save()?;
        Ok(())
    }

    pub(crate) fn node_client(&self) -> &NodeClient {
        &self.node
    }
}

#[cfg(test)]
mod vault_migration_tests {
    use super::*;
    use crate::test_support::IsolatedWalletData;

    const OLD_PASS: &str = "old-wallet-passphrase";
    const NEW_PASS: &str = "new-wallet-passphrase";

    #[test]
    fn renderer_activity_never_extends_the_absolute_unlock_deadline() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        wallet.create_wallet(OLD_PASS).unwrap();

        let original_deadline = wallet.unlocked.as_ref().unwrap().absolute_deadline;
        let opened_at = wallet.unlocked.as_ref().unwrap().unlocked_at;
        assert_eq!(
            original_deadline.saturating_duration_since(opened_at),
            MAX_UNLOCK_LIFETIME
        );
        wallet.bump_unlock_activity();
        assert_eq!(
            wallet.unlocked.as_ref().unwrap().absolute_deadline,
            original_deadline
        );

        wallet.unlocked.as_mut().unwrap().absolute_deadline =
            Instant::now() - Duration::from_secs(1);
        wallet.bump_unlock_activity();
        assert!(wallet.unlocked.is_none());
    }

    #[test]
    fn cold_vault_activity_is_a_noop_and_uses_the_stricter_deadline() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        wallet.create_wallet(OLD_PASS).unwrap();
        wallet.audit_activate_cold_vault(OLD_PASS).unwrap();

        let session = wallet.unlocked.as_ref().unwrap();
        assert!(
            session
                .absolute_deadline
                .saturating_duration_since(session.unlocked_at)
                <= COLD_VAULT_UNLOCK_LIFETIME
        );
        let idle_before = session.unlocked_at;
        let deadline_before = session.absolute_deadline;
        wallet.bump_unlock_activity();
        let session = wallet.unlocked.as_ref().unwrap();
        assert_eq!(session.unlocked_at, idle_before);
        assert_eq!(session.absolute_deadline, deadline_before);

        wallet.unlocked.as_mut().unwrap().absolute_deadline =
            Instant::now() - Duration::from_secs(1);
        wallet.touch_auto_lock();
        assert!(wallet.unlocked.is_none());
    }

    #[test]
    fn authenticated_vault_policy_overrides_tampered_settings() {
        let _wallet_data = IsolatedWalletData::new();
        let wallet = WalletService::new(None, None).unwrap();
        let account = WalletAccount::create_random().unwrap();
        let secret = account.secret_hex();
        let address = account.address();
        let vault = EncryptedVault::encrypt_with_policy(
            &secret,
            &address,
            OLD_PASS,
            "paranoid",
            "webauthn_gate",
            None,
            None,
        )
        .unwrap();
        vault.save(&wallet.vault_path).unwrap();

        let tampered = WalletSettings {
            security_profile: "balanced".into(),
            hardware_signing_mode: "software".into(),
            webauthn_enabled: false,
            ..WalletSettings::default()
        };
        tampered.save().unwrap();
        drop(wallet);

        let mut reopened = WalletService::new(None, None).unwrap();
        let status = reopened.status();
        assert_eq!(status.security_profile, "paranoid");
        assert_eq!(status.hardware_signing_mode, "webauthn_gate");
        assert!(!status.watch_only);
        assert_eq!(reopened.unlock(OLD_PASS).unwrap(), address);
        let settings = reopened.get_settings();
        assert_eq!(settings.security_profile, "paranoid");
        assert_eq!(settings.hardware_signing_mode, "webauthn_gate");

        let mirrored = WalletSettings::load().unwrap();
        assert_eq!(mirrored.security_profile, "paranoid");
        assert_eq!(mirrored.hardware_signing_mode, "webauthn_gate");
    }

    #[test]
    fn legacy_v2_unlock_migrates_to_v3_without_trusting_legacy_second_factor() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        let account = WalletAccount::create_random().unwrap();
        let secret = account.secret_hex();
        let address = account.address();
        let legacy = EncryptedVault::encrypt_legacy_v2_for_test(
            &secret,
            &address,
            OLD_PASS,
            "balanced",
            Some("attacker-replaceable-legacy-credential"),
        )
        .unwrap();
        legacy.save(&wallet.vault_path).unwrap();

        wallet.settings.security_profile = "balanced".into();
        wallet.settings.hardware_signing_mode = "software".into();
        wallet.settings.webauthn_enabled = true;
        wallet.settings.save().unwrap();

        let status = wallet.status();
        assert_eq!(status.hardware_signing_mode, "webauthn_gate");
        assert!(!status.webauthn_enabled);
        assert_eq!(wallet.unlock(OLD_PASS).unwrap(), address);

        let migrated = EncryptedVault::load(&wallet.vault_path).unwrap();
        assert_eq!(
            migrated.metadata.version,
            crate::vault::VAULT_VERSION_LATEST
        );
        assert_eq!(migrated.metadata.security_profile, "balanced");
        assert_eq!(migrated.metadata.hardware_signing_mode, "webauthn_gate");
        assert!(migrated.metadata.webauthn_credential_b64.is_none());
        assert!(
            migrated
                .metadata
                .webauthn_credential_binding_sha256
                .is_none()
        );
        assert!(migrated.decrypt_verified_secret(OLD_PASS).is_ok());
        assert_eq!(wallet.settings.hardware_signing_mode, "webauthn_gate");
        assert!(!wallet.settings.webauthn_enabled);
    }

    #[test]
    fn passphrase_change_rotates_classic_and_quantum_vaults_together() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        let address = wallet.create_wallet(OLD_PASS).unwrap();

        let current_vault = wallet.vault_snapshot().unwrap();
        let old_quantum_key =
            crate::quantum_vault::QuantumFileKey::derive(OLD_PASS, current_vault.salt()).unwrap();
        let quantum_json = r#"{"kind":"opaque","payload":"protected-quantum-key"}"#;
        crate::quantum_vault::save_encrypted(&old_quantum_key, quantum_json).unwrap();
        wallet.quantum_keystore_mem = Some(quantum_json.into());

        wallet.change_passphrase(OLD_PASS, NEW_PASS).unwrap();
        wallet.lock();
        let migrated_vault = EncryptedVault::load(&wallet.vault_path).unwrap();
        assert!(migrated_vault.decrypt(OLD_PASS).is_err());
        assert_eq!(wallet.unlock(NEW_PASS).unwrap(), address);
        assert_eq!(
            wallet.quantum_keystore_json().unwrap().as_deref(),
            Some(quantum_json)
        );

        let migrated_vault = EncryptedVault::load(&wallet.vault_path).unwrap();
        let new_quantum_key =
            crate::quantum_vault::QuantumFileKey::derive(NEW_PASS, migrated_vault.salt()).unwrap();
        assert_eq!(
            crate::quantum_vault::load_encrypted(&new_quantum_key)
                .unwrap()
                .as_deref(),
            Some(quantum_json)
        );
        assert!(crate::quantum_vault::load_encrypted(&old_quantum_key).is_err());
    }

    #[test]
    fn cold_vault_never_retains_quantum_file_key_or_plaintext() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        wallet.create_wallet(OLD_PASS).unwrap();
        wallet
            .store_quantum_keystore_json(
                r#"{"kind":"opaque","payload":"protected-quantum-key"}"#.into(),
            )
            .unwrap();

        wallet.audit_activate_cold_vault(OLD_PASS).unwrap();
        assert!(wallet.quantum_keystore_mem.is_none());
        assert!(
            wallet
                .unlocked
                .as_ref()
                .is_some_and(|session| session.quantum_file_key.is_none())
        );

        wallet.lock();
        std::fs::write(
            crate::paths::quantum_keystore_path(),
            b"intentionally corrupt",
        )
        .unwrap();
        wallet.unlock(OLD_PASS).unwrap();
        assert!(wallet.quantum_keystore_mem.is_none());
        assert!(
            wallet
                .unlocked
                .as_ref()
                .is_some_and(|session| session.quantum_file_key.is_none())
        );
    }

    #[test]
    fn failed_authentication_changes_no_wallet_file() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        wallet.create_wallet(OLD_PASS).unwrap();

        let current_vault = wallet.vault_snapshot().unwrap();
        let quantum_key =
            crate::quantum_vault::QuantumFileKey::derive(OLD_PASS, current_vault.salt()).unwrap();
        crate::quantum_vault::save_encrypted(&quantum_key, r#"{"payload":"quantum"}"#).unwrap();

        let vault_before = std::fs::read(&wallet.vault_path).unwrap();
        let quantum_before = std::fs::read(crate::paths::quantum_keystore_path()).unwrap();
        let settings_before = std::fs::read(crate::paths::settings_path()).unwrap();

        assert!(
            wallet
                .change_passphrase("incorrect-passphrase", NEW_PASS)
                .is_err()
        );
        assert_eq!(std::fs::read(&wallet.vault_path).unwrap(), vault_before);
        assert_eq!(
            std::fs::read(crate::paths::quantum_keystore_path()).unwrap(),
            quantum_before
        );
        assert_eq!(
            std::fs::read(crate::paths::settings_path()).unwrap(),
            settings_before
        );
    }

    #[test]
    fn security_profile_change_requires_authentication_and_reencrypts_kdf() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        wallet.create_wallet(OLD_PASS).unwrap();

        let vault_before = std::fs::read(&wallet.vault_path).unwrap();
        assert!(
            wallet
                .set_security_profile(SecurityProfile::paranoid())
                .is_err()
        );
        assert_eq!(std::fs::read(&wallet.vault_path).unwrap(), vault_before);
        assert!(
            wallet
                .change_security_profile("incorrect-passphrase", SecurityProfile::paranoid(),)
                .is_err()
        );
        assert_eq!(std::fs::read(&wallet.vault_path).unwrap(), vault_before);

        let mut wallet = WalletService::new(None, None).unwrap();
        wallet
            .change_security_profile(OLD_PASS, SecurityProfile::paranoid())
            .unwrap();
        let migrated = EncryptedVault::load(&wallet.vault_path).unwrap();
        assert_eq!(migrated.metadata.security_profile, "paranoid");
        assert_eq!(
            migrated.metadata.kdf,
            crate::kdf::KdfParams::paranoid().label()
        );
        assert!(migrated.decrypt_verified_secret(OLD_PASS).is_ok());
        assert_eq!(wallet.settings.security_profile, "paranoid");
    }

    #[test]
    fn generic_settings_reject_sensitive_changes_and_preserve_redacted_secret() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        wallet.create_wallet(OLD_PASS).unwrap();
        wallet.settings.quantum_keystore_json = Some("legacy-protected-value".into());

        let mut redacted = wallet.get_settings();
        redacted.quantum_keystore_json = None;
        wallet.update_settings(redacted).unwrap();
        assert_eq!(
            wallet.settings.quantum_keystore_json.as_deref(),
            Some("legacy-protected-value")
        );

        let mut submitted_secret = wallet.get_settings();
        submitted_secret.quantum_keystore_json = Some("renderer-value".into());
        assert!(wallet.update_settings(submitted_secret).is_err());

        let mut downgraded = wallet.get_settings();
        downgraded.security_profile = "paranoid".into();
        assert!(wallet.update_settings(downgraded).is_err());

        let mut hardware = wallet.get_settings();
        hardware.hardware_signing_mode = "watch_only".into();
        assert!(wallet.update_settings(hardware).is_err());
    }

    /// Consent to the bounded mainnet pilot is a money-policy decision, and the
    /// generic settings command must not be able to make it.
    ///
    /// It was the only field on this struct that chose a mainnet settlement
    /// model and that any unauthenticated caller on the IPC surface could flip,
    /// while a channel id - which decides far less - already needed the
    /// authenticated path. Withdrawal is the other half and is deliberately not
    /// symmetric: turning the pilot off is a tightening, and a user who wants
    /// out must never be held in by a screen that cannot ask for a passphrase.
    #[test]
    fn bounded_mainnet_pilot_consent_needs_its_own_authenticated_command() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        wallet.create_wallet(OLD_PASS).unwrap();
        assert!(!wallet.settings.trusted_mainnet_fast_pay_pilot);

        let mut consented = wallet.get_settings();
        consented.trusted_mainnet_fast_pay_pilot = true;
        assert!(
            wallet.update_settings(consented).is_err(),
            "generic settings must not be able to turn the mainnet pilot on"
        );
        assert!(!wallet.settings.trusted_mainnet_fast_pay_pilot);

        wallet
            .set_trusted_mainnet_fast_pay_pilot(OLD_PASS, true)
            .unwrap();
        assert!(wallet.settings.trusted_mainnet_fast_pay_pilot);
        // The router is what the Send screen asks for a rail, and it holds its
        // own copy of the settings. A consent that never reaches it is a
        // consent that does nothing until the wallet is restarted.
        assert!(wallet.router.settings().trusted_mainnet_fast_pay_pilot);

        assert!(
            wallet
                .set_trusted_mainnet_fast_pay_pilot("wrong-passphrase", false)
                .is_err(),
            "the authenticated command must still check the passphrase"
        );
        assert!(wallet.settings.trusted_mainnet_fast_pay_pilot);

        let mut withdrawn = wallet.get_settings();
        withdrawn.trusted_mainnet_fast_pay_pilot = false;
        wallet
            .update_settings(withdrawn)
            .expect("withdrawing consent is a tightening and needs no ceremony");
        assert!(!wallet.settings.trusted_mainnet_fast_pay_pilot);
        assert!(!wallet.router.settings().trusted_mainnet_fast_pay_pilot);
    }

    #[test]
    fn sensitive_passphrase_verification_uses_shared_backoff() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).unwrap();
        wallet.create_wallet(OLD_PASS).unwrap();

        assert!(
            wallet
                .verify_wallet_passphrase("incorrect-passphrase")
                .is_err()
        );
        assert!(matches!(
            wallet.verify_wallet_passphrase(OLD_PASS),
            Err(WalletError::UnlockRateLimited(_))
        ));
    }
}

#[cfg(test)]
mod asset_facade_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::test_support::IsolatedWalletData;

    const WATCH_ADDRESS: &str = "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW";

    async fn spawn_balance_node(balance: f64) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let route_calls = Arc::clone(&calls);
        let app = Router::new().route(
            "/query/balance",
            get(move || {
                let calls = Arc::clone(&route_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Json(json!({
                        "ret": 0,
                        "list": [{
                            "address": WATCH_ADDRESS,
                            "hacash": balance.to_string(),
                            "diamond": 0,
                            "satoshi": 0,
                            "diamonds": ""
                        }]
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind wallet facade node");
        let address = listener.local_addr().expect("wallet facade node address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve wallet facade node");
        });
        (format!("http://{address}"), calls, server)
    }

    #[tokio::test]
    async fn locked_and_auto_locked_asset_reads_never_reach_the_node() {
        let _wallet_data = IsolatedWalletData::new();
        let (node_url, calls, server) = spawn_balance_node(7.0).await;
        let mut wallet = WalletService::new(Some(node_url), None).expect("test wallet service");

        assert!(matches!(
            wallet.balance_mei().await,
            Err(WalletError::Locked)
        ));
        assert!(matches!(
            wallet.list_owned_diamonds().await,
            Err(WalletError::Locked)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        wallet
            .import_watch_only(WATCH_ADDRESS)
            .expect("watch-only session");
        wallet.profile.auto_lock_secs = 0;
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(matches!(
            wallet.balance_mei().await,
            Err(WalletError::Locked)
        ));
        assert!(wallet.status().locked);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn watch_only_reads_assets_but_node_switch_cannot_reuse_old_cache() {
        let _wallet_data = IsolatedWalletData::new();
        let (node_a, calls_a, server_a) = spawn_balance_node(1.0).await;
        let (node_b, calls_b, server_b) = spawn_balance_node(2.0).await;
        let mut wallet = WalletService::new(Some(node_a), None).expect("test wallet service");
        wallet
            .import_watch_only(WATCH_ADDRESS)
            .expect("watch-only session");

        assert_eq!(wallet.balance_mei().await.unwrap(), 1.0);
        assert_eq!(wallet.balance_mei().await.unwrap(), 1.0);
        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
        assert!(matches!(
            wallet.require_signing_account(),
            Err(WalletError::Policy(_))
        ));

        let mut settings = wallet.get_settings();
        settings.node_url = node_b;
        wallet.update_settings(settings).expect("switch node");
        assert_eq!(wallet.balance_mei().await.unwrap(), 2.0);
        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b.load(Ordering::SeqCst), 1);

        server_a.abort();
        server_b.abort();
    }
}

#[cfg(test)]
mod node_discovery_commit_tests {
    use super::*;
    use crate::node_discovery::{NodeCandidateStatus, NodeDiscoveryReport};
    use crate::test_support::IsolatedWalletData;

    fn candidate(url: &str, online: bool) -> NodeCandidateStatus {
        NodeCandidateStatus {
            url: url.into(),
            online,
            network_match: online,
            height: online.then_some(100),
            diamond: online.then_some(5),
            error: (!online).then(|| "offline".into()),
        }
    }

    #[test]
    fn stale_node_configuration_never_switches_to_an_old_candidate() {
        let _wallet_data = IsolatedWalletData::new();
        let active = "http://127.0.0.1:30001";
        let old_fallback = "http://127.0.0.1:30002";
        let new_fallback = "http://127.0.0.1:30003";
        let mut wallet = WalletService::new(Some(active.into()), None).unwrap();
        wallet.settings.node_fallback_urls = vec![old_fallback.into()];
        let snapshot = wallet.node_discovery_snapshot();
        let report = NodeDiscoveryReport {
            active_node: active.into(),
            switched: false,
            network_mode: snapshot.network_mode.clone(),
            candidates: vec![candidate(active, false), candidate(old_fallback, true)],
        };

        // Simulate a settings update racing with the in-flight network probes.
        wallet.settings.node_fallback_urls = vec![new_fallback.into()];
        let committed = wallet
            .commit_node_discovery(&snapshot, report)
            .expect("stale discovery must be ignored safely");

        assert!(!committed.switched);
        assert_eq!(committed.active_node, active);
        assert_eq!(wallet.node.base_url(), active);
        assert_eq!(wallet.settings.node_fallback_urls, vec![new_fallback]);
    }
}

#[cfg(test)]
mod quantum_network_policy_tests {
    use super::*;
    use crate::test_support::IsolatedWalletData;

    fn unsigned_type4() -> AirgapUnsigned {
        AirgapUnsigned {
            v: AIRGAP_VERSION,
            from: "quantum-from".into(),
            to: "recipient".into(),
            amount_mei: 1.0,
            amount_wire: "1".into(),
            fee: "1:244".into(),
            service_fee_mei: 0.003,
            service_fee_treasury: Some(crate::send_options::WALLET_TREASURY_ADDRESS.into()),
            body_hex: "00".into(),
            summary: "test Type 4".into(),
            tx_type: 4,
        }
    }

    fn signed_type4() -> AirgapSigned {
        let unsigned = unsigned_type4();
        AirgapSigned {
            v: unsigned.v,
            from: unsigned.from,
            to: unsigned.to,
            amount_mei: unsigned.amount_mei,
            amount_wire: unsigned.amount_wire,
            fee: unsigned.fee,
            service_fee_mei: unsigned.service_fee_mei,
            service_fee_treasury: unsigned.service_fee_treasury,
            signed_hex: unsigned.body_hex,
            summary: unsigned.summary,
            tx_type: unsigned.tx_type,
        }
    }

    fn assert_testnet_gate<T>(result: WalletResult<T>) {
        match result {
            Err(WalletError::Policy(message)) => {
                assert!(
                    message.contains("testnet only"),
                    "unexpected policy error: {message}"
                );
            }
            Err(error) => panic!("expected testnet policy error, got {error}"),
            Ok(_) => panic!("mainnet Type 4 path unexpectedly succeeded"),
        }
    }

    #[tokio::test]
    async fn every_type4_boundary_rejects_mainnet_before_other_work() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(Some("http://127.0.0.1:1".into()), None)
            .expect("test wallet service");
        wallet.network_mode = "mainnet".into();

        assert_testnet_gate(wallet.require_quantum_testnet());
        assert_testnet_gate(wallet.quantum_preflight_type4("invalid", "1").await);
        assert_testnet_gate(wallet.quantum_send_type4("invalid", "1", "pass").await);
        assert_testnet_gate(wallet.prepare_airgap_type4("invalid", "1").await);
        assert_testnet_gate(wallet.quantum_airgap_sign_type4(&unsigned_type4(), "pass"));
        assert_testnet_gate(wallet.broadcast_airgap_signed(&signed_type4()).await);
    }

    #[test]
    fn centralized_quantum_gate_allows_only_exact_testnet_mode() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(Some("http://127.0.0.1:1".into()), None)
            .expect("test wallet service");

        wallet.network_mode = "testnet".into();
        assert!(wallet.require_quantum_testnet().is_ok());

        for mode in ["mainnet", "", "TESTNET", "unknown"] {
            wallet.network_mode = mode.into();
            assert_testnet_gate(wallet.require_quantum_testnet());
        }
    }
}

#[cfg(test)]
mod l1_recipient_network_policy_tests {
    use field::Address;

    use super::*;
    use crate::test_support::IsolatedWalletData;

    #[test]
    fn mainnet_l1_preview_policy_rejects_quantum_and_accepts_p2sh() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(Some("http://127.0.0.1:1".into()), None)
            .expect("test wallet service");
        wallet.network_mode = "mainnet".into();

        let pqc = Address::create_pqckey([6; 20]).to_readable();
        let hybrid = Address::create_hybrid([7; 20]).to_readable();
        let p2sh = Address::create_scriptmh([5; 20]).to_readable();

        assert!(matches!(
            wallet.require_l1_recipient(&pqc),
            Err(WalletError::Policy(_))
        ));
        assert!(matches!(
            wallet.require_l1_recipient(&hybrid),
            Err(WalletError::Policy(_))
        ));
        assert!(wallet.require_l1_recipient(&p2sh).is_ok());
    }
}
