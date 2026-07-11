use std::path::PathBuf;
use std::time::{Duration, Instant};

use protocol::transaction;
use sys::ToHex;
use zeroize::Zeroize;

use crate::account::WalletAccount;
use crate::airgap::{
    encode_envelope_qr, parse_airgap_qr_parts, parse_airgap_qr_text, AirgapEnvelope,
    AirgapParseResult, AirgapPrepareResult, AirgapSignResult, AirgapSigned, AirgapUnsigned,
    AIRGAP_VERSION,
};
use crate::bills::{BillEntry, BillStore};
use crate::hardware::{check_signing_allowed, HardwareSigningMode};
use crate::channel::{
    build_channel_close_tx, build_channel_open_tx, derive_channel_id, query_channel, ChannelInfo,
};
use crate::error::{WalletError, WalletResult};
use crate::hip23::{
    is_valid_hacash_address, validate_all_patterns, validate_simple_l1_send, BalanceFloorInput,
    HeightScopeInput, Hip23PatternCheck, Hip23SendCheck, Type3CheckInput,
};

use crate::fast_pay::{
    apply_discovered_hub, discover_healthy_hub, evaluate_fast_pay, FastPayStatus,
    DEFAULT_CHANNEL_DEPOSIT_MEI,
};
use crate::history::{TxHistory, TxRecord};
use crate::l2_hub::{HubHealth, L2HubClient};
use crate::dust_whisper::{
    relay_health as whisper_relay_health, submit_tx_hex as whisper_submit_tx_hex,
    whisper_fallback_notice, DustWhisperSettings, RelayHealthStatus,
};
use crate::node::NodeClient;
use crate::payment::{PaymentPlan, PaymentRail, PaymentRouter};
use crate::privacy::{mask_address, mask_amount, mask_hash, PrivacySettings};
use crate::security::{check_send_policy, SecurityProfile, UnlockContext};
use crate::settings::WalletSettings;
use crate::unlock_guard::UnlockGuard;
use crate::vault::{default_vault_path, EncryptedVault, VaultMetaSnapshot};
use crate::webauthn::WebAuthnGate;

const BALANCE_CACHE_TTL: Duration = Duration::from_secs(12);

pub struct WalletService {
    vault_path: PathBuf,
    vault_cache: Option<EncryptedVault>,
    vault_meta: Option<VaultMetaSnapshot>,
    node: NodeClient,
    router: PaymentRouter,
    profile: SecurityProfile,
    settings: WalletSettings,
    bills: BillStore,
    history: TxHistory,
    webauthn: WebAuthnGate,
    unlock_guard: UnlockGuard,
    balance_cache: Option<(String, f64, Instant)>,
    quantum_keystore_mem: Option<String>,
    unlocked: Option<UnlockedSession>,
}

enum SessionKey {
    Signing(WalletAccount),
    WatchOnly,
}

struct UnlockedSession {
    address: String,
    key: SessionKey,
    unlocked_at: Instant,
    /// Set only by `webauthn_auth_finish` — never trusted from IPC/UI flags.
    webauthn_verified: bool,
    /// Set only by `finish_native_biometric` after OS verification.
    biometric_verified: bool,
    pending_biometric_nonce: Option<String>,
    quantum_file_key: Option<crate::quantum_vault::QuantumFileKey>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletStatus {
    pub has_wallet: bool,
    pub locked: bool,
    pub address: Option<String>,
    pub security_profile: String,
    pub node_url: String,
    pub l2_enabled: bool,
    pub l2_hub_url: Option<String>,
    pub channel_id: Option<String>,
    pub webauthn_enabled: bool,
    pub l2_bill_count: usize,
    pub auto_lock_secs: u64,
    pub seconds_until_lock: Option<u64>,
    pub hardware_signing_mode: String,
    pub watch_only: bool,
    pub privacy: PrivacySettings,
    pub dust_whisper: DustWhisperSettings,
    pub fast_pay_state: String,
    pub fast_pay_message: String,
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

#[derive(Debug, Clone, serde::Serialize)]
pub struct SendResult {
    pub rail: PaymentRail,
    pub tx_hash: String,
    pub summary: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AssetSummary {
    pub hac_mei: f64,
    pub hacd_count: usize,
    pub hacd_names: Vec<String>,
    /// On-chain BTC balance in the Hacash wallet (satoshi).
    pub btc_wallet_satoshi: u64,
    /// BTC balance locked in the active Fast Pay channel (satoshi), if any.
    pub btc_channel_satoshi: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelSetupPreview {
    pub channel_id: String,
    pub left_address: String,
    pub right_address: String,
    pub left_deposit: String,
    pub right_deposit: String,
}

impl WalletService {
    pub fn new(node_url: Option<String>, l2_hub_url: Option<String>) -> WalletResult<Self> {
        crate::protocol_init::ensure_protocol_setup();
        let mut settings = WalletSettings::load().unwrap_or_default();
        if let Some(url) = node_url {
            settings.node_url = url;
        }
        if let Some(hub) = l2_hub_url {
            settings.l2_hub_url = Some(hub);
        }
        let profile = SecurityProfile::from_name(&settings.security_profile);
        let node = NodeClient::new(settings.node_url.clone());
        let bills = BillStore::load().unwrap_or_default();
        let history = TxHistory::load().unwrap_or_default();
        let router = PaymentRouter::new(node.clone(), settings.clone(), bills.clone());
        Ok(Self {
            vault_path: default_vault_path(),
            vault_cache: None,
            vault_meta: None,
            node,
            router,
            profile,
            settings,
            bills,
            history,
            webauthn: WebAuthnGate::new()?,
            unlock_guard: UnlockGuard::default(),
            balance_cache: None,
            quantum_keystore_mem: None,
            unlocked: None,
        })
    }

    pub fn status(&self) -> WalletStatus {
        let has_wallet =
            self.vault_path.exists() || self.settings.watch_only_address.is_some();
        let watch_only = self.settings.hardware_mode() == HardwareSigningMode::WatchOnly
            || self.settings.watch_only_address.is_some();
        let meta = self
            .vault_meta
            .as_ref()
            .cloned()
            .or_else(|| self.read_vault().ok().map(|v| v.meta_snapshot()));
        let vault_webauthn = meta
            .as_ref()
            .and_then(|m| m.webauthn_credential_b64.clone());
        let seconds_until_lock = self.unlocked.as_ref().map(|s| {
            let elapsed = s.unlocked_at.elapsed().as_secs();
            self.profile.auto_lock_secs.saturating_sub(elapsed)
        });
        let fast_pay = self.fast_pay_status_sync();
        WalletStatus {
            has_wallet,
            locked: self.unlocked.is_none(),
            address: self
                .unlocked
                .as_ref()
                .map(|s| s.address.clone())
                .or_else(|| meta.map(|m| m.address))
                .or_else(|| self.settings.watch_only_address.clone()),
            security_profile: self.profile.name.clone(),
            node_url: self.node.base_url().to_string(),
            l2_enabled: self.router.has_l2_hub(),
            l2_hub_url: self.settings.l2_hub_url.clone(),
            channel_id: self.settings.channel_id_hex.clone(),
            webauthn_enabled: vault_webauthn.is_some() || self.settings.webauthn_enabled,
            l2_bill_count: self.bills.count(),
            auto_lock_secs: self.profile.auto_lock_secs,
            seconds_until_lock,
            hardware_signing_mode: self.settings.hardware_signing_mode.clone(),
            watch_only,
            privacy: self.settings.privacy.clone(),
            dust_whisper: self.settings.dust_whisper.clone(),
            fast_pay_state: fast_pay.state.as_str().to_string(),
            fast_pay_message: fast_pay.message,
        }
    }

    fn fast_pay_status_sync(&self) -> FastPayStatus {
        if self.settings.channel_id_hex.is_some() && self.settings.l2_hub_url.is_some() {
            return FastPayStatus::ready("Fast Pay");
        }
        if self.settings.l2_hub_url.is_some() {
            return FastPayStatus::needs_channel("your provider", DEFAULT_CHANNEL_DEPOSIT_MEI);
        }
        FastPayStatus::no_provider()
    }

    pub fn get_settings(&self) -> WalletSettings {
        self.settings.clone()
    }

    pub fn update_settings(&mut self, settings: WalletSettings) -> WalletResult<()> {
        settings.save()?;
        self.router.update_settings(settings.clone());
        self.node = NodeClient::new(settings.node_url.clone());
        self.profile = SecurityProfile::from_name(&settings.security_profile);
        self.settings = settings;
        Ok(())
    }

    pub fn create_wallet(&mut self, passphrase: &str) -> WalletResult<String> {
        if self.vault_path.exists() {
            return Err(WalletError::Vault("wallet already exists".into()));
        }
        let account = WalletAccount::create(passphrase)?;
        let address = account.address();
        let mut secret = account.secret_hex();
        let vault = EncryptedVault::encrypt(&secret, &address, passphrase, &self.profile.name)?;
        secret.zeroize();
        self.persist_vault(vault)?;
        self.settings.save()?;
        self.unlock(passphrase)?;
        Ok(address)
    }

    pub fn import_wallet(&mut self, seed: &str, passphrase: &str) -> WalletResult<String> {
        if self.vault_path.exists() {
            return Err(WalletError::Vault("wallet already exists — remove vault first".into()));
        }
        if seed.trim().is_empty() || passphrase.len() < 8 {
            return Err(WalletError::Vault(
                "seed and passphrase (min 8 chars) required".into(),
            ));
        }
        let trimmed = seed.trim();
        if trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.len() != 64 {
            return Err(WalletError::Vault(
                "hex secret must be exactly 64 characters".into(),
            ));
        }
        let account = if is_secret_hex(seed) {
            WalletAccount::from_secret_hex(seed.trim())?
        } else {
            WalletAccount::create(seed.trim())?
        };
        let address = account.address();
        let mut secret = account.secret_hex();
        let vault = EncryptedVault::encrypt(&secret, &address, passphrase, &self.profile.name)?;
        secret.zeroize();
        self.persist_vault(vault)?;
        self.settings.save()?;
        self.unlock(passphrase)?;
        Ok(address)
    }

    pub fn export_backup(&self, passphrase: &str) -> WalletResult<String> {
        if !self.vault_path.exists() {
            return Err(WalletError::NoWallet);
        }
        let vault = self.read_vault()?;
        vault.decrypt(passphrase)?;
        vault.export_json()
    }

    pub fn change_passphrase(&mut self, old_passphrase: &str, new_passphrase: &str) -> WalletResult<()> {
        if new_passphrase.len() < 8 {
            return Err(WalletError::Vault("new passphrase must be at least 8 characters".into()));
        }
        let mut vault = self.vault_snapshot()?;
        vault.reencrypt(old_passphrase, new_passphrase)?;
        vault.metadata.security_profile = self.profile.name.clone();
        if self.unlocked.is_some() {
            let mut secret = vault.decrypt(new_passphrase)?;
            let account = WalletAccount::from_secret_hex(&secret)?;
            secret.zeroize();
            if let Some(session) = &mut self.unlocked {
                session.address = account.address();
                session.key = SessionKey::Signing(account);
                session.unlocked_at = Instant::now();
            }
        }
        self.persist_vault(vault)?;
        Ok(())
    }

    pub fn unlock(&mut self, passphrase: &str) -> WalletResult<String> {
        if self.unlocked.is_some() {
            return Err(WalletError::AlreadyUnlocked);
        }
        self.unlock_guard.check_allowed()?;
        let vault = self.vault_snapshot()?;
        let decrypt_result = vault.decrypt(passphrase);
        if decrypt_result.is_err() {
            self.unlock_guard.record_failure();
            return Err(WalletError::InvalidPassphrase);
        }
        self.unlock_guard.record_success();
        let mut secret = decrypt_result?;
        let account = WalletAccount::from_secret_hex(&secret)?;
        secret.zeroize();
        let address = account.address();
        self.profile = SecurityProfile::from_name(&self.settings.security_profile);
        self.balance_cache = None;
        let qkey = crate::quantum_vault::QuantumFileKey::derive(passphrase, vault.salt())?;
        let mut qks = crate::quantum_vault::load_encrypted(&qkey)?;
        if qks.is_none() {
            if let Some(legacy) = self.settings.quantum_keystore_json.take() {
                crate::quantum_vault::save_encrypted(&qkey, &legacy)?;
                if let Some(meta) = crate::quantum::quantum_meta_from_json(&legacy) {
                    self.settings.quantum_meta = Some(meta);
                }
                self.settings.save()?;
                qks = Some(legacy);
            }
        }
        self.quantum_keystore_mem = qks;
        self.unlocked = Some(UnlockedSession {
            address: address.clone(),
            key: SessionKey::Signing(account),
            unlocked_at: Instant::now(),
            webauthn_verified: false,
            biometric_verified: false,
            pending_biometric_nonce: None,
            quantum_file_key: Some(qkey),
        });
        Ok(address)
    }

    /// Import a watch-only wallet (Sparrow-style) — monitor balance, no local signing.
    pub fn import_watch_only(&mut self, address: &str) -> WalletResult<String> {
        let addr = address.trim();
        if !is_valid_hacash_address(addr) {
            return Err(WalletError::Vault("invalid Hacash address".into()));
        }
        if self.vault_path.exists() {
            return Err(WalletError::Vault(
                "signing wallet exists — remove vault before watch-only import".into(),
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
        self.unlocked = Some(UnlockedSession {
            address: address.clone(),
            key: SessionKey::WatchOnly,
            unlocked_at: Instant::now(),
            webauthn_verified: false,
            biometric_verified: false,
            pending_biometric_nonce: None,
            quantum_file_key: None,
        });
        Ok(address)
    }

    pub fn set_hardware_signing_mode(&mut self, mode: HardwareSigningMode) -> WalletResult<()> {
        if mode == HardwareSigningMode::WatchOnly && self.settings.watch_only_address.is_none() {
            return Err(WalletError::Vault(
                "watch-only mode requires a watch-only imported address".into(),
            ));
        }
        if mode == HardwareSigningMode::WatchOnly && self.vault_path.exists() {
            return Err(WalletError::Vault(
                "cannot enable watch-only mode while encrypted vault exists".into(),
            ));
        }
        self.settings.hardware_signing_mode = mode.as_str().into();
        self.settings.save()?;
        Ok(())
    }

    /// Begin OS-native biometric ceremony (Windows Hello). Returns nonce for platform UI.
    pub fn begin_native_biometric(&mut self) -> WalletResult<String> {
        let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
        let nonce = random_biometric_nonce();
        session.pending_biometric_nonce = Some(nonce.clone());
        Ok(nonce)
    }

    /// Complete OS-native biometric ceremony after platform verifier succeeds.
    pub fn finish_native_biometric(&mut self, nonce: &str) -> WalletResult<()> {
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

    /// Test-only bypass — production apps must use `finish_native_biometric`.
    #[doc(hidden)]
    pub fn confirm_biometric_for_send(&mut self) -> WalletResult<()> {
        let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
        session.biometric_verified = true;
        Ok(())
    }

    pub fn lock(&mut self) {
        self.unlocked = None;
        self.balance_cache = None;
        self.quantum_keystore_mem = None;
    }

    pub fn touch_auto_lock(&mut self) {
        if let Some(session) = &self.unlocked {
            if session.unlocked_at.elapsed() > Duration::from_secs(self.profile.auto_lock_secs) {
                self.lock();
            }
        }
    }

    /// Resets the auto-lock idle timer while the wallet stays unlocked.
    pub fn bump_unlock_activity(&mut self) {
        if let Some(session) = &mut self.unlocked {
            session.unlocked_at = Instant::now();
        }
    }

    pub fn webauthn_register_begin(&self) -> WalletResult<String> {
        let address = self.require_address()?;
        self.webauthn.begin_register(&address)
    }

    pub fn webauthn_register_finish(&mut self, credential_json: &str) -> WalletResult<()> {
        let cred_b64 = self.webauthn.finish_register(credential_json)?;
        let mut vault = self.vault_snapshot()?;
        vault.metadata.webauthn_credential_b64 = Some(cred_b64);
        self.persist_vault(vault)?;
        self.settings.webauthn_enabled = true;
        self.settings.save()?;
        Ok(())
    }

    pub fn webauthn_auth_begin(&self) -> WalletResult<String> {
        let cred = self
            .load_webauthn_credential()?
            .ok_or_else(|| WalletError::Policy("WebAuthn not registered".into()))?;
        let cred_id = crate::webauthn::credential_id_from_store(&cred)?;
        self.webauthn.begin_auth(&cred_id)
    }

    pub fn webauthn_auth_finish(&mut self, assertion_json: &str) -> WalletResult<()> {
        let stored = self.load_webauthn_credential()?;
        self.webauthn
            .finish_auth(assertion_json, stored.as_deref())?;
        if let Some(session) = &mut self.unlocked {
            session.webauthn_verified = true;
        }
        Ok(())
    }

    pub async fn balance_mei(&mut self) -> WalletResult<f64> {
        self.touch_auto_lock();
        let address = self.require_address()?;
        if let Some((cached_addr, bal, fetched_at)) = &self.balance_cache {
            if cached_addr == &address && fetched_at.elapsed() < BALANCE_CACHE_TTL {
                return Ok(*bal);
            }
        }
        let bal = self.node.balance_mei(&address).await?;
        self.balance_cache = Some((address, bal, Instant::now()));
        Ok(bal)
    }

    pub async fn asset_summary(&mut self) -> WalletResult<AssetSummary> {
        self.touch_auto_lock();
        let address = self.require_address()?;
        let balance_entry = self.node.query_balance_entry(&address, false).await?;
        let hac_mei = balance_entry.hacash_mei()?;
        self.balance_cache = Some((address.clone(), hac_mei, Instant::now()));
        let btc_wallet_satoshi = balance_entry.btc_satoshi();
        let hacd_names = self.list_owned_diamonds().await?;
        let hacd_count = hacd_names.len();
        let mut btc_channel_satoshi = 0u64;
        if let Some(ch) = self.channel_info().await? {
            if ch.user_is_left(&address) {
                btc_channel_satoshi = ch.left.satoshi;
            } else if ch.user_is_right(&address) {
                btc_channel_satoshi = ch.right.satoshi;
            }
        }
        Ok(AssetSummary {
            hac_mei,
            hacd_count,
            hacd_names: hacd_names.into_iter().take(8).collect(),
            btc_wallet_satoshi,
            btc_channel_satoshi,
        })
    }

    pub async fn list_owned_diamonds(&self) -> WalletResult<Vec<String>> {
        let from = self.require_address()?;
        crate::hacd_send::list_owned_diamonds(&self.node, &from).await
    }

    pub async fn preview_send_hacd(
        &mut self,
        to: &str,
        diamond_names: &[String],
    ) -> WalletResult<crate::hacd_send::HacdSendPreview> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        crate::hacd_send::preview_hacd_send(&self.node, &from, to, diamond_names).await
    }

    pub async fn preview_send_btc(
        &mut self,
        to: &str,
        satoshi: u64,
    ) -> WalletResult<crate::btc_send::BtcSendPreview> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        crate::btc_send::preview_btc_send(&self.node, &from, to, satoshi).await
    }

    pub async fn send_btc(&mut self, to: &str, satoshi: u64) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        let unlock_ctx = self.second_factor_from_session()?;
        check_send_policy(&self.profile, 0, &unlock_ctx)?;
        if self.profile.yubikey_required {
            let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
            if !session.webauthn_verified {
                return Err(WalletError::Policy(
                    "WebAuthn (YubiKey/Windows Hello) required — complete ceremony first".into(),
                ));
            }
        }
        self.clear_second_factor();
        let from = self.require_address()?;
        let preview = self.preview_send_btc(to, satoshi).await?;
        if !preview.hip23.ok {
            return Err(WalletError::Policy(preview.hip23.errors.join("; ")));
        }
        let built = self
            .node
            .build_send_btc_tx(&from, to, preview.satoshi, &preview.fee_wire)
            .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
        let signed_hex = self.sign_tx_hex(&body_hex)?;
        let submitted = self.submit_signed_tx(&signed_hex).await?;
        let summary = self.summary_with_whisper_notice(preview.summary.clone(), &submitted);
        let hash = submitted
            .hash
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
        let result = SendResult {
            rail: PaymentRail::L1OnChain,
            tx_hash: hash,
            summary,
        };
        self.append_history_if_enabled(
            result.rail,
            &result.tx_hash,
            &from,
            to,
            0.0,
            &result.summary,
        )?;
        Ok(result)
    }

    pub async fn send_hacd(&mut self, to: &str, diamond_names: &[String]) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        let unlock_ctx = self.second_factor_from_session()?;
        check_send_policy(&self.profile, 0, &unlock_ctx)?;
        if self.profile.yubikey_required {
            let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
            if !session.webauthn_verified {
                return Err(WalletError::Policy(
                    "WebAuthn (YubiKey/Windows Hello) required — complete ceremony first".into(),
                ));
            }
        }
        self.clear_second_factor();
        let from = self.require_address()?;
        let preview = self.preview_send_hacd(to, diamond_names).await?;
        if !preview.hip23.ok {
            return Err(WalletError::Policy(preview.hip23.errors.join("; ")));
        }
        let built = self
            .node
            .build_send_diamond_tx(&from, to, &preview.diamond_names, &preview.fee_wire)
            .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
        let signed_hex = self.sign_tx_hex(&body_hex)?;
        let submitted = self.submit_signed_tx(&signed_hex).await?;
        let summary = self.summary_with_whisper_notice(preview.summary.clone(), &submitted);
        let hash = submitted
            .hash
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
        let result = SendResult {
            rail: PaymentRail::L1OnChain,
            tx_hash: hash,
            summary,
        };
        self.append_history_if_enabled(
            result.rail,
            &result.tx_hash,
            &from,
            to,
            0.0,
            &result.summary,
        )?;
        Ok(result)
    }

    pub async fn query_diamond(&self, name: &str) -> WalletResult<crate::node::DiamondInfo> {
        let normalized = name.trim().to_uppercase();
        if normalized.len() < 4 || normalized.len() > 6 {
            return Err(WalletError::Other("HACD name must be 4–6 letters".into()));
        }
        if !normalized.chars().all(|c| c.is_ascii_uppercase()) {
            return Err(WalletError::Other(
                "HACD name must contain only A–Z letters".into(),
            ));
        }
        self.node.query_diamond_by_name(&normalized).await
    }

    pub async fn hub_health(&self) -> WalletResult<Option<HubHealth>> {
        let hub_url = match &self.settings.l2_hub_url {
            Some(u) => u.clone(),
            None => return Ok(None),
        };
        Ok(Some(L2HubClient::new(hub_url).health().await?))
    }

    /// Discover a public CSP, persist hub settings, and open a channel when needed.
    pub async fn enable_fast_pay(
        &mut self,
        deposit_mei: Option<f64>,
    ) -> WalletResult<FastPayStatus> {
        self.touch_auto_lock();
        let deposit = deposit_mei.unwrap_or(DEFAULT_CHANNEL_DEPOSIT_MEI);

        if self.settings.l2_hub_url.is_none() {
            if let Some(discovered) = discover_healthy_hub().await {
                apply_discovered_hub(&mut self.settings, &discovered);
            }
        }

        let hub_address = match self.settings.hub_right_address.clone() {
            Some(a) if !a.is_empty() => a,
            _ => {
                if let Some(url) = self.settings.l2_hub_url.clone() {
                    if let Ok(health) = L2HubClient::new(url).health().await {
                        if let Some(addr) = health.hub_address.filter(|a| !a.is_empty()) {
                            self.settings.hub_right_address = Some(addr.clone());
                            addr
                        } else {
                            return Err(WalletError::L2(
                                "Fast Pay provider found but hub address is missing — set it in Advanced → Fast Pay"
                                    .into(),
                            ));
                        }
                    } else {
                        return Err(WalletError::L2(
                            "No Fast Pay provider is online right now. Try again later or send on-chain."
                                .into(),
                        ));
                    }
                } else {
                    return Err(WalletError::L2(
                        "No Fast Pay provider is online right now. Your sends still work on-chain."
                            .into(),
                    ));
                }
            }
        };

        if self.settings.channel_id_hex.is_none() {
            self.open_channel(&hub_address, deposit, 0.0).await?;
        }

        self.settings.save()?;
        self.router.update_settings(self.settings.clone());
        self.fast_pay_status().await
    }

    pub async fn fast_pay_status(&self) -> WalletResult<FastPayStatus> {
        let user = self.unlocked.as_ref().map(|s| s.address.as_str());
        evaluate_fast_pay(&self.node, &self.settings, user).await
    }

    async fn maybe_discover_hub(&mut self) -> WalletResult<()> {
        if self.settings.l2_hub_url.is_some() {
            return Ok(());
        }
        if let Some(discovered) = discover_healthy_hub().await {
            apply_discovered_hub(&mut self.settings, &discovered);
            self.settings.save()?;
            self.router.update_settings(self.settings.clone());
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
                "configure at least one DUST Whisper relay URL for messenger".into(),
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

    pub async fn messenger_poll_inbox(&self) -> WalletResult<u32> {
        let my = self.require_address()?;
        let account = self.require_signing_account()?;
        let relays = self.settings.dust_whisper.trimmed_relay_urls();
        if relays.is_empty() {
            return Ok(0);
        }
        crate::messenger::messenger_poll_inbox(self.node.http(), account, &my, &relays).await
    }

    pub(crate) async fn submit_signed_tx(
        &self,
        signed_hex: &str,
    ) -> WalletResult<crate::node::SubmitTxResponse> {
        whisper_submit_tx_hex(&self.node, &self.settings.dust_whisper, signed_hex).await
    }

    fn summary_with_whisper_notice(
        &self,
        summary: String,
        submitted: &crate::node::SubmitTxResponse,
    ) -> String {
        match whisper_fallback_notice(&submitted.message) {
            Some(notice) => format!("{summary} — {notice}"),
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

    pub fn preview_channel_open(
        &mut self,
        hub_address: &str,
        user_deposit_mei: f64,
        hub_deposit_mei: f64,
    ) -> WalletResult<ChannelSetupPreview> {
        self.touch_auto_lock();
        let user = self.require_address()?;
        let channel_id = derive_channel_id(&user, hub_address, 1);
        Ok(ChannelSetupPreview {
            channel_id,
            left_address: user,
            right_address: hub_address.to_owned(),
            left_deposit: format_amount_mei(user_deposit_mei),
            right_deposit: format_amount_mei(hub_deposit_mei),
        })
    }

    pub async fn open_channel(
        &mut self,
        hub_address: &str,
        user_deposit_mei: f64,
        hub_deposit_mei: f64,
    ) -> WalletResult<String> {
        self.touch_auto_lock();
        let preview = self.preview_channel_open(hub_address, user_deposit_mei, hub_deposit_mei)?;
        let built = build_channel_open_tx(
            &self.node,
            &preview.left_address,
            &preview.channel_id,
            &preview.left_address,
            &preview.left_deposit,
            &preview.right_address,
            &preview.right_deposit,
            &crate::hip23::wire_mei_for_node("1:244"),
        )
        .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing channel open body".into()))?;
        let signed_hex = self.sign_tx_hex(&body_hex)?;
        let submitted = self.submit_signed_tx(&signed_hex).await?;
        let hash = submitted
            .hash
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;

        self.settings.hub_right_address = Some(hub_address.to_owned());
        self.settings.channel_id_hex = Some(preview.channel_id);
        self.settings.save()?;
        self.router.update_settings(self.settings.clone());
        self.append_history_if_enabled(
            PaymentRail::L1OnChain,
            &hash,
            &preview.left_address,
            &preview.right_address,
            user_deposit_mei,
            "Channel open",
        )?;
        Ok(hash)
    }

    pub async fn close_channel(&mut self) -> WalletResult<String> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        let channel_id = self
            .settings
            .channel_id_hex
            .clone()
            .ok_or_else(|| WalletError::Transaction("no active channel configured".into()))?;
        let built = build_channel_close_tx(
            &self.node,
            &from,
            &channel_id,
            &crate::hip23::wire_mei_for_node("1:244"),
        )
        .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing channel close body".into()))?;
        let signed_hex = self.sign_tx_hex(&body_hex)?;
        let submitted = self.submit_signed_tx(&signed_hex).await?;
        let hash = submitted
            .hash
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
        self.settings.channel_id_hex = None;
        self.settings.save()?;
        self.router.update_settings(self.settings.clone());
        self.append_history_if_enabled(
            PaymentRail::L1OnChain,
            &hash,
            &from,
            &channel_id,
            0.0,
            "Channel close",
        )?;
        Ok(hash)
    }

    pub async fn preview_send(
        &mut self,
        to: &str,
        amount_mei: f64,
        options: crate::send_options::SendOptions,
    ) -> WalletResult<SendPreview> {
        self.touch_auto_lock();
        self.maybe_discover_hub().await?;
        let from = self.require_address()?;
        let amount_wire = format_amount_mei(amount_mei);
        let balance = self.node.balance_mei(&from).await.unwrap_or(0.0);
        let hip23 = validate_simple_l1_send(to, amount_mei, balance, crate::hip23::L1_DEFAULT_FEE_MEI)?;
        let fast_pay = evaluate_fast_pay(&self.node, &self.settings, Some(&from)).await?;
        let plan = self
            .router
            .plan_send(&from, to, amount_mei, options)
            .await?;
        Ok(SendPreview {
            plan,
            from,
            to: to.to_owned(),
            amount_mei,
            amount_wire: amount_wire.clone(),
            fee: crate::hip23::wire_mei_for_node("1:244"),
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
        let preview = self
            .preview_send(to, amount_mei, crate::send_options::SendOptions::default())
            .await?;
        if preview.plan.rail != PaymentRail::L1OnChain {
            return Err(WalletError::Policy(
                "air-gap QR supports L1 on-chain sends only (disable L2 route)".into(),
            ));
        }
        if !preview.hip23.ok {
            return Err(WalletError::Policy(
                "HIP-23 checks failed — cannot prepare air-gap send".into(),
            ));
        }
        let built = self
            .node
            .build_send_hac_tx(&from, to, &preview.amount_wire, &preview.fee)
            .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
        let unsigned = AirgapUnsigned {
            v: AIRGAP_VERSION,
            from: from.clone(),
            to: preview.to.clone(),
            amount_mei: preview.amount_mei,
            amount_wire: preview.amount_wire,
            fee: preview.fee,
            body_hex,
            summary: preview.plan.summary,
            tx_type: 1,
        };
        let envelope = AirgapEnvelope::Unsigned(unsigned.clone());
        let qr_parts = encode_envelope_qr(&envelope)?;
        Ok(AirgapPrepareResult {
            envelope: unsigned,
            qr_parts,
        })
    }

    /// Offline signer: sign an unsigned air-gap envelope and return signed QR payload(s).
    pub fn sign_airgap_unsigned(
        &mut self,
        unsigned: &AirgapUnsigned,
    ) -> WalletResult<AirgapSignResult> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        if unsigned.from != from {
            return Err(WalletError::Policy(format!(
                "offline signer address {from} does not match unsigned tx from {}",
                unsigned.from
            )));
        }
        let signed_hex = self.sign_tx_hex(&unsigned.body_hex)?;
        let signed = AirgapSigned {
            v: AIRGAP_VERSION,
            tx_type: unsigned.tx_type,
            from: unsigned.from.clone(),
            to: unsigned.to.clone(),
            amount_mei: unsigned.amount_mei,
            signed_hex,
            summary: unsigned.summary.clone(),
        };
        let envelope = AirgapEnvelope::Signed(signed.clone());
        let qr_parts = encode_envelope_qr(&envelope)?;
        Ok(AirgapSignResult {
            envelope: signed,
            qr_parts,
        })
    }

    /// Online coordinator: broadcast a signed tx from air-gap QR without local signing.
    pub async fn broadcast_airgap_signed(
        &mut self,
        signed: &AirgapSigned,
    ) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        if signed.tx_type == 4 {
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
            let summary = signed.summary.clone();
            let _ = self.append_quantum_history(
                &hash,
                &signed.from,
                &signed.to,
                signed.amount_mei,
                &summary,
            );
            return Ok(SendResult {
                rail: PaymentRail::QuantumType4,
                tx_hash: hash,
                summary,
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
            summary: signed.summary.clone(),
        };
        self.append_history_if_enabled(
            result.rail,
            &result.tx_hash,
            &signed.from,
            &signed.to,
            signed.amount_mei,
            &result.summary,
        )?;
        Ok(result)
    }

    pub fn parse_airgap_qr(&mut self, text: &str) -> WalletResult<AirgapParseResult> {
        self.touch_auto_lock();
        parse_airgap_qr_text(text)
    }

    pub fn parse_airgap_qr_batch(&mut self, parts: &[String]) -> WalletResult<AirgapParseResult> {
        self.touch_auto_lock();
        parse_airgap_qr_parts(parts)
    }

    pub async fn send_hac(
        &mut self,
        to: &str,
        amount_mei: f64,
        options: crate::send_options::SendOptions,
    ) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        let unlock_ctx = self.second_factor_from_session()?;
        check_send_policy(&self.profile, amount_mei as u64, &unlock_ctx)?;
        if self.profile.yubikey_required {
            let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
            if !session.webauthn_verified {
                return Err(WalletError::Policy(
                    "WebAuthn (YubiKey/Windows Hello) required — complete ceremony first".into(),
                ));
            }
        }
        // Single-use second factor: consumed before signing (enterprise per-tx model).
        self.clear_second_factor();
        let from = self.require_address()?;
        let preview = self.preview_send(to, amount_mei, options).await?;

        let result = match preview.plan.rail {
            PaymentRail::L2Fast => {
                let account = match &self.unlocked.as_ref().ok_or(WalletError::Locked)?.key {
                    SessionKey::Signing(acc) => acc.clone(),
                    SessionKey::WatchOnly => {
                        return Err(WalletError::Policy(
                            "watch-only wallet cannot sign L2 bills".into(),
                        ));
                    }
                };
                let payment_id = self
                    .router
                    .execute_l2(
                        &from,
                        to,
                        amount_mei,
                        &preview.amount_wire,
                        &account,
                        options.hub_fee_payer,
                    )
                    .await?;
                self.bills = self.router.bills().clone();
                SendResult {
                    rail: PaymentRail::L2Fast,
                    tx_hash: payment_id,
                    summary: preview.plan.summary,
                }
            }
            PaymentRail::L1OnChain => {
                let built = self
                    .node
                    .build_send_hac_tx(&from, to, &preview.amount_wire, &preview.fee)
                    .await?;
                let body_hex = built
                    .body
                    .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
                let signed_hex = self.sign_tx_hex(&body_hex)?;
                let submitted = self.submit_signed_tx(&signed_hex).await?;
                let summary =
                    self.summary_with_whisper_notice(preview.plan.summary, &submitted);
                let hash = submitted
                    .hash
                    .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
                SendResult {
                    rail: PaymentRail::L1OnChain,
                    tx_hash: hash,
                    summary,
                }
            }
            PaymentRail::QuantumType4 => {
                return Err(WalletError::Policy(
                    "Type 4 quantum sends use the Quantum tab — not legacy Send".into(),
                ));
            }
        };

        self.append_history_if_enabled(
            result.rail,
            &result.tx_hash,
            &from,
            to,
            amount_mei,
            &result.summary,
        )?;
        Ok(result)
    }

    pub fn set_security_profile(&mut self, profile: SecurityProfile) -> WalletResult<()> {
        let name = profile.name.clone();
        self.profile = profile;
        self.settings.security_profile = name;
        self.settings.save()?;
        // Policy lives in settings; vault AAD binds security_profile — never patch
        // metadata without full reencrypt (see vault_aad + change_passphrase).
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

    fn sign_tx_hex(&self, body_hex: &str) -> WalletResult<String> {
        let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        let watch_only = matches!(session.key, SessionKey::WatchOnly);
        check_signing_allowed(
            self.settings.hardware_mode(),
            watch_only,
            session.webauthn_verified,
        )?;
        let account = match &session.key {
            SessionKey::Signing(acc) => acc,
            SessionKey::WatchOnly => {
                return Err(WalletError::Policy(
                    "watch-only wallet cannot sign transactions".into(),
                ))
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

    fn require_signing_account(&self) -> WalletResult<&WalletAccount> {
        let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        match &session.key {
            SessionKey::Signing(acc) => Ok(acc),
            SessionKey::WatchOnly => Err(WalletError::Policy(
                "watch-only wallet cannot access messenger".into(),
            )),
        }
    }

    fn load_webauthn_credential(&self) -> WalletResult<Option<String>> {
        Ok(self
            .vault_meta
            .as_ref()
            .and_then(|m| m.webauthn_credential_b64.clone()))
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
            let _ = self.vault_snapshot()?;
        }
        Ok(())
    }
}

fn format_amount_mei(amount_mei: f64) -> String {
    crate::hip23::format_mei_for_node(amount_mei)
}

fn is_secret_hex(seed: &str) -> bool {
    let s = seed.trim();
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn random_biometric_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

impl WalletService {
    pub(crate) fn quantum_mode_enabled(&self) -> bool {
        self.settings.quantum_mode
    }

    pub(crate) fn quantum_meta_snapshot(&self) -> Option<crate::settings::QuantumMeta> {
        self.settings.quantum_meta.clone()
    }

    pub(crate) fn quantum_keystore_json(&self) -> Option<String> {
        if let Some(mem) = &self.quantum_keystore_mem {
            return Some(mem.clone());
        }
        self.settings.quantum_keystore_json.clone()
    }

    pub(crate) fn ensure_quantum_signing_policy(&self) -> WalletResult<()> {
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
            self.settings.hardware_mode(),
            watch_only,
            webauthn_verified,
        )?;
        if self.profile.yubikey_required {
            let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
            if !session.webauthn_verified {
                return Err(WalletError::Policy(
                    "WebAuthn (YubiKey/Windows Hello) required — complete ceremony first".into(),
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
        self.bump_unlock_activity();
        if let Some(meta) = crate::quantum::quantum_meta_from_json(&json) {
            self.settings.quantum_meta = Some(meta);
        }
        self.settings.quantum_keystore_json = None;
        self.settings.quantum_mode = true;
        self.quantum_keystore_mem = Some(json.clone());
        if let Some(session) = self.unlocked.as_mut() {
            if let Some(key) = session.quantum_file_key.as_ref() {
                crate::quantum_vault::save_encrypted(key, &json)?;
            }
        }
        self.settings.save()?;
        Ok(())
    }

    pub(crate) fn node_client(&self) -> &NodeClient {
        &self.node
    }

}