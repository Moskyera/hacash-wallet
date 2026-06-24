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

use crate::history::{TxHistory, TxRecord};
use crate::l2_hub::{HubHealth, L2HubClient};
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
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SendResult {
    pub rail: PaymentRail,
    pub tx_hash: String,
    pub summary: String,
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
        }
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
        self.unlocked = Some(UnlockedSession {
            address: address.clone(),
            key: SessionKey::Signing(account),
            unlocked_at: Instant::now(),
            webauthn_verified: false,
            biometric_verified: false,
            pending_biometric_nonce: None,
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
    }

    pub fn touch_auto_lock(&mut self) {
        if let Some(session) = &self.unlocked {
            if session.unlocked_at.elapsed() > Duration::from_secs(self.profile.auto_lock_secs) {
                self.lock();
            }
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

    pub async fn hub_health(&self) -> WalletResult<Option<HubHealth>> {
        let hub_url = match &self.settings.l2_hub_url {
            Some(u) => u.clone(),
            None => return Ok(None),
        };
        Ok(Some(L2HubClient::new(hub_url).health().await?))
    }

    pub fn list_bills(&self) -> Vec<BillEntry> {
        self.bills.list()
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
            "1:244",
        )
        .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing channel open body".into()))?;
        let signed_hex = self.sign_tx_hex(&body_hex)?;
        let submitted = self.node.submit_tx_hex(&signed_hex).await?;
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
        let built = build_channel_close_tx(&self.node, &from, &channel_id, "1:244").await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing channel close body".into()))?;
        let signed_hex = self.sign_tx_hex(&body_hex)?;
        let submitted = self.node.submit_tx_hex(&signed_hex).await?;
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

    pub async fn preview_send(&mut self, to: &str, amount_mei: f64) -> WalletResult<SendPreview> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        let amount_wire = format_amount_mei(amount_mei);
        let balance = self.node.balance_mei(&from).await.unwrap_or(0.0);
        let hip23 = validate_simple_l1_send(to, amount_mei, balance, 0.001)?;
        let plan = self.router.plan_send(&from, to, amount_mei).await?;
        Ok(SendPreview {
            plan,
            from,
            to: to.to_owned(),
            amount_mei,
            amount_wire: amount_wire.clone(),
            fee: "1:244".into(),
            hip23,
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
        let preview = self.preview_send(to, amount_mei).await?;
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
        let coordinator = self.require_address()?;
        if coordinator != signed.from {
            return Err(WalletError::Policy(
                "signed tx sender does not match this wallet address".into(),
            ));
        }
        let submitted = self.node.submit_tx_hex(&signed.signed_hex).await?;
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

    pub async fn send_hac(&mut self, to: &str, amount_mei: f64) -> WalletResult<SendResult> {
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
        let preview = self.preview_send(to, amount_mei).await?;

        let result = match preview.plan.rail {
            PaymentRail::L2Fast => {
                let payment_id = self
                    .router
                    .execute_l2(&from, to, amount_mei, &preview.amount_wire)
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
                let submitted = self.node.submit_tx_hex(&signed_hex).await?;
                let hash = submitted
                    .hash
                    .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
                SendResult {
                    rail: PaymentRail::L1OnChain,
                    tx_hash: hash,
                    summary: preview.plan.summary,
                }
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

    fn clear_second_factor(&mut self) {
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
    let whole = amount_mei.floor() as u64;
    let frac = ((amount_mei - whole as f64) * 1000.0).round() as u64;
    format!("{whole}:{frac}")
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