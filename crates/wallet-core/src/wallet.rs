use std::path::PathBuf;
use std::time::{Duration, Instant};

use protocol::transaction;
use sys::ToHex;
use zeroize::Zeroize;

use crate::account::WalletAccount;
use crate::bills::BillStore;
use crate::channel::{
    build_channel_open_tx, derive_channel_id, query_channel, ChannelInfo,
};
use crate::error::{WalletError, WalletResult};
use crate::hip23::{validate_simple_l1_send, Hip23SendCheck};
use crate::node::NodeClient;
use crate::payment::{PaymentPlan, PaymentRail, PaymentRouter};
use crate::security::{check_send_policy, SecurityProfile, UnlockContext};
use crate::settings::WalletSettings;
use crate::vault::{default_vault_path, EncryptedVault};
use crate::webauthn::WebAuthnGate;

pub struct WalletService {
    vault_path: PathBuf,
    node: NodeClient,
    router: PaymentRouter,
    profile: SecurityProfile,
    settings: WalletSettings,
    bills: BillStore,
    webauthn: WebAuthnGate,
    unlocked: Option<UnlockedSession>,
}

struct UnlockedSession {
    account: WalletAccount,
    unlocked_at: Instant,
    webauthn_verified: bool,
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
        let node = NodeClient::new(settings.node_url.clone());
        let bills = BillStore::load().unwrap_or_default();
        let router = PaymentRouter::new(node.clone(), settings.clone(), bills.clone());
        Ok(Self {
            vault_path: default_vault_path(),
            node,
            router,
            profile: SecurityProfile::default(),
            settings,
            bills,
            webauthn: WebAuthnGate::new()?,
            unlocked: None,
        })
    }

    pub fn status(&self) -> WalletStatus {
        let has_wallet = self.vault_path.exists();
        let vault_webauthn = if has_wallet {
            EncryptedVault::load(&self.vault_path)
                .ok()
                .and_then(|v| v.metadata.webauthn_credential_b64)
        } else {
            None
        };
        WalletStatus {
            has_wallet,
            locked: self.unlocked.is_none(),
            address: self
                .unlocked
                .as_ref()
                .map(|s| s.account.address())
                .or_else(|| {
                    if has_wallet {
                        EncryptedVault::load(&self.vault_path)
                            .ok()
                            .map(|v| v.metadata.address)
                    } else {
                        None
                    }
                }),
            security_profile: self.profile.name.clone(),
            node_url: self.node.base_url().to_string(),
            l2_enabled: self.router.has_l2_hub(),
            l2_hub_url: self.settings.l2_hub_url.clone(),
            channel_id: self.settings.channel_id_hex.clone(),
            webauthn_enabled: vault_webauthn.is_some() || self.settings.webauthn_enabled,
            l2_bill_count: self.bills.count(),
        }
    }

    pub fn get_settings(&self) -> WalletSettings {
        self.settings.clone()
    }

    pub fn update_settings(&mut self, settings: WalletSettings) -> WalletResult<()> {
        settings.save()?;
        self.router.update_settings(settings.clone());
        self.node = NodeClient::new(settings.node_url.clone());
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
        vault.save(&self.vault_path)?;
        self.settings.save()?;
        self.unlock(passphrase)?;
        Ok(address)
    }

    pub fn unlock(&mut self, passphrase: &str) -> WalletResult<String> {
        if self.unlocked.is_some() {
            return Err(WalletError::AlreadyUnlocked);
        }
        let vault = EncryptedVault::load(&self.vault_path)?;
        let mut secret = vault.decrypt(passphrase)?;
        let account = WalletAccount::from_secret_hex(&secret)?;
        secret.zeroize();
        let address = account.address();
        self.unlocked = Some(UnlockedSession {
            account,
            unlocked_at: Instant::now(),
            webauthn_verified: false,
        });
        Ok(address)
    }

    pub fn lock(&mut self) {
        self.unlocked = None;
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
        let mut vault = EncryptedVault::load(&self.vault_path)?;
        vault.metadata.webauthn_credential_b64 = Some(cred_b64);
        vault.save(&self.vault_path)?;
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
        self.webauthn.finish_auth(assertion_json)?;
        if let Some(session) = &mut self.unlocked {
            session.webauthn_verified = true;
        }
        Ok(())
    }

    pub async fn balance_mei(&mut self) -> WalletResult<f64> {
        self.touch_auto_lock();
        let address = self.require_address()?;
        self.node.balance_mei(&address).await
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

    pub async fn send_hac(
        &mut self,
        to: &str,
        amount_mei: f64,
        unlock_ctx: UnlockContext,
    ) -> WalletResult<SendResult> {
        self.touch_auto_lock();
        check_send_policy(&self.profile, amount_mei as u64, &unlock_ctx)?;
        if self.profile.yubikey_required && !unlock_ctx.yubikey_ok {
            if let Some(session) = &self.unlocked {
                if !session.webauthn_verified {
                    return Err(WalletError::Policy(
                        "WebAuthn (YubiKey/Windows Hello) required".into(),
                    ));
                }
            }
        }
        let from = self.require_address()?;
        let preview = self.preview_send(to, amount_mei).await?;

        match preview.plan.rail {
            PaymentRail::L2Fast => {
                let payment_id = self
                    .router
                    .execute_l2(&from, to, amount_mei, &preview.amount_wire)
                    .await?;
                self.bills = self.router.bills().clone();
                Ok(SendResult {
                    rail: PaymentRail::L2Fast,
                    tx_hash: payment_id,
                    summary: preview.plan.summary,
                })
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
                Ok(SendResult {
                    rail: PaymentRail::L1OnChain,
                    tx_hash: hash,
                    summary: preview.plan.summary,
                })
            }
        }
    }

    pub fn set_security_profile(&mut self, profile: SecurityProfile) {
        self.profile = profile;
    }

    fn sign_tx_hex(&self, body_hex: &str) -> WalletResult<String> {
        let session = self.unlocked.as_ref().ok_or(WalletError::Locked)?;
        let body = hex::decode(body_hex).map_err(|e| WalletError::Transaction(e.to_string()))?;
        let (mut tx, _) = transaction::transaction_create(&body)
            .map_err(|e| WalletError::Transaction(e.to_string()))?;
        tx.fill_sign(session.account.inner())
            .map_err(|e| WalletError::Transaction(e.to_string()))?;
        Ok(tx.serialize().to_hex())
    }

    fn require_address(&self) -> WalletResult<String> {
        self.unlocked
            .as_ref()
            .map(|s| s.account.address())
            .ok_or(WalletError::Locked)
    }

    fn load_webauthn_credential(&self) -> WalletResult<Option<String>> {
        if !self.vault_path.exists() {
            return Ok(None);
        }
        let vault = EncryptedVault::load(&self.vault_path)?;
        Ok(vault.metadata.webauthn_credential_b64)
    }
}

fn format_amount_mei(amount_mei: f64) -> String {
    let whole = amount_mei.floor() as u64;
    let frac = ((amount_mei - whole as f64) * 1000.0).round() as u64;
    format!("{whole}:{frac}")
}