use std::path::PathBuf;
use std::time::{Duration, Instant};

use basis::interface::TxExec;
use protocol::transaction;
use sys::ToHex;
use zeroize::Zeroize;

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::node::NodeClient;
use crate::payment::{PaymentPlan, PaymentRail, PaymentRouter};
use crate::security::{check_send_policy, SecurityProfile, UnlockContext};
use crate::vault::{default_vault_path, EncryptedVault};

pub struct WalletService {
    vault_path: PathBuf,
    node: NodeClient,
    router: PaymentRouter,
    profile: SecurityProfile,
    unlocked: Option<UnlockedSession>,
}

struct UnlockedSession {
    account: WalletAccount,
    unlocked_at: Instant,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletStatus {
    pub has_wallet: bool,
    pub locked: bool,
    pub address: Option<String>,
    pub security_profile: String,
    pub node_url: String,
    pub l2_enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SendPreview {
    pub plan: PaymentPlan,
    pub from: String,
    pub to: String,
    pub amount_mei: f64,
    pub amount_wire: String,
    pub fee: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SendResult {
    pub rail: PaymentRail,
    pub tx_hash: String,
    pub summary: String,
}

impl WalletService {
    pub fn new(node_url: Option<String>, l2_hub_url: Option<String>) -> Self {
        let node = node_url
            .map(NodeClient::new)
            .unwrap_or_else(NodeClient::default);
        let router = PaymentRouter::new(node.clone(), l2_hub_url.clone());
        Self {
            vault_path: default_vault_path(),
            node,
            router,
            profile: SecurityProfile::default(),
            unlocked: None,
        }
    }

    pub fn status(&self) -> WalletStatus {
        let has_wallet = self.vault_path.exists();
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
        }
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

    pub async fn balance_mei(&mut self) -> WalletResult<f64> {
        self.touch_auto_lock();
        let address = self.require_address()?;
        self.node.balance_mei(&address).await
    }

    pub async fn preview_send(&mut self, to: &str, amount_mei: f64) -> WalletResult<SendPreview> {
        self.touch_auto_lock();
        let from = self.require_address()?;
        let amount_wire = format_amount_mei(amount_mei);
        let plan = self.router.plan_send(&from, to, amount_mei).await?;
        Ok(SendPreview {
            plan,
            from,
            to: to.to_owned(),
            amount_mei,
            amount_wire: amount_wire.clone(),
            fee: "1:244".into(),
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
        let from = self.require_address()?;
        let preview = self.preview_send(to, amount_mei).await?;

        match preview.plan.rail {
            PaymentRail::L2Fast => {
                let hash = self.router.execute_l2(&from, to, amount_mei).await?;
                Ok(SendResult {
                    rail: PaymentRail::L2Fast,
                    tx_hash: hash,
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
}

fn format_amount_mei(amount_mei: f64) -> String {
    let whole = amount_mei.floor() as u64;
    let frac = ((amount_mei - whole as f64) * 1000.0).round() as u64;
    format!("{whole}:{frac}")
}