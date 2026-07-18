//! Launchpad dApp session and signing facade.
//!
//! The public IPC method names remain unchanged; this module keeps dApp
//! authorization, transaction policy and signing together instead of growing
//! the general wallet session service.

use crate::error::{WalletError, WalletResult};
use crate::security::check_send_policy;

use super::WalletService;

impl WalletService {
    pub fn dapp_session_active(&self) -> bool {
        self.dapp_session.is_active()
    }

    pub fn dapp_session_is_authorized(&self, origin: &str) -> bool {
        self.dapp_session.is_authorized(origin)
    }

    pub fn dapp_connect(&mut self, origin: &str) -> WalletResult<serde_json::Value> {
        self.touch_auto_lock();
        crate::dapp::require_trusted_origin(origin)?;
        let address = self.require_address()?;
        self.dapp_session.authorize(origin);
        if self.settings.privacy.pause_auto_lock_dapp {
            self.bump_unlock_activity();
        }
        Ok(serde_json::json!({ "address": address }))
    }

    pub fn dapp_disconnect(&mut self, origin: &str) -> WalletResult<serde_json::Value> {
        crate::dapp::require_trusted_origin(origin)?;
        let disconnected = self.dapp_session.revoke(origin);
        Ok(serde_json::json!({
            "ok": true,
            "disconnected": disconnected,
        }))
    }

    pub fn dapp_wallet(&mut self, origin: &str) -> WalletResult<serde_json::Value> {
        crate::dapp::require_trusted_origin(origin)?;
        // Expired sessions must be revoked before checking dApp authorization.
        self.touch_auto_lock();
        if !self.dapp_session.is_authorized(origin) {
            return Ok(serde_json::json!({ "err": "Wallet not connected" }));
        }
        if self.settings.privacy.pause_auto_lock_dapp {
            self.bump_unlock_activity();
        }
        let address = self.require_address()?;
        Ok(serde_json::json!({ "address": address }))
    }

    /// Resets auto-lock idle timer while a trusted dApp session is active.
    pub fn dapp_keepalive_bump(&mut self) {
        if self.unlocked.is_some()
            && self.dapp_session.is_active()
            && self.settings.privacy.pause_auto_lock_dapp
        {
            self.bump_unlock_activity();
        }
    }

    pub fn dapp_heartbeat(&mut self, origin: &str) -> WalletResult<serde_json::Value> {
        crate::dapp::require_trusted_origin(origin)?;
        // A heartbeat cannot revive an already expired wallet session.
        self.touch_auto_lock();
        if self.dapp_session.is_authorized(origin) {
            if self.settings.privacy.pause_auto_lock_dapp {
                self.bump_unlock_activity();
            }
            Ok(serde_json::json!({ "ok": true }))
        } else {
            Ok(serde_json::json!({ "ok": false, "err": "Wallet not connected" }))
        }
    }

    pub async fn dapp_transfer(
        &mut self,
        origin: &str,
        txobj: &str,
    ) -> WalletResult<serde_json::Value> {
        self.touch_auto_lock();
        crate::dapp::require_trusted_origin(origin)?;
        if !self.dapp_session.is_authorized(origin) {
            return Ok(serde_json::json!({ "err": "Wallet not connected", "ret": 1 }));
        }
        let from = self.require_address()?;
        let parsed = crate::dapp::decode_txobj(txobj)?;
        let actions_val = parsed
            .get("actions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| WalletError::Transaction("txobj missing actions".into()))?;
        let mut actions = crate::dapp::normalize_actions(actions_val)?;
        crate::dapp::append_mandatory_wallet_fee(&mut actions)?;
        let mut fee_payload = parsed.clone();
        fee_payload["main_address"] = serde_json::json!(from);
        fee_payload["actions"] = serde_json::json!(actions.clone());
        let fee =
            crate::dapp::estimate_fee_for_payload(self.node_client(), &from, &fee_payload).await?;
        let payload = serde_json::json!({
            "main_address": from,
            "fee": fee,
            "actions": actions
        });
        let built = self.node.post_create_transaction(payload).await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
        let canonical =
            crate::tx_binding::verify_transaction_intent(&body_hex, &from, &fee, &actions)?;
        let unlock_ctx = self.second_factor_from_session()?;
        check_send_policy(
            &self.profile,
            self.profile.require_second_factor_above_mei,
            &unlock_ctx,
        )?;
        self.clear_second_factor();
        let signed_hex = self.sign_tx_hex(&body_hex)?;
        let submitted = self.submit_signed_tx(&signed_hex).await?;
        let txhash = submitted
            .hash
            .clone()
            .unwrap_or_else(|| built.hash.unwrap_or_default());
        self.bump_unlock_activity();
        Ok(serde_json::json!({
            "ret": 0,
            "success": true,
            "txbody": signed_hex,
            "txhash": txhash,
            "txfee": fee,
            "description": [canonical.approval_summary()],
            "body_sha256": canonical.body_sha256
        }))
    }

    pub async fn dapp_sign_tx(
        &mut self,
        origin: &str,
        txbody: &str,
        autosubmit: bool,
    ) -> WalletResult<serde_json::Value> {
        self.touch_auto_lock();
        crate::dapp::require_trusted_origin(origin)?;
        if !self.dapp_session.is_authorized(origin) {
            return Ok(serde_json::json!({ "err": "Wallet not connected", "ret": 1 }));
        }
        let address = self.require_address()?;
        let canonical = crate::tx_binding::validate_signer_body(txbody, &address)?;
        crate::dapp::validate_raw_sign_transaction(&canonical)?;
        let unlock_ctx = self.second_factor_from_session()?;
        check_send_policy(
            &self.profile,
            self.profile.require_second_factor_above_mei,
            &unlock_ctx,
        )?;
        self.clear_second_factor();
        let signed_hex = self.sign_tx_hex(txbody)?;
        self.bump_unlock_activity();
        let mut result = serde_json::json!({
            "ret": 0,
            "body": signed_hex,
            "address": address,
            "hash": crate::dapp::built_hash_hint(txbody),
            "description": canonical.approval_summary(),
            "body_sha256": canonical.body_sha256,
        });
        if autosubmit {
            let submitted = self.submit_signed_tx(&signed_hex).await?;
            if let Some(hash) = submitted.hash {
                result["txhash"] = serde_json::json!(hash);
                result["success"] = serde_json::json!(true);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::test_support::IsolatedWalletData;

    const ORIGIN: &str = "https://hacd.it";
    const WATCH_ADDRESS: &str = "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW";

    fn connect_then_expire(wallet: &mut WalletService) {
        wallet.profile.auto_lock_secs = 180;
        wallet.open_watch_only().expect("watch-only session");
        wallet.dapp_connect(ORIGIN).expect("connect dApp");
        wallet.profile.auto_lock_secs = 0;
        thread::sleep(Duration::from_millis(2));
    }

    #[test]
    fn expired_sessions_are_revoked_by_status_wallet_and_heartbeat() {
        let _wallet_data = IsolatedWalletData::new();
        let mut wallet = WalletService::new(None, None).expect("wallet service");
        wallet
            .import_watch_only(WATCH_ADDRESS)
            .expect("initial watch-only session");
        wallet.lock();

        connect_then_expire(&mut wallet);
        assert!(wallet.status().locked);
        assert!(!wallet.dapp_session_active());

        connect_then_expire(&mut wallet);
        wallet.bump_unlock_activity();
        assert!(wallet.status().locked);
        assert!(!wallet.dapp_session_active());

        connect_then_expire(&mut wallet);
        let response = wallet.dapp_wallet(ORIGIN).expect("trusted dApp response");
        assert_eq!(response["err"], "Wallet not connected");
        assert!(wallet.status().locked);
        assert!(!wallet.dapp_session_active());

        connect_then_expire(&mut wallet);
        let response = wallet
            .dapp_heartbeat(ORIGIN)
            .expect("trusted heartbeat response");
        assert_eq!(response["ok"], false);
        assert_eq!(response["err"], "Wallet not connected");
        assert!(wallet.status().locked);
        assert!(!wallet.dapp_session_active());
    }
}
