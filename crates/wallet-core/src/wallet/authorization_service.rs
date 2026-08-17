//! Preparation and execution of exact transaction-bound wallet operations.

use crate::authorization::{
    AssuranceMethod, AuthorizationRequirement, NativeAuthorizationChallenge, OperationKind,
    PreparedOperationState, PreparedOperationView, TrustedDisplayField, TrustedOperationDisplay,
};
use crate::channel::{
    CooperativeCloseSettlement, build_channel_close_tx_with_dynamic_fee,
    build_channel_open_tx_with_dynamic_fee, cooperative_close_settlement,
};
use crate::error::{WalletError, WalletResult};
use crate::hardware::HardwareSigningMode;
use crate::payment::PaymentRail;

use super::{ChannelSetupPreview, SendResult, TxStatus, WalletService};

#[derive(Debug)]
pub(super) enum PreparedExecution {
    HacL1 {
        body_hex: String,
        node_url: String,
        from: String,
        to: String,
        amount_mei: f64,
        summary: String,
    },
    Hacd {
        body_hex: String,
        node_url: String,
        from: String,
        to: String,
        diamond_names: Vec<String>,
        summary: String,
    },
    NativeAsset {
        body_hex: String,
        node_url: String,
        from: String,
        to: String,
        serial: u64,
        amount: u64,
        summary: String,
    },
    BridgedBtc {
        body_hex: String,
        node_url: String,
        from: String,
        to: String,
        satoshi: u64,
        summary: String,
    },
    ChannelOpen {
        body_hex: String,
        network_fee: String,
        node_url: String,
        hub_url: String,
        network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
        preview: ChannelSetupPreview,
        recovery_operation_id: String,
        recovery_idempotency_key: String,
        recovery_created_unix: u64,
        recovery_expires_unix: u64,
    },
    ChannelClose {
        body_hex: String,
        network_fee: String,
        node_url: String,
        hub_url: String,
        network_binding: l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding,
        hub_address: String,
        from: String,
        channel_id: String,
        reuse_version: u64,
        open_height: u64,
        settlement: CooperativeCloseSettlement,
        recovery_operation_id: String,
        recovery_idempotency_key: String,
        recovery_created_unix: u64,
        recovery_expires_unix: u64,
    },
    AirgapClassic {
        unsigned: crate::airgap::AirgapUnsigned,
    },
    ColdVaultActivation {
        current_hardware_mode: String,
    },
}

/// Domain separator for the irreversible cold vault transition. The renderer
/// never supplies these bytes: they are rebuilt from authenticated vault state.
const COLD_VAULT_ACTIVATION_DOMAIN: &[u8] = b"hacash-cold-vault-activation-v1\0";

fn cold_vault_activation_canonical(current_hardware_mode: &str) -> Vec<u8> {
    let mut canonical = COLD_VAULT_ACTIVATION_DOMAIN.to_vec();
    canonical.extend_from_slice(current_hardware_mode.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(HardwareSigningMode::AirgapOnly.as_str().as_bytes());
    canonical
}

pub(super) type SessionAuthorization = PreparedOperationState<PreparedExecution>;

/// Unforgeable outside this child module: the private field can only be
/// constructed after the exact prepared air-gap ticket has been consumed.
pub(super) struct PreparedAirgapSigningPermit(());

impl PreparedAirgapSigningPermit {
    fn after_consumed_ticket(
        mode: HardwareSigningMode,
        assurance: Option<AssuranceMethod>,
    ) -> WalletResult<Self> {
        if mode == HardwareSigningMode::AirgapOnly
            && !matches!(
                assurance,
                Some(AssuranceMethod::NativeBiometric | AssuranceMethod::WebAuthn)
            )
        {
            return Err(WalletError::Policy(
                "cold vault requires a fresh platform factor for this exact air-gap operation"
                    .into(),
            ));
        }
        Ok(Self(()))
    }
}

/// Unforgeable outside this child module. Activating the cold vault is
/// irreversible, so it may only proceed once the exact activation ticket has
/// been consumed together with a fresh platform-authenticator ceremony.
pub(super) struct ColdVaultActivationPermit(());

impl ColdVaultActivationPermit {
    fn after_consumed_ticket(assurance: Option<AssuranceMethod>) -> WalletResult<Self> {
        if !matches!(
            assurance,
            Some(AssuranceMethod::NativeBiometric | AssuranceMethod::WebAuthn)
        ) {
            return Err(WalletError::Policy(
                "cold vault activation is irreversible and requires a fresh platform factor for this exact activation"
                    .into(),
            ));
        }
        Ok(Self(()))
    }
}

impl WalletService {
    pub fn begin_prepared_native_authorization(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<NativeAuthorizationChallenge> {
        self.touch_auto_lock();
        self.unlocked
            .as_mut()
            .ok_or(WalletError::Locked)?
            .authorization
            .begin_native(operation_id)
    }

    pub fn finish_prepared_native_authorization(
        &mut self,
        operation_id: &str,
        nonce: &str,
    ) -> WalletResult<()> {
        self.touch_auto_lock();
        self.unlocked
            .as_mut()
            .ok_or(WalletError::Locked)?
            .authorization
            .finish_native(operation_id, nonce)
    }

    pub fn webauthn_prepared_auth_begin(
        &mut self,
        operation_id: &str,
        client_origin: Option<&str>,
    ) -> WalletResult<String> {
        self.touch_auto_lock();
        let result = (|| {
            let digest = self
                .unlocked
                .as_mut()
                .ok_or(WalletError::Locked)?
                .authorization
                .begin_webauthn(operation_id)?;
            let credential = self
                .load_webauthn_credential()?
                .ok_or_else(|| WalletError::Policy("WebAuthn is not registered".into()))?;
            let credential_id = crate::webauthn::credential_id_from_store(&credential)?;
            self.webauthn
                .begin_auth_bound(&credential_id, client_origin, &digest)
        })();
        if result.is_err() {
            self.clear_prepared_operation();
        }
        result
    }

    pub fn webauthn_prepared_auth_finish(
        &mut self,
        operation_id: &str,
        assertion_json: &str,
    ) -> WalletResult<()> {
        self.touch_auto_lock();
        let stored = self.load_webauthn_credential()?;
        let updated = match self.webauthn.finish_auth(assertion_json, stored.as_deref()) {
            Ok(updated) => updated,
            Err(error) => {
                self.clear_prepared_operation();
                return Err(error);
            }
        };
        let mut vault = self.vault_snapshot()?;
        vault.update_webauthn_counter_credential(&updated)?;
        if let Err(error) = self.persist_vault(vault) {
            self.clear_prepared_operation();
            return Err(error);
        }
        self.unlocked
            .as_mut()
            .ok_or(WalletError::Locked)?
            .authorization
            .finish_webauthn(operation_id)
    }

    pub async fn prepare_send_hac(
        &mut self,
        to: &str,
        amount_mei: f64,
        options: crate::send_options::SendOptions,
    ) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let from = self.require_address()?;
        let preview = self.preview_send(to, amount_mei, &options).await?;
        if preview.plan.rail != PaymentRail::L1OnChain {
            self.clear_prepared_operation();
            return Err(WalletError::Policy(
                "transaction-bound authorization currently requires Force L1; Fast Pay signing is blocked for protected sends"
                    .into(),
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
        self.ensure_transaction_network_binding(&body_hex).await?;
        let requirement =
            self.authorization_requirement(crate::hip23::policy_amount_mei_ceil(amount_mei)?)?;
        let display = exact_transaction_display(
            "Send HAC",
            &preview.plan.summary,
            &canonical,
            vec![
                field("Recipient", to),
                field("Amount", &format!("{} HAC", preview.amount_wire)),
                field("Network fee", &preview.fee),
            ],
        );
        self.store_prepared(
            OperationKind::HacL1,
            &from,
            &body_hex,
            display,
            requirement,
            PreparedExecution::HacL1 {
                body_hex: body_hex.clone(),
                node_url: self.node.base_url().to_owned(),
                from: from.clone(),
                to: to.to_owned(),
                amount_mei,
                summary: preview.plan.summary,
            },
        )
    }

    pub async fn execute_prepared_hac(&mut self, operation_id: &str) -> WalletResult<SendResult> {
        let (payload, assurance) = self.take_prepared(operation_id, OperationKind::HacL1)?;
        let PreparedExecution::HacL1 {
            body_hex,
            node_url,
            from,
            to,
            amount_mei,
            summary,
        } = payload
        else {
            return Err(WalletError::Policy("prepared HAC payload mismatch".into()));
        };
        self.require_prepared_environment(&node_url)?;
        let pending = self.begin_pending_history(PaymentRail::L1OnChain, &from, &to, amount_mei)?;
        let result = self
            .sign_submit_prepared(&body_hex, assurance)
            .await
            .and_then(|submitted| {
                let hash = submitted
                    .hash
                    .clone()
                    .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
                Ok(SendResult {
                    rail: PaymentRail::L1OnChain,
                    tx_hash: hash,
                    summary: self.summary_with_whisper_notice(summary, &submitted),
                    pending: false,
                })
            });
        self.finish_prepared_history(pending, result)
    }

    pub async fn prepare_send_hacd(
        &mut self,
        to: &str,
        diamond_names: &[String],
    ) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let from = self.require_address()?;
        let preview = self.preview_send_hacd(to, diamond_names).await?;
        if !preview.hip23.ok {
            return Err(WalletError::Policy(preview.hip23.errors.join("; ")));
        }
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
        let canonical = crate::tx_binding::verify_hacd_transfer_with_service_fee(
            &body_hex,
            &from,
            &preview.fee_wire,
            to,
            &preview.diamond_names,
            &service_fee,
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let requirement = self.authorization_requirement(self.second_factor_threshold_mei())?;
        let display = exact_transaction_display(
            "Send HACD",
            &preview.summary,
            &canonical,
            vec![
                field("Recipient", to),
                field("HACD", &preview.diamond_names.join(", ")),
                field("Network fee", &preview.fee_wire),
            ],
        );
        self.store_prepared(
            OperationKind::Hacd,
            &from,
            &body_hex,
            display,
            requirement,
            PreparedExecution::Hacd {
                body_hex: body_hex.clone(),
                node_url: self.node.base_url().to_owned(),
                from: from.clone(),
                to: to.to_owned(),
                diamond_names: preview.diamond_names,
                summary: preview.summary,
            },
        )
    }

    pub async fn execute_prepared_hacd(&mut self, operation_id: &str) -> WalletResult<SendResult> {
        let (payload, assurance) = self.take_prepared(operation_id, OperationKind::Hacd)?;
        let PreparedExecution::Hacd {
            body_hex,
            node_url,
            from,
            to,
            diamond_names,
            summary,
        } = payload
        else {
            return Err(WalletError::Policy("prepared HACD payload mismatch".into()));
        };
        self.require_prepared_environment(&node_url)?;
        let pending = self.begin_pending_history(PaymentRail::L1OnChain, &from, &to, 0.0)?;
        let label = if summary.is_empty() {
            format!("Send {} HACD", diamond_names.len())
        } else {
            summary
        };
        let result = self
            .sign_submit_prepared(&body_hex, assurance)
            .await
            .and_then(|submitted| {
                let hash = submitted
                    .hash
                    .clone()
                    .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
                Ok(SendResult {
                    rail: PaymentRail::L1OnChain,
                    tx_hash: hash,
                    summary: self.summary_with_whisper_notice(label, &submitted),
                    pending: false,
                })
            });
        self.finish_prepared_history(pending, result)
    }

    pub async fn prepare_send_native_asset(
        &mut self,
        to: &str,
        serial_raw: &str,
        amount_raw: &str,
    ) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let from = self.require_address()?;
        let preview = self
            .preview_send_native_asset(to, serial_raw, amount_raw)
            .await?;
        if !preview.hip23.ok {
            return Err(WalletError::Policy(preview.hip23.errors.join("; ")));
        }
        let serial =
            crate::native_asset_send::parse_positive_u64_decimal(&preview.serial, "Asset serial")?;
        let amount =
            crate::native_asset_send::parse_positive_u64_decimal(&preview.amount, "Asset amount")?;
        let built = self
            .node
            .build_send_native_asset_tx(&from, to, serial, amount, &preview.fee_wire)
            .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing tx body".into()))?;
        let canonical = crate::tx_binding::verify_native_asset_transfer(
            &body_hex,
            &from,
            &preview.fee_wire,
            to,
            serial,
            amount,
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let requirement = self.authorization_requirement(self.second_factor_threshold_mei())?;
        let display = exact_transaction_display(
            "Send HIP-20 asset",
            &preview.summary,
            &canonical,
            vec![
                field("Recipient", to),
                field("Asset serial", &preview.serial),
                field("Amount", &preview.amount),
                field("Network fee", &preview.fee_wire),
            ],
        );
        self.store_prepared(
            OperationKind::NativeAsset,
            &from,
            &body_hex,
            display,
            requirement,
            PreparedExecution::NativeAsset {
                body_hex: body_hex.clone(),
                node_url: self.node.base_url().to_owned(),
                from: from.clone(),
                to: to.to_owned(),
                serial,
                amount,
                summary: preview.summary,
            },
        )
    }

    pub async fn execute_prepared_native_asset(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<SendResult> {
        let (payload, assurance) = self.take_prepared(operation_id, OperationKind::NativeAsset)?;
        let PreparedExecution::NativeAsset {
            body_hex,
            node_url,
            from,
            to,
            serial,
            amount,
            summary,
        } = payload
        else {
            return Err(WalletError::Policy(
                "prepared HIP-20 payload mismatch".into(),
            ));
        };
        self.require_prepared_environment(&node_url)?;
        let pending = self.begin_pending_history(PaymentRail::L1OnChain, &from, &to, 0.0)?;
        let label = if summary.is_empty() {
            format!("Send {amount} units of HIP-20 asset #{serial}")
        } else {
            summary
        };
        let result = self
            .sign_submit_prepared(&body_hex, assurance)
            .await
            .and_then(|submitted| {
                let hash = submitted
                    .hash
                    .clone()
                    .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
                Ok(SendResult {
                    rail: PaymentRail::L1OnChain,
                    tx_hash: hash,
                    summary: self.summary_with_whisper_notice(label, &submitted),
                    pending: false,
                })
            });
        self.finish_prepared_history(pending, result)
    }

    pub async fn prepare_send_btc(
        &mut self,
        to: &str,
        satoshi: u64,
    ) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let from = self.require_address()?;
        let preview = self.preview_send_btc(to, satoshi).await?;
        if !preview.hip23.ok {
            return Err(WalletError::Policy(preview.hip23.errors.join("; ")));
        }
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
        let canonical = crate::tx_binding::verify_satoshi_transfers(
            &body_hex,
            &from,
            &preview.fee_wire,
            &transfers,
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let requirement = self.authorization_requirement(self.second_factor_threshold_mei())?;
        let display = exact_transaction_display(
            "Send bridged BTC",
            &preview.summary,
            &canonical,
            vec![
                field("Recipient", to),
                field("Amount", &format!("{} satoshi", preview.satoshi)),
                field("Network fee", &preview.fee_wire),
            ],
        );
        self.store_prepared(
            OperationKind::BridgedBtc,
            &from,
            &body_hex,
            display,
            requirement,
            PreparedExecution::BridgedBtc {
                body_hex: body_hex.clone(),
                node_url: self.node.base_url().to_owned(),
                from: from.clone(),
                to: to.to_owned(),
                satoshi,
                summary: preview.summary,
            },
        )
    }

    pub async fn execute_prepared_btc(&mut self, operation_id: &str) -> WalletResult<SendResult> {
        let (payload, assurance) = self.take_prepared(operation_id, OperationKind::BridgedBtc)?;
        let PreparedExecution::BridgedBtc {
            body_hex,
            node_url,
            from,
            to,
            satoshi,
            summary,
        } = payload
        else {
            return Err(WalletError::Policy("prepared BTC payload mismatch".into()));
        };
        self.require_prepared_environment(&node_url)?;
        let pending = self.begin_pending_history(PaymentRail::L1OnChain, &from, &to, 0.0)?;
        let label = if summary.is_empty() {
            format!("Send {satoshi} bridged BTC satoshi")
        } else {
            summary
        };
        let result = self
            .sign_submit_prepared(&body_hex, assurance)
            .await
            .and_then(|submitted| {
                let hash = submitted
                    .hash
                    .clone()
                    .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
                Ok(SendResult {
                    rail: PaymentRail::L1OnChain,
                    tx_hash: hash,
                    summary: self.summary_with_whisper_notice(label, &submitted),
                    pending: false,
                })
            });
        self.finish_prepared_history(pending, result)
    }

    /// Record a channel that the node has confirmed, everywhere it is read.
    ///
    /// The payment router keeps its own copy of the settings, and that copy is
    /// what the Send screen asks for a channel. Writing `channel_id_hex` into
    /// `self.settings` and saving the file left the router still holding the
    /// pre-open snapshot, in which there is no channel; `try_l2_plan` read
    /// `None`, returned no Fast Pay plan, and the send fell through to a paid
    /// L1 transaction. Silently: the user had just opened and funded a
    /// channel, was shown "channel confirmed", and then paid a fee anyway,
    /// until something else happened to rebuild the router or the wallet was
    /// restarted. Every other site that mutates and saves settings refreshes
    /// the router in the same breath; the three channel-open confirmation
    /// sites did not, and now they do, through here.
    fn adopt_confirmed_channel(&mut self, channel_id: &str) -> WalletResult<()> {
        self.set_active_channel(Some(channel_id.to_owned()))
    }

    /// Forget a channel the node has confirmed closed, everywhere it is read.
    ///
    /// The mirror of [`Self::adopt_confirmed_channel`], and it was missing for
    /// the same reason: the two channel-close confirmation sites wrote
    /// `channel_id_hex = None` into `self.settings`, saved, and returned,
    /// leaving the payment router holding a channel that no longer exists. That
    /// direction is the safe one - `channel_is_ready` rejects a closed channel,
    /// so the send falls back to L1 rather than paying into a dead channel -
    /// but the user is quoted a free Fast Pay send on the Send screen and then
    /// charged a blockchain fee, until the wallet is restarted. Same omission,
    /// same long-lived `WalletService`, so it goes through one place now.
    fn release_closed_channel(&mut self) -> WalletResult<()> {
        self.set_active_channel(None)
    }

    fn set_active_channel(&mut self, channel_id: Option<String>) -> WalletResult<()> {
        self.settings.channel_id_hex = channel_id;
        self.settings.save()?;
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
        Ok(())
    }

    pub async fn prepare_channel_open(
        &mut self,
        hub_address: &str,
        user_deposit_mei: &str,
        hub_deposit_mei: &str,
    ) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let preview = self
            .preview_channel_open(hub_address, user_deposit_mei, hub_deposit_mei)
            .await?;
        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("Fast Pay provider is not configured".into()))?;
        let network_binding =
            exact_l1_channel_network_binding(&self.node, &self.settings.network_mode).await?;
        crate::l2_hub::L2HubClient::new_for_wallet_policy(
            &hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        )
        .require_channel_open_ready(&preview.right_address, &preview.left_deposit)
        .await?;
        let encoded_channel_id = crate::channel::encoded_channel_id(&preview.channel_id)?;
        let (built, fee) = build_channel_open_tx_with_dynamic_fee(
            &self.node,
            network_binding.chain_id,
            &preview.left_address,
            &preview.channel_id,
            &preview.left_address,
            &preview.left_deposit,
            &preview.right_address,
            &preview.right_deposit,
            self.settings.send.l1_fee_speed,
        )
        .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing channel open body".into()))?;
        let canonical = crate::tx_binding::verify_transaction_intent(
            &body_hex,
            &preview.left_address,
            &fee,
            &[
                serde_json::json!({
                    "kind": 0x0411, "chains": [network_binding.chain_id]
                }),
                serde_json::json!({
                    "kind": 2, "channel_id": encoded_channel_id,
                    "left_bill": { "address": preview.left_address, "amount": preview.left_deposit },
                    "right_bill": { "address": preview.right_address, "amount": preview.right_deposit }
                }),
            ],
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let exact_deposit = l2_fast_pay_hub::amount::parse_amount_mei(&preview.left_deposit)
            .map_err(|error| WalletError::Policy(error.to_string()))?;
        let policy_amount_mei = exact_deposit
            .as_millimeis()
            .checked_add(999)
            .ok_or_else(|| WalletError::Policy("channel deposit exceeds policy range".into()))?
            / 1_000;
        let requirement = self.authorization_requirement(policy_amount_mei)?;
        let display = exact_transaction_display(
            "Open Fast Pay channel",
            "Lock funds in a channel",
            &canonical,
            vec![
                field("Hub", hub_address),
                field("Your deposit", &preview.left_deposit),
                field("Hub deposit", &preview.right_deposit),
                field("Network fee", &fee),
                field("Wallet fee", "0 HAC"),
                field(
                    "Total wallet debit",
                    &format!(
                        "{} HAC",
                        exact_hac_sum(&[
                            ("channel deposit", &preview.left_deposit),
                            ("network fee", &fee),
                        ])?
                    ),
                ),
                field("Channel", &preview.channel_id),
                field("Incarnation", &preview.reuse_version.to_string()),
            ],
        );
        let wallet_address = preview.left_address.clone();
        let recovery_created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.store_prepared(
            OperationKind::ChannelOpen,
            &wallet_address,
            &body_hex,
            display,
            requirement,
            PreparedExecution::ChannelOpen {
                body_hex: body_hex.clone(),
                network_fee: fee,
                node_url: self.node.base_url().to_owned(),
                hub_url,
                network_binding,
                preview,
                recovery_operation_id: uuid::Uuid::new_v4().to_string(),
                recovery_idempotency_key: format!("hpay:channel-open:{}", uuid::Uuid::new_v4()),
                recovery_created_unix,
                recovery_expires_unix: recovery_created_unix.saturating_add(300),
            },
        )
    }

    pub async fn execute_prepared_channel_open(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<String> {
        self.require_online_signing_transport()?;
        let (payload, assurance) = self.take_prepared(operation_id, OperationKind::ChannelOpen)?;
        let PreparedExecution::ChannelOpen {
            body_hex,
            network_fee,
            node_url,
            hub_url,
            network_binding,
            preview,
            recovery_operation_id,
            recovery_idempotency_key,
            recovery_created_unix,
            recovery_expires_unix,
        } = payload
        else {
            return Err(WalletError::Policy(
                "prepared channel-open payload mismatch".into(),
            ));
        };
        self.require_prepared_environment(&node_url)?;
        let live_network =
            exact_l1_channel_network_binding(&self.node, &self.settings.network_mode).await?;
        if live_network != network_binding {
            return Err(WalletError::Policy(
                "node network identity changed after channel-open preparation".into(),
            ));
        }
        if self.settings.l2_hub_url.as_deref() != Some(hub_url.as_str()) {
            return Err(WalletError::Policy(
                "Fast Pay Hub changed after channel-open preparation".into(),
            ));
        }
        let client = crate::l2_hub::L2HubClient::new_for_wallet_policy(
            &hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        client
            .require_channel_open_ready(&preview.right_address, &preview.left_deposit)
            .await?;
        if preview.reuse_version != 1 {
            return Err(WalletError::Policy(
                "Mainnet Fast Pay pilot channels are one-use only; this prepared channel cannot be reopened."
                    .into(),
            ));
        }
        let current_reuse = crate::channel::next_channel_reuse_version(
            &self.node,
            &preview.channel_id,
            &preview.left_address,
            &preview.right_address,
        )
        .await?;
        if current_reuse != preview.reuse_version {
            return Err(WalletError::L2(
                "channel incarnation changed after preparation; review the exact preview again"
                    .into(),
            ));
        }
        let encoded_channel_id = crate::channel::encoded_channel_id(&preview.channel_id)?;
        crate::tx_binding::verify_transaction_intent(
            &body_hex,
            &preview.left_address,
            &network_fee,
            &[
                serde_json::json!({
                    "kind": 0x0411, "chains": [network_binding.chain_id]
                }),
                serde_json::json!({
                    "kind": 2, "channel_id": encoded_channel_id,
                    "left_bill": { "address": preview.left_address, "amount": preview.left_deposit },
                    "right_bill": { "address": preview.right_address, "amount": preview.right_deposit }
                }),
            ],
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let required_zhu = exact_hac_sum_zhu(&[
            ("channel deposit", &preview.left_deposit),
            ("network fee", &network_fee),
        ])?;
        let available_zhu = parse_hac_zhu(
            "wallet balance",
            self.node
                .query_balance_entry(&preview.left_address, false)
                .await?
                .hacash_decimal(),
        )?;
        if available_zhu < required_zhu {
            return Err(WalletError::Policy(format!(
                "Fast Pay channel setup requires {} HAC including network fee, but only {} HAC is available",
                format_hac_zhu(required_zhu)?,
                format_hac_zhu(available_zhu)?
            )));
        }
        let deposit = l2_fast_pay_hub::amount::parse_amount_mei(&preview.left_deposit)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let user_deposit_zhu = deposit
            .as_millimeis()
            .checked_mul(l2_fast_pay_hub::readiness::ZHU_PER_MILLIMEI)
            .ok_or_else(|| WalletError::L2("channel deposit exceeds mainnet limits".into()))?;
        let account = self.require_signing_account()?;
        let mut safety = crate::l1_channel_safety::ChannelOpenSafety::open(
            account,
            &preview.right_address,
            &preview.channel_id,
            preview.reuse_version,
        )?;
        let locator = crate::l1_channel_safety::PendingChannelOpenLocator {
            operation_id: recovery_operation_id.clone(),
            hub_identity: preview.right_address.clone(),
            channel_id: preview.channel_id.clone(),
            reuse_version: preview.reuse_version,
            user_address: preview.left_address.clone(),
            left_deposit: preview.left_deposit.clone(),
            right_deposit: preview.right_deposit.clone(),
        };
        crate::l1_channel_safety::persist_pending_locator(account, &locator)?;
        let durable = safety.begin_or_resume(crate::l1_channel_safety::BeginChannelOpen {
            operation_id: &recovery_operation_id,
            idempotency_key: &recovery_idempotency_key,
            user_address: &preview.left_address,
            reuse_version: preview.reuse_version,
            user_deposit_zhu,
            unsigned_transaction_hex: &body_hex,
            created_unix: recovery_created_unix,
            expires_unix: recovery_expires_unix,
        })?;
        let request = if let Some(request) = durable.request {
            request
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > durable.expires_unix {
                safety.cancel_before_signing()?;
                crate::l1_channel_safety::clear_pending_locator(
                    self.require_signing_account()?,
                    &durable.operation_id,
                )?;
                return Err(WalletError::Policy(
                    "Channel setup approval expired before signing. Review it again.".into(),
                ));
            }
            if durable.status != crate::l1_channel_safety::ChannelOpenStatus::PersistedBeforeSigning
            {
                safety.mark_recovery_required()?;
                return Err(WalletError::L2(format!(
                    "RecoveryRequired: channel-open exact signed bytes are unavailable for {}",
                    durable.operation_id
                )));
            }
            safety.mark_signature_may_exist()?;
            let webauthn = assurance == Some(AssuranceMethod::WebAuthn);
            let biometric = assurance == Some(AssuranceMethod::NativeBiometric);
            {
                let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
                session.webauthn_verified = webauthn;
                session.biometric_verified = biometric;
            }
            let request_result: WalletResult<l2_fast_pay_hub::l1_channel::L1ChannelOpenRequest> =
                (|| {
                    let partial_transaction_hex = self.sign_tx_hex(&body_hex)?;
                    verify_user_channel_action_signature(
                        &partial_transaction_hex,
                        &preview.left_address,
                        2,
                        Some(network_binding.chain_id),
                    )?;
                    let account = self.require_signing_account()?;
                    let mut request = l2_fast_pay_hub::l1_channel::L1ChannelOpenRequest {
                        schema: l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA.into(),
                        network: network_binding.network_kind.clone(),
                        chain_id: network_binding.chain_id,
                        mainnet: network_binding.mainnet,
                        block_1_hash: network_binding.block_1_hash.clone(),
                        node_profile_id: network_binding.node_profile_id.clone(),
                        network_instance_id: network_binding.network_instance_id.clone(),
                        transaction_format_version: network_binding.transaction_format_version,
                        operation_id: recovery_operation_id.clone(),
                        idempotency_key: recovery_idempotency_key.clone(),
                        created_unix: recovery_created_unix,
                        expires_unix: recovery_expires_unix,
                        hub_address: preview.right_address.clone(),
                        channel_id: preview.channel_id.clone(),
                        expected_reuse_version: preview.reuse_version,
                        partial_transaction_commitment:
                            l2_fast_pay_hub::l1_channel::transaction_commitment(
                                &partial_transaction_hex,
                            )
                            .map_err(|error| WalletError::L2(error.to_string()))?,
                        partial_transaction_hex,
                        authorization_public_key_hex: hex::encode(
                            account.inner().public_key().serialize_compressed(),
                        ),
                        authorization_signature_hex: String::new(),
                    };
                    let commitment: [u8; 32] = hex::decode(
                        l2_fast_pay_hub::l1_channel::request_commitment(&request)
                            .map_err(|error| WalletError::L2(error.to_string()))?,
                    )
                    .map_err(|_| WalletError::L2("invalid open request commitment".into()))?
                    .try_into()
                    .map_err(|_| WalletError::L2("invalid open request commitment size".into()))?;
                    request.authorization_signature_hex =
                        hex::encode(account.inner().do_sign(&commitment));
                    Ok(request)
                })();
            self.clear_second_factor();
            let request = request_result?;
            safety.persist_user_signed(&request)?;
            request
        };

        let response = match client.open_channel(&request).await {
            Ok(response) => response,
            Err(error) => {
                // Recovery stays required: this wallet cannot tell a Hub that
                // refused the request from a Hub that accepted it and then lost
                // the answer, and guessing the safe-looking one is how funds go
                // missing. What it can do is lead with what the Hub actually
                // said instead of burying it behind an operation id - a user
                // the Hub turned away for not being on its pilot allowlist was
                // reading a sentence about uncertainty and an id, with the real
                // reason trailing off the end of it.
                safety.mark_recovery_required()?;
                return Err(WalletError::L2(format!(
                    "the Fast Pay Hub did not confirm this channel open: {error}. The wallet is \
                     holding operation {} for recovery; recover it before opening another channel.",
                    request.operation_id
                )));
            }
        };
        verify_hub_channel_open_status(&response, &preview, &request)?;
        safety.persist_hub_status(&response)?;
        if response.status == "recovery_required" {
            return Err(WalletError::L2(format!(
                "RecoveryRequired: Hub could not confirm channel-open broadcast for {}",
                request.operation_id
            )));
        }
        let transaction_hash = response.transaction_hash.as_deref().ok_or_else(|| {
            WalletError::L2("Hub omitted the channel-open transaction hash".into())
        })?;
        if !hub_channel_open_has_finality(&response.status) {
            safety.mark_opening()?;
            return Ok(format!(
                "Fast Pay channel submitted: {transaction_hash}. Waiting for 6 confirmations."
            ));
        }
        match crate::channel::query_channel(&self.node, &preview.channel_id).await {
            Ok(channel)
                if exact_open_channel_matches(&channel, &preview, preview.reuse_version) =>
            {
                safety.mark_confirmed()?;
                self.adopt_confirmed_channel(&preview.channel_id)?;
                crate::l1_channel_safety::clear_pending_locator(
                    self.require_signing_account()?,
                    &request.operation_id,
                )?;
                Ok(format!("Fast Pay channel confirmed: {transaction_hash}"))
            }
            Ok(_) => {
                safety.mark_recovery_required()?;
                Err(WalletError::L2(
                    "RecoveryRequired: the trusted node returned a different channel incarnation"
                        .into(),
                ))
            }
            Err(WalletError::Node(message)) if message.contains("channel not found") => {
                safety.mark_opening()?;
                Ok(format!(
                    "Fast Pay channel submitted: {transaction_hash}. Confirmation is pending."
                ))
            }
            Err(error) => {
                safety.mark_recovery_required()?;
                Err(WalletError::L2(format!(
                    "channel-open was broadcast by the Hub but trusted-node confirmation is uncertain: {error}"
                )))
            }
        }
    }
    pub async fn recover_channel_open(&mut self) -> WalletResult<String> {
        self.require_online_signing_transport()?;
        self.touch_auto_lock();
        let locator = {
            let account = self.require_signing_account()?;
            crate::l1_channel_safety::load_pending_locator(account)?.ok_or_else(|| {
                WalletError::L2("there is no pending Fast Pay channel setup to finish".into())
            })?
        };
        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("Fast Pay provider is not configured".into()))?;
        let mut safety = crate::l1_channel_safety::ChannelOpenSafety::open(
            self.require_signing_account()?,
            &locator.hub_identity,
            &locator.channel_id,
            locator.reuse_version,
        )?;
        let operation = safety.operation()?;
        if operation.operation_id != locator.operation_id
            || operation.hub_identity != locator.hub_identity
            || operation.channel_id != locator.channel_id
            || operation.reuse_version != locator.reuse_version
            || operation.user_address != locator.user_address
        {
            return Err(WalletError::L2(
                "RecoveryRequired: pending channel setup does not match authenticated recovery state"
                    .into(),
            ));
        }
        let preview = ChannelSetupPreview {
            channel_id: locator.channel_id.clone(),
            reuse_version: locator.reuse_version,
            left_address: locator.user_address.clone(),
            right_address: locator.hub_identity.clone(),
            left_deposit: locator.left_deposit.clone(),
            right_deposit: locator.right_deposit.clone(),
        };
        self.ensure_transaction_network_binding(&operation.unsigned_transaction_hex)
            .await?;

        if operation.status == crate::l1_channel_safety::ChannelOpenStatus::PersistedBeforeSigning
            && operation.request.is_none()
        {
            safety.cancel_before_signing()?;
            crate::l1_channel_safety::clear_pending_locator(
                self.require_signing_account()?,
                &operation.operation_id,
            )?;
            return Ok(
                "No channel-open signature was created. Review and confirm the setup again.".into(),
            );
        }
        if operation.request.is_none() {
            safety.mark_recovery_required()?;
            return Err(WalletError::L2(
                "RecoveryRequired: a channel-open signature may exist but its exact bytes are unavailable; automatic retry is blocked"
                    .into(),
            ));
        }

        if operation
            .response
            .as_ref()
            .is_some_and(|response| hub_channel_open_has_finality(&response.status))
            || operation.status == crate::l1_channel_safety::ChannelOpenStatus::Confirmed
        {
            match crate::channel::query_channel(&self.node, &preview.channel_id).await {
                Ok(channel)
                    if exact_open_channel_matches(&channel, &preview, preview.reuse_version) =>
                {
                    safety.mark_confirmed()?;
                    self.adopt_confirmed_channel(&preview.channel_id)?;
                    crate::l1_channel_safety::clear_pending_locator(
                        self.require_signing_account()?,
                        &operation.operation_id,
                    )?;
                    return Ok(format!(
                        "Fast Pay channel confirmed: {}",
                        operation
                            .response
                            .as_ref()
                            .and_then(|response| response.transaction_hash.as_deref())
                            .unwrap_or("verified on chain")
                    ));
                }
                Ok(_) => {
                    safety.mark_recovery_required()?;
                    return Err(WalletError::L2(
                        "RecoveryRequired: the node returned a different channel incarnation"
                            .into(),
                    ));
                }
                Err(WalletError::Node(message)) if message.contains("channel not found") => {}
                Err(error) => {
                    return Err(WalletError::L2(format!(
                        "channel-open recovery could not verify the trusted node: {error}"
                    )));
                }
            }
        }

        let request = operation.request.clone().ok_or_else(|| {
            WalletError::L2("RecoveryRequired: exact channel-open request is missing".into())
        })?;
        let client = crate::l2_hub::L2HubClient::new_for_wallet_policy(
            &hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        let response = match client.open_channel(&request).await {
            Ok(response) => response,
            Err(error) => {
                safety.mark_recovery_required()?;
                return Err(WalletError::L2(format!(
                    "channel-open recovery could not resume the exact Hub operation {}: {error}",
                    operation.operation_id
                )));
            }
        };
        verify_hub_channel_open_status(&response, &preview, &request)?;
        safety.persist_hub_status(&response)?;
        if response.status == "recovery_required" {
            return Err(WalletError::L2(format!(
                "RecoveryRequired: Hub open operation {} remains uncertain",
                operation.operation_id
            )));
        }
        let transaction_hash = response
            .transaction_hash
            .as_deref()
            .ok_or_else(|| WalletError::L2("Hub omitted the recovered transaction hash".into()))?;
        if !hub_channel_open_has_finality(&response.status) {
            safety.mark_opening()?;
            return Ok(format!(
                "Fast Pay channel submitted: {transaction_hash}. Waiting for 6 confirmations."
            ));
        }
        match crate::channel::query_channel(&self.node, &preview.channel_id).await {
            Ok(channel)
                if exact_open_channel_matches(&channel, &preview, preview.reuse_version) =>
            {
                safety.mark_confirmed()?;
                self.adopt_confirmed_channel(&preview.channel_id)?;
                crate::l1_channel_safety::clear_pending_locator(
                    self.require_signing_account()?,
                    &operation.operation_id,
                )?;
                Ok(format!("Fast Pay channel confirmed: {transaction_hash}"))
            }
            Ok(_) => {
                safety.mark_recovery_required()?;
                Err(WalletError::L2(
                    "RecoveryRequired: recovered operation produced a different channel incarnation"
                        .into(),
                ))
            }
            Err(WalletError::Node(message)) if message.contains("channel not found") => {
                safety.mark_opening()?;
                Ok(format!(
                    "Fast Pay channel submitted: {transaction_hash}. Confirmation is pending."
                ))
            }
            Err(error) => {
                safety.mark_recovery_required()?;
                Err(WalletError::L2(format!(
                    "channel-open recovery is waiting for trusted-node confirmation: {error}"
                )))
            }
        }
    }
    pub async fn prepare_channel_close(&mut self) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let from = self.require_address()?;
        let channel_id = self
            .settings
            .channel_id_hex
            .clone()
            .ok_or_else(|| WalletError::Transaction("no active channel configured".into()))?;
        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("Fast Pay provider is not configured".into()))?;
        let network_binding =
            exact_l1_channel_network_binding(&self.node, &self.settings.network_mode).await?;
        let channel = crate::channel::query_channel(&self.node, &channel_id).await?;
        if !channel.is_open()
            || channel.close_height != 0
            || channel.open_height == 0
            || channel.reuse_version == 0
            || channel.challenging.is_some()
        {
            return Err(WalletError::L2(
                "channel is not in an exact, unchallenged open incarnation".into(),
            ));
        }
        let hub_address = if channel.left.address == from {
            channel.right.address.clone()
        } else if channel.right.address == from {
            channel.left.address.clone()
        } else {
            return Err(WalletError::L2(
                "active channel does not belong to this Personal Wallet".into(),
            ));
        };
        let trusted = crate::l2_bill::trusted_channel_state(&self.bills, &channel)?;
        let settlement = cooperative_close_settlement(&channel, &trusted)?;
        crate::l2_hub::L2HubClient::new_for_wallet_policy(
            &hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        )
        .require_channel_close_ready(&hub_address, settlement.transfer.is_some())
        .await?;
        let encoded_channel_id = crate::channel::encoded_channel_id(&channel_id)?;
        let (built, fee) = build_channel_close_tx_with_dynamic_fee(
            &self.node,
            network_binding.chain_id,
            &from,
            &channel_id,
            &settlement,
            self.settings.send.l1_fee_speed,
        )
        .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing channel close body".into()))?;
        let expected_actions = channel_close_expected_actions(
            network_binding.chain_id,
            &encoded_channel_id,
            &settlement,
        );
        let canonical = crate::tx_binding::verify_transaction_intent(
            &body_hex,
            &from,
            &fee,
            &expected_actions,
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let requirement = self.authorization_requirement(self.second_factor_threshold_mei())?;
        let display = exact_transaction_display(
            "Close Fast Pay channel",
            "Hub freezes the channel, co-signs the exact cooperative settlement, broadcasts it, and confirms the close",
            &canonical,
            vec![
                field("Channel", &channel_id),
                field("Hub", &hub_address),
                field("Network fee", &fee),
                field("Wallet fee", "0 HAC"),
                field("Open height", &channel.open_height.to_string()),
                field("Reuse version", &channel.reuse_version.to_string()),
                field(
                    "Original L1 distribution",
                    &format!(
                        "{}: {} HAC | {}: {} HAC",
                        channel.left.address,
                        channel.left.hacash,
                        channel.right.address,
                        channel.right.hacash
                    ),
                ),
                field(
                    "Final signed-bill distribution",
                    &format!(
                        "{}: {} HAC | {}: {} HAC",
                        settlement.left_address,
                        crate::channel::format_millimeis_hac(settlement.final_left_millimeis),
                        settlement.right_address,
                        crate::channel::format_millimeis_hac(settlement.final_right_millimeis)
                    ),
                ),
                field("Latest bill", &settlement.bill_auto_number.to_string()),
                field(
                    "Principal settlement",
                    &settlement
                        .transfer
                        .as_ref()
                        .map(|transfer| {
                            format!(
                                "{} HAC from {} to {}",
                                crate::channel::format_millimeis_hac(transfer.amount_millimeis),
                                transfer.from_address,
                                transfer.to_address
                            )
                        })
                        .unwrap_or_else(|| "No principal transfer required".into()),
                ),
            ],
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.store_prepared(
            OperationKind::ChannelClose,
            &from,
            &body_hex,
            display,
            requirement,
            PreparedExecution::ChannelClose {
                body_hex: body_hex.clone(),
                network_fee: fee,
                node_url: self.node.base_url().to_owned(),
                hub_url,
                network_binding,
                hub_address,
                from: from.clone(),
                channel_id,
                reuse_version: channel.reuse_version,
                open_height: channel.open_height,
                settlement,
                recovery_operation_id: uuid::Uuid::new_v4().to_string(),
                recovery_idempotency_key: format!("hpay:channel-close:{}", uuid::Uuid::new_v4()),
                recovery_created_unix: now,
                recovery_expires_unix: now.saturating_add(300),
            },
        )
    }
    pub async fn execute_prepared_channel_close(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<String> {
        self.require_online_signing_transport()?;
        let (payload, assurance) = self.take_prepared(operation_id, OperationKind::ChannelClose)?;
        let PreparedExecution::ChannelClose {
            body_hex,
            network_fee,
            node_url,
            hub_url,
            network_binding,
            hub_address,
            from,
            channel_id,
            reuse_version,
            open_height,
            settlement,
            recovery_operation_id,
            recovery_idempotency_key,
            recovery_created_unix,
            recovery_expires_unix,
        } = payload
        else {
            return Err(WalletError::Policy(
                "prepared channel-close payload mismatch".into(),
            ));
        };
        self.require_prepared_environment(&node_url)?;
        let live_network =
            exact_l1_channel_network_binding(&self.node, &self.settings.network_mode).await?;
        if live_network != network_binding {
            return Err(WalletError::Policy(
                "node network identity changed after channel-close preparation".into(),
            ));
        }
        if self.settings.l2_hub_url.as_deref() != Some(hub_url.as_str()) {
            return Err(WalletError::Policy(
                "Fast Pay Hub changed after channel-close preparation".into(),
            ));
        }
        let channel = crate::channel::query_channel(&self.node, &channel_id).await?;
        require_exact_close_incarnation(&channel, &from, &hub_address, reuse_version, open_height)?;
        let current_trusted = crate::l2_bill::trusted_channel_state(&self.bills, &channel)?;
        let current_settlement = cooperative_close_settlement(&channel, &current_trusted)?;
        if current_settlement != settlement {
            return Err(WalletError::Policy(
                "latest signed Fast Pay bill changed after close preview; prepare a new close"
                    .into(),
            ));
        }
        let encoded_channel_id = crate::channel::encoded_channel_id(&channel_id)?;
        let expected_actions = channel_close_expected_actions(
            network_binding.chain_id,
            &encoded_channel_id,
            &settlement,
        );
        crate::tx_binding::verify_transaction_intent(
            &body_hex,
            &from,
            &network_fee,
            &expected_actions,
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let client = crate::l2_hub::L2HubClient::new_for_wallet_policy(
            &hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        client
            .require_channel_close_ready(&hub_address, settlement.transfer.is_some())
            .await?;

        let account = self.require_signing_account()?;
        let mut safety = crate::l1_channel_close_safety::ChannelCloseSafety::open(
            account,
            &hub_address,
            &channel_id,
        )?;
        let durable =
            safety.begin_or_resume(crate::l1_channel_close_safety::BeginChannelClose {
                operation_id: &recovery_operation_id,
                idempotency_key: &recovery_idempotency_key,
                user_address: &from,
                reuse_version,
                open_height,
                unsigned_transaction_hex: &body_hex,
                created_unix: recovery_created_unix,
                expires_unix: recovery_expires_unix,
            })?;
        let request = if let Some(request) = durable.request {
            request
        } else {
            if durable.status
                == crate::l1_channel_close_safety::ChannelCloseStatus::SignatureMayExist
            {
                safety.mark_recovery_required()?;
                return Err(WalletError::L2(format!(
                    "RecoveryRequired: a user close signature may exist but exact bytes are unavailable for operation {}",
                    durable.operation_id
                )));
            }
            safety.mark_signature_may_exist()?;
            let webauthn = assurance == Some(AssuranceMethod::WebAuthn);
            let biometric = assurance == Some(AssuranceMethod::NativeBiometric);
            {
                let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
                session.webauthn_verified = webauthn;
                session.biometric_verified = biometric;
            }
            let request_result: WalletResult<
                l2_fast_pay_hub::l1_channel_close::L1ChannelCloseRequest,
            > = (|| {
                let partial_transaction_hex = self.sign_tx_hex(&body_hex)?;
                crate::tx_binding::verify_transaction_intent(
                    &partial_transaction_hex,
                    &from,
                    &network_fee,
                    &expected_actions,
                )?;
                verify_user_channel_close_signature(
                    &partial_transaction_hex,
                    &from,
                    network_binding.chain_id,
                )?;
                let account = self.require_signing_account()?;
                let mut request = l2_fast_pay_hub::l1_channel_close::L1ChannelCloseRequest {
                    schema: l2_fast_pay_hub::l1_channel_close::L1_CHANNEL_CLOSE_SCHEMA.into(),
                    network: network_binding.network_kind.clone(),
                    chain_id: network_binding.chain_id,
                    mainnet: network_binding.mainnet,
                    block_1_hash: network_binding.block_1_hash.clone(),
                    node_profile_id: network_binding.node_profile_id.clone(),
                    network_instance_id: network_binding.network_instance_id.clone(),
                    transaction_format_version: network_binding.transaction_format_version,
                    operation_id: recovery_operation_id.clone(),
                    idempotency_key: recovery_idempotency_key.clone(),
                    created_unix: recovery_created_unix,
                    expires_unix: recovery_expires_unix,
                    hub_address: hub_address.clone(),
                    user_address: from.clone(),
                    channel_id: channel_id.clone(),
                    reuse_version,
                    open_height,
                    partial_transaction_commitment:
                        l2_fast_pay_hub::l1_channel::transaction_commitment(
                            &partial_transaction_hex,
                        )
                        .map_err(|error| WalletError::L2(error.to_string()))?,
                    partial_transaction_hex,
                    authorization_public_key_hex: hex::encode(
                        account.inner().public_key().serialize_compressed(),
                    ),
                    authorization_signature_hex: String::new(),
                };
                let commitment: [u8; 32] = hex::decode(
                    l2_fast_pay_hub::l1_channel_close::close_request_commitment(&request)
                        .map_err(|error| WalletError::L2(error.to_string()))?,
                )
                .map_err(|_| WalletError::L2("invalid close request commitment".into()))?
                .try_into()
                .map_err(|_| WalletError::L2("invalid close request commitment size".into()))?;
                request.authorization_signature_hex =
                    hex::encode(account.inner().do_sign(&commitment));
                Ok(request)
            })();
            self.clear_second_factor();
            let request = request_result?;
            safety.persist_user_signed(&request)?;
            request
        };

        let response = match client.close_channel(&request).await {
            Ok(response) => response,
            Err(error) => {
                safety.mark_recovery_required()?;
                return Err(WalletError::L2(format!(
                    "channel-close network result is uncertain; recover exact operation {}: {error}",
                    request.operation_id
                )));
            }
        };
        safety.validate_hub_response(&response)?;
        if response.status == "retired" {
            match crate::channel::query_channel(&self.node, &channel_id).await {
                Ok(channel) => {
                    if let Err(error) = require_exact_closed_incarnation(
                        &channel,
                        &from,
                        &hub_address,
                        reuse_version,
                        open_height,
                    ) {
                        safety.mark_recovery_required()?;
                        return Err(error);
                    }
                }
                Err(error) => {
                    safety.mark_recovery_required()?;
                    return Err(WalletError::L2(format!(
                        "Hub reported close confirmation but the wallet node could not prove it: {error}"
                    )));
                }
            }
        }
        let durable = safety.persist_hub_response(&response)?;
        match durable.status {
            crate::l1_channel_close_safety::ChannelCloseStatus::Confirmed => {
                self.release_closed_channel()?;
                let hash = response.transaction_hash.ok_or_else(|| {
                    WalletError::L2("confirmed channel close is missing transaction hash".into())
                })?;
                Ok(format!("Channel closed and confirmed: {hash}"))
            }
            crate::l1_channel_close_safety::ChannelCloseStatus::HubSubmitted => {
                let hash = response
                    .transaction_hash
                    .unwrap_or_else(|| "unknown".into());
                Ok(format!(
                    "Channel close submitted: {hash}. Confirmation is pending."
                ))
            }
            crate::l1_channel_close_safety::ChannelCloseStatus::RecoveryRequired => {
                Err(WalletError::L2(format!(
                    "Hub requires exact channel-close recovery for operation {}",
                    request.operation_id
                )))
            }
            _ => Err(WalletError::L2(
                "channel-close did not reach a durable Hub state".into(),
            )),
        }
    }
    pub async fn recover_channel_close(&mut self) -> WalletResult<String> {
        self.require_online_signing_transport()?;
        self.touch_auto_lock();
        let from = self.require_address()?;
        let channel_id = self
            .settings
            .channel_id_hex
            .clone()
            .ok_or_else(|| WalletError::L2("no channel is awaiting close recovery".into()))?;
        let hub_url = self
            .settings
            .l2_hub_url
            .clone()
            .ok_or_else(|| WalletError::L2("Fast Pay provider is not configured".into()))?;
        let channel = crate::channel::query_channel(&self.node, &channel_id).await?;
        let hub_address = if channel.left.address == from {
            channel.right.address.clone()
        } else if channel.right.address == from {
            channel.left.address.clone()
        } else {
            return Err(WalletError::L2(
                "recovery channel does not belong to this Personal Wallet".into(),
            ));
        };
        let account = self.require_signing_account()?;
        let mut safety = crate::l1_channel_close_safety::ChannelCloseSafety::open(
            account,
            &hub_address,
            &channel_id,
        )?;
        let operation = safety.operation()?;
        if channel.reuse_version != operation.reuse_version
            || channel.open_height != operation.open_height
        {
            safety.mark_recovery_required()?;
            return Err(WalletError::L2(
                "RecoveryRequired: fullnode channel incarnation changed".into(),
            ));
        }
        let request = operation.request.as_ref().ok_or_else(|| {
            WalletError::L2(format!(
                "RecoveryRequired: exact user-signed bytes are unavailable for operation {}",
                operation.operation_id
            ))
        })?;
        let client = crate::l2_hub::L2HubClient::new_for_wallet_policy(
            &hub_url,
            &self.settings.network_mode,
            self.settings.trusted_mainnet_fast_pay_pilot,
        );
        let response = client.close_channel(request).await.map_err(|error| {
            WalletError::L2(format!(
                "channel-close recovery remains pending for {}: {error}",
                operation.operation_id
            ))
        })?;
        safety.validate_hub_response(&response)?;
        if response.status == "retired" {
            match crate::channel::query_channel(&self.node, &channel_id).await {
                Ok(channel) => {
                    if let Err(error) = require_exact_closed_incarnation(
                        &channel,
                        &from,
                        &hub_address,
                        operation.reuse_version,
                        operation.open_height,
                    ) {
                        safety.mark_recovery_required()?;
                        return Err(error);
                    }
                }
                Err(error) => {
                    safety.mark_recovery_required()?;
                    return Err(WalletError::L2(format!(
                        "Hub reported close confirmation but the wallet node could not prove it: {error}"
                    )));
                }
            }
        }
        let durable = safety.persist_hub_response(&response)?;
        match durable.status {
            crate::l1_channel_close_safety::ChannelCloseStatus::Confirmed => {
                self.release_closed_channel()?;
                let hash = response.transaction_hash.ok_or_else(|| {
                    WalletError::L2("confirmed channel close is missing transaction hash".into())
                })?;
                Ok(format!("Channel closed and confirmed: {hash}"))
            }
            crate::l1_channel_close_safety::ChannelCloseStatus::HubSubmitted => {
                let hash = response
                    .transaction_hash
                    .unwrap_or_else(|| "unknown".into());
                Ok(format!(
                    "Channel close submitted: {hash}. Confirmation is pending."
                ))
            }
            _ => Err(WalletError::L2(format!(
                "channel-close recovery is still required for operation {}",
                operation.operation_id
            ))),
        }
    }
    pub fn prepare_airgap_sign(
        &mut self,
        unsigned: &crate::airgap::AirgapUnsigned,
    ) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let from = self.require_address()?;
        if unsigned.from != from {
            return Err(WalletError::Policy(format!(
                "offline signer address {from} does not match unsigned tx from {}",
                unsigned.from
            )));
        }
        let inspection = self
            .inspect_airgap_envelope(&crate::airgap::AirgapEnvelope::Unsigned(unsigned.clone()))?;
        if inspection.tx_type != crate::airgap::AIRGAP_CLASSIC_L1_TX_TYPE {
            return Err(WalletError::Policy(
                "Type 4 air-gap transactions require the Quantum Lab signer".into(),
            ));
        }
        let requirement = self.authorization_requirement(crate::hip23::policy_amount_mei_ceil(
            inspection.amount_mei,
        )?)?;
        let display = TrustedOperationDisplay {
            title: "Sign offline transaction".into(),
            summary: inspection.summary.clone(),
            fields: vec![
                field("Recipient", &inspection.to),
                field("Amount", &format!("{} HAC", inspection.amount_wire)),
                field("Network fee", &inspection.network_fee),
                field("Body SHA-256", &inspection.body_sha256),
            ],
        };
        self.store_prepared(
            OperationKind::AirgapClassic,
            &from,
            &unsigned.body_hex,
            display,
            requirement,
            PreparedExecution::AirgapClassic {
                unsigned: unsigned.clone(),
            },
        )
    }

    pub fn execute_prepared_airgap_sign(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<crate::airgap::AirgapSignResult> {
        let signing_mode = self.authenticated_signing_mode()?;
        let cold_vault = signing_mode == HardwareSigningMode::AirgapOnly;
        let result = (|| {
            let (payload, assurance) =
                self.take_prepared(operation_id, OperationKind::AirgapClassic)?;
            let PreparedExecution::AirgapClassic { unsigned } = payload else {
                return Err(WalletError::Policy(
                    "prepared air-gap payload mismatch".into(),
                ));
            };
            let permit =
                PreparedAirgapSigningPermit::after_consumed_ticket(signing_mode, assurance)?;
            {
                let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
                session.webauthn_verified = assurance == Some(AssuranceMethod::WebAuthn);
                session.biometric_verified = assurance == Some(AssuranceMethod::NativeBiometric);
            }
            // The stored envelope is inspected again locally. No network request or
            // renderer-controlled field occurs between ticket consumption and sign.
            self.sign_prepared_airgap_unsigned(&unsigned, permit)
        })();
        if cold_vault {
            // Drop every secret and grant immediately, but retain an explicit
            // address-only state so the already-returned QR remains visible.
            self.exhaust_cold_signing_session();
        } else {
            self.clear_second_factor();
        }
        result
    }
    /// Stage the irreversible cold vault transition for review. No key material
    /// and no passphrase is touched here: the ticket only commits to the exact
    /// policy change, so the platform ceremony that follows signs over *this*
    /// activation and nothing else.
    pub fn prepare_cold_vault_activation(&mut self) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let address = self.require_address()?;
        let current_mode = self.authenticated_signing_mode()?;
        match current_mode {
            HardwareSigningMode::AirgapOnly => {
                return Err(WalletError::Policy(
                    "cold vault is already active for this vault".into(),
                ));
            }
            HardwareSigningMode::WatchOnly => {
                return Err(WalletError::Policy(
                    "a watch-only wallet holds no key to move into a cold vault".into(),
                ));
            }
            HardwareSigningMode::Software | HardwareSigningMode::WebAuthnGate => {}
        }
        // Cold Vault's whole promise is that only a freshly authorized offline
        // signature can move funds. That promise is false for a key derived from
        // a guessable phrase: whoever guesses it signs without this app at all.
        // Offering Cold Vault here would be a lie, so refuse and say why.
        if self.legacy_key_derivation().is_some() {
            return Err(WalletError::Policy(
                "this key was derived from a recovery phrase, so Cold Vault cannot protect it; sweep the funds to a newly generated wallet instead"
                    .into(),
            ));
        }
        // Amount-based policy is irrelevant here: the transition itself is the
        // irreversible act, so it always demands the strongest factor on record.
        let requirement = if self.load_webauthn_credential()?.is_some() {
            AuthorizationRequirement::WebAuthn
        } else {
            AuthorizationRequirement::AnyPlatformFactor
        };
        let display = TrustedOperationDisplay {
            title: "Activate Cold Vault".into(),
            summary:
                "Permanent: this vault will afterwards sign only exact, freshly authorized offline Type 2 transactions."
                    .into(),
            fields: vec![
                field("Wallet", &address),
                field("Network", &self.network_mode),
                field("Current signing policy", current_mode.as_str()),
                field("New signing policy", HardwareSigningMode::AirgapOnly.as_str()),
                field("Reversible", "No"),
                field("Biometric unlock", "Deleted"),
                field("Online signing", "Blocked forever"),
                // The unlock factor and the signing factor are not the same set. An
                // Android screen lock can unlock the wallet, and the user is told so,
                // but it is refused for authorizing a signature. Stating it here is
                // the difference between an informed choice and a surprise later.
                // Scoped to Android on purpose: this display is also shown on desktop,
                // where Windows Hello may legitimately be configured with a PIN, so a
                // blanket claim that a PIN is refused would be false there.
                field(
                    "Future signing",
                    "A fresh device factor every time. On Android, fingerprint or face only, not the phone PIN",
                ),
                // Stated in the ceremony itself: the policy is bound to this vault
                // file, not to the key. Any backup taken before now still restores
                // an online wallet for the same address on any device.
                field("Older backups", "Still sign online for this address"),
            ],
        };
        let canonical = cold_vault_activation_canonical(current_mode.as_str());
        self.store_prepared_canonical(
            OperationKind::ColdVaultActivation,
            &address,
            &canonical,
            display,
            requirement,
            PreparedExecution::ColdVaultActivation {
                current_hardware_mode: current_mode.as_str().into(),
            },
        )
    }

    /// Consume the exact activation ticket and perform the irreversible
    /// migration. Every exit path erases session grants.
    pub fn execute_prepared_cold_vault_activation(
        &mut self,
        operation_id: &str,
        current_passphrase: &str,
    ) -> WalletResult<()> {
        let result = (|| {
            let (payload, assurance) =
                self.take_prepared(operation_id, OperationKind::ColdVaultActivation)?;
            let PreparedExecution::ColdVaultActivation {
                current_hardware_mode,
            } = payload
            else {
                return Err(WalletError::Policy(
                    "prepared cold vault payload mismatch".into(),
                ));
            };
            let permit = ColdVaultActivationPermit::after_consumed_ticket(assurance)?;
            if self.authenticated_signing_mode()?.as_str() != current_hardware_mode {
                return Err(WalletError::Policy(
                    "signing policy changed after cold vault activation was prepared".into(),
                ));
            }
            self.verify_wallet_passphrase(current_passphrase)?;
            let current_vault = self.vault_snapshot()?;
            let (_, credential) = current_vault.policy_for_migration()?;
            let _ = permit;
            self.migrate_vault_encryption(
                current_passphrase,
                current_passphrase,
                crate::security::SecurityProfile::paranoid(),
                HardwareSigningMode::AirgapOnly,
                credential.as_deref(),
                true,
            )
        })();
        self.clear_session_authorizations();
        result
    }

    /// Non-consuming: does a freshly authorized activation ticket for exactly
    /// `operation_id` exist right now? The shell uses this to gate the one
    /// irreversible pre-step it must perform itself — deleting the OS unlock
    /// secret — so that step can never run on an unapproved request.
    pub fn cold_vault_activation_is_authorized(&self, operation_id: &str) -> bool {
        self.unlocked.as_ref().is_some_and(|session| {
            session
                .authorization
                .is_authorized_for(operation_id, OperationKind::ColdVaultActivation)
        })
    }

    fn authorization_requirement(
        &self,
        policy_amount_mei: u64,
    ) -> WalletResult<AuthorizationRequirement> {
        match self.authenticated_signing_mode()? {
            HardwareSigningMode::WatchOnly => Err(WalletError::Policy(
                "watch-only wallet cannot prepare a signature".into(),
            )),
            HardwareSigningMode::WebAuthnGate => Ok(AuthorizationRequirement::WebAuthn),
            HardwareSigningMode::AirgapOnly => Ok(AuthorizationRequirement::AnyPlatformFactor),
            HardwareSigningMode::Software => {
                if policy_amount_mei < self.second_factor_threshold_mei() {
                    Ok(AuthorizationRequirement::None)
                } else if self.profile.yubikey_required {
                    Ok(AuthorizationRequirement::WebAuthn)
                } else {
                    Ok(AuthorizationRequirement::AnyPlatformFactor)
                }
            }
        }
    }

    fn store_prepared(
        &mut self,
        kind: OperationKind,
        wallet_address: &str,
        body_hex: &str,
        display: TrustedOperationDisplay,
        requirement: AuthorizationRequirement,
        payload: PreparedExecution,
    ) -> WalletResult<PreparedOperationView> {
        let bytes = match hex::decode(body_hex) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = self.webauthn.clear_pending();
                return Err(WalletError::Transaction(error.to_string()));
            }
        };
        self.store_prepared_canonical(kind, wallet_address, &bytes, display, requirement, payload)
    }

    /// Bind a ticket to canonical bytes that are not a transaction body (policy
    /// transitions). Callers must build those bytes from authenticated state.
    fn store_prepared_canonical(
        &mut self,
        kind: OperationKind,
        wallet_address: &str,
        canonical: &[u8],
        display: TrustedOperationDisplay,
        requirement: AuthorizationRequirement,
        payload: PreparedExecution,
    ) -> WalletResult<PreparedOperationView> {
        self.webauthn.clear_pending()?;
        let chain_id = match self.network_mode.as_str() {
            "mainnet" => Some(0),
            "testnet" => Some(1),
            _ => None,
        };
        let network_mode = self.network_mode.clone();
        self.unlocked
            .as_mut()
            .ok_or(WalletError::Locked)?
            .authorization
            .prepare(
                kind,
                wallet_address,
                &network_mode,
                chain_id,
                canonical,
                display,
                requirement,
                payload,
            )
    }

    fn take_prepared(
        &mut self,
        operation_id: &str,
        kind: OperationKind,
    ) -> WalletResult<(PreparedExecution, Option<AssuranceMethod>)> {
        self.touch_auto_lock();
        let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
        let (payload, assurance, view) = session.authorization.take(operation_id, kind)?;
        if view.wallet_address != session.address || view.network_mode != self.network_mode {
            return Err(WalletError::Policy(
                "wallet or network changed after operation preparation".into(),
            ));
        }
        Ok((payload, assurance))
    }

    fn require_prepared_environment(&self, node_url: &str) -> WalletResult<()> {
        if self.node.base_url() != node_url {
            return Err(WalletError::Policy(
                "node changed after operation preparation".into(),
            ));
        }
        Ok(())
    }

    async fn sign_submit_prepared(
        &mut self,
        body_hex: &str,
        assurance: Option<AssuranceMethod>,
    ) -> WalletResult<crate::node::SubmitTxResponse> {
        self.require_online_signing_transport()?;
        let webauthn = assurance == Some(AssuranceMethod::WebAuthn);
        let biometric = assurance == Some(AssuranceMethod::NativeBiometric);
        {
            let session = self.unlocked.as_mut().ok_or(WalletError::Locked)?;
            session.webauthn_verified = webauthn;
            session.biometric_verified = biometric;
        }
        // No await occurs between installing the exact ticket and signing the
        // canonical bytes. The session grant is then erased before submission.
        let signed = self.sign_tx_hex(body_hex);
        self.clear_second_factor();
        let signed = signed?;
        self.submit_signed_tx(&signed).await
    }

    fn finish_prepared_history(
        &mut self,
        pending_key: Option<String>,
        result: WalletResult<SendResult>,
    ) -> WalletResult<SendResult> {
        match result {
            Ok(result) => {
                self.resolve_pending_history(
                    pending_key,
                    &result.tx_hash,
                    &result.summary,
                    TxStatus::Confirmed,
                )?;
                Ok(result)
            }
            Err(error) => {
                let _ = self.fail_pending_history(pending_key);
                Err(error)
            }
        }
    }

    /// Visible to the parent module so a policy change can invalidate a ticket that was
    /// prepared under the previous rule. Still not public: only the wallet decides when a
    /// pending operation stops being valid.
    pub(super) fn clear_prepared_operation(&mut self) {
        if let Some(session) = self.unlocked.as_mut() {
            session.authorization.clear();
        }
        let _ = self.webauthn.clear_pending();
    }

    pub fn protected_unprepared_signing_block(
        &self,
        operation: &str,
        policy_amount_mei: u64,
    ) -> WalletResult<()> {
        if self.authorization_requirement(policy_amount_mei)? != AuthorizationRequirement::None {
            return Err(WalletError::Policy(format!(
                "{operation} is blocked by high-value policy until it uses exact prepared-operation authorization"
            )));
        }
        Ok(())
    }
}

fn require_exact_close_incarnation(
    channel: &crate::channel::ChannelInfo,
    user_address: &str,
    hub_address: &str,
    reuse_version: u64,
    open_height: u64,
) -> WalletResult<()> {
    if !channel.is_open()
        || channel.close_height != 0
        || channel.challenging.is_some()
        || channel.reuse_version != reuse_version
        || channel.open_height != open_height
        || !((channel.left.address == user_address && channel.right.address == hub_address)
            || (channel.right.address == user_address && channel.left.address == hub_address))
    {
        return Err(WalletError::L2(
            "channel incarnation or parties changed after close preview".into(),
        ));
    }
    Ok(())
}

fn require_exact_closed_incarnation(
    channel: &crate::channel::ChannelInfo,
    user_address: &str,
    hub_address: &str,
    reuse_version: u64,
    open_height: u64,
) -> WalletResult<()> {
    if channel.is_open()
        || channel.close_height == 0
        || channel.challenging.is_some()
        || channel.reuse_version != reuse_version
        || channel.open_height != open_height
        || !((channel.left.address == user_address && channel.right.address == hub_address)
            || (channel.right.address == user_address && channel.left.address == hub_address))
    {
        return Err(WalletError::L2(
            "wallet node did not confirm the exact closed channel incarnation".into(),
        ));
    }
    Ok(())
}
fn channel_close_expected_actions(
    chain_id: u32,
    encoded_channel_id: &str,
    settlement: &CooperativeCloseSettlement,
) -> Vec<serde_json::Value> {
    let mut actions = vec![
        serde_json::json!({
            "kind": 0x0411,
            "chains": [chain_id],
        }),
        serde_json::json!({
            "kind": 3,
            "channel_id": encoded_channel_id,
        }),
    ];
    if let Some(transfer) = &settlement.transfer {
        actions.push(serde_json::json!({
            "kind": 14,
            "from": transfer.from_address,
            "to": transfer.to_address,
            "hacash": crate::channel::format_millimeis_hac(transfer.amount_millimeis),
        }));
    }
    actions
}

fn verify_user_channel_close_signature(
    signed_transaction_hex: &str,
    user_address: &str,
    chain_id: u32,
) -> WalletResult<()> {
    let raw = hex::decode(signed_transaction_hex)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let (tx, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let actions = tx.actions();
    let exact_topology = match actions.len() {
        2 => actions[0].kind() == 0x0411 && actions[1].kind() == 3,
        3 => actions[0].kind() == 0x0411 && actions[1].kind() == 3 && actions[2].kind() == 14,
        _ => false,
    };
    let exact_chain = actions.first().and_then(|action| {
        protocol::action::ChainAllow::downcast(action).map(|guard| guard.chains.as_list())
    });
    if consumed != raw.len()
        || tx.ty() != 2
        || !exact_topology
        || !exact_chain.is_some_and(|chains| chains.len() == 1 && chains[0].uint() == chain_id)
        || tx.signs().len() != 1
    {
        return Err(WalletError::Policy(
            "partial channel-close transaction must be one user-signed Type 2 with exact ChainAllow-bound close topology"
                .into(),
        ));
    }
    let user = field::Address::from_readable(user_address)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let signer = field::Address::from(sys::Account::get_address_by_public_key(
        *tx.signs()[0].publickey,
    ));
    let verified = protocol::transaction::verify_target_signature(&user, tx.as_read())
        .map_err(|error| WalletError::Policy(error.to_string()))?;
    if signer != user || !verified {
        return Err(WalletError::Policy(
            "partial channel-close user signature was not verified".into(),
        ));
    }
    Ok(())
}

fn verify_user_channel_action_signature(
    signed_transaction_hex: &str,
    user_address: &str,
    action_kind: u16,
    exact_chain_id: Option<u32>,
) -> WalletResult<()> {
    let raw = hex::decode(signed_transaction_hex)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let (tx, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let exact_actions = match exact_chain_id {
        Some(chain_id) => {
            if tx.actions().len() != 2
                || tx.actions()[0].kind() != 0x0411
                || tx.actions()[1].kind() != action_kind
            {
                false
            } else {
                protocol::action::ChainAllow::downcast(&tx.actions()[0])
                    .map(|guard| guard.chains.as_list())
                    .is_some_and(|chains| chains.len() == 1 && chains[0].uint() == chain_id)
            }
        }
        None => tx.actions().len() == 1 && tx.actions()[0].kind() == action_kind,
    };
    if consumed != raw.len() || tx.ty() != 2 || !exact_actions || tx.signs().len() != 1 {
        return Err(WalletError::Policy(format!(
            "partial channel transaction has an invalid signed Type 2 topology for Action {action_kind}"
        )));
    }
    let user = field::Address::from_readable(user_address)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let signer = field::Address::from(sys::Account::get_address_by_public_key(
        *tx.signs()[0].publickey,
    ));
    let verified = protocol::transaction::verify_target_signature(&user, tx.as_read())
        .map_err(|error| WalletError::Policy(error.to_string()))?;
    if signer != user || !verified {
        return Err(WalletError::Policy(
            "partial channel transaction user signature was not verified".into(),
        ));
    }
    Ok(())
}
fn verify_hub_channel_open_status(
    response: &l2_fast_pay_hub::l1_channel::L1ChannelOpenStatusResponse,
    preview: &ChannelSetupPreview,
    request: &l2_fast_pay_hub::l1_channel::L1ChannelOpenRequest,
) -> WalletResult<()> {
    if response.schema != l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA
        || response.operation_id != request.operation_id
        || response.channel_id != request.channel_id
        || response.channel_id != preview.channel_id
        || !matches!(
            response.status.as_str(),
            "submission_started" | "submitted" | "confirmed" | "recovery_required"
        )
    {
        return Err(WalletError::L2(
            "Hub returned an invalid channel-open status envelope".into(),
        ));
    }
    let expected_hash = response
        .transaction_hash
        .as_deref()
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| WalletError::L2("Hub returned an invalid transaction hash".into()))?;
    let raw = hex::decode(&request.partial_transaction_hex)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let (tx, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let exact_chain_guard = tx.actions().first().and_then(|action| {
        protocol::action::ChainAllow::downcast(action).map(|guard| guard.chains.as_list())
    });
    if consumed != raw.len()
        || tx.ty() != 2
        || tx.actions().len() != 2
        || tx.actions()[0].kind() != 0x0411
        || tx.actions()[1].kind() != 2
        || !exact_chain_guard
            .is_some_and(|chains| chains.len() == 1 && chains[0].uint() == request.chain_id)
        || tx.signs().len() != 1
        || !hex::encode(tx.hash().as_bytes()).eq_ignore_ascii_case(expected_hash)
    {
        return Err(WalletError::Policy(
            "Hub channel-open status is not bound to the exact user-signed transaction".into(),
        ));
    }
    Ok(())
}

async fn exact_l1_channel_network_binding(
    node: &crate::node::NodeClient,
    expected_mode: &str,
) -> WalletResult<l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding> {
    crate::l1_channel_flow::exact_l1_channel_network_binding(node, expected_mode).await
}

fn hub_channel_open_has_finality(status: &str) -> bool {
    status == "confirmed"
}

fn exact_open_channel_matches(
    channel: &crate::channel::ChannelInfo,
    preview: &ChannelSetupPreview,
    reuse_version: u64,
) -> bool {
    let parsed = |amount: &str| {
        l2_fast_pay_hub::amount::parse_amount_mei(amount)
            .ok()
            .map(|value| value.as_millimeis())
    };
    channel.is_open()
        && channel.close_height == 0
        && channel.open_height > 0
        && channel.challenging.is_none()
        && channel.reuse_version == reuse_version
        && channel.left.address == preview.left_address
        && channel.right.address == preview.right_address
        && parsed(&channel.left.hacash) == parsed(&preview.left_deposit)
        && parsed(&channel.right.hacash) == parsed(&preview.right_deposit)
        && channel.left.satoshi == 0
        && channel.right.satoshi == 0
}
fn field(label: &str, value: &str) -> TrustedDisplayField {
    TrustedDisplayField {
        label: label.into(),
        value: value.into(),
    }
}

fn parse_hac_zhu(label: &str, value: &str) -> WalletResult<u64> {
    field::Amount::from(value)
        .map_err(|error| WalletError::Policy(format!("invalid {label}: {error}")))?
        .to_zhu_u64()
        .map_err(|error| WalletError::Policy(format!("invalid {label}: {error}")))
}

fn exact_hac_sum_zhu(values: &[(&str, &str)]) -> WalletResult<u64> {
    values.iter().try_fold(0u64, |total, (label, value)| {
        total
            .checked_add(parse_hac_zhu(label, value)?)
            .ok_or_else(|| WalletError::Policy("HAC total exceeds supported range".into()))
    })
}

fn format_hac_zhu(value: u64) -> WalletResult<String> {
    const ZHU_PER_HAC: u64 = 100_000_000;
    let whole = value / ZHU_PER_HAC;
    let fraction = value % ZHU_PER_HAC;
    if fraction == 0 {
        return Ok(whole.to_string());
    }
    let fraction = format!("{fraction:08}").trim_end_matches('0').to_owned();
    Ok(format!("{whole}.{fraction}"))
}

fn exact_hac_sum(values: &[(&str, &str)]) -> WalletResult<String> {
    format_hac_zhu(exact_hac_sum_zhu(values)?)
}

fn exact_transaction_display(
    title: &str,
    summary: &str,
    canonical: &crate::tx_binding::CanonicalTransaction,
    mut fields: Vec<TrustedDisplayField>,
) -> TrustedOperationDisplay {
    fields.push(field("Transaction type", &canonical.tx_type.to_string()));
    fields.push(field("Body SHA-256", &canonical.body_sha256));
    TrustedOperationDisplay {
        title: title.into(),
        summary: summary.into(),
        fields,
    }
}

#[cfg(test)]
mod channel_open_finality_tests {
    use super::{exact_hac_sum, hub_channel_open_has_finality};

    #[test]
    fn wallet_activates_channel_only_after_hub_finality() {
        for status in ["submission_started", "submitted", "recovery_required"] {
            assert!(!hub_channel_open_has_finality(status), "{status}");
        }
        assert!(hub_channel_open_has_finality("confirmed"));
    }

    #[test]
    fn channel_open_total_debit_uses_exact_zhu_arithmetic() {
        assert_eq!(
            exact_hac_sum(&[("deposit", "0.01"), ("network fee", "0.0001")]).unwrap(),
            "0.0101"
        );
        assert!(exact_hac_sum(&[("deposit", "NaN")]).is_err());
    }
}
