//! Preparation and execution of exact transaction-bound wallet operations.

use crate::authorization::{
    AssuranceMethod, AuthorizationRequirement, NativeAuthorizationChallenge, OperationKind,
    PreparedOperationState, PreparedOperationView, TrustedDisplayField, TrustedOperationDisplay,
};
use crate::channel::{build_channel_close_tx, build_channel_open_tx};
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
        node_url: String,
        preview: ChannelSetupPreview,
        user_deposit_mei: f64,
    },
    ChannelClose {
        body_hex: String,
        node_url: String,
        from: String,
        channel_id: String,
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

    pub async fn prepare_channel_open(
        &mut self,
        hub_address: &str,
        user_deposit_mei: f64,
        hub_deposit_mei: f64,
    ) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let preview = self.preview_channel_open(hub_address, user_deposit_mei, hub_deposit_mei)?;
        let fee = crate::hip23::wire_mei_for_node("1:244");
        let encoded_channel_id = crate::channel::encoded_channel_id(&preview.channel_id)?;
        let built = build_channel_open_tx(
            &self.node,
            &preview.left_address,
            &preview.channel_id,
            &preview.left_address,
            &preview.left_deposit,
            &preview.right_address,
            &preview.right_deposit,
            &fee,
        )
        .await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing channel open body".into()))?;
        let canonical = crate::tx_binding::verify_transaction_intent(
            &body_hex,
            &preview.left_address,
            &fee,
            &[serde_json::json!({
                "kind": 2, "channel_id": encoded_channel_id,
                "left_bill": { "address": preview.left_address, "amount": preview.left_deposit },
                "right_bill": { "address": preview.right_address, "amount": preview.right_deposit }
            })],
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let requirement = self
            .authorization_requirement(crate::hip23::policy_amount_mei_ceil(user_deposit_mei)?)?;
        let display = exact_transaction_display(
            "Open Fast Pay channel",
            "Lock funds in a channel",
            &canonical,
            vec![
                field("Hub", hub_address),
                field("Your deposit", &preview.left_deposit),
                field("Channel", &preview.channel_id),
            ],
        );
        let wallet_address = preview.left_address.clone();
        self.store_prepared(
            OperationKind::ChannelOpen,
            &wallet_address,
            &body_hex,
            display,
            requirement,
            PreparedExecution::ChannelOpen {
                body_hex: body_hex.clone(),
                node_url: self.node.base_url().to_owned(),
                preview,
                user_deposit_mei,
            },
        )
    }

    pub async fn execute_prepared_channel_open(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<String> {
        let (payload, assurance) = self.take_prepared(operation_id, OperationKind::ChannelOpen)?;
        let PreparedExecution::ChannelOpen {
            body_hex,
            node_url,
            preview,
            user_deposit_mei,
        } = payload
        else {
            return Err(WalletError::Policy(
                "prepared channel-open payload mismatch".into(),
            ));
        };
        self.require_prepared_environment(&node_url)?;
        let submitted = self.sign_submit_prepared(&body_hex, assurance).await?;
        let hash = submitted
            .hash
            .clone()
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
        self.settings.hub_right_address = Some(preview.right_address.clone());
        self.settings.channel_id_hex = Some(preview.channel_id.clone());
        self.settings.save()?;
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
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

    pub async fn prepare_channel_close(&mut self) -> WalletResult<PreparedOperationView> {
        self.touch_auto_lock();
        self.clear_prepared_operation();
        let from = self.require_address()?;
        let channel_id = self
            .settings
            .channel_id_hex
            .clone()
            .ok_or_else(|| WalletError::Transaction("no active channel configured".into()))?;
        let fee = crate::hip23::wire_mei_for_node("1:244");
        let encoded_channel_id = crate::channel::encoded_channel_id(&channel_id)?;
        let built = build_channel_close_tx(&self.node, &from, &channel_id, &fee).await?;
        let body_hex = built
            .body
            .ok_or_else(|| WalletError::Transaction("missing channel close body".into()))?;
        let canonical = crate::tx_binding::verify_transaction_intent(
            &body_hex,
            &from,
            &fee,
            &[serde_json::json!({ "kind": 3, "channel_id": encoded_channel_id })],
        )?;
        self.ensure_transaction_network_binding(&body_hex).await?;
        let requirement = self.authorization_requirement(self.second_factor_threshold_mei())?;
        let display = exact_transaction_display(
            "Close Fast Pay channel",
            "Close the on-chain channel",
            &canonical,
            vec![field("Channel", &channel_id)],
        );
        self.store_prepared(
            OperationKind::ChannelClose,
            &from,
            &body_hex,
            display,
            requirement,
            PreparedExecution::ChannelClose {
                body_hex: body_hex.clone(),
                node_url: self.node.base_url().to_owned(),
                from: from.clone(),
                channel_id,
            },
        )
    }

    pub async fn execute_prepared_channel_close(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<String> {
        let (payload, assurance) = self.take_prepared(operation_id, OperationKind::ChannelClose)?;
        let PreparedExecution::ChannelClose {
            body_hex,
            node_url,
            from,
            channel_id,
        } = payload
        else {
            return Err(WalletError::Policy(
                "prepared channel-close payload mismatch".into(),
            ));
        };
        self.require_prepared_environment(&node_url)?;
        let submitted = self.sign_submit_prepared(&body_hex, assurance).await?;
        let hash = submitted
            .hash
            .clone()
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
        self.settings.channel_id_hex = None;
        self.settings.save()?;
        self.router
            .update_settings(self.node.clone(), self.settings.clone());
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

fn field(label: &str, value: &str) -> TrustedDisplayField {
    TrustedDisplayField {
        label: label.into(),
        value: value.into(),
    }
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
