use serde::{Deserialize, Serialize};

use crate::codec::{CanonicalEncode, Decoder, Encoder};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DevicePermission, DeviceRegistry, DeviceRole, DeviceSignaturePurpose,
    PlatformDeviceSigner, sign_with_platform,
};
use crate::replay::{ReplayGuard, ReplayMetadata, ReplayPermit};

const ADMIN_DOMAIN: &[u8] = b"HPAY/COMPANION/ADMIN-COMMAND/V2";
const ADMIN_CONTEXT: &str = "admin_command";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminCommandKind {
    SuspendAgentPayments,
    RevokeAgent { agent_id: String },
    RevokeMobileDevice { device_id: DeviceId },
}

impl AdminCommandKind {
    fn tag(&self) -> u8 {
        match self {
            Self::SuspendAgentPayments => 1,
            Self::RevokeAgent { .. } => 2,
            Self::RevokeMobileDevice { .. } => 3,
        }
    }

    fn permission(&self) -> DevicePermission {
        match self {
            Self::SuspendAgentPayments => DevicePermission::EmergencyStop,
            Self::RevokeAgent { .. } => DevicePermission::RevokeAgent,
            Self::RevokeMobileDevice { .. } => DevicePermission::RevokeMobileDevice,
        }
    }

    fn encode(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u8(self.tag());
        match self {
            Self::SuspendAgentPayments => {}
            Self::RevokeAgent { agent_id } => encoder.push_string(agent_id)?,
            Self::RevokeMobileDevice { device_id } => encoder.push_string(device_id.as_str())?,
        }
        Ok(())
    }

    fn decode(decoder: &mut Decoder<'_>) -> CompanionResult<Self> {
        match decoder.read_u8()? {
            1 => Ok(Self::SuspendAgentPayments),
            2 => {
                let agent_id = decoder.read_string()?;
                if agent_id.is_empty() {
                    return Err(CompanionError::MalformedMessage);
                }
                Ok(Self::RevokeAgent { agent_id })
            }
            3 => Ok(Self::RevokeMobileDevice {
                device_id: DeviceId::parse(decoder.read_string()?)?,
            }),
            _ => Err(CompanionError::AdminCommandNotAllowed),
        }
    }
}

/// Signed mobile administrative command. Deliberately has no resume or
/// limit-increase variant: mobile authority can only reduce risk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCommand {
    #[serde(with = "crate::serde_decimal_u64")]
    pub command_version: u64,
    pub command_id: String,
    pub command_type: AdminCommandKind,
    pub agent_wallet_id: String,
    pub mobile_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub device_authorization_epoch: u64,
    pub desktop_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub policy_epoch: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub command_sequence: u64,
    pub nonce: String,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
}

impl AdminCommand {
    pub fn canonical_bytes(&self) -> CompanionResult<Vec<u8>> {
        self.validate_shape()?;
        CanonicalEncode::canonical_bytes(self, ADMIN_DOMAIN)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> CompanionResult<Self> {
        let mut decoder = Decoder::new(bytes, ADMIN_DOMAIN)?;
        let value = Self {
            command_version: decoder.read_u64()?,
            command_id: decoder.read_string()?,
            command_type: AdminCommandKind::decode(&mut decoder)?,
            agent_wallet_id: decoder.read_string()?,
            mobile_device_id: DeviceId::parse(decoder.read_string()?)?,
            device_authorization_epoch: decoder.read_u64()?,
            desktop_device_id: DeviceId::parse(decoder.read_string()?)?,
            policy_epoch: decoder.read_u64()?,
            command_sequence: decoder.read_u64()?,
            nonce: decoder.read_string()?,
            issued_at: decoder.read_u64()?,
            expires_at: decoder.read_u64()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    pub fn replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata {
            context: ADMIN_CONTEXT.to_owned(),
            sender_device_id: self.mobile_device_id.clone(),
            sequence: self.command_sequence,
            nonce: self.nonce.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        if self.command_version != 2
            || self.command_id.is_empty()
            || self.agent_wallet_id.is_empty()
            || self.device_authorization_epoch == 0
            || self.policy_epoch == 0
            || self.command_sequence == 0
            || self.nonce.len() < 32
            || self.nonce.len() > 128
            || !self.nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || self.expires_at <= self.issued_at
        {
            return Err(CompanionError::MalformedMessage);
        }
        match &self.command_type {
            AdminCommandKind::RevokeAgent { agent_id } if agent_id.is_empty() => {
                Err(CompanionError::MalformedMessage)
            }
            AdminCommandKind::RevokeMobileDevice { device_id }
                if device_id == &self.mobile_device_id =>
            {
                Ok(())
            }
            AdminCommandKind::RevokeMobileDevice { .. } => {
                Err(CompanionError::AdminCommandNotAllowed)
            }
            _ => Ok(()),
        }
    }
}

impl CanonicalEncode for AdminCommand {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()> {
        encoder.push_u64(self.command_version);
        encoder.push_string(&self.command_id)?;
        self.command_type.encode(encoder)?;
        encoder.push_string(&self.agent_wallet_id)?;
        encoder.push_string(self.mobile_device_id.as_str())?;
        encoder.push_u64(self.device_authorization_epoch);
        encoder.push_string(self.desktop_device_id.as_str())?;
        encoder.push_u64(self.policy_epoch);
        encoder.push_u64(self.command_sequence);
        encoder.push_string(&self.nonce)?;
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdminCommand {
    pub command: AdminCommand,
    pub signature_hex: String,
}

impl SignedAdminCommand {
    pub async fn sign(
        command: AdminCommand,
        signer: &dyn PlatformDeviceSigner,
    ) -> CompanionResult<Self> {
        if signer.identity().role() != DeviceRole::Mobile
            || signer.identity().device_id() != &command.mobile_device_id
        {
            return Err(CompanionError::WalletScopeMismatch);
        }
        let signature_hex = sign_with_platform(
            signer,
            DeviceSignaturePurpose::AdminCommand,
            &command.canonical_bytes()?,
        )
        .await?;
        Ok(Self {
            command,
            signature_hex,
        })
    }

    pub fn verify(
        &self,
        expected_wallet_id: &str,
        expected_desktop_device_id: &DeviceId,
        expected_policy_epoch: u64,
        registry: &DeviceRegistry,
        replay_guard: &ReplayGuard,
        now: u64,
    ) -> CompanionResult<ReplayPermit> {
        self.command.validate_shape()?;
        if self.command.agent_wallet_id != expected_wallet_id {
            return Err(CompanionError::WalletScopeMismatch);
        }
        if &self.command.desktop_device_id != expected_desktop_device_id
            || self.command.policy_epoch != expected_policy_epoch
        {
            return Err(CompanionError::AdminCommandNotAllowed);
        }
        let record = registry.require(
            &self.command.mobile_device_id,
            expected_wallet_id,
            DeviceRole::Mobile,
            self.command.command_type.permission(),
        )?;
        if record.authorization_epoch != self.command.device_authorization_epoch {
            return Err(CompanionError::AuthorizationEpochMismatch);
        }
        record.verify_signature(
            DeviceSignaturePurpose::AdminCommand,
            &self.command.canonical_bytes()?,
            &self.signature_hex,
        )?;
        replay_guard.check(&self.command.replay_metadata(), now)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::identity::SoftwareDeviceIdentity as DeviceIdentity;

    fn fixture(kind: AdminCommandKind) -> (DeviceIdentity, DeviceRegistry, AdminCommand) {
        let mobile = DeviceIdentity::generate(DeviceRole::Mobile);
        let desktop = DeviceIdentity::generate(DeviceRole::Desktop);
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                mobile
                    .public_record(
                        "wallet_one",
                        BTreeSet::from([
                            DevicePermission::EmergencyStop,
                            DevicePermission::RevokeAgent,
                            DevicePermission::RevokeMobileDevice,
                        ]),
                        90,
                    )
                    .unwrap(),
            )
            .unwrap();
        let command = AdminCommand {
            command_version: 2,
            command_id: "command_1".to_owned(),
            command_type: kind,
            agent_wallet_id: "wallet_one".to_owned(),
            mobile_device_id: mobile.device_id().clone(),
            device_authorization_epoch: 1,
            desktop_device_id: desktop.device_id().clone(),
            policy_epoch: 5,
            command_sequence: 1,
            nonce: "ab".repeat(16),
            issued_at: 100,
            expires_at: 200,
        };
        (mobile, registry, command)
    }

    #[tokio::test]
    async fn emergency_stop_and_revoke_are_signed_and_replay_safe() {
        for kind in [
            AdminCommandKind::SuspendAgentPayments,
            AdminCommandKind::RevokeAgent {
                agent_id: "agent_one".to_owned(),
            },
        ] {
            let (mobile, registry, command) = fixture(kind);
            let signed = SignedAdminCommand::sign(command.clone(), &mobile)
                .await
                .unwrap();
            let mut guard = ReplayGuard::new();
            let permit = signed
                .verify(
                    "wallet_one",
                    &command.desktop_device_id,
                    5,
                    &registry,
                    &guard,
                    101,
                )
                .unwrap();
            guard.commit(permit, 101).unwrap();
            assert_eq!(
                signed.verify(
                    "wallet_one",
                    &command.desktop_device_id,
                    5,
                    &registry,
                    &guard,
                    102,
                ),
                Err(CompanionError::SequenceReplay)
            );
        }

        let (mobile, registry, mut command) = fixture(AdminCommandKind::SuspendAgentPayments);
        command.command_type = AdminCommandKind::RevokeMobileDevice {
            device_id: mobile.device_id().clone(),
        };
        let signed = SignedAdminCommand::sign(command.clone(), &mobile)
            .await
            .unwrap();
        assert!(
            signed
                .verify(
                    "wallet_one",
                    &command.desktop_device_id,
                    5,
                    &registry,
                    &ReplayGuard::new(),
                    101,
                )
                .is_ok()
        );
    }

    #[tokio::test]
    async fn mutation_expiry_and_wrong_desktop_fail() {
        let (mobile, registry, command) = fixture(AdminCommandKind::SuspendAgentPayments);
        let mut signed = SignedAdminCommand::sign(command.clone(), &mobile)
            .await
            .unwrap();
        signed.command.policy_epoch += 1;
        assert_eq!(
            signed.verify(
                "wallet_one",
                &command.desktop_device_id,
                6,
                &registry,
                &ReplayGuard::new(),
                101,
            ),
            Err(CompanionError::InvalidSignature)
        );
        let signed = SignedAdminCommand::sign(command.clone(), &mobile)
            .await
            .unwrap();
        assert_eq!(
            signed.verify(
                "wallet_one",
                &DeviceId::parse("desktop_wrong").unwrap(),
                5,
                &registry,
                &ReplayGuard::new(),
                101,
            ),
            Err(CompanionError::AdminCommandNotAllowed)
        );
        assert_eq!(
            signed.verify(
                "wallet_one",
                &command.desktop_device_id,
                5,
                &registry,
                &ReplayGuard::new(),
                200,
            ),
            Err(CompanionError::Expired)
        );
    }

    #[tokio::test]
    async fn stale_device_epoch_and_cross_device_revoke_fail_closed() {
        let (mobile, registry, command) = fixture(AdminCommandKind::SuspendAgentPayments);
        let mut stale = command.clone();
        stale.device_authorization_epoch = 2;
        let stale = SignedAdminCommand::sign(stale, &mobile).await.unwrap();
        assert_eq!(
            stale.verify(
                "wallet_one",
                &command.desktop_device_id,
                5,
                &registry,
                &ReplayGuard::new(),
                101,
            ),
            Err(CompanionError::AuthorizationEpochMismatch)
        );

        let mut cross_device = command;
        cross_device.command_type = AdminCommandKind::RevokeMobileDevice {
            device_id: DeviceId::parse("mobile_other").unwrap(),
        };
        assert!(matches!(
            SignedAdminCommand::sign(cross_device, &mobile).await,
            Err(CompanionError::AdminCommandNotAllowed)
        ));
    }

    #[test]
    fn admin_json_u64_fields_are_strict_decimal_strings() {
        let (_, _, mut command) = fixture(AdminCommandKind::SuspendAgentPayments);
        command.command_version = u64::MAX;
        command.device_authorization_epoch = u64::MAX;
        command.policy_epoch = u64::MAX;
        command.command_sequence = u64::MAX;
        command.issued_at = u64::MAX;
        command.expires_at = u64::MAX;

        let value = serde_json::to_value(&command).unwrap();
        for field in [
            "command_version",
            "device_authorization_epoch",
            "policy_epoch",
            "command_sequence",
            "issued_at",
            "expires_at",
        ] {
            assert_eq!(value[field], serde_json::json!(u64::MAX.to_string()));
        }
        assert_eq!(
            serde_json::from_value::<AdminCommand>(value.clone()).unwrap(),
            command
        );

        let mut numeric = value;
        numeric["command_sequence"] = serde_json::json!(1);
        assert!(serde_json::from_value::<AdminCommand>(numeric).is_err());
    }

    #[tokio::test]
    async fn decoder_rejects_unrecognized_command_and_trailing_data() {
        let (_, _, command) = fixture(AdminCommandKind::SuspendAgentPayments);
        let mut bytes = command.canonical_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            AdminCommand::from_canonical_bytes(&bytes),
            Err(CompanionError::MalformedMessage)
        );
        let json = r#"{
          "command_version":2,"command_id":"c",
          "command_type":{"command_type":"resume_agent_payments"},
          "agent_wallet_id":"w","mobile_device_id":"mobile_a",
          "device_authorization_epoch":1,
          "desktop_device_id":"desktop_a","policy_epoch":1,
          "command_sequence":1,"nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "issued_at":1,"expires_at":2
        }"#;
        assert!(serde_json::from_str::<AdminCommand>(json).is_err());

        let (_, _, command) = fixture(AdminCommandKind::SuspendAgentPayments);
        let mut legacy_json = serde_json::to_value(command).unwrap();
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("device_authorization_epoch");
        legacy_json["command_version"] = serde_json::json!(1);
        assert!(serde_json::from_value::<AdminCommand>(legacy_json).is_err());
    }
}
