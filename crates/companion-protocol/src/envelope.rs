use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::codec::{Encoder, MAX_MESSAGE_BYTES};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::DeviceId;
use crate::message::CompanionMessage;
use crate::replay::ReplayMetadata;

pub const FRAME_VERSION: u64 = 1;
const FRAME_AAD_DOMAIN: &[u8] = b"HPAY/COMPANION/ENCRYPTED-FRAME/V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedCompanionFrame {
    #[serde(with = "crate::serde_decimal_u64")]
    pub frame_version: u64,
    pub session_id: String,
    pub sender_device_id: DeviceId,
    pub recipient_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub sequence: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

impl EncryptedCompanionFrame {
    pub fn replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata {
            context: format!("encrypted_frame:{}", self.session_id),
            sender_device_id: self.sender_device_id.clone(),
            sequence: self.sequence,
            nonce: self.nonce_hex.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    fn aad(&self) -> CompanionResult<Vec<u8>> {
        let mut encoder = Encoder::new(FRAME_AAD_DOMAIN)?;
        encoder.push_u64(self.frame_version);
        encoder.push_string(&self.session_id)?;
        encoder.push_string(self.sender_device_id.as_str())?;
        encoder.push_string(self.recipient_device_id.as_str())?;
        encoder.push_u64(self.sequence);
        encoder.push_u64(self.issued_at);
        encoder.push_u64(self.expires_at);
        encoder.push_string(&self.nonce_hex)?;
        encoder.finish()
    }

    fn validate_shape(&self) -> CompanionResult<()> {
        if self.frame_version != FRAME_VERSION {
            return Err(CompanionError::UnsupportedVersion);
        }
        if self.session_id.is_empty()
            || self.sequence == 0
            || self.expires_at <= self.issued_at
            || self.nonce_hex.len() != 24
            || !self.nonce_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.ciphertext_hex.len() > (MAX_MESSAGE_BYTES + 16) * 2
            || !self.ciphertext_hex.len().is_multiple_of(2)
            || !self
                .ciphertext_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }
}

/// Session-scoped encryption state. The key is derived during pairing and is
/// never serialized or included in debug output.
pub struct SessionCipher {
    session_id: String,
    local_device_id: DeviceId,
    remote_device_id: DeviceId,
    session_key: Zeroizing<[u8; 32]>,
    expires_at: u64,
}

impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionCipher")
            .field("session_id", &self.session_id)
            .field("local_device_id", &self.local_device_id)
            .field("remote_device_id", &self.remote_device_id)
            .field("session_key", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SessionCipher {
    #[cfg(any(test, feature = "dev-software-identity"))]
    pub(crate) fn new(
        session_id: impl Into<String>,
        local_device_id: DeviceId,
        remote_device_id: DeviceId,
        session_key: [u8; 32],
        expires_at: u64,
    ) -> CompanionResult<Self> {
        Self::new_zeroizing(
            session_id,
            local_device_id,
            remote_device_id,
            Zeroizing::new(session_key),
            expires_at,
        )
    }

    /// Explicit development-only constructor for adversarial protocol tooling.
    #[cfg(feature = "dev-software-identity")]
    pub fn new_for_testing(
        session_id: impl Into<String>,
        local_device_id: DeviceId,
        remote_device_id: DeviceId,
        session_key: [u8; 32],
        expires_at: u64,
    ) -> CompanionResult<Self> {
        Self::new(
            session_id,
            local_device_id,
            remote_device_id,
            session_key,
            expires_at,
        )
    }

    pub(crate) fn new_zeroizing(
        session_id: impl Into<String>,
        local_device_id: DeviceId,
        remote_device_id: DeviceId,
        session_key: Zeroizing<[u8; 32]>,
        expires_at: u64,
    ) -> CompanionResult<Self> {
        let session_id = session_id.into();
        if session_id.is_empty() || expires_at == 0 {
            return Err(CompanionError::InvalidSession);
        }
        Ok(Self {
            session_id,
            local_device_id,
            remote_device_id,
            session_key,
            expires_at,
        })
    }

    pub fn encrypt(
        &self,
        message: &CompanionMessage,
        now: u64,
    ) -> CompanionResult<EncryptedCompanionFrame> {
        if now >= self.expires_at {
            return Err(CompanionError::InvalidSession);
        }
        message.validate_at(now)?;
        self.ensure_inner_scope(message)?;
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut frame = EncryptedCompanionFrame {
            frame_version: FRAME_VERSION,
            session_id: self.session_id.clone(),
            sender_device_id: message.sender_device_id.clone(),
            recipient_device_id: message.recipient_device_id.clone(),
            sequence: message.sequence,
            issued_at: message.issued_at,
            expires_at: message.expires_at.min(self.expires_at),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: String::new(),
        };
        let plaintext = message.to_bytes()?;
        let nonce_value = Nonce::from(nonce);
        let cipher = Aes256Gcm::new_from_slice(self.session_key.as_ref())
            .map_err(|_| CompanionError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: &plaintext,
                    aad: &frame.aad()?,
                },
            )
            .map_err(|_| CompanionError::Crypto)?;
        frame.ciphertext_hex = hex::encode(ciphertext);
        frame.validate_shape()?;
        Ok(frame)
    }

    pub fn decrypt(
        &self,
        frame: &EncryptedCompanionFrame,
        now: u64,
    ) -> CompanionResult<(CompanionMessage, ReplayMetadata)> {
        if now >= self.expires_at {
            return Err(CompanionError::InvalidSession);
        }
        frame.validate_shape()?;
        if frame.session_id != self.session_id
            || frame.sender_device_id != self.remote_device_id
            || frame.recipient_device_id != self.local_device_id
            || frame.expires_at > self.expires_at
        {
            return Err(CompanionError::InvalidSession);
        }
        frame.replay_metadata().validate_at(now)?;
        let nonce: [u8; 12] = hex::decode(&frame.nonce_hex)
            .map_err(|_| CompanionError::MalformedMessage)?
            .try_into()
            .map_err(|_| CompanionError::MalformedMessage)?;
        let nonce_value = Nonce::from(nonce);
        let ciphertext =
            hex::decode(&frame.ciphertext_hex).map_err(|_| CompanionError::MalformedMessage)?;
        let cipher = Aes256Gcm::new_from_slice(self.session_key.as_ref())
            .map_err(|_| CompanionError::Crypto)?;
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: &ciphertext,
                    aad: &frame.aad()?,
                },
            )
            .map_err(|_| CompanionError::Crypto)?;
        let message = CompanionMessage::from_bytes(&plaintext)?;
        if message.session_id != frame.session_id
            || message.sender_device_id != frame.sender_device_id
            || message.recipient_device_id != frame.recipient_device_id
            || message.sequence != frame.sequence
            || message.issued_at != frame.issued_at
            || message.expires_at < frame.expires_at
        {
            return Err(CompanionError::InvalidSession);
        }
        message.validate_at(now)?;
        Ok((message, frame.replay_metadata()))
    }

    fn ensure_inner_scope(&self, message: &CompanionMessage) -> CompanionResult<()> {
        if message.session_id != self.session_id
            || message.sender_device_id != self.local_device_id
            || message.recipient_device_id != self.remote_device_id
            || message.expires_at > self.expires_at
        {
            return Err(CompanionError::InvalidSession);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{CompanionPayload, PROTOCOL_VERSION};

    fn pair() -> (SessionCipher, SessionCipher, CompanionMessage) {
        let desktop = DeviceId::parse("desktop_one").unwrap();
        let mobile = DeviceId::parse("mobile_one").unwrap();
        let key = [7_u8; 32];
        let desktop_cipher =
            SessionCipher::new("session_one", desktop.clone(), mobile.clone(), key, 300).unwrap();
        let mobile_cipher =
            SessionCipher::new("session_one", mobile.clone(), desktop.clone(), key, 300).unwrap();
        let message = CompanionMessage {
            protocol_version: PROTOCOL_VERSION,
            message_id: "message_one".to_owned(),
            session_id: "session_one".to_owned(),
            sender_device_id: desktop,
            recipient_device_id: mobile,
            sequence: 1,
            issued_at: 100,
            expires_at: 200,
            payload: CompanionPayload::Ping,
        };
        (desktop_cipher, mobile_cipher, message)
    }

    #[test]
    fn encrypted_roundtrip_and_replay_metadata() {
        let (desktop, mobile, message) = pair();
        let frame = desktop.encrypt(&message, 101).unwrap();
        let (decoded, replay) = mobile.decrypt(&frame, 102).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(replay.sequence, 1);
        assert_eq!(replay.nonce, frame.nonce_hex);
    }

    #[test]
    fn ciphertext_header_session_and_expiry_mutations_fail() {
        let (desktop, mobile, message) = pair();
        let frame = desktop.encrypt(&message, 101).unwrap();
        let mut ciphertext = frame.clone();
        // Guaranteed to differ: a fixed "00" leaves a ciphertext that already
        // starts with those digits untouched, and it then decrypts cleanly.
        let replacement = if ciphertext.ciphertext_hex.starts_with("00") {
            "01"
        } else {
            "00"
        };
        ciphertext.ciphertext_hex.replace_range(0..2, replacement);
        assert_eq!(
            mobile.decrypt(&ciphertext, 102),
            Err(CompanionError::Crypto)
        );
        let mut header = frame.clone();
        header.sequence += 1;
        assert_eq!(mobile.decrypt(&header, 102), Err(CompanionError::Crypto));
        let mut session = frame.clone();
        session.session_id = "other".to_owned();
        assert_eq!(
            mobile.decrypt(&session, 102),
            Err(CompanionError::InvalidSession)
        );
        assert_eq!(mobile.decrypt(&frame, 200), Err(CompanionError::Expired));
    }

    /// The handshake half of the clock-offset fix is in `session/validation.rs`.
    /// This is the other half: once the session is up, every frame carries the
    /// sender's own `issued_at`, and a peer one second ahead must not have every
    /// frame refused - which is what a zero skew budget here produced, one layer
    /// above the handshake it had just been fixed in.
    #[test]
    fn a_frame_from_a_peer_slightly_ahead_is_accepted_and_one_far_ahead_is_not() {
        use crate::replay::MAX_CLOCK_SKEW_SECS;

        let (desktop, mobile, message) = pair();
        let frame = desktop.encrypt(&message, 100).unwrap();
        // The measured case: the reader's clock is one second behind the
        // sender's stamp. The replay guard already accepted this exact frame at
        // this exact second; `validate_at` must agree.
        assert!(frame.replay_metadata().validate_at(99).is_ok());
        assert_eq!(message.validate_at(99), Ok(()));
        assert!(mobile.decrypt(&frame, 99).is_ok());
        // The whole budget, and one second past it.
        assert_eq!(message.validate_at(100 - MAX_CLOCK_SKEW_SECS), Ok(()));
        assert_eq!(
            message.validate_at(100 - MAX_CLOCK_SKEW_SECS - 1),
            Err(CompanionError::InvalidIssuedAt)
        );
        // Expiry keeps its absolute refusal: the budget buys an expired frame
        // nothing at all.
        assert_eq!(message.validate_at(200), Err(CompanionError::Expired));
        assert_eq!(
            message.validate_at(200 + MAX_CLOCK_SKEW_SECS),
            Err(CompanionError::Expired)
        );
        assert_eq!(mobile.decrypt(&frame, 200), Err(CompanionError::Expired));
    }

    #[test]
    fn encrypted_frame_json_u64_fields_are_strict_decimal_strings() {
        let (desktop, _, message) = pair();
        let mut frame = desktop.encrypt(&message, 101).unwrap();
        frame.frame_version = u64::MAX;
        frame.sequence = u64::MAX;
        frame.issued_at = u64::MAX;
        frame.expires_at = u64::MAX;

        let value = serde_json::to_value(&frame).unwrap();
        for field in ["frame_version", "sequence", "issued_at", "expires_at"] {
            assert_eq!(value[field], serde_json::json!(u64::MAX.to_string()));
        }
        assert_eq!(
            serde_json::from_value::<EncryptedCompanionFrame>(value.clone()).unwrap(),
            frame
        );

        let mut numeric = value;
        numeric["sequence"] = serde_json::json!(1);
        assert!(serde_json::from_value::<EncryptedCompanionFrame>(numeric).is_err());
    }

    #[test]
    fn malformed_and_oversized_frames_are_rejected_before_decrypt() {
        let (_, mobile, _) = pair();
        let malformed = EncryptedCompanionFrame {
            frame_version: FRAME_VERSION,
            session_id: "session_one".to_owned(),
            sender_device_id: DeviceId::parse("desktop_one").unwrap(),
            recipient_device_id: DeviceId::parse("mobile_one").unwrap(),
            sequence: 1,
            issued_at: 100,
            expires_at: 200,
            nonce_hex: "bad".to_owned(),
            ciphertext_hex: "00".to_owned(),
        };
        assert_eq!(
            mobile.decrypt(&malformed, 101),
            Err(CompanionError::MalformedMessage)
        );
        let mut oversized = malformed;
        oversized.nonce_hex = "00".repeat(12);
        oversized.ciphertext_hex = "00".repeat(MAX_MESSAGE_BYTES + 17);
        assert_eq!(
            mobile.decrypt(&oversized, 101),
            Err(CompanionError::MalformedMessage)
        );
    }
}
