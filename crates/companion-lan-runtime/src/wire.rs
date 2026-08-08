use hpay_companion_protocol::{
    DeviceId, EncryptedCompanionFrame, PairingConfirmation, PairingRequest,
};

use crate::error::{LanRuntimeError, LanRuntimeResult};

pub(crate) fn encode_client_hello(device_id: &DeviceId) -> Vec<u8> {
    device_id.as_str().as_bytes().to_vec()
}

pub(crate) fn decode_client_hello(bytes: &[u8]) -> LanRuntimeResult<DeviceId> {
    let value = std::str::from_utf8(bytes).map_err(|_| LanRuntimeError::MalformedFrame)?;
    DeviceId::parse(value.to_owned()).map_err(Into::into)
}

pub(crate) fn encode_encrypted_frame(frame: &EncryptedCompanionFrame) -> LanRuntimeResult<Vec<u8>> {
    serde_json::to_vec(frame).map_err(|_| LanRuntimeError::FrameEncoding)
}

pub(crate) fn decode_encrypted_frame(bytes: &[u8]) -> LanRuntimeResult<EncryptedCompanionFrame> {
    serde_json::from_slice(bytes).map_err(|_| LanRuntimeError::MalformedFrame)
}

pub(crate) fn encode_pairing_request(request: &PairingRequest) -> LanRuntimeResult<Vec<u8>> {
    serde_json::to_vec(request).map_err(|_| LanRuntimeError::FrameEncoding)
}

pub(crate) fn decode_pairing_request(bytes: &[u8]) -> LanRuntimeResult<PairingRequest> {
    serde_json::from_slice(bytes).map_err(|_| LanRuntimeError::MalformedFrame)
}

pub(crate) fn encode_pairing_confirmation(
    confirmation: &PairingConfirmation,
) -> LanRuntimeResult<Vec<u8>> {
    serde_json::to_vec(confirmation).map_err(|_| LanRuntimeError::FrameEncoding)
}

pub(crate) fn decode_pairing_confirmation(bytes: &[u8]) -> LanRuntimeResult<PairingConfirmation> {
    serde_json::from_slice(bytes).map_err(|_| LanRuntimeError::MalformedFrame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpay_companion_protocol::FRAME_VERSION;

    #[test]
    fn encrypted_json_is_strict_and_hello_is_typed() {
        let frame = EncryptedCompanionFrame {
            frame_version: FRAME_VERSION,
            session_id: "session_1".to_owned(),
            sender_device_id: DeviceId::parse("desktop_1").unwrap(),
            recipient_device_id: DeviceId::parse("mobile_1").unwrap(),
            sequence: 1,
            issued_at: 100,
            expires_at: 200,
            nonce_hex: "00".repeat(12),
            ciphertext_hex: "00".repeat(16),
        };
        let encoded = encode_encrypted_frame(&frame).unwrap();
        assert_eq!(decode_encrypted_frame(&encoded).unwrap(), frame);
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["plaintext"] = serde_json::json!("forbidden");
        assert!(decode_encrypted_frame(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(decode_client_hello(b"").is_err());
        assert!(decode_client_hello(b"mobile_1").is_ok());
    }
}
