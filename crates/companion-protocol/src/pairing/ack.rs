use zeroize::Zeroizing;

use super::MobilePairingProof;
use crate::envelope::{EncryptedCompanionFrame, SessionCipher};
use crate::error::{CompanionError, CompanionResult};
use crate::identity::{DeviceId, DevicePublicRecord};
use crate::message::{CompanionMessage, CompanionPayload, PROTOCOL_VERSION};

const ACK_MESSAGE_ID: &str = "pairing_mobile_proof";
const ACK_SEQUENCE: u64 = 1;

pub(super) fn encrypt(
    proof: MobilePairingProof,
    session_key: Zeroizing<[u8; 32]>,
    now: u64,
) -> CompanionResult<EncryptedCompanionFrame> {
    let cipher = SessionCipher::new_zeroizing(
        proof.session_id.clone(),
        proof.mobile_device_id.clone(),
        proof.desktop_device_id.clone(),
        session_key,
        proof.expires_at,
    )?;
    let message = CompanionMessage {
        protocol_version: PROTOCOL_VERSION,
        message_id: ACK_MESSAGE_ID.to_owned(),
        session_id: proof.session_id.clone(),
        sender_device_id: proof.mobile_device_id.clone(),
        recipient_device_id: proof.desktop_device_id.clone(),
        sequence: ACK_SEQUENCE,
        issued_at: proof.issued_at,
        expires_at: proof.expires_at,
        payload: CompanionPayload::PairingMobileProof(proof),
    };
    cipher.encrypt(&message, now)
}

pub(super) fn decrypt(
    frame: &EncryptedCompanionFrame,
    session_id: &str,
    desktop_device_id: &DeviceId,
    mobile_record: &DevicePublicRecord,
    session_key: Zeroizing<[u8; 32]>,
    expires_at: u64,
    now: u64,
) -> CompanionResult<MobilePairingProof> {
    let cipher = SessionCipher::new_zeroizing(
        session_id,
        desktop_device_id.clone(),
        mobile_record.device_id.clone(),
        session_key,
        expires_at,
    )?;
    let (message, replay) = cipher.decrypt(frame, now)?;
    if replay.sequence != ACK_SEQUENCE
        || message.message_id != ACK_MESSAGE_ID
        || message.sequence != ACK_SEQUENCE
        || message.session_id != session_id
        || message.sender_device_id != mobile_record.device_id
        || message.recipient_device_id != *desktop_device_id
        || message.expires_at != expires_at
    {
        return Err(CompanionError::PairingMismatch);
    }
    let CompanionPayload::PairingMobileProof(proof) = message.payload else {
        return Err(CompanionError::PairingMismatch);
    };
    if message.issued_at != proof.issued_at
        || message.expires_at != proof.expires_at
        || message.session_id != proof.session_id
        || message.sender_device_id != proof.mobile_device_id
        || message.recipient_device_id != proof.desktop_device_id
    {
        return Err(CompanionError::PairingMismatch);
    }
    Ok(proof)
}
