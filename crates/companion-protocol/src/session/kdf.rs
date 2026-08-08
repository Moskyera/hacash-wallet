use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::types::{SessionChallenge, SessionConfirmation, SessionResponse};
use super::validation::{PUBLIC_KEY_BYTES, lower_hex};
use crate::codec::Encoder;
use crate::error::{CompanionError, CompanionResult};

const TRANSCRIPT_DOMAIN: &[u8] = b"HPAY/COMPANION/SESSION-TRANSCRIPT/V1";
const KDF_DOMAIN: &[u8] = b"HPAY/COMPANION/SESSION-KEY/V1";

pub(super) fn random_secret() -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(secret.as_mut());
    secret
}

pub(super) fn ephemeral_public(secret: &[u8; 32]) -> PublicKey {
    PublicKey::from(&StaticSecret::from(*secret))
}

pub(super) fn decode_public(value: &str) -> CompanionResult<PublicKey> {
    lower_hex(value, PUBLIC_KEY_BYTES)?;
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|_| CompanionError::MalformedMessage)?
        .try_into()
        .map_err(|_| CompanionError::MalformedMessage)?;
    Ok(PublicKey::from(bytes))
}

pub(super) fn diffie_hellman(
    local_secret: &[u8; 32],
    peer_public: &PublicKey,
) -> CompanionResult<Zeroizing<[u8; 32]>> {
    let secret = StaticSecret::from(*local_secret);
    let shared = secret.diffie_hellman(peer_public);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(CompanionError::Crypto);
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

pub(super) fn derive_session_key(
    shared_secret: &[u8; 32],
    challenge: &SessionChallenge,
    response: &SessionResponse,
    confirmation: &SessionConfirmation,
) -> CompanionResult<Zeroizing<[u8; 32]>> {
    let mut transcript = Encoder::new(TRANSCRIPT_DOMAIN)?;
    transcript.push_bytes(&challenge.unsigned_bytes()?)?;
    transcript.push_bytes(&response.unsigned_bytes()?)?;
    transcript.push_bytes(&confirmation.unsigned_bytes()?)?;
    let transcript_hash = Sha256::digest(transcript.finish()?);
    let hkdf = Hkdf::<Sha256>::new(Some(&transcript_hash), shared_secret);
    let mut session_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(KDF_DOMAIN, session_key.as_mut())
        .map_err(|_| CompanionError::Crypto)?;
    Ok(session_key)
}
