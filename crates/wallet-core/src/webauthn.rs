//! WebAuthn ceremony coordinator (YubiKey + Windows Hello via browser API).
//! Verifies challenge + origin in clientDataJSON; stores credential binding locally.

use std::sync::Mutex;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use coset::{iana, CborSerializable, CoseKey, Label, RegisteredLabelWithPrivate};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};

/// Desktop dev (Tauri + Vite).
pub const DEFAULT_RP_ID: &str = "localhost";
pub const DEFAULT_RP_ORIGIN: &str = "http://localhost:1420";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id_b64: String,
    pub public_key_b64: Option<String>,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnStatus {
    pub enabled: bool,
}

struct CeremonyState {
    challenge_b64: String,
    purpose: String,
    expected_origin: String,
    rp_id: String,
}

fn resolve_webauthn_context(client_origin: Option<&str>) -> (String, String) {
    if let Some(origin) = client_origin.map(str::trim).filter(|o| !o.is_empty()) {
        if let Some(rp_id) = origin_to_rp_id(origin) {
            return (origin.to_string(), rp_id);
        }
    }
    (
        DEFAULT_RP_ORIGIN.to_string(),
        DEFAULT_RP_ID.to_string(),
    )
}

fn origin_to_rp_id(origin: &str) -> Option<String> {
    let url = url::Url::parse(origin).ok()?;
    let host = url.host_str()?.to_string();
    if host.is_empty() {
        return None;
    }
    Some(match host.as_str() {
        "127.0.0.1" | "0.0.0.0" => "localhost".to_string(),
        other => other.to_string(),
    })
}

fn prefer_platform_authenticator(origin: &str) -> bool {
    !origin.contains("localhost") && !origin.contains("127.0.0.1")
}

pub struct WebAuthnGate {
    pending: Mutex<Option<CeremonyState>>,
}

impl WebAuthnGate {
    pub fn new() -> WalletResult<Self> {
        Ok(Self {
            pending: Mutex::new(None),
        })
    }

    pub fn begin_register(&self, username: &str, client_origin: Option<&str>) -> WalletResult<String> {
        let challenge = random_challenge();
        let (expected_origin, rp_id) = resolve_webauthn_context(client_origin);
        *self.pending.lock().map_err(|e| lock_err(e))? = Some(CeremonyState {
            challenge_b64: challenge.clone(),
            purpose: "registration".into(),
            expected_origin: expected_origin.clone(),
            rp_id: rp_id.clone(),
        });
        let platform = prefer_platform_authenticator(&expected_origin);
        let authenticator_selection = if platform {
            json!({
                "authenticatorAttachment": "platform",
                "userVerification": "required",
                "residentKey": "preferred"
            })
        } else {
            json!({
                "userVerification": "preferred",
                "residentKey": "preferred"
            })
        };
        let options = json!({
            "publicKey": {
                "challenge": challenge,
                "rp": { "name": "Hacash Wallet", "id": rp_id },
                "user": {
                    "id": URL_SAFE_NO_PAD.encode(username.as_bytes()),
                    "name": username,
                    "displayName": "Hacash Wallet User"
                },
                "pubKeyCredParams": [
                    { "type": "public-key", "alg": -7 },
                    { "type": "public-key", "alg": -257 }
                ],
                "authenticatorSelection": authenticator_selection,
                "timeout": 60000,
                "attestation": "none"
            }
        });
        serde_json::to_string(&options).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn finish_register(&self, credential_json: &str) -> WalletResult<String> {
        let state = self.take_pending("registration")?;
        let cred: RegisterCredential = serde_json::from_str(credential_json)
            .map_err(|e| WalletError::Other(e.to_string()))?;
        verify_client_data(
            &cred.response.client_data_json,
            &state.challenge_b64,
            "webauthn.create",
            &state.expected_origin,
        )?;
        let stored = StoredCredential {
            credential_id_b64: cred.raw_id,
            public_key_b64: cred.response.public_key,
            registered_at: chrono::Utc::now().to_rfc3339(),
        };
        let raw = serde_json::to_string(&stored).map_err(|e| WalletError::Other(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(raw.as_bytes()))
    }

    pub fn begin_auth(
        &self,
        credential_id_b64: &str,
        client_origin: Option<&str>,
    ) -> WalletResult<String> {
        let challenge = random_challenge();
        let (expected_origin, rp_id) = resolve_webauthn_context(client_origin);
        *self.pending.lock().map_err(|e| lock_err(e))? = Some(CeremonyState {
            challenge_b64: challenge.clone(),
            purpose: "authentication".into(),
            expected_origin,
            rp_id: rp_id.clone(),
        });
        let options = json!({
            "publicKey": {
                "challenge": challenge,
                "rpId": rp_id,
                "allowCredentials": [{
                    "type": "public-key",
                    "id": credential_id_b64
                }],
                "userVerification": "required",
                "timeout": 60000
            }
        });
        serde_json::to_string(&options).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn finish_auth(&self, assertion_json: &str, stored_b64: Option<&str>) -> WalletResult<()> {
        let state = self.take_pending("authentication")?;
        let cred: AuthCredential = serde_json::from_str(assertion_json)
            .map_err(|e| WalletError::Other(e.to_string()))?;
        let client_data_bytes = decode_b64(&cred.response.client_data_json)?;
        verify_client_data_bytes(
            &client_data_bytes,
            &state.challenge_b64,
            "webauthn.get",
            &state.expected_origin,
        )?;

        let stored_cred = stored_b64
            .map(load_stored_credential)
            .transpose()?;

        if stored_cred
            .as_ref()
            .and_then(|s| s.public_key_b64.as_ref())
            .is_some()
        {
            let auth_b64 = cred
                .response
                .authenticator_data
                .as_ref()
                .ok_or_else(|| {
                    WalletError::Policy(
                        "authenticatorData required when credential has public key".into(),
                    )
                })?;
            let sig_b64 = cred.response.signature.as_ref().ok_or_else(|| {
                WalletError::Policy("signature required when credential has public key".into())
            })?;
            let auth_data = decode_b64(auth_b64)?;
            verify_authenticator_data(&auth_data, &state.rp_id)?;
            let pk_b64 = stored_cred
                .as_ref()
                .and_then(|s| s.public_key_b64.as_ref())
                .expect("checked above");
            let signature = decode_b64(sig_b64)?;
            let client_hash = Sha256::digest(&client_data_bytes);
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&client_hash);
            verify_es256_signature(pk_b64, &signed, &signature)?;
        } else if let (Some(auth_b64), Some(sig_b64)) = (
            cred.response.authenticator_data.as_ref(),
            cred.response.signature.as_ref(),
        ) {
            let auth_data = decode_b64(auth_b64)?;
            verify_authenticator_data(&auth_data, &state.rp_id)?;
            if let Some(stored) = stored_cred.as_ref() {
                if let Some(pk_b64) = &stored.public_key_b64 {
                    let signature = decode_b64(sig_b64)?;
                    let client_hash = Sha256::digest(&client_data_bytes);
                    let mut signed = auth_data.clone();
                    signed.extend_from_slice(&client_hash);
                    verify_es256_signature(pk_b64, &signed, &signature)?;
                }
            }
        }
        Ok(())
    }
}

impl Default for WebAuthnGate {
    fn default() -> Self {
        Self::new().expect("webauthn gate init")
    }
}

#[derive(Deserialize)]
struct RegisterCredential {
    #[serde(rename = "rawId")]
    raw_id: String,
    response: RegisterResponse,
}

#[derive(Deserialize)]
struct RegisterResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "publicKey")]
    public_key: Option<String>,
}

#[derive(Deserialize)]
struct AuthCredential {
    response: AuthResponse,
}

#[derive(Deserialize)]
struct AuthResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: Option<String>,
    signature: Option<String>,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

fn verify_client_data(
    client_data_b64: &str,
    expected_challenge: &str,
    expected_type: &str,
    expected_origin: &str,
) -> WalletResult<()> {
    let bytes = decode_b64(client_data_b64)?;
    verify_client_data_bytes(&bytes, expected_challenge, expected_type, expected_origin)
}

fn verify_client_data_bytes(
    bytes: &[u8],
    expected_challenge: &str,
    expected_type: &str,
    expected_origin: &str,
) -> WalletResult<()> {
    let parsed: ClientData =
        serde_json::from_slice(bytes).map_err(|e| WalletError::Other(e.to_string()))?;
    if parsed.typ != expected_type {
        return Err(WalletError::Policy("invalid WebAuthn ceremony type".into()));
    }
    if parsed.challenge != expected_challenge {
        return Err(WalletError::Policy("WebAuthn challenge mismatch".into()));
    }
    if !origins_match(&parsed.origin, expected_origin) {
        return Err(WalletError::Policy(format!(
            "unexpected origin: {} (expected {})",
            parsed.origin, expected_origin
        )));
    }
    Ok(())
}

fn origins_match(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }
    normalize_origin(actual) == normalize_origin(expected)
}

fn normalize_origin(origin: &str) -> String {
    let Ok(url) = url::Url::parse(origin) else {
        return origin.to_string();
    };
    let host = url.host_str().unwrap_or("");
    let normalized_host = match host {
        "127.0.0.1" => "localhost",
        "0.0.0.0" => "localhost",
        other => other,
    };
    format!(
        "{}://{}{}",
        url.scheme(),
        normalized_host,
        url.port()
            .filter(|port| match url.scheme() {
                "http" => *port != 80,
                "https" => *port != 443,
                _ => true,
            })
            .map(|port| format!(":{port}"))
            .unwrap_or_default()
    )
}

fn verify_authenticator_data(auth_data: &[u8], rp_id: &str) -> WalletResult<()> {
    if auth_data.len() < 37 {
        return Err(WalletError::Policy("authenticatorData too short".into()));
    }
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    if auth_data[..32] != rp_hash[..] {
        return Err(WalletError::Policy("WebAuthn rpIdHash mismatch".into()));
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(WalletError::Policy("WebAuthn user not present".into()));
    }
    Ok(())
}

fn verify_es256_signature(pk_b64: &str, signed: &[u8], signature: &[u8]) -> WalletResult<()> {
    let pk_bytes = decode_b64(pk_b64)?;
    let cose = CoseKey::from_slice(&pk_bytes).map_err(|e| WalletError::Policy(e.to_string()))?;
    if cose.alg != Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)) {
        return Err(WalletError::Policy("unsupported WebAuthn public key algorithm".into()));
    }
    let x = cose_param_bytes(&cose, -2)
        .ok_or_else(|| WalletError::Policy("COSE key missing x coordinate".into()))?;
    let y = cose_param_bytes(&cose, -3)
        .ok_or_else(|| WalletError::Policy("COSE key missing y coordinate".into()))?;
    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(x);
    uncompressed.extend_from_slice(y);
    let point = EncodedPoint::from_bytes(&uncompressed)
        .map_err(|e| WalletError::Policy(e.to_string()))?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| WalletError::Policy(e.to_string()))?;
    let sig = Signature::from_der(signature).or_else(|_| {
        Signature::from_slice(signature)
            .map_err(|e| WalletError::Policy(format!("invalid ES256 signature: {e}")))
    })?;
    verifying_key
        .verify(signed, &sig)
        .map_err(|e| WalletError::Policy(format!("WebAuthn signature invalid: {e}")))?;
    Ok(())
}

fn decode_b64(value: &str) -> WalletResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| {
            use base64::engine::general_purpose::STANDARD;
            STANDARD.decode(value)
        })
        .map_err(|e| WalletError::Other(e.to_string()))
}

fn cose_param_bytes<'a>(key: &'a CoseKey, label: i64) -> Option<&'a [u8]> {
    key.params
        .iter()
        .find(|(l, _)| *l == Label::Int(label))
        .and_then(|(_, v)| v.as_bytes().map(|b| b.as_slice()))
}

fn load_stored_credential(stored_b64: &str) -> WalletResult<StoredCredential> {
    let bytes = URL_SAFE_NO_PAD
        .decode(stored_b64)
        .map_err(|e| WalletError::Other(e.to_string()))?;
    let raw = String::from_utf8(bytes).map_err(|e| WalletError::Other(e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| WalletError::Other(e.to_string()))
}

fn random_challenge() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

impl WebAuthnGate {
    fn take_pending(&self, purpose: &str) -> WalletResult<CeremonyState> {
        let state = self
            .pending
            .lock()
            .map_err(|e| lock_err(e))?
            .take()
            .ok_or_else(|| WalletError::Other("WebAuthn ceremony not started".into()))?;
        if state.purpose != purpose {
            return Err(WalletError::Other("WebAuthn ceremony purpose mismatch".into()));
        }
        Ok(state)
    }
}

fn lock_err<T>(e: std::sync::PoisonError<T>) -> WalletError {
    WalletError::Other(format!("lock poisoned: {e}"))
}

pub fn credential_id_from_store(stored_b64: &str) -> WalletResult<String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(stored_b64)
        .map_err(|e| WalletError::Other(e.to_string()))?;
    let raw = String::from_utf8(bytes).map_err(|e| WalletError::Other(e.to_string()))?;
    let stored: StoredCredential =
        serde_json::from_str(&raw).map_err(|e| WalletError::Other(e.to_string()))?;
    Ok(stored.credential_id_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_url_safe() {
        let c = random_challenge();
        assert!(!c.contains('+'));
        assert!(!c.contains('/'));
        assert_eq!(c.len(), 43);
    }

    #[test]
    fn register_ceremony_roundtrip() {
        let gate = WebAuthnGate::new().unwrap();
        let options_json = gate.begin_register("1TestAddr", None).unwrap();
        assert!(options_json.contains("publicKey"));

        let parsed: serde_json::Value = serde_json::from_str(&options_json).unwrap();
        let challenge = parsed["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": DEFAULT_RP_ORIGIN
        });
        let client_data_b64 = URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes());
        let cred_json = json!({
            "rawId": "dGVzdA",
            "response": {
                "clientDataJSON": client_data_b64,
                "publicKey": null
            }
        })
        .to_string();

        let stored = gate.finish_register(&cred_json).unwrap();
        assert!(!stored.is_empty());
        let cred_id = credential_id_from_store(&stored).unwrap();
        assert_eq!(cred_id, "dGVzdA");
    }

    #[test]
    fn accepts_localhost_origin_alias() {
        let gate = WebAuthnGate::new().unwrap();
        let options_json = gate
            .begin_register("1TestAddr", Some("http://127.0.0.1:1420"))
            .unwrap();
        let challenge = serde_json::from_str::<serde_json::Value>(&options_json).unwrap()
            ["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": "http://localhost:1420"
        });
        let client_data_b64 = URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes());
        let cred_json = json!({
            "rawId": "dGVzdA",
            "response": { "clientDataJSON": client_data_b64, "publicKey": null }
        })
        .to_string();
        assert!(gate.finish_register(&cred_json).is_ok());
    }

    #[test]
    fn rejects_challenge_mismatch() {
        let gate = WebAuthnGate::new().unwrap();
        gate.begin_register("1Test", None).unwrap();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": "wrong",
            "origin": DEFAULT_RP_ORIGIN
        });
        let client_data_b64 = URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes());
        let cred_json = json!({
            "rawId": "dGVzdA",
            "response": { "clientDataJSON": client_data_b64, "publicKey": null }
        })
        .to_string();
        assert!(gate.finish_register(&cred_json).is_err());
    }
}