//! WebAuthn ceremony coordinator (YubiKey + Windows Hello via browser API).
//! Verifies challenge + origin in clientDataJSON; stores credential binding locally.

use std::sync::Mutex;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::error::{WalletError, WalletResult};

const RP_ID: &str = "localhost";
const RP_ORIGIN: &str = "http://localhost:1420";

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

    pub fn begin_register(&self, username: &str) -> WalletResult<String> {
        let challenge = random_challenge();
        *self.pending.lock().map_err(|e| lock_err(e))? = Some(CeremonyState {
            challenge_b64: challenge.clone(),
            purpose: "registration".into(),
        });
        let options = json!({
            "publicKey": {
                "challenge": challenge,
                "rp": { "name": "Hacash Wallet", "id": RP_ID },
                "user": {
                    "id": URL_SAFE_NO_PAD.encode(username.as_bytes()),
                    "name": username,
                    "displayName": "Hacash Wallet User"
                },
                "pubKeyCredParams": [
                    { "type": "public-key", "alg": -7 },
                    { "type": "public-key", "alg": -257 }
                ],
                "authenticatorSelection": {
                    "userVerification": "preferred",
                    "residentKey": "preferred"
                },
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
        verify_client_data(&cred.response.client_data_json, &state.challenge_b64, "webauthn.create")?;
        let stored = StoredCredential {
            credential_id_b64: cred.raw_id,
            public_key_b64: cred.response.public_key,
            registered_at: chrono::Utc::now().to_rfc3339(),
        };
        let raw = serde_json::to_string(&stored).map_err(|e| WalletError::Other(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(raw.as_bytes()))
    }

    pub fn begin_auth(&self, credential_id_b64: &str) -> WalletResult<String> {
        let challenge = random_challenge();
        *self.pending.lock().map_err(|e| lock_err(e))? = Some(CeremonyState {
            challenge_b64: challenge.clone(),
            purpose: "authentication".into(),
        });
        let options = json!({
            "publicKey": {
                "challenge": challenge,
                "rpId": RP_ID,
                "allowCredentials": [{
                    "type": "public-key",
                    "id": credential_id_b64
                }],
                "userVerification": "preferred",
                "timeout": 60000
            }
        });
        serde_json::to_string(&options).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn finish_auth(&self, assertion_json: &str) -> WalletResult<()> {
        let state = self.take_pending("authentication")?;
        let cred: AuthCredential = serde_json::from_str(assertion_json)
            .map_err(|e| WalletError::Other(e.to_string()))?;
        verify_client_data(
            &cred.response.client_data_json,
            &state.challenge_b64,
            "webauthn.get",
        )?;
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
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

fn verify_client_data(client_data_b64: &str, expected_challenge: &str, expected_type: &str) -> WalletResult<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(client_data_b64)
        .map_err(|e| WalletError::Other(e.to_string()))?;
    let parsed: ClientData =
        serde_json::from_slice(&bytes).map_err(|e| WalletError::Other(e.to_string()))?;
    if parsed.typ != expected_type {
        return Err(WalletError::Policy("invalid WebAuthn ceremony type".into()));
    }
    if parsed.challenge != expected_challenge {
        return Err(WalletError::Policy("WebAuthn challenge mismatch".into()));
    }
    if parsed.origin != RP_ORIGIN {
        return Err(WalletError::Policy(format!(
            "unexpected origin: {}",
            parsed.origin
        )));
    }
    Ok(())
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
        let options_json = gate.begin_register("1TestAddr").unwrap();
        assert!(options_json.contains("publicKey"));

        let parsed: serde_json::Value = serde_json::from_str(&options_json).unwrap();
        let challenge = parsed["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_string();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": RP_ORIGIN
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
    fn rejects_challenge_mismatch() {
        let gate = WebAuthnGate::new().unwrap();
        gate.begin_register("1Test").unwrap();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": "wrong",
            "origin": RP_ORIGIN
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