//! WebAuthn ceremony coordinator (YubiKey + Windows Hello via browser API).
//!
//! Registration accepts only `none` attestation carrying an attested ES256 credential.
//! Authentication is fail-closed: the credential id, RP id, origin, UP/UV flags,
//! signature, and authenticator counter are all checked before a ceremony succeeds.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::{
    AsCborValue, CborSerializable, CoseKey, Label, RegisteredLabel, RegisteredLabelWithPrivate,
    cbor::value::Value, iana,
};
use p256::EncodedPoint;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};

/// Desktop dev (Tauri + Vite).
pub const DEFAULT_RP_ID: &str = "localhost";
pub const DEFAULT_RP_ORIGIN: &str = "http://localhost:1420";

const STORED_CREDENTIAL_VERSION: u8 = 2;
const MAX_CREDENTIAL_JSON_BYTES: usize = 64 * 1024;
const MAX_CLIENT_DATA_BYTES: usize = 8 * 1024;
const MAX_ATTESTATION_OBJECT_BYTES: usize = 32 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES: usize = 16 * 1024;
const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
const MAX_SIGNATURE_BYTES: usize = 1024;
const CEREMONY_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub version: u8,
    pub credential_id_b64: String,
    pub public_key_cose_b64: String,
    pub rp_id: String,
    pub origin: String,
    pub sign_count: u32,
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
    started_at: Instant,
}

fn resolve_webauthn_context(client_origin: Option<&str>) -> WalletResult<(String, String)> {
    if let Some(origin) = client_origin.map(str::trim).filter(|o| !o.is_empty()) {
        let normalized = canonical_web_origin(origin)?;
        let rp_id = origin_to_rp_id(&normalized)
            .ok_or_else(|| WalletError::Policy("WebAuthn origin has no RP host".into()))?;
        return Ok((normalized, rp_id));
    }
    Ok((DEFAULT_RP_ORIGIN.to_string(), DEFAULT_RP_ID.to_string()))
}

fn origin_to_rp_id(origin: &str) -> Option<String> {
    let url = url::Url::parse(origin).ok()?;
    let host = url.host_str()?.to_string();
    if host.is_empty() {
        return None;
    }
    Some(host)
}

fn canonical_web_origin(origin: &str) -> WalletResult<String> {
    let url = url::Url::parse(origin)
        .map_err(|_| WalletError::Policy("invalid WebAuthn origin".into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| WalletError::Policy("WebAuthn origin has no host".into()))?;
    let local_http = host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && local_http) {
        return Err(WalletError::Policy(
            "WebAuthn origin must be HTTPS or a loopback/localhost HTTP origin".into(),
        ));
    }
    if url.username() != ""
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(WalletError::Policy(
            "WebAuthn origin must not contain credentials, a path, query, or fragment".into(),
        ));
    }
    Ok(url.origin().ascii_serialization())
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

    pub fn begin_register(
        &self,
        username: &str,
        client_origin: Option<&str>,
    ) -> WalletResult<String> {
        if username.trim().is_empty() || username.len() > 256 {
            return Err(WalletError::Policy(
                "WebAuthn user name must contain 1 to 256 bytes".into(),
            ));
        }
        let challenge = random_challenge();
        let (expected_origin, rp_id) = resolve_webauthn_context(client_origin)?;
        *self.pending.lock().map_err(lock_err)? = Some(CeremonyState {
            challenge_b64: challenge.clone(),
            purpose: "registration".into(),
            expected_origin: expected_origin.clone(),
            rp_id: rp_id.clone(),
            started_at: Instant::now(),
        });
        let platform = prefer_platform_authenticator(&expected_origin);
        let authenticator_selection = if platform {
            json!({
                "authenticatorAttachment": "platform",
                "userVerification": "required",
                "residentKey": "preferred",
                "requireResidentKey": false
            })
        } else {
            json!({
                "userVerification": "required",
                "residentKey": "preferred",
                "requireResidentKey": false
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
                    { "type": "public-key", "alg": -7 }
                ],
                "authenticatorSelection": authenticator_selection,
                "timeout": 60000,
                "attestation": "none"
            }
        });
        serde_json::to_string(&options).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn finish_register(&self, credential_json: &str) -> WalletResult<String> {
        if credential_json.len() > MAX_CREDENTIAL_JSON_BYTES {
            return Err(WalletError::Policy(
                "WebAuthn registration response is too large".into(),
            ));
        }
        let state = self.take_pending("registration")?;
        let cred: RegisterCredential =
            serde_json::from_str(credential_json).map_err(|e| WalletError::Other(e.to_string()))?;
        let credential_id = verify_credential_identity(&cred.id, &cred.raw_id, &cred.typ)?;
        verify_client_data(
            &cred.response.client_data_json,
            &state.challenge_b64,
            "webauthn.create",
            &state.expected_origin,
        )?;
        let auth_data = parse_none_attestation(&cred.response.attestation_object)?;
        let registration =
            verify_registration_authenticator_data(&auth_data, &state.rp_id, &credential_id)?;
        let stored = StoredCredential {
            version: STORED_CREDENTIAL_VERSION,
            credential_id_b64: cred.raw_id,
            public_key_cose_b64: URL_SAFE_NO_PAD.encode(registration.public_key_cose),
            rp_id: state.rp_id,
            origin: state.expected_origin,
            sign_count: registration.sign_count,
            registered_at: chrono::Utc::now().to_rfc3339(),
        };
        encode_stored_credential(&stored)
    }

    pub fn begin_auth(
        &self,
        credential_id_b64: &str,
        client_origin: Option<&str>,
    ) -> WalletResult<String> {
        self.begin_auth_inner(credential_id_b64, client_origin, None)
    }

    /// Start a fresh authentication whose opaque WebAuthn challenge also
    /// contains the server-side digest of one prepared operation.
    pub fn begin_auth_bound(
        &self,
        credential_id_b64: &str,
        client_origin: Option<&str>,
        operation_digest: &[u8; 32],
    ) -> WalletResult<String> {
        self.begin_auth_inner(credential_id_b64, client_origin, Some(operation_digest))
    }

    fn begin_auth_inner(
        &self,
        credential_id_b64: &str,
        client_origin: Option<&str>,
        operation_digest: Option<&[u8; 32]>,
    ) -> WalletResult<String> {
        decode_credential_id(credential_id_b64)?;
        let challenge = operation_digest
            .map(random_bound_challenge)
            .unwrap_or_else(random_challenge);
        let (expected_origin, rp_id) = resolve_webauthn_context(client_origin)?;
        *self.pending.lock().map_err(lock_err)? = Some(CeremonyState {
            challenge_b64: challenge.clone(),
            purpose: "authentication".into(),
            expected_origin,
            rp_id: rp_id.clone(),
            started_at: Instant::now(),
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

    pub fn clear_pending(&self) -> WalletResult<()> {
        *self.pending.lock().map_err(lock_err)? = None;
        Ok(())
    }

    pub fn finish_auth(
        &self,
        assertion_json: &str,
        stored_b64: Option<&str>,
    ) -> WalletResult<String> {
        if assertion_json.len() > MAX_CREDENTIAL_JSON_BYTES {
            return Err(WalletError::Policy(
                "WebAuthn authentication response is too large".into(),
            ));
        }
        let state = self.take_pending("authentication")?;
        let stored_b64 = stored_b64
            .ok_or_else(|| WalletError::Policy("WebAuthn credential is not registered".into()))?;
        let mut stored = load_stored_credential(stored_b64)?;
        validate_stored_credential(&stored)?;
        if stored.rp_id != state.rp_id || stored.origin != state.expected_origin {
            return Err(WalletError::Policy(
                "WebAuthn RP/origin differs from the registered credential".into(),
            ));
        }

        let cred: AuthCredential =
            serde_json::from_str(assertion_json).map_err(|e| WalletError::Other(e.to_string()))?;
        let credential_id = verify_credential_identity(&cred.id, &cred.raw_id, &cred.typ)?;
        if credential_id != decode_credential_id(&stored.credential_id_b64)? {
            return Err(WalletError::Policy(
                "WebAuthn credential id does not match the registered credential".into(),
            ));
        }
        let client_data_bytes = decode_b64_limited(
            &cred.response.client_data_json,
            MAX_CLIENT_DATA_BYTES,
            "clientDataJSON",
        )?;
        verify_client_data_bytes(
            &client_data_bytes,
            &state.challenge_b64,
            "webauthn.get",
            &state.expected_origin,
        )?;
        let auth_data = decode_b64_limited(
            &cred.response.authenticator_data,
            MAX_AUTHENTICATOR_DATA_BYTES,
            "authenticatorData",
        )?;
        let auth = verify_assertion_authenticator_data(&auth_data, &state.rp_id)?;
        let signature =
            decode_b64_limited(&cred.response.signature, MAX_SIGNATURE_BYTES, "signature")?;
        let client_hash = Sha256::digest(&client_data_bytes);
        let mut signed = auth_data;
        signed.extend_from_slice(&client_hash);
        verify_es256_signature(&stored.public_key_cose_b64, &signed, &signature)?;
        advance_sign_count(&mut stored, auth.sign_count)?;
        encode_stored_credential(&stored)
    }
}

impl Default for WebAuthnGate {
    fn default() -> Self {
        Self::new().expect("webauthn gate init")
    }
}

#[derive(Deserialize)]
struct RegisterCredential {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: String,
    #[serde(rename = "type")]
    typ: String,
    response: RegisterResponse,
}

#[derive(Deserialize)]
struct RegisterResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

#[derive(Deserialize)]
struct AuthCredential {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: String,
    #[serde(rename = "type")]
    typ: String,
    response: AuthResponse,
}

#[derive(Deserialize)]
struct AuthResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
}

struct AuthenticatorHeader {
    flags: u8,
    sign_count: u32,
}

struct RegistrationData {
    public_key_cose: Vec<u8>,
    sign_count: u32,
}

fn verify_client_data(
    client_data_b64: &str,
    expected_challenge: &str,
    expected_type: &str,
    expected_origin: &str,
) -> WalletResult<()> {
    let bytes = decode_b64_limited(client_data_b64, MAX_CLIENT_DATA_BYTES, "clientDataJSON")?;
    verify_client_data_bytes(&bytes, expected_challenge, expected_type, expected_origin)
}

fn verify_client_data_bytes(
    bytes: &[u8],
    expected_challenge: &str,
    expected_type: &str,
    expected_origin: &str,
) -> WalletResult<()> {
    let parsed: ClientData = serde_json::from_slice(bytes)
        .map_err(|e| WalletError::Policy(format!("invalid WebAuthn clientDataJSON: {e}")))?;
    if parsed.typ != expected_type {
        return Err(WalletError::Policy("invalid WebAuthn ceremony type".into()));
    }
    if parsed.challenge != expected_challenge {
        return Err(WalletError::Policy("WebAuthn challenge mismatch".into()));
    }
    if parsed.cross_origin {
        return Err(WalletError::Policy(
            "cross-origin WebAuthn ceremonies are not allowed".into(),
        ));
    }
    let actual_origin = canonical_web_origin(&parsed.origin)?;
    if actual_origin != expected_origin {
        return Err(WalletError::Policy(format!(
            "unexpected origin: {actual_origin} (expected {expected_origin})"
        )));
    }
    Ok(())
}

fn verify_credential_identity(id: &str, raw_id: &str, typ: &str) -> WalletResult<Vec<u8>> {
    if typ != "public-key" {
        return Err(WalletError::Policy(
            "WebAuthn credential type must be public-key".into(),
        ));
    }
    let raw_id_bytes = decode_credential_id(raw_id)?;
    if decode_credential_id(id)? != raw_id_bytes {
        return Err(WalletError::Policy(
            "WebAuthn credential id and rawId differ".into(),
        ));
    }
    Ok(raw_id_bytes)
}

fn decode_credential_id(value: &str) -> WalletResult<Vec<u8>> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_ID_BYTES * 2 {
        return Err(WalletError::Policy(
            "WebAuthn credential id has an invalid length".into(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| WalletError::Policy("WebAuthn credential id is not base64url".into()))?;
    if bytes.is_empty()
        || bytes.len() > MAX_CREDENTIAL_ID_BYTES
        || URL_SAFE_NO_PAD.encode(&bytes) != value
    {
        return Err(WalletError::Policy(
            "WebAuthn credential id is not canonical base64url".into(),
        ));
    }
    Ok(bytes)
}

fn parse_none_attestation(attestation_b64: &str) -> WalletResult<Vec<u8>> {
    let bytes = decode_b64_limited(
        attestation_b64,
        MAX_ATTESTATION_OBJECT_BYTES,
        "attestationObject",
    )?;
    let mut reader = bytes.as_slice();
    let value: Value = coset::cbor::de::from_reader(&mut reader)
        .map_err(|e| WalletError::Policy(format!("invalid WebAuthn attestation object: {e}")))?;
    if !reader.is_empty() {
        return Err(WalletError::Policy(
            "WebAuthn attestation object has trailing data".into(),
        ));
    }
    let Value::Map(entries) = value else {
        return Err(WalletError::Policy(
            "WebAuthn attestation object must be a CBOR map".into(),
        ));
    };
    let mut fmt = None;
    let mut auth_data = None;
    let mut att_stmt_empty = None;
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err(WalletError::Policy(
                "WebAuthn attestation object has a non-text key".into(),
            ));
        };
        match (key.as_str(), value) {
            ("fmt", Value::Text(value)) => {
                if fmt.replace(value).is_some() {
                    return Err(WalletError::Policy(
                        "WebAuthn attestation object contains a duplicate fmt".into(),
                    ));
                }
            }
            ("authData", Value::Bytes(value)) => {
                if auth_data.replace(value).is_some() {
                    return Err(WalletError::Policy(
                        "WebAuthn attestation object contains duplicate authData".into(),
                    ));
                }
            }
            ("attStmt", Value::Map(value)) => {
                if att_stmt_empty.replace(value.is_empty()).is_some() {
                    return Err(WalletError::Policy(
                        "WebAuthn attestation object contains duplicate attStmt".into(),
                    ));
                }
            }
            ("fmt" | "authData" | "attStmt", _) => {
                return Err(WalletError::Policy(
                    "WebAuthn attestation object contains an invalid field".into(),
                ));
            }
            _ => {
                return Err(WalletError::Policy(
                    "WebAuthn attestation object contains an unexpected field".into(),
                ));
            }
        }
    }
    if fmt.as_deref() != Some("none") || att_stmt_empty != Some(true) {
        return Err(WalletError::Policy(
            "only WebAuthn none attestation is supported".into(),
        ));
    }
    auth_data.ok_or_else(|| WalletError::Policy("WebAuthn attestation lacks authData".into()))
}

fn verify_authenticator_header(auth_data: &[u8], rp_id: &str) -> WalletResult<AuthenticatorHeader> {
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
    if flags & 0x04 == 0 {
        return Err(WalletError::Policy(
            "WebAuthn user verification required".into(),
        ));
    }
    if flags & 0x10 != 0 && flags & 0x08 == 0 {
        return Err(WalletError::Policy(
            "WebAuthn backup-state flag is inconsistent".into(),
        ));
    }
    Ok(AuthenticatorHeader {
        flags,
        sign_count: u32::from_be_bytes(
            auth_data[33..37]
                .try_into()
                .map_err(|_| WalletError::Policy("invalid WebAuthn signature counter".into()))?,
        ),
    })
}

fn verify_registration_authenticator_data(
    auth_data: &[u8],
    rp_id: &str,
    expected_credential_id: &[u8],
) -> WalletResult<RegistrationData> {
    let header = verify_authenticator_header(auth_data, rp_id)?;
    if header.flags & 0x40 == 0 {
        return Err(WalletError::Policy(
            "WebAuthn registration lacks attested credential data".into(),
        ));
    }
    let credential_len_offset = 37 + 16;
    if auth_data.len() < credential_len_offset + 2 {
        return Err(WalletError::Policy(
            "WebAuthn attested credential data is truncated".into(),
        ));
    }
    let credential_len = u16::from_be_bytes([
        auth_data[credential_len_offset],
        auth_data[credential_len_offset + 1],
    ]) as usize;
    if credential_len == 0 || credential_len > MAX_CREDENTIAL_ID_BYTES {
        return Err(WalletError::Policy(
            "WebAuthn attested credential id has an invalid length".into(),
        ));
    }
    let credential_start = credential_len_offset + 2;
    let credential_end = credential_start
        .checked_add(credential_len)
        .ok_or_else(|| {
            WalletError::Policy("WebAuthn attested credential length overflow".into())
        })?;
    if credential_end > auth_data.len()
        || auth_data[credential_start..credential_end] != *expected_credential_id
    {
        return Err(WalletError::Policy(
            "WebAuthn attested credential id does not match rawId".into(),
        ));
    }

    let mut key_reader = &auth_data[credential_end..];
    let key_value: Value = coset::cbor::de::from_reader(&mut key_reader)
        .map_err(|e| WalletError::Policy(format!("invalid WebAuthn COSE key: {e}")))?;
    let cose = CoseKey::from_cbor_value(key_value)
        .map_err(|e| WalletError::Policy(format!("invalid WebAuthn COSE key: {e}")))?;
    validate_cose_es256(&cose)?;
    verify_extensions(header.flags, key_reader)?;
    let public_key_cose = cose
        .to_vec()
        .map_err(|e| WalletError::Policy(format!("invalid WebAuthn COSE key: {e}")))?;
    Ok(RegistrationData {
        public_key_cose,
        sign_count: header.sign_count,
    })
}

fn verify_assertion_authenticator_data(
    auth_data: &[u8],
    rp_id: &str,
) -> WalletResult<AuthenticatorHeader> {
    let header = verify_authenticator_header(auth_data, rp_id)?;
    if header.flags & 0x40 != 0 {
        return Err(WalletError::Policy(
            "WebAuthn assertion unexpectedly contains attested credential data".into(),
        ));
    }
    verify_extensions(header.flags, &auth_data[37..])?;
    Ok(header)
}

fn verify_extensions(flags: u8, bytes: &[u8]) -> WalletResult<()> {
    if flags & 0x80 == 0 {
        if bytes.is_empty() {
            return Ok(());
        }
        return Err(WalletError::Policy(
            "WebAuthn authenticatorData has undeclared trailing data".into(),
        ));
    }
    let mut reader = bytes;
    let value: Value = coset::cbor::de::from_reader(&mut reader)
        .map_err(|e| WalletError::Policy(format!("invalid WebAuthn extensions: {e}")))?;
    if !reader.is_empty() || !matches!(value, Value::Map(_)) {
        return Err(WalletError::Policy(
            "WebAuthn extensions must be one CBOR map".into(),
        ));
    }
    Ok(())
}

fn validate_cose_es256(cose: &CoseKey) -> WalletResult<VerifyingKey> {
    if cose.kty != RegisteredLabel::Assigned(iana::KeyType::EC2)
        || cose.alg != Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256))
        || cose_param_i64(cose, -1) != Some(iana::EllipticCurve::P_256 as i64)
        || cose
            .params
            .iter()
            .any(|(label, _)| *label == Label::Int(-4))
    {
        return Err(WalletError::Policy(
            "WebAuthn credential must be a public P-256 ES256 key".into(),
        ));
    }
    if !cose.key_ops.is_empty()
        && !cose
            .key_ops
            .contains(&RegisteredLabel::Assigned(iana::KeyOperation::Verify))
    {
        return Err(WalletError::Policy(
            "WebAuthn credential key does not permit verification".into(),
        ));
    }
    let x = cose_param_bytes(cose, -2)
        .filter(|coordinate| coordinate.len() == 32)
        .ok_or_else(|| WalletError::Policy("COSE key has an invalid x coordinate".into()))?;
    let y = cose_param_bytes(cose, -3)
        .filter(|coordinate| coordinate.len() == 32)
        .ok_or_else(|| WalletError::Policy("COSE key has an invalid y coordinate".into()))?;
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(x);
    uncompressed.extend_from_slice(y);
    let point =
        EncodedPoint::from_bytes(&uncompressed).map_err(|e| WalletError::Policy(e.to_string()))?;
    VerifyingKey::from_encoded_point(&point)
        .map_err(|e| WalletError::Policy(format!("invalid WebAuthn P-256 key: {e}")))
}

fn verify_es256_signature(pk_b64: &str, signed: &[u8], signature: &[u8]) -> WalletResult<()> {
    let pk_bytes = decode_b64_limited(pk_b64, 2048, "stored COSE public key")?;
    let cose = CoseKey::from_slice(&pk_bytes)
        .map_err(|e| WalletError::Policy(format!("invalid stored WebAuthn COSE key: {e}")))?;
    let verifying_key = validate_cose_es256(&cose)?;
    let sig = Signature::from_der(signature)
        .map_err(|e| WalletError::Policy(format!("invalid WebAuthn ES256 signature: {e}")))?;
    verifying_key
        .verify(signed, &sig)
        .map_err(|e| WalletError::Policy(format!("WebAuthn signature invalid: {e}")))?;
    Ok(())
}

fn decode_b64_limited(value: &str, max_decoded: usize, field: &str) -> WalletResult<Vec<u8>> {
    let max_encoded = max_decoded.saturating_mul(4) / 3 + 4;
    if value.is_empty() || value.len() > max_encoded {
        return Err(WalletError::Policy(format!(
            "WebAuthn {field} has an invalid length"
        )));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| WalletError::Policy(format!("WebAuthn {field} is not base64url")))?;
    if bytes.is_empty() || bytes.len() > max_decoded {
        return Err(WalletError::Policy(format!(
            "WebAuthn {field} has an invalid length"
        )));
    }
    Ok(bytes)
}

fn cose_param_bytes(key: &CoseKey, label: i64) -> Option<&[u8]> {
    key.params
        .iter()
        .find(|(candidate, _)| *candidate == Label::Int(label))
        .and_then(|(_, value)| value.as_bytes().map(Vec::as_slice))
}

fn cose_param_i64(key: &CoseKey, label: i64) -> Option<i64> {
    key.params
        .iter()
        .find(|(candidate, _)| *candidate == Label::Int(label))
        .and_then(|(_, value)| match value {
            Value::Integer(value) => i64::try_from(*value).ok(),
            _ => None,
        })
}

fn load_stored_credential(stored_b64: &str) -> WalletResult<StoredCredential> {
    let bytes = decode_b64_limited(stored_b64, 16 * 1024, "stored credential")?;
    serde_json::from_slice(&bytes).map_err(|_| {
        WalletError::Policy(
            "stored WebAuthn credential is legacy, corrupt, or missing key material; re-register it"
                .into(),
        )
    })
}

fn encode_stored_credential(stored: &StoredCredential) -> WalletResult<String> {
    let raw = serde_json::to_vec(stored).map_err(|e| WalletError::Other(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn validate_stored_credential(stored: &StoredCredential) -> WalletResult<()> {
    if stored.version != STORED_CREDENTIAL_VERSION {
        return Err(WalletError::Policy(
            "legacy WebAuthn credential must be re-registered".into(),
        ));
    }
    decode_credential_id(&stored.credential_id_b64)?;
    let origin = canonical_web_origin(&stored.origin)?;
    if origin != stored.origin || origin_to_rp_id(&origin).as_deref() != Some(&stored.rp_id) {
        return Err(WalletError::Policy(
            "stored WebAuthn RP/origin binding is invalid".into(),
        ));
    }
    let public_key =
        decode_b64_limited(&stored.public_key_cose_b64, 2048, "stored COSE public key")?;
    let cose = CoseKey::from_slice(&public_key)
        .map_err(|e| WalletError::Policy(format!("invalid stored WebAuthn COSE key: {e}")))?;
    validate_cose_es256(&cose)?;
    Ok(())
}

fn advance_sign_count(stored: &mut StoredCredential, next: u32) -> WalletResult<()> {
    if (stored.sign_count != 0 || next != 0) && next <= stored.sign_count {
        return Err(WalletError::Policy(
            "WebAuthn signature counter did not increase; credential cloning is possible".into(),
        ));
    }
    stored.sign_count = next;
    Ok(())
}

fn random_challenge() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn random_bound_challenge(operation_digest: &[u8; 32]) -> String {
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes[..32]);
    bytes[32..].copy_from_slice(operation_digest);
    URL_SAFE_NO_PAD.encode(bytes)
}

impl WebAuthnGate {
    fn take_pending(&self, purpose: &str) -> WalletResult<CeremonyState> {
        let state = self
            .pending
            .lock()
            .map_err(lock_err)?
            .take()
            .ok_or_else(|| WalletError::Other("WebAuthn ceremony not started".into()))?;
        if state.purpose != purpose {
            return Err(WalletError::Other(
                "WebAuthn ceremony purpose mismatch".into(),
            ));
        }
        if state.started_at.elapsed() > CEREMONY_TTL {
            return Err(WalletError::Policy(
                "WebAuthn ceremony expired; start a new verification".into(),
            ));
        }
        Ok(state)
    }
}

fn lock_err<T>(e: std::sync::PoisonError<T>) -> WalletError {
    WalletError::Other(format!("lock poisoned: {e}"))
}

pub fn credential_id_from_store(stored_b64: &str) -> WalletResult<String> {
    let stored = load_stored_credential(stored_b64)?;
    validate_stored_credential(&stored)?;
    Ok(stored.credential_id_b64)
}

/// Stable digest of the immutable parts of a registered credential.
///
/// The signature counter is deliberately excluded so a successful assertion can
/// advance it without changing the vault's authenticated policy. Every field is
/// length-prefixed to avoid ambiguous concatenation.
pub fn credential_binding_sha256(stored_b64: &str) -> WalletResult<String> {
    let stored = load_stored_credential(stored_b64)?;
    validate_stored_credential(&stored)?;
    let credential_id = decode_credential_id(&stored.credential_id_b64)?;
    let public_key =
        decode_b64_limited(&stored.public_key_cose_b64, 2048, "stored COSE public key")?;

    let mut digest = Sha256::new();
    digest.update(b"hacash-wallet-webauthn-binding-v1");
    hash_binding_field(&mut digest, &credential_id)?;
    hash_binding_field(&mut digest, &public_key)?;
    hash_binding_field(&mut digest, stored.rp_id.as_bytes())?;
    hash_binding_field(&mut digest, stored.origin.as_bytes())?;
    Ok(hex::encode(digest.finalize()))
}

fn hash_binding_field(digest: &mut Sha256, value: &[u8]) -> WalletResult<()> {
    let len = u32::try_from(value.len())
        .map_err(|_| WalletError::Policy("WebAuthn binding field is too large".into()))?;
    digest.update(len.to_be_bytes());
    digest.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_url_safe() {
        let challenge = random_challenge();
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert_eq!(challenge.len(), 43);
    }

    #[test]
    fn prepared_challenge_is_fresh_and_contains_exact_operation_digest() {
        let digest = [0x5au8; 32];
        let first = URL_SAFE_NO_PAD
            .decode(random_bound_challenge(&digest))
            .unwrap();
        let second = URL_SAFE_NO_PAD
            .decode(random_bound_challenge(&digest))
            .unwrap();
        assert_eq!(&first[32..], digest.as_slice());
        assert_eq!(&second[32..], digest.as_slice());
        assert_ne!(&first[..32], &second[..32]);
    }

    #[test]
    fn expired_ceremony_is_rejected() {
        let gate = WebAuthnGate::new().unwrap();
        gate.begin_register("1TestAddr", None).unwrap();
        gate.pending.lock().unwrap().as_mut().unwrap().started_at =
            Instant::now() - CEREMONY_TTL - Duration::from_secs(1);
        let error = gate.finish_register("{}").unwrap_err().to_string();
        assert!(error.contains("expired"), "unexpected error: {error}");
    }
}
