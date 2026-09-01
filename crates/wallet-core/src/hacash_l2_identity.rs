//! Cryptographic verification for the public Hacash L2 hub identity.
//! A manifest provider_id is only a label. Trust comes from a fresh signed
//! HACASH_L2_HELLO_V1 and an owner-approved pin in authenticated Agent state.

use crate::error::{WalletError, WalletResult};
use crate::settings::validate_service_url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SELF_HELLO_BYTES: usize = 512 * 1024;
const MAX_HELLO_CHANNELS: usize = 4_096;
const HELLO_MAX_AGE_SECONDS: u64 = 600;
const HELLO_MAX_FUTURE_SKEW_SECONDS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HacashL2ProviderPinStatus {
    Unverified,
    Unpinned,
    Matched,
    Mismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HacashL2ProviderIdentity {
    pub provider_id: String,
    pub base_url: String,
    pub mesh_protocol_version: String,
    pub identity_address: String,
    pub identity_pubkey_hex: String,
    pub fingerprint_sha3_hex: String,
    pub verified_at_unix: u64,
}

#[derive(Debug, Deserialize)]
struct SelfHelloEnvelope {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    signed: bool,
    hello: PeerHello,
}

#[derive(Debug, Default, Deserialize)]
struct PeerHello {
    #[serde(default)]
    provider_id: String,
    #[serde(default)]
    public_url: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    channels: Vec<AdvertisedChannel>,
    #[serde(default)]
    meta: HubMeta,
    #[serde(default)]
    timestamp_unix: u64,
    #[serde(default)]
    identity_pubkey_hex: String,
    #[serde(default)]
    identity_address: String,
    #[serde(default)]
    signature_hex: String,
}

#[derive(Debug, Default, Deserialize)]
struct HubMeta {
    #[serde(default)]
    protocol_version: String,
    #[serde(default)]
    fee_base_mei: u64,
    #[serde(default)]
    fee_ppm: u64,
    #[serde(default)]
    total_capacity_mei: u64,
    #[serde(default)]
    identity_address: String,
    #[serde(default)]
    identity_pubkey_hex: String,
}

#[derive(Debug, Deserialize)]
struct AdvertisedChannel {
    channel_id: String,
    left_address: String,
    right_address: String,
    via_provider: String,
    #[serde(default)]
    capacity_mei: u64,
    #[serde(default)]
    left_available_mei: u64,
    #[serde(default)]
    right_available_mei: u64,
    #[serde(default)]
    capacity_zhu: u64,
    #[serde(default)]
    left_available_zhu: u64,
    #[serde(default)]
    right_available_zhu: u64,
    #[serde(default)]
    fee_ppm: u64,
}

pub(crate) async fn fetch_verified_provider_identity(
    http: &reqwest::Client,
    configured_base: &str,
    manifest_provider_id: &str,
) -> WalletResult<HacashL2ProviderIdentity> {
    let response = http
        .get(format!("{configured_base}/v1/net/self"))
        .send()
        .await
        .map_err(|error| WalletError::L2(format!("Hacash L2 identity unavailable: {error}")))?;
    if !response.status().is_success() {
        return Err(WalletError::L2(format!(
            "Hacash L2 identity returned HTTP {}",
            response.status()
        )));
    }
    let envelope: SelfHelloEnvelope =
        read_json_bounded(response, MAX_SELF_HELLO_BYTES, "identity").await?;
    verify_self_hello(configured_base, manifest_provider_id, envelope, now_unix())
}

pub fn validate_provider_identity(identity: &HacashL2ProviderIdentity) -> bool {
    if !valid_provider_id(&identity.provider_id)
        || !identity.mesh_protocol_version.starts_with("2.")
        || identity.verified_at_unix == 0
        || validate_service_url(&identity.base_url, "Hacash L2 provider pin")
            .ok()
            .as_deref()
            != Some(identity.base_url.as_str())
    {
        return false;
    }
    let Ok(public_key) =
        decode_fixed_hex::<33>(&identity.identity_pubkey_hex, "identity public key")
    else {
        return false;
    };
    if !matches!(public_key[0], 0x02 | 0x03)
        || sys::Account::to_readable(&sys::Account::get_address_by_public_key(public_key))
            != identity.identity_address
    {
        return false;
    }
    provider_identity_fingerprint(
        &identity.provider_id,
        &identity.base_url,
        &identity.identity_address,
        &identity.identity_pubkey_hex.to_ascii_lowercase(),
    )
    .eq_ignore_ascii_case(&identity.fingerprint_sha3_hex)
}
pub fn provider_identity_matches(
    expected: &HacashL2ProviderIdentity,
    observed: &HacashL2ProviderIdentity,
) -> bool {
    expected.provider_id == observed.provider_id
        && expected.base_url == observed.base_url
        && expected.identity_address == observed.identity_address
        && expected
            .identity_pubkey_hex
            .eq_ignore_ascii_case(&observed.identity_pubkey_hex)
        && expected
            .fingerprint_sha3_hex
            .eq_ignore_ascii_case(&observed.fingerprint_sha3_hex)
}

fn verify_self_hello(
    configured_base: &str,
    manifest_provider_id: &str,
    envelope: SelfHelloEnvelope,
    now: u64,
) -> WalletResult<HacashL2ProviderIdentity> {
    if !envelope.ok || !envelope.signed || envelope.hello.signature_hex.trim().is_empty() {
        return Err(WalletError::L2(
            "Hacash L2 provider did not return a signed identity".into(),
        ));
    }
    let hello = envelope.hello;
    if hello.provider_id != manifest_provider_id
        || !valid_provider_id(&hello.provider_id)
        || hello.name.len() > 256
        || hello.name.chars().any(char::is_control)
    {
        return Err(WalletError::L2(
            "Hacash L2 provider identity does not match the manifest".into(),
        ));
    }
    let hello_base = validate_service_url(&hello.public_url, "Hacash L2 identity URL")?;
    if hello_base != configured_base {
        return Err(WalletError::L2(
            "Hacash L2 signed identity does not match the configured origin".into(),
        ));
    }
    // Protocol 1.x did not bind complete channel advertisements.
    if !hello.meta.protocol_version.starts_with("2.") {
        return Err(WalletError::L2(
            "Hacash L2 signed identity requires mesh protocol 2.x".into(),
        ));
    }
    if hello.timestamp_unix == 0
        || hello.timestamp_unix > now.saturating_add(HELLO_MAX_FUTURE_SKEW_SECONDS)
        || now.saturating_sub(hello.timestamp_unix) > HELLO_MAX_AGE_SECONDS
    {
        return Err(WalletError::L2(
            "Hacash L2 signed identity is expired or outside the clock-skew limit".into(),
        ));
    }
    if hello.channels.len() > MAX_HELLO_CHANNELS {
        return Err(WalletError::L2(
            "Hacash L2 identity advertises too many channels".into(),
        ));
    }

    let identity_address =
        exact_address_field(&hello.identity_address, &hello.meta.identity_address)?;
    let identity_pubkey_hex = exact_hex_field(
        &hello.identity_pubkey_hex,
        &hello.meta.identity_pubkey_hex,
        "public key",
    )?
    .to_ascii_lowercase();
    let public_key = decode_fixed_hex::<33>(&identity_pubkey_hex, "identity public key")?;
    if !matches!(public_key[0], 0x02 | 0x03) {
        return Err(WalletError::L2(
            "Hacash L2 identity public key is not compressed secp256k1".into(),
        ));
    }
    let derived_address =
        sys::Account::to_readable(&sys::Account::get_address_by_public_key(public_key));
    if derived_address != identity_address {
        return Err(WalletError::L2(
            "Hacash L2 identity address does not match its public key".into(),
        ));
    }

    let channel_ids = validate_and_sort_channel_ids(&hello.channels)?;
    let channel_ads_hash = channel_ads_hash_hex(&hello.channels);
    let canonical = hello_canonical_message(
        &hello,
        &identity_address,
        &channel_ids.join(","),
        &channel_ads_hash,
    );
    let digest = sys::sha3(canonical.as_bytes());
    let signature = decode_hello_signature(&hello.signature_hex, &public_key)?;
    if !sys::Account::verify_signature(&digest, &public_key, &signature) {
        return Err(WalletError::L2(
            "Hacash L2 provider identity signature is invalid".into(),
        ));
    }

    Ok(HacashL2ProviderIdentity {
        provider_id: hello.provider_id.clone(),
        base_url: configured_base.into(),
        mesh_protocol_version: hello.meta.protocol_version.clone(),
        identity_address: identity_address.clone(),
        identity_pubkey_hex: identity_pubkey_hex.clone(),
        fingerprint_sha3_hex: provider_identity_fingerprint(
            &hello.provider_id,
            configured_base,
            &identity_address,
            &identity_pubkey_hex,
        ),
        verified_at_unix: now,
    })
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.trim() == value
        && !value.contains(' ')
        && !value.contains('_')
        && !value.chars().any(char::is_control)
}

fn exact_address_field(top: &str, meta: &str) -> WalletResult<String> {
    let top = top.trim();
    let meta = meta.trim();
    if top.is_empty() && meta.is_empty() {
        return Err(WalletError::L2(
            "Hacash L2 identity address is missing".into(),
        ));
    }
    if !top.is_empty() && !meta.is_empty() && top != meta {
        return Err(WalletError::L2(
            "Hacash L2 identity address fields disagree".into(),
        ));
    }
    Ok(if top.is_empty() { meta } else { top }.to_owned())
}

fn exact_hex_field(top: &str, meta: &str, label: &str) -> WalletResult<String> {
    let top = top.trim();
    let meta = meta.trim();
    if top.is_empty() && meta.is_empty() {
        return Err(WalletError::L2(format!(
            "Hacash L2 identity {label} is missing"
        )));
    }
    if !top.is_empty() && !meta.is_empty() && !top.eq_ignore_ascii_case(meta) {
        return Err(WalletError::L2(format!(
            "Hacash L2 identity {label} fields disagree"
        )));
    }
    Ok(if top.is_empty() { meta } else { top }.to_owned())
}

fn validate_and_sort_channel_ids(channels: &[AdvertisedChannel]) -> WalletResult<Vec<String>> {
    let mut unique = BTreeSet::new();
    for channel in channels {
        if channel.channel_id.len() != 32
            || !channel
                .channel_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || channel.left_address.len() > 128
            || channel.right_address.len() > 128
            || channel.via_provider.len() > 128
            || !unique.insert(channel.channel_id.clone())
        {
            return Err(WalletError::L2(
                "Hacash L2 identity contains invalid channel advertisements".into(),
            ));
        }
    }
    Ok(unique.into_iter().collect())
}

fn hello_canonical_message(
    hello: &PeerHello,
    identity_address: &str,
    channel_ids: &str,
    channel_ads_hash_hex: &str,
) -> String {
    format!(
        "HACASH_L2_HELLO_V1\nprovider_id={}\npublic_url={}\nname={}\ntimestamp_unix={}\nprotocol_version={}\nidentity_address={}\nchannel_ids={}\nfee_base_mei={}\nfee_ppm={}\ntotal_capacity_mei={}\nchannel_ads_hash_hex={}\n",
        hello.provider_id,
        hello.public_url,
        hello.name,
        hello.timestamp_unix,
        hello.meta.protocol_version,
        identity_address,
        channel_ids,
        hello.meta.fee_base_mei,
        hello.meta.fee_ppm,
        hello.meta.total_capacity_mei,
        channel_ads_hash_hex,
    )
}

fn channel_ads_hash_hex(channels: &[AdvertisedChannel]) -> String {
    let mut ordered: Vec<_> = channels.iter().collect();
    ordered.sort_by(|a, b| {
        (
            &a.channel_id,
            &a.left_address,
            &a.right_address,
            &a.via_provider,
            a.capacity_mei,
            a.left_available_mei,
            a.right_available_mei,
            a.capacity_zhu,
            a.left_available_zhu,
            a.right_available_zhu,
            a.fee_ppm,
        )
            .cmp(&(
                &b.channel_id,
                &b.left_address,
                &b.right_address,
                &b.via_provider,
                b.capacity_mei,
                b.left_available_mei,
                b.right_available_mei,
                b.capacity_zhu,
                b.left_available_zhu,
                b.right_available_zhu,
                b.fee_ppm,
            ))
    });
    let mut bytes = Vec::with_capacity(32 + ordered.len() * 160);
    bytes.extend_from_slice(b"HACASH_L2_CHANNEL_ADS_V2\0");
    bytes.extend_from_slice(&(ordered.len() as u64).to_be_bytes());
    for channel in ordered {
        for value in [
            &channel.channel_id,
            &channel.left_address,
            &channel.right_address,
            &channel.via_provider,
        ] {
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        for value in [
            channel.capacity_mei,
            channel.left_available_mei,
            channel.right_available_mei,
            channel.capacity_zhu,
            channel.left_available_zhu,
            channel.right_available_zhu,
            channel.fee_ppm,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    hex::encode(sys::sha3(bytes))
}

fn decode_hello_signature(value: &str, public_key: &[u8; 33]) -> WalletResult<[u8; 64]> {
    let raw = hex::decode(value.trim())
        .map_err(|_| WalletError::L2("Hacash L2 identity signature is not hex".into()))?;
    let signature = match raw.len() {
        64 => raw.as_slice(),
        97 if raw[..33] == public_key[..] => &raw[33..],
        97 => {
            return Err(WalletError::L2(
                "Hacash L2 identity signature embeds another public key".into(),
            ));
        }
        _ => {
            return Err(WalletError::L2(
                "Hacash L2 identity signature has an invalid wire length".into(),
            ));
        }
    };
    signature
        .try_into()
        .map_err(|_| WalletError::L2("Hacash L2 identity signature is invalid".into()))
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> WalletResult<[u8; N]> {
    let bytes =
        hex::decode(value).map_err(|_| WalletError::L2(format!("Hacash L2 {label} is not hex")))?;
    bytes
        .try_into()
        .map_err(|_| WalletError::L2(format!("Hacash L2 {label} has an invalid length")))
}

pub fn provider_identity_fingerprint(
    provider_id: &str,
    base_url: &str,
    address: &str,
    pubkey: &str,
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"HPAY_HACASH_L2_PROVIDER_PIN_V1\0");
    for value in [provider_id, base_url, address, pubkey] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    hex::encode(sys::sha3(bytes))
}

async fn read_json_bounded<T: for<'de> Deserialize<'de>>(
    mut response: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> WalletResult<T> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(WalletError::L2(format!(
            "Hacash L2 {label} exceeds the response limit"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| WalletError::L2(format!("invalid Hacash L2 response: {error}")))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(WalletError::L2(format!(
                "Hacash L2 {label} exceeds the response limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|error| WalletError::L2(format!("invalid Hacash L2 {label}: {error}")))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_envelope(
        account: &sys::Account,
        base_url: &str,
        provider_id: &str,
        now: u64,
    ) -> SelfHelloEnvelope {
        let pubkey = account.public_key().serialize_compressed();
        let address = account.readable().to_owned();
        let mut hello = PeerHello {
            provider_id: provider_id.into(),
            public_url: base_url.into(),
            name: "Test provider".into(),
            channels: vec![],
            meta: HubMeta {
                protocol_version: "2.0".into(),
                identity_address: address.clone(),
                identity_pubkey_hex: hex::encode(pubkey),
                ..Default::default()
            },
            timestamp_unix: now,
            identity_pubkey_hex: hex::encode(pubkey),
            identity_address: address,
            signature_hex: String::new(),
        };
        let digest = sys::sha3(
            hello_canonical_message(
                &hello,
                &hello.identity_address,
                "",
                &channel_ads_hash_hex(&hello.channels),
            )
            .as_bytes(),
        );
        let mut sign = Vec::from(pubkey);
        sign.extend_from_slice(&account.do_sign(&digest));
        hello.signature_hex = hex::encode(sign);
        SelfHelloEnvelope {
            ok: true,
            signed: true,
            hello,
        }
    }

    #[test]
    fn signed_hello_verifies_and_produces_a_stable_pin() {
        let account = sys::Account::create_by_secret_key_value([7; 32]).unwrap();
        let first = verify_self_hello(
            "https://hub.example",
            "HubA",
            signed_envelope(&account, "https://hub.example", "HubA", 1_000),
            1_001,
        )
        .unwrap();
        let second = verify_self_hello(
            "https://hub.example",
            "HubA",
            signed_envelope(&account, "https://hub.example", "HubA", 1_005),
            1_006,
        )
        .unwrap();
        assert!(provider_identity_matches(&first, &second));
        assert_eq!(first.fingerprint_sha3_hex.len(), 64);
    }

    #[test]
    fn stale_origin_mismatch_and_key_substitution_fail_closed() {
        let account = sys::Account::create_by_secret_key_value([8; 32]).unwrap();
        let stale = signed_envelope(&account, "https://hub.example", "HubA", 1_000);
        assert!(
            verify_self_hello("https://hub.example", "HubA", stale, 1_601)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );

        let wrong_origin = signed_envelope(&account, "https://other.example", "HubA", 2_000);
        assert!(
            verify_self_hello("https://hub.example", "HubA", wrong_origin, 2_001)
                .unwrap_err()
                .to_string()
                .contains("origin")
        );

        let other = sys::Account::create_by_secret_key_value([9; 32]).unwrap();
        let mut substituted = signed_envelope(&account, "https://hub.example", "HubA", 3_000);
        substituted.hello.identity_pubkey_hex =
            hex::encode(other.public_key().serialize_compressed());
        substituted.hello.meta.identity_pubkey_hex = substituted.hello.identity_pubkey_hex.clone();
        assert!(
            verify_self_hello("https://hub.example", "HubA", substituted, 3_001)
                .unwrap_err()
                .to_string()
                .contains("address")
        );
    }

    #[test]
    fn identity_rotation_never_matches_the_existing_pin() {
        let first_account = sys::Account::create_by_secret_key_value([10; 32]).unwrap();
        let second_account = sys::Account::create_by_secret_key_value([11; 32]).unwrap();
        let first = verify_self_hello(
            "https://hub.example",
            "HubA",
            signed_envelope(&first_account, "https://hub.example", "HubA", 4_000),
            4_001,
        )
        .unwrap();
        let rotated = verify_self_hello(
            "https://hub.example",
            "HubA",
            signed_envelope(&second_account, "https://hub.example", "HubA", 4_002),
            4_003,
        )
        .unwrap();
        assert!(!provider_identity_matches(&first, &rotated));
    }
}
