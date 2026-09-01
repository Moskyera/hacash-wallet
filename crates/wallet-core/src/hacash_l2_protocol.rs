//! Read-only compatibility probe for the standalone Hacash L2 protocol.
//!
//! This is separate from `l2_hub`, which implements HPAY's legacy Wallet Hub
//! API v4. No payment or signing method is exposed here.

use crate::error::{WalletError, WalletResult};
use crate::hacash_l2_identity::fetch_verified_provider_identity;
pub use crate::hacash_l2_identity::{
    HacashL2ProviderIdentity, HacashL2ProviderPinStatus, provider_identity_fingerprint,
    provider_identity_matches, validate_provider_identity,
};
use crate::settings::validate_service_url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HACASH_AGENT_PAY_PROTOCOL: &str = "hacash-agent-pay/1";
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const REQUIRED_AGENT_ENDPOINTS: [(&str, &str, &str); 7] = [
    ("manifest", "GET", "/v1/agent/v1/manifest"),
    ("quote", "POST", "/v1/agent/v1/quote"),
    ("pay", "POST", "/v1/agent/v1/pay"),
    ("sign", "POST", "/v1/agent/v1/sign"),
    ("status", "GET", "/v1/agent/v1/payment/{id}"),
    ("inbox", "GET", "/v1/agent/v1/inbox?address={addr}"),
    ("receipt", "GET", "/v1/agent/v1/receipt/{id}"),
];

// Local HPAY build facts. A remote manifest can never turn these on.
const UNILATERAL_L1_EXIT_VERIFIED: bool = false;
const INDEPENDENT_PROTOCOL_AUDIT_COMPLETE: bool = false;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HacashL2ReadinessBlocker {
    ProtocolMismatch,
    ManifestOriginMismatch,
    ProviderIdentityMissing,
    ProviderIdentityUnverified,
    ProviderIdentityUnpinned,
    ProviderIdentityChanged,
    RequiredEndpointMissing,
    SigningContractMismatch,
    UnilateralL1ExitUnverified,
    IndependentProtocolAuditRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HacashL2ProtocolProbe {
    pub protocol: String,
    pub version: String,
    pub provider_id: String,
    pub base_url: String,
    /// Safe for manifest/quote/status reads only; never authorizes signing.
    pub read_only_compatible: bool,
    pub mainnet_spending_ready: bool,
    pub finality: String,
    pub provider_pin_status: HacashL2ProviderPinStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_identity: Option<HacashL2ProviderIdentity>,
    pub blockers: Vec<HacashL2ReadinessBlocker>,
}

#[derive(Debug, Deserialize)]
struct AgentManifest {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    provider_id: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    endpoints: BTreeMap<String, ManifestEndpoint>,
    #[serde(default)]
    signing: ManifestSigning,
}

#[derive(Debug, Default, Deserialize)]
struct ManifestEndpoint {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
}

#[derive(Debug, Default, Deserialize)]
struct ManifestSigning {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    curve: String,
    #[serde(default)]
    wire: String,
    #[serde(default)]
    order: String,
}

/// Typed HAP client with no mutation or signing surface.
pub struct HacashL2ProtocolClient {
    base_url: String,
    http: reqwest::Client,
}

impl HacashL2ProtocolClient {
    pub fn new(base_url: &str) -> WalletResult<Self> {
        let base_url = validate_service_url(base_url, "Hacash L2 hub")?;
        let http = crate::http_client::shared_http_client()
            .cloned()
            .map_err(WalletError::L2)?;
        Ok(Self { base_url, http })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn probe_agent_protocol(&self) -> WalletResult<HacashL2ProtocolProbe> {
        self.probe_agent_protocol_with_pin(None).await
    }

    pub async fn probe_agent_protocol_with_pin(
        &self,
        expected_provider: Option<&HacashL2ProviderIdentity>,
    ) -> WalletResult<HacashL2ProtocolProbe> {
        let response = self
            .http
            .get(format!("{}/v1/agent/v1/manifest", self.base_url))
            .send()
            .await
            .map_err(|e| WalletError::L2(format!("Hacash L2 hub unreachable: {e}")))?;
        if !response.status().is_success() {
            return Err(WalletError::L2(format!(
                "Hacash L2 manifest returned HTTP {}",
                response.status()
            )));
        }
        let manifest = read_manifest_bounded(response).await?;
        let mut probe = classify_manifest(&self.base_url, manifest);
        if !probe.read_only_compatible {
            return Ok(probe);
        }
        let identity =
            fetch_verified_provider_identity(&self.http, &self.base_url, &probe.provider_id).await;
        attach_provider_identity(&mut probe, identity, expected_provider);
        Ok(probe)
    }
}

async fn read_manifest_bounded(mut response: reqwest::Response) -> WalletResult<AgentManifest> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MANIFEST_BYTES as u64)
    {
        return Err(WalletError::L2(
            "Hacash L2 manifest exceeds the response limit".into(),
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| WalletError::L2(format!("invalid Hacash L2 response: {error}")))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_MANIFEST_BYTES {
            return Err(WalletError::L2(
                "Hacash L2 manifest exceeds the response limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|error| WalletError::L2(format!("invalid Hacash L2 manifest: {error}")))
}

fn classify_manifest(configured_base: &str, manifest: AgentManifest) -> HacashL2ProtocolProbe {
    let mut blockers = Vec::new();
    if manifest.protocol != HACASH_AGENT_PAY_PROTOCOL {
        blockers.push(HacashL2ReadinessBlocker::ProtocolMismatch);
    }
    let manifest_base =
        validate_service_url(&manifest.base_url, "Hacash L2 manifest base").unwrap_or_default();
    if manifest_base != configured_base {
        blockers.push(HacashL2ReadinessBlocker::ManifestOriginMismatch);
    }
    if manifest.provider_id.trim().is_empty() || manifest.provider_id.len() > 128 {
        blockers.push(HacashL2ReadinessBlocker::ProviderIdentityMissing);
    }
    blockers.push(HacashL2ReadinessBlocker::ProviderIdentityUnverified);
    if REQUIRED_AGENT_ENDPOINTS.iter().any(|(name, method, path)| {
        manifest.endpoints.get(*name).is_none_or(|endpoint| {
            !endpoint.method.eq_ignore_ascii_case(method) || endpoint.path != *path
        })
    }) {
        blockers.push(HacashL2ReadinessBlocker::RequiredEndpointMissing);
    }
    let signing = &manifest.signing;
    if !signing.hash.eq_ignore_ascii_case("sha3-256")
        || !signing.curve.eq_ignore_ascii_case("secp256k1")
        || !signing.wire.starts_with("97-byte hex Sign")
        || signing.order != "payee first, then path intermediates, payer last"
    {
        blockers.push(HacashL2ReadinessBlocker::SigningContractMismatch);
    }
    if !UNILATERAL_L1_EXIT_VERIFIED {
        blockers.push(HacashL2ReadinessBlocker::UnilateralL1ExitUnverified);
    }
    if !INDEPENDENT_PROTOCOL_AUDIT_COMPLETE {
        blockers.push(HacashL2ReadinessBlocker::IndependentProtocolAuditRequired);
    }
    let read_only_compatible = !blockers.iter().any(|blocker| {
        matches!(
            blocker,
            HacashL2ReadinessBlocker::ProtocolMismatch
                | HacashL2ReadinessBlocker::ManifestOriginMismatch
                | HacashL2ReadinessBlocker::ProviderIdentityMissing
                | HacashL2ReadinessBlocker::RequiredEndpointMissing
                | HacashL2ReadinessBlocker::SigningContractMismatch
        )
    });
    HacashL2ProtocolProbe {
        protocol: manifest.protocol,
        version: manifest.version,
        provider_id: manifest.provider_id,
        base_url: manifest_base,
        read_only_compatible,
        mainnet_spending_ready: blockers.is_empty(),
        finality: "hub_coordinated_not_l1".into(),
        provider_pin_status: HacashL2ProviderPinStatus::Unverified,
        provider_identity: None,
        blockers,
    }
}

fn attach_provider_identity(
    probe: &mut HacashL2ProtocolProbe,
    identity: WalletResult<HacashL2ProviderIdentity>,
    expected: Option<&HacashL2ProviderIdentity>,
) {
    let Ok(identity) = identity else {
        return;
    };
    probe
        .blockers
        .retain(|item| *item != HacashL2ReadinessBlocker::ProviderIdentityUnverified);
    match expected {
        None => {
            probe.provider_pin_status = HacashL2ProviderPinStatus::Unpinned;
            probe
                .blockers
                .push(HacashL2ReadinessBlocker::ProviderIdentityUnpinned);
        }
        Some(pin) if provider_identity_matches(pin, &identity) => {
            probe.provider_pin_status = HacashL2ProviderPinStatus::Matched;
        }
        Some(_) => {
            probe.provider_pin_status = HacashL2ProviderPinStatus::Mismatch;
            probe
                .blockers
                .push(HacashL2ReadinessBlocker::ProviderIdentityChanged);
        }
    }
    probe.provider_identity = Some(identity);
    probe.mainnet_spending_ready = probe.blockers.is_empty();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest(base_url: &str) -> AgentManifest {
        let endpoints = REQUIRED_AGENT_ENDPOINTS
            .into_iter()
            .map(|(name, method, path)| {
                (
                    name.into(),
                    ManifestEndpoint {
                        method: method.into(),
                        path: path.into(),
                    },
                )
            })
            .collect();
        AgentManifest {
            protocol: HACASH_AGENT_PAY_PROTOCOL.into(),
            version: "0.2.0".into(),
            provider_id: "verified-later".into(),
            base_url: base_url.into(),
            endpoints,
            signing: ManifestSigning {
                hash: "sha3-256".into(),
                curve: "secp256k1".into(),
                wire: "97-byte hex Sign = compressed_pubkey[33] || ecdsa_sig[64]".into(),
                order: "payee first, then path intermediates, payer last".into(),
            },
        }
    }

    #[test]
    fn compatible_manifest_is_read_only_but_never_mainnet_ready() {
        let probe = classify_manifest("https://hub.example", valid_manifest("https://hub.example"));
        assert!(probe.read_only_compatible);
        assert!(!probe.mainnet_spending_ready);
        assert_eq!(probe.finality, "hub_coordinated_not_l1");
        assert!(
            probe
                .blockers
                .contains(&HacashL2ReadinessBlocker::ProviderIdentityUnverified)
        );
        assert!(
            probe
                .blockers
                .contains(&HacashL2ReadinessBlocker::UnilateralL1ExitUnverified)
        );
    }

    #[test]
    fn manifest_cannot_redirect_trust_to_another_origin() {
        let probe = classify_manifest(
            "https://hub.example",
            valid_manifest("https://evil.example"),
        );
        assert!(!probe.read_only_compatible);
        assert!(
            probe
                .blockers
                .contains(&HacashL2ReadinessBlocker::ManifestOriginMismatch)
        );
    }

    #[test]
    fn protocol_and_signing_downgrades_fail_closed() {
        let mut manifest = valid_manifest("https://hub.example");
        manifest.protocol = "hacash-agent-pay/0".into();
        manifest.signing.hash = "sha256".into();
        let probe = classify_manifest("https://hub.example", manifest);
        assert!(!probe.read_only_compatible);
        assert!(
            probe
                .blockers
                .contains(&HacashL2ReadinessBlocker::ProtocolMismatch)
        );
        assert!(
            probe
                .blockers
                .contains(&HacashL2ReadinessBlocker::SigningContractMismatch)
        );
    }

    #[test]
    fn verified_identity_requires_an_explicit_pin_and_rejects_rotation() {
        let identity = HacashL2ProviderIdentity {
            provider_id: "HubA".into(),
            base_url: "https://hub.example".into(),
            mesh_protocol_version: "2.0".into(),
            identity_address: "1ProviderAddress".into(),
            identity_pubkey_hex: format!("02{}", "11".repeat(32)),
            fingerprint_sha3_hex: "22".repeat(32),
            verified_at_unix: 1_000,
        };
        let mut first_contact =
            classify_manifest("https://hub.example", valid_manifest("https://hub.example"));
        attach_provider_identity(&mut first_contact, Ok(identity.clone()), None);
        assert_eq!(
            first_contact.provider_pin_status,
            HacashL2ProviderPinStatus::Unpinned
        );
        assert!(
            first_contact
                .blockers
                .contains(&HacashL2ReadinessBlocker::ProviderIdentityUnpinned)
        );

        let mut matched =
            classify_manifest("https://hub.example", valid_manifest("https://hub.example"));
        attach_provider_identity(&mut matched, Ok(identity.clone()), Some(&identity));
        assert_eq!(
            matched.provider_pin_status,
            HacashL2ProviderPinStatus::Matched
        );
        assert!(
            !matched
                .blockers
                .contains(&HacashL2ReadinessBlocker::ProviderIdentityUnverified)
        );

        let mut rotated = identity.clone();
        rotated.identity_pubkey_hex = format!("03{}", "33".repeat(32));
        rotated.fingerprint_sha3_hex = "44".repeat(32);
        let mut mismatch =
            classify_manifest("https://hub.example", valid_manifest("https://hub.example"));
        attach_provider_identity(&mut mismatch, Ok(rotated), Some(&identity));
        assert_eq!(
            mismatch.provider_pin_status,
            HacashL2ProviderPinStatus::Mismatch
        );
        assert!(
            mismatch
                .blockers
                .contains(&HacashL2ReadinessBlocker::ProviderIdentityChanged)
        );
    }

    #[tokio::test]
    async fn manifest_reader_stops_before_an_unbounded_body_is_buffered() {
        use axum::Router;
        use axum::routing::get;

        let app = Router::new().route(
            "/v1/agent/v1/manifest",
            get(|| async { "x".repeat(MAX_MANIFEST_BYTES + 1) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HAP test server");
        let address = listener.local_addr().expect("HAP test address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve HAP test");
        });
        let client =
            HacashL2ProtocolClient::new(&format!("http://{address}")).expect("local HAP client");
        let error = client
            .probe_agent_protocol()
            .await
            .expect_err("oversized manifest must fail");
        assert!(error.to_string().contains("response limit"));
        server.abort();
    }

    #[test]
    fn public_hubs_require_https_but_local_development_may_use_http() {
        assert!(HacashL2ProtocolClient::new("http://hub.example").is_err());
        assert!(HacashL2ProtocolClient::new("https://hub.example").is_ok());
        assert!(HacashL2ProtocolClient::new("http://127.0.0.1:9090").is_ok());
    }
}
