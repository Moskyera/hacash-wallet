//! Fast Pay transport boundaries.
//!
//! The current Wallet Hub API v4 is a custom HPAY HTTP/JSON protocol. This
//! adapter gives that implementation an explicit name without changing its
//! behavior or presenting it as the official Hacash ChannelPay protocol.

use std::ops::Deref;

use crate::l2_hub::L2HubClient;

/// Truthful UI/configuration label for the existing custom transport.
pub const LEGACY_HTTP_FAST_PAY_LABEL: &str = "Legacy Wallet Hub API v4";

/// Behavior-preserving adapter around the existing custom HTTP Fast Pay client.
///
/// Official ChannelPay uses a different binary WebSocket protocol and will be
/// implemented by a separate `OfficialChannelPayClient`. It must never be
/// hidden behind this adapter or selected as an automatic post-sign fallback.
pub struct LegacyHttpFastPayAdapter {
    client: L2HubClient,
}

impl LegacyHttpFastPayAdapter {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: L2HubClient::new(base_url),
        }
    }

    pub fn client(&self) -> &L2HubClient {
        &self.client
    }

    pub fn into_client(self) -> L2HubClient {
        self.client
    }
}

impl Deref for LegacyHttpFastPayAdapter {
    type Target = L2HubClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl From<L2HubClient> for LegacyHttpFastPayAdapter {
    fn from(client: L2HubClient) -> Self {
        Self { client }
    }
}

impl From<LegacyHttpFastPayAdapter> for L2HubClient {
    fn from(adapter: LegacyHttpFastPayAdapter) -> Self {
        adapter.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_adapter_preserves_existing_client_surface() {
        let adapter = LegacyHttpFastPayAdapter::new("http://127.0.0.1:8790/");
        let _: &L2HubClient = adapter.client();
        let _: &L2HubClient = &adapter;
    }

    #[test]
    fn legacy_label_does_not_claim_official_channelpay() {
        assert_eq!(LEGACY_HTTP_FAST_PAY_LABEL, "Legacy Wallet Hub API v4");
        assert!(!LEGACY_HTTP_FAST_PAY_LABEL.contains("ChannelPay"));
    }
}
