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
    // No `new(base_url)` constructor, deliberately. It built its client with
    // `L2HubClient::new`, which hard-wires testnet and the trustless-only
    // policy: every mainnet gate in that client sits behind `if self.mainnet`,
    // so an adapter built that way and pointed at a mainnet Hub would have
    // walked past all of them. It had no callers, which is the only reason it
    // was not a second door - and a door with no lock and no traffic is still a
    // door. Wrap a client someone else built with the wallet owner's policy:
    // `LegacyHttpFastPayAdapter::from(L2HubClient::new_for_wallet_policy(..))`.

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

    /// The adapter can only ever wrap a client someone else built, and the
    /// only constructors that exist take the wallet owner's network and
    /// consent. There is no way to reach a mainnet Hub through this type with
    /// the mainnet gates switched off.
    #[test]
    fn legacy_adapter_preserves_existing_client_surface() {
        let adapter = LegacyHttpFastPayAdapter::from(L2HubClient::new_for_wallet_policy(
            "http://127.0.0.1:8790/",
            "testnet",
            false,
        ));
        let _: &L2HubClient = adapter.client();
        let _: &L2HubClient = &adapter;
    }

    #[test]
    fn legacy_label_does_not_claim_official_channelpay() {
        assert_eq!(LEGACY_HTTP_FAST_PAY_LABEL, "Legacy Wallet Hub API v4");
        assert!(!LEGACY_HTTP_FAST_PAY_LABEL.contains("ChannelPay"));
    }
}
