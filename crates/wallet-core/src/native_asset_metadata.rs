//! Display-only HIP-20 metadata from the community indexer.
//!
//! Consensus identity and signing decisions always use the on-chain serial and
//! balance returned by the configured Hacash node. This metadata is never used
//! to construct or authorize a transaction.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

const METADATA_ROOT: &str = "https://explorer.hacash.community/api/v1/assets";
const MAX_METADATA_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeAssetMetadata {
    pub serial: String,
    pub ticket: String,
    pub name: String,
    pub decimal: u8,
    pub supply: String,
    pub issuer: String,
    pub created_height: u64,
    pub created_tx: String,
    pub source: String,
    pub display_only: bool,
}

#[derive(Debug, Deserialize)]
struct MetadataEnvelope {
    asset: MetadataWire,
}

#[derive(Debug, Deserialize)]
struct MetadataWire {
    serial: u64,
    ticket: String,
    name: String,
    decimal: u8,
    supply: String,
    issuer: String,
    created_height: u64,
    created_tx: String,
}

pub async fn fetch_native_asset_metadata(serial: u64) -> WalletResult<NativeAssetMetadata> {
    if serial == 0 {
        return Err(WalletError::Other(
            "Asset serial must be a positive integer".into(),
        ));
    }
    let url = format!("{METADATA_ROOT}/{serial}");
    let response = crate::http_client::shared_http_client()
        .map_err(WalletError::Node)?
        .get(&url)
        .send()
        .await
        .map_err(|error| WalletError::Node(format!("HIP-20 metadata request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(WalletError::Node(format!(
            "HIP-20 metadata unavailable (HTTP {})",
            response.status().as_u16()
        )));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| WalletError::Node(format!("HIP-20 metadata body failed: {error}")))?;
    if body.len() > MAX_METADATA_BODY_BYTES {
        return Err(WalletError::Node(
            "HIP-20 metadata response exceeds safe size".into(),
        ));
    }
    parse_metadata(serial, &body)
}

fn parse_metadata(serial: u64, body: &[u8]) -> WalletResult<NativeAssetMetadata> {
    let wire: MetadataEnvelope = serde_json::from_slice(body)
        .map_err(|error| WalletError::Node(format!("HIP-20 metadata shape invalid: {error}")))?;
    let asset = wire.asset;
    if asset.serial != serial {
        return Err(WalletError::Node(
            "HIP-20 metadata serial does not match the requested asset".into(),
        ));
    }
    if asset.ticket.is_empty()
        || asset.ticket.len() > 8
        || !asset
            .ticket
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(WalletError::Node(
            "HIP-20 metadata ticket is invalid".into(),
        ));
    }
    if asset.name.is_empty() || asset.name.len() > 64 || asset.name.chars().any(char::is_control) {
        return Err(WalletError::Node("HIP-20 metadata name is invalid".into()));
    }
    if asset.decimal > 16 {
        return Err(WalletError::Node(
            "HIP-20 metadata decimal is invalid".into(),
        ));
    }
    crate::native_asset_send::parse_positive_u64_decimal(&asset.supply, "Asset supply")?;
    if !crate::hip23::is_valid_hacash_address(&asset.issuer) {
        return Err(WalletError::Node(
            "HIP-20 metadata issuer address is invalid".into(),
        ));
    }
    if asset.created_tx.len() != 64
        || !asset
            .created_tx
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(WalletError::Node(
            "HIP-20 metadata creation transaction is invalid".into(),
        ));
    }
    Ok(NativeAssetMetadata {
        serial: serial.to_string(),
        ticket: asset.ticket,
        name: asset.name,
        decimal: asset.decimal,
        supply: asset.supply,
        issuer: asset.issuer,
        created_height: asset.created_height,
        created_tx: asset.created_tx.to_ascii_lowercase(),
        source: "Hacash Community Explorer".into(),
        display_only: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(serial: u64) -> Vec<u8> {
        serde_json::json!({
            "asset": {
                "serial": serial,
                "ticket": "HACP",
                "name": "Hacash Points",
                "decimal": 0,
                "supply": "1000000000",
                "issuer": "1EkAb172mhWEtE6gdwvjgZTbRSf1mhiytf",
                "created_height": 765445,
                "created_tx": "c898607833f05407c5b794771122dcbe8332bd1c5888efec3f7d875013f6beea"
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn parses_first_mainnet_asset_metadata_as_display_only() {
        let metadata = parse_metadata(1025, &body(1025)).unwrap();
        assert_eq!(metadata.ticket, "HACP");
        assert_eq!(metadata.name, "Hacash Points");
        assert!(metadata.display_only);
    }

    #[test]
    fn rejects_cross_asset_and_malformed_identity_data() {
        assert!(parse_metadata(1026, &body(1025)).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&body(1025)).unwrap();
        value["asset"]["ticket"] = serde_json::json!("<script>");
        assert!(parse_metadata(1025, &serde_json::to_vec(&value).unwrap()).is_err());
    }
}
