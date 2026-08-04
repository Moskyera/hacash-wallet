//! Isolated fixture loader for future Official Hacash ChannelPay interop tests.
//!
//! This module deliberately contains no network client and no protocol session.
//! A fixture set is accepted only when its manifest digest is pinned by the
//! caller, its upstream revisions match the reviewed baseline, and every raw
//! binary vector matches its declared digest and declared wire format.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};

pub const PINNED_CHANNELPAY_COMMIT: &str = "d63e4109f2f9f4471f0838536b68b240848a77ef";
pub const PINNED_HACASH_CORE_COMMIT: &str = "8bb265fc1a68acc0af3236354fba7386bac4d9c5";
pub const OFFICIAL_CHANNELPAY_PROTOCOL_VERSION: u32 = 1;

const MANIFEST_FILE: &str = "manifest.json";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_VECTOR_BYTES: u64 = 1024 * 1024;
const MAX_VECTORS: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifest {
    schema_version: u32,
    producer: String,
    protocol_version: u32,
    channelpay_commit: String,
    hacash_core_commit: String,
    vectors: Vec<FixtureRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRecord {
    name: String,
    path: String,
    sha256: String,
    format: FixtureFormat,
    message_type: Option<u8>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FixtureFormat {
    ProtocolFrame,
    CompleteDocuments,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOfficialFixture {
    pub name: String,
    pub format: FixtureFormat,
    pub message_type: Option<u8>,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct VerifiedOfficialFixtureSet {
    pub channelpay_commit: String,
    pub hacash_core_commit: String,
    pub vectors: Vec<VerifiedOfficialFixture>,
}

impl VerifiedOfficialFixtureSet {
    pub fn load(
        root: &Path,
        expected_manifest_sha256: &str,
    ) -> WalletResult<VerifiedOfficialFixtureSet> {
        let expected_manifest_sha256 = parse_digest(expected_manifest_sha256)?;
        let manifest_path = root.join(MANIFEST_FILE);
        let manifest_bytes = bounded_read(&manifest_path, MAX_MANIFEST_BYTES)?;
        if Sha256::digest(&manifest_bytes).as_slice() != expected_manifest_sha256 {
            return Err(WalletError::L2(
                "Official ChannelPay fixture manifest digest mismatch".into(),
            ));
        }
        let manifest: FixtureManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| WalletError::L2("invalid Official ChannelPay fixture manifest".into()))?;
        if manifest.schema_version != 1
            || manifest.producer != "official-hacash-channelpay-go"
            || manifest.protocol_version != OFFICIAL_CHANNELPAY_PROTOCOL_VERSION
            || manifest.channelpay_commit != PINNED_CHANNELPAY_COMMIT
            || manifest.hacash_core_commit != PINNED_HACASH_CORE_COMMIT
        {
            return Err(WalletError::L2(
                "Official ChannelPay fixture provenance does not match the pinned baseline".into(),
            ));
        }
        if manifest.vectors.is_empty() || manifest.vectors.len() > MAX_VECTORS {
            return Err(WalletError::L2(
                "Official ChannelPay fixture count is invalid".into(),
            ));
        }

        let mut vectors = Vec::with_capacity(manifest.vectors.len());
        for record in manifest.vectors {
            validate_name(&record.name)?;
            let relative = safe_relative_path(&record.path)?;
            let bytes = bounded_read(&root.join(relative), MAX_VECTOR_BYTES)?;
            let expected = parse_digest(&record.sha256)?;
            if Sha256::digest(&bytes).as_slice() != expected {
                return Err(WalletError::L2(format!(
                    "Official ChannelPay vector {} digest mismatch",
                    record.name
                )));
            }
            match (record.format, record.message_type) {
                (FixtureFormat::ProtocolFrame, Some(message_type))
                    if bytes.first().copied() == Some(message_type) => {}
                (FixtureFormat::CompleteDocuments, None) => {}
                _ => {
                    return Err(WalletError::L2(format!(
                        "Official ChannelPay vector {} format metadata mismatch",
                        record.name
                    )));
                }
            }
            vectors.push(VerifiedOfficialFixture {
                name: record.name,
                format: record.format,
                message_type: record.message_type,
                bytes,
            });
        }

        Ok(Self {
            channelpay_commit: manifest.channelpay_commit,
            hacash_core_commit: manifest.hacash_core_commit,
            vectors,
        })
    }
}

fn bounded_read(path: &Path, limit: u64) -> WalletResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| WalletError::L2("Official ChannelPay fixture file is missing".into()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(WalletError::L2(
            "Official ChannelPay fixture file is unsafe or oversized".into(),
        ));
    }
    fs::read(path).map_err(|error| WalletError::L2(error.to_string()))
}

fn safe_relative_path(raw: &str) -> WalletResult<PathBuf> {
    let path = Path::new(raw);
    if raw.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(WalletError::L2(
            "Official ChannelPay fixture path is not a safe relative path".into(),
        ));
    }
    Ok(path.to_path_buf())
}

fn parse_digest(raw: &str) -> WalletResult<[u8; 32]> {
    let bytes = hex::decode(raw.trim())
        .map_err(|_| WalletError::L2("Official ChannelPay digest must be hex".into()))?;
    bytes
        .try_into()
        .map_err(|_| WalletError::L2("Official ChannelPay digest must be SHA-256".into()))
}

fn validate_name(name: &str) -> WalletResult<()> {
    if name.is_empty()
        || name.len() > 96
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(WalletError::L2(
            "Official ChannelPay fixture name is invalid".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(vector_digest: &str, path: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "producer": "official-hacash-channelpay-go",
            "protocol_version": 1,
            "channelpay_commit": PINNED_CHANNELPAY_COMMIT,
            "hacash_core_commit": PINNED_HACASH_CORE_COMMIT,
            "vectors": [{
                "name": "harness-only-sample",
                "path": path,
                "sha256": vector_digest,
                "format": "protocol_frame",
                "message_type": 4
            }]
        }))
        .unwrap()
    }

    #[test]
    fn verified_fixture_loader_is_pinned_and_transport_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let vector = [4_u8, 0, 1, 2];
        fs::write(directory.path().join("login.bin"), vector).unwrap();
        let vector_digest = hex::encode(Sha256::digest(vector));
        let manifest = manifest(&vector_digest, "login.bin");
        fs::write(directory.path().join(MANIFEST_FILE), &manifest).unwrap();
        let manifest_digest = hex::encode(Sha256::digest(&manifest));

        let verified =
            VerifiedOfficialFixtureSet::load(directory.path(), &manifest_digest).unwrap();
        assert_eq!(verified.vectors.len(), 1);
        assert_eq!(verified.vectors[0].format, FixtureFormat::ProtocolFrame);
        assert_eq!(verified.vectors[0].message_type, Some(4));
        assert_eq!(verified.vectors[0].bytes, vector);
    }

    #[test]
    fn unpinned_tampered_and_traversal_fixtures_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let vector = [4_u8, 0, 1, 2];
        fs::write(directory.path().join("login.bin"), vector).unwrap();
        let vector_digest = hex::encode(Sha256::digest(vector));
        let manifest = manifest(&vector_digest, "../login.bin");
        fs::write(directory.path().join(MANIFEST_FILE), &manifest).unwrap();
        let manifest_digest = hex::encode(Sha256::digest(&manifest));

        assert!(VerifiedOfficialFixtureSet::load(directory.path(), &"00".repeat(32)).is_err());
        assert!(VerifiedOfficialFixtureSet::load(directory.path(), &manifest_digest).is_err());
    }

    #[test]
    fn pinned_official_go_vectors_cross_parse_with_rust_wire_codec() {
        use field::Serialize;
        use l2_fast_pay_hub::wire::ChannelPayCompleteDocuments;

        const MANIFEST_SHA256: &str =
            "10a4e320c43999415ee81b40197838e53cf76a61df00e3b2a4a070b44bc0eacd";
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/official-channelpay-v1");
        let verified = VerifiedOfficialFixtureSet::load(&root, MANIFEST_SHA256).unwrap();
        assert_eq!(verified.vectors.len(), 10);

        let documents = verified
            .vectors
            .iter()
            .find(|fixture| fixture.name == "complete-documents")
            .unwrap();
        assert_eq!(documents.format, FixtureFormat::CompleteDocuments);
        assert_eq!(documents.message_type, None);

        let encoded = hex::encode(&documents.bytes);
        let parsed = ChannelPayCompleteDocuments::from_bill_hex(&encoded).unwrap();
        assert_eq!(parsed.to_bill_hex(), encoded);
        assert!(parsed.prove_bindings_valid());
        assert_eq!(parsed.prove_bodies.len(), 1);
        assert_eq!(parsed.chain_payment.must_sign_addresses.len(), 2);
        assert_eq!(parsed.chain_payment.must_signs.len(), 2);

        let prove_frame = verified
            .vectors
            .iter()
            .find(|fixture| fixture.name == "prove-body")
            .unwrap();
        assert_eq!(prove_frame.message_type, Some(9));
        // type (1) + transaction id (8) + body index (1)
        assert_eq!(parsed.prove_bodies[0].serialize(), prove_frame.bytes[10..]);
    }
}
