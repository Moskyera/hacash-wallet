use sha2::{Digest, Sha256};

/// Same derivation as `hacash-wallet-core::channel::derive_channel_id`.
pub fn derive_channel_id(left: &str, right: &str, reuse_version: u64) -> String {
    let seed = format!("{left}|{right}|{reuse_version}");
    let hash = Sha256::digest(seed.as_bytes());
    hex::encode(&hash[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_is_deterministic_32_hex() {
        let id = derive_channel_id("1Alice", "1Hub", 1);
        assert_eq!(id.len(), 32);
        assert_eq!(id, derive_channel_id("1Alice", "1Hub", 1));
        assert_ne!(id, derive_channel_id("1Bob", "1Hub", 1));
    }
}