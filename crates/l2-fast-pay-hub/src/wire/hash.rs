use field::{Fixed16, Hash};
use sha3::{Digest, Sha3_256};

/// SHA3-256 over `stuff` (matches `fields.CalculateHash` in Go core).
pub fn sha3_hash(stuff: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(stuff);
    let digest: [u8; 32] = hasher.finalize().into();
    Hash::from(digest)
}

/// First 16 bytes of SHA3-256(stuff). `HashHalfChecker` in Go.
pub fn half_checker(stuff: &[u8]) -> Fixed16 {
    sha3_hash(stuff).half()
}
