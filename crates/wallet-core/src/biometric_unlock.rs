//! Encrypted passphrase cache for OS-biometric app unlock (mobile).
//! The OS biometric prompt gates access; ciphertext is stored in app-private storage.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{WalletError, WalletResult};
use crate::paths::{biometric_unlock_path, secure_write};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const AAD: &[u8] = b"hacash-wallet-biometric-unlock-v1";

#[derive(Serialize, Deserialize)]
struct BiometricUnlockBlob {
    version: u8,
    wrap_key: String,
    nonce: String,
    ciphertext: String,
}

pub fn is_configured() -> bool {
    biometric_unlock_path().exists()
}

pub fn save_encrypted_passphrase(passphrase: &str) -> WalletResult<()> {
    let mut wrap_key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut wrap_key);
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new_from_slice(&wrap_key)
        .map_err(|e| WalletError::Vault(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: passphrase.as_bytes(),
                aad: AAD,
            },
        )
        .map_err(|e| WalletError::Vault(e.to_string()))?;

    let blob = BiometricUnlockBlob {
        version: 1,
        wrap_key: hex::encode(wrap_key),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    };
    wrap_key.zeroize();

    let json = serde_json::to_string(&blob).map_err(|e| WalletError::Vault(e.to_string()))?;
    secure_write(&biometric_unlock_path(), json.as_bytes())
        .map_err(|e| WalletError::Vault(e.to_string()))
}

pub fn load_encrypted_passphrase() -> WalletResult<String> {
    let path = biometric_unlock_path();
    if !path.exists() {
        return Err(WalletError::Vault("biometric unlock not configured".into()));
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| WalletError::Vault(e.to_string()))?;
    let blob: BiometricUnlockBlob =
        serde_json::from_str(&raw).map_err(|e| WalletError::Vault(e.to_string()))?;
    if blob.version != 1 {
        return Err(WalletError::Vault("unsupported biometric unlock version".into()));
    }

    let wrap_key = hex::decode(&blob.wrap_key).map_err(|e| WalletError::Vault(e.to_string()))?;
    if wrap_key.len() != KEY_LEN {
        return Err(WalletError::Vault("invalid biometric unlock key".into()));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&wrap_key);

    let nonce = hex::decode(&blob.nonce).map_err(|e| WalletError::Vault(e.to_string()))?;
    if nonce.len() != NONCE_LEN {
        return Err(WalletError::Vault("invalid biometric unlock nonce".into()));
    }
    let ciphertext =
        hex::decode(&blob.ciphertext).map_err(|e| WalletError::Vault(e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| WalletError::Vault(e.to_string()))?;
    key.zeroize();

    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_ref(),
                aad: AAD,
            },
        )
        .map_err(|_| WalletError::Vault("biometric unlock decrypt failed".into()))?;
    String::from_utf8(plain).map_err(|e| WalletError::Vault(e.to_string()))
}

pub fn clear() -> WalletResult<()> {
    let path = biometric_unlock_path();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| WalletError::Vault(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn biometric_unlock_roundtrip() {
        let _g = test_guard();
        let prev = std::env::var("HACASH_WALLET_DATA").ok();
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HACASH_WALLET_DATA", dir.path()) };
        let _ = clear();

        save_encrypted_passphrase("test-pass-phrase").unwrap();
        assert!(is_configured());
        let loaded = load_encrypted_passphrase().unwrap();
        assert_eq!(loaded, "test-pass-phrase");

        clear().unwrap();
        assert!(!is_configured());

        if let Some(p) = prev {
            unsafe { std::env::set_var("HACASH_WALLET_DATA", p) };
        } else {
            unsafe { std::env::remove_var("HACASH_WALLET_DATA") };
        }
    }
}