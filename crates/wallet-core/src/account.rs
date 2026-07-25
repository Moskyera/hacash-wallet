use rand::RngCore;
use sys::Account;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{WalletError, WalletResult};

pub struct WalletAccount {
    account: Account,
}

impl WalletAccount {
    /// Deterministic account from seed text or passphrase (import / legacy recovery only).
    pub fn create(passphrase: &str) -> WalletResult<Self> {
        let account = Account::create_by(passphrase).map_err(WalletError::Other)?;
        Ok(Self { account })
    }

    /// Cryptographically random account. used for new wallet creation.
    pub fn create_random() -> WalletResult<Self> {
        let account = Account::create_randomly(&|buf| {
            rand::thread_rng().fill_bytes(buf);
            Ok(())
        })
        .map_err(WalletError::Other)?;
        Ok(Self { account })
    }

    pub fn from_secret_hex(secret_hex: &str) -> WalletResult<Self> {
        let account = Account::create_by(secret_hex).map_err(WalletError::Other)?;
        Ok(Self { account })
    }

    pub fn address(&self) -> String {
        self.account.readable().to_owned()
    }

    /// Serialize the secret only for encrypted-vault handoff.
    ///
    /// Both the binary serialization and the returned hex buffer are erased
    /// when their scoped owners are dropped. The long-lived `sys::Account`
    /// still requires its own upstream `Drop` implementation because its
    /// private key field cannot be soundly mutated through this wrapper.
    pub fn secret_hex(&self) -> Zeroizing<String> {
        let mut secret = self.account.secret_key().serialize();
        let encoded = Zeroizing::new(hex::encode(secret));
        secret.zeroize();
        encoded
    }

    pub fn inner(&self) -> &Account {
        &self.account
    }
}
