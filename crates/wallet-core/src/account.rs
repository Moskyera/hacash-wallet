use sys::Account;

use crate::error::{WalletError, WalletResult};

#[derive(Clone)]
pub struct WalletAccount {
    account: Account,
}

impl WalletAccount {
    pub fn create(passphrase: &str) -> WalletResult<Self> {
        let account = Account::create_by(passphrase).map_err(|e| WalletError::Other(e))?;
        Ok(Self { account })
    }

    pub fn from_secret_hex(secret_hex: &str) -> WalletResult<Self> {
        let account = Account::create_by(secret_hex).map_err(|e| WalletError::Other(e))?;
        Ok(Self { account })
    }

    pub fn address(&self) -> String {
        self.account.readable().to_owned()
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.account.secret_key().serialize())
    }

    pub fn inner(&self) -> &Account {
        &self.account
    }
}