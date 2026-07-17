use sys::Account;

use crate::error::{HubError, HubResult};
use crate::wire::ChannelPayCompleteDocuments;

/// CSP hub signing key loaded from env/CLI.
#[derive(Clone)]
pub struct HubSigner {
    account: Account,
}

impl HubSigner {
    pub fn from_secret_hex(secret_hex: &str) -> HubResult<Self> {
        let trimmed = secret_hex.trim();
        if trimmed.is_empty() {
            return Err(HubError::State("hub secret key is empty".into()));
        }
        let account = Account::create_by(trimmed)
            .map_err(|e| HubError::State(format!("invalid hub secret key: {e}")))?;
        Ok(Self { account })
    }

    pub fn address(&self) -> &str {
        self.account.readable()
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Sign hub slot(s) on the chain-payment envelope.
    pub fn sign_documents(&self, documents: &mut ChannelPayCompleteDocuments) -> HubResult<()> {
        documents
            .chain_payment
            .fill_sign_by_account(self.account())?;
        Ok(())
    }
}
