//! Agent-only signing boundary. The unlocked session retains the blockchain
//! secret only as zeroizing bytes and constructs the upstream account for the
//! final signature call. This minimizes post-drop remnants, but it cannot
//! protect an unlocked process from an attacker who can read live memory.

use std::fmt;

use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::tx_binding::verify_hac_transfers;
use protocol::transaction;
use sys::ToHex;
use zeroize::{Zeroize, Zeroizing};

use crate::amount::HacUnits;
use crate::error::{AgentWalletError, AgentWalletResult};
use crate::operation::{ApprovedUnsignedTransaction, SignedAgentTransaction};
use crate::types::{AgentWalletId, WalletScope};

pub(crate) struct AgentTransactionSigner {
    wallet_id: AgentWalletId,
    wallet_scope: WalletScope,
    address: String,
    network_mode: String,
    signer_epoch: u64,
    unlock_expires_at: u64,
    // The unlock session retains only zeroizing Agent-owned bytes. A
    // WalletAccount is constructed at the final signing boundary and dropped
    // immediately after fill_sign; pinned sys::Account clears its SecretKey
    // in Drop.
    secret_key: Zeroizing<[u8; 32]>,
}

pub(crate) struct SignedAgentEnvelope {
    pub(crate) transaction: SignedAgentTransaction,
    pub(crate) tx_hash: String,
}

impl AgentTransactionSigner {
    pub(crate) fn new(
        wallet_id: AgentWalletId,
        address: String,
        network_mode: String,
        signer_epoch: u64,
        secret_hex: &str,
        unlocked_at: u64,
    ) -> AgentWalletResult<Self> {
        if signer_epoch == 0 || !matches!(network_mode.as_str(), "mainnet" | "testnet") {
            return Err(AgentWalletError::SigningBlocked);
        }
        if secret_hex.len() != 64 {
            return Err(AgentWalletError::Vault);
        }
        let decoded = Zeroizing::new(hex::decode(secret_hex).map_err(|_| AgentWalletError::Vault)?);
        if decoded.len() != 32 {
            return Err(AgentWalletError::Vault);
        }
        let mut secret_key = Zeroizing::new([0_u8; 32]);
        secret_key.copy_from_slice(decoded.as_slice());
        {
            let encoded = Zeroizing::new(hex::encode(secret_key.as_slice()));
            let account =
                WalletAccount::from_secret_hex(&encoded).map_err(|_| AgentWalletError::Vault)?;
            if account.address() != address {
                return Err(AgentWalletError::InvalidWalletScope);
            }
        }
        let wallet_scope = WalletScope::for_agent_wallet(&wallet_id);
        let unlock_expires_at = unlocked_at
            .checked_add(15 * 60)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        Ok(Self {
            wallet_id,
            wallet_scope,
            address,
            network_mode,
            signer_epoch,
            unlock_expires_at,
            secret_key,
        })
    }

    pub(crate) fn sign(
        &self,
        approved: ApprovedUnsignedTransaction,
        expected_wallet_scope: &WalletScope,
        expected_signer_epoch: u64,
        now: u64,
    ) -> AgentWalletResult<SignedAgentEnvelope> {
        if expected_wallet_scope != &self.wallet_scope
            || approved.agent_wallet_id() != &self.wallet_id
            || expected_signer_epoch != self.signer_epoch
            || approved.expires_at() == 0
            || now >= self.unlock_expires_at
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        if approved.asset() != "HAC" {
            return Err(AgentWalletError::UnsupportedAsset);
        }
        if approved.approval_commitment_sha256().len() != 64
            || approved.amount_units() == HacUnits::ZERO
            || approved.network_fee_units() != HacUnits::MIN_NETWORK_FEE
            || approved.wallet_fee_units() != HacUnits::ZERO
            || approved
                .amount_units()
                .checked_add(approved.network_fee_units())?
                != approved.total_debit_units()
        {
            return Err(AgentWalletError::ApprovalCommitmentMismatch);
        }
        hacash_wallet_core::require_address_for_network(approved.recipient(), &self.network_mode)
            .map_err(|_| AgentWalletError::RecipientNotAllowed)?;

        let amount = approved.amount_units().to_decimal();
        let network_fee = approved.network_fee_units().to_decimal();
        let transfers = [(approved.recipient(), amount.as_str())];
        let canonical = verify_hac_transfers(
            approved.unsigned_tx_hex(),
            &self.address,
            &network_fee,
            &transfers,
        )
        .map_err(|_| AgentWalletError::ApprovalCommitmentMismatch)?;
        if canonical.tx_type != 2
            || canonical.main_address != self.address
            || !canonical
                .required_signers
                .iter()
                .any(|signer| signer == &self.address)
        {
            return Err(AgentWalletError::SigningBlocked);
        }
        approved.revalidate_transaction_commitment()?;

        let body = hex::decode(approved.unsigned_tx_hex())
            .map_err(|_| AgentWalletError::SigningBlocked)?;
        let (mut transaction, consumed) =
            transaction::transaction_create(&body).map_err(|_| AgentWalletError::SigningBlocked)?;
        if consumed != body.len() || transaction.ty() != 2 {
            return Err(AgentWalletError::SigningBlocked);
        }
        // Create the upstream account only for the actual signature call.
        // Both the temporary encoding and pinned sys::Account secret are
        // erased by their respective Drop implementations on every exit path.
        {
            let encoded = Zeroizing::new(hex::encode(self.secret_key.as_slice()));
            let account = WalletAccount::from_secret_hex(&encoded)
                .map_err(|_| AgentWalletError::SigningBlocked)?;
            if account.address() != self.address {
                return Err(AgentWalletError::SigningBlocked);
            }
            transaction
                .fill_sign(account.inner())
                .map_err(|_| AgentWalletError::SigningBlocked)?;
        }
        let tx_hash = transaction.hash().to_hex();
        if tx_hash.is_empty() {
            return Err(AgentWalletError::SigningBlocked);
        }
        let signed_hex = transaction.serialize().to_hex();
        let transaction = approved.into_signed(signed_hex)?;
        Ok(SignedAgentEnvelope {
            transaction,
            tx_hash,
        })
    }

    pub(crate) fn wallet_scope(&self) -> &WalletScope {
        &self.wallet_scope
    }
}

impl fmt::Debug for AgentTransactionSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentTransactionSigner")
            .field("wallet_id", &self.wallet_id)
            .field("wallet_scope", &self.wallet_scope)
            .field("address", &self.address)
            .field("network_mode", &self.network_mode)
            .field("signer_epoch", &self.signer_epoch)
            .field("unlock_expires_at", &self.unlock_expires_at)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for AgentTransactionSigner {
    fn drop(&mut self) {
        self.address.zeroize();
        self.network_mode.zeroize();
        self.secret_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_holds_only_zeroizing_secret_bytes_and_redacts_debug() {
        let account = WalletAccount::create_random().unwrap();
        let secret = account.secret_hex();
        let signer = AgentTransactionSigner::new(
            AgentWalletId::new(),
            account.address(),
            "testnet".into(),
            1,
            &secret,
            1_000,
        )
        .unwrap();

        let debug = format!("{signer:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(secret.as_str()));
        assert!(std::mem::needs_drop::<AgentTransactionSigner>());
        assert!(std::mem::needs_drop::<WalletAccount>());
        assert!(std::mem::needs_drop::<sys::Account>());
    }

    #[test]
    fn signer_rejects_secret_from_another_agent_wallet() {
        let account_a = WalletAccount::create_random().unwrap();
        let account_b = WalletAccount::create_random().unwrap();
        let secret_b = account_b.secret_hex();
        let result = AgentTransactionSigner::new(
            AgentWalletId::new(),
            account_a.address(),
            "testnet".into(),
            1,
            &secret_b,
            1_000,
        );
        assert!(matches!(result, Err(AgentWalletError::InvalidWalletScope)));
    }
}
