//! Narrow signing boundary for a validated Fast Pay bill.
//!
//! This trait deliberately exposes neither a private key, a generic
//! transaction signer, nor an L1 fallback. Callers must validate and durably
//! persist the exact Hub bill before invoking it.

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::l2_bill::cosign_bill_hex;
use crate::l2_safety::{
    ClientL2Operation, ClientOperationStatus, RestrictedSenderAuthority,
    validate_restricted_sender_authority,
};
use l2_fast_pay_hub::wire::ChannelPayCompleteDocuments;
use zeroize::Zeroizing;

/// Opaque, single-operation authority to add the local Fast Pay signature.
///
/// Only wallet-core can construct this value, after the Hub bill has passed
/// protocol validation and its exact unsigned bytes have been durably stored.
/// External signer implementations can inspect the complete binding, but they
/// cannot fabricate signing authority from raw bill hex.
pub struct FastPaySigningAuthorization {
    operation_id: String,
    idempotency_key: String,
    wallet_scope: String,
    hub_identity: String,
    channel_id: String,
    channel_reuse_version: u64,
    network_mode: String,
    payer: String,
    payee: String,
    amount: String,
    amount_units: u64,
    unsigned_bill_hex: String,
    unsigned_state_commitment: String,
    owner_authority_commitment: Option<String>,
    restricted_sender_authority: Option<RestrictedSenderAuthority>,
}

impl FastPaySigningAuthorization {
    pub(crate) fn from_persisted(operation: &ClientL2Operation) -> WalletResult<Self> {
        if operation.status != ClientOperationStatus::PersistedBeforeSigning {
            return Err(WalletError::L2(
                "Fast Pay signing authority requires a durably persisted unsigned bill".into(),
            ));
        }
        let unsigned_bill_hex = operation.unsigned_bill_hex.clone().ok_or_else(|| {
            WalletError::L2("Fast Pay signing authority is missing unsigned bytes".into())
        })?;
        let unsigned_state_commitment =
            operation.unsigned_state_commitment.clone().ok_or_else(|| {
                WalletError::L2("Fast Pay signing authority is missing its commitment".into())
            })?;
        let documents = ChannelPayCompleteDocuments::from_bill_hex(&unsigned_bill_hex)
            .map_err(|error| WalletError::L2(error.to_string()))?;
        let calculated_commitment = hex::encode(documents.chain_payment.sign_stuff_hash());
        if !documents.prove_bindings_valid() || calculated_commitment != unsigned_state_commitment {
            return Err(WalletError::L2(
                "Fast Pay signing authority does not match the durable unsigned bill".into(),
            ));
        }
        if operation.owner_authority_commitment.is_some() {
            let context = operation
                .restricted_sender_authority
                .as_ref()
                .ok_or_else(|| {
                    WalletError::L2(
                        "restricted Fast Pay authority is missing its explicit durable context"
                            .into(),
                    )
                })?;
            validate_restricted_sender_authority(
                context,
                &operation.network_mode,
                operation.amount_units,
            )?;
            if operation.owner_authority_commitment.as_deref()
                != Some(context.owner_authority_commitment.as_str())
            {
                return Err(WalletError::L2(
                    "restricted Fast Pay authority commitment and context disagree".into(),
                ));
            }
        } else if operation.restricted_sender_authority.is_some() {
            return Err(WalletError::L2(
                "restricted Fast Pay context exists without owner authority".into(),
            ));
        }
        Ok(Self {
            operation_id: operation.operation_id.clone(),
            idempotency_key: operation.idempotency_key.clone(),
            wallet_scope: operation.wallet_scope.clone(),
            hub_identity: operation.hub_identity.clone(),
            channel_id: operation.channel_id.clone(),
            channel_reuse_version: operation.channel_reuse_version,
            network_mode: operation.network_mode.clone(),
            payer: operation.payer.clone(),
            payee: operation.payee.clone(),
            amount: operation.amount.clone(),
            amount_units: operation.amount_units,
            unsigned_bill_hex,
            unsigned_state_commitment,
            owner_authority_commitment: operation.owner_authority_commitment.clone(),
            restricted_sender_authority: operation.restricted_sender_authority.clone(),
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub fn wallet_scope(&self) -> &str {
        &self.wallet_scope
    }
    pub fn hub_identity(&self) -> &str {
        &self.hub_identity
    }
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }
    pub fn channel_reuse_version(&self) -> u64 {
        self.channel_reuse_version
    }
    pub fn network_mode(&self) -> &str {
        &self.network_mode
    }
    pub fn payer(&self) -> &str {
        &self.payer
    }
    pub fn payee(&self) -> &str {
        &self.payee
    }
    pub fn amount(&self) -> &str {
        &self.amount
    }
    pub fn amount_units(&self) -> u64 {
        self.amount_units
    }
    pub fn unsigned_bill_hex(&self) -> &str {
        &self.unsigned_bill_hex
    }
    pub fn unsigned_state_commitment(&self) -> &str {
        &self.unsigned_state_commitment
    }
    pub fn owner_authority_commitment(&self) -> Option<&str> {
        self.owner_authority_commitment.as_deref()
    }
    pub fn restricted_sender_authority(&self) -> Option<&RestrictedSenderAuthority> {
        self.restricted_sender_authority.as_ref()
    }
}

pub trait FastPayBillSigner: Send + Sync {
    fn fast_pay_address(&self) -> &str;

    fn cosign_authorized_fast_pay_bill(
        &self,
        authorization: &FastPaySigningAuthorization,
    ) -> WalletResult<String>;
}

/// Narrow capability for deriving one authenticated scoped L2 journal key.
/// Implementations must domain-separate the result by every supplied binding.
pub trait FastPayJournalKeyProvider: Send + Sync {
    fn fast_pay_journal_address(&self) -> &str;

    fn derive_fast_pay_journal_key(
        &self,
        wallet_scope: &str,
        network_mode: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Zeroizing<[u8; 32]>>;
}

impl FastPayBillSigner for WalletAccount {
    fn fast_pay_address(&self) -> &str {
        self.inner().readable()
    }

    fn cosign_authorized_fast_pay_bill(
        &self,
        authorization: &FastPaySigningAuthorization,
    ) -> WalletResult<String> {
        cosign_bill_hex(authorization.unsigned_bill_hex(), self)
    }
}

impl FastPayJournalKeyProvider for WalletAccount {
    fn fast_pay_journal_address(&self) -> &str {
        self.inner().readable()
    }

    fn derive_fast_pay_journal_key(
        &self,
        wallet_scope: &str,
        network_mode: &str,
        hub_identity: &str,
        channel_id: &str,
    ) -> WalletResult<Zeroizing<[u8; 32]>> {
        crate::l2_safety::derive_journal_key(
            self,
            wallet_scope,
            network_mode,
            hub_identity,
            channel_id,
        )
    }
}
