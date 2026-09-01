use field::{Serialize as FieldSerialize, Sign};
use sys::Account;
use zeroize::Zeroizing;

use crate::error::{HubError, HubResult};
use crate::hvm_channel::{HvmChannelBillV1, HvmChannelBindingV1};
use crate::hvm_registry::{HvmRegistryBillV2, HvmRegistryBindingV2};
use crate::wire::ChannelPayCompleteDocuments;

/// CSP hub signing key loaded from env/CLI.
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

    pub(crate) fn account(&self) -> &Account {
        &self.account
    }

    pub(crate) fn secret_matches_hex(&self, candidate_hex: &str) -> bool {
        let candidate_hex = candidate_hex.trim();
        if candidate_hex.len() != 64 {
            return false;
        }
        let expected = Zeroizing::new(self.account.secret_key().serialize());
        let mut candidate = Zeroizing::new([0_u8; 32]);
        if hex::decode_to_slice(candidate_hex, &mut *candidate).is_err() {
            return false;
        }
        expected
            .iter()
            .zip(candidate.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    /// Sign hub slot(s) on the chain-payment envelope.
    pub fn sign_documents(&self, documents: &mut ChannelPayCompleteDocuments) -> HubResult<()> {
        documents
            .chain_payment
            .fill_sign_by_account(self.account())?;
        Ok(())
    }

    /// Sign only the Hub/right slot of one exact HVM bill.
    pub fn sign_hvm_bill(
        &self,
        binding: &HvmChannelBindingV1,
        bill: &mut HvmChannelBillV1,
    ) -> HubResult<()> {
        if self.address() != binding.right_hub_address {
            return Err(HubError::State(
                "Hub signer does not match the HVM channel right party".into(),
            ));
        }
        bill.validate_left_signed(binding)?;
        if !bill.right_signature_hex.is_empty() {
            return Err(HubError::State(
                "HVM bill already contains a right-party signature".into(),
            ));
        }
        let hash = bill.signing_hash(binding)?;
        bill.right_signature_hex = hex::encode(Sign::create_by(self.account(), &hash).serialize());
        bill.validate_fully_signed(binding)
    }

    /// Sign only the Hub slot of one exact shared-registry bill.
    pub fn sign_hvm_registry_bill(
        &self,
        binding: &HvmRegistryBindingV2,
        bill: &mut HvmRegistryBillV2,
    ) -> HubResult<()> {
        if self.address() != binding.right_hub_address {
            return Err(HubError::State(
                "Hub signer does not match the HVM registry Hub".into(),
            ));
        }
        bill.validate_left_signed(binding)?;
        if !bill.hub_signature_hex.is_empty() {
            return Err(HubError::State(
                "HVM registry bill already contains a Hub signature".into(),
            ));
        }
        let hash = bill.signing_hash(binding)?;
        bill.hub_signature_hex = hex::encode(Sign::create_by(self.account(), &hash).serialize());
        bill.validate_fully_signed(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::HubSigner;
    use sys::Account;

    #[test]
    fn secret_identity_check_is_exact_and_never_accepts_malformed_keys() {
        let account = Account::create_by("hpay-hub-signer-identity-test").unwrap();
        let secret_hex = hex::encode(account.secret_key().serialize());
        let signer = HubSigner::from_secret_hex(&secret_hex).unwrap();
        assert!(signer.secret_matches_hex(&secret_hex));
        assert!(signer.secret_matches_hex(&secret_hex.to_ascii_uppercase()));

        let other = Account::create_by("hpay-hub-signer-other-key").unwrap();
        assert!(!signer.secret_matches_hex(&hex::encode(other.secret_key().serialize())));
        assert!(!signer.secret_matches_hex(""));
        assert!(!signer.secret_matches_hex(&"zz".repeat(32)));
        assert!(!signer.secret_matches_hex(&secret_hex[..62]));
    }
}
