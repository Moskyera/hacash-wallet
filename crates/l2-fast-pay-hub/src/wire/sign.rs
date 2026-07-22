use basis::method::verify_signature;
use field::{Address, Sign};
use sys::Account;

use crate::error::{HubError, HubResult};

use super::chain_payment::OffChainChannelTransfer;

impl OffChainChannelTransfer {
    /// Sign and fill the slot matching `acc`'s address (Go `DoSignFillPosition`).
    pub fn fill_sign_by_account(&mut self, acc: &Account) -> HubResult<Sign> {
        let hash = self.sign_stuff_hash();
        let signobj = Sign::create_by(acc, &hash);
        self.fill_sign(signobj.clone())?;
        Ok(signobj)
    }

    /// Insert a signature at the matching `must_sign_addresses` slot.
    pub fn fill_sign(&mut self, sign: Sign) -> HubResult<()> {
        let pubkey = sign.publickey.to_array();
        let addr_bytes = Account::get_address_by_public_key(pubkey);
        let sign_addr = Address::from(addr_bytes);
        let mut matched = false;
        for (i, addr) in self.must_sign_addresses.iter().enumerate() {
            if addr.as_ref() == sign_addr.as_ref() && i < self.must_signs.len() {
                self.must_signs[i] = sign;
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(HubError::Payment(format!(
                "sign address {} not in must-sign list",
                Account::to_readable(&addr_bytes)
            )));
        }
        Ok(())
    }

    /// True when every required slot has a non-empty pubkey.
    pub fn all_slots_filled(&self) -> bool {
        let empty = field::Fixed33::default();
        self.must_signs
            .iter()
            .all(|s| s.publickey.to_array() != empty.to_array())
    }

    /// True only when every required signature slot is filled and verifies for its address.
    pub fn all_signatures_verified(&self) -> bool {
        if !self.all_slots_filled() || self.must_sign_addresses.len() != self.must_signs.len() {
            return false;
        }
        let hash = self.sign_stuff_hash();
        self.must_sign_addresses
            .iter()
            .zip(self.must_signs.iter())
            .all(|(address, signature)| verify_signature(&hash, address, signature))
    }

    /// True when every non-empty slot verifies, while empty slots remain allowed.
    pub fn all_filled_signatures_verified(&self) -> bool {
        if self.must_sign_addresses.len() != self.must_signs.len() {
            return false;
        }
        let empty = field::Fixed33::default();
        let hash = self.sign_stuff_hash();
        self.must_sign_addresses
            .iter()
            .zip(self.must_signs.iter())
            .all(|(address, signature)| {
                signature.publickey.to_array() == empty.to_array()
                    || verify_signature(&hash, address, signature)
            })
    }

    /// True when the slot for a readable Hacash address contains a valid signature.
    pub fn signature_verified_for_readable(&self, readable: &str) -> bool {
        let Ok(address) = Address::from_readable(readable) else {
            return false;
        };
        self.signature_verified_for_address(&address)
    }

    /// True when the slot for `target` contains a valid signature.
    pub fn signature_verified_for_address(&self, target: &Address) -> bool {
        if self.must_sign_addresses.len() != self.must_signs.len() {
            return false;
        }
        let empty = field::Fixed33::default();
        let hash = self.sign_stuff_hash();
        self.must_sign_addresses
            .iter()
            .zip(self.must_signs.iter())
            .find(|(address, _)| address.as_ref() == target.as_ref())
            .is_some_and(|(address, signature)| {
                signature.publickey.to_array() != empty.to_array()
                    && verify_signature(&hash, address, signature)
            })
    }

    /// Merge only valid, filled signatures from the same immutable bill.
    /// Empty slots never erase signatures already collected by the hub.
    pub fn merge_verified_signatures(&mut self, candidate: &Self) -> HubResult<()> {
        if self.sign_stuff_hash() != candidate.sign_stuff_hash()
            || self.must_sign_addresses.len() != candidate.must_sign_addresses.len()
            || self.must_signs.len() != candidate.must_signs.len()
            || self
                .must_sign_addresses
                .iter()
                .zip(candidate.must_sign_addresses.iter())
                .any(|(left, right)| left.as_ref() != right.as_ref())
        {
            return Err(HubError::Payment(
                "signature submission does not match the prepared bill".into(),
            ));
        }

        let empty = field::Fixed33::default();
        let hash = self.sign_stuff_hash();
        for (index, (address, signature)) in candidate
            .must_sign_addresses
            .iter()
            .zip(candidate.must_signs.iter())
            .enumerate()
        {
            if signature.publickey.to_array() == empty.to_array() {
                continue;
            }
            if !verify_signature(&hash, address, signature) {
                return Err(HubError::Payment(
                    "signature submission contains an invalid signature".into(),
                ));
            }
            self.must_signs[index] = signature.clone();
        }
        Ok(())
    }
}
