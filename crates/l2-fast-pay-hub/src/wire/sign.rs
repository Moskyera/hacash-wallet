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
            if addr.as_ref() == sign_addr.as_ref() {
                if i < self.must_signs.len() {
                    self.must_signs[i] = sign;
                    matched = true;
                    break;
                }
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
}