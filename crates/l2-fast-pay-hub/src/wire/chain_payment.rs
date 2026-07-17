use field::{Address, Fixed33, Fixed64, HashHalf, Parse, Serialize, Sign, Timestamp, Uint1};
use sys::Ret;

use super::hash::sha3_hash;
use super::prove_body::TransferProveBody;

/// `fields.SignSize` in Go core (33-byte pubkey + 64-byte signature).
const SIGN_WIRE_SIZE: usize = 33 + 64;

/// `channel.OffChainFormPaymentChannelTransfer` (unsigned. empty signature slots).
#[derive(Debug, Clone)]
pub struct OffChainChannelTransfer {
    pub timestamp: Timestamp,
    pub order_note_hash: HashHalf,
    pub must_sign_count: Uint1,
    pub must_sign_addresses: Vec<Address>,
    pub channel_count: Uint1,
    pub prove_hash_checkers: Vec<HashHalf>,
    pub must_signs: Vec<Sign>,
}

impl OffChainChannelTransfer {
    pub fn serialize_no_sign(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.timestamp.serialize_to(&mut out);
        self.order_note_hash.serialize_to(&mut out);
        self.must_sign_count.serialize_to(&mut out);
        for addr in &self.must_sign_addresses {
            addr.serialize_to(&mut out);
        }
        self.channel_count.serialize_to(&mut out);
        for hx in &self.prove_hash_checkers {
            hx.serialize_to(&mut out);
        }
        out
    }

    pub fn sign_stuff_hash(&self) -> field::Hash {
        sha3_hash(&self.serialize_no_sign())
    }

    pub fn from_prove_bodies(
        prove_bodies: &[TransferProveBody],
        sign_addresses: Vec<Address>,
        timestamp: u64,
    ) -> Self {
        let prove_hash_checkers: Vec<HashHalf> =
            prove_bodies.iter().map(|b| b.hash_half_checker()).collect();
        let must_sign_count = Uint1::from(sign_addresses.len() as u8);
        let channel_count = Uint1::from(prove_bodies.len() as u8);
        let must_signs = (0..sign_addresses.len()).map(|_| empty_sign()).collect();
        Self {
            timestamp: Timestamp::from(timestamp),
            order_note_hash: HashHalf::default(),
            must_sign_count,
            must_sign_addresses: sign_addresses,
            channel_count,
            prove_hash_checkers,
            must_signs,
        }
    }
}

impl Serialize for OffChainChannelTransfer {
    fn serialize_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.serialize_no_sign());
        for sign in &self.must_signs {
            sign.serialize_to(out);
        }
    }

    fn size(&self) -> usize {
        self.serialize_no_sign().len() + self.must_signs.len() * SIGN_WIRE_SIZE
    }
}

impl Parse for OffChainChannelTransfer {
    fn parse(&mut self, buf: &[u8]) -> Ret<usize> {
        let mut used = 0;
        used += self.timestamp.parse(&buf[used..])?;
        used += self.order_note_hash.parse(&buf[used..])?;
        used += self.must_sign_count.parse(&buf[used..])?;
        let sign_n = *self.must_sign_count as usize;
        self.must_sign_addresses = Vec::with_capacity(sign_n);
        for _ in 0..sign_n {
            let mut addr = Address::default();
            used += addr.parse(&buf[used..])?;
            self.must_sign_addresses.push(addr);
        }
        used += self.channel_count.parse(&buf[used..])?;
        let ch_n = *self.channel_count as usize;
        self.prove_hash_checkers = Vec::with_capacity(ch_n);
        for _ in 0..ch_n {
            let mut hx = HashHalf::default();
            used += hx.parse(&buf[used..])?;
            self.prove_hash_checkers.push(hx);
        }
        self.must_signs = Vec::with_capacity(sign_n);
        for _ in 0..sign_n {
            let mut sign = empty_sign();
            used += sign.parse(&buf[used..])?;
            self.must_signs.push(sign);
        }
        Ok(used)
    }
}

fn empty_sign() -> Sign {
    Sign {
        publickey: Fixed33::default(),
        signature: Fixed64::default(),
    }
}

/// Dedupe and lexicographically sort addresses (Go `CleanSortMustSignAddresses`).
pub fn clean_sort_addresses(mut addrs: Vec<Address>) -> Vec<Address> {
    addrs.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    addrs.dedup();
    addrs
}
