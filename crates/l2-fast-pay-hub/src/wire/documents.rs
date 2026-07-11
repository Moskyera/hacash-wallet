use field::{Parse, Serialize, Uint1};
use sys::Ret;

use crate::error::{HubError, HubResult};

use super::chain_payment::OffChainChannelTransfer;
use super::prove_body::TransferProveBody;

/// `channel.ChannelPayCompleteDocuments`
#[derive(Debug, Clone)]
pub struct ChannelPayCompleteDocuments {
    pub prove_bodies: Vec<TransferProveBody>,
    pub chain_payment: OffChainChannelTransfer,
}

impl ChannelPayCompleteDocuments {
    pub fn to_bill_hex(&self) -> String {
        hex::encode(self.serialize())
    }

    pub fn from_bill_hex(hex_str: &str) -> HubResult<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| HubError::Payment(e.to_string()))?;
        let mut doc = Self::empty();
        doc.parse(&bytes)
            .map_err(|e| HubError::Payment(e.to_string()))?;
        Ok(doc)
    }

    fn empty() -> Self {
        Self {
            prove_bodies: Vec::new(),
            chain_payment: OffChainChannelTransfer {
                timestamp: field::Timestamp::default(),
                order_note_hash: field::HashHalf::default(),
                must_sign_count: Uint1::default(),
                must_sign_addresses: Vec::new(),
                channel_count: Uint1::default(),
                prove_hash_checkers: Vec::new(),
                must_signs: Vec::new(),
            },
        }
    }
}

impl Serialize for ChannelPayCompleteDocuments {
    fn serialize_to(&self, out: &mut Vec<u8>) {
        let count = Uint1::from(self.prove_bodies.len() as u8);
        count.serialize_to(out);
        for body in &self.prove_bodies {
            body.serialize_to(out);
        }
        self.chain_payment.serialize_to(out);
    }

    fn size(&self) -> usize {
        let mut n = Uint1::from(self.prove_bodies.len() as u8).size();
        for body in &self.prove_bodies {
            n += body.size();
        }
        n + self.chain_payment.size()
    }
}

impl Parse for ChannelPayCompleteDocuments {
    fn parse(&mut self, buf: &[u8]) -> Ret<usize> {
        let mut used = 0;
        let mut count = Uint1::default();
        used += count.parse(&buf[used..])?;
        let n = *count as usize;
        self.prove_bodies = Vec::with_capacity(n);
        for _ in 0..n {
            let mut body = TransferProveBody {
                channel_id: field::ChannelId::default(),
                reuse_version: field::Uint4::default(),
                bill_auto_number: field::Uint8::default(),
                pay_direction: field::Uint1::default(),
                pay_amount: field::Amount::default(),
                pay_satoshi: super::satoshi_var::SatoshiVariation::empty(),
                left_balance: field::Amount::default(),
                right_balance: field::Amount::default(),
                left_satoshi: super::satoshi_var::SatoshiVariation::empty(),
                right_satoshi: super::satoshi_var::SatoshiVariation::empty(),
                left_address: field::Address::default(),
                right_address: field::Address::default(),
            };
            used += body.parse(&buf[used..])?;
            self.prove_bodies.push(body);
        }
        used += self.chain_payment.parse(&buf[used..])?;
        Ok(used)
    }
}