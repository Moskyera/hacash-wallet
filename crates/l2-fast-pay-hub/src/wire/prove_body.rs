use field::{Address, Amount, ChannelId, Parse, Serialize, Uint1, Uint4, Uint8};
use sys::Ret;

use super::hash::half_checker;
use super::satoshi_var::SatoshiVariation;

pub const DIRECTION_LEFT_TO_RIGHT: u8 = 1;
pub const DIRECTION_RIGHT_TO_LEFT: u8 = 2;

/// `channel.ChannelChainTransferProveBodyInfo`
#[derive(Debug, Clone)]
pub struct TransferProveBody {
    pub channel_id: ChannelId,
    pub reuse_version: Uint4,
    pub bill_auto_number: Uint8,
    pub pay_direction: Uint1,
    pub pay_amount: Amount,
    pub pay_satoshi: SatoshiVariation,
    pub left_balance: Amount,
    pub right_balance: Amount,
    pub left_satoshi: SatoshiVariation,
    pub right_satoshi: SatoshiVariation,
    pub left_address: Address,
    pub right_address: Address,
}

impl TransferProveBody {
    pub fn sign_stuff(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn hash_half_checker(&self) -> field::HashHalf {
        half_checker(&self.sign_stuff())
    }
}

impl Serialize for TransferProveBody {
    fn serialize_to(&self, out: &mut Vec<u8>) {
        self.channel_id.serialize_to(out);
        self.reuse_version.serialize_to(out);
        self.bill_auto_number.serialize_to(out);
        self.pay_direction.serialize_to(out);
        self.pay_amount.serialize_to(out);
        self.pay_satoshi.serialize_to(out);
        self.left_balance.serialize_to(out);
        self.right_balance.serialize_to(out);
        self.left_satoshi.serialize_to(out);
        self.right_satoshi.serialize_to(out);
        self.left_address.serialize_to(out);
        self.right_address.serialize_to(out);
    }

    fn size(&self) -> usize {
        self.channel_id.size()
            + self.reuse_version.size()
            + self.bill_auto_number.size()
            + self.pay_direction.size()
            + self.pay_amount.size()
            + self.pay_satoshi.size()
            + self.left_balance.size()
            + self.right_balance.size()
            + self.left_satoshi.size()
            + self.right_satoshi.size()
            + self.left_address.size()
            + self.right_address.size()
    }
}

impl Parse for TransferProveBody {
    fn parse(&mut self, buf: &[u8]) -> Ret<usize> {
        let mut used = 0;
        used += self.channel_id.parse(&buf[used..])?;
        used += self.reuse_version.parse(&buf[used..])?;
        used += self.bill_auto_number.parse(&buf[used..])?;
        used += self.pay_direction.parse(&buf[used..])?;
        used += self.pay_amount.parse(&buf[used..])?;
        used += self.pay_satoshi.parse(&buf[used..])?;
        used += self.left_balance.parse(&buf[used..])?;
        used += self.right_balance.parse(&buf[used..])?;
        used += self.left_satoshi.parse(&buf[used..])?;
        used += self.right_satoshi.parse(&buf[used..])?;
        used += self.left_address.parse(&buf[used..])?;
        used += self.right_address.parse(&buf[used..])?;
        Ok(used)
    }
}
