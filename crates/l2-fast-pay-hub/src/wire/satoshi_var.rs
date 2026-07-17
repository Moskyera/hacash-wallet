use field::{Bool, Parse, Serialize, Uint8};
use sys::Ret;

/// `fields.SatoshiVariation`. optional BTC satoshi leg on channel bills.
#[derive(Debug, Clone, Default)]
pub struct SatoshiVariation {
    pub not_empty: Bool,
    pub value_sat: Uint8,
}

impl SatoshiVariation {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_sat(sats: u64) -> Self {
        if sats == 0 {
            return Self::empty();
        }
        Self {
            not_empty: Bool::new(true),
            value_sat: Uint8::from(sats),
        }
    }
}

impl Serialize for SatoshiVariation {
    fn serialize_to(&self, out: &mut Vec<u8>) {
        self.not_empty.serialize_to(out);
        if self.not_empty.as_ref()[0] == 1 {
            self.value_sat.serialize_to(out);
        }
    }

    fn size(&self) -> usize {
        if self.not_empty.as_ref()[0] == 1 {
            self.not_empty.size() + self.value_sat.size()
        } else {
            self.not_empty.size()
        }
    }
}

impl Parse for SatoshiVariation {
    fn parse(&mut self, buf: &[u8]) -> Ret<usize> {
        let mut used = self.not_empty.parse(buf)?;
        if self.not_empty.as_ref()[0] == 1 {
            used += self.value_sat.parse(&buf[used..])?;
        }
        Ok(used)
    }
}
