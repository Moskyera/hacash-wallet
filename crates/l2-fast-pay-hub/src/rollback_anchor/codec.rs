//! Canonical encoding for the external rollback anchor.
//!
//! This is the encoding proven by `crates/companion-protocol/src/codec.rs`,
//! re-stated here because that module is `pub(crate)` to its own crate. The
//! rules are identical and deliberately so:
//!
//! - the domain is written first, as a length-prefixed field, so it is inside
//!   the hashed preimage rather than merely a convention;
//! - integers are big-endian and fixed width;
//! - strings and byte strings carry a `u32` big-endian length prefix;
//! - enumerations are a `u8` tag with an exhaustive mapping;
//! - a decoder verifies the domain, decodes exactly, and `finish()` fails on a
//!   single trailing byte. Trailing bytes are a malformed message, never a
//!   forward-compatibility mechanism.

use crate::error::{HubError, HubResult};

pub(crate) const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_STRING_BYTES: usize = 4 * 1024;

fn malformed() -> HubError {
    HubError::Node("rollback anchor message is malformed".into())
}

fn too_large() -> HubError {
    HubError::Node("rollback anchor message is too large".into())
}

pub(crate) trait CanonicalEncode {
    fn encode_canonical(&self, encoder: &mut Encoder) -> HubResult<()>;

    fn canonical_bytes(&self, domain: &[u8]) -> HubResult<Vec<u8>> {
        let mut encoder = Encoder::new(domain)?;
        self.encode_canonical(&mut encoder)?;
        encoder.finish()
    }

    fn canonical_sha256(&self, domain: &[u8]) -> HubResult<[u8; 32]> {
        Ok(sys::sha2(&self.canonical_bytes(domain)?))
    }

    fn canonical_sha256_hex(&self, domain: &[u8]) -> HubResult<String> {
        Ok(hex::encode(self.canonical_sha256(domain)?))
    }
}

#[derive(Debug, Default)]
pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new(domain: &[u8]) -> HubResult<Self> {
        let mut this = Self::default();
        this.push_bytes(domain)?;
        Ok(this)
    }

    pub(crate) fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Optional fields are a `bool` tag followed by the value when present.
    /// No message needs one today; the encoder keeps the primitive so that the
    /// first one to need it cannot invent a second convention.
    #[allow(dead_code)]
    pub(crate) fn push_bool(&mut self, value: bool) {
        self.push_u8(u8::from(value));
    }

    pub(crate) fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn push_string(&mut self, value: &str) -> HubResult<()> {
        if value.len() > MAX_STRING_BYTES || value.chars().any(char::is_control) {
            return Err(malformed());
        }
        self.push_bytes(value.as_bytes())
    }

    pub(crate) fn push_bytes(&mut self, value: &[u8]) -> HubResult<()> {
        let length = u32::try_from(value.len()).map_err(|_| too_large())?;
        self.push_u32(length);
        self.bytes.extend_from_slice(value);
        if self.bytes.len() > MAX_MESSAGE_BYTES {
            return Err(too_large());
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> HubResult<Vec<u8>> {
        if self.bytes.len() > MAX_MESSAGE_BYTES {
            return Err(too_large());
        }
        Ok(self.bytes)
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8], domain: &[u8]) -> HubResult<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(too_large());
        }
        let mut decoder = Self { bytes, cursor: 0 };
        if decoder.read_bytes()? != domain {
            return Err(malformed());
        }
        Ok(decoder)
    }

    pub(crate) fn read_u8(&mut self) -> HubResult<u8> {
        let value = *self.bytes.get(self.cursor).ok_or_else(malformed)?;
        self.cursor += 1;
        Ok(value)
    }

    #[allow(dead_code)]
    pub(crate) fn read_bool(&mut self) -> HubResult<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(malformed()),
        }
    }

    pub(crate) fn read_u32(&mut self) -> HubResult<u32> {
        let raw = self.read_exact(4)?;
        Ok(u32::from_be_bytes(raw.try_into().map_err(|_| malformed())?))
    }

    pub(crate) fn read_u64(&mut self) -> HubResult<u64> {
        let raw = self.read_exact(8)?;
        Ok(u64::from_be_bytes(raw.try_into().map_err(|_| malformed())?))
    }

    pub(crate) fn read_bytes(&mut self) -> HubResult<&'a [u8]> {
        let length = usize::try_from(self.read_u32()?).map_err(|_| malformed())?;
        self.read_exact(length)
    }

    pub(crate) fn read_string(&mut self) -> HubResult<String> {
        let raw = self.read_bytes()?;
        if raw.len() > MAX_STRING_BYTES {
            return Err(too_large());
        }
        let value = std::str::from_utf8(raw).map_err(|_| malformed())?;
        if value.chars().any(char::is_control) {
            return Err(malformed());
        }
        Ok(value.to_owned())
    }

    pub(crate) fn finish(self) -> HubResult<()> {
        if self.cursor != self.bytes.len() {
            return Err(malformed());
        }
        Ok(())
    }

    fn read_exact(&mut self, length: usize) -> HubResult<&'a [u8]> {
        let end = self.cursor.checked_add(length).ok_or_else(malformed)?;
        let raw = self.bytes.get(self.cursor..end).ok_or_else(malformed)?;
        self.cursor = end;
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sample {
        left: u64,
        right: String,
    }

    impl CanonicalEncode for Sample {
        fn encode_canonical(&self, encoder: &mut Encoder) -> HubResult<()> {
            encoder.push_u64(self.left);
            encoder.push_string(&self.right)
        }
    }

    #[test]
    fn the_domain_is_inside_the_preimage_and_trailing_bytes_are_refused() {
        let sample = Sample {
            left: 7,
            right: "channel".into(),
        };
        let one = sample.canonical_sha256_hex(b"HPAY/TEST/ONE").unwrap();
        let two = sample.canonical_sha256_hex(b"HPAY/TEST/TWO").unwrap();
        assert_ne!(one, two, "the domain must change the commitment");

        let mut bytes = sample.canonical_bytes(b"HPAY/TEST/ONE").unwrap();
        let mut decoder = Decoder::new(&bytes, b"HPAY/TEST/ONE").unwrap();
        assert_eq!(decoder.read_u64().unwrap(), 7);
        assert_eq!(decoder.read_string().unwrap(), "channel");
        decoder.finish().unwrap();

        bytes.push(0);
        let mut decoder = Decoder::new(&bytes, b"HPAY/TEST/ONE").unwrap();
        decoder.read_u64().unwrap();
        decoder.read_string().unwrap();
        assert!(
            decoder.finish().is_err(),
            "a single trailing byte is a malformed message"
        );

        let bytes = sample.canonical_bytes(b"HPAY/TEST/ONE").unwrap();
        assert!(
            Decoder::new(&bytes, b"HPAY/TEST/TWO").is_err(),
            "a decoder must refuse a message written under another domain"
        );
    }
}
