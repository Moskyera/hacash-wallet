use sha2::{Digest, Sha256};

use crate::error::{CompanionError, CompanionResult};

pub(crate) const MAX_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_STRING_BYTES: usize = 16 * 1024;

pub(crate) trait CanonicalEncode {
    fn encode_canonical(&self, encoder: &mut Encoder) -> CompanionResult<()>;

    fn canonical_bytes(&self, domain: &[u8]) -> CompanionResult<Vec<u8>> {
        let mut encoder = Encoder::new(domain)?;
        self.encode_canonical(&mut encoder)?;
        encoder.finish()
    }

    fn canonical_sha256(&self, domain: &[u8]) -> CompanionResult<[u8; 32]> {
        let bytes = self.canonical_bytes(domain)?;
        Ok(Sha256::digest(bytes).into())
    }
}

#[derive(Debug, Default)]
pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new(domain: &[u8]) -> CompanionResult<Self> {
        let mut this = Self::default();
        this.push_bytes(domain)?;
        Ok(this)
    }

    pub(crate) fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn push_bool(&mut self, value: bool) {
        self.push_u8(u8::from(value));
    }

    pub(crate) fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn push_string(&mut self, value: &str) -> CompanionResult<()> {
        if value.len() > MAX_STRING_BYTES || value.chars().any(char::is_control) {
            return Err(CompanionError::MalformedMessage);
        }
        self.push_bytes(value.as_bytes())
    }

    pub(crate) fn push_bytes(&mut self, value: &[u8]) -> CompanionResult<()> {
        let length = u32::try_from(value.len()).map_err(|_| CompanionError::MessageTooLarge)?;
        self.push_u32(length);
        self.bytes.extend_from_slice(value);
        if self.bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CompanionError::MessageTooLarge);
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> CompanionResult<Vec<u8>> {
        if self.bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CompanionError::MessageTooLarge);
        }
        Ok(self.bytes)
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8], domain: &[u8]) -> CompanionResult<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CompanionError::MessageTooLarge);
        }
        let mut decoder = Self { bytes, cursor: 0 };
        if decoder.read_bytes()? != domain {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(decoder)
    }

    pub(crate) fn read_u8(&mut self) -> CompanionResult<u8> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or(CompanionError::MalformedMessage)?;
        self.cursor += 1;
        Ok(value)
    }

    pub(crate) fn read_bool(&mut self) -> CompanionResult<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CompanionError::MalformedMessage),
        }
    }

    pub(crate) fn read_u32(&mut self) -> CompanionResult<u32> {
        let raw = self.read_exact(4)?;
        Ok(u32::from_be_bytes(
            raw.try_into()
                .map_err(|_| CompanionError::MalformedMessage)?,
        ))
    }

    pub(crate) fn read_u64(&mut self) -> CompanionResult<u64> {
        let raw = self.read_exact(8)?;
        Ok(u64::from_be_bytes(
            raw.try_into()
                .map_err(|_| CompanionError::MalformedMessage)?,
        ))
    }

    pub(crate) fn read_bytes(&mut self) -> CompanionResult<&'a [u8]> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| CompanionError::MalformedMessage)?;
        self.read_exact(length)
    }

    pub(crate) fn read_string(&mut self) -> CompanionResult<String> {
        let raw = self.read_bytes()?;
        if raw.len() > MAX_STRING_BYTES {
            return Err(CompanionError::MessageTooLarge);
        }
        let value = std::str::from_utf8(raw).map_err(|_| CompanionError::MalformedMessage)?;
        if value.chars().any(char::is_control) {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(value.to_owned())
    }

    pub(crate) fn finish(self) -> CompanionResult<()> {
        if self.cursor != self.bytes.len() {
            return Err(CompanionError::MalformedMessage);
        }
        Ok(())
    }

    fn read_exact(&mut self, length: usize) -> CompanionResult<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(CompanionError::MalformedMessage)?;
        let raw = self
            .bytes
            .get(self.cursor..end)
            .ok_or(CompanionError::MalformedMessage)?;
        self.cursor = end;
        Ok(raw)
    }
}
