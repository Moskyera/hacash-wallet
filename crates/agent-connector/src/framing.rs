use std::io::{Read, Write};

use crate::error::{ConnectorError, ConnectorResult};

pub const MAX_FRAME_BYTES: usize = 64 * 1024;
const PREFIX_BYTES: usize = 4;

/// Four-byte, network-order length framing with a hard upper bound.
#[derive(Debug, Clone, Copy)]
pub struct FrameCodec {
    max_frame_bytes: usize,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new(MAX_FRAME_BYTES).expect("constant frame limit is valid")
    }
}

impl FrameCodec {
    pub fn new(max_frame_bytes: usize) -> ConnectorResult<Self> {
        if max_frame_bytes == 0 || max_frame_bytes > MAX_FRAME_BYTES {
            return Err(ConnectorError::InvalidFrame);
        }
        Ok(Self { max_frame_bytes })
    }

    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    pub fn encode(&self, payload: &[u8]) -> ConnectorResult<Vec<u8>> {
        self.validate_length(payload.len())?;
        let length = u32::try_from(payload.len()).map_err(|_| ConnectorError::FrameTooLarge)?;
        let mut frame = Vec::with_capacity(PREFIX_BYTES + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    pub fn decode_exact(&self, frame: &[u8]) -> ConnectorResult<Vec<u8>> {
        if frame.len() < PREFIX_BYTES {
            return Err(ConnectorError::InvalidFrame);
        }
        let announced =
            u32::from_be_bytes(frame[..PREFIX_BYTES].try_into().expect("fixed prefix")) as usize;
        self.validate_length(announced)?;
        if frame.len() != PREFIX_BYTES + announced {
            return Err(ConnectorError::InvalidFrame);
        }
        Ok(frame[PREFIX_BYTES..].to_vec())
    }

    pub fn read_from<R: Read>(&self, reader: &mut R) -> ConnectorResult<Vec<u8>> {
        let mut prefix = [0_u8; PREFIX_BYTES];
        reader
            .read_exact(&mut prefix)
            .map_err(|_| ConnectorError::InvalidFrame)?;
        let length = u32::from_be_bytes(prefix) as usize;
        self.validate_length(length)?;
        let mut payload = vec![0_u8; length];
        reader
            .read_exact(&mut payload)
            .map_err(|_| ConnectorError::InvalidFrame)?;
        Ok(payload)
    }

    pub fn write_to<W: Write>(&self, writer: &mut W, payload: &[u8]) -> ConnectorResult<()> {
        let frame = self.encode(payload)?;
        writer.write_all(&frame).map_err(|_| ConnectorError::Io)?;
        writer.flush().map_err(|_| ConnectorError::Io)
    }

    fn validate_length(&self, length: usize) -> ConnectorResult<()> {
        if length == 0 {
            return Err(ConnectorError::InvalidFrame);
        }
        if length > self.max_frame_bytes {
            return Err(ConnectorError::FrameTooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    struct PrefixOnlyReader {
        prefix: [u8; PREFIX_BYTES],
        offset: usize,
    }

    impl Read for PrefixOnlyReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                self.offset < self.prefix.len(),
                "an oversized prefix must be rejected before any payload read"
            );
            let available = &self.prefix[self.offset..];
            let read = available.len().min(output.len());
            output[..read].copy_from_slice(&available[..read]);
            self.offset += read;
            Ok(read)
        }
    }

    #[test]
    fn frame_roundtrip_is_explicit_and_bounded() {
        let codec = FrameCodec::default();
        let frame = codec.encode(br#"{"ok":true}"#).unwrap();
        assert_eq!(codec.decode_exact(&frame).unwrap(), br#"{"ok":true}"#);
        assert!(codec.encode(&vec![0; MAX_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn malformed_truncated_and_trailing_frames_fail() {
        let codec = FrameCodec::default();
        assert!(codec.decode_exact(&[0, 0, 0]).is_err());
        assert!(codec.decode_exact(&[0, 0, 0, 4, 1, 2]).is_err());
        assert!(codec.decode_exact(&[0, 0, 0, 1, 1, 2]).is_err());
        assert_eq!(
            codec.decode_exact(&[0xff, 0xff, 0xff, 0xff]),
            Err(ConnectorError::FrameTooLarge)
        );
    }
    #[test]
    fn public_codec_limit_cannot_exceed_the_protocol_maximum() {
        assert!(matches!(
            FrameCodec::new(MAX_FRAME_BYTES + 1),
            Err(ConnectorError::InvalidFrame)
        ));
        assert_eq!(
            FrameCodec::new(MAX_FRAME_BYTES).unwrap().max_frame_bytes(),
            MAX_FRAME_BYTES
        );
    }

    #[test]
    fn oversized_prefix_is_rejected_before_payload_read_or_allocation() {
        let announced = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes();
        let mut reader = PrefixOnlyReader {
            prefix: announced,
            offset: 0,
        };
        assert_eq!(
            FrameCodec::default().read_from(&mut reader),
            Err(ConnectorError::FrameTooLarge)
        );
        assert_eq!(reader.offset, PREFIX_BYTES);
    }
}
