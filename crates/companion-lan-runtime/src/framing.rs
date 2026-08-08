use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::config::MAX_WIRE_FRAME_BYTES;
use crate::error::{LanRuntimeError, LanRuntimeResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PacketKind {
    ClientHello = 1,
    SessionChallenge = 2,
    SessionResponse = 3,
    SessionConfirmation = 4,
    EncryptedFrame = 5,
    PairingRequest = 6,
    PairingConfirmation = 7,
    PairingAck = 8,
    PairingReceived = 9,
}

impl TryFrom<u8> for PacketKind {
    type Error = LanRuntimeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::SessionChallenge),
            3 => Ok(Self::SessionResponse),
            4 => Ok(Self::SessionConfirmation),
            5 => Ok(Self::EncryptedFrame),
            6 => Ok(Self::PairingRequest),
            7 => Ok(Self::PairingConfirmation),
            8 => Ok(Self::PairingAck),
            9 => Ok(Self::PairingReceived),
            _ => Err(LanRuntimeError::MalformedFrame),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Packet {
    pub kind: PacketKind,
    pub body: Vec<u8>,
}

pub(crate) async fn read_packet<R>(reader: &mut R, deadline: Duration) -> LanRuntimeResult<Packet>
where
    R: AsyncRead + Unpin,
{
    timeout(deadline, read_packet_inner(reader))
        .await
        .map_err(|_| LanRuntimeError::Timeout)?
}

async fn read_packet_inner<R>(reader: &mut R) -> LanRuntimeResult<Packet>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).await?;
    let length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| LanRuntimeError::FrameTooLarge)?;
    if length == 0 {
        return Err(LanRuntimeError::MalformedFrame);
    }
    if length > MAX_WIRE_FRAME_BYTES {
        return Err(LanRuntimeError::FrameTooLarge);
    }
    let mut frame = vec![0_u8; length];
    reader.read_exact(&mut frame).await?;
    let kind = PacketKind::try_from(frame[0])?;
    Ok(Packet {
        kind,
        body: frame[1..].to_vec(),
    })
}

pub(crate) async fn write_packet<W>(
    writer: &mut W,
    kind: PacketKind,
    body: &[u8],
    deadline: Duration,
) -> LanRuntimeResult<()>
where
    W: AsyncWrite + Unpin,
{
    if body.len() >= MAX_WIRE_FRAME_BYTES {
        return Err(LanRuntimeError::FrameTooLarge);
    }
    let length = body
        .len()
        .checked_add(1)
        .ok_or(LanRuntimeError::FrameTooLarge)?;
    let length = u32::try_from(length).map_err(|_| LanRuntimeError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(body.len() + 5);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.push(kind as u8);
    frame.extend_from_slice(body);
    timeout(deadline, writer.write_all(&frame))
        .await
        .map_err(|_| LanRuntimeError::Timeout)??;
    timeout(deadline, writer.flush())
        .await
        .map_err(|_| LanRuntimeError::Timeout)??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test]
    async fn framed_roundtrip_is_exact() {
        let (mut left, mut right) = duplex(1024);
        let send = tokio::spawn(async move {
            write_packet(
                &mut left,
                PacketKind::EncryptedFrame,
                b"ciphertext",
                Duration::from_secs(1),
            )
            .await
        });
        let packet = read_packet(&mut right, Duration::from_secs(1))
            .await
            .unwrap();
        send.await.unwrap().unwrap();
        assert_eq!(packet.kind, PacketKind::EncryptedFrame);
        assert_eq!(packet.body, b"ciphertext");
    }

    #[tokio::test]
    async fn every_pairing_packet_kind_roundtrips_exactly() {
        for kind in [
            PacketKind::PairingRequest,
            PacketKind::PairingConfirmation,
            PacketKind::PairingAck,
            PacketKind::PairingReceived,
        ] {
            let (mut left, mut right) = duplex(128);
            let send = tokio::spawn(async move {
                write_packet(&mut left, kind, b"typed", Duration::from_secs(1)).await
            });
            let packet = read_packet(&mut right, Duration::from_secs(1))
                .await
                .unwrap();
            send.await.unwrap().unwrap();
            assert_eq!(packet.kind, kind);
            assert_eq!(packet.body, b"typed");
        }
    }
    #[tokio::test]
    async fn zero_oversized_unknown_and_truncated_frames_fail_closed() {
        for bytes in [
            0_u32.to_be_bytes().to_vec(),
            u32::try_from(MAX_WIRE_FRAME_BYTES + 1)
                .unwrap()
                .to_be_bytes()
                .to_vec(),
            [1_u32.to_be_bytes().as_slice(), &[99]].concat(),
            [
                4_u32.to_be_bytes().as_slice(),
                &[PacketKind::ClientHello as u8, 1],
            ]
            .concat(),
        ] {
            let (mut left, mut right) = duplex(MAX_WIRE_FRAME_BYTES + 8);
            left.write_all(&bytes).await.unwrap();
            drop(left);
            assert!(
                read_packet(&mut right, Duration::from_secs(1))
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn stalled_prefix_times_out() {
        let (_left, mut right) = duplex(8);
        assert!(matches!(
            read_packet(&mut right, Duration::from_millis(10)).await,
            Err(LanRuntimeError::Timeout)
        ));
    }
}
