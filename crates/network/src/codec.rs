use crate::compression::Compression;
use crate::encryption::Encryption;
use crate::error::NetworkCodecError;
use bedrock_protocol_core::error::ProtoCodecError;
use bedrock_protocol_core::{PacketHeader, Packets, ProtoCodecVAR};
use std::io::Cursor;

pub const MAX_BATCH_PACKETS: usize = 4096;
pub const MAX_BATCH_LEN: usize = 10 << 20;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnreadBytes {
    #[default]
    Warn,
    Reject,
}

pub fn encode_packets<T: Packets>(
    packets: &[T],
    compression: Option<&Compression>,
    encryption: Option<&mut Encryption>,
) -> Result<Vec<u8>, NetworkCodecError> {
    tracing::trace!("Encoding packets");

    let mut packets_stream = batch_packets::<T>(packets)?;
    packets_stream = compress_packets(packets_stream, compression)?;
    packets_stream = encrypt_packets(packets_stream, encryption)?;

    Ok(packets_stream)
}

pub fn decode_packets<T: Packets>(
    mut packets_stream: Vec<u8>,
    compression: Option<&Compression>,
    encryption: Option<&mut Encryption>,
    max_batch_len: usize,
    unread_bytes: UnreadBytes,
) -> Result<Vec<T>, NetworkCodecError> {
    tracing::trace!("Decoding packets");

    packets_stream = decrypt_packets(packets_stream, encryption)?;
    packets_stream = decompress_packets(packets_stream, compression, max_batch_len)?;
    let packets = separate_packets::<T>(packets_stream, unread_bytes)?;

    Ok(packets)
}

fn batch_packets<T: Packets>(packets: &[T]) -> Result<Vec<u8>, NetworkCodecError> {
    let frames = packets
        .iter()
        .map(|packet| {
            let header = PacketHeader {
                packet_id: packet.id(),
                sender_sub_client_id: 0,
                target_sub_client_id: 0,
            };

            let mut frame = Vec::with_capacity(packet.size_hint(&header));
            packet.serialize(&header, &mut frame)?;
            Ok(frame)
        })
        .collect::<Result<Vec<_>, NetworkCodecError>>()?;

    Ok(join_batch(&frames))
}

fn separate_packets<T: Packets>(
    packets_stream: Vec<u8>,
    unread_bytes: UnreadBytes,
) -> Result<Vec<T>, NetworkCodecError> {
    split_batch(&packets_stream)?
        .into_iter()
        .map(|frame| decode_packet(frame, unread_bytes))
        .collect()
}

pub fn decode_packet<T: Packets>(
    frame: &[u8],
    unread_bytes: UnreadBytes,
) -> Result<T, NetworkCodecError> {
    let mut frame = Cursor::new(frame);
    let (packet, header) = T::deserialize(&mut frame)?;

    let unread = frame.get_ref().len() - frame.position() as usize;
    if unread > 0 && unread_bytes == UnreadBytes::Reject {
        return Err(ProtoCodecError::LeftOvers(unread).into());
    }
    if unread > 0 {
        tracing::warn!(
            "packet {} deserializer left {unread} unread bytes, skipping to next packet",
            header.packet_id,
        );
    }

    Ok(packet)
}

pub fn split_batch(batch: &[u8]) -> Result<Vec<&[u8]>, NetworkCodecError> {
    let mut stream = Cursor::new(batch);
    let mut frames = vec![];

    while (stream.position() as usize) < batch.len() {
        let declared = <u32 as ProtoCodecVAR>::deserialize(&mut stream)?;
        let rest = &batch[stream.position() as usize..];
        if declared == 0 {
            return Err(NetworkCodecError::EmptyPacket);
        }
        if frames.len() == MAX_BATCH_PACKETS {
            return Err(NetworkCodecError::PacketCountExceeded(MAX_BATCH_PACKETS));
        }
        let Some(frame) = rest.get(..declared as usize) else {
            return Err(NetworkCodecError::PacketLengthOutOfBounds {
                declared,
                remaining: rest.len(),
            });
        };

        frames.push(frame);
        stream.set_position(stream.position() + declared as u64);
    }

    Ok(frames)
}

pub fn join_batch<F: AsRef<[u8]>>(frames: &[F]) -> Vec<u8> {
    let mut batch = Vec::with_capacity(frames.iter().map(|frame| frame.as_ref().len() + 5).sum());

    for frame in frames {
        let frame = frame.as_ref();
        <u32 as ProtoCodecVAR>::serialize(&(frame.len() as u32), &mut batch)
            .expect("writing to a Vec cannot fail");
        batch.extend_from_slice(frame);
    }

    batch
}

pub fn compress_packets(
    mut packet_stream: Vec<u8>,
    compression: Option<&Compression>,
) -> Result<Vec<u8>, NetworkCodecError> {
    if let Some(compression) = compression {
        packet_stream = compression.compress(packet_stream)?;
    }

    Ok(packet_stream)
}

pub fn decompress_packets(
    mut packet_stream: Vec<u8>,
    compression: Option<&Compression>,
    max_len: usize,
) -> Result<Vec<u8>, NetworkCodecError> {
    if let Some(compression) = compression {
        packet_stream = compression.decompress(packet_stream, max_len)?;
    }

    Ok(packet_stream)
}

pub fn encrypt_packets(
    mut packet_stream: Vec<u8>,
    encryption: Option<&mut Encryption>,
) -> Result<Vec<u8>, NetworkCodecError> {
    if let Some(encryption) = encryption {
        packet_stream = encryption.encrypt(packet_stream)?;
    }

    Ok(packet_stream)
}

pub fn decrypt_packets(
    mut packet_stream: Vec<u8>,
    encryption: Option<&mut Encryption>,
) -> Result<Vec<u8>, NetworkCodecError> {
    if let Some(encryption) = encryption {
        packet_stream = encryption.decrypt(packet_stream)?;
    }

    Ok(packet_stream)
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    #[test]
    fn joined_frames_split_back_into_the_same_frames() {
        let frames = [vec![1u8, 2, 3], vec![9u8; 200], vec![7u8]];

        let batch = join_batch(&frames);

        assert_eq!(
            split_batch(&batch).unwrap(),
            frames.iter().map(Vec::as_slice).collect::<Vec<_>>()
        );
    }

    #[test]
    fn batch_with_a_zero_length_frame_is_an_error() {
        assert!(matches!(
            split_batch(&[0]),
            Err(NetworkCodecError::EmptyPacket)
        ));
    }

    #[test]
    fn batch_whose_frame_overruns_it_is_an_error() {
        assert!(matches!(
            split_batch(&[5, 1, 2]),
            Err(NetworkCodecError::PacketLengthOutOfBounds {
                declared: 5,
                remaining: 2
            })
        ));
    }

    #[test]
    fn empty_batch_has_no_frames() {
        assert!(split_batch(&[]).unwrap().is_empty());
    }

    #[test]
    fn batch_with_more_frames_than_the_cap_is_an_error() {
        assert!(matches!(
            split_batch(&[1, 4].repeat(MAX_BATCH_PACKETS + 1)),
            Err(NetworkCodecError::PacketCountExceeded(MAX_BATCH_PACKETS))
        ));
        assert_eq!(
            split_batch(&[1, 4].repeat(MAX_BATCH_PACKETS))
                .unwrap()
                .len(),
            MAX_BATCH_PACKETS
        );
    }
}

#[cfg(test)]
mod unread_tests {
    use super::*;
    use crate::login::packets::{LoginPackets, LoginStatus};
    use bedrock_protocol::V2225;

    fn frame_with_a_trailing_byte() -> Vec<u8> {
        let batch =
            encode_packets::<V2225>(&[V2225::play_status(LoginStatus::LoginSuccess)], None, None)
                .unwrap();
        let mut frame = split_batch(&batch).unwrap()[0].to_vec();
        frame.push(0);
        frame
    }

    #[test]
    fn unread_bytes_are_tolerated_when_warning() {
        assert!(decode_packet::<V2225>(&frame_with_a_trailing_byte(), UnreadBytes::Warn).is_ok());
    }

    #[test]
    fn unread_bytes_are_an_error_when_rejecting() {
        assert!(matches!(
            decode_packet::<V2225>(&frame_with_a_trailing_byte(), UnreadBytes::Reject),
            Err(NetworkCodecError::ProtoCodecError(
                ProtoCodecError::LeftOvers(1)
            ))
        ));
    }
}
