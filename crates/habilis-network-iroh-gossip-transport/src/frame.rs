//! The frame: one QUIC datagram, addressed, on the mesh gossip topic.
//!
//! ```text
//! offset  size  field
//! 0       1     kind = 0x01
//! 1       1     version = 1
//! 2       32    dst  endpoint id
//! 34      32    src  endpoint id
//! 66      n     one QUIC datagram, 1 <= n <= 3774
//! ```
//!
//! A mesh `Message` is JSON, so it starts with `{` (0x7B). Any first byte that is
//! not `{` is not a `Message`, and `0x01` is this frame. The receive loop splits
//! on that byte before it parses anything.

use bytes::Bytes;
use iroh_base::EndpointId;

/// The first byte of a transport frame.
pub const FRAME_KIND: u8 = 0x01;
/// The only layout this build reads and writes.
pub const FRAME_VERSION: u8 = 1;
/// Bytes before the datagram: kind, version, destination, source.
pub const HEADER_LEN: usize = 66;
/// The largest frame, in bytes. It is the 4096-byte default message size of
/// iroh-gossip, less the 256 bytes that the engine keeps for gossip's own header
/// (the same margin that bounds a mesh `Message` at 3840).
pub const MAX_FRAME_LEN: usize = 3840;
/// The largest datagram that fits a frame.
pub const MAX_DATAGRAM_LEN: usize = MAX_FRAME_LEN - HEADER_LEN;

/// A frame that was read: the two ends and the datagram, borrowed from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub dst: EndpointId,
    pub src: EndpointId,
    pub datagram: &'a [u8],
}

/// Why a datagram cannot be framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// There is nothing to send.
    Empty,
    /// The datagram does not fit one gossip message.
    TooLarge { len: usize },
}

/// Why bytes are not a frame this build reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The first byte is not [`FRAME_KIND`]: this is another kind of message.
    NotAFrame,
    /// A layout version this build does not know.
    UnknownVersion(u8),
    /// Shorter than the header plus one byte of datagram.
    Truncated,
    /// Longer than [`MAX_FRAME_LEN`].
    TooLarge { len: usize },
    /// An id that is not a valid endpoint id.
    BadId,
}

/// Write `datagram` as a frame from `src` to `dst`.
///
/// # Errors
/// The datagram is empty or longer than [`MAX_DATAGRAM_LEN`].
pub fn encode(dst: EndpointId, src: EndpointId, datagram: &[u8]) -> Result<Bytes, EncodeError> {
    if datagram.is_empty() {
        return Err(EncodeError::Empty);
    }
    if datagram.len() > MAX_DATAGRAM_LEN {
        return Err(EncodeError::TooLarge {
            len: datagram.len(),
        });
    }
    let mut bytes = Vec::with_capacity(HEADER_LEN + datagram.len());
    bytes.push(FRAME_KIND);
    bytes.push(FRAME_VERSION);
    bytes.extend_from_slice(dst.as_bytes());
    bytes.extend_from_slice(src.as_bytes());
    bytes.extend_from_slice(datagram);
    Ok(Bytes::from(bytes))
}

/// Read a frame.
///
/// # Errors
/// The bytes are not a frame of this build: see [`DecodeError`].
pub fn decode(bytes: &[u8]) -> Result<Frame<'_>, DecodeError> {
    if bytes.first() != Some(&FRAME_KIND) {
        return Err(DecodeError::NotAFrame);
    }
    if bytes.len() > MAX_FRAME_LEN {
        return Err(DecodeError::TooLarge { len: bytes.len() });
    }
    if bytes.len() <= HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    if bytes[1] != FRAME_VERSION {
        return Err(DecodeError::UnknownVersion(bytes[1]));
    }
    let id_at = |start: usize| -> Result<EndpointId, DecodeError> {
        let raw: [u8; 32] = bytes[start..start + 32]
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        EndpointId::from_bytes(&raw).map_err(|_| DecodeError::BadId)
    };
    Ok(Frame {
        dst: id_at(2)?,
        src: id_at(34)?,
        datagram: &bytes[HEADER_LEN..],
    })
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn a_frame_round_trips() {
        let datagram = [7u8; 1200];

        let bytes = encode(id(1), id(2), &datagram).expect("a datagram that fits");
        let frame = decode(&bytes).expect("a frame");

        assert_eq!(frame.dst, id(1));
        assert_eq!(frame.src, id(2));
        assert_eq!(frame.datagram, datagram);
    }

    /// The layout is a wire contract: a second build must read what this one writes.
    #[test]
    fn the_header_is_kind_version_destination_source() {
        let bytes = encode(id(1), id(2), &[9, 9, 9]).expect("a frame");

        assert_eq!(bytes[0], FRAME_KIND);
        assert_eq!(bytes[1], FRAME_VERSION);
        assert_eq!(&bytes[2..34], id(1).as_bytes());
        assert_eq!(&bytes[34..66], id(2).as_bytes());
        assert_eq!(&bytes[66..], [9, 9, 9]);
        assert_eq!(bytes.len(), HEADER_LEN + 3);
    }

    #[test]
    fn the_largest_datagram_fits_and_one_more_byte_does_not() {
        let fits = vec![1u8; MAX_DATAGRAM_LEN];
        let over = vec![1u8; MAX_DATAGRAM_LEN + 1];

        assert_eq!(MAX_DATAGRAM_LEN, 3774);
        assert_eq!(
            encode(id(1), id(2), &fits).expect("fits").len(),
            MAX_FRAME_LEN
        );
        assert_eq!(
            encode(id(1), id(2), &over),
            Err(EncodeError::TooLarge { len: over.len() })
        );
    }

    #[test]
    fn an_empty_datagram_is_not_framed() {
        assert_eq!(encode(id(1), id(2), &[]), Err(EncodeError::Empty));
    }

    #[test]
    fn a_mesh_message_is_not_a_frame() {
        assert_eq!(decode(br#"{"kind":"chat"}"#), Err(DecodeError::NotAFrame));
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let mut bytes = encode(id(1), id(2), &[1]).expect("a frame").to_vec();
        bytes[1] = 2;

        assert_eq!(decode(&bytes), Err(DecodeError::UnknownVersion(2)));
    }

    #[test]
    fn a_frame_with_no_datagram_is_truncated() {
        let bytes = encode(id(1), id(2), &[1]).expect("a frame");

        assert_eq!(decode(&bytes[..HEADER_LEN]), Err(DecodeError::Truncated));
        assert_eq!(decode(&bytes[..10]), Err(DecodeError::Truncated));
        assert_eq!(decode(&[FRAME_KIND]), Err(DecodeError::Truncated));
    }

    #[test]
    fn a_frame_over_the_gossip_budget_is_refused_on_read() {
        let mut bytes = vec![0u8; MAX_FRAME_LEN + 1];
        bytes[0] = FRAME_KIND;
        bytes[1] = FRAME_VERSION;

        assert_eq!(
            decode(&bytes),
            Err(DecodeError::TooLarge {
                len: MAX_FRAME_LEN + 1
            })
        );
    }

    /// The frame is written twice, here and in the engine, which is below this crate
    /// in no way that a constant could cross. This pins them equal: a mesh message
    /// of the engine's cap fits one gossip message, and so does a frame.
    /// It was green on its first run.
    #[test]
    fn the_largest_frame_equals_the_engine_message_cap() {
        assert_eq!(
            MAX_FRAME_LEN,
            habilis_network_util::consts::MAX_MESSAGE_SIZE
        );
    }
}
