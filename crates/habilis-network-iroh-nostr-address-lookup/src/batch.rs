//! The content of a data event: the sender's id, a serial, then length-prefixed datagrams, in
//! base64. QUIC encrypts and authenticates each datagram, so the batch carries no seal of its own.

use std::error::Error;
use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64;

/// The most bytes one batch holds before base64: the header and every prefixed datagram. An event
/// carries it as about `22 KiB` of text, far under the `128 KiB` a relay frame may hold.
pub(crate) const MAX_BATCH_BYTES: usize = 16 * 1024;

/// The longest datagram a batch carries: the longest frame the gossip transport makes (`3840`
/// bytes, header included), because a datagram reaches this crate as such a frame. A QUIC datagram
/// stays under the path MTU, far under this, so a longer one is not ours. The transport crate pins
/// the same number in a test.
pub(crate) const MAX_DATAGRAM: usize = 3840;

/// The length of an endpoint id.
pub(crate) const ID_LEN: usize = 32;

/// The length of the serial of a batch.
const SERIAL_LEN: usize = 4;

/// The length of the header of a batch: the sender id, then the serial.
const HEADER_LEN: usize = ID_LEN + SERIAL_LEN;

/// The length prefix of each datagram.
const PREFIX_LEN: usize = 2;

/// Why the content of an event is not a batch.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub(crate) enum BatchError {
    /// The text is not base64.
    NotBase64,
    /// The text is longer than any batch encodes to.
    TooLong,
    /// The bytes end inside the id or a datagram.
    Truncated,
    /// A datagram is longer than [`MAX_DATAGRAM`].
    DatagramTooLong,
}

impl fmt::Display for BatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotBase64 => "batch is not base64",
            Self::TooLong => "batch is too long",
            Self::Truncated => "batch ends inside a field",
            Self::DatagramTooLong => "batch datagram is too long",
        })
    }
}

impl Error for BatchError {}

/// Datagrams for one destination, from one sender, waiting to go out in one event. The serial
/// makes two batches with the same datagrams two events: an event id has a time in seconds, and a
/// relay and a receiver drop an id they have seen.
#[derive(Debug, Clone)]
pub(crate) struct Batch {
    bytes: Vec<u8>,
    datagrams: usize,
}

impl Batch {
    pub(crate) fn new(from: &[u8; ID_LEN], serial: u32) -> Self {
        let mut bytes = from.to_vec();
        bytes.extend_from_slice(&serial.to_be_bytes());
        Self {
            bytes,
            datagrams: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.len() == HEADER_LEN
    }

    /// Whether `datagram` is one a batch carries, and fits next to what it holds.
    pub(crate) fn fits(&self, datagram: &[u8]) -> bool {
        datagram.len() <= MAX_DATAGRAM
            && self.bytes.len() + PREFIX_LEN + datagram.len() <= MAX_BATCH_BYTES
    }

    /// Append `datagram`. `false`, and nothing changes, when it does not fit.
    pub(crate) fn push(&mut self, datagram: &[u8]) -> bool {
        if !self.fits(datagram) {
            return false;
        }
        let length = u16::try_from(datagram.len()).unwrap_or(u16::MAX);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(datagram);
        self.datagrams += 1;
        true
    }

    /// How many datagrams the batch holds.
    pub(crate) fn datagrams(&self) -> usize {
        self.datagrams
    }

    /// The batch as the content of an event.
    pub(crate) fn encode(&self) -> String {
        use base64::Engine as _;

        BASE64.encode(&self.bytes)
    }
}

/// A batch read back.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Decoded {
    /// The endpoint id the sender wrote in the header. Nothing proves it: any member that holds
    /// the mesh key can write any id. The frame inside each datagram names its sender too.
    pub(crate) from: [u8; ID_LEN],
    /// The datagrams, in the order they were pushed.
    pub(crate) datagrams: Vec<Vec<u8>>,
}

/// Read the content of an event as a batch.
pub(crate) fn decode(content: &str) -> Result<Decoded, BatchError> {
    use base64::Engine as _;

    if content.len() > MAX_BATCH_BYTES.div_ceil(3) * 4 {
        return Err(BatchError::TooLong);
    }
    let bytes = BASE64.decode(content).map_err(|_| BatchError::NotBase64)?;
    let split: Option<(&[u8; HEADER_LEN], &[u8])> = bytes.split_first_chunk();
    let (header, mut rest) = split.ok_or(BatchError::Truncated)?;
    let from: &[u8; ID_LEN] = header.first_chunk().ok_or(BatchError::Truncated)?;
    let mut datagrams = Vec::new();
    while !rest.is_empty() {
        let framed: Option<(&[u8; PREFIX_LEN], &[u8])> = rest.split_first_chunk();
        let (prefix, after) = framed.ok_or(BatchError::Truncated)?;
        let length = usize::from(u16::from_be_bytes(*prefix));
        if length > MAX_DATAGRAM {
            return Err(BatchError::DatagramTooLong);
        }
        let (datagram, after) = after
            .split_at_checked(length)
            .ok_or(BatchError::Truncated)?;
        datagrams.push(datagram.to_vec());
        rest = after;
    }
    Ok(Decoded {
        from: *from,
        datagrams,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BASE64, Batch, BatchError, HEADER_LEN, ID_LEN, MAX_BATCH_BYTES, MAX_DATAGRAM, decode,
    };
    use crate::event::{Event, Keys};
    use crate::lane::Lane;
    use crate::wire;
    use base64::Engine as _;

    const FROM: [u8; ID_LEN] = [7u8; ID_LEN];

    #[test]
    fn datagrams_come_back_in_order_with_the_sender() {
        let mut batch = Batch::new(&FROM, 0);
        for datagram in [&b"one"[..], b"", b"three"] {
            assert!(batch.push(datagram), "the datagram fits");
        }
        let decoded = decode(&batch.encode()).expect("a batch decodes");
        assert_eq!(decoded.from, FROM, "the sender id");
        assert_eq!(
            decoded.datagrams,
            vec![b"one".to_vec(), Vec::new(), b"three".to_vec()],
            "the datagrams in order, an empty one too"
        );
    }

    #[test]
    fn the_serial_makes_equal_batches_encode_differently() {
        let (mut first, mut second) = (Batch::new(&FROM, 1), Batch::new(&FROM, 2));
        for batch in [&mut first, &mut second] {
            assert!(batch.push(b"same"), "the datagram fits");
        }
        assert_ne!(first.encode(), second.encode(), "two serials, two contents");
        assert_eq!(
            decode(&first.encode()).expect("decodes"),
            decode(&second.encode()).expect("decodes"),
            "the receiver reads the same sender and datagrams"
        );
    }

    #[test]
    fn a_batch_refuses_what_does_not_fit() {
        let mut batch = Batch::new(&FROM, 0);
        assert!(
            !batch.push(&vec![0u8; MAX_DATAGRAM + 1]),
            "a datagram over the ceiling is not carried"
        );
        assert!(
            batch.is_empty(),
            "a refused datagram leaves the batch empty"
        );
        let datagram = vec![1u8; MAX_DATAGRAM];
        let mut pushed = 0;
        while batch.push(&datagram) {
            pushed += 1;
        }
        assert_eq!(
            pushed,
            (MAX_BATCH_BYTES - HEADER_LEN) / (MAX_DATAGRAM + 2),
            "the batch stops at its byte ceiling"
        );
        assert!(
            BASE64.decode(batch.encode()).expect("base64").len() <= MAX_BATCH_BYTES,
            "the bytes stay under the ceiling"
        );
    }

    /// A relay frame holds `128 KiB`. The fullest batch, as an EVENT frame, stays under the
    /// 130816 bytes the plan allows.
    #[test]
    fn the_fullest_batch_makes_an_event_under_130816_bytes() {
        let mut batch = Batch::new(&FROM, 0);
        while batch.push(&[0xab; 1]) {}
        let keys = Keys::generate();
        let event = Event::sign(Lane::Data, &keys, 1_700_000_000, &[9u8; 32], batch.encode());
        let frame = wire::event(&event);
        assert!(frame.len() < 130_816, "the frame is {} bytes", frame.len());
        assert!(frame.len() > 20_000, "the batch was full: {}", frame.len());
    }

    #[test]
    fn what_is_not_a_batch_is_refused() {
        assert_eq!(decode("%%%"), Err(BatchError::NotBase64), "not base64");
        assert_eq!(
            decode(&BASE64.encode([1u8; HEADER_LEN - 1])),
            Err(BatchError::Truncated),
            "the id is cut"
        );
        let mut cut_prefix = vec![0u8; HEADER_LEN];
        cut_prefix.push(0);
        assert_eq!(
            decode(&BASE64.encode(&cut_prefix)),
            Err(BatchError::Truncated),
            "a prefix is cut"
        );
        let mut cut_datagram = vec![0u8; HEADER_LEN];
        cut_datagram.extend_from_slice(&[0, 5, 1, 2]);
        assert_eq!(
            decode(&BASE64.encode(&cut_datagram)),
            Err(BatchError::Truncated),
            "a datagram is cut"
        );
        let mut long_datagram = vec![0u8; HEADER_LEN];
        long_datagram
            .extend_from_slice(&u16::try_from(MAX_DATAGRAM + 1).unwrap_or(0).to_be_bytes());
        long_datagram.resize(HEADER_LEN + 2 + MAX_DATAGRAM + 1, 0);
        assert_eq!(
            decode(&BASE64.encode(&long_datagram)),
            Err(BatchError::DatagramTooLong),
            "a datagram over the ceiling"
        );
        assert_eq!(
            decode(&"A".repeat(40_000)),
            Err(BatchError::TooLong),
            "text longer than any batch"
        );
    }
}
