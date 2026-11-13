use std::error::Error;
use std::fmt;

/// Why an answer of a chunk fetch is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum FetchError {
    /// The holder does not have what was asked for, or does not say. Both look the same on the wire.
    Absent,
    /// The bytes are not a request or an answer of the protocol.
    Malformed(&'static str),
    /// The map names another size than the pointer of the slice.
    SizeMismatch { declared: u64, expected: u64 },
    /// The leaves of the map do not hash to the root that was asked for.
    RootMismatch,
    /// A chunk does not hash to its leaf of the map.
    CorruptChunk { index: usize },
    /// A chunk is longer than the map says: the holder sends more than it declared.
    PastDeclaredSize { index: usize },
    /// A chunk is shorter than the map says.
    ShortChunk { index: usize },
}

impl fmt::Display for FetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => write!(formatter, "the holder does not have it"),
            Self::Malformed(what) => write!(formatter, "malformed: {what}"),
            Self::SizeMismatch { declared, expected } => write!(
                formatter,
                "the map has {declared} bytes, and the pointer names {expected}"
            ),
            Self::RootMismatch => write!(formatter, "the map does not hash to the root"),
            Self::CorruptChunk { index } => {
                write!(formatter, "chunk {index} does not hash to its leaf")
            }
            Self::PastDeclaredSize { index } => {
                write!(formatter, "chunk {index} is longer than the map says")
            }
            Self::ShortChunk { index } => {
                write!(formatter, "chunk {index} is shorter than the map says")
            }
        }
    }
}

impl Error for FetchError {}
