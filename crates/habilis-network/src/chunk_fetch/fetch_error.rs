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
    /// The holder cannot be reached: the dial or the stream failed.
    Unreachable,
    /// The holder did not answer inside the deadline.
    Stalled,
    /// No holder was left to ask, or the list of holders was empty.
    NoSource,
    /// The chunk store could not keep the value.
    Store,
    /// The value does not open with the key of the mesh.
    Seal,
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
            Self::Unreachable => write!(formatter, "the holder cannot be reached"),
            Self::Stalled => write!(formatter, "the holder did not answer in time"),
            Self::NoSource => write!(formatter, "no holder is left to ask"),
            Self::Store => write!(formatter, "the chunk store cannot keep the value"),
            Self::Seal => write!(
                formatter,
                "the value does not open with the key of the mesh"
            ),
        }
    }
}

impl Error for FetchError {}
