//! The public id a producer files a stream under.

use std::fmt;

use super::ID_LEN;
use habilis_network::protocol::identity;

/// The public id a producer files a stream under. It names the stream and
/// opens nothing: [`super::StreamSecret`] does that.
///
/// # Examples
///
/// A stream id keeps the bytes it was made from.
///
/// ```
/// use habilis_network_stream::{ID_LEN, StreamId};
///
/// let id = StreamId::from([7u8; ID_LEN]);
/// assert_eq!(id.as_bytes(), &[7u8; ID_LEN]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId([u8; ID_LEN]);

impl From<[u8; ID_LEN]> for StreamId {
    fn from(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl StreamId {
    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        identity::write_hex(formatter, &self.0)
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "StreamId({self})")
    }
}
