//! The public id a producer files a stream under.

use std::fmt;

use super::ID_LEN;
use habilis_network::protocol::identity::write_hex;

/// The public id a producer files a stream under. It names the stream and
/// opens nothing: [`super::StreamSecret`] does that.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId([u8; ID_LEN]);

impl StreamId {
    /// Wrap the 16 bytes of an id.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "StreamId({self})")
    }
}
