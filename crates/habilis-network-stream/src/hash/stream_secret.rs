//! The bearer secret of a stream.

use std::fmt;

use super::SECRET_LEN;
use zeroize::Zeroizing;

/// The bearer secret of a stream. Whoever holds it can take the consumer slot,
/// so `Debug` prints no byte, and the type has no `PartialEq`: compare two with
/// [`habilis_network::protocol::ct_eq`] on [`Self::as_bytes`]. Its bytes are wiped on drop (best-effort: a
/// copy that a caller made from [`Self::as_bytes`] is not tracked).
///
/// # Examples
///
/// A stream secret keeps the bytes it was made from.
///
/// ```
/// use habilis_network_stream::{SECRET_LEN, StreamSecret};
///
/// let secret = StreamSecret::from([3u8; SECRET_LEN]);
/// assert_eq!(secret.as_bytes(), &[3u8; SECRET_LEN]);
/// ```
#[derive(Clone)]
pub struct StreamSecret(pub(super) Zeroizing<[u8; SECRET_LEN]>);

/// Wrap the 32 bytes of a secret. The array passed in is a copy that the
/// caller still holds: keep it in a [`Zeroizing`] when it is a secret.
impl From<[u8; SECRET_LEN]> for StreamSecret {
    fn from(bytes: [u8; SECRET_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// Take a buffer that is already wiped on drop, whole, so that the code
/// makes no plain copy of the secret on the way in. This is the conversion
/// for a secret that is already in a [`Zeroizing`] (bytes read off a stream,
/// a random draw). The `[u8; SECRET_LEN]` conversion stays for raw input at an edge.
impl From<Zeroizing<[u8; SECRET_LEN]>> for StreamSecret {
    fn from(bytes: Zeroizing<[u8; SECRET_LEN]>) -> Self {
        Self::from_zeroizing(bytes)
    }
}

impl StreamSecret {
    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    /// Make a stream secret from its bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Make a stream secret from bytes already held in zeroizing memory.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; SECRET_LEN]>) -> Self {
        Self(bytes)
    }
}

// The only field is a `Zeroizing`.
impl zeroize::ZeroizeOnDrop for StreamSecret {}

impl fmt::Debug for StreamSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamSecret(***)")
    }
}
