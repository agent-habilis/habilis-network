//! The bearer secret of a stream.

use std::fmt;

use super::SECRET_LEN;
use zeroize::Zeroizing;

/// The bearer secret of a stream. Whoever holds it can take the consumer slot,
/// so `Debug` prints no byte, and the type has no `PartialEq`: compare two with
/// [`habilis_network::protocol::ct_eq`] on [`Self::as_bytes`]. Its bytes are wiped on drop (best-effort: a
/// copy that a caller made from [`Self::as_bytes`] is not tracked).
#[derive(Clone)]
pub struct StreamSecret(pub(super) Zeroizing<[u8; SECRET_LEN]>);

impl StreamSecret {
    /// Wrap the 32 bytes of a secret. The array passed in is a copy that the
    /// caller still holds: keep it in a [`Zeroizing`] when it is a secret.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Take a buffer that is already wiped on drop, whole, so that the code
    /// makes no plain copy of the secret on the way in. This is the constructor
    /// for a secret that is already in a [`Zeroizing`] (bytes read off a stream,
    /// a random draw). [`Self::from_bytes`] stays for raw input at an edge.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; SECRET_LEN]>) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

// The only field is a `Zeroizing`.
impl zeroize::ZeroizeOnDrop for StreamSecret {}

impl fmt::Debug for StreamSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamSecret(***)")
    }
}
