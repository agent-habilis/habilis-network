//! The bearer secret of a ticket.

use zeroize::Zeroizing;

use std::fmt;
/// The 32-byte bearer secret of a ticket. Whoever holds it can redeem the
/// ticket, so `Debug` prints no byte, and the type has no `PartialEq`: compare
/// two with [`super::ct_eq`] on [`Self::as_bytes`], which does not stop at the first
/// byte that differs. Its bytes are wiped on drop (best-effort: a copy that
/// a caller made from [`Self::as_bytes`] is not tracked).
///
/// A raw array is not a secret, so a swap with another 32-byte value does not
/// compile:
///
/// ```compile_fail,E0308
/// use habilis_network_protocol::TicketAuth;
///
/// let raw = [0u8; 32];
/// let _ = TicketAuth::blob(&raw, None);
/// ```
#[derive(Clone)]
pub struct TicketSecret(pub(super) Zeroizing<[u8; 32]>);

/// Wrap 32 raw bytes. The array passed in is a copy that the caller still
/// holds: keep it in a [`Zeroizing`] when it is a secret.
impl From<[u8; 32]> for TicketSecret {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// Take a buffer that is already wiped on drop, whole, so that no plain
/// copy of the secret exists on the way in. This is the conversion for a
/// secret that is already in a [`Zeroizing`] (a stretch, a salt or a token
/// read off a stream). The `[u8; 32]` conversion stays for raw input at an edge.
impl From<Zeroizing<[u8; 32]>> for TicketSecret {
    fn from(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self::from_zeroizing(bytes)
    }
}

impl TicketSecret {
    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Make a ticket secret from its 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Make a ticket secret from bytes already held in zeroizing memory.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

// The only field is a `Zeroizing`.
impl zeroize::ZeroizeOnDrop for TicketSecret {}

impl fmt::Debug for TicketSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TicketSecret(***)")
    }
}
