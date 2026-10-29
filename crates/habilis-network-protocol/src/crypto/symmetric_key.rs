//! A 32-byte key that encrypts, wraps or derives.

use zeroize::Zeroizing;

use super::derive;

/// A 32-byte key that encrypts, wraps or derives: the stretched password key,
/// the invite root, and each key derived from them. Its bytes are wiped on
/// drop, `Debug` prints no byte, and the type has no `PartialEq`: compare two
/// with [`super::ct_eq`] on [`Self::as_bytes`].
/// # Examples
///
/// A key derives a child key for each label, and the child differs from its parent.
///
/// ```
/// use habilis_network_protocol::SymmetricKey;
///
/// let key = SymmetricKey::from([9u8; 32]);
/// let child = key.derive(b"state");
/// assert_ne!(child.as_bytes(), key.as_bytes());
/// ```
#[derive(Clone)]
pub struct SymmetricKey(pub(super) Zeroizing<[u8; 32]>);

/// Wrap 32 raw bytes. The array passed in is a copy that the caller still
/// holds: keep it in a [`Zeroizing`] when it is a secret.
impl From<[u8; 32]> for SymmetricKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Take a buffer that is already wiped on drop, whole, so that no plain
/// copy of the secret exists on the way in. This is the conversion for a
/// secret that is already in a [`Zeroizing`] (a derivation, a stretch, bytes
/// read off a stream). The `[u8; 32]` conversion stays for raw input at an edge.
impl From<Zeroizing<[u8; 32]>> for SymmetricKey {
    fn from(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

impl SymmetricKey {
    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive an independent [`SymmetricKey`] for `label`: the hash of the
    /// key under a domain and the label, held in a wiped buffer.
    ///
    /// # Panics
    /// If `label` exceeds 255 bytes; labels are short internal constants.
    #[must_use]
    pub fn derive(&self, label: &[u8]) -> Self {
        Self::from(derive::derive_secret(&self.0, label))
    }
}

// The only field is a `Zeroizing`.
impl zeroize::ZeroizeOnDrop for SymmetricKey {}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SymmetricKey(***)")
    }
}
