//! The signer of a message: its key and its signature.

use iroh_base::Signature;

use crate::AuthorKey;

/// The key that signed a message and its signature. The two are one value, so a message cannot
/// carry a key with no signature, or a signature with no key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signer {
    pub(super) key: AuthorKey,
    pub(super) signature: Signature,
}

impl Signer {
    /// Pair a key with the signature it made. Nothing checks it here: [`Message::verify_signature_with`]
    /// does.
    #[must_use]
    pub(crate) const fn new(key: AuthorKey, signature: Signature) -> Self {
        Self { key, signature }
    }

    /// The key that signed.
    #[must_use]
    pub const fn key(&self) -> AuthorKey {
        self.key
    }

    /// The detached signature.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}
