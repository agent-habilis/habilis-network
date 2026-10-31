//! What every derivation of a mesh keys on.

use super::{Seed, SymmetricKey};

/// What every derivation of a mesh keys on: the wire [`Seed`] of an open
/// mesh, or the [`SymmetricKey`] that a password or an invite put in its
/// place. Two types feed one derivation because a mesh has one or the other,
/// never both, and the derivations are the same hash over either.
#[derive(Clone, Copy)]
pub(crate) enum Keying<'key> {
    Wire(&'key Seed),
    Secret(&'key SymmetricKey),
}

impl Keying<'_> {
    pub(super) fn bytes(&self) -> &[u8; 32] {
        match self {
            Self::Wire(seed) => seed.as_bytes(),
            Self::Secret(key) => key.as_bytes(),
        }
    }
}
