//! The well-known rendezvous endpoint of a mesh, and its loopback port ladder.

use super::Keying;
use iroh_base::{EndpointId, SecretKey};

use super::derive;

use std::array;
/// The shared rendezvous endpoint secret key. Every member that
/// co-hosts the rendezvous binds an iroh endpoint to this key, so the
/// node id is stable and joiner-computable. `SecretKey::from_bytes` is
/// infallible — any 32 bytes is a valid Ed25519 secret.
#[must_use]
pub(crate) fn rendezvous_secret(source: Keying<'_>) -> SecretKey {
    SecretKey::from_bytes(&derive::derive_secret(source.bytes(), b"rendezvous"))
}

/// The well-known rendezvous `EndpointId` (public key of
/// [`rendezvous_secret`]). Bootstrap target for every joiner.
#[must_use]
pub(crate) fn rendezvous_id(source: Keying<'_>) -> EndpointId {
    rendezvous_secret(source).public()
}

/// Number of deterministic loopback ports derived per mesh. A single
/// 2-byte-derived port collides across independent private meshes on
/// one host often enough to matter; a ladder lets the beacon skip a
/// foreign-squatted rung instead of hanging. Claim/probe semantics:
/// see `crate::beacon` module docs. A full collision needs all
/// `RENDEZVOUS_LADDER` rungs simultaneously foreign-held — negligible.
pub(crate) const RENDEZVOUS_LADDER: usize = 8;

/// The deterministic loopback port ladder for a private mesh, in
/// preference order. Mapped into `1024..=32767`: above the privileged
/// ports, and below the ephemeral ranges of Linux (32768-60999), macOS
/// and Windows (49152-65535), so the ephemeral bind of another endpoint
/// never lands on a rung. Derived from one `derive_secret` digest (2
/// bytes per rung); rungs are near-certainly distinct, and a rare
/// in-ladder dup merely wastes a rung (harmless).
///
/// # Panics
/// Never in practice: the derived port stays within `u16` by construction.
#[must_use]
pub(crate) fn rendezvous_ports(source: Keying<'_>) -> [u16; RENDEZVOUS_LADDER] {
    const LOW: u32 = 1024;
    const SPAN: u32 = 32767 - LOW + 1; // 31744
    let digest = derive::derive_secret(source.bytes(), b"port");
    array::from_fn(|index| {
        let raw = u32::from(u16::from_le_bytes([
            digest[2 * index],
            digest[2 * index + 1],
        ]));
        u16::try_from(LOW + (raw % SPAN)).expect("LOW + (_ % SPAN) <= 32767")
    })
}
