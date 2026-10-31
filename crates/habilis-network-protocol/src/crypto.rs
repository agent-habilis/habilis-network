//! Seed-derived identities and the gossip topic.
//!
//! Concept split: this module owns the seed-derived **identity** (the
//! rendezvous keypair/ports + the gossip topic id, all computed
//! locally by every joiner). The *role* of actually binding and
//! serving the rendezvous — the **beacon** — lives in
//! `habilis-network`'s beacon.
//!
//! The mesh id token carries a random 32-byte `seed` (see
//! [`crate::meshes`]). Every value the mesh needs is derived
//! from it in memory — no stored address, no file:
//!
//! - the gossip topic (`derive_topic_id`),
//! - a well-known **rendezvous endpoint** keypair: every joiner can
//!   compute `rendezvous_id` locally and bootstrap from it without
//!   ever contacting the creator,
//! - (private meshes only) a deterministic loopback port ladder, since
//!   `presets::Minimal` has no pkarr/DNS lookup to resolve
//!   `rendezvous_id` into an address.
//!
//! All derivations are domain-separated SHA-256 so the topic seed, the
//! rendezvous secret key, and the port can never collide for one
//! `seed`.

mod derive;
pub(crate) use derive::{derive_secret, derive_topic_id, topic_seed};
mod keying;
pub(crate) use keying::Keying;
mod password;
pub use password::Password;
pub(crate) use password::{
    PASSWORD_VERIFIER_LEN, invite_wrap_key, password_verifier, stretch_mesh_password,
};
mod rendezvous;
pub(crate) use rendezvous::{
    RENDEZVOUS_LADDER, rendezvous_id, rendezvous_ports, rendezvous_secret,
};
mod seed;
pub use seed::Seed;
mod symmetric_key;
pub use symmetric_key::SymmetricKey;
mod ticket_auth;
pub use ticket_auth::TicketAuth;
mod ticket_secret;
pub use ticket_secret::TicketSecret;

/// Constant-time equality for 32-byte auth tokens: XOR-fold the full pair so
/// the cost never depends on where the first mismatch lies (a short-circuit
/// `==` is a timing oracle on the secret).
///
/// # Examples
///
/// Two tokens compare equal only when all 32 bytes match.
///
/// ```
/// use habilis_network_protocol::ct_eq;
///
/// let token = [7u8; 32];
/// assert!(ct_eq(&token, &[7u8; 32]));
///
/// let mut other = token;
/// other[31] ^= 1;
/// assert!(!ct_eq(&token, &other));
/// ```
#[must_use]
pub fn ct_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (lhs, rhs)| acc | (lhs ^ rhs))
        == 0
}
