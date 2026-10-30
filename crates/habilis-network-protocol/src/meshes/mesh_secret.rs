//! The mesh's derivation secret: the wire seed, a password key or an invite root.

use std::fmt;

use crate::crypto::SymmetricKey;
use iroh_base::SecretKey;

/// The mesh's derivation secret.
///
/// One enum rather than three `Option` fields, because at most one of them was
/// ever meant to be set: an invite-only mesh's password wraps its tickets and
/// never folds into the topic, so "invite root" and "stretched password key"
/// are alternatives, not a pair. The old shape let a caller set both and left
/// [`Mesh::effective_seed`] to pick, which is a precedence rule nothing stated.
#[derive(Clone)]
pub(super) enum MeshSecret {
    /// No password applied and no invite redeemed: derivations use the wire
    /// seed.
    Open,
    /// The Argon2id-stretched password key. Every derivation (topic,
    /// rendezvous, port ladder) switches onto it, so holding the id without
    /// the password computes nothing reachable.
    Password(SymmetricKey),
    /// The invite-only derivation secret, held only in memory: baked into no
    /// hash, carried only by creator-minted invites, so the bare invite-only
    /// hash reaches nothing.
    Invite {
        root: SymmetricKey,
        /// The Ed25519 issuer **private** key — the mint authority, held only
        /// by the creator's live session, so a restart ends minting. `None` on
        /// a redeemer, which can join but never mint.
        issuer: Option<Box<SecretKey>>,
    },
}

impl fmt::Debug for MeshSecret {
    // Redact every variant's payload: the invite root and the issuer secret
    // gate an invite-only mesh, and the stretched key is the password.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => formatter.write_str("Open"),
            Self::Password(_) => formatter.write_str("Password(***)"),
            Self::Invite { issuer, .. } => write!(
                formatter,
                "Invite {{ root: ***, issuer: {} }}",
                if issuer.is_some() { "***" } else { "None" }
            ),
        }
    }
}
