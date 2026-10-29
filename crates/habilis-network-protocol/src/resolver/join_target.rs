//! What a join accepts: a bare mesh id or an invite.

use std::str::FromStr;

use super::join_target_error::JoinTargetError;
use crate::MeshId;
use crate::invite::InviteTicket;
use crate::mesh::MeshIdError;

/// What a join accepts: a bare base58 mesh id, or a creator-minted bare
/// base58 invite to an invite-only mesh. A shared *string* is not a join
/// target — it derives its own mesh through the topic path. Classified and
/// validated **once**, at the boundary (clap `FromStr` / MCP entry), so
/// `resolve` matches the variant instead of re-sniffing a `String`.
/// # Examples
///
/// Text that is neither a mesh id nor an invite does not parse.
///
/// ```
/// use habilis_network_protocol::JoinTarget;
///
/// let target: Result<JoinTarget, _> = "not a mesh id".parse();
/// assert!(target.is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JoinTarget {
    /// A bare base58 mesh id — resolves with no I/O.
    Mesh(MeshId),
    /// A bare base58 invite to an invite-only mesh — redeemed (signature +
    /// expiry checked, root unwrapped) in `JoinParams`, which holds the
    /// password.
    Invite(InviteTicket),
}

impl FromStr for JoinTarget {
    type Err = JoinTargetError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        // Neither token is branded, so classification is try-decode. The
        // invite goes first because it is the more specific parse: its payload
        // carries a kind byte, and its checksum makes a false positive on a
        // mesh id a ~2^-32 event. Only then does the id decoder see the input.
        if let Ok(invite) = InviteTicket::decode(trimmed) {
            return Ok(JoinTarget::Invite(invite));
        }
        let parsed: Result<MeshId, MeshIdError> = trimmed.parse();
        match parsed {
            Ok(id) => Ok(JoinTarget::Mesh(id)),
            // Wrong length or wrong charset means it was never a token; a
            // payload that decodes far enough to fail on its *contents* is a
            // real id the user mistyped, and keeps its specific reason.
            Err(MeshIdError::Length(_) | MeshIdError::Charset(_)) => {
                Err(JoinTargetError::Unrecognized(trimmed.to_owned()))
            }
            Err(other) => Err(JoinTargetError::MalformedMeshId(other)),
        }
    }
}
