//! The routing address of a frame: the one peer it is sent to, if any.

use crate::nickname_error::Nickname;

use super::MessageKind;

/// The single addressee of a directed frame — the routing mirror of
/// `gossip::recv::addressed_to_us`. `Some(nick)` for a frame that targets
/// exactly one peer (`Pong`, an application's directed push legs, its RPC
/// request/response); `None` for a broadcast or infrastructure kind. The
/// `habilis-network`'s transport layer send router uses this to decide point-to-point vs gossip.
///
/// Deliberately **separate** from `addressed_to_us`: that answers a *surfacing*
/// question and treats `Pong` as broadcast-visible, whereas routing wants the
/// `Pong`'s addressee too. Merging them would change the surface/relay filter.
///
/// # Examples
///
/// A frame that is not directed names no recipient.
///
/// ```
/// use habilis_network_protocol::messages::{MessageKind, sole_addressee};
///
/// assert!(sole_addressee(&MessageKind::Meta).is_none());
/// ```
#[must_use]
pub fn sole_addressee(kind: &MessageKind) -> Option<&Nickname> {
    match kind {
        MessageKind::Pong { to, .. } => Some(to),
        MessageKind::App { to, .. } => to.as_ref(),
        MessageKind::Presence { .. }
        | MessageKind::PeerInfo
        | MessageKind::Digest
        | MessageKind::Ping
        | MessageKind::State
        | MessageKind::StateDigest
        | MessageKind::Meta
        | MessageKind::MetaDigest
        | MessageKind::LinkState => None,
    }
}
