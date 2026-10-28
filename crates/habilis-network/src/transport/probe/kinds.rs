//! The kinds of path, and how they rank.

use super::path_kind::PathKind;

use iroh::endpoint::Connection;

pub(crate) fn path_list(conn: &Connection) -> Vec<String> {
    conn.paths()
        .iter()
        .map(|path| {
            format!(
                "{:?}{}",
                path.remote_addr(),
                if path.is_selected() { " selected" } else { "" }
            )
        })
        .collect()
}

pub(crate) fn selected_kind(conn: &Connection) -> PathKind {
    conn.paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map_or(PathKind::None, |path| {
            if path.is_ip() {
                PathKind::Ip
            } else if path.is_relay() {
                PathKind::Relay
            } else if let iroh::TransportAddr::Custom(addr) = path.remote_addr() {
                custom_kind(addr.id())
            } else {
                // A kind of address that iroh does not have today.
                PathKind::Multihop
            }
        })
}

/// Pure: the kind of a custom path by the id of its transport.
pub(crate) fn custom_kind(id: u64) -> PathKind {
    if id == habilis_network_iroh_webrtc_transport::WEBRTC_TRANSPORT_ID {
        PathKind::WebRtc
    } else if id == habilis_network_iroh_gossip_transport::GOSSIP_TRANSPORT_ID {
        PathKind::Gossip
    } else {
        PathKind::Multihop
    }
}

/// Pure: whether the gossip transport may carry frames to a pair whose selected path is `kind`.
/// The admission table calls it on the best path of each peer (see `gossip_view`).
pub(crate) fn allow_for(kind: PathKind) -> bool {
    !matches!(kind, PathKind::Ip | PathKind::WebRtc | PathKind::Multihop)
}

/// Pure: the kind that stands for a peer whose connections read as `kinds`: the best of them, in
/// the order of the ladder (IP, a session, multihop, the relay), and `None` when no connection has
/// a selected path yet. iroh selects a path per connection, and a link that is still on the relay
/// can sit beside a connection that is already direct: the first reading must not speak for the
/// pair. The order is the ladder's: do not reorder it (`path_action` relies on `[WebRtc, Ip]`
/// reading IP).
pub(crate) fn best_kind(kinds: impl IntoIterator<Item = PathKind>) -> Option<PathKind> {
    let rank = |kind: &PathKind| match kind {
        PathKind::Ip => 0,
        PathKind::WebRtc => 1,
        PathKind::Multihop => 2,
        PathKind::Gossip => 3,
        PathKind::Relay => 4,
        PathKind::None => 5,
    };
    kinds
        .into_iter()
        .filter(|kind| *kind != PathKind::None)
        .min_by_key(rank)
}

/// Pure: whether any connection with a selected path reads as something below IP. A session
/// that one connection rides is in use, whatever the others read: [`best_kind`] would read IP
/// for `[Ip, WebRtc]`, and the session must stay.
pub(crate) fn any_not_ip(kinds: impl IntoIterator<Item = PathKind>) -> bool {
    kinds
        .into_iter()
        .any(|kind| !matches!(kind, PathKind::Ip | PathKind::None))
}

/// Pure: the kind of a pair's selected path, from the watcher's last report if it
/// has one, else from any live connection of the admission table. A pair that only
/// gossips has no pooled connection and so no watcher, but its gossip connection
/// is in the table.
pub(crate) fn pair_kind(watched: Option<PathKind>, admitted: Option<PathKind>) -> Option<PathKind> {
    watched.filter(|kind| *kind != PathKind::None).or(admitted)
}
