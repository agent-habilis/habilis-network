//! The kinds of path, and how they rank.

use super::path_kind::PathKind;

use iroh::endpoint::Connection;

pub(crate) fn path_list(connection: &Connection) -> Vec<String> {
    connection
        .paths()
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

pub(crate) fn selected_kind(connection: &Connection) -> PathKind {
    connection
        .paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map_or(PathKind::None, |path| {
            if path.is_ip() {
                PathKind::Ip
            } else if path.is_relay() {
                PathKind::Relay
            } else if let iroh::TransportAddr::Custom(address) = path.remote_addr() {
                custom_kind(address.id())
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
    } else if id == habilis_network_iroh_gossip_transport::NOSTR_TRANSPORT_ID {
        PathKind::Nostr
    } else {
        PathKind::Multihop
    }
}

/// Pure: whether the gossip transport may carry frames to a pair whose selected path is `kind`.
/// The admission table calls it on the best path of each peer (see `gossip_view`).
pub(crate) fn allow_for(kind: PathKind) -> bool {
    match kind {
        PathKind::Ip | PathKind::WebRtc | PathKind::Multihop => false,
        PathKind::Gossip | PathKind::Relay | PathKind::Nostr | PathKind::None => true,
    }
}

/// Pure: whether the Nostr transport may carry frames to a pair whose connections read as
/// `kinds`. Only a pair with no other selected path: Nostr is the last fallback, and an address
/// that iroh adds as a keep-alive backup to every connection would put a rate-limited relay in
/// the path of every pair. A connection with no path yet, and a pair with no connection (a
/// handshake), are allowed.
pub(crate) fn nostr_allow_for(kinds: &[PathKind]) -> bool {
    kinds
        .iter()
        .all(|kind| matches!(kind, PathKind::None | PathKind::Nostr))
}

/// Pure: the kind that stands for a peer whose connections read as `kinds`: the best of them, in
/// the order of the ladder (IP, a session, multihop, gossip, the relay, Nostr), and `None` when no connection has
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
        PathKind::Nostr => 5,
        PathKind::None => 6,
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

#[cfg(test)]
mod tests {
    use super::{PathKind, allow_for, best_kind, custom_kind, nostr_allow_for};
    use habilis_network_iroh_gossip_transport::{GOSSIP_TRANSPORT_ID, NOSTR_TRANSPORT_ID};
    use habilis_network_iroh_webrtc_transport::WEBRTC_TRANSPORT_ID;

    #[test]
    fn the_nostr_transport_id_names_the_nostr_kind() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            custom_kind(NOSTR_TRANSPORT_ID),
            PathKind::Nostr,
            "the Nostr id reads as the Nostr kind"
        );
        assert_eq!(custom_kind(WEBRTC_TRANSPORT_ID), PathKind::WebRtc, "webrtc");
        assert_eq!(custom_kind(GOSSIP_TRANSPORT_ID), PathKind::Gossip, "gossip");
        assert_eq!(custom_kind(0x1234), PathKind::Multihop, "an unknown id");
    }

    /// A Nostr path is the last fallback: below the relay, above no path at all.
    #[test]
    fn a_nostr_path_ranks_below_the_relay_and_above_no_path() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            best_kind([PathKind::Nostr, PathKind::Relay]),
            Some(PathKind::Relay),
            "the relay beats Nostr"
        );
        assert_eq!(
            best_kind([PathKind::Nostr, PathKind::Gossip]),
            Some(PathKind::Gossip),
            "gossip beats Nostr"
        );
        assert_eq!(
            best_kind([PathKind::None, PathKind::Nostr]),
            Some(PathKind::Nostr),
            "Nostr is a path, and no path is not"
        );
    }

    #[test]
    fn gossip_frames_may_ride_a_pair_that_is_only_on_nostr() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(allow_for(PathKind::Nostr), "Nostr is below gossip");
    }

    /// The Nostr transport carries a pair that has no other selected path: iroh adds a Nostr
    /// address as a keep-alive backup on every connection otherwise.
    #[test]
    fn the_nostr_path_is_allowed_only_for_a_pair_with_no_other_selected_path() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(nostr_allow_for(&[]), "a new pair has no path yet");
        assert!(
            nostr_allow_for(&[PathKind::None]),
            "no path is selected yet"
        );
        assert!(
            nostr_allow_for(&[PathKind::Nostr]),
            "Nostr already carries it"
        );
        for other in [
            PathKind::Ip,
            PathKind::WebRtc,
            PathKind::Multihop,
            PathKind::Gossip,
            PathKind::Relay,
        ] {
            assert!(
                !nostr_allow_for(&[other]),
                "{other:?} is selected, so Nostr is not needed"
            );
            assert!(
                !nostr_allow_for(&[PathKind::Nostr, other]),
                "one connection on {other:?} is enough to refuse Nostr"
            );
        }
    }
}
