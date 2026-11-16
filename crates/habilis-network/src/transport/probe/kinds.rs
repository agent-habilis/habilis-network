//! The kinds of path, and how they rank.

use super::path_kind::PathKind;

use iroh::endpoint::{Connection, Path};

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
        .find(Path::is_selected)
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

/// Like [`selected_kind`], but a selected path that a test took away from `local` with the block
/// hooks reads as no path. The selector refuses such a path and iroh may still hold it as the
/// selected one, so the connection would read as well served while no payload may ride it. Without
/// the test hooks nothing is blocked, and this is [`selected_kind`].
pub(crate) fn selected_kind_unblocked(
    connection: &Connection,
    local: iroh::EndpointId,
) -> PathKind {
    let paths = connection.paths();
    let selected = paths.iter().find(Path::is_selected);
    let address: Option<iroh::TransportAddr> = selected.map(|path| path.remote_addr().clone());
    let remote = connection.remote_id();
    if address.is_some_and(|address| path_is_blocked(local, remote, &address)) {
        PathKind::None
    } else {
        selected_kind(connection)
    }
}

/// Pure: whether a test took the path with `address` to `remote` away from `local`: a block of the
/// rung, or a block of the rung to this remote only.
pub(crate) fn path_is_blocked(
    local: iroh::EndpointId,
    remote: iroh::EndpointId,
    address: &iroh::TransportAddr,
) -> bool {
    use habilis_network_iroh_transport_util as transport_util;
    let (rung, ip) = match address {
        iroh::TransportAddr::Ip(socket) => (transport_util::Rung::Ip, Some(*socket)),
        iroh::TransportAddr::Relay(_) => (transport_util::Rung::Relay, None),
        iroh::TransportAddr::Custom(custom) => (transport_util::custom_rung(custom.id()), None),
        _ => (transport_util::Rung::Other, None),
    };
    transport_util::is_blocked_to(local, rung, ip, Some(remote))
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
/// `kinds`. Only a pair with no other usable path: Nostr is the last fallback, and an address
/// that iroh adds as a keep-alive backup to every connection would put a rate-limited relay in
/// the path of every pair. A relay path is usable only where `relay_carries` (the mesh lets the
/// relay carry payload): on a lookup-only relay the pair has no path there. A connection with no
/// path yet is allowed. A pair with no connection is allowed only when the engine `wanted` Nostr
/// for it (its first flight rides what the pair has).
pub(crate) fn nostr_allow_for(kinds: &[PathKind], relay_carries: bool, wanted: bool) -> bool {
    let usable = kinds.iter().any(|kind| match kind {
        PathKind::None | PathKind::Nostr => false,
        PathKind::Relay => relay_carries,
        PathKind::Ip | PathKind::WebRtc | PathKind::Multihop | PathKind::Gossip => true,
    });
    if usable {
        false
    } else if kinds.is_empty() {
        wanted
    } else {
        true
    }
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

    /// A path that a test took away from a node reads as no path to that node: the selector
    /// refuses it, and iroh may still hold it as the selected one. Without the test hooks nothing
    /// is ever blocked.
    #[cfg(feature = "iroh-test-utils")]
    #[test]
    fn a_path_that_a_test_blocked_reads_as_no_path() {
        use habilis_network_iroh_transport_util::Rung;
        let _guard = ::habilis_network_test_tracing::init();
        let local = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let remote = iroh::SecretKey::from_bytes(&[10; 32]).public();
        let ip = iroh::TransportAddr::Ip(([127, 0, 0, 1], 9).into());
        let relay = iroh::TransportAddr::Relay("https://relay.invalid".parse().expect("relay url"));
        assert!(
            !super::path_is_blocked(local, remote, &ip),
            "nothing blocked"
        );
        habilis_network_iroh_webrtc_transport::block_rung(local, Rung::Ip, true);
        assert!(
            super::path_is_blocked(local, remote, &ip),
            "the IP rung is blocked for this node"
        );
        assert!(
            !super::path_is_blocked(local, remote, &relay),
            "the relay rung is not"
        );
        let other = iroh::SecretKey::from_bytes(&[9; 32]).public();
        assert!(
            !super::path_is_blocked(other, remote, &ip),
            "another node is not affected"
        );
        habilis_network_iroh_webrtc_transport::block_rung(local, Rung::Ip, false);
        assert!(
            !super::path_is_blocked(local, remote, &ip),
            "the block is lifted"
        );
        habilis_network_iroh_webrtc_transport::block_rung_to(local, Rung::Relay, remote, true);
        assert!(
            super::path_is_blocked(local, remote, &relay),
            "a block of the relay rung to this remote only"
        );
        assert!(
            !super::path_is_blocked(local, other, &relay),
            "another remote is not blocked"
        );
        habilis_network_iroh_webrtc_transport::block_rung_to(local, Rung::Relay, remote, false);
    }

    #[test]
    fn gossip_frames_may_ride_a_pair_that_is_only_on_nostr() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(allow_for(PathKind::Nostr), "Nostr is below gossip");
    }

    /// The Nostr transport carries a pair that has no other usable path: iroh adds a Nostr
    /// address as a keep-alive backup on every connection otherwise. A relay path is usable only
    /// where the relay carries payload; on a lookup-only relay it is no path. A pair with no
    /// connection is allowed only when the engine wants Nostr for it.
    #[test]
    fn the_nostr_path_is_allowed_only_for_a_pair_with_no_other_usable_path() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !nostr_allow_for(&[], true, false),
            "a new pair rides what it has first"
        );
        assert!(
            nostr_allow_for(&[], true, true),
            "a pair that the engine wants Nostr for"
        );
        assert!(
            nostr_allow_for(&[PathKind::None], true, false),
            "no path is selected yet"
        );
        assert!(
            nostr_allow_for(&[PathKind::Nostr], true, false),
            "Nostr already carries it"
        );
        for other in [
            PathKind::Ip,
            PathKind::WebRtc,
            PathKind::Multihop,
            PathKind::Gossip,
        ] {
            for wanted in [false, true] {
                assert!(
                    !nostr_allow_for(&[other], false, wanted),
                    "{other:?} is selected, so Nostr is not needed"
                );
                assert!(
                    !nostr_allow_for(&[PathKind::Nostr, other], false, wanted),
                    "one connection on {other:?} is enough to refuse Nostr"
                );
            }
        }
        assert!(
            !nostr_allow_for(&[PathKind::Relay], true, true),
            "a relay that carries payload serves the pair"
        );
        assert!(
            nostr_allow_for(&[PathKind::Relay], false, false),
            "a lookup-only relay carries no payload: the pair has no usable path"
        );
    }
}
