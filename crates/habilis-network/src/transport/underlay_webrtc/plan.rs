//! The plan of which underlay a peer is reached over, and the denials that shape it.

use std::time::Duration;

use crate::transport::UdpTransport;
use crate::transport::probe::PathKind;

use iroh::EndpointId;

/// How long the task of an offer that was turned away as not a neighbor keeps its slot, the first
/// time in a row. Its end wakes the event loop, which offers again: the answerer reads our link
/// vector a few milliseconds after our offer reaches it, so the second offer finds us a neighbor,
/// and the alive tick (30 s) would be too late for the route that the session carries. A peer
/// that turns us away again goes through the backoff of the admission table.
pub(super) const REFUSAL_RETRY: Duration = Duration::from_secs(1);

/// What one tick does with the sessions of the underlay.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Underlay ids to offer a session to.
    pub(crate) dial: Vec<EndpointId>,
    /// Underlay ids whose session is no longer wanted.
    pub(crate) detach: Vec<EndpointId>,
}

/// Decide the sessions of the underlay. `room` is how many new offers the table of sessions admits
/// now (see `SignalAdmission::room`): the lowest ids that are wanted go first, and the others wait for
/// a later tick. `wanted` are the underlay ids of the
/// neighbors that need a session (see [`wanted_underlays`]), and `kept` those whose session
/// stays, that is every neighbor that is not on IP; `held` are the ids with a live
/// session, and `local` is our own underlay id. The lower id dials, so exactly one
/// offer crosses per pair. A session goes only when its neighbor is no longer one
/// or when the pair climbed to IP: an application path that is not read for the
/// moment (an idle connection of the pool closed, say) does not end it, since the
/// session carries the edge of a route that other members use.
pub(crate) fn plan(
    local: EndpointId,
    wanted: &[EndpointId],
    kept: &[EndpointId],
    held: &[EndpointId],
    room: usize,
) -> Plan {
    let fresh = wanted.iter().copied();
    let mut dial: Vec<EndpointId> = fresh
        .filter(|peer| local < *peer && !held.contains(peer))
        .collect();
    // Sorted, so that a cap that bites picks the same peers on each run.
    dial.sort_unstable();
    dial.truncate(room);
    let unkept = held.iter().copied();
    let detach: Vec<EndpointId> = unkept.filter(|peer| !kept.contains(peer)).collect();
    Plan { dial, detach }
}

/// The neighbors that need a session on the underlay: those whose application
/// path is `WebRTC`. `neighbors` pairs each gossip neighbor with its underlay
/// address, and `kind_of` gives the selected path of the application pair.
/// A neighbor that left the list, or whose path climbed to IP, is not wanted, so
/// `plan` detaches its session.
///
/// A node without `udp` has an underlay with no IP socket, so no neighbor reaches it over IP
/// and the session is the only path of the underlay to every neighbor, whatever the
/// application path is. The same holds from the other side: a neighbor whose underlay address
/// has no IP entry (a node without `udp`, read from its signed link vector) is wanted, since
/// it can only be reached by a session. [`plan`] dials only from the lower id, so each end
/// has to want the pair for the lower one to offer.
pub(super) fn wanted_underlays(
    neighbors: &[(EndpointId, iroh::EndpointAddr)],
    local_has_udp: UdpTransport,
    kind_of: impl Fn(EndpointId) -> Option<PathKind>,
) -> Vec<iroh::EndpointAddr> {
    if local_has_udp == UdpTransport::Absent {
        return neighbors
            .iter()
            .map(|(_, address)| address.clone())
            .collect();
    }
    neighbors
        .iter()
        .filter(|(member, address)| {
            kind_of(*member) == Some(PathKind::WebRtc) || address.ip_addrs().next().is_none()
        })
        .map(|(_, address)| address.clone())
        .collect()
}

/// The neighbors that a test did not deny. A denied member gets no underlay session: it is not
/// offered one, it is not allowed to open one, and one that exists is detached.
pub(super) fn undenied(
    neighbors: Vec<(EndpointId, iroh::EndpointAddr)>,
    is_denied: impl Fn(EndpointId) -> bool,
) -> Vec<(EndpointId, iroh::EndpointAddr)> {
    neighbors
        .into_iter()
        .filter(|(member, _)| !is_denied(*member))
        .collect()
}

/// The neighbors whose session stays: all of them except those whose application
/// path is on IP, where the underlay reaches the neighbor over IP already.
pub(super) fn kept_underlays(
    neighbors: &[(EndpointId, iroh::EndpointAddr)],
    kind_of: impl Fn(EndpointId) -> Option<PathKind>,
) -> Vec<EndpointId> {
    neighbors
        .iter()
        .filter(|(member, _)| kind_of(*member) != Some(PathKind::Ip))
        .map(|(_, address)| address.id)
        .collect()
}
