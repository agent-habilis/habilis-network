//! A graft request and the peer it targets.

use iroh::EndpointId;

use crate::daemon::state::EventLoopState;
use crate::util::clock::Instant;

use crate::transport;
/// How a graft asks for a link.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GraftRequest {
    /// Always accepted: a peer with a full view drops a neighbor to make room.
    Join,
    /// Low priority: a peer with a full view refuses and keeps its neighbors.
    Neighbor,
    /// No request: the peer refused lately and its wait runs.
    Skip,
}

/// The peer that a graft asks for, and the rendezvous it is told apart from: the rendezvous is
/// asked with a `Join`, and a swap of the two compiles, since both are an `EndpointId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GraftTarget {
    pub(crate) peer: EndpointId,
    pub(crate) rendezvous: EndpointId,
}

/// The request that grafts `peer`. The rendezvous gets a `Join`, because a low
/// priority request to a peer that holds a tombstone for us is refused for ever.
/// Every other graft only fills a view, and must not make a full one drop a neighbor.
///
/// A peer that refused a `Neighbor` request lately is skipped by a paced graft, for the wait of
/// its backoff (`GraftBackoff`). The `PeerInfo` graft is not held, but its request is recorded
/// too, so that its silence reads as a refusal.
///
/// A low priority request evicts nobody, so a node that arrives when every other node is
/// full gets no link from it. A `paced` graft (the fill tick, a proven direct path) asks
/// with a `Join` instead when the node is starved: it held two or more links fewer than G
/// for `STARVED`, at most once per `STARVED`. A `PeerInfo` graft is not paced.
pub(crate) fn graft_request(
    state: &mut EventLoopState,
    target: GraftTarget,
    max_peers: usize,
    now: Instant,
    paced: bool,
) -> GraftRequest {
    let GraftTarget {
        peer,
        rendezvous: rendezvous_id,
    } = target;
    if peer == rendezvous_id {
        return GraftRequest::Join;
    }
    state.note_link_count(state.linked_endpoints.len(), max_peers, now);
    if paced && state.starved_join_due(now) {
        // A `Join` is not refused, so it ignores the backoff of the peer.
        GraftRequest::Join
    } else if paced && state.graft_backoff.is_blocked(&peer, now) {
        tracing::debug!(target: transport::LOG_TARGET, %peer, "graft skipped: the peer refused lately");
        GraftRequest::Skip
    } else {
        state.graft_backoff.asked(peer, now);
        GraftRequest::Neighbor
    }
}
