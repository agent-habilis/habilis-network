/// How far a member has got on its way into the mesh. A member holds each step in a set while the
/// step is true, so one step can hold while another is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Standing {
    /// Goes off when the receiver stream terminally ends; IPC keeps working for `msg` / `poll`
    /// after that.
    GossipOpen,
    /// Set once we've broadcast our arrival (`joined` + `PeerInfo`). The announce is deferred to
    /// the first `NeighborUp` so it isn't lost into an unconnected overlay; subsequent neighbors
    /// only get a (log-invisible) `PeerInfo` re-send.
    Announced,
    /// Set once we have a link to a *real peer* (a non-rendezvous `NeighborUp`). `Announced` is
    /// set on any neighbor, including the rendezvous relay, which is too early to deliver user
    /// content (the relay path may not be converged). Outbound user messages are buffered until
    /// `Meshed`, then flushed, so the first message after a join can't be a lost one-shot.
    Meshed,
    /// `Meshed` was cleared by a fault path (starvation recovery / hard resume edge) rather than
    /// never having been set. Gates `note_inbound`'s meshed-restore so a fresh joiner's pre-mesh
    /// inbound never flips `Meshed` early; only a degraded node heals on traffic.
    Degraded,
    /// Whether the event loop is serving IPC yet. Not set at start (the pre-loop state-file write
    /// reports "identity up, not yet serving"); set once the loop is draining, so a state-file
    /// reader (a readiness gate) can gate on a write that means the daemon will answer.
    Ready,
}
