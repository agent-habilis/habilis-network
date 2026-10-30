/// A fact about this node's rendezvous, the co-hosted bootstrap point of the mesh. A node holds
/// each fact in a set while the fact is true, so one fact can hold while another is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RendezvousFlag {
    /// Whether the gossip overlay currently links us to the co-hosted rendezvous (its
    /// `NeighborUp`/`NeighborDown` arms drive it). Gates the healer's connect-probe: probing the
    /// rendezvous while a live link exists makes the beacon's gossip *adopt* the probe connection
    /// and then mark the peer down when the probe handle drops — one rendezvous-link flap per heal
    /// tick, forever (the 2026-05-30 soak's residual flap).
    Linked,
    /// Whether we let go of the rendezvous link on purpose (see
    /// `should_release_rendezvous`). The `NeighborDown` that follows
    /// The `NeighborDown` that follows is then no loss, so nothing re-grafts it or arms a reclaim
    /// for it. Cleared when the link comes back.
    Released,
    /// This process co-hosts the rendezvous. Its own link to it keeps the beacon's gossip view
    /// non-empty, which is what lets a joiner be introduced to the mesh: if the host let go as
    /// well, a joiner arriving after the early members had released would find an empty view and
    /// the mesh would split into islands (the 18-node test shows it). So this node never releases
    /// the link.
    HostsRendezvous,
}
