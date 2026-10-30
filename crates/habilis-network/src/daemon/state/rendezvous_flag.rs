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
    /// Whether the held rendezvous `WebRTC` session has already survived one
    /// heal tick without producing a link — the arming half of the stale
    /// detach in `negotiate_rendezvous_session`.
    SessionStale,
    /// Whether an IP-capable node's rendezvous JSEP offer is armed. IP
    /// capability normally means the punch inside the bootstrap connection
    /// reaches the rendezvous — but it says nothing about the *beacon*: a
    /// browser-held rendezvous has no UDP to punch to. The first linkless
    /// heal tick sets this instead of offering; the second offers. Cleared
    /// on the rendezvous `NeighborUp`, so a healthy mesh never offers.
    OfferFallback,
    /// Whether this mesh's rendezvous answers JSEP. Only a public beacon does
    /// (`beacon::build_rendezvous_endpoint`); a private ladder rendezvous has
    /// no `WebRTC` handle, so an offer to it can never attach, and the offer
    /// fallback must never arm there.
    AnswersJsep,
    /// Whether the previous rival probe read the public rendezvous as free.
    /// A claim needs two: a single free verdict may have landed inside a
    /// live beacon's rival-re-check release window, and claiming on it is
    /// what created rival copies that shed each other indefinitely. Both
    /// must fall in one arbitration, so every reopen or settle of the
    /// rendezvous identity clears it (`forget_rendezvous_verdict`).
    ProbeReadFree,
    /// Whether grafting the rendezvous must wait for an attached `WebRTC`
    /// session — true for a webrtc-shaped node on a lookup-only mesh; see
    /// `transport::webrtc::rendezvous::rendezvous_graftable`.
    GraftNeedsSession,
}
