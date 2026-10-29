//! The ICE profile a WebRTC session is built with.

/// How far ICE may reach when gathering candidates.
///
/// A loopback mesh must make no external network call — that is the whole
/// promise of `LookupOpts::loopback()` — but `IceConfig::default()` queries two
/// public STUN servers. Without this, threading the share's real lookups into
/// the mesh derivation would have closed one hole (mDNS, DHT, a published
/// rendezvous) and left this one open.
///
/// Target-independent on purpose. The native backend maps it onto `IceConfig`;
/// the browser backend ignores it, because a tab is never a loopback peer — it
/// has no loopback peers to reach.
///
/// # Examples
///
/// An ICE profile says how a WebRTC session finds its candidate addresses. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::direct::IceProfile;
///
/// # fn demo(profile: IceProfile) {
/// let _ = profile;
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct IceProfile {
    /// Gather host candidates only: no STUN, no TURN, no packets off the box.
    pub host_only: bool,
}

impl IceProfile {
    /// Set whether only host candidates are gathered.
    #[must_use]
    pub fn with_host_only(
        mut self,
        // true gathers host candidates only: no STUN, no TURN
        host_only: bool,
    ) -> Self {
        self.host_only = host_only;
        self
    }
}
