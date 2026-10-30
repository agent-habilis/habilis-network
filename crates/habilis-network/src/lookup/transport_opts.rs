use crate::protocol::mesh::TransportPolicy;

/// Whether gossip is one of the paths of an instance: a two-way choice, kept as an enum so that
/// [`TransportOpts`] holds no more than three bools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum GossipPath {
    /// Gossip carries no data.
    #[default]
    Off,
    /// Gossip carries data.
    On,
}

impl GossipPath {
    /// Whether gossip carries data.
    #[must_use]
    pub fn is_on(self) -> bool {
        matches!(self, Self::On)
    }
}

impl From<bool> for GossipPath {
    fn from(on: bool) -> Self {
        if on { Self::On } else { Self::Off }
    }
}

/// Which transports this *instance* may carry data on.
///
/// Deliberately **not** part of the mesh id. [`LookupOpts`](crate::protocol::mesh::LookupOpts) is mixed into
/// `derive_topic_id` so that every member provably agrees on where to
/// rendezvous — right for discovery, and exactly wrong for transports: a
/// browser only ever has relay and `WebRTC`, a native peer also has IP and
/// multihop. Baking transports into mesh identity would mean a browser could
/// never join a mesh a CLI created. So this is local, per-peer, and reconciled
/// per pair by ICE and iroh's own path selection.
///
/// `Default` is "everything this target has".
///
/// # Examples
///
/// The transport options say which transports a node turns on. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::TransportOpts;
///
/// # fn demo(opts: TransportOpts) -> bool {
/// opts.udp
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransportOpts {
    /// QUIC on direct and hole-punched UDP paths, plus the address lookups
    /// that find them. Cleared by a WebRTC-only instance.
    pub udp: bool,
    /// The relay. **Never cleared by `webrtc`-only**, because the relay is the
    /// rendezvous: it carries the bootstrap dial and the JSEP exchange. Clearing
    /// it would sever the very thing that lets a `WebRTC` session be negotiated.
    ///
    /// Not the mesh policy: this says whether *this node* registers a relay
    /// transport at all, the way `udp` and `webrtc` do. Whether the relay may
    /// carry payload is mesh-wide and lives in the id, as
    /// `protocol::TransportPolicy::relay_transport`.
    pub relay: bool,
    /// QUIC over a `WebRTC` data channel. Off, the transport is not registered
    /// on the endpoint, no offer is answered and none is made — so a pair
    /// with IP cleared too has the relay as its only path.
    pub webrtc: bool,
    /// Gossip as a path: the mesh's own topic carries the QUIC packets of a pair that has no
    /// other path. Off by default, and set only by [`Self::within`]: it is a choice of the
    /// mesh, which every member makes the same way, and not a limit of this node.
    pub gossip: GossipPath,
}

impl TransportOpts {
    /// Set the UDP transport.
    #[must_use]
    pub fn udp(
        mut self,
        // true enables the UDP transport
        udp: bool,
    ) -> Self {
        self.udp = udp;
        self
    }

    /// The relay to dial for the lookup, instead of the one the mesh names.
    #[must_use]
    pub fn relay(
        mut self,
        // true enables the relay
        relay: bool,
    ) -> Self {
        self.relay = relay;
        self
    }

    /// Set the WebRTC transport.
    #[must_use]
    pub fn webrtc(
        mut self,
        // true enables the WebRTC transport
        webrtc: bool,
    ) -> Self {
        self.webrtc = webrtc;
        self
    }

    /// Set the gossip transport.
    #[must_use]
    pub fn gossip(
        mut self,
        // true enables the gossip transport
        gossip: bool,
    ) -> Self {
        self.gossip = GossipPath::from(gossip);
        self
    }
}

impl Default for TransportOpts {
    fn default() -> Self {
        Self {
            udp: true,
            relay: true,
            webrtc: true,
            gossip: GossipPath::Off,
        }
    }
}

impl TransportOpts {
    /// Data-plane exclusivity for `WebRTC`: IP paths cleared, relay kept for
    /// rendezvous and signalling.
    ///
    /// The intent is to make a WebRTC-only run *falsifiable* — with IP cleared,
    /// any data path that is not the `WebRTC` one is a failure rather than a
    /// silent fallback. Note this is not the transport crate's
    /// `ExclusivePreset`, which clears relay transports outright and would
    /// leave nothing to negotiate over.
    ///
    /// # History, because the code once said otherwise
    ///
    /// This was documented as broken: with IP cleared, peers appeared to see
    /// each other on the roster but never link (`link_len=0, meshed=false`) and
    /// never attempt a JSEP round. It **does not reproduce** — verified twice,
    /// mixed (one peer IP-less, one not) and with both peers IP-less; each run
    /// reaches `link_len=1, meshed=true` with a session in each direction.
    ///
    /// The original failure was most likely environmental: it was measured
    /// while a pile of stale peers from earlier runs were still holding relay
    /// registrations for the same meshes. Worth knowing if it comes back —
    /// check for orphaned processes before concluding the flag is at fault.
    ///
    /// One real bug *was* found and fixed along the way: `clear_address_lookup()`
    /// must not be part of this. `add_peer_addr` registers a `MemoryLookup` on
    /// the endpoint and the zero-lookup rendezvous bootstrap **is** that
    /// registration, so clearing the store leaves a peer unable to dial anything
    /// while still showing a healthy roster — which reads like a NAT problem and
    /// is not one.
    #[must_use]
    pub fn webrtc_only() -> Self {
        Self {
            udp: false,
            relay: true,
            webrtc: true,
            gossip: GossipPath::Off,
        }
    }
}

impl TransportOpts {
    /// These paths, less any the mesh's transport list leaves out. Never
    /// widens: a path this node lacks stays off whatever the mesh allows, and
    /// a browser has no UDP at all.
    #[must_use]
    pub fn within(self, policy: &TransportPolicy) -> Self {
        Self {
            udp: self.udp && policy.udp && !cfg!(target_arch = "wasm32"),
            webrtc: self.webrtc && policy.webrtc,
            // Set, not narrowed: the mesh decides, and it needs a direct path to ride.
            gossip: GossipPath::from(
                policy.gossip && (policy.udp || policy.webrtc) && !cfg!(target_arch = "wasm32"),
            ),
            ..self
        }
    }

    /// Whether these paths carry payload on a node with no UDP, such as a
    /// browser: only a data channel or relay payload can.
    #[must_use]
    pub fn carry_without_udp(self, policy: &TransportPolicy) -> bool {
        self.webrtc || policy.relay_transport
    }
}
