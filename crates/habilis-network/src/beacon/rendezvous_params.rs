use iroh::{EndpointId, RelayUrl, SecretKey};
use iroh_gossip::proto::TopicId;
use tokio::sync::watch;

use crate::protocol::mesh::LookupOpts;

/// Everything [`ensure`] needs to (re)build the rendezvous endpoint.
/// Cheap to clone-hold for the event loop's lifetime.
#[derive(Debug)]
pub(crate) struct RendezvousParams {
    pub(crate) topic_id: TopicId,
    /// `rendezvous_secret(seed)` — the shared identity every co-host binds.
    pub(crate) secret: SecretKey,
    /// Empty when the mesh has lookups (ephemeral, address-lookup
    /// discoverable). Non-empty for a loopback-only mesh: the
    /// deterministic loopback port *ladder* in preference order. The
    /// beacon binds the first free rung; an independent mesh squatting a
    /// rung (seed collision) is skipped instead of mistaken for our own
    /// beacon.
    pub(crate) bind_ports: Vec<u16>,
    /// `rendezvous_id`, memoized for neighbor filtering / bootstrap seeding.
    pub(crate) id: EndpointId,
    /// The peer's resolved lookup config. The beacon
    /// endpoint must publish `rendezvous_id` to the *same*
    /// address-lookups (or a joiner using only mDNS/DHT could never
    /// resolve it) — see `beacon_lookups`.
    pub(crate) lookups: LookupOpts,
    /// The mesh's `transport.relay_transport`. With it off, the beacon holds every
    /// inbound gossip connection — a joiner's first link — until iroh selects
    /// a direct path on it, so no frame ever crosses the relay.
    pub(crate) relay_transport: crate::transport::PayloadPath,
    /// The single relay **rung** the beacon homes on — initialized to
    /// the first ladder rung (optimistic, unprobed) at setup and
    /// corrected off the event loop: a backgrounded startup probe and
    /// the beacon's own liveness self-monitor publish a new rung through
    /// [`Self::rung_tx`], which the event loop applies back here. The
    /// joiner pre-registers `rendezvous_id` at this exact rung
    /// (`daemon::setup::register_rendezvous`), so the beacon must home
    /// here or that relay-direct dial finds nothing. `None` ⇒ no
    /// reachable relay (private mode, relay disabled, or every rung
    /// down) — joiners fall back to mDNS/DHT.
    pub(crate) bootstrap_relay: Option<RelayUrl>,
    /// How the off-loop rung selectors (the backgrounded startup probe
    /// and the beacon co-host's liveness self-monitor) publish a freshly
    /// chosen rung. The event loop holds the matching receiver and, on a
    /// change, updates [`Self::bootstrap_relay`], re-registers the
    /// rendezvous, and re-homes the beacon — so the heavy ladder walk
    /// never runs on the sole event loop.
    pub(crate) rung_tx: watch::Sender<Option<RelayUrl>>,
}

impl RendezvousParams {
    /// Whether the beacon answers JSEP: only a public one carries a `WebRTC`
    /// transport, and a private ladder rendezvous never does.
    pub(crate) fn answers_jsep(&self) -> bool {
        self.bind_ports.is_empty()
    }
}
