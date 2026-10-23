//! The lookup layer: building the iroh endpoint for a mesh mode and
//! wiring the selected lookups onto it. Each lookup mechanism lives in
//! its own submodule — [`mdns`] (LAN multicast), [`dht`] (mainline DHT),
//! and [`relay`] (the relay ladder + bootstrap-rung selection/failover).

#[cfg(feature = "host")]
mod capability;
#[cfg(all(feature = "host", feature = "dht"))]
mod dht;
#[cfg(all(feature = "host", feature = "mdns"))]
mod mdns;
mod relay;

// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.
#[cfg(feature = "host")]
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::address_lookup::memory::MemoryLookup;
#[cfg(feature = "host")]
use iroh::endpoint::PortmapperConfig;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use iroh_gossip::proto::HyparviewConfig;

use crate::protocol::mesh::{LookupOpts, RelayChoice, TransportPolicy};
use crate::transport::PayloadPath;
use crate::util::clock::millis_saturating;

/// A local relay server every side of a test can reach: plain HTTP, so the
/// engine dials `ws://` with no TLS — and so can a **browser**, which owns
/// its own trust store and refuses a self-signed certificate with no
/// override (`iroh::test_utils::run_relay_server` is https-only). No QUIC
/// address discovery: a tab has no UDP, and the tests that use this force
/// the relay to be the only path anyway.
#[cfg(all(any(test, feature = "iroh-test-utils"), not(target_arch = "wasm32")))]
#[cfg_attr(
    not(feature = "iroh-test-utils"),
    expect(
        unreachable_pub,
        reason = "`net` re-exports it only with `iroh-test-utils`"
    )
)]
pub mod test_relay {
    use anyhow::Context as _;

    /// Spawn the relay; the URL is `http://127.0.0.1:<port>/`. Dropping the
    /// server stops it.
    ///
    /// # Errors
    /// Binding or spawning the relay server fails.
    #[cfg_attr(
        not(feature = "iroh-test-utils"),
        expect(
            unreachable_pub,
            reason = "`net` re-exports it only with `iroh-test-utils`"
        )
    )]
    pub async fn spawn_plain() -> anyhow::Result<(iroh::RelayUrl, iroh_relay::server::Server)> {
        let mut config = iroh_relay::server::ServerConfig::default();
        config.relay = Some(iroh_relay::server::RelayConfig::new((
            std::net::Ipv4Addr::LOCALHOST,
            0,
        )));
        config.quic = None;
        let server = iroh_relay::server::Server::spawn(config)
            .await
            .context("spawning the local relay server")?;
        let addr = server
            .http_addr()
            .context("the local relay server bound no HTTP address")?;
        let url = format!("http://{addr}/")
            .parse()
            .context("the local relay address is not a relay URL")?;
        Ok((url, server))
    }
}

#[cfg(feature = "host")]
pub use capability::{NetworkCapability, probe as capability_probe};
pub use relay::{RENDEZVOUS_RELAY_LADDER, probe_ladder, relay_ladder};
pub(crate) use relay::{
    RungRefresh, StoppableTask, plan_rung_refresh, select_bootstrap_rung, spawn_relay_monitor,
};

/// Build an iroh endpoint for a mesh's lookups.
///
/// - `lookups`: which address-lookups (mDNS / DHT) and relay to wire.
///   When any lookup is on, the builder is composed from
///   `presets::Minimal` plus the selected lookups; the relay maps via
///   `relay::relay_mode`. An all-off (loopback-only) set wires none of
///   them.
/// - `secret_key`: `Some` pins a deterministic identity (used for the
///   shared rendezvous endpoint); `None` lets iroh generate a fresh
///   random key (the normal peer endpoint).
/// - `bind_port`: loopback-only — `Some(port)` binds
///   `127.0.0.1:port` (the deterministic rendezvous port; a bind
///   failure with `AddrInUse` is the claim-if-free signal that another
///   member already holds the beacon). `None` binds an ephemeral port.
///   Ignored when lookups are on (N0 manages binding).
/// # Errors
/// Returns an error if the inputs are invalid or the operation fails.
/// The custom transports to register on an endpoint.
///
/// A struct rather than more positional arguments because the set grows: each
/// transport is independently optional, and several are host-only (they own
/// UDP sockets), so the field list itself differs per target. `Default` is
/// "IP and relay only".
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct TransportHandles {
    /// Source-routed multi-hop: reach a peer with no direct path by relaying
    /// through intermediate peers. Built with the `multihop` feature; the native
    /// underlay builder, `build_peer_multihop_with`, is host-only.
    #[cfg(feature = "multihop")]
    pub multihop: Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    /// QUIC over a `WebRTC` data channel. The browser's only way onto the
    /// mesh, and an opportunistic extra path for a native peer.
    pub webrtc: Option<habilis_network_iroh_webrtc_transport::WebRtcHandle>,
    /// Gossip as a path: QUIC packets carried as frames on the mesh topic, below every
    /// direct path and above the relay. On the member endpoint only: the beacon, the
    /// blob endpoint and the multihop underlay never carry it.
    pub gossip: Option<habilis_network_iroh_gossip_transport::GossipHandle>,
    /// The table that decides who holds a direct-peer slot. When set, the
    /// endpoint reports every connection to it, so that it can drop the ones
    /// that are gone.
    pub admission: Option<crate::transport::SignalAdmission>,
    /// The endpoint is a multi-hop underlay, an internal forwarding endpoint
    /// and not a peer or a beacon. Changes only the role a log line names.
    pub underlay: bool,
    /// Which transports this instance may carry data on. Lives here rather than
    /// as another positional argument for the same reason the handles do.
    pub opts: TransportOpts,
}

impl TransportHandles {
    /// True when no custom transport is registered.
    #[must_use]
    fn is_empty(&self) -> bool {
        #[cfg(feature = "multihop")]
        if self.multihop.is_some() {
            return false;
        }
        self.webrtc.is_none() && self.gossip.is_none()
    }
}

/// Which transports this *instance* may carry data on.
///
/// Deliberately **not** part of the mesh id. [`LookupOpts`] is mixed into
/// `derive_topic_id` so that every member provably agrees on where to
/// rendezvous — right for discovery, and exactly wrong for transports: a
/// browser only ever has relay and `WebRTC`, a native peer also has IP and
/// multihop. Baking transports into mesh identity would mean a browser could
/// never join a mesh a CLI created. So this is local, per-peer, and reconciled
/// per pair by ICE and iroh's own path selection.
///
/// `Default` is "everything this target has".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent on/off per path this node may carry data on"
)]
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
    pub gossip: bool,
}

impl TransportOpts {
    /// Set the UDP transport.
    #[must_use]
    pub fn with_udp(mut self, udp: bool) -> Self {
        self.udp = udp;
        self
    }

    /// Set the relay.
    #[must_use]
    pub fn with_relay(mut self, relay: bool) -> Self {
        self.relay = relay;
        self
    }

    /// Set the WebRTC transport.
    #[must_use]
    pub fn with_webrtc(mut self, webrtc: bool) -> Self {
        self.webrtc = webrtc;
        self
    }

    /// Set the gossip transport.
    #[must_use]
    pub fn with_gossip(mut self, gossip: bool) -> Self {
        self.gossip = gossip;
        self
    }
}

impl Default for TransportOpts {
    fn default() -> Self {
        Self {
            udp: true,
            relay: true,
            webrtc: true,
            gossip: false,
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
            gossip: false,
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
            gossip: policy.gossip && (policy.udp || policy.webrtc) && !cfg!(target_arch = "wasm32"),
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

/// Install on `builder` every custom transport and hook a mesh node needs: the
/// multi-hop transport (with its address lookup and backup path selector), the
/// `WebRTC` transport with its selector, and the connection hook that records
/// the endpoint's connections in the admission table.
///
/// The one definition of that wiring. [`build_endpoint`] calls it, and so does
/// [`InjectedEndpoint::bind`](crate::runtime::InjectedEndpoint::bind), so an
/// injected endpoint and an engine-built one cannot drift. Without the hook the
/// table sees none of the endpoint's connections: the relay policy is not kept on
/// the gossip connections that the node dials, and a slot whose connection is gone
/// is never pruned.
///
/// The builder is consumed here, so no caller can add a `path_selector` or a
/// `hooks` call after it: both are single slots, and the last call wins.
#[must_use]
pub(crate) fn install_transports(
    mut builder: iroh::endpoint::Builder,
    transports: &TransportHandles,
) -> iroh::endpoint::Builder {
    // Register the multi-hop custom transport (plus its address lookup + backup
    // path selector) so a `connect` to a peer with no direct path rides the
    // multihop path. The handle's app id must match this endpoint's key — the
    // caller (`build_peer_multihop`) pins the same secret.
    #[cfg(feature = "multihop")]
    let mut selector_set = false;
    #[cfg(feature = "multihop")]
    if let Some(handle) = transports.multihop.clone() {
        builder = builder.preset(handle);
        selector_set = true;
    }
    #[cfg(not(feature = "multihop"))]
    let mut selector_set = false;
    // WebRTC is additive: it joins IP and relay as another candidate path
    // rather than replacing them. Two native peers are better served by iroh's
    // own hole-punching; this is the browser's only path, and a fallback for
    // NATs that defeat hole-punching but not ICE.
    if let Some(handle) = transports.webrtc.clone() {
        if transports.opts.webrtc {
            builder = builder.add_custom_transport(handle.transport());
            // MUST come after `builder.preset(handle)` for multihop above: there
            // is a single `path_selector` slot and the last call wins. Safe only
            // because both selectors rank by the same ladder (IP, WebRTC,
            // multihop, relay), whichever one is installed. Do not "tidy" this
            // above the preset.
            builder = builder.path_selector(handle.path_selector());
            selector_set = true;
        } else if cfg!(feature = "iroh-test-utils") {
            // Tests only: a mesh whose list leaves out `webrtc` still takes the
            // selector, without the transport, so that a test can take IP paths
            // away from one node to others (`Request::BlockIpTo`). Without it
            // such a node uses iroh's own selector, which the hook cannot reach.
            builder = builder.path_selector(handle.path_selector());
            selector_set = true;
        }
    }
    // Gossip is the lowest custom rung, and the member endpoint only. The selector of the
    // multihop or the `WebRTC` transport already ranks it; with neither, iroh's default
    // would put gossip above IP, so the ladder of the gossip handle is the selector.
    if let Some(handle) = transports.gossip.clone() {
        builder = builder
            .add_custom_transport(handle.custom_transport())
            .address_lookup(handle.address_lookup());
        if !selector_set {
            builder = builder.path_selector(handle.path_selector());
        }
    }
    if let Some(admission) = &transports.admission {
        builder = builder.hooks(admission.connection_hook());
    }
    builder
}

/// The memory windows of a QUIC connection, on every endpoint of the engine, the multihop underlay
/// and the blob endpoint included (decision D11). They are generous on purpose: the count of direct
/// connections is the real limit, and these only keep one connection from growing without bound.
/// Keep-alive, idle timeout, multipath, stream counts and datagrams stay at the iroh defaults.
fn quic_limits() -> iroh::endpoint::QuicTransportConfig {
    use crate::util::tuning::{
        QUIC_CONNECTION_RECEIVE_WINDOW, QUIC_SEND_WINDOW, QUIC_STREAM_RECEIVE_WINDOW,
    };
    use iroh::endpoint::{QuicTransportConfig, VarInt};

    QuicTransportConfig::builder()
        .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(QUIC_CONNECTION_RECEIVE_WINDOW))
        .send_window(QUIC_SEND_WINDOW)
        .build()
}

/// # Errors
/// Returns an error if the inputs are invalid or the operation fails.
pub async fn build_endpoint(
    lookups: &LookupOpts,
    secret_key: Option<SecretKey>,
    bind_port: Option<u16>,
    alpns: Vec<Vec<u8>>,
    transports: TransportHandles,
) -> Result<Endpoint> {
    Ok(
        build_endpoint_keeping_mdns(lookups, secret_key, bind_port, alpns, transports)
            .await?
            .0,
    )
}

/// The handle of the mDNS address lookup of an endpoint, kept so that the endpoint can hear the
/// other members of its mesh on the LAN. An uninhabited type where mDNS is not compiled in.
#[cfg(all(feature = "host", feature = "mdns"))]
pub type MdnsHandle = iroh_mdns_address_lookup::MdnsAddressLookup;
#[cfg(not(all(feature = "host", feature = "mdns")))]
pub type MdnsHandle = std::convert::Infallible;

/// What the LAN says about the other members of our mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(all(feature = "host", feature = "mdns")),
    expect(
        dead_code,
        reason = "only the mDNS forwarder makes these, and it needs `host` and `mdns`"
    )
)]
pub(crate) enum LanEvent {
    /// A member of our mesh announced itself, with the addresses it announced.
    Seen(EndpointAddr),
    /// A record expired. It may name an endpoint that was never a member: the listener ignores it
    /// when it holds nothing for the id.
    Gone(iroh::EndpointId),
}

/// The LAN members of our mesh, as the event loop reads them. `None` where the endpoint has no
/// mDNS handle: that is the off switch of the LAN arm.
///
/// # Errors
/// Returns an error if the tag does not fit the user data of the endpoint.
#[cfg_attr(
    not(all(feature = "host", feature = "mdns")),
    expect(
        clippy::unused_async,
        reason = "the forwarder is started with an await, and only where mDNS is compiled in"
    )
)]
pub(crate) async fn lan_contacts(
    endpoint: &Endpoint,
    mdns: Option<MdnsHandle>,
    topic: &iroh_gossip::proto::TopicId,
) -> Result<Option<tokio::sync::mpsc::Receiver<LanEvent>>> {
    #[cfg(all(feature = "host", feature = "mdns"))]
    if let Some(handle) = mdns {
        // The tag first, so that the record we announce already says that we are a member.
        tag_as_member(endpoint, topic)?;
        return Ok(Some(
            mdns::spawn_lan_contacts(&handle, lan_member_tag(topic), endpoint.id()).await,
        ));
    }
    #[cfg(not(all(feature = "host", feature = "mdns")))]
    let _ = (endpoint, mdns, topic);
    Ok(None)
}

/// What a member of a mesh puts in the user data of its endpoint, so that another member can tell
/// it from a beacon, a probe, or an endpoint of another mesh in the same mDNS service. It hashes
/// the topic id of the mesh, which already folds in the name, the config and the password: two
/// rooms with the same name and different passwords do not share a tag.
#[cfg(all(feature = "host", feature = "mdns"))]
#[must_use]
pub(crate) fn lan_member_tag(topic: &iroh_gossip::proto::TopicId) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    let digest = Sha256::new()
        .chain_update(b"habilis-network/lan-member/1")
        .chain_update(topic.as_bytes())
        .finalize();
    let mut tag = String::from("hn1:");
    for byte in &digest[..8] {
        let _ = write!(tag, "{byte:02x}");
    }
    tag
}

/// Mark the endpoint as a member of the mesh with this topic, in the mDNS record it announces.
/// The tag is set after the endpoint is built, because the member endpoint exists before the mesh
/// is known, and an injected endpoint is built by the caller. iroh announces the new record at
/// once.
/// # Errors
/// Returns an error if the tag does not fit the user data of an endpoint.
#[cfg(all(feature = "host", feature = "mdns"))]
pub(crate) fn tag_as_member(
    endpoint: &Endpoint,
    topic: &iroh_gossip::proto::TopicId,
) -> Result<()> {
    let tag = lan_member_tag(topic)
        .parse()
        .context("the member tag does not fit the endpoint user data")?;
    endpoint.set_user_data_for_address_lookup(Some(tag));
    Ok(())
}

/// [`build_endpoint`], and the mDNS handle when the endpoint has one.
/// # Errors
/// As [`build_endpoint`].
#[cfg_attr(
    not(feature = "host"),
    expect(
        unused_variables,
        reason = "`bind_port` feeds the loopback `bind_addr` below, which is `host`-only"
    )
)]
pub(crate) async fn build_endpoint_keeping_mdns(
    lookups: &LookupOpts,
    secret_key: Option<SecretKey>,
    bind_port: Option<u16>,
    alpns: Vec<Vec<u8>>,
    transports: TransportHandles,
) -> Result<(Endpoint, Option<MdnsHandle>)> {
    // A peer endpoint carrying a custom transport also pins a key, so it is
    // *not* a beacon; the presence of a handle disambiguates.
    let is_beacon = secret_key.is_some() && transports.is_empty() && !transports.underlay;
    let underlay = transports.underlay;
    let network = lookups.network_label();
    let mut builder = if lookups.is_loopback() {
        debug_assert!(
            !lookups.mdns && !lookups.dht && lookups.relay_lookup == RelayChoice::Disabled,
            "loopback-only mesh must resolve to all-off lookups"
        );
        // Loopback-only = strictly loopback, **zero external network calls**.
        // `Minimal` picks the rustls crypto provider without N0's
        // DNS/relay defaults; we then lock down every path that could
        // touch a non-loopback host: `bind_addr` 127.0.0.1,
        // `RelayMode::Disabled` (no relay; no address-lookup is wired
        // for a loopback-only mesh so no DNS/pkarr/mDNS/DHT either), and
        // `PortmapperConfig::Disabled` — the one remaining default-on
        // reach (UPnP/PCP/NAT-PMP to the LAN gateway, on even with the
        // relay off). With relay + portmapper off, iroh's netcheck has
        // no external targets (local-interface report only).
        // `bind_port` is the deterministic rendezvous port when
        // co-hosting the beacon, else 0 (ephemeral).
        {
            let builder = Endpoint::builder(presets::Minimal);
            #[cfg(feature = "host")]
            let builder = builder
                .bind_addr(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    bind_port.unwrap_or(0),
                ))
                .context("failed to set bind address")?
                .portmapper_config(PortmapperConfig::Disabled);
            builder.relay_mode(RelayMode::Disabled)
        }
    } else {
        // `Minimal` (not `presets::N0`): N0-DNS is intentionally not
        // wired (the relay ladder is the fast path; DHT is the
        // operator-free eternal backstop). `Minimal` still sets the
        // rustls crypto provider. The mDNS / DHT address-lookups are
        // wired **after** bind (below) — in iroh 1.0 they live in
        // companion crates and need the bound endpoint's id.
        Endpoint::builder(presets::Minimal).relay_mode(relay::relay_mode(&lookups.relay_lookup))
    };

    #[cfg(all(feature = "host", feature = "iroh-test-utils"))]
    let underlay_id = secret_key.as_ref().map(SecretKey::public);
    if let Some(secret_key) = secret_key {
        builder = builder.secret_key(secret_key);
    }

    // ALPNs the endpoint accepts inbound connections for. Empty for the gossip /
    // rendezvous endpoints (their Router registers `GOSSIP_ALPN`); a transfer
    // producer passes its ALPN (e.g. `FILE_ALPN`) so it can `endpoint.accept()`
    // directly.
    if !alpns.is_empty() {
        builder = builder.alpns(alpns);
    }

    let opts = transports.opts;
    builder = install_transports(builder, &transports);
    // Tests only: the underlay is an endpoint of its own, and a test that takes
    // paths away from a pair (`habilis_network_iroh_webrtc_transport::block_ip_to`)
    // needs a selector on it that reads the same tables. An underlay with a
    // `WebRtcHandle` already runs `WebRtcPreferred` (see `install_transports`),
    // which reads them. This one is for an underlay without a handle, which would
    // otherwise run iroh's default selector: it gets `MultihopLadder`.
    #[cfg(all(feature = "host", feature = "iroh-test-utils"))]
    if let Some(id) = underlay_id.filter(|_| underlay && transports.webrtc.is_none()) {
        builder = builder.path_selector(
            habilis_network_iroh_multihop_transport::underlay_path_selector(
                habilis_network_iroh_multihop_transport::UnderlayId::new(id),
            ),
        );
    }
    // Data-plane exclusivity: with IP cleared, a WebRTC-only peer cannot
    // silently fall back onto a hole-punched path, so a run that *claims* to be
    // WebRTC-only can be shown to be one. The relay is left alone on purpose —
    // it is the rendezvous, not a data path, and clearing it would leave the
    // JSEP exchange nowhere to happen.
    //
    // Non-wasm only, and not because of a feature gate: `clear_ip_transports`
    // does not *exist* on a wasm build of iroh, because a browser has no IP
    // transports to clear. The flag is already satisfied there by construction.
    #[cfg(not(target_arch = "wasm32"))]
    if !opts.udp {
        // `clear_ip_transports` only — deliberately **not**
        // `clear_address_lookup`. That was the first attempt and it silently
        // broke everything: `add_peer_addr` registers a `MemoryLookup` on the
        // endpoint, and the zero-lookup bootstrap *is* that registration
        // (`register_rendezvous` pre-registers the rendezvous at its relay
        // rung). Clearing the lookup store leaves the peer unable to dial
        // anything at all — it sat at `link_len=0, meshed=false` while still
        // seeing the roster through the beacon, which reads like a NAT problem
        // and is not one. The IP *discovery* legs are skipped further down
        // instead, where mDNS and DHT are wired.
        builder = builder.clear_ip_transports();
        tracing::info!(
            target: "habilis_network::lookup",
            "IP transports cleared; data must ride WebRTC (relay kept for rendezvous)"
        );
    }

    // Transport config is left at iroh's defaults, but for the memory windows: iroh tunes
    // keep-alive / idle (and the per-path multipath settings) for its
    // holepunching, and its own docs warn that adjusting them "may cause
    // suboptimal usage". A prior aggressive 10s idle / 5s keep-alive override
    // fought that tuning — marginal / distant links falsely idle-timed-out,
    // HyParView refilled from passive, and the resulting NeighborDown/Up churn
    // drove a per-connection memory leak. So we set only the memory windows of a connection
    // (decision D11), never the keep-alive, the idle timeout or the multipath settings.
    builder = builder.transport_config(quic_limits());

    // For the private rendezvous endpoint this returns `AddrInUse`
    // when another member already holds the deterministic port — the
    // caller treats that as "someone else is the beacon" and retries.
    let endpoint = builder.bind().await.context("failed to bind endpoint")?;
    // Post-bind address-lookup wiring: in iroh 1.0 the mDNS / mainline-DHT
    // providers are companion crates built from the bound endpoint's id and
    // added to its lookup services. Loopback-only meshes wire none (asserted
    // above). The relay leg is configured pre-bind via `relay_mode`.
    // These are wired *after* bind (iroh 1.0 moved them to companion crates
    // that need the bound endpoint's id), so `clear_address_lookup` above does
    // not reach them — they have to be skipped here as well. Both exist to find
    // IP paths, so an instance with IP off has no use for either.
    #[cfg(all(feature = "host", feature = "mdns"))]
    let mdns_handle = if lookups.mdns && opts.udp {
        Some(mdns::wire(&endpoint)?)
    } else {
        None
    };
    #[cfg(not(all(feature = "host", feature = "mdns")))]
    let mdns_handle: Option<MdnsHandle> = None;
    if lookups.dht && opts.udp {
        #[cfg(all(feature = "host", feature = "dht"))]
        dht::wire(&endpoint)?;
    }
    tracing::info!(target: "habilis_network::lookup",
        network,
        mdns = lookups.mdns,
        dht = lookups.dht,
        relay = ?lookups.relay_lookup,
        role = if underlay {
            "underlay"
        } else if is_beacon {
            "beacon"
        } else {
            "peer"
        },
        endpoint_id = %endpoint.id(),
        "endpoint bound"
    );
    Ok((endpoint, mdns_handle))
}

/// The normal peer endpoint: a fresh random identity, no
/// pinned port. Thin intent-named wrapper over `build_endpoint`
/// so call sites don't carry the rendezvous-only `None, None`.
/// # Errors
/// Binding the socket fails, or an address-lookup service cannot be wired.
pub async fn build_peer_endpoint(lookups: &LookupOpts) -> Result<Endpoint> {
    build_endpoint(lookups, None, None, Vec::new(), TransportHandles::default()).await
}

/// The multi-hop handle configuration this engine uses for a mesh: whether the
/// relay may carry cells is the mesh's `relay` rule, the other numbers are the
/// engine's. A caller that builds its own handle to inject uses this.
#[cfg(feature = "multihop")]
#[must_use]
pub fn multihop_handle_config(
    relay_payload: PayloadPath,
) -> habilis_network_iroh_multihop_transport::HandleConfig {
    habilis_network_iroh_multihop_transport::HandleConfig::default()
        .with_relay_payload(relay_payload.relay_allowed())
        .with_vector_max_age(crate::util::tuning::LINKSTATE_MAX_AGE)
        .with_relay_stuck_after(crate::util::tuning::MULTIHOP_RELAY_STUCK)
}

/// [`multihop_handle_config`] for a browser: the same numbers, and the link cost of
/// `HandleConfig::for_browser`, so that routes avoid a browser as a hop. Chosen by the browser
/// build of `build_member_endpoint`, and not by the target: a native member made to look like a
/// browser can use it too.
#[cfg(feature = "multihop")]
#[cfg_attr(
    all(feature = "host", not(test)),
    expect(
        dead_code,
        reason = "the browser build of `build_member_endpoint` is its caller"
    )
)]
#[must_use]
pub(crate) fn browser_handle_config(
    relay_payload: PayloadPath,
) -> habilis_network_iroh_multihop_transport::HandleConfig {
    multihop_handle_config(relay_payload).with_link_cost(
        habilis_network_iroh_multihop_transport::HandleConfig::for_browser().link_cost,
    )
}

/// Assert that an injected endpoint agrees with the mesh it joins.
///
/// [`InjectedEndpoint::bind`](crate::runtime::InjectedEndpoint::bind) already
/// checks the identities, so only the mesh-dependent part is left here: whether
/// the relay may carry the cells of the multi-hop handle, and whether the endpoint
/// can reach the rendezvous that the mesh uses.
///
/// # Errors
/// The multi-hop handle lets the relay carry cells on a mesh whose transport list
/// has no `relay`.
pub(crate) fn check_injected_against_mesh(
    endpoint: &Endpoint,
    relay_payload: bool,
    mesh_lookups: &LookupOpts,
    mesh_relay_transport: bool,
) -> Result<()> {
    // Whether the relay may carry cells is a rule of the mesh, in its id. A
    // handle that lets it, on a mesh that does not, would carry other peers'
    // cells over the relay.
    anyhow::ensure!(
        !relay_payload || mesh_relay_transport,
        "injected multihop handle lets the relay carry cells but the mesh's transport \
         list has no `relay`: build the handle with `relay_payload` off"
    );

    // The other half of the injection contract, and the half that had no check
    // at all. A caller that injects an endpoint built for one reach into a mesh
    // derived at another gets a setup that comes up clean and does not work:
    // the mesh registers its rendezvous somewhere the endpoint has no transport
    // to dial, so peers never find each other, while the node reports success.
    // One log line would have caught a share bound loopback-only whose mesh was
    // busy publishing a public rendezvous.
    // Keyed on whether the mesh *expects* a relay, not on whether it is
    // loopback. An mDNS-only mesh is neither loopback nor relayed, and having no
    // relay address is exactly right for it — warning there would be a false
    // alarm, which is its own defect.
    let endpoint_has_relay = endpoint
        .addr()
        .addrs
        .iter()
        .any(|addr| matches!(addr, iroh::TransportAddr::Relay(_)));
    let mesh_wants_relay = mesh_lookups.relay_lookup != RelayChoice::Disabled;
    if mesh_wants_relay && !endpoint_has_relay {
        tracing::warn!(
            "injected endpoint advertises no relay address but the mesh rendezvous \
             is on a relay; peers will not find each other until one comes up"
        );
    } else if !mesh_wants_relay && endpoint_has_relay {
        tracing::warn!(
            "injected endpoint has a relay address but the mesh does not use one; \
             the rendezvous will bootstrap without it"
        );
    }
    Ok(())
}

/// A peer endpoint with the `WebRTC` transport registered, plus the handle that
/// owns its session registry.
///
/// The key is minted here and pinned, because the transport advertises
/// `custom_addr(local_id)` as the address peers dial it on — so it has to know
/// the endpoint's identity, but the endpoint is built *with* the transport.
/// Getting this wrong is silent: the endpoint comes up fine and every `WebRTC`
/// dial goes to an address nobody listens on.
///
/// Registration is additive, so IP and relay stay available. A native peer
/// still prefers iroh's own hole-punched paths; for a browser this is the only
/// direct path there is.
///
/// # Errors
/// Returns an error if the endpoint fails to bind.
pub async fn build_peer_webrtc(
    lookups: &LookupOpts,
    opts: TransportOpts,
) -> Result<(
    Endpoint,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
)> {
    let (endpoint, handle, _mdns) = build_peer_webrtc_with(lookups, opts, None).await?;
    Ok((endpoint, handle))
}

/// [`build_peer_webrtc`], reporting the endpoint's connections to `admission`,
/// which keeps one entry per peer and drops the connections that are gone.
///
/// # Errors
/// Returns an error if the endpoint fails to bind.
pub(crate) async fn build_peer_webrtc_with(
    lookups: &LookupOpts,
    opts: TransportOpts,
    admission: Option<&crate::transport::SignalAdmission>,
) -> Result<(
    Endpoint,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    Option<MdnsHandle>,
)> {
    let secret = mint_secret();
    let handle = new_webrtc_handle(secret.public());
    let gossip = new_gossip_handle(opts, secret.public(), admission);
    let (endpoint, mdns) = build_endpoint_keeping_mdns(
        lookups,
        Some(secret),
        None,
        Vec::new(),
        TransportHandles {
            #[cfg(feature = "multihop")]
            multihop: None,
            webrtc: Some(handle.clone()),
            gossip: gossip.clone(),
            admission: admission.cloned(),
            underlay: false,
            opts,
        },
    )
    .await?;
    debug_assert_eq!(
        endpoint.id(),
        handle.transport().local_id(),
        "the WebRTC transport must advertise this endpoint's identity"
    );
    Ok((endpoint, handle, mdns))
}

/// The gossip handle of a member endpoint, made from the key that the endpoint will bind, when
/// `opts` has gossip. The budget is set here: the crate's default is none, and the engine never
/// runs without one. The admission table keeps the handle: the table sees the connections, so
/// it is what tells the handle which peers are established and which pairs a higher rung
/// carries, and the event loop reads the handle back from it.
fn new_gossip_handle(
    opts: TransportOpts,
    local: iroh::EndpointId,
    admission: Option<&crate::transport::SignalAdmission>,
) -> Option<habilis_network_iroh_gossip_transport::GossipHandle> {
    opts.gossip.then(|| {
        let handle = habilis_network_iroh_gossip_transport::GossipHandle::new(local);
        handle.set_budget(Some(
            habilis_network_iroh_gossip_transport::DEFAULT_BUDGET_BYTES_PER_SEC,
        ));
        if let Some(admission) = admission {
            admission.set_gossip(handle.clone());
        }
        handle
    })
}

/// Build the target's `WebRtcHandle`. The constructors differ — str0m natively,
/// a `RTCPeerConnection` hub in a tab — but the handle type does not, so this is
/// the one place the split shows.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn new_webrtc_handle(
    local: iroh::EndpointId,
) -> habilis_network_iroh_webrtc_transport::WebRtcHandle {
    habilis_network_iroh_webrtc_transport::WebRtcHandle::new(
        habilis_network_iroh_webrtc_transport::WebRtcTransport::new(local),
    )
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn new_webrtc_handle(
    local: iroh::EndpointId,
) -> habilis_network_iroh_webrtc_transport::WebRtcHandle {
    habilis_network_iroh_webrtc_transport::WebRtcHandle::hub(local)
}

/// A fresh random identity. Every endpoint of one peer is built from the one
/// key this returns, so that a peer is one peer on every path.
fn mint_secret() -> SecretKey {
    let mut key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut key_bytes);
    SecretKey::from_bytes(&key_bytes)
}

/// A peer endpoint with the multi-hop **and** the `WebRTC` transport
/// registered, with the handles that own their state: the
/// [`MultihopHandle`](habilis_network_iroh_multihop_transport::MultihopHandle)
/// (forwarding underlay and routing table) and the `WebRTC` session registry.
///
/// One key is the peer's identity on every path: the application endpoint (UDP
/// and relay), the `WebRTC` address and the multi-hop hop identity. It is minted
/// here, before any endpoint exists, because each handle has to know the
/// identity its endpoint will bind.
///
/// The underlay is the exception, on purpose. It is an internal forwarding
/// endpoint on a key derived from the peer's, so it is stable across restarts and
/// the link-vector, which the peer signs, names it. A relay delivers a packet that names an id to one
/// endpoint registered under it, so an underlay on the application key would
/// take the application endpoint's relayed packets, or lose its own (measured:
/// 12 of 12 relay-only dials went to the endpoint that registered second). The
/// underlay needs the relay to punch through a NAT, so it cannot share the id.
///
/// # Errors
/// Returns an error if either endpoint fails to bind.
// The engine builds through `build_peer_multihop_with`; this is the form without
// the `WebRTC` leg of the underlay, which the tests of the receive path build with.
#[cfg(all(feature = "host", test))]
pub(crate) async fn build_peer_multihop(
    lookups: &LookupOpts,
    opts: TransportOpts,
    admission: Option<&crate::transport::SignalAdmission>,
    relay_payload: PayloadPath,
) -> Result<(
    Endpoint,
    habilis_network_iroh_multihop_transport::MultihopHandle,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
)> {
    let (endpoint, handle, webrtc, _underlay_webrtc, _mdns) = build_peer_multihop_with(
        lookups,
        opts,
        admission,
        multihop_handle_config(relay_payload),
        None,
    )
    .await?;
    Ok((endpoint, handle, webrtc))
}

/// Tests only: while set, no node of this process gets a `WebRTC` leg on its
/// underlay, which gives a harness the control cell of a measurement of what the
/// leg costs. A flag of the process, like `block_ip_paths`: set it before the node
/// starts.
#[cfg(all(feature = "multihop", feature = "iroh-test-utils"))]
static UNDERLAY_LEG_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Tests only: see `UNDERLAY_LEG_OFF`.
#[cfg(all(feature = "host", feature = "iroh-test-utils"))]
pub fn set_underlay_leg_off(off: bool) {
    UNDERLAY_LEG_OFF.store(off, std::sync::atomic::Ordering::SeqCst);
}

/// The cap of the `WebRTC` leg of the underlay for a node with `max_peers` (G):
/// `Some(G)`, or `None` while a test switched the leg off.
#[cfg(feature = "multihop")]
#[cfg_attr(
    not(feature = "iroh-test-utils"),
    expect(
        clippy::unnecessary_wraps,
        reason = "None only when a test switched the leg off"
    )
)]
pub(crate) fn underlay_cap(max_peers: usize) -> Option<usize> {
    #[cfg(feature = "iroh-test-utils")]
    if UNDERLAY_LEG_OFF.load(std::sync::atomic::Ordering::SeqCst) {
        return None;
    }
    Some(max_peers)
}

/// [`build_peer_multihop`], and with `underlay_cap` set the underlay also gets a
/// `WebRTC` leg: its own `WebRtcHandle`, an admission table with that cap (G),
/// and the signal protocol on its router, answered for gossip neighbors only.
/// See [`crate::transport::underlay_webrtc`]. `None`, or an instance with
/// `WebRTC` off, leaves the underlay on IP and the relay.
///
/// # Errors
/// Returns an error if either endpoint fails to bind.
#[cfg(feature = "multihop")]
pub(crate) async fn build_peer_multihop_with(
    lookups: &LookupOpts,
    opts: TransportOpts,
    admission: Option<&crate::transport::SignalAdmission>,
    handle_config: habilis_network_iroh_multihop_transport::HandleConfig,
    underlay_cap: Option<usize>,
) -> Result<(
    Endpoint,
    habilis_network_iroh_multihop_transport::MultihopHandle,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    Option<crate::transport::underlay_webrtc::UnderlayWebRtc>,
    Option<MdnsHandle>,
)> {
    let secret = mint_secret();
    let webrtc = new_webrtc_handle(secret.public());
    let gossip = new_gossip_handle(opts, secret.public(), admission);
    let underlay_secret = habilis_network_iroh_multihop_transport::underlay_secret(&secret);
    // The `WebRTC` leg of the underlay: the handle and the table are made before
    // the endpoint, because the endpoint takes the transport and reports its
    // connections to the table from the first handshake on.
    let underlay_leg = underlay_cap.filter(|_| opts.webrtc).map(|cap| {
        (
            new_webrtc_handle(underlay_secret.public()),
            crate::transport::SignalAdmission::new_route_table(cap),
        )
    });
    let underlay = build_endpoint(
        lookups,
        Some(underlay_secret),
        None,
        Vec::new(),
        TransportHandles {
            underlay: true,
            webrtc: underlay_leg.as_ref().map(|(handle, _)| handle.clone()),
            admission: underlay_leg.as_ref().map(|(_, table)| table.clone()),
            // The underlay has IP sockets only when the node does: a node run without `udp`
            // has no IP on any of its endpoints, and its underlay rides WebRTC and the relay.
            opts: TransportOpts {
                udp: opts.udp,
                ..TransportOpts::default()
            },
            ..TransportHandles::default()
        },
    )
    .await?;
    let mut protocols: Vec<(Vec<u8>, Box<dyn iroh::protocol::DynProtocolHandler>)> = Vec::new();
    let mut underlay_webrtc = None;
    if let Some((handle, table)) = underlay_leg {
        let allowed = crate::transport::underlay_webrtc::Allowed::default();
        let ice = crate::transport::IceProfile {
            host_only: lookups.is_loopback(),
        };
        // The underlay is an endpoint of its own, with lookup services of its own, so it has
        // an address book of its own.
        let book = address_book(&underlay);
        let acceptor = crate::transport::WebRtcSignalAcceptor::new(
            handle.clone(),
            underlay.clone(),
            book.clone(),
            underlay.id(),
            table.clone(),
            ice,
        );
        protocols.push((
            crate::transport::MESH_WEBRTC_SIGNAL_ALPN.to_vec(),
            Box::new(crate::transport::underlay_webrtc::UnderlaySignalGate::new(
                acceptor,
                allowed.clone(),
            )),
        ));
        // A session that attached is used only after a connect that completes, and
        // the nudge is that connect: see `webrtc::nudge_session`.
        protocols.push((
            crate::transport::webrtc::NUDGE_ALPN.to_vec(),
            Box::new(crate::transport::webrtc::NudgeAcceptor),
        ));
        underlay_webrtc = Some(crate::transport::underlay_webrtc::UnderlayWebRtc {
            handle,
            admission: table,
            endpoint: underlay.clone(),
            book,
            allowed,
        });
    }
    let handle = habilis_network_iroh_multihop_transport::MultihopHandle::with_protocols(
        &secret,
        underlay,
        handle_config,
        protocols,
    )?;
    let (endpoint, mdns) = build_endpoint_keeping_mdns(
        lookups,
        Some(secret),
        None,
        Vec::new(),
        TransportHandles {
            multihop: Some(handle.clone()),
            webrtc: Some(webrtc.clone()),
            gossip: gossip.clone(),
            admission: admission.cloned(),
            underlay: false,
            opts,
        },
    )
    .await?;
    Ok((endpoint, handle, webrtc, underlay_webrtc, mdns))
}

/// The address book of `endpoint`: one `MemoryLookup`, added to the lookup services of the
/// endpoint. Call it once per endpoint, where the endpoint is built, and keep the book with the
/// endpoint. [`add_peer_addr`] is the one writer of the book. The addresses of the peers change
/// (a home relay comes late, an interface changes) and are told again, so a lookup per call would
/// add one service to the endpoint for each of them.
///
/// An endpoint that exposes no lookup services gets a book that nothing reads, as a call of
/// `add_peer_addr` used to fail and be ignored.
pub fn address_book(endpoint: &Endpoint) -> MemoryLookup {
    let book = MemoryLookup::new();
    match endpoint.address_lookup() {
        Ok(services) => services.add(book.clone()),
        Err(error) => {
            tracing::warn!(target: "habilis_network::lookup", %error, "the endpoint has no lookup services for its address book");
        }
    }
    book
}

/// Register a peer's address in the address book of the endpoint, so that the endpoint can
/// connect to it by its id. The book is made by [`address_book`].
pub fn add_peer_addr(book: &MemoryLookup, addr: EndpointAddr) {
    let node = addr.id.fmt_short();
    let ip_addrs: Vec<_> = addr.ip_addrs().copied().collect();
    book.add_endpoint_info(addr);
    tracing::debug!(target: "habilis_network::lookup", %node, ?ip_addrs, "registered a direct peer address with the endpoint");
}

/// [`add_peer_addr`] for an identity that changes holder: the entry is replaced, not merged. A merge
/// keeps the address of every beacon that this process held under the id, and a dial to the id
/// then tries ports of beacons that are gone.
pub(crate) fn replace_peer_addr(book: &MemoryLookup, addr: EndpointAddr) {
    let node = addr.id.fmt_short();
    let ip_addrs: Vec<_> = addr.ip_addrs().copied().collect();
    book.set_endpoint_info(addr);
    tracing::debug!(target: "habilis_network::lookup", %node, ?ip_addrs, "replaced the address of a peer in the endpoint's book");
}

/// Bounded `GOSSIP_ALPN` connect-probe. On a mesh whose relay is lookup
/// only the far side's accept gate holds and finally closes this connection;
/// the probe wants only the resolution side effect, so that is harmless.
/// Dialing forces iroh to
/// (re)resolve and (re)path `target` via the configured
/// address-lookups; the connection is only ever wanted for that side
/// effect. `true` iff a connection was established within `timeout`
/// (a foreign / dead / unreachable target yields `false`); callers
/// wanting only the resolution side effect ignore the bool.
pub async fn probe_connect(
    endpoint: &Endpoint,
    target: impl Into<EndpointAddr>,
    timeout: Duration,
) -> bool {
    probe_answer(endpoint, target, timeout).await == ProbeAnswer::Ours
}

/// What a connect-probe found at an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeAnswer {
    /// The connection opened: the listener presented the identity that was asked for.
    Ours,
    /// The handshake failed on the identity: our own verifier rejected the key that the listener
    /// presented ([`CERTIFICATE_ALERTS`]), or iroh could not read an identity from it. This, and
    /// only this, proves that what answers is not the mesh that was asked for.
    Foreign,
    /// A listener answered and ended the dial without proving an identity: a close, a refusal, a
    /// reset, a version mismatch, an alert that is not about the key (a holder of our own mesh
    /// that is bound and not serving yet answers `no_application_protocol`, which the server
    /// sends before its certificate), or a transport error. A busy, closing or starting holder
    /// of our own mesh sends these, so they say nothing about the mesh: a caller reads them as
    /// silence.
    Refused,
    /// Nothing answered inside the timeout, or there was nothing to dial. A port that nobody is
    /// bound on reads the same: UDP does not tell. A host too loaded to answer reads the same.
    NoAnswer,
}

/// [`probe_connect`] with the failure told apart: a listener that answered and refused is not a
/// listener that said nothing, and a listener that failed the identity is not one that refused.
/// A caller that must not act on silence (a bind cannot be taken back) acts on
/// [`ProbeAnswer::Foreign`] only and waits on [`ProbeAnswer::Refused`] and
/// [`ProbeAnswer::NoAnswer`].
pub(crate) async fn probe_answer(
    endpoint: &Endpoint,
    target: impl Into<EndpointAddr>,
    timeout: Duration,
) -> ProbeAnswer {
    let addr: EndpointAddr = target.into();
    let started = crate::util::clock::Instant::now();
    let mut failure = None;
    let answer = match n0_future::time::timeout(
        timeout,
        endpoint.connect(addr.clone(), GOSSIP_ALPN),
    )
    .await
    {
        Ok(Ok(conn)) => {
            // Close explicitly, not via drop: the resolution side effect is
            // done, and an orderly CONNECTION_CLOSE lets the accept side
            // (the beacon's gossip, which adopts GOSSIP_ALPN connections)
            // release the connection immediately instead of via its own
            // error path.
            conn.close(0u32.into(), b"probe");
            ProbeAnswer::Ours
        }
        Ok(Err(error)) => {
            failure = Some(error.to_string());
            answer_of_connect_error(&error)
        }
        Err(_) => ProbeAnswer::NoAnswer,
    };
    let connected = answer == ProbeAnswer::Ours;
    // `?addr`: a loopback/private direct addr means a *local*
    // rendezvous co-host (self-partition signature); relay/public is
    // the cross-machine path. `elapsed_ms` exposes a slow relay
    // re-home outrunning the steady probe budget.
    //
    // A *failed* probe is the diagnostic signal a partition/post-sleep
    // re-bootstrap can't re-home the rendezvous, so it lands at `info`
    // (always-on file); a steady success every heal tick would be a
    // firehose, so it stays `debug`.
    let elapsed_ms = millis_saturating(started.elapsed());
    if connected {
        tracing::debug!(target: "habilis_network::lookup", connected, elapsed_ms, addr = ?addr, "rendezvous connect-probe finished");
    } else {
        tracing::info!(target: "habilis_network::lookup", connected, elapsed_ms, ?answer, ?failure, addr = ?addr, "rendezvous connect-probe finished");
    }
    answer
}

/// The TLS alerts that a certificate verifier raises about the key of the peer, by alert number
/// (QUIC carries each as crypto error `0x100` plus the alert). `unknown_ca` 48 is the one that
/// this mesh produces: our verifier returns `InvalidCertificate(UnknownIssuer)` for another key
/// (iroh `tls/verifier.rs`), and rustls sends that as `UnknownCA` (rustls 0.23 `error.rs`,
/// `From<CertificateError> for AlertDescription`). The others are the alerts of the same verifier family: `bad_certificate`
/// 42 (`NotValidForName`), `unsupported_certificate` 43, `certificate_revoked` 44,
/// `certificate_expired` 45, `certificate_unknown` 46 and `decrypt_error` 51 (a bad signature).
/// Every other alert, `no_application_protocol` 120 included, is sent before a certificate is
/// seen and proves nothing about the identity.
const CERTIFICATE_ALERTS: [u8; 7] = [48, 42, 43, 44, 45, 46, 51];

/// A dial that ended in an error: a handshake that failed on the identity is
/// [`ProbeAnswer::Foreign`], a listener that closed or refused is [`ProbeAnswer::Refused`], and
/// every other failure said nothing.
fn answer_of_connect_error(error: &iroh::endpoint::ConnectError) -> ProbeAnswer {
    use iroh::endpoint::{AuthenticationError, ConnectError, ConnectingError};

    match error {
        ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        }
        | ConnectError::Connection { source, .. } => answer_of_connection_error(source),
        ConnectError::Connecting {
            source:
                ConnectingError::HandshakeFailure {
                    source: AuthenticationError::RemoteId { .. },
                    ..
                },
            ..
        } => ProbeAnswer::Foreign,
        ConnectError::Connecting {
            source: ConnectingError::HandshakeFailure { .. },
            ..
        } => ProbeAnswer::Refused,
        ConnectError::Connect { .. } | ConnectError::Connecting { .. } | _ => ProbeAnswer::NoAnswer,
    }
}

/// A connection error, during the handshake or after it. Only a certificate alert that our own
/// verifier raises about the key is [`ProbeAnswer::Foreign`]. A close, a reset, a refusal and
/// any other alert are [`ProbeAnswer::Refused`]. A timeout, a close of ours and exhausted
/// connection ids say nothing.
fn answer_of_connection_error(error: &iroh::endpoint::ConnectionError) -> ProbeAnswer {
    use iroh::endpoint::{ConnectionError, TransportErrorCode};

    match error {
        // Foreign is what our own verifier said about the key of the peer, nothing else.
        ConnectionError::TransportError(failure)
            if CERTIFICATE_ALERTS
                .iter()
                .any(|&alert| failure.code == TransportErrorCode::crypto(alert)) =>
        {
            ProbeAnswer::Foreign
        }
        ConnectionError::TransportError(_)
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::ApplicationClosed(_)
        | ConnectionError::Reset
        | ConnectionError::VersionMismatch => ProbeAnswer::Refused,
        ConnectionError::TimedOut
        | ConnectionError::LocallyClosed
        | ConnectionError::CidsExhausted => ProbeAnswer::NoAnswer,
    }
}

/// How many events of a topic the gossip keeps for a task that is not scheduled yet: sixteen full
/// answers to an anti-entropy digest. A late joiner meets the answers of its peers in one burst,
/// and every change is a message of the topic. The default of 256 overflowed on a loaded host
/// (the reader got `Lagged`, and the node logged "gossip event stream lagged").
const TOPIC_EVENT_CAPACITY: usize = 16 * crate::util::tuning::ANTIENTROPY_MAX_RESEND;

/// Build an iroh-gossip instance and a Router that accepts incoming gossip connections.
///
/// The Router spawns an accept loop that routes incoming QUIC connections
/// with the gossip ALPN to the Gossip protocol handler. Without this,
/// peers cannot accept inbound connections from other peers.
pub(crate) fn build_mesh(
    endpoint: Endpoint,
    active_view_capacity: usize,
    unicast: Option<crate::transport::UnicastAcceptor>,
    // The admission travels with the handle because the acceptor built below
    // has to share it with the dialing side — one ceiling per node, not one
    // per role. The beacon passes `None` and needs neither.
    webrtc: Option<(
        habilis_network_iroh_webrtc_transport::WebRtcHandle,
        crate::transport::SignalAdmission,
        crate::transport::IceProfile,
    )>,
    protocols: Vec<(Vec<u8>, Box<dyn iroh::protocol::DynProtocolHandler>)>,
    // The mesh's `transport.relay_transport`: with it off, every inbound gossip
    // connection is held until iroh selects a direct path on it.
    relay_transport: bool,
    // This node has no UDP path, so its gossip gate needs a `WebRTC` session
    // with the dialer (see `DirectOnlyGossip::accept`).
    needs_session: bool,
) -> (Gossip, Router, MemoryLookup) {
    // `active_view_capacity` is the live direct-neighbor cap (`--max-peers`),
    // raised above iroh-gossip's default (5) so meshes up to it form a full mesh
    // with nothing to shuffle — no membership churn, hence none of the
    // churn-driven per-connection leak. Set it small to reproduce the churn. The
    // passive (healing/shuffle) pool is kept at 2× the active view.
    let membership = HyparviewConfig {
        active_view_capacity: active_view_capacity.max(1),
        passive_view_capacity: (active_view_capacity * 2).max(1),
        ..Default::default()
    };
    let gossip = Gossip::builder()
        .membership_config(membership)
        .topic_event_capacity(TOPIC_EVENT_CAPACITY)
        .spawn(endpoint.clone());
    let local = endpoint.id();
    // The address book of the endpoint, made where the endpoint is wrapped. The caller keeps it,
    // and the signal acceptor registers webrtc transport addresses in it on attach.
    let book = address_book(&endpoint);
    // Cloned before the Router consumes the endpoint.
    let endpoint_for_acceptor = endpoint.clone();
    if let Some((_, admission, _)) = &webrtc {
        admission.watch_dialed_gossip(!relay_transport);
    }
    let session_gate = webrtc
        .as_ref()
        .filter(|_| needs_session)
        .map(|(handle, admission, _)| (handle.clone(), admission.clone(), local));
    // Every router serves the nudge, the beacon's too: a session that attaches to the rendezvous
    // is followed by a nudge, and it does its work only when the connect completes.
    let mut builder = Router::builder(endpoint)
        .accept(
            GOSSIP_ALPN,
            crate::transport::DirectOnlyGossip::new(
                gossip.clone(),
                PayloadPath::from(relay_transport),
                session_gate,
            ),
        )
        .accept(
            crate::transport::webrtc::NUDGE_ALPN,
            crate::transport::webrtc::NudgeAcceptor,
        );
    // A peer also accepts inbound unicast; the rendezvous/beacon endpoint
    // passes `None` (it is not a peer and carries no unicast traffic).
    if let Some(acceptor) = unicast {
        builder = builder.accept(crate::transport::UNICAST_ALPN, acceptor);
    }
    // …and answers JSEP offers, so a peer that cannot reach us over IP can
    // still open a direct data channel. Answering is unconditional: the role
    // rule (lower `EndpointId` offers) decides who *dials*, and a peer that
    // never answers can never be dialled by anyone.
    if let Some((handle, admission, ice)) = webrtc {
        builder = builder.accept(
            crate::transport::MESH_WEBRTC_SIGNAL_ALPN,
            crate::transport::WebRtcSignalAcceptor::new(
                handle,
                endpoint_for_acceptor,
                book.clone(),
                local,
                admission,
                ice,
            ),
        );
    }
    // The caller's own protocols, if it shares this endpoint with us.
    //
    // They have to come through here rather than the caller running its own
    // `endpoint.accept()` loop, and the reason is not stylistic: `Router::spawn`
    // calls `endpoint.set_alpns`, whose own documentation says it *overrides*
    // the ALPN list — so a caller that set its ALPNs at build time silently
    // loses them the moment we spawn. And two accept loops on one endpoint are
    // two consumers of one queue, so each inbound connection goes to whichever
    // loop wins the race. One Router owns `accept()`; everyone else registers.
    for (alpn, handler) in protocols {
        builder = builder.accept(alpn, handler);
    }
    let router = builder.spawn();
    (gossip, router, book)
}

#[cfg(test)]
mod tests {
    use super::{LookupOpts, TransportOpts, TransportPolicy, build_peer_endpoint};
    use crate::transport::PayloadPath;
    use habilis_network_test_tracing::test;
    use std::collections::HashSet;

    /// R1: the tag of a mesh is the same for one topic, differs between topics (the topic id
    /// folds in the password: two rooms of one name with two passwords are two topics) and fits the
    /// user data of an endpoint.
    #[cfg(all(feature = "host", feature = "mdns"))]
    #[test]
    fn the_lan_tag_follows_the_topic() {
        let one = iroh_gossip::proto::TopicId::from_bytes([1u8; 32]);
        let other = iroh_gossip::proto::TopicId::from_bytes([2u8; 32]);

        assert_eq!(super::lan_member_tag(&one), super::lan_member_tag(&one));
        assert_ne!(super::lan_member_tag(&one), super::lan_member_tag(&other));
        let user_data: Result<iroh::endpoint_info::UserData, _> =
            super::lan_member_tag(&one).parse();
        assert!(user_data.is_ok(), "the tag must fit the user data");
    }

    /// R1: our tag in, a foreign tag out, no user data out.
    #[cfg(all(feature = "host", feature = "mdns"))]
    #[test]
    fn only_our_tag_is_a_member_of_our_mesh() {
        let ours = super::lan_member_tag(&iroh_gossip::proto::TopicId::from_bytes([1u8; 32]));
        let foreign = super::lan_member_tag(&iroh_gossip::proto::TopicId::from_bytes([2u8; 32]));
        let user = |text: &str| text.parse::<iroh::endpoint_info::UserData>().expect("fits");

        assert!(super::mdns::is_member_tag(Some(&user(&ours)), &ours));
        assert!(!super::mdns::is_member_tag(Some(&user(&foreign)), &ours));
        assert!(!super::mdns::is_member_tag(Some(&user("hello")), &ours));
        assert!(!super::mdns::is_member_tag(None, &ours));
    }

    /// R2 (the forwarder's filter): a new id passes, the same record again does not, a changed record
    /// does, and a `Gone` passes only for an id that was passed before.
    #[cfg(all(feature = "host", feature = "mdns"))]
    #[test]
    fn the_forwarder_passes_news_only() {
        use std::collections::HashMap;

        use super::LanEvent;
        use super::mdns::news_only;

        let id = iroh::SecretKey::generate().public();
        let stranger = iroh::SecretKey::generate().public();
        let at = |port: u16| {
            iroh::EndpointAddr::new(id).with_ip_addr(std::net::SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                port,
            )))
        };
        let mut known = HashMap::new();

        assert_eq!(
            news_only(LanEvent::Gone(stranger), &mut known),
            None,
            "a Gone for an id never passed ends here"
        );
        assert!(news_only(LanEvent::Seen(at(1)), &mut known).is_some());
        assert_eq!(
            news_only(LanEvent::Seen(at(1)), &mut known),
            None,
            "the same record again is the refresh, not news"
        );
        assert!(
            news_only(LanEvent::Seen(at(2)), &mut known).is_some(),
            "a changed record is news"
        );
        assert_eq!(
            news_only(LanEvent::Gone(id), &mut known),
            Some(LanEvent::Gone(id))
        );
        assert_eq!(news_only(LanEvent::Gone(id), &mut known), None);
    }

    /// R3: two members of one mesh and a stranger of another, all on the LAN with mDNS and no
    /// beacon at all. The members hear each other through the mDNS stream, graft each other, and
    /// become gossip neighbors; the stranger is never reported. The test runs on a host that sends
    /// multicast; where it cannot, nothing is discovered and the test fails on the deadline, which
    /// the slot reports as VOID for fix C, never as green.
    #[cfg(all(feature = "host", feature = "mdns"))]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs a host that sends mDNS multicast: run with --ignored --nocapture"]
    async fn two_members_on_the_lan_link_with_no_beacon() {
        use std::io::Write as _;
        use std::time::{Duration, Instant};

        use futures_util::StreamExt as _;
        use iroh_gossip::api::Event;

        use super::{
            Endpoint, GOSSIP_ALPN, Gossip, LanEvent, MemoryLookup, RelayChoice, Router,
            TransportHandles, address_book,
        };

        struct Member {
            endpoint: Endpoint,
            book: MemoryLookup,
            sender: iroh_gossip::api::GossipSender,
            receiver: iroh_gossip::api::GossipReceiver,
            events: tokio::sync::mpsc::Receiver<LanEvent>,
            _router: Router,
        }

        async fn member(topic: iroh_gossip::proto::TopicId) -> Member {
            let lan = LookupOpts::new(RelayChoice::Disabled).with_mdns(true);
            let (endpoint, handle) = super::build_endpoint_keeping_mdns(
                &lan,
                None,
                None,
                Vec::new(),
                TransportHandles::default(),
            )
            .await
            .expect("a LAN endpoint");
            super::tag_as_member(&endpoint, &topic).expect("the tag fits");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let router = Router::builder(endpoint.clone())
                .accept(GOSSIP_ALPN, gossip.clone())
                .spawn();
            let (sender, receiver) = gossip
                .subscribe(topic, Vec::new())
                .await
                .expect("subscribe without a bootstrap")
                .split();
            let events = super::mdns::spawn_lan_contacts(
                &handle.expect("mDNS is wired on a LAN endpoint"),
                super::lan_member_tag(&topic),
                endpoint.id(),
            )
            .await;
            Member {
                book: address_book(&endpoint),
                endpoint,
                sender,
                receiver,
                events,
                _router: router,
            }
        }

        let topic = iroh_gossip::proto::TopicId::from_bytes([3u8; 32]);
        let other_topic = iroh_gossip::proto::TopicId::from_bytes([4u8; 32]);
        let started = Instant::now();
        let mut first = member(topic).await;
        let mut second = member(topic).await;
        let stranger = member(other_topic).await;
        let ids = (first.endpoint.id(), second.endpoint.id());
        let mut stderr = std::io::stderr();
        let mut seen_first = HashSet::new();
        let mut seen_second = HashSet::new();
        let mut neighbors = (false, false);

        let deadline = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(deadline);
        while !(neighbors.0 && neighbors.1) {
            tokio::select! {
                () = &mut deadline => break,
                Some(event) = first.events.recv() => {
                    if let LanEvent::Seen(addr) = event {
                        let _ = writeln!(stderr, "lan: first saw {} at {:?}", addr.id.fmt_short(), started.elapsed());
                        seen_first.insert(addr.id);
                        first.book.add_endpoint_info(addr.clone());
                        first.sender.neighbor_peers(vec![addr.id]).await.expect("graft request");
                    }
                }
                Some(event) = second.events.recv() => {
                    if let LanEvent::Seen(addr) = event {
                        let _ = writeln!(stderr, "lan: second saw {} at {:?}", addr.id.fmt_short(), started.elapsed());
                        seen_second.insert(addr.id);
                        second.book.add_endpoint_info(addr.clone());
                        second.sender.neighbor_peers(vec![addr.id]).await.expect("graft request");
                    }
                }
                Some(Ok(Event::NeighborUp(id))) = first.receiver.next() => {
                    if id == ids.1 {
                        let _ = writeln!(stderr, "lan: first has the second as neighbor at {:?}", started.elapsed());
                        neighbors.0 = true;
                    }
                }
                Some(Ok(Event::NeighborUp(id))) = second.receiver.next() => {
                    if id == ids.0 {
                        let _ = writeln!(stderr, "lan: second has the first as neighbor at {:?}", started.elapsed());
                        neighbors.1 = true;
                    }
                }
            }
        }

        assert!(
            neighbors.0 && neighbors.1,
            "the two members did not become gossip neighbors through the LAN within 30 s: first saw {seen_first:?}, second saw {seen_second:?}, neighbors {neighbors:?}"
        );
        assert!(
            !seen_first.contains(&stranger.endpoint.id())
                && !seen_second.contains(&stranger.endpoint.id()),
            "a member of another mesh was reported"
        );
        first.endpoint.close().await;
        second.endpoint.close().await;
        stranger.endpoint.close().await;
    }

    /// A merge kept the address of every beacon that this process held under the rendezvous id.
    #[test]
    fn replacing_a_peer_address_leaves_exactly_the_new_one() {
        use super::{add_peer_addr, replace_peer_addr};

        let book = iroh::address_lookup::memory::MemoryLookup::new();
        let id = iroh::SecretKey::generate().public();
        let at = |port: u16| {
            iroh::EndpointAddr::new(id).with_ip_addr(std::net::SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                port,
            )))
        };
        add_peer_addr(&book, at(4000));

        replace_peer_addr(&book, at(5000));

        let ip_addrs: Vec<_> = book
            .get_endpoint_info(id)
            .expect("an entry")
            .into_endpoint_addr()
            .ip_addrs()
            .copied()
            .collect();
        assert_eq!(
            ip_addrs,
            vec![std::net::SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                5000
            ))],
            "the book keeps the address of a beacon that is gone"
        );
    }

    #[test]
    fn the_mesh_policy_turns_off_the_paths_it_leaves_out() {
        let webrtc_only = TransportPolicy::default().with_udp(false);
        let on_webrtc = TransportOpts::default().within(&webrtc_only);
        assert!(!on_webrtc.udp && on_webrtc.webrtc && on_webrtc.relay);

        let udp_only = TransportPolicy::default().with_webrtc(false);
        let on_udp = TransportOpts::default().within(&udp_only);
        assert!(on_udp.udp && !on_udp.webrtc && on_udp.relay);

        let narrow_node = TransportOpts::webrtc_only().within(&TransportPolicy::default());
        assert!(
            !narrow_node.udp && narrow_node.webrtc,
            "a mesh never turns on a path the node lacks"
        );
    }

    // Binds the `Minimal`-based reachable branch (the default relay
    // ladder, no lookup wired) and the loopback all-off branch. mDNS
    // multicast / mainline-DHT socket setup is environment-dependent, so
    // it is not exercised here; presence-allowlist resolution is
    // unit-tested in `protocol::mesh`, and the relay ladder logic in
    // [`super::relay`].

    /// **A receiver that never reads grants the whole window to one stream.** Every endpoint of the
    /// engine sets the QUIC windows of decision D11: 16 `MiB` for a stream and for a connection, far
    /// above the iroh default of about 1.2 `MiB`, so that one blob stream can use the whole window, and
    /// still a bound for a peer that sends faster than the node reads. The test pins the value, so
    /// that a change of the constant is a change of the test.
    ///
    /// The sender is a plain iroh endpoint whose own buffer is capped at 64 `KiB`. It cannot get
    /// more than that ahead of what the receiver has taken in, so the bytes that its writes
    /// accept, less its own buffer, are what the receiver granted. Nobody reads at the receiver.
    #[cfg(feature = "host")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_receiver_that_never_reads_grants_the_whole_window_to_one_stream() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        const ALPN: &[u8] = b"habilis-test/flood/0";
        const WINDOW: usize = 16 * 1024 * 1024;
        const SENDER_BUFFER: usize = 64 * 1024;
        let receiver = super::build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            vec![ALPN.to_vec()],
            super::TransportHandles::default(),
        )
        .await
        .expect("bind the receiver");
        let sender = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .transport_config(
                iroh::endpoint::QuicTransportConfig::builder()
                    .send_window(SENDER_BUFFER as u64)
                    .build(),
            )
            .bind()
            .await
            .expect("bind the sender");

        let receiving = tokio::spawn({
            let receiver = receiver.clone();
            async move {
                let incoming = receiver.accept().await.expect("an incoming connection");
                let conn = incoming.await.expect("the handshake");
                let stream = conn.accept_uni().await.expect("a stream");
                // Nothing is read: the connection and the stream stay open and unread.
                tokio::time::sleep(Duration::from_secs(10)).await;
                drop((conn, stream));
            }
        });
        let conn = sender
            .connect(receiver.addr(), ALPN)
            .await
            .expect("connect to the receiver");
        let mut stream = conn.open_uni().await.expect("open a stream");
        let accepted = Arc::new(AtomicUsize::new(0));
        let writing = tokio::spawn({
            let accepted = Arc::clone(&accepted);
            async move {
                let chunk = vec![0u8; 16 * 1024];
                while stream.write_all(&chunk).await.is_ok() {
                    accepted.fetch_add(chunk.len(), Ordering::Relaxed);
                }
            }
        });

        tokio::time::sleep(Duration::from_secs(2)).await;
        let taken_in = accepted
            .load(Ordering::Relaxed)
            .saturating_sub(SENDER_BUFFER);
        writing.abort();
        receiving.abort();

        assert!(
            taken_in > WINDOW - 4 * 1024 * 1024 && taken_in <= WINDOW + 64 * 1024,
            "the receiver took in {taken_in} bytes of a stream nobody read; the window is {WINDOW}"
        );
        sender.close().await;
        receiver.close().await;
    }

    /// **Many streams that nobody reads still fit in the connection window.** Forty streams
    /// at 16 `MiB` each could hold 640 `MiB`; the window of the connection (decision D11) holds the
    /// receiver to 16 `MiB` for all of them together, where the iroh defaults let it take in about
    /// 47 `MiB`. The test pins the value, and also that the receiver does take in the window. Counted
    /// at the sender, as in
    /// `a_receiver_that_never_reads_grants_the_whole_window_to_one_stream`.
    #[cfg(feature = "host")]
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn streams_that_nobody_reads_fit_in_the_connection_window() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        const ALPN: &[u8] = b"habilis-test/flood/1";
        const WINDOW: usize = 16 * 1024 * 1024;
        const SENDER_BUFFER: usize = 64 * 1024;
        const STREAMS: usize = 40;
        let receiver = super::build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            vec![ALPN.to_vec()],
            super::TransportHandles::default(),
        )
        .await
        .expect("bind the receiver");
        let sender = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .transport_config(
                iroh::endpoint::QuicTransportConfig::builder()
                    .send_window(SENDER_BUFFER as u64)
                    .build(),
            )
            .bind()
            .await
            .expect("bind the sender");

        let receiving = tokio::spawn({
            let receiver = receiver.clone();
            async move {
                let incoming = receiver.accept().await.expect("an incoming connection");
                let conn = incoming.await.expect("the handshake");
                let mut streams = Vec::new();
                while let Ok(stream) = conn.accept_uni().await {
                    streams.push(stream);
                }
            }
        });
        let conn = sender
            .connect(receiver.addr(), ALPN)
            .await
            .expect("connect to the receiver");
        let accepted = Arc::new(AtomicUsize::new(0));
        let mut writers = Vec::new();
        for _ in 0..STREAMS {
            let mut stream = conn.open_uni().await.expect("open a stream");
            let accepted = Arc::clone(&accepted);
            writers.push(tokio::spawn(async move {
                let chunk = vec![0u8; 16 * 1024];
                while stream.write_all(&chunk).await.is_ok() {
                    accepted.fetch_add(chunk.len(), Ordering::Relaxed);
                }
            }));
        }

        tokio::time::sleep(Duration::from_secs(6)).await;
        let taken_in = accepted
            .load(Ordering::Relaxed)
            .saturating_sub(SENDER_BUFFER);
        for writer in writers {
            writer.abort();
        }
        receiving.abort();

        assert!(
            taken_in > WINDOW - 4 * 1024 * 1024 && taken_in <= WINDOW + 64 * 1024,
            "the receiver took in {taken_in} bytes of {STREAMS} streams nobody read; the connection window is {WINDOW}"
        );
        sender.close().await;
        receiver.close().await;
    }

    // An address that changes is told again, so addresses are registered again and again for one
    // endpoint. The endpoint has one lookup service for them, made once by `address_book`, not one
    // per registration.
    #[test]
    async fn the_addresses_of_one_endpoint_go_to_one_lookup_service() {
        let peer = iroh::SecretKey::generate().public();
        let at =
            |ip: &str| iroh::EndpointAddr::new(peer).with_ip_addr(ip.parse().expect("an address"));
        let first = build_peer_endpoint(&LookupOpts::loopback())
            .await
            .expect("loopback endpoint must bind");
        let second = build_peer_endpoint(&LookupOpts::loopback())
            .await
            .expect("loopback endpoint must bind");
        let services =
            |endpoint: &iroh::Endpoint| endpoint.address_lookup().expect("lookup services").len();
        let (first_before, second_before) = (services(&first), services(&second));

        let first_book = super::address_book(&first);
        super::add_peer_addr(&first_book, at("192.0.2.1:4000"));
        super::add_peer_addr(&first_book, at("192.0.2.2:4000"));
        let second_book = super::address_book(&second);
        super::add_peer_addr(&second_book, at("192.0.2.3:4000"));

        assert_eq!(
            services(&first),
            first_before + 1,
            "two registrations for one endpoint add one lookup service"
        );
        assert_eq!(
            services(&second),
            second_before + 1,
            "another endpoint has a book of its own"
        );
        first.close().await;
        second.close().await;
    }

    #[test]
    async fn loopback_all_off_binds() {
        let endpoint = build_peer_endpoint(&LookupOpts::loopback())
            .await
            .expect("loopback endpoint must bind");
        endpoint.close().await;
    }

    // A handles value with only gossip is a member endpoint: it must not read as a beacon.
    #[test]
    fn a_handles_value_with_only_gossip_is_not_empty() {
        let handle = habilis_network_iroh_gossip_transport::GossipHandle::new(
            iroh::SecretKey::from_bytes(&[51; 32]).public(),
        );
        assert!(super::TransportHandles::default().is_empty());
        let only_gossip = super::TransportHandles {
            gossip: Some(handle),
            ..super::TransportHandles::default()
        };
        assert!(!only_gossip.is_empty());
    }

    // Gossip is a choice of the mesh: the opts follow the policy, and it needs a direct path.
    #[test]
    fn the_mesh_policy_decides_gossip_for_the_opts() {
        let policy = |gossip: bool, udp: bool, webrtc: bool| {
            TransportPolicy::default()
                .with_gossip(gossip)
                .with_udp(udp)
                .with_webrtc(webrtc)
        };
        let within = |mesh: TransportPolicy| TransportOpts::default().within(&mesh).gossip;
        assert!(!TransportOpts::default().gossip, "off until the mesh asks");
        assert!(within(policy(true, true, true)));
        assert!(within(policy(true, false, true)), "webrtc is a direct path");
        assert!(!within(policy(false, true, true)));
        assert!(
            !within(policy(true, false, false)),
            "no direct path to ride"
        );
    }

    // The gossip transport is on the member endpoint and nowhere else: not on the multihop
    // underlay. iroh does not list the address of a custom transport in `Endpoint::addr` (the
    // `WebRTC` one is not there either), so the reading is the admission table, which keeps the
    // handle that the member endpoint was built with: the member's table has it, and the
    // underlay's does not. The member of a mesh without gossip has none. A beacon is built from
    // `TransportHandles::default()`, which has no gossip, and from opts that never name it.
    #[cfg(feature = "host")]
    #[test]
    async fn only_the_member_endpoint_has_the_gossip_handle() {
        let build = |gossip: bool| async move {
            let opts = TransportOpts {
                gossip,
                ..TransportOpts::default()
            };
            let table = crate::transport::SignalAdmission::new(8);
            let (endpoint, handle, _webrtc, leg, _mdns) = super::build_peer_multihop_with(
                &LookupOpts::loopback(),
                opts,
                Some(&table),
                super::multihop_handle_config(PayloadPath::DirectOnly),
                Some(5),
            )
            .await
            .expect("a multihop peer binds");
            handle.close().await;
            endpoint.close().await;
            (table, leg.expect("a leg when a cap is given"))
        };

        let (member_table, leg) = build(true).await;
        assert!(
            member_table.gossip_handle().is_some(),
            "the member endpoint has the handle"
        );
        assert!(
            leg.admission.gossip_handle().is_none(),
            "the multihop underlay does not"
        );
        let (table_without, _leg) = build(false).await;
        assert!(
            table_without.gossip_handle().is_none(),
            "a mesh without gossip has none"
        );
        assert!(super::TransportHandles::default().gossip.is_none());
    }

    // The list `udp,gossip` has no WebRTC and no multihop, so no other selector is installed: the
    // member still gets the gossip handle (the admission table keeps it), the gossip address,
    // and the ladder of the gossip handle, which keeps IP above gossip.
    #[cfg(feature = "host")]
    #[test]
    async fn the_member_of_a_udp_and_gossip_list_keeps_ip_above_gossip() {
        use habilis_network_iroh_gossip_transport::gossip_addr;
        use std::time::Duration;

        use iroh::protocol::{AcceptError, ProtocolHandler};

        const ALPN: &[u8] = b"habilis-network/test-udp-gossip-list/0";
        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(
                &self,
                connection: iroh::endpoint::Connection,
            ) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }
        let opts = TransportOpts {
            webrtc: false,
            gossip: true,
            ..TransportOpts::default()
        };
        let hub = habilis_network_iroh_gossip_transport::memory::MemoryHub::new();
        let mut members = Vec::new();
        for _ in 0..2 {
            let table = crate::transport::SignalAdmission::new(8);
            let (endpoint, _webrtc, _mdns) =
                super::build_peer_webrtc_with(&LookupOpts::loopback(), opts, Some(&table))
                    .await
                    .expect("a member binds");
            let handle = table
                .gossip_handle()
                .expect("the table keeps the gossip handle");
            hub.join(&handle);
            members.push(endpoint);
        }
        let (alice, bob) = (members.remove(0), members.remove(0));
        let router = iroh::protocol::Router::builder(bob.clone())
            .accept(ALPN, Hold)
            .spawn();
        let both = bob
            .addr()
            .addrs
            .into_iter()
            .chain([iroh::TransportAddr::Custom(gossip_addr(bob.id()))]);
        let connection = alice
            .connect(iroh::EndpointAddr::from_parts(bob.id(), both), ALPN)
            .await
            .expect("connect");

        let paths_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while connection.paths().len() < 2 && tokio::time::Instant::now() < paths_deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(connection.paths().len() >= 2, "IP and gossip are both open");
        let selected_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while connection
            .paths()
            .iter()
            .find(iroh::endpoint::Path::is_selected)
            .is_none()
            && tokio::time::Instant::now() < selected_deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            crate::transport::path::selected_is_ip(&connection),
            "IP is above gossip: the ladder of the gossip handle is the selector"
        );
        router.shutdown().await.expect("shutdown");
        alice.close().await;
    }

    // The underlay gets a `WebRTC` leg only when it is asked for, and only when
    // this instance has `WebRTC` on. Its table takes the cap it is given (G).
    // A browser advertises its links at ten times the cost; every other number is the engine's.
    #[cfg(feature = "multihop")]
    #[test]
    fn the_handle_config_of_a_browser_differs_from_the_engine_s_in_the_link_cost_only() {
        let native = super::multihop_handle_config(PayloadPath::RelayAllowed);
        let browser = super::browser_handle_config(PayloadPath::RelayAllowed);
        assert_eq!(native.link_cost, 10);
        assert_eq!(browser.link_cost, 100);
        assert_eq!(browser.with_link_cost(native.link_cost), native);
    }

    #[cfg(feature = "host")]
    #[test]
    async fn the_underlay_leg_takes_the_cap_it_is_given_and_needs_webrtc_on() {
        let build = |opts: TransportOpts, cap: Option<usize>| async move {
            super::build_peer_multihop_with(
                &LookupOpts::loopback(),
                opts,
                None,
                super::multihop_handle_config(PayloadPath::DirectOnly),
                cap,
            )
            .await
            .expect("a multihop peer binds")
        };

        let (endpoint, handle, _webrtc, leg, _mdns) =
            build(TransportOpts::default(), Some(5)).await;
        let leg = leg.expect("a leg when a cap is given");
        assert_eq!(leg.admission.cap(), 5, "the table has the cap of G");
        assert_eq!(
            leg.endpoint.id(),
            handle.underlay_id().get(),
            "the leg is on the underlay"
        );
        assert_eq!(leg.handle.session_count(), 0);
        handle.close().await;
        endpoint.close().await;

        let (capless_endpoint, capless_handle, _, without_cap, _) =
            build(TransportOpts::default(), None).await;
        capless_handle.close().await;
        capless_endpoint.close().await;
        assert!(without_cap.is_none(), "no cap, no leg");
        let off = TransportOpts {
            webrtc: false,
            ..TransportOpts::default()
        };
        let (off_endpoint, off_handle, _, webrtc_off, _) = build(off, Some(5)).await;
        off_handle.close().await;
        off_endpoint.close().await;
        assert!(webrtc_off.is_none(), "WebRTC off, no leg");
    }

    // A test can switch the leg of the underlay off for the whole process, which
    // is the control cell of a measurement.
    #[cfg(all(feature = "host", feature = "iroh-test-utils"))]
    #[test]
    fn a_test_can_switch_the_underlay_leg_off() {
        assert_eq!(super::underlay_cap(7), Some(7), "on by default");
        super::set_underlay_leg_off(true);
        assert_eq!(super::underlay_cap(7), None, "switched off");
        super::set_underlay_leg_off(false);
        assert_eq!(super::underlay_cap(7), Some(7), "switched on again");
    }

    // One identity per peer: the application endpoint (UDP and relay), the
    // WebRTC address and the multihop hop identity share one key. The underlay
    // has a key of its own (see `build_peer_multihop`).
    #[cfg(feature = "host")]
    #[test]
    async fn one_key_serves_udp_webrtc_and_multihop() {
        let (endpoint, handle, webrtc) = super::build_peer_multihop(
            &LookupOpts::loopback(),
            TransportOpts::default(),
            None,
            PayloadPath::DirectOnly,
        )
        .await
        .expect("a multihop peer binds");
        assert_eq!(handle.app_id().get(), endpoint.id(), "hop identity");
        assert_eq!(
            webrtc.transport().local_id(),
            endpoint.id(),
            "WebRTC address"
        );
        assert_ne!(
            handle.underlay_addr().id,
            endpoint.id(),
            "a relay hands an id's packets to one endpoint only"
        );
        handle.close().await;
        endpoint.close().await;
    }

    // An injected endpoint's multihop handle must obey the mesh's relay rule. Its
    // keys are checked when it is bound: see `InjectedEndpoint::bind`.
    #[test]
    async fn an_injected_multihop_handle_must_obey_the_mesh_relay_rule() {
        let lookups = LookupOpts::loopback();
        let (endpoint, _webrtc) = super::build_peer_webrtc(&lookups, TransportOpts::default())
            .await
            .expect("a peer binds");
        super::check_injected_against_mesh(&endpoint, false, &lookups, false)
            .expect("a handle that does not carry cells is allowed");
        let relay_error = super::check_injected_against_mesh(&endpoint, true, &lookups, false)
            .expect_err("relay cells on a lookup-only mesh");
        assert!(relay_error.to_string().contains("relay"), "{relay_error}");
        super::check_injected_against_mesh(&endpoint, true, &lookups, true)
            .expect("the mesh lets the relay carry cells");
        endpoint.close().await;
    }

    /// The window of a starting holder: the rung is bound with an empty ALPN list and its router
    /// has not set `GOSSIP_ALPN` yet (`build_endpoint` gives a rung exactly this before
    /// `Router::spawn`). A dial on `GOSSIP_ALPN` then fails on the ALPN, which a listener sends
    /// before any certificate: it proves nothing about the identity, so the probe must not
    /// answer `Foreign`, which makes a walk bind a second rung.
    #[test]
    async fn a_holder_of_our_identity_that_serves_no_alpn_yet_is_not_a_foreign_mesh() {
        use std::net::SocketAddr;

        use iroh::{EndpointAddr, SecretKey};

        use super::{ProbeAnswer, TransportHandles, build_endpoint, probe_answer};

        let secret = SecretKey::generate();
        let id = secret.public();
        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let holder = build_endpoint(
            &LookupOpts::loopback(),
            Some(secret),
            Some(port),
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        .expect("a bound rung without a router");
        let driving = holder.clone();
        let task = n0_future::task::spawn(async move {
            while let Some(incoming) = driving.accept().await {
                if let Ok(accepting) = incoming.accept() {
                    let _ = accepting.await;
                }
            }
        });
        let prober = build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        .expect("a prober");
        let addr = EndpointAddr::new(id)
            .with_ip_addr(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));

        let answer = probe_answer(&prober, addr, std::time::Duration::from_secs(2)).await;

        prober.close().await;
        holder.close().await;
        task.abort();
        assert_ne!(
            answer,
            ProbeAnswer::Foreign,
            "a holder of our mesh that has no ALPN yet is not another mesh"
        );
        assert_ne!(
            answer,
            ProbeAnswer::Ours,
            "a dial that failed on the ALPN did not open"
        );
    }

    /// A listener of the identity that was asked for, which refuses every connection (a beacon that
    /// is saturated or going down does the same), is not another mesh: its refusal proves nothing
    /// about the identity, so the probe must not answer `Foreign`, which makes a walk bind a rung.
    #[test]
    async fn a_refusal_from_a_listener_of_our_identity_is_not_a_foreign_mesh() {
        use std::net::SocketAddr;

        use iroh::{EndpointAddr, SecretKey};
        use iroh_gossip::net::GOSSIP_ALPN;

        use super::{ProbeAnswer, TransportHandles, build_endpoint, probe_answer};

        let secret = SecretKey::generate();
        let id = secret.public();
        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let listener = build_endpoint(
            &LookupOpts::loopback(),
            Some(secret),
            Some(port),
            vec![GOSSIP_ALPN.to_vec()],
            TransportHandles::default(),
        )
        .await
        .expect("a listener of our identity");
        let refusing = listener.clone();
        let task = n0_future::task::spawn(async move {
            while let Some(incoming) = refusing.accept().await {
                incoming.refuse();
            }
        });
        let prober = build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        .expect("a prober");
        let addr = EndpointAddr::new(id)
            .with_ip_addr(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));

        let answer = probe_answer(&prober, addr, std::time::Duration::from_secs(2)).await;

        prober.close().await;
        listener.close().await;
        task.abort();
        assert_ne!(
            answer,
            ProbeAnswer::Foreign,
            "a listener that refused is not another mesh: it proved no identity"
        );
        assert_ne!(answer, ProbeAnswer::Ours, "a refused dial did not open");
    }

    /// A session that attaches to the rendezvous is followed by a nudge: a dial on the nudge ALPN
    /// that does its work only when it completes. The router of the beacon is built with no
    /// unicast acceptor, so it has to serve the nudge ALPN all the same, or the handshake fails
    /// with `no_application_protocol` and the nudge does nothing.
    #[test]
    async fn a_router_that_carries_no_unicast_completes_a_nudge() {
        use std::net::SocketAddr;

        use iroh::{EndpointAddr, SecretKey};
        use iroh_gossip::net::GOSSIP_ALPN;

        use super::{TransportHandles, build_endpoint, build_mesh};

        let secret = SecretKey::generate();
        let id = secret.public();
        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let beacon = build_endpoint(
            &LookupOpts::loopback(),
            Some(secret),
            Some(port),
            vec![GOSSIP_ALPN.to_vec()],
            TransportHandles::default(),
        )
        .await
        .expect("a beacon endpoint");
        let (_gossip, router, _book) = build_mesh(beacon, 5, None, None, Vec::new(), true, false);
        let dialer = build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        .expect("a dialer");
        let addr = EndpointAddr::new(id)
            .with_ip_addr(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));

        let nudge = n0_future::time::timeout(
            std::time::Duration::from_secs(5),
            dialer.connect(addr, crate::transport::webrtc::NUDGE_ALPN),
        )
        .await
        .map(|dialed| dialed.map(|_| ()));

        dialer.close().await;
        let _ = router.shutdown().await;
        assert!(
            matches!(nudge, Ok(Ok(()))),
            "the nudge did not complete: {nudge:?}"
        );
    }

    /// What each way a dial can end proves: only the verdict of our verifier on the key is another
    /// mesh. An alert that is sent before a certificate (`no_application_protocol`, from a holder
    /// of our own mesh whose router has not set its ALPN yet), a close, a reset and a version
    /// mismatch say nothing of the identity; a local failure says nothing.
    #[test]
    fn every_way_a_dial_ends_is_read_by_what_it_proves() {
        use iroh::endpoint::{ConnectionError, TransportError, TransportErrorCode};

        use super::{ProbeAnswer, answer_of_connection_error};

        let alert = |code: u8| {
            ConnectionError::TransportError(TransportError::new(
                TransportErrorCode::crypto(code),
                String::new(),
            ))
        };
        let unknown_ca = alert(48);
        let no_application_protocol = alert(120);
        let handshake_failure = alert(40);
        assert_eq!(
            answer_of_connection_error(&unknown_ca),
            ProbeAnswer::Foreign,
            "the verifier rejected the key"
        );
        for refused in [
            no_application_protocol,
            handshake_failure,
            ConnectionError::Reset,
            ConnectionError::VersionMismatch,
        ] {
            assert_eq!(
                answer_of_connection_error(&refused),
                ProbeAnswer::Refused,
                "{refused:?}"
            );
        }
        for silent in [
            ConnectionError::TimedOut,
            ConnectionError::LocallyClosed,
            ConnectionError::CidsExhausted,
        ] {
            assert_eq!(
                answer_of_connection_error(&silent),
                ProbeAnswer::NoAnswer,
                "{silent:?}"
            );
        }
    }

    #[test]
    #[ignore = "needs the public relay ladder; run with --ignored"]
    async fn public_default_relay_binds() {
        // No lookup wired: exercises the `Minimal` + pinned-ladder
        // composition. `bind()` is non-blocking wrt the relay, so this
        // is offline-safe even with the relay ladder configured.
        let endpoint = build_peer_endpoint(&LookupOpts::public_preset())
            .await
            .expect("endpoint with pinned relay ladder must bind");
        endpoint.close().await;
    }
}
