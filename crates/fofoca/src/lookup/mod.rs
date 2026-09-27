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
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, endpoint::presets, protocol::Router};
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use iroh_gossip::proto::HyparviewConfig;

use crate::protocol::mesh::{LookupOpts, RelayChoice};
use crate::util::clock::millis_saturating;

/// A local relay server every side of a test can reach: plain HTTP, so the
/// engine dials `ws://` with no TLS — and so can a **browser**, which owns
/// its own trust store and refuses a self-signed certificate with no
/// override (`iroh::test_utils::run_relay_server` is https-only). No QUIC
/// address discovery: a tab has no UDP, and the tests that use this force
/// the relay to be the only path anyway.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub mod test_relay {
    use anyhow::Context as _;

    /// Spawn the relay; the URL is `http://127.0.0.1:<port>/`. Dropping the
    /// server stops it.
    ///
    /// # Errors
    /// Binding or spawning the relay server fails.
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
pub(crate) use relay::RungRefresh;
pub use relay::{RENDEZVOUS_RELAY_LADDER, probe_ladder, relay_ladder};
pub(crate) use relay::{
    StoppableTask, plan_rung_refresh, select_bootstrap_rung, spawn_relay_monitor,
};

/// Build an iroh endpoint for a mesh's lookups.
///
/// - `lookups`: which address-lookups (mDNS / DHT) and relay to wire.
///   When any lookup is on, the builder is composed from
///   `presets::Minimal` plus the selected lookups; the relay maps via
///   [`relay::relay_mode`]. An all-off (loopback-only) set wires none of
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
pub struct TransportHandles {
    /// Source-routed multi-hop: reach a peer with no direct path by relaying
    /// through intermediate peers. Host-only — it forwards real UDP packets.
    #[cfg(feature = "host")]
    pub multihop: Option<fofoca_iroh_multihop_transport::MultihopHandle>,
    /// QUIC over a `WebRTC` data channel. The browser's only way onto the
    /// mesh, and an opportunistic extra path for a native peer.
    pub webrtc: Option<fofoca_iroh_webrtc_transport::WebRtcHandle>,
    /// Which transports this instance may carry data on. Lives here rather than
    /// as another positional argument for the same reason the handles do.
    pub opts: TransportOpts,
}

impl TransportHandles {
    /// True when no custom transport is registered.
    #[must_use]
    fn is_empty(&self) -> bool {
        #[cfg(feature = "host")]
        if self.multihop.is_some() {
            return false;
        }
        self.webrtc.is_none()
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
    reason = "one independent on/off per transport; a bitflags type would read worse"
)]
pub struct TransportOpts {
    /// Direct UDP and hole-punched paths, plus the address lookups that find
    /// them. Cleared by a WebRTC-only instance.
    pub ip: bool,
    /// The relay. **Never cleared by `webrtc`-only**, because the relay is the
    /// rendezvous: it carries the bootstrap dial and the JSEP exchange. Clearing
    /// it would sever the very thing that lets a `WebRTC` session be negotiated.
    ///
    /// Not the mesh policy: this says whether *this node* registers a relay
    /// transport at all, the way `ip` and `webrtc` do. Whether the relay may
    /// carry payload is mesh-wide and lives in the id, as
    /// `protocol::TransportPolicy::relay_transport`.
    pub relay: bool,
    /// QUIC over a `WebRTC` data channel. Off, the transport is not registered
    /// on the endpoint, no offer is answered and none is made — so a pair
    /// with IP cleared too has the relay as its only path.
    pub webrtc: bool,
    /// Source-routed multi-hop. Host-only.
    pub multihop: bool,
}

impl Default for TransportOpts {
    fn default() -> Self {
        Self {
            ip: true,
            relay: true,
            webrtc: true,
            multihop: false,
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
            ip: false,
            relay: true,
            webrtc: true,
            multihop: false,
        }
    }
}

/// Per-node path switches a consumer hands over as plain data (a C struct, a
/// browser's options object). Not the mesh's transport policy: that says what
/// payload *may* ride and is in the id; this says what *this node* has. Only the
/// two a consumer plausibly turns off are exposed: the relay stays (it is the
/// rendezvous) and multihop stays an engine concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct PathFlags {
    /// Direct UDP and hole-punched paths.
    pub ip: bool,
    /// QUIC over a `WebRTC` data channel.
    pub webrtc: bool,
}

impl Default for PathFlags {
    fn default() -> Self {
        Self {
            ip: true,
            webrtc: true,
        }
    }
}

impl From<PathFlags> for TransportOpts {
    fn from(paths: PathFlags) -> Self {
        Self {
            ip: paths.ip,
            webrtc: paths.webrtc,
            ..Self::default()
        }
    }
}

/// # Errors
/// Returns an error if the inputs are invalid or the operation fails.
#[cfg_attr(
    not(feature = "host"),
    expect(
        unused_variables,
        reason = "`bind_port` feeds the loopback `bind_addr` below, which is `host`-only"
    )
)]
pub async fn build_endpoint(
    lookups: &LookupOpts,
    secret_key: Option<SecretKey>,
    bind_port: Option<u16>,
    alpns: Vec<Vec<u8>>,
    transports: TransportHandles,
) -> Result<Endpoint> {
    // A peer endpoint carrying a custom transport also pins a key, so it is
    // *not* a beacon; the presence of a handle disambiguates.
    let is_beacon = secret_key.is_some() && transports.is_empty();
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

    // Register the multi-hop custom transport (plus its address lookup + backup
    // path selector) so a `connect` to a peer with no direct path rides the
    // multihop path. The handle's app id must match this endpoint's key — the
    // caller (`build_peer_multihop`) pins the same secret.
    #[cfg(feature = "host")]
    if let Some(handle) = transports.multihop {
        builder = builder.preset(handle);
    }
    // WebRTC is additive: it joins IP and relay as another candidate path
    // rather than replacing them. Two native peers are better served by iroh's
    // own hole-punching; this is the browser's only path, and a fallback for
    // NATs that defeat hole-punching but not ICE.
    if let Some(handle) = transports.webrtc
        && transports.opts.webrtc
    {
        builder = builder.add_custom_transport(handle.transport());
        // MUST come after `builder.preset(handle)` for multihop above: there is
        // a single `path_selector` slot and the last call wins. Safe only
        // because this selector's bottom tier ranks foreign custom transports
        // below the relay, reproducing MultihopBackup's own policy. Do not
        // "tidy" this above the preset.
        builder = builder.path_selector(handle.path_selector());
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
    if !transports.opts.ip {
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
            target: "fofoca::lookup",
            "IP transports cleared; data must ride WebRTC (relay kept for rendezvous)"
        );
    }

    // Transport config is intentionally left at iroh's defaults: iroh tunes
    // keep-alive / idle (and the per-path multipath settings) for its
    // holepunching, and its own docs warn that adjusting them "may cause
    // suboptimal usage". A prior aggressive 10s idle / 5s keep-alive override
    // fought that tuning — marginal / distant links falsely idle-timed-out,
    // HyParView refilled from passive, and the resulting NeighborDown/Up churn
    // drove a per-connection memory leak. So we set nothing here.

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
    if lookups.mdns && transports.opts.ip {
        #[cfg(all(feature = "host", feature = "mdns"))]
        mdns::wire(&endpoint)?;
    }
    if lookups.dht && transports.opts.ip {
        #[cfg(all(feature = "host", feature = "dht"))]
        dht::wire(&endpoint)?;
    }
    tracing::info!(target: "fofoca::lookup",
        network,
        mdns = lookups.mdns,
        dht = lookups.dht,
        relay = ?lookups.relay_lookup,
        role = if is_beacon { "beacon" } else { "peer" },
        endpoint_id = %endpoint.id(),
        "endpoint bound"
    );
    Ok(endpoint)
}

/// The normal peer endpoint: a fresh random identity, no
/// pinned port. Thin intent-named wrapper over `build_endpoint`
/// so call sites don't carry the rendezvous-only `None, None`.
/// # Errors
/// Binding the socket fails, or an address-lookup service cannot be wired.
pub async fn build_peer_endpoint(lookups: &LookupOpts) -> Result<Endpoint> {
    build_endpoint(lookups, None, None, Vec::new(), TransportHandles::default()).await
}

/// Assert a caller-supplied endpoint and hub agree on identity.
///
/// The `WebRTC` transport advertises `custom_addr(local_id)` as the address peers
/// dial it on, so the hub must have been built from the same key the endpoint
/// binds. Getting this wrong is **silent**: the endpoint comes up fine and every
/// `WebRTC` dial goes to an address nobody listens on. `build_peer_webrtc` gets
/// this right by construction; an injected pair is only as good as its caller,
/// so it is checked here instead of assumed.
///
/// The reach check is a `warn!`, not an error: relay home is not established at
/// bind time, so a false negative would fail a perfectly good setup.
///
/// # Errors
/// The endpoint and hub advertise different identities.
pub fn check_injected_identity(
    endpoint: &Endpoint,
    webrtc: &fofoca_iroh_webrtc_transport::WebRtcHandle,
    mesh_lookups: &LookupOpts,
) -> Result<()> {
    let bound = endpoint.id();
    let advertised = webrtc.transport().local_id();
    anyhow::ensure!(
        bound == advertised,
        "injected endpoint binds {bound} but its WebRTC transport advertises \
         {advertised}; they must share one key or every WebRTC dial goes nowhere"
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
) -> Result<(Endpoint, fofoca_iroh_webrtc_transport::WebRtcHandle)> {
    let mut key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut key_bytes);
    let secret = SecretKey::from_bytes(&key_bytes);
    let handle = new_webrtc_handle(secret.public());
    let endpoint = build_endpoint(
        lookups,
        Some(secret),
        None,
        Vec::new(),
        TransportHandles {
            #[cfg(feature = "host")]
            multihop: None,
            webrtc: Some(handle.clone()),
            opts,
        },
    )
    .await?;
    debug_assert_eq!(
        endpoint.id(),
        handle.transport().local_id(),
        "the WebRTC transport must advertise this endpoint's identity"
    );
    Ok((endpoint, handle))
}

/// A `WebRtcHandle` for an endpoint that was built *without* it registered.
///
/// Only the multihop path needs this: multihop pins the key for its own hop
/// identity, so it owns the endpoint and `WebRTC` cannot be a custom transport on
/// it. The handle still answers inbound JSEP (the Router arm is independent of
/// the transport registration), it just has no path to send over — so a
/// multihop peer negotiates nothing. Kept rather than skipped so the wiring has
/// one shape, and so making the two coexist later is a change in one place.
///
/// `host`-only with multihop itself — `fofoca-iroh-multihop-transport` is not
/// in the wasm dependency table, so a browser peer has no multihop path to
/// detach for.
#[cfg(feature = "host")]
pub(crate) fn detached_webrtc_handle(
    local: iroh::EndpointId,
) -> fofoca_iroh_webrtc_transport::WebRtcHandle {
    new_webrtc_handle(local)
}

/// Build the target's `WebRtcHandle`. The constructors differ — str0m natively,
/// a `RTCPeerConnection` hub in a tab — but the handle type does not, so this is
/// the one place the split shows.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn new_webrtc_handle(
    local: iroh::EndpointId,
) -> fofoca_iroh_webrtc_transport::WebRtcHandle {
    fofoca_iroh_webrtc_transport::WebRtcHandle::new(
        fofoca_iroh_webrtc_transport::WebRtcTransport::new(local),
    )
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn new_webrtc_handle(
    local: iroh::EndpointId,
) -> fofoca_iroh_webrtc_transport::WebRtcHandle {
    fofoca_iroh_webrtc_transport::WebRtcHandle::hub(local)
}

/// A peer endpoint with the multi-hop transport registered, plus the
/// [`MultihopHandle`](fofoca_iroh_multihop_transport::MultihopHandle) that owns the
/// forwarding underlay and routing table. The app endpoint's key is pinned so it
/// matches the handle's advertised hop identity. The underlay is a second,
/// plain peer endpoint dedicated to hop-by-hop packet forwarding.
///
/// # Errors
/// Returns an error if either endpoint fails to bind.
#[cfg(feature = "host")]
pub(crate) async fn build_peer_multihop(
    lookups: &LookupOpts,
) -> Result<(Endpoint, fofoca_iroh_multihop_transport::MultihopHandle)> {
    let mut key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut key_bytes);
    let secret = SecretKey::from_bytes(&key_bytes);
    let underlay =
        build_endpoint(lookups, None, None, Vec::new(), TransportHandles::default()).await?;
    let handle = fofoca_iroh_multihop_transport::MultihopHandle::new(secret.public(), underlay);
    let endpoint = build_endpoint(
        lookups,
        Some(secret),
        None,
        Vec::new(),
        TransportHandles {
            multihop: Some(handle.clone()),
            webrtc: None,
            opts: TransportOpts::default(),
        },
    )
    .await?;
    Ok((endpoint, handle))
}

/// Register a peer's address so the endpoint can connect to it.
/// # Errors
/// The endpoint exposes no address book to add to.
pub fn add_peer_addr(endpoint: &Endpoint, addr: EndpointAddr) -> Result<()> {
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(addr);
    endpoint.address_lookup()?.add(lookup);
    tracing::debug!(target: "fofoca::lookup", "registered a direct peer address with the endpoint");
    Ok(())
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
    let addr: EndpointAddr = target.into();
    let started = crate::util::clock::Instant::now();
    let connected = match n0_future::time::timeout(
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
            true
        }
        _ => false,
    };
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
        tracing::debug!(target: "fofoca::lookup", connected, elapsed_ms, addr = ?addr, "rendezvous connect-probe finished");
    } else {
        tracing::info!(target: "fofoca::lookup", connected, elapsed_ms, addr = ?addr, "rendezvous connect-probe finished");
    }
    connected
}

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
        fofoca_iroh_webrtc_transport::WebRtcHandle,
        crate::transport::SignalAdmission,
        crate::transport::IceProfile,
    )>,
    protocols: Vec<(Vec<u8>, Box<dyn iroh::protocol::DynProtocolHandler>)>,
    // The mesh's `transport.relay_transport`: with it off, every inbound gossip
    // connection is held until iroh selects a direct path on it.
    relay_transport: bool,
) -> (Gossip, Router) {
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
        .spawn(endpoint.clone());
    let local = endpoint.id();
    // Cloned before the Router consumes the endpoint; the signal acceptor
    // registers webrtc transport addresses on attach.
    let endpoint_for_acceptor = endpoint.clone();
    let mut builder = Router::builder(endpoint).accept(
        GOSSIP_ALPN,
        crate::transport::DirectOnlyGossip::new(gossip.clone(), relay_transport),
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
    (gossip, router)
}

#[cfg(test)]
mod tests {
    use super::{LookupOpts, build_peer_endpoint};

    // Binds the `Minimal`-based reachable branch (the default relay
    // ladder, no lookup wired) and the loopback all-off branch. mDNS
    // multicast / mainline-DHT socket setup is environment-dependent, so
    // it is not exercised here; presence-allowlist resolution is
    // unit-tested in `protocol::mesh`, and the relay ladder logic in
    // [`super::relay`].

    #[tokio::test]
    async fn loopback_all_off_binds() {
        let endpoint = build_peer_endpoint(&LookupOpts::loopback())
            .await
            .expect("loopback endpoint must bind");
        endpoint.close().await;
    }

    #[tokio::test]
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
