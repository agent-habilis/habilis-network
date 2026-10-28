//! The lookup layer: building the iroh endpoint for a mesh mode and
//! wiring the selected lookups onto it. Each lookup mechanism lives in
//! its own submodule — [`mdns`] (LAN multicast), [`dht`] (mainline DHT),
//! and [`relay`] (the relay ladder + bootstrap-rung selection/failover).

mod lan;
mod lan_event;
mod mdns_handle;

mod endpoint;

#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;
use crate::transport::webrtc;
use crate::util::{clock, tuning};
#[cfg(all(feature = "multihop", feature = "iroh-test-utils"))]
use std::sync::atomic;
#[cfg(any(
    all(feature = "host", feature = "iroh-test-utils"),
    all(feature = "iroh-test-utils", feature = "multihop")
))]
use std::sync::atomic::Ordering;
#[cfg(feature = "host")]
mod capability;
#[cfg(all(feature = "host", feature = "dht"))]
mod dht;
mod error;
#[cfg(all(feature = "host", feature = "mdns"))]
mod mdns;
mod relay;
mod transport_handles;
mod transport_opts;

// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.
use std::time::Duration;

use anyhow::Result;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
use iroh_gossip::proto::HyparviewConfig;

use crate::protocol::mesh::{LookupOpts, RelayChoice};
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
pub mod test_relay;

#[cfg(feature = "host")]
pub use capability::{NetworkCapability, probe as capability_probe};
pub use error::EndpointError;
pub use relay::{RENDEZVOUS_RELAY_LADDER, probe_ladder, relay_ladder};
pub(crate) use relay::{
    RungRefresh, StoppableTask, plan_rung_refresh, select_bootstrap_rung, spawn_relay_monitor,
};
pub use transport_handles::TransportHandles;
pub use transport_opts::TransportOpts;

pub use endpoint::build_endpoint;

pub(crate) use endpoint::install_transports;
pub(crate) use lan::{build_endpoint_keeping_mdns, lan_contacts};
pub(crate) use lan_event::LanEvent;
pub use mdns_handle::MdnsHandle;

/// The normal peer endpoint: a fresh random identity, no
/// pinned port. Thin intent-named wrapper over `build_endpoint`
/// so call sites don't carry the rendezvous-only `None, None`.
/// # Errors
/// Binding the socket fails, or an address-lookup service cannot be wired.
pub async fn build_peer_endpoint(lookups: &LookupOpts) -> Result<Endpoint, EndpointError> {
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
        .with_vector_max_age(tuning::LINKSTATE_MAX_AGE)
        .with_relay_stuck_after(tuning::MULTIHOP_RELAY_STUCK)
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
) -> Result<
    (
        Endpoint,
        habilis_network_iroh_webrtc_transport::WebRtcHandle,
    ),
    EndpointError,
> {
    let (endpoint, handle, _mdns) = build_peer_webrtc_with(lookups, opts, None)
        .await
        .map_err(EndpointError::internal)?;
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
static UNDERLAY_LEG_OFF: atomic::AtomicBool = atomic::AtomicBool::new(false);

/// Tests only: see `UNDERLAY_LEG_OFF`.
#[cfg(all(feature = "host", feature = "iroh-test-utils"))]
pub fn set_underlay_leg_off(
    // true turns the underlay leg off, false turns it back on
    off: bool,
) {
    UNDERLAY_LEG_OFF.store(off, Ordering::SeqCst);
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
    if UNDERLAY_LEG_OFF.load(Ordering::SeqCst) {
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
    Option<underlay_webrtc::UnderlayWebRtc>,
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
        let allowed = underlay_webrtc::Allowed::default();
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
            Box::new(underlay_webrtc::UnderlaySignalGate::new(
                acceptor,
                allowed.clone(),
            )),
        ));
        // A session that attached is used only after a connect that completes, and
        // the nudge is that connect: see `webrtc::nudge_acceptor::nudge_session`.
        protocols.push((webrtc::NUDGE_ALPN.to_vec(), Box::new(webrtc::NudgeAcceptor)));
        underlay_webrtc = Some(underlay_webrtc::UnderlayWebRtc {
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
    let started = clock::Instant::now();
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
            source:
                ConnectingError::HandshakeFailure {
                    source: AuthenticationError::NoAlpn { .. },
                    ..
                },
            ..
        } => ProbeAnswer::Refused,
        #[expect(
            clippy::match_same_arms,
            reason = "AuthenticationError is non_exhaustive, so this arm keeps the wildcard for the other variants"
        )]
        ConnectError::Connecting {
            source: ConnectingError::HandshakeFailure { .. },
            ..
        } => ProbeAnswer::Refused,
        ConnectError::Connect { .. }
        | ConnectError::Connecting {
            source:
                ConnectingError::InternalConsistencyError { .. }
                | ConnectingError::LocallyRejected { .. },
            ..
        }
        | _ => ProbeAnswer::NoAnswer,
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
const TOPIC_EVENT_CAPACITY: usize = 16 * tuning::ANTIENTROPY_MAX_RESEND;

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
        .accept(webrtc::NUDGE_ALPN, webrtc::NudgeAcceptor);
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
mod tests;
