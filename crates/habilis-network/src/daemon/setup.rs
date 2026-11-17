use crate::{beacon, transport};
use iroh_gossip::{api, net, proto};
#[cfg(not(all(unix, feature = "host")))]
use std::fs::File;
#[cfg(all(unix, feature = "host"))]
use std::fs::{File, OpenOptions};
#[cfg(all(unix, feature = "host"))]
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{mem, sync};
#[cfg(all(unix, feature = "host"))]
use std::{time::Duration, time::Instant};
#[cfg(feature = "host")]
use tokio::task;
#[cfg(all(unix, feature = "host"))]
use tokio::time;
mod injected_endpoint;
mod setup_kind;
mod setup_params;

use crate::transport::UdpTransport;

use anyhow::Result;

use super::setup_error::SetupError;
use iroh::{Endpoint, RelayUrl};
use rand::RngCore;
use tokio::sync::{mpsc, watch};
#[cfg(all(unix, feature = "host"))]
use zeroize::Zeroizing;

use crate::gossip::event::{NodeEvent, NodeSink};
use crate::lookup;
use crate::protocol::crypto::Password;
use crate::protocol::meshes::{LookupOpts, Mesh, MeshConfig, MeshName, Transport};
use crate::protocol::{MeshId, Nickname};
use crate::util::tuning::{RELAY_RUNG_PROBE, SETUP_RUNG_READ};
use lookup::{
    ProbeAnswer, StoppableTask, add_peer_addr, build_mesh, relay_ladder, select_bootstrap_rung,
};

use crate::beacon::RendezvousParams;
use crate::lifecycle;

use super::config::{
    EndpointOwner, Endpoints, MeshSpec, RendezvousConfig, RuntimeConfig, TransportSet,
};
use super::state::RunKeys;
use super::{CoHostPolicy, DriverMode, EventLoopConfig};

use crate::gossip::split;
use crate::protocol::meshes::RelayChoice;
use crate::protocol::{Seed, SymmetricKey, TransportPolicy as crate_TransportPolicy, identity};
#[cfg(any(feature = "host", feature = "multihop"))]
use crate::transport::underlay_webrtc;
use crate::transport::webrtc;
use crate::util::{consts, tuning};
use iroh::address_lookup::memory;
use iroh::protocol::{Router, Router as iroh_Router};

pub use injected_endpoint::InjectedEndpoint;
pub use setup_kind::SetupKind;
pub use setup_params::{LiveCount, SetupParams};
/// Build the `RendezvousParams` for a mesh. `id` is the well-known
/// rendezvous `EndpointId`; `bind_port` is `Some` only for private
/// meshes (the deterministic loopback port — public is ephemeral and
/// pkarr-discoverable).
fn rendezvous_params(
    mesh: &Mesh,
    topic_id: proto::TopicId,
    lookups: &LookupOpts,
    rung_tx: watch::Sender<Option<RelayUrl>>,
) -> RendezvousParams {
    let bind_ports = if mesh.is_loopback() {
        mesh.rendezvous_ports().to_vec()
    } else {
        Vec::new()
    };
    // Optimistic rung 0 — the first ladder rung, **unprobed**, so setup
    // (and the joiner's `ready`) never blocks on a relay handshake. A
    // backgrounded probe (`spawn_startup_rung_confirmation`) and the
    // beacon's own liveness self-monitor correct it off the event loop
    // via `rung_tx` if rung 0 turns out to be unreachable. Empty for
    // private / relay-disabled ⇒ `None`.
    let bootstrap_relay = relay_ladder(&lookups.relay_lookup).next();
    let relay_transport = mesh.config().transport.allows(Transport::Relay);
    RendezvousParams {
        topic_id,
        secret: mesh.rendezvous_secret(),
        bind_ports,
        id: mesh.rendezvous_id(),
        lookups: lookups.clone(),
        relay_transport: transport::PayloadPath::from(relay_transport),
        bootstrap_relay,
        rung_tx,
    }
}

/// Confirm the optimistic rung 0 **off the event loop**: walk the ladder
/// once (the only relay handshakes setup pays, and detached so `ready`
/// is already out) and, if the first *reachable* rung differs from rung
/// 0, publish it through `rung_tx`. Covers a rung-0-down-at-start for
/// both creator and joiner; the joiner has no beacon self-monitor, so
/// this is its only startup correction. `None` for an empty (private /
/// relay-disabled) ladder.
fn spawn_startup_rung_confirmation(
    ladder: Vec<RelayUrl>,
    rung_tx: watch::Sender<Option<RelayUrl>>,
) -> Option<StoppableTask> {
    if ladder.is_empty() {
        return None;
    }
    Some(StoppableTask::spawn(|stopped| async move {
        let confirmed = select_bootstrap_rung(&ladder, RELAY_RUNG_PROBE, Some(&stopped)).await;
        if stopped.has_changed().is_err() {
            // A departure ended the walk: its `None` is not a verdict.
            return;
        }
        rung_tx.send_if_modified(|current| {
            if *current == confirmed {
                false
            } else {
                *current = confirmed;
                true
            }
        });
    }))
}

/// Pre-register `rendezvous_id`'s address so a cold joiner reaches it
/// with **zero address-lookup wait** — a creator-independent bootstrap
/// that needs no discovery query to make the first dial:
///
/// - **loopback-only**: every loopback ladder rung (iroh's node-id dial
///   reaches whichever rung our beacon bound; see `crate::beacon`).
/// - **reachable across machines**: the seed-derived `rendezvous_id` at
///   **every rung** of the relay choice, and at the rung of the walk
///   (`params.bootstrap_relay`). The beacon homes on one rung of the ladder
///   (`beacon::beacon_lookups`), the rung that its own walk read, and a
///   peer's walk can read another one. An address with every rung reaches
///   the beacon on whichever it is, so this is a real relay-direct dial, no
///   DNS/DHT/mDNS round-trip. DHT/mDNS stay wired as the eternal/LAN
///   backstop if every rung is ever unreachable.
///
/// Also re-asserted by the daemon's hard-heal path (resume / silent
/// partition): the startup hint may now point at a dead path, so the
/// relay-homed `rendezvous_id` address is registered again before the
/// long re-bootstrap probe.
/// The address itself comes from [`crate::beacon::rendezvous_addr`], shared
/// with the rival probe's dial target: the probe asks whether anyone serves
/// the identity *a joiner would reach*, so the two must name the same place or
/// it is answering a different question.
/// The rungs a member leaves out of the rendezvous address it registers at setup, from what each
/// busy rung answered to a probe. A member that walks the ladder (every policy but `Never`) keeps
/// only a rung read as ours: its walk reads the rest and admits one that turns out to be ours, and
/// a foreign listener never fails its dial. A member that never walks (`CoHostPolicy::Never`, the
/// `discover` session) leaves out only a rung read as foreign: it reads no rung later, and a rung
/// that refused or said nothing may be the beacon it came for, starting or loaded.
fn rungs_withheld_at_setup(policy: CoHostPolicy, read: &[(u16, ProbeAnswer)]) -> Vec<u16> {
    read.iter()
        .filter(|(_, answer)| match policy {
            CoHostPolicy::Never => matches!(answer, ProbeAnswer::Foreign),
            CoHostPolicy::Eager | CoHostPolicy::EagerProbed | CoHostPolicy::Deferred => {
                !matches!(answer, ProbeAnswer::Ours)
            }
        })
        .map(|(port, _)| *port)
        .collect()
}

pub(crate) fn register_rendezvous(
    book: &memory::MemoryLookup,
    params: &RendezvousParams,
    withheld: &[u16],
) {
    // Relay disabled (not in the allowlist) or private without a port ladder:
    // nothing to pre-register — joiners resolve the rendezvous id via
    // mDNS/DHT only.
    // Without the rungs in `withheld`: a dial of the id tries every address that the endpoint knows
    // for it, and a listener of another program on one of them fails the dial as a whole.
    let Some(address) = beacon::rendezvous_addr_without(params, withheld) else {
        return;
    };
    if params.bind_ports.is_empty() {
        tracing::info!(
            target: "habilis_network::lookup",
            relay = ?params.bootstrap_relay,
            "pre-registered rendezvous at the relay rung for zero-lookup dial"
        );
    } else {
        // Explicit target: needs RendezvousParams, so can't live in lookups.
        tracing::info!(
            target: "habilis_network::lookup",
            rungs = params.bind_ports.len(),
            "pre-registered rendezvous on the loopback port ladder"
        );
    }
    add_peer_addr(book, address);
}

/// Build the endpoint, subscribe to the topic, and produce a ready
/// `EventLoopConfig`. Shared by the `create` / `join` CLI paths and
/// the in-process sessions.
///
/// Output ordering differs by design: `Create` prints the mesh ID to
/// stderr, then `info`, then `ready`; `Join` emits `ready` then `info`.
/// The unicast inbound channel + its Router acceptor. The acceptor forwards
/// received `UNICAST_ALPN` frames to the returned receiver, which the event
/// loop drains into `gossip::ingest`. Bounded so a flooding peer can't
/// back-pressure the loop (a dropped frame is not repaired until the loss repair lands).
fn unicast_inbox(
    relay_transport: transport::PayloadPath,
) -> (
    mpsc::Receiver<transport::UnicastFrame>,
    transport::UnicastAcceptor,
) {
    let (tx, rx): (
        mpsc::Sender<transport::UnicastFrame>,
        mpsc::Receiver<transport::UnicastFrame>,
    ) = mpsc::channel(consts::UNICAST_INBOX_CAP);
    (rx, transport::UnicastAcceptor::new(tx, relay_transport))
}

/// The chunk request channel and its Router acceptor. The acceptor hands each request of `CHUNKS_ALPN` to the
/// returned receiver, which the event loop answers from its state. Bounded, so a flooding peer cannot
/// back-pressure the loop: a request over the cap gets the absent answer.
fn chunk_inbox(
    relay_transport: transport::PayloadPath,
) -> (
    mpsc::Receiver<transport::ChunkAsk>,
    transport::ChunkAcceptor,
) {
    let (tx, rx): (
        mpsc::Sender<transport::ChunkAsk>,
        mpsc::Receiver<transport::ChunkAsk>,
    ) = mpsc::channel(tuning::CHUNK_INBOX_CAP);
    (rx, transport::ChunkAcceptor::new(tx, relay_transport))
}

/// The multihop handle that `build_member_endpoint` returns: the real one when the `multihop`
/// feature is on, a placeholder that is always `None` when it is off.
#[cfg(all(feature = "multihop", not(feature = "host")))]
type MultihopSlot = Option<habilis_network_iroh_multihop_transport::MultihopHandle>;
#[cfg(all(not(feature = "multihop"), not(feature = "host")))]
type MultihopSlot = Option<()>;
/// The `WebRTC` leg of the multihop underlay that `build_member_endpoint` returns, likewise.
#[cfg(all(feature = "multihop", not(feature = "host")))]
type UnderlaySlot = Option<underlay_webrtc::UnderlayWebRtc>;
#[cfg(all(not(feature = "multihop"), not(feature = "host")))]
type UnderlaySlot = Option<()>;

/// Build this member's peer endpoint, registering the multi-hop transport
/// (and standing up its underlay) when the mesh policy has `multihop`. The
/// multi-hop and `WebRTC` transports share the one endpoint and its one key.
#[cfg(feature = "host")]
async fn build_member_endpoint(
    build: &SetupBuild<'_>,
    injected: Option<InjectedEndpoint>,
) -> Result<(
    Endpoint,
    Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    transport::SignalAdmission,
    Option<underlay_webrtc::UnderlayWebRtc>,
    Option<lookup::MdnsHandle>,
)> {
    if let Some(injected) = injected {
        // Shared endpoint: no key to mint, nothing to bind. `InjectedEndpoint::bind`
        // built it, and checked that its handles carry its key. The mesh policy
        // decides multi-hop, as it does for an endpoint the engine builds: a handle
        // on a mesh whose list has no `multihop` (or on a node with no UDP) is
        // dropped, so no vector is advertised or taken in and no route resolves.
        let mdns = injected.mdns_handle();
        let had_multihop = injected.multihop.is_some();
        let multihop = injected.multihop.filter(|_| build.multihop);
        if had_multihop && multihop.is_none() {
            tracing::info!(
                target: "habilis_network::lookup",
                "the mesh policy has no multihop for this node: the injected multihop handle is not used"
            );
        }
        lookup::check_injected_against_mesh(
            &injected.endpoint,
            multihop.as_ref().is_some_and(
                habilis_network_iroh_multihop_transport::MultihopHandle::relay_payload,
            ),
            build.lookups,
            build.relay_transport.relay_allowed(),
        )?;
        // The caller built the underlay of its handle itself, so there is no
        // `WebRTC` leg on it.
        return Ok((
            injected.endpoint,
            multihop,
            injected.webrtc,
            injected.admission,
            None,
            mdns,
        ));
    }
    // Made before the endpoint, because the endpoint reports its connections
    // to this table from the first handshake on.
    let admission = transport::SignalAdmission::new(build.max_direct);
    if build.multihop {
        // G caps the sessions of the underlay: it holds one to each known member that needs one.
        let (endpoint, handle, webrtc, underlay_webrtc, mdns) = lookup::build_peer_multihop_with(
            build.lookups,
            build.transports,
            Some(&admission),
            lookup::multihop_handle_config(build.relay_transport),
            lookup::underlay_cap(build.max_peers),
        )
        .await?;
        Ok((
            endpoint,
            Some(handle),
            webrtc,
            admission,
            underlay_webrtc,
            mdns,
        ))
    } else {
        let (endpoint, webrtc, mdns) =
            lookup::build_peer_webrtc_with(build.lookups, build.transports, Some(&admission))
                .await?;
        Ok((endpoint, None, webrtc, admission, None, mdns))
    }
}

/// Off a host (a browser): the multihop transport is built when the mesh policy has it and the
/// node has a direct path (`build.multihop`), with the link cost of a browser, so that routes
/// avoid it as a hop; otherwise the endpoint is the plain peer one. The underlay has no IP
/// sockets, and rides `WebRTC` and the relay.
#[cfg(not(feature = "host"))]
async fn build_member_endpoint(
    build: &SetupBuild<'_>,
    injected: Option<InjectedEndpoint>,
) -> Result<(
    Endpoint,
    MultihopSlot,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    transport::SignalAdmission,
    UnderlaySlot,
    Option<lookup::MdnsHandle>,
)> {
    if let Some(injected) = injected {
        // A browser has no multi-hop underlay, so a multihop handle that the caller
        // passed is ignored here, and the endpoint is used as it is.
        lookup::check_injected_against_mesh(
            &injected.endpoint,
            false,
            build.lookups,
            build.relay_transport.relay_allowed(),
        )?;
        return Ok((
            injected.endpoint,
            None,
            injected.webrtc,
            injected.admission,
            None,
            injected.mdns,
        ));
    }
    let admission = transport::SignalAdmission::new(build.max_direct);
    #[cfg(feature = "multihop")]
    if build.multihop {
        let (endpoint, handle, webrtc, underlay_webrtc, mdns) = lookup::build_peer_multihop_with(
            build.lookups,
            build.transports,
            Some(&admission),
            lookup::browser_handle_config(build.relay_transport),
            lookup::underlay_cap(build.max_peers),
        )
        .await?;
        return Ok((
            endpoint,
            Some(handle),
            webrtc,
            admission,
            underlay_webrtc,
            mdns,
        ));
    }
    let (endpoint, webrtc, mdns) =
        lookup::build_peer_webrtc_with(build.lookups, build.transports, Some(&admission)).await?;
    Ok((endpoint, None, webrtc, admission, None, mdns))
}

/// The endpoint and its `WebRTC` transport must share one key: the transport
/// advertises `custom_addr(local_id)`, so a mismatch is silent, and every `WebRTC`
/// dial goes to an address nobody listens on.
fn check_webrtc_key(
    bound: iroh::EndpointId,
    webrtc: &habilis_network_iroh_webrtc_transport::WebRtcHandle,
) -> Result<()> {
    let advertised = webrtc.transport().local_id();
    anyhow::ensure!(
        bound == advertised,
        "injected endpoint binds {bound} but its WebRTC transport advertises \
         {advertised}; they must share one key or every WebRTC dial goes nowhere"
    );
    Ok(())
}

/// The hop identity of the multi-hop handle is the key the endpoint binds, or a
/// route that names this peer reaches nobody. Its underlay has a key of its own,
/// see `build_peer_multihop`.
#[cfg(feature = "multihop")]
fn check_hop_key(
    bound: iroh::EndpointId,
    multihop: Option<&habilis_network_iroh_multihop_transport::MultihopHandle>,
) -> Result<()> {
    if let Some(handle) = multihop {
        let hop_identity = handle.app_id().get();
        anyhow::ensure!(
            bound == hop_identity,
            "injected endpoint binds {bound} but its multihop handle has hop identity \
             {hop_identity}; they must share one key or every route to this peer goes nowhere"
        );
    }
    Ok(())
}

/// Why a browser refuses a mesh with no relay lookup: one string, so a test
/// can match the refusal without copying its text.
pub const BROWSER_NEEDS_RELAY_LOOKUP: &str = "a browser cannot reach a peer in this mesh: it has no UDP, so it needs the relay (`relay` in lookup, and a relay transport on this node)";

/// Why a browser refuses a mesh whose list leaves it no payload path.
pub const BROWSER_HAS_NO_PATH: &str = "a browser cannot carry payload in this mesh: its transport list has neither `webrtc` nor `relay`";

/// The paths this member runs: the mesh's transport list decides which direct
/// paths exist, and a node can only have fewer.
///
/// # Errors
/// A node that can never reach anyone: without UDP, one with no relay (see
/// [`reaches_relay`]). On a browser, also a mesh [`refuse_in_browser`]
/// refuses. Refused here rather than left as a member that links to nobody
/// and says nothing. Whether a reachable node may carry payload in this mesh
/// is the accept gate's call at runtime, not this one's.
fn member_transports(
    lookups: &LookupOpts,
    transports: lookup::TransportOpts,
    policy: &crate_TransportPolicy,
) -> Result<lookup::TransportOpts> {
    let transports = transports.within(policy);
    #[cfg(target_arch = "wasm32")]
    refuse_in_browser(lookups, policy, transports)?;
    anyhow::ensure!(
        transports.udp || reaches_relay(lookups, transports),
        "this node has no UDP, so it needs the relay (`relay` in lookup, and a relay transport on this node)"
    );
    Ok(transports)
}

/// Whether this node can dial a relay: the lookup names one, and the node
/// registers a relay transport. A node without UDP reaches a peer only through
/// the relay, and a data channel's handshake crosses the relay too.
fn reaches_relay(lookups: &LookupOpts, transports: lookup::TransportOpts) -> bool {
    lookups.relay_lookup != RelayChoice::Disabled && transports.relay
}

/// Whether a browser, which has no UDP, can run with these lookups and paths
/// (already narrowed to `policy`).
///
/// # Errors
/// A browser that cannot reach the relay (`reaches_relay`). Or a list that
/// leaves both the data channel and relay payload out: nothing could carry
/// its payload.
///
/// # Examples
///
/// In a browser, a setup that asks for a transport the browser lacks is refused. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::TransportOpts;
/// use habilis_network::protocol::TransportPolicy;
/// use habilis_network::protocol::meshes::LookupOpts;
/// use habilis_network::runtime::{SetupError, refuse_in_browser};
///
/// # fn demo(lookups: &LookupOpts, policy: &TransportPolicy, transports: TransportOpts) -> Result<(), SetupError> {
/// refuse_in_browser(lookups, &policy, transports)
/// # }
/// ```
pub fn refuse_in_browser(
    lookups: &LookupOpts,
    policy: &crate_TransportPolicy,
    transports: lookup::TransportOpts,
) -> Result<(), SetupError> {
    refuse_in_browser_checked(lookups, policy, transports).map_err(SetupError::internal)
}

fn refuse_in_browser_checked(
    lookups: &LookupOpts,
    policy: &crate_TransportPolicy,
    transports: lookup::TransportOpts,
) -> Result<()> {
    anyhow::ensure!(
        reaches_relay(lookups, transports),
        BROWSER_NEEDS_RELAY_LOOKUP
    );
    anyhow::ensure!(transports.carry_without_udp(policy), BROWSER_HAS_NO_PATH);
    Ok(())
}

/// The kind-independent build inputs threaded into [`setup_create`] /
/// [`setup_join`]: the loop-shared refs both attach paths need to stand up
/// the endpoint, gossip overlay and rendezvous.
struct SetupBuild<'build> {
    author: &'build Nickname,
    sink: &'build dyn NodeSink,
    max_peers: usize,
    max_direct: usize,
    lookups: &'build LookupOpts,
    unicast_acceptor: &'build transport::UnicastAcceptor,
    chunk_acceptor: &'build transport::ChunkAcceptor,
    /// The mesh policy's `multihop`: register the multi-hop transport on the
    /// peer endpoint.
    #[cfg_attr(
        not(feature = "multihop"),
        expect(
            dead_code,
            reason = "accepted and ignored without the `multihop` feature — see `build_member_endpoint`"
        )
    )]
    multihop: bool,
    transports: lookup::TransportOpts,
    /// The caller's co-host override, read before the policy is final: what a joiner registers
    /// for the rendezvous depends on whether it will walk the ladder.
    cohost: Option<CoHostPolicy>,
    /// The caller's ALPN handlers, moved out exactly once by whichever of
    /// create/join runs. Interior mutability because they are boxed trait
    /// objects — not `Clone` — and `SetupBuild` is threaded by reference.
    ///
    /// `Mutex`, not `RefCell`: `RefCell` is not `Sync`, which made `SetupBuild`
    /// not `Send`, which made the whole `setup_mesh` future not `Send` — so a
    /// consumer could not `tokio::spawn` a mesh setup at all (agent-gossip does,
    /// for its directory advertiser and its `api::Session`). Nothing is
    /// contended here and nothing holds the guard across an `.await`; the
    /// `Mutex` is bought purely for the `Sync` it carries.
    protocols: sync::Mutex<CallerProtocols>,
    rung_tx: &'build watch::Sender<Option<RelayUrl>>,
    /// The mesh's `transport.relay_transport`, for the accept gates.
    relay_transport: transport::PayloadPath,
}

impl SetupBuild<'_> {
    /// Move the caller's ALPN handlers out, leaving the slot empty. Called
    /// exactly once, by whichever of create/join runs.
    fn take_protocols(&self) -> CallerProtocols {
        mem::take(
            &mut *self
                .protocols
                .lock()
                .expect("nothing panics while holding the protocols lock"),
        )
    }
}

/// The ALPN handlers a caller registers on the mesh's Router.
type CallerProtocols = habilis_network_iroh_transport_util::ProtocolSet;

/// The freshly-assembled mesh handles a [`SetupKind`] arm produces.
struct Assembled {
    mesh_id: MeshId,
    mesh_name: MeshName,
    endpoint: Endpoint,
    router: iroh_Router,
    gossip: net::Gossip,
    topic: api::GossipTopic,
    rdv: RendezvousParams,
    cohost: CoHostPolicy,
    /// The raw mesh password (passworded mesh) — retained so the daemon can
    /// key blob tickets with it. `None` when passwordless.
    mesh_password: Option<Password>,
    /// The Argon2id-stretched mesh key — retained to derive the state/meta/
    /// broadcast content-encryption keys. `None` when passwordless. Wiped on drop.
    mesh_key: Option<SymmetricKey>,
    /// The invite-only creator's mesh (with its in-memory issuer key + root),
    /// retained so `invite` can mint. `Some` only on an invite-only creator.
    mint_mesh: Option<Mesh>,
    /// The multi-hop transport handle when the mesh policy has `multihop`, threaded
    /// into `EventLoopState` so the link-state tick can feed its routing table.
    /// Present with the `multihop` feature; the native underlay builder that fills
    /// it, `build_peer_multihop_with`, is host-only.
    #[cfg(feature = "multihop")]
    multihop: Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    /// The `WebRTC` leg of the multihop underlay, threaded into `EventLoopState`
    /// for the alive tick that opens its sessions. `None` when multihop is off.
    #[cfg(feature = "multihop")]
    underlay_webrtc: Option<underlay_webrtc::UnderlayWebRtc>,
    /// The members of the mesh that the LAN announces; see `EventLoopConfig::lan_contacts`.
    lan_contacts: Option<mpsc::Receiver<lookup::LanEvent>>,
    /// This peer's `WebRTC` transport handle, threaded into `EventLoopState` so
    /// the session manager can negotiate with peers as it learns of them, and
    /// so a consumer can read its live direct-peer count.
    webrtc: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    /// The negotiation-slot table the Router's signal acceptor was built with.
    /// Threaded on so `EventLoopState` gets the *same* one — the dialing side
    /// and the answering side must share a ceiling, or neither enforces it.
    webrtc_admission: transport::SignalAdmission,
    /// The address book of the member endpoint: the one place its peers' addresses are registered.
    address_book: memory::MemoryLookup,
    /// How far ICE may reach — host-only on a loopback mesh. Derived from the
    /// mesh's own lookups, so it cannot disagree with them.
    webrtc_ice: transport::IceProfile,
    /// The raw topic string (`SetupKind::Topic` only); `None` for create/join.
    topic_string: Option<String>,
}

/// G and C with `0` taken as the default. Every option set (`Opts`, the C
/// struct, the browser object, a caller's own `SetupParams`) ends in
/// [`setup_mesh`], so this is the one place where that has to hold.
fn resolve_caps(max_peers: usize, max_direct: usize) -> (usize, usize) {
    (
        if max_peers == 0 {
            tuning::GOSSIP_ACTIVE_VIEW_CAPACITY
        } else {
            max_peers
        },
        if max_direct == 0 {
            transport::MAX_DIRECT_PEERS
        } else {
            max_direct
        },
    )
}

/// # Errors
/// The join target fails to resolve, the password fails to verify, or the
/// endpoint cannot bind.
///
/// # Cancellation
/// The setup has many await points, and dropping its future at any of them drops what it built so far (the endpoint
/// and the router) without a graceful close. Let it end, and then shut the node down, for a clean stop. A drop while
/// the start waits for the run lock leaves no lock and no run counter behind: the worker that waits stops at its
/// next step.
///
/// # Examples
///
/// It sets up a mesh from its kind and its parameters, and it returns the config for the event loop. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::{EventLoopConfig, SetupError, SetupKind, SetupParams, setup_mesh};
///
/// # async fn demo(kind: SetupKind, params: SetupParams) -> Result<EventLoopConfig, SetupError> {
/// setup_mesh(kind, params).await
/// # }
/// ```
pub async fn setup_mesh(
    kind: SetupKind,
    params: SetupParams,
) -> Result<EventLoopConfig, SetupError> {
    // `Box::pin` keeps the assembly future off the frame of every caller that awaits it, so those
    // callers stay under clippy's `large_futures` threshold. The size depends on the target, so
    // boxing the one await is more robust than shaving fields.
    Box::pin(setup_mesh_inner(kind, params))
        .await
        .map_err(SetupError::internal)
}

/// The mesh config the setup runs with. Create mints it from the caller's choices; join decodes
/// it from the id, so one source of truth either way.
fn validated_mesh_config(kind: &SetupKind) -> Result<&MeshConfig> {
    let mesh_config = match kind {
        SetupKind::Create { config, .. } => config,
        SetupKind::Join { mesh, .. } | SetupKind::Topic { mesh, .. } => mesh.config(),
    };
    // Decode already validated a joined id; a minted config has had no check
    // yet, and an invalid one would produce an id every joiner rejects.
    mesh_config.validate()?;
    Ok(mesh_config)
}

/// The identity of this member, kept across restarts. Its seed lives in `<state>.key`, mode 0600.
/// A key file of the wrong length is replaced, with a warning. No state file means a new key.
#[cfg(all(unix, feature = "host"))]
fn load_or_create_identity(state: Option<&Path>) -> Result<identity::Identity> {
    use std::io::Read as _;
    let Some(state) = state else {
        return Ok(identity::Identity::generate());
    };
    let key_path = state.with_extension("key");
    let mut reading = OpenOptions::new();
    reading.read(true);
    match open_trusted_key_file(&key_path, &mut reading) {
        Ok(mut file) => {
            // The file holds the raw seed of this member, so both buffers that touch it wipe
            // themselves: a plain `Vec` leaves the seed in freed heap pages for the life of the
            // process.
            let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
            file.read_to_end(&mut bytes)?;
            let seed: Option<Zeroizing<[u8; 32]>> = bytes
                .get(..32)
                .and_then(|seed| <[u8; 32]>::try_from(seed).ok())
                .map(Zeroizing::new);
            if let Some(seed) = seed {
                return Ok(identity::Identity::from_seed(&seed));
            }
            tracing::warn!(target: "habilis_network::lifecycle", "identity key file has the wrong length; a new key replaces it");
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => anyhow::bail!(
            "the member key file {} is not trusted: {error}; remove it to make a new member key",
            key_path.display()
        ),
    }
    let identity = identity::Identity::generate();
    write_key_file(&key_path, identity.seed().as_slice(), 0)?;
    Ok(identity)
}

/// Open the key file with `options`, without following a link, and check the OPEN file: a regular file, owned by
/// this user, that group and others cannot access (the mode that `write_key_file` makes). Its seed becomes the
/// identity of this member, so a file that another user planted is not used. The checks are on the descriptor, not
/// on the path, so a link or a file that is put at the path between a check and the open cannot slip through. A
/// missing file is `NotFound`; a file that fails a check is `PermissionDenied`.
#[cfg(all(unix, feature = "host"))]
fn open_trusted_key_file(key_path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    use rustix::io::Errno;
    use rustix::process::geteuid;
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let file: File = options
        .custom_flags(no_link_flags())
        .open(key_path)
        .map_err(|error| {
            if error.raw_os_error() == Some(Errno::LOOP.raw_os_error()) {
                Error::new(ErrorKind::PermissionDenied, "it is a link")
            } else {
                error
            }
        })?;
    let meta = file.metadata()?;
    let refused: Option<&str> = if !meta.file_type().is_file() {
        Some("it is not a regular file")
    } else if meta.uid() != geteuid().as_raw() {
        Some("another user owns it")
    } else if meta.permissions().mode() & 0o077 != 0 {
        Some("group or others can access it")
    } else {
        None
    };
    match refused {
        Some(why) => Err(Error::new(ErrorKind::PermissionDenied, why)),
        None => Ok(file),
    }
}

/// The flags for every file that the member key, the run counter and the lock keep in the state folder: no
/// link is followed, so a link that is planted at the path cannot make a start lock, write or cut the file
/// that it points to. `NONBLOCK`: an open of a FIFO with no peer waits for one, and a regular file ignores the
/// flag.
#[cfg(all(unix, feature = "host"))]
fn no_link_flags() -> i32 {
    use rustix::fs::OFlags;
    i32::try_from((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits()).unwrap_or(0)
}

/// Write the member key file: the 32 bytes of the seed, then the start time of the process that owns
/// the daemon (0 until the owner is known), as 8 bytes. The file is private to the user.
#[cfg(all(unix, feature = "host"))]
fn write_key_file(key_path: &Path, seed: &[u8], owner_start: u64) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    // The last run that the file names stays: the owner of the file changes, the count does not.
    let last_run = last_recorded_run_in(key_path);
    // No truncate at the open: a file that fails the checks is not touched, and one that passes is cut after.
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false).mode(0o600);
    let mut file = open_trusted_key_file(key_path, &mut options)?;
    file.set_len(0)?;
    file.write_all(seed)?;
    file.write_all(&owner_start.to_le_bytes())?;
    if let Some(last_run) = last_run {
        file.write_all(&last_run.to_le_bytes())?;
    }
    Ok(())
}

/// The run number of this start, kept in `<state>.run`. It counts up by 1 at each start and never
/// reads the clock, so a clock that went back cannot make a newer run look older. The one exception
/// is a lost file: then the count restarts from the clock (see `counter_lost`). A missing file is a
/// lost file when a member key exists, since peers hold runs above 1 for that member. No state file
/// means run 1.
#[cfg(all(unix, feature = "host"))]
fn next_run(state: Option<&Path>, member_known: bool, cancel: &AtomicBool) -> Result<u64> {
    use std::io::ErrorKind;
    let Some(state) = state else {
        return Ok(1);
    };
    let run_path = state.with_extension("run");
    // The read of the counter and the write of the next one are one step: two starts of one state path
    // would otherwise read one count and publish one run. The lock is on a file of its own, because the
    // counter file is replaced by a rename; it is held until `run_lock` drops at the end of the call.
    let run_lock = lock_run_counter(state, cancel)?;
    let run = match read_run_file(&run_path) {
        Ok(bytes) => match <[u8; 8]>::try_from(bytes.as_slice()) {
            Ok(last) => u64::from_le_bytes(last).saturating_add(1),
            Err(_) => counter_lost(state),
        },
        // No counter, but a member key from an earlier start: the counter was deleted. Peers hold
        // runs above 1 for this member, so the count restarts from the clock, as for a bad file.
        Err(error) if error.kind() == ErrorKind::NotFound && member_known => counter_lost(state),
        Err(error) if error.kind() == ErrorKind::NotFound => 1,
        Err(_) => counter_lost(state),
    };
    write_run(state, run)?;
    record_last_run(state, run);
    drop(run_lock);
    Ok(run)
}

/// The bytes of the run counter file, read like the key file: no link is followed, a file that is not a regular
/// file is refused, and at most 16 bytes are read (the counter is 8 bytes, and a file of another length is not a
/// counter).
#[cfg(all(unix, feature = "host"))]
fn read_run_file(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind, Read as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(no_link_flags());
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "it is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(16).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Keep `run` in the member key file too, at bytes 40 to 48 (after the seed and the owner start), as the second
/// record of the counter. A start that loses the counter file a second time, after the clock went back, reads it
/// there. A key file that is too short to hold it is left as it is.
#[cfg(all(unix, feature = "host"))]
fn record_last_run(state: &Path, run: u64) {
    use std::io::ErrorKind;
    use std::os::unix::fs::FileExt as _;
    let mut writing = OpenOptions::new();
    writing.write(true);
    let opened = open_trusted_key_file(&state.with_extension("key"), &mut writing);
    let file = match opened {
        Ok(file) => file,
        // No key file, no second record: a state path with no member key keeps the one counter file.
        Err(error) if error.kind() == ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(target: "habilis_network::lifecycle", %error, "the last run could not be recorded in the key file");
            return;
        }
    };
    if let Err(error) = file.write_all_at(&run.to_le_bytes(), 40) {
        tracing::warn!(target: "habilis_network::lifecycle", %error, "the last run could not be recorded in the key file");
    }
}

/// The last run that the member key file of `state` names, if it names one.
#[cfg(all(unix, feature = "host"))]
fn last_recorded_run(state: &Path) -> Option<u64> {
    last_recorded_run_in(&state.with_extension("key"))
}

/// The last run that the key file at `key_path` names, if it names one.
#[cfg(all(unix, feature = "host"))]
fn last_recorded_run_in(key_path: &Path) -> Option<u64> {
    use std::os::unix::fs::FileExt as _;
    let mut reading = OpenOptions::new();
    reading.read(true);
    let file = open_trusted_key_file(key_path, &mut reading).ok()?;
    // Only the 8 bytes of the counter are read: the seed in the first 32 bytes never enters this process's
    // heap through a buffer that is not wiped.
    let mut counter = [0u8; 8];
    file.read_exact_at(&mut counter, 40).ok()?;
    Some(u64::from_le_bytes(counter))
}

/// Take the exclusive lock on `<state>.key.lock` and keep it as long as the returned file lives, so two
/// live starts of one state path cannot be one member: the second would read the same member key and take
/// the next run, and a peer would drop the first as an older run of that member. Each try is non-blocking, and
/// a held lock is tried again for `KEY_LOCK_RETRY`, in steps of `KEY_LOCK_STEP`, because a restart that comes
/// right after a leave meets the old daemon while it still stops; the wait is a timer of the runtime, so the
/// old daemon, which may run on the same thread, still gets to stop. After that the start fails and names the
/// way out. It is an OS lock on the descriptor, so it goes with the process, and a crash frees the key. The
/// file is opened close-on-exec (the default of Rust), so a child of the daemon does not keep the lock after
/// the daemon is gone. No state path means no key to keep. A file system that has no file locks cannot start
/// a daemon with a member key: the error names the lock file.
#[cfg(all(unix, feature = "host"))]
// the lock is shared with every clone of the keys, and the last one to drop frees it
async fn hold_member_key(state: Option<&Path>) -> Result<Option<sync::Arc<File>>> {
    let Some(state) = state else {
        return Ok(None);
    };
    let lock = open_key_lock(state)?;
    let give_up = Instant::now() + KEY_LOCK_RETRY;
    while !try_key_lock(&lock, state)? {
        if Instant::now() >= give_up {
            return Err(key_held_error(state));
        }
        time::sleep(KEY_LOCK_STEP).await;
    }
    // shared with every clone of the keys: the lock goes when the last one drops
    Ok(Some(sync::Arc::new(lock)))
}

/// [`hold_member_key`] with one try and no wait, for a caller that is not async.
#[cfg(all(unix, feature = "host"))]
// the lock is shared with every clone of the keys, and the last one to drop frees it
fn hold_member_key_once(state: Option<&Path>) -> Result<Option<sync::Arc<File>>> {
    let Some(state) = state else {
        return Ok(None);
    };
    let lock = open_key_lock(state)?;
    if try_key_lock(&lock, state)? {
        // shared with every clone of the keys: the lock goes when the last one drops
        Ok(Some(sync::Arc::new(lock)))
    } else {
        Err(key_held_error(state))
    }
}

/// What is wrong with a state folder of this `mode`, owned by user `owner`, for the user `effective_user` who
/// starts the node. The member key, the run counter and the lock live in that folder. A user who can write it
/// can unlink or rename them while they are held: a second start then reads the same member key at a higher
/// run, and peers replace the first session. That user is the owner of the folder when it is not the user who
/// starts the node (root excepted), and anyone who can write it through its group or as an other (unless the
/// sticky bit, as on `/tmp`, stops other users from unlinking or renaming files that they do not own). A folder
/// that only the group can write is refused too: a trusted group cannot be known (the members of a group come
/// from several sources, and the primary group of a user is not in the list), and there is no setting for it.
#[cfg(all(unix, feature = "host"))]
fn state_folder_problem(mode: u32, owner: u32, effective_user: u32) -> Option<&'static str> {
    // The owner of a folder can unlink or rename any file in it, sticky bit or not. Root owns `/tmp` and can
    // do that to any file anyway.
    if owner != effective_user && owner != 0 {
        return Some("is owned by another user");
    }
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Some(
            "can be written by other users (its group or the others) and has no sticky bit",
        );
    }
    None
}

/// Refuse a state folder that [`state_folder_problem`] names. A folder that cannot be read is left to the open
/// of the lock file, which names it.
#[cfg(all(unix, feature = "host"))]
fn refuse_shared_state_folder(state: &Path) -> Result<()> {
    use rustix::process::geteuid;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let parent: Option<&Path> = state.parent();
    let named: Option<&Path> = parent.filter(|folder| !folder.as_os_str().is_empty());
    let folder: &Path = named.unwrap_or_else(|| Path::new("."));
    let Ok(meta) = fs::metadata(folder) else {
        return Ok(());
    };
    let mode = meta.permissions().mode();
    if let Some(problem) = state_folder_problem(mode, meta.uid(), geteuid().as_raw()) {
        anyhow::bail!(
            "the state folder {folder} {problem}, so another user could remove the member key or its lock: use a --state-file in a private folder of this user (`chmod go-w {folder}` closes the group-write and the other-write case)",
            folder = folder.display()
        );
    }
    Ok(())
}

/// What is wrong with a lock file that was opened: a lock file must be a regular file that the user who starts
/// the node owns. In a sticky folder (`/tmp` style) another user can create the name first. The file is theirs
/// then: they can unlink or replace it while we hold the lock, so a second start locks another file, or they can
/// hold the lock themselves. Root is not accepted: nobody else should own a lock file of this user.
#[cfg(all(unix, feature = "host"))]
fn lock_file_problem(is_regular: bool, owner: u32, effective_user: u32) -> Option<&'static str> {
    if !is_regular {
        return Some("is not a regular file");
    }
    if owner != effective_user {
        return Some("is owned by another user");
    }
    None
}

/// Refuse a lock file that [`lock_file_problem`] names. The check is on the opened file (`fstat` on the
/// descriptor), so a file that is put at the path between a check and the open cannot slip in.
#[cfg(all(unix, feature = "host"))]
fn refuse_foreign_lock_file(lock: &File, path: &Path) -> Result<()> {
    use anyhow::Context as _;
    use rustix::process::geteuid;
    use std::fs::Metadata;
    use std::os::unix::fs::MetadataExt as _;
    let meta: Metadata = lock
        .metadata()
        .with_context(|| format!("the lock file {} cannot be read", path.display()))?;
    let is_regular: bool = meta.file_type().is_file();
    let problem: Option<&str> = lock_file_problem(is_regular, meta.uid(), geteuid().as_raw());
    if let Some(problem) = problem {
        anyhow::bail!(
            "the lock file {path} {problem}, so it cannot keep two starts apart: remove it if no daemon runs, or use a --state-file in a private folder of this user",
            path = path.display()
        );
    }
    Ok(())
}

/// Open the lock file of the member key of `state`, mode 0600.
#[cfg(all(unix, feature = "host"))]
fn open_key_lock(state: &Path) -> Result<File> {
    use anyhow::Context as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    refuse_shared_state_folder(state)?;
    let lock_path = state.with_extension("key.lock");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false).mode(0o600);
    let lock: File = options
        .custom_flags(no_link_flags())
        .open(&lock_path)
        .with_context(|| format!("the lock file {} cannot be opened", lock_path.display()))?;
    refuse_foreign_lock_file(&lock, &lock_path)?;
    Ok(lock)
}

/// One try at the lock: true when it is taken, false when another holder has it.
#[cfg(all(unix, feature = "host"))]
fn try_key_lock(lock: &File, state: &Path) -> Result<bool> {
    use std::fs::TryLockError;
    match lock.try_lock() {
        Ok(()) => Ok(true),
        Err(TryLockError::WouldBlock) => Ok(false),
        Err(TryLockError::Error(error)) => Err(anyhow::Error::from(error).context(format!(
            "the lock file {} cannot be locked: the file system may not support file locks, and a daemon with a member key cannot start there",
            state.with_extension("key.lock").display()
        ))),
    }
}

/// The error of a start that finds the member key held.
#[cfg(all(unix, feature = "host"))]
fn key_held_error(state: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "another daemon still runs on this state file and holds the member key {}: wait for it to exit and retry, or use another nickname or --state-file",
        state.with_extension("key").display()
    )
}

/// The longest that a start waits for the run lock in all, whatever the counter does: a holder that keeps
/// writing the counter file must not hold a worker of the runtime for ever.
#[cfg(all(unix, feature = "host"))]
const RUN_LOCK_CAP: Duration = Duration::from_secs(30);
/// How long a start tries again for the lock of the member key, while the daemon that holds it stops.
#[cfg(all(unix, feature = "host"))]
const KEY_LOCK_RETRY: Duration = Duration::from_secs(2);
/// The wait between two tries for the lock of the member key.
#[cfg(all(unix, feature = "host"))]
const KEY_LOCK_STEP: Duration = Duration::from_millis(50);

/// A target with no files keeps no member key, so it takes no lock.
#[cfg(not(all(unix, feature = "host")))]
#[expect(
    clippy::unused_async,
    reason = "the same signature as the version for a target with files"
)]
// the same type as the version for a target with files
async fn hold_member_key(_state: Option<&Path>) -> Result<Option<sync::Arc<File>>> {
    Ok(None)
}

/// [`hold_member_key`] with one try, for a caller that is not async: no lock on a target with no files.
#[cfg(not(all(unix, feature = "host")))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the version for a target with files"
)]
// the same type as the version for a target with files
fn hold_member_key_once(_state: Option<&Path>) -> Result<Option<sync::Arc<File>>> {
    Ok(None)
}

/// Take the exclusive lock on `<state>.run.lock`, which makes the allocation of a run one step across
/// processes and threads. The lock is held for one read and one write of the counter, so a holder lets go at
/// once. A holder that does not (in a sticky folder, a user who made the file first and locked it) must not block
/// a worker of the runtime for ever. The lock is tried again, in steps of `KEY_LOCK_STEP`, for as long as the
/// counter moves: when other starts take the lock in turn, each one writes the counter file, and a start that
/// waits in a queue of them is not stuck. The wait ends, and the start fails and names the file, when the counter
/// has not moved for `KEY_LOCK_RETRY`, and in any case after `RUN_LOCK_CAP`. The movement is read from the
/// modification time of the counter file with no link followed; a file system with a coarse clock (FAT keeps 2 s)
/// shows a movement late, which the cap bounds. The wait is a sleep of this thread, because the caller is not async: it
/// holds a worker for `KEY_LOCK_RETRY` when a holder does not let go. The lock goes with the returned file.
#[cfg(all(unix, feature = "host"))]
fn lock_run_counter(state: &Path, cancel: &AtomicBool) -> Result<File> {
    lock_run_counter_within(state, KEY_LOCK_RETRY, RUN_LOCK_CAP, cancel)
}

/// [`lock_run_counter`] with its two bounds as parameters: `stall` is how long the counter may stand still while
/// the lock is held by another start, and `cap` is the longest wait in all.
#[cfg(all(unix, feature = "host"))]
fn lock_run_counter_within(
    state: &Path,
    stall: Duration,
    cap: Duration,
    cancel: &AtomicBool,
) -> Result<File> {
    use std::fs::{self, TryLockError};
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::thread;
    let lock_path = state.with_extension("run.lock");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false).mode(0o600);
    options.custom_flags(no_link_flags());
    let lock = options.open(&lock_path)?;
    refuse_foreign_lock_file(&lock, &lock_path)?;
    // When the counter file was written last: a holder that lets go writes it, so a change is a start that made
    // progress, and the wait for it starts again.
    let run_path = state.with_extension("run");
    // `symlink_metadata`: no link is followed. A link at the counter path moves only when it is replaced, and
    // another user cannot make progress by touching the file that the link points to.
    let moved = || {
        let meta: Option<fs::Metadata> = fs::symlink_metadata(&run_path).ok();
        meta.and_then(|meta| meta.modified().ok())
    };
    let mut last_move = moved();
    let started = Instant::now();
    let mut give_up = started + stall;
    loop {
        match lock.try_lock() {
            // The flag is read here as well as in the wait below: a lock that nobody holds, or one that the
            // holder let go while this worker slept, is taken without ever reaching the wait.
            Ok(()) if cancel.load(Ordering::Relaxed) => anyhow::bail!(
                "the start was cancelled before it took the run lock {}",
                lock_path.display()
            ),
            Ok(()) => return Ok(lock),
            Err(TryLockError::WouldBlock) => {
                if cancel.load(Ordering::Relaxed) {
                    anyhow::bail!(
                        "the start was cancelled while it waited for the run lock {}",
                        lock_path.display()
                    );
                }
                let now = Instant::now();
                let latest = moved();
                if latest != last_move {
                    last_move = latest;
                    give_up = now + stall;
                }
                // The stall bound restarts at each write of the counter; the cap does not: a holder that keeps
                // writing must not hold a worker of the runtime for ever.
                if now < give_up && now.saturating_duration_since(started) < cap {
                    thread::sleep(KEY_LOCK_STEP);
                    continue;
                }
                anyhow::bail!(
                    "the run lock {path} is held by another start, and the run counter has not moved for {wait} s, or the wait passed {limit} s: wait for it, or remove the file if no daemon runs",
                    path = lock_path.display(),
                    wait = stall.as_secs(),
                    limit = cap.as_secs()
                );
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
    }
}

/// Keep `run` in `<state>.run`.
#[cfg(all(unix, feature = "host"))]
fn write_run(state: &Path, run: u64) -> Result<()> {
    use std::fs::{self, File, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let run_path = state.with_extension("run");
    // A crash after the write and before the rename leaves the old counter, never a cut short one.
    let tmp_path = state.with_extension("run.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    options.custom_flags(no_link_flags());
    let mut file = options.open(&tmp_path)?;
    file.write_all(&run.to_le_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp_path, &run_path)?;
    // Without this, a power loss can undo the rename, and the next start repeats a run that peers saw.
    if let Some(folder) = run_path
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
    {
        File::open(folder)?.sync_all()?;
    }
    Ok(())
}

/// The counter file is unreadable, so the count restarts from the unix seconds: the counter grows by
/// 1 per start and the seconds grow faster, so the number is above any count that peers kept. A clock that went
/// back since an earlier loss could still give a lower number, so the run is never below the last run that the
/// key file names, plus one.
#[cfg(all(unix, feature = "host"))]
fn counter_lost(state: &Path) -> u64 {
    use crate::protocol::UnixSecs;
    let clock = u64::try_from(UnixSecs::now().as_secs()).unwrap_or(1).max(1);
    let run = last_recorded_run(state).map_or(clock, |last| clock.max(last.saturating_add(1)));
    tracing::warn!(target: "habilis_network::lifecycle", new_run = run, "run counter file is unreadable, so its old run is unknown; the count restarts from the clock");
    run
}

/// A target with no files has no state to count in, so each start is run 1.
#[cfg(not(all(unix, feature = "host")))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the file-backed version, so the caller is one call"
)]
fn next_run(_state: Option<&Path>, _member_known: bool, _cancel: &AtomicBool) -> Result<u64> {
    Ok(1)
}

/// The member key of this node, kept in the state file. A target with no files (wasm, or a build
/// without `host`) has none: a key made at each start would prove nothing across restarts.
#[cfg(all(unix, feature = "host"))]
// the key is shared with the loop and its handlers, which hold clones
fn member_key(state: Option<&Path>) -> Result<Option<sync::Arc<identity::Identity>>> {
    // shared with the loop and its handlers, which hold clones
    Ok(Some(sync::Arc::new(load_or_create_identity(state)?)))
}

/// A target with no files has no member key.
#[cfg(not(all(unix, feature = "host")))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the version for a target with files"
)]
// the key is shared with the loop and its handlers, which hold clones
fn member_key(_state: Option<&Path>) -> Result<Option<sync::Arc<identity::Identity>>> {
    Ok(None)
}

/// [`bind_to_owner`] for the keys of a start, under the path that they came from. The explicit state
/// file is not that path: a start with no state file of its own keeps its pair under the default
/// path of the mesh, and a caller that read the explicit file alone would bind nothing.
#[cfg(feature = "host")]
pub(crate) fn bind_keys_to_owner(keys: RunKeys, owner_start: Option<u64>) -> RunKeys {
    let state = keys.keys_state.clone();
    bind_to_owner(keys, state.as_deref(), owner_start)
}

/// Bind the member key and the run counter to the process that owns the daemon. The pair is kept in
/// files so that a restart of the same agent keeps its identity, and the files are named for the pid
/// of the agent. After a crash a later agent can get the same pid, and it must not take the identity
/// of the one that crashed. The key file holds the start time of the owner, which differs for two
/// processes of one pid: they start in different seconds, unless the pid wrapped within one second of
/// the first. A pair made by this very start is stamped. A pair of another owner, with no stamp, or
/// with no start time to check against, is not reused: a new member, at run 1.
#[cfg(all(unix, feature = "host"))]
pub(crate) fn bind_to_owner(
    keys: RunKeys,
    state: Option<&Path>,
    owner_start: Option<u64>,
) -> RunKeys {
    use std::fs;
    let (Some(state), Some(member)) = (state, keys.member.as_ref()) else {
        return keys;
    };
    let key_path = state.with_extension("key");
    // The read takes the seed as well as the owner start, so the buffer wipes itself.
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(fs::read(&key_path).unwrap_or_default());
    let tail = bytes
        .get(32..40)
        .and_then(|tail| <[u8; 8]>::try_from(tail).ok());
    let held = tail.map(u64::from_le_bytes);
    match (owner_start, held) {
        (Some(start), Some(held)) if held == start => keys,
        (Some(start), _) if keys.member_new => {
            if let Err(error) = write_key_file(&key_path, member.seed().as_slice(), start) {
                tracing::warn!(target: "habilis_network::lifecycle", %error, "the owner of the member key could not be kept");
            }
            keys
        }
        (None, _) if keys.member_new => keys,
        _ => replace_member(keys, state, owner_start.unwrap_or(0)),
    }
}

/// A target with no files has no pair of files to bind to an owner.
#[cfg(all(not(all(unix, feature = "host")), feature = "host"))]
pub(crate) fn bind_to_owner(
    keys: RunKeys,
    _state: Option<&Path>,
    _owner_start: Option<u64>,
) -> RunKeys {
    keys
}

/// A new member key and run 1, kept in the files, for a pair that another owner left behind.
#[cfg(all(unix, feature = "host"))]
fn replace_member(keys: RunKeys, state: &Path, owner_start: u64) -> RunKeys {
    let member = identity::Identity::generate();
    let key_path = state.with_extension("key");
    let seed = member.seed();
    let key_written = write_key_file(&key_path, seed.as_slice(), owner_start);
    let written = key_written.and_then(|()| write_run(state, 1));
    if let Err(error) = written {
        tracing::warn!(target: "habilis_network::lifecycle", %error, "the new member key could not be kept");
    }
    tracing::warn!(target: "habilis_network::lifecycle", "the member key and the run counter are from another owner, so a new member key replaces them and the run starts at 1");
    RunKeys {
        // shared with the loop and its handlers, which hold clones
        member: Some(sync::Arc::new(member)),
        run: 1,
        member_new: true,
        ..keys
    }
}

/// The state path that the member key and the run counter live under: the state file when there is one, and
/// otherwise, for a caller that asks for it (`keys_in_default_state`), the default state path of the mesh
/// under the runtime base. `None` keeps ephemeral keys.
#[cfg_attr(
    not(feature = "host"),
    expect(
        clippy::unnecessary_wraps,
        reason = "the same signature as the host version, which can fail to make the folder"
    )
)]
fn keys_state_path(
    state_file: Option<&Path>,
    runtime_base: Option<&Path>,
    mesh: &MeshId,
    author: &Nickname,
    in_default_state: bool,
) -> Result<Option<PathBuf>> {
    let explicit = state_file.map(Path::to_path_buf);
    #[cfg(feature = "host")]
    {
        use crate::util;
        if explicit.is_some() {
            return Ok(explicit);
        }
        let Some(base) = runtime_base.filter(|_| in_default_state) else {
            return Ok(None);
        };
        // The key file goes in the folder of the mesh, which the control socket would make later.
        util::ensure_mesh_runtime_dir(base, mesh.as_str())?;
        Ok(Some(default_state_path(base, mesh, author)))
    }
    #[cfg(not(feature = "host"))]
    {
        let _ = (runtime_base, mesh, author, in_default_state);
        Ok(explicit)
    }
}

/// The default state path of a mesh: `<runtime base>/<mesh folder>/<nickname>.state.json`, where the CLI keeps
/// the readiness file of a daemon that was given no `--state-file`.
#[cfg(feature = "host")]
pub(crate) fn default_state_path(base: &Path, mesh: &MeshId, author: &Nickname) -> PathBuf {
    use crate::util;
    util::mesh_runtime_dir(base, mesh.as_str()).join(format!("{author}.state.json"))
}

/// The chunk folder of a node: `<runtime base>/<mesh folder>/<nickname>.chunks`. A run clears it when it starts.
#[cfg(feature = "host")]
pub(crate) fn default_chunks_path(base: &Path, mesh: &MeshId, author: &Nickname) -> PathBuf {
    use crate::util;
    util::mesh_runtime_dir(base, mesh.as_str()).join(format!("{author}.chunks"))
}

/// The keys of this run, under the state path that [`keys_state_path`] gives. `mesh` is the mesh id and the
/// nickname of this member.
async fn run_keys_for(
    state_file: Option<&Path>,
    runtime_base: Option<&Path>,
    keys_in_default_state: bool,
    (mesh, author): (&MeshId, &Nickname),
    // shared with every clone of the keys; `None` where the lock was not taken before the setup
    key_lock: Option<sync::Arc<File>>,
) -> Result<RunKeys> {
    let keys_path = keys_state_path(
        state_file,
        runtime_base,
        mesh,
        author,
        keys_in_default_state,
    )?;
    run_keys_off_the_runtime(keys_path, key_lock).await
}

/// The flag of a start that nobody cancels, for the tests of the run counter.
#[cfg(test)]
static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);

/// Sets its flag when it drops: the cancel signal of a worker that cannot be stopped from outside.
struct CancelOnDrop(
    // shared with the worker, which reads it at each step of its wait
    sync::Arc<AtomicBool>,
);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// [`run_keys`] or [`run_keys_holding`], on a blocking worker: the wait for the run lock sleeps its thread, for
/// 30 s at the most, and it must not stop the timers of a runtime that runs on one thread. A browser has no such
/// worker (`spawn_blocking` needs `rt-multi-thread`), and a target with no files has no lock to wait for.
#[cfg_attr(
    not(feature = "host"),
    expect(
        clippy::unused_async,
        reason = "a target with no blocking worker runs the keys inline, and keeps the signature"
    )
)]
async fn run_keys_off_the_runtime(
    keys_path: Option<PathBuf>,
    // the lock is shared with every clone of the keys, and the last one to drop frees it
    key_lock: Option<sync::Arc<File>>,
) -> Result<RunKeys> {
    // The worker cannot be stopped from outside: when this future is dropped (the setup was cancelled) the guard
    // sets the flag, and the wait for the run lock ends at its next step and takes nothing.
    // shared by the worker, which reads it, and the guard, which sets it
    let cancel = sync::Arc::new(AtomicBool::new(false));
    // the second handle, for the guard
    let _cancel_on_drop = CancelOnDrop(sync::Arc::clone(&cancel));
    let run = move || match key_lock {
        Some(held) => run_keys_holding(keys_path.as_deref(), Some(held), &cancel),
        // a new mesh has a random id, so its default state path cannot be held by another start
        None => run_keys(keys_path.as_deref(), &cancel),
    };
    #[cfg(feature = "host")]
    {
        task::spawn_blocking(run).await?
    }
    #[cfg(not(feature = "host"))]
    {
        run()
    }
}

/// The state path of the keys of a start, as far as it is known before the endpoint is bound: the explicit
/// state file, or the default path of a mesh that the id names (a join or a topic). A new mesh has no id yet,
/// and a random one, so its default state path is nobody else's.
fn early_keys_state_path(
    kind: &SetupKind,
    state_file: Option<&Path>,
    runtime_base: Option<&Path>,
    keys_in_default_state: bool,
    author: &Nickname,
) -> Result<Option<PathBuf>> {
    match kind {
        SetupKind::Join { mesh, .. } | SetupKind::Topic { mesh, .. } => {
            let id = MeshId::try_new(&mesh.to_string())
                .expect("Mesh::to_string always produces a valid MeshId");
            keys_state_path(state_file, runtime_base, &id, author, keys_in_default_state)
        }
        SetupKind::Create { .. } => Ok(state_file.map(Path::to_path_buf)),
    }
}

/// The keys of this run. The member key comes from the state file. The session key is the one that
/// signs frames and is the seal key, so it must be new each run: a restart that reused it would sign
/// as the old run.
fn run_keys(state: Option<&Path>, cancel: &AtomicBool) -> Result<RunKeys> {
    run_keys_holding(state, hold_member_key_once(state)?, cancel)
}

/// [`run_keys`] for a start that holds the lock of the member key of `state` already: the setup takes it
/// before it binds an endpoint, so a refused start leaves nothing behind.
fn run_keys_holding(
    state: Option<&Path>,
    // the lock is shared with every clone of the keys, and the last one to drop frees it
    key_lock: Option<sync::Arc<File>>,
    cancel: &AtomicBool,
) -> Result<RunKeys> {
    // read before `member_key` makes the file: a member key that exists is from an earlier start
    let member_known = state.is_some_and(|state| state.with_extension("key").exists());
    Ok(RunKeys {
        key_lock,
        keys_state: state.map(Path::to_path_buf),
        // shared with the loop and its handlers, which hold clones
        session: sync::Arc::new(identity::Identity::generate()),
        member: member_key(state)?,
        run: next_run(state, member_known, cancel)?,
        member_new: !member_known,
    })
}

/// The caller owns an endpoint that it injected; the engine owns the one that it binds.
fn owner_of(injected: Option<&InjectedEndpoint>) -> EndpointOwner {
    if injected.is_none() {
        EndpointOwner::Engine
    } else {
        EndpointOwner::Caller
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the setup is one assembly of the mesh, in the order that its parts need"
)]
async fn setup_mesh_inner(kind: SetupKind, params: SetupParams) -> Result<EventLoopConfig> {
    let SetupParams {
        author,
        max_peers,
        max_direct,
        runtime_base,
        state_file,
        keys_in_default_state,
        sink,
        cohost: cohost_override,
        live_count,
        endpoint: injected,
        protocols,
        transports,
    } = params;
    // The member key is taken first, before an endpoint is bound or a topic joined: a start that another
    // daemon holds the key of fails with nothing left behind.
    let early_state = early_keys_state_path(
        &kind,
        state_file.as_deref(),
        runtime_base.as_deref(),
        keys_in_default_state,
        &author,
    )?;
    let key_lock = hold_member_key(early_state.as_deref()).await?;
    let endpoint_owner = owner_of(injected.as_ref());
    let (max_peers, max_direct) = resolve_caps(max_peers, max_direct);
    // The localhost binding is owned + bound by the caller; the engine only needs
    // the resolved port for the `ready` event. `Some(0)` (ephemeral) is resolved
    // caller-side and passed back in here as the real port.
    let mesh_config = validated_mesh_config(&kind)?;
    let lookups = mesh_config.lookups.clone();
    let relay_transport =
        transport::PayloadPath::from(mesh_config.transport.allows(Transport::Relay));
    let transports = member_transports(&lookups, transports, &mesh_config.transport)?;
    // The off-loop rung channel: the backgrounded startup probe and the
    // beacon's liveness self-monitor publish a chosen rung here; the
    // event loop applies it (re-register + re-home) without ever running
    // a ladder walk on the sole loop. Initialized to the optimistic
    // rung 0 (empty ladder ⇒ `None`).
    let ladder: Vec<_> = relay_ladder(&lookups.relay_lookup).collect();
    let (rung_tx, rung_rx) = watch::channel(ladder.first().cloned());
    let (unicast_rx, unicast_acceptor) = unicast_inbox(relay_transport);
    let (chunk_rx, chunk_acceptor) = chunk_inbox(relay_transport);

    let build = SetupBuild {
        author: &author,
        sink: sink.as_ref(),
        max_peers,
        max_direct,
        lookups: &lookups,
        unicast_acceptor: &unicast_acceptor,
        chunk_acceptor: &chunk_acceptor,
        // The mesh policy's `multihop`, on a node that has a direct path for its underlay to
        // forward over: UDP, or a WebRTC data channel when IP is cleared. With neither there is
        // no direct path, and no handle.
        multihop: mesh_config.transport.allows(Transport::Multihop)
            && (transports.udp || transports.webrtc),
        transports,
        protocols: sync::Mutex::new(protocols),
        rung_tx: &rung_tx,
        relay_transport,
        cohost: cohost_override,
    };
    let Assembled {
        mesh_id,
        mesh_name,
        endpoint,
        router,
        gossip,
        topic,
        rdv,
        cohost,
        mesh_password,
        mesh_key,
        mint_mesh,
        #[cfg(feature = "multihop")]
            multihop: multihop_handle,
        #[cfg(feature = "multihop")]
        underlay_webrtc,
        lan_contacts,
        webrtc,
        webrtc_admission,
        address_book,
        webrtc_ice,
        topic_string,
    } = assemble(kind, &build, injected).await?;
    // Read out of `build` before anything below moves what it borrows
    // (`author`, `sink`, `rung_tx`).

    let keys = run_keys_for(
        state_file.as_deref(),
        runtime_base.as_deref(),
        keys_in_default_state,
        (&mesh_id, &author),
        key_lock,
    )
    .await?;
    Ok(EventLoopConfig {
        mesh: MeshSpec {
            mesh: mesh_id,
            name: mesh_name,
            topic_string,
            mint_mesh,
            author,
            // The mesh spec and the loop state both hold the keys, so they are shared.
            keys,
            mesh_password,
            mesh_key,
        },
        transports: TransportSet {
            webrtc,
            webrtc_enabled: transports.webrtc,
            webrtc_admission,
            webrtc_ice,
            address_book,
            local_udp_transport: UdpTransport::from(transports.udp),
            relay_transport,
            #[cfg(feature = "multihop")]
            multihop: multihop_handle,
            #[cfg(feature = "multihop")]
            underlay_webrtc,
        },
        endpoints: Endpoints {
            topic,
            gossip,
            endpoint,
            endpoint_owner,
            router,
            unicast_rx,
            chunk_rx,
            lan_contacts,
        },
        rendezvous: RendezvousConfig {
            rendezvous_params: rdv,
            rung_rx,
            // Off the critical path: nothing below blocks `ready`, which `run` emits
            // once the IPC socket accepts. Confirm/correct the optimistic rung 0 in the
            // background (covers a joiner, which has no beacon self-monitor of its own).
            rung_probe: spawn_startup_rung_confirmation(ladder, rung_tx),
            cohost: cohost_override.unwrap_or(cohost),
        },
        runtime: RuntimeConfig {
            sink,
            max_peers,
            runtime_base,
            state_file,
            live_count,
            // Default to the CLI driver; the in-process sessions
            // overwrite `cfg.runtime.driver` before handing it to `daemon::run`.
            driver: DriverMode::Cli,
            #[cfg(feature = "host")]
            owner: None,
        },
    })
}

async fn assemble(
    kind: SetupKind,
    build: &SetupBuild<'_>,
    injected: Option<InjectedEndpoint>,
) -> Result<Assembled> {
    Ok(match kind {
        SetupKind::Create {
            name,
            config,
            advertise,
            password,
            invite_only,
        } => {
            setup_create(
                build,
                CreateSetup {
                    name,
                    config,
                    advertise,
                    password,
                    invite_only,
                },
                injected,
            )
            .await?
        }
        kind @ (SetupKind::Join { .. } | SetupKind::Topic { .. }) => {
            setup_join(build, kind, injected).await?
        }
    })
}

/// Stand up the gossip overlay, and with it the one admission table and ICE
/// profile this node uses.
///
/// Shared by both attach arms because the coupling is what matters: the signal
/// acceptor built inside [`build_mesh`] gets a clone of the *same* table
/// `EventLoopState` gets. Two tables would be two ceilings, each enforcing half
/// of one — the failure `SignalAdmission` exists to make impossible.
///
/// A loopback mesh gathers host candidates only. Anything else would put STUN
/// packets on the wire from a mesh whose whole point is that it makes no
/// external network call.
fn build_overlay(
    build: &SetupBuild<'_>,
    mesh: &Mesh,
    endpoint: &Endpoint,
    webrtc: &habilis_network_iroh_webrtc_transport::WebRtcHandle,
    admission: transport::SignalAdmission,
) -> (
    net::Gossip,
    Router,
    transport::SignalAdmission,
    memory::MemoryLookup,
    transport::IceProfile,
) {
    let ice = transport::IceProfile {
        host_only: mesh.is_loopback(),
    };
    let unicast = build.unicast_acceptor.clone().admission(admission.clone());
    let webrtc_lane = build
        .transports
        .webrtc
        .then(|| (webrtc.clone(), admission.clone(), ice));
    let protocols: CallerProtocols = build.take_protocols().protocol(
        transport::CHUNKS_ALPN.to_vec(),
        build.chunk_acceptor.clone(),
    );
    let (gossip, router, address_book) = build_mesh(
        endpoint.clone(),
        build.max_peers,
        Some(unicast),
        webrtc_lane,
        protocols,
        build.relay_transport.relay_allowed(),
        webrtc::lane_needs::local_needs_webrtc_lane(UdpTransport::from(build.transports.udp)),
    );
    (gossip, router, admission, address_book, ice)
}

/// The value cluster [`setup_create`] needs beyond the shared [`SetupBuild`]
/// handles — mirrors [`SetupKind::Create`]'s fields one-for-one.
struct CreateSetup {
    name: MeshName,
    config: MeshConfig,
    advertise: Option<MeshName>,
    password: Option<Password>,
    invite_only: bool,
}

/// Mint a new mesh: seed + optional password stretch, then stand up the
/// endpoint, gossip overlay and rendezvous. The origin co-hosts the
/// rendezvous immediately ([`CoHostPolicy::Eager`]): it has no bootstrap
/// dial to self-collide with, and an otherwise empty mesh needs a beacon
/// from t=0.
async fn setup_create(
    build: &SetupBuild<'_>,
    create: CreateSetup,
    injected: Option<InjectedEndpoint>,
) -> Result<Assembled> {
    let CreateSetup {
        name,
        config,
        advertise,
        password,
        invite_only,
    } = create;
    let sink = build.sink;
    let author = build.author;

    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);

    #[cfg_attr(
        not(feature = "multihop"),
        expect(
            unused_variables,
            reason = "no multihop handle without the `multihop` feature — see `build_member_endpoint`"
        )
    )]
    let (endpoint, multihop, webrtc, admission, underlay_webrtc, mdns) =
        build_member_endpoint(build, injected).await?;

    let mut mesh = Mesh::try_new(Seed::new(seed), name.clone(), config)?;
    // Invite-only: mint the invite root + issuer keypair and bake the issuer
    // pubkey into the id BEFORE it is rendered. Cheap (random keys, no Argon2).
    if invite_only {
        mesh.set_invite();
    }
    // Password: on a plain mesh it stretches the topic (the verifier is baked
    // into the id) off the async worker; on an invite-only mesh the topic is
    // already gated by the invite root, so the password only wraps minted
    // invites — retained, never folded into derivation. Either way the raw
    // password is returned (not dropped) so the daemon can key tickets with it.
    let (mesh, mesh_password) = match (password, invite_only) {
        // Argon2id costs ~100ms, so on a host it goes to a blocking worker.
        // There is no such worker in a browser — `spawn_blocking` needs
        // `rt-multi-thread` — so it runs inline and janks the frame it lands on.
        // Acceptable: it happens once, at join, on a passworded mesh only.
        #[cfg(feature = "host")]
        (Some(password), false) => {
            task::spawn_blocking(move || {
                let mut mesh = mesh;
                mesh.set_password(password.clone());
                (mesh, Some(password))
            })
            .await?
        }
        #[cfg(not(feature = "host"))]
        (Some(password), false) => {
            let mut mesh = mesh;
            mesh.set_password(password.clone());
            (mesh, Some(password))
        }
        (password, _) => (mesh, password),
    };
    let mesh_key = mesh.mesh_key();
    // The creator alone retains its full mesh (issuer key + root) to mint from.
    let mint_mesh = mesh.requires_invite().then(|| mesh.clone());
    let id_str = mesh.to_string();
    let mesh_id = MeshId::try_new(&id_str).expect("Mesh::to_string always produces a valid MeshId");

    sink.emit(NodeEvent::Info(format!(
        "created #{name} and joined as <{author}>"
    )));
    if mesh.requires_password() {
        sink.emit(NodeEvent::Info(
            "password-protected — joiners must present the password".to_owned(),
        ));
    }
    if mesh.requires_invite() {
        sink.emit(NodeEvent::Info(
            "invite-only — joiners need a minted invite".to_owned(),
        ));
    }
    if let Some(directory) = &advertise {
        sink.emit(NodeEvent::Info(format!("advertising on #{directory}")));
    }
    // `ready` is emitted by `run`, once the IPC socket accepts — not here.
    // The one place the protocol's byte-shaped TopicId becomes iroh-gossip's.
    // Keeping the conversion here is what lets habilis-network-protocol build
    // without iroh-gossip at all (see habilis_network_protocol::topic).
    let topic_id = proto::TopicId::from_bytes(mesh.topic_id().to_bytes());
    let lan_contacts = lookup::lan_contacts(&endpoint, mdns, &topic_id).await?;
    lifecycle::log_ready(
        topic_id,
        name.as_str(),
        author.as_str(),
        mesh.network_label(),
    );

    let (gossip, router, webrtc_admission, address_book, webrtc_ice) =
        build_overlay(build, &mesh, &endpoint, &webrtc, admission);
    let rdv = rendezvous_params(&mesh, topic_id, build.lookups, build.rung_tx.clone());
    // Creator has no peers yet — bootstrap is empty.
    let topic = split::subscribe_mesh(&gossip, topic_id, rdv.id, []).await?;

    register_rendezvous(&address_book, &rdv, &beacon::busy_rungs(&rdv));

    Ok(Assembled {
        mesh_id,
        mesh_name: name,
        endpoint,
        router,
        gossip,
        topic,
        rdv,
        cohost: CoHostPolicy::Eager,
        mesh_password,
        mesh_key,
        mint_mesh,
        #[cfg(feature = "multihop")]
        multihop,
        #[cfg(feature = "multihop")]
        underlay_webrtc,
        lan_contacts,
        webrtc,
        webrtc_admission,
        address_book,
        webrtc_ice,
        topic_string: None,
    })
}

/// Attach to an existing mesh. Join and Topic share one attach path;
/// they differ only in the co-host policy (Topic has no distinguished
/// creator, so its first peer must beacon) and the startup line. Like
/// `create`, non-blocking on the *mesh*: the subscribe below only kicks off a
/// background connect, so a joiner is never invisible while bootstrapping and
/// `ready` never waits for a peer. It does wait for the IPC socket — see
/// `run`.
async fn setup_join(
    build: &SetupBuild<'_>,
    kind: SetupKind,
    injected: Option<InjectedEndpoint>,
) -> Result<Assembled> {
    let sink = build.sink;
    let author = build.author;

    let (mesh, mesh_password, cohost, topic_string) = match kind {
        SetupKind::Join { mesh, password } => (mesh, password, CoHostPolicy::Deferred, None),
        // A topic mesh is always passwordless.
        SetupKind::Topic { mesh, topic_string } => {
            (mesh, None, CoHostPolicy::EagerProbed, Some(topic_string))
        }
        SetupKind::Create { .. } => unreachable!("outer arm excludes Create"),
    };
    let mesh_key = mesh.mesh_key();
    let id_str = mesh.to_string();
    let mesh_id = MeshId::try_new(&id_str).expect("Mesh::to_string always produces a valid MeshId");
    // The one place the protocol's byte-shaped TopicId becomes iroh-gossip's.
    // Keeping the conversion here is what lets habilis-network-protocol build
    // without iroh-gossip at all (see habilis_network_protocol::topic).
    let topic_id = proto::TopicId::from_bytes(mesh.topic_id().to_bytes());

    #[cfg_attr(
        not(feature = "multihop"),
        expect(
            unused_variables,
            reason = "no multihop handle without the `multihop` feature — see `build_member_endpoint`"
        )
    )]
    let (endpoint, multihop, webrtc, admission, underlay_webrtc, mdns) =
        build_member_endpoint(build, injected).await?;

    let lan_contacts = lookup::lan_contacts(&endpoint, mdns, &topic_id).await?;
    let rdv = rendezvous_params(&mesh, topic_id, build.lookups, build.rung_tx.clone());
    let (gossip, router, webrtc_admission, address_book, webrtc_ice) =
        build_overlay(build, &mesh, &endpoint, &webrtc, admission);
    // Must precede the join (the subscribe below): the peer resolves the rendezvous id via
    // this registered address — the loopback port ladder (loopback-only) or
    // the chosen relay rung (reachable across machines).
    let read = beacon::read_busy_rungs(&rdv, SETUP_RUNG_READ).await;
    let withheld = rungs_withheld_at_setup(build.cohost.unwrap_or(cohost), &read);
    register_rendezvous(&address_book, &rdv, &withheld);
    // We subscribe, background-connect to the rendezvous, and — for a plain
    // join — `daemon::run` defers co-hosting our own (same seed-id) rendezvous
    // until we are meshed, so we never register a duplicate `rendezvous_id` on
    // the shared pinned relay that could capture our own bootstrap dial. A
    // topic instead claims eagerly (probe-first) so the first peer beacons.
    // See `EventLoopConfig::cohost`.
    // A webrtc-shaped lookup-only node must not bootstrap-dial the
    // rendezvous yet: the graft waits for its session (see
    // `transport::webrtc::rendezvous::rendezvous_graftable`); the heal tick grafts once
    // it is attached.
    let needs_session = webrtc::session_policy::node_graft_needs_session(
        build.relay_transport.relay_allowed(),
        UdpTransport::from(build.transports.udp),
    );
    let bootstrap = if needs_session { vec![] } else { vec![rdv.id] };
    let topic = split::subscribe_mesh(&gossip, topic_id, rdv.id, bootstrap).await?;

    // `ready` is emitted by `run`, once the IPC socket accepts — not here.
    lifecycle::log_ready(
        topic_id,
        mesh.name().as_str(),
        author.as_str(),
        mesh.network_label(),
    );
    // A topic gossip announces the raw string, not the derived `#name` — the
    // name is lossy and the string is what a user shares to meet peers.
    sink.emit(NodeEvent::Info(match &topic_string {
        Some(raw_topic) => format!("joined topic {raw_topic} as <{author}>"),
        None => format!("joined #{} as <{author}>", mesh.name()),
    }));

    Ok(Assembled {
        mesh_id,
        mesh_name: mesh.name().clone(),
        endpoint,
        router,
        gossip,
        topic,
        rdv,
        cohost,
        mesh_password,
        mesh_key,
        // A joiner holds no issuer key, so it can never mint — even after
        // redeeming an invite-only mesh.
        mint_mesh: None,
        #[cfg(feature = "multihop")]
        multihop,
        #[cfg(feature = "multihop")]
        underlay_webrtc,
        lan_contacts,
        webrtc,
        webrtc_admission,
        address_book,
        webrtc_ice,
        topic_string,
    })
}

#[cfg(all(test, feature = "host"))]
mod tests {
    #[cfg(all(unix, feature = "host"))]
    use crate::daemon::state::RunKeys;
    #[cfg(all(unix, feature = "host"))]
    use crate::protocol::AuthorKey;
    use std::path::{Path, PathBuf};
    #[cfg(all(unix, feature = "host"))]
    use std::thread;
    use std::{env, fs, process};

    #[cfg(all(unix, feature = "host"))]
    fn member_key(keys: &RunKeys) -> Option<AuthorKey> {
        let member = keys.member.as_ref();
        member.map(|member| member.author_key())
    }

    #[cfg(all(unix, feature = "host"))]
    fn member_of(keys: &RunKeys) -> AuthorKey {
        let member = keys.member.as_ref().expect("a member key");
        member.author_key()
    }

    /// A temp dir that goes away when the test ends, also when an assert fails.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = env::temp_dir().join(format!("{name}-{}", process::id()));
            drop(fs::remove_dir_all(&dir));
            fs::create_dir_all(&dir).expect("a temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    /// The member key, the run counter and the lock live in the folder of the state file. A user that can write
    /// that folder can unlink or rename them while they are held, and a second start then reads the same
    /// member key at a higher run and replaces the first session. A folder that others can write is refused
    /// unless it has the sticky bit (like `/tmp`), which stops other users from unlinking or renaming files
    /// that they do not own. A private folder is the normal case.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_state_folder_that_others_can_write_without_the_sticky_bit_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("habilis-shared-folder");
        let state = dir.path().join("session.json");
        let folder = |mode: u32| {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).expect("a mode");
        };

        folder(0o777);
        let open = super::hold_member_key_once(Some(&state));
        let refusal: Option<String> = open.err().map(|error| format!("{error:#}"));
        let text: String = refusal.unwrap_or_default();
        let named: String = dir.path().display().to_string();
        assert!(
            text.contains("can be written by other users") && text.contains(&named),
            "a folder with mode 0777 was not refused with its name: {text:?}"
        );

        folder(0o1777);
        assert!(
            super::hold_member_key_once(Some(&state)).is_ok(),
            "a folder with the sticky bit (mode 1777) was refused"
        );
        let private = dir.path().join("private.json");
        folder(0o700);
        assert!(
            super::hold_member_key_once(Some(&private)).is_ok(),
            "a private folder (mode 0700) was refused"
        );
    }

    /// The lock files and the temporary file of the run counter are opened without following a link, as the key
    /// file is: a link that is planted at one of those paths must not make a start lock, write or cut the file
    /// that it points to. Each case is its own state path, with a target that must stay as it was.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn the_lock_files_and_the_temporary_run_file_are_not_opened_through_a_link() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let dir = TempDir::new("habilis-lock-links");
        let planted = |name: &str| {
            let state = dir.path().join(format!("{name}.json"));
            let target = dir.path().join(format!("{name}.target"));
            fs::write(&target, b"untouched").expect("a target file");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("a mode");
            (state, target)
        };

        let (lock_state, lock_target) = planted("key-lock");
        symlink(&lock_target, lock_state.with_extension("key.lock"))
            .expect("a link at the key lock");
        assert!(
            super::hold_member_key_once(Some(&lock_state)).is_err(),
            "the key lock was opened through a link"
        );

        let (run_state, run_target) = planted("run-lock");
        symlink(&run_target, run_state.with_extension("run.lock")).expect("a link at the run lock");
        assert!(
            super::next_run(Some(&run_state), false, &super::NEVER_CANCELLED).is_err(),
            "the run lock was opened through a link"
        );

        let (tmp_state, tmp_target) = planted("run-tmp");
        symlink(&tmp_target, tmp_state.with_extension("run.tmp"))
            .expect("a link at the temporary file");
        assert!(
            super::next_run(Some(&tmp_state), false, &super::NEVER_CANCELLED).is_err(),
            "the temporary run file was opened through a link"
        );
        assert_eq!(
            fs::read(&tmp_target).expect("the target"),
            b"untouched",
            "the counter was written through a link to its target"
        );
    }

    /// A state folder that the group can write is refused like one that others can write, unless it has the
    /// sticky bit. Another member of that group can unlink or rename the key file, the run file and the lock. A
    /// trusted group cannot be known (the members of a group come from several sources, and the primary group of
    /// a user is not in the list), and there is no setting for it: one rule. A folder at mode 0775 needs `chmod g-w`.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_state_folder_that_the_group_can_write_without_the_sticky_bit_is_refused() {
        let me = 501;
        for mode in [0o770, 0o775, 0o720, 0o2775] {
            assert!(
                super::state_folder_problem(mode, me, me).is_some(),
                "a folder of mode {mode:o} that the group can write was accepted"
            );
        }
        for mode in [0o700, 0o755, 0o750, 0o1775, 0o1777] {
            assert_eq!(
                super::state_folder_problem(mode, me, me),
                None,
                "a folder of mode {mode:o} was refused"
            );
        }
    }

    /// A lock file that another user owns, or that is not a regular file, is refused: see `lock_file_problem`.
    /// The check is a pure function of what `fstat` says on the opened file, so it is tested with owners that a
    /// test cannot make with chown.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_lock_file_that_another_user_owns_or_that_is_no_regular_file_is_refused() {
        let (me, other, root) = (501, 4242, 0);

        assert_eq!(
            super::lock_file_problem(true, other, me),
            Some("is owned by another user"),
            "a lock file of another user was accepted"
        );
        assert_eq!(
            super::lock_file_problem(true, root, me),
            Some("is owned by another user"),
            "a lock file of root was accepted"
        );
        assert_eq!(
            super::lock_file_problem(false, me, me),
            Some("is not a regular file"),
            "a lock file that is no regular file was accepted"
        );
        assert_eq!(
            super::lock_file_problem(true, me, me),
            None,
            "a lock file of this user was refused"
        );
    }

    /// A holder of the run lock that writes the counter file all the time does not extend the wait for ever: the
    /// stall bound restarts at each write, so the wait has an absolute cap as well. Here the stall is 1 s and the
    /// cap 3 s, and the holder writes every 200 ms for 12 s: the wait must end with an error at the cap.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_holder_that_keeps_writing_the_run_counter_does_not_extend_the_wait_for_ever() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};
        use std::time::Duration;
        let dir = TempDir::new("habilis-run-lock-toucher");
        let state = dir.path().join("session.json");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        let holder: fs::File = options
            .open(state.with_extension("run.lock"))
            .expect("the file of the holder");
        holder.lock().expect("the holder takes the lock");
        // the toucher thread and the test share the flag that stops the toucher
        let stop = Arc::new(AtomicBool::new(false));
        let toucher = {
            let (stop, run_path) = (Arc::clone(&stop), state.with_extension("run"));
            thread::spawn(move || {
                let mut count = 0u8;
                while !stop.load(Ordering::Relaxed) && count < 60 {
                    fs::write(&run_path, u64::from(count).to_le_bytes()).expect("a write");
                    count += 1;
                    thread::sleep(Duration::from_millis(200));
                }
            })
        };
        let (done, outcome) = mpsc::channel();
        let waiting = state;
        thread::spawn(move || {
            let refused = super::lock_run_counter_within(
                &waiting,
                Duration::from_secs(1),
                Duration::from_secs(3),
                &super::NEVER_CANCELLED,
            )
            .is_err();
            // the test has stopped waiting when this fails, and then nothing needs the answer
            done.send(refused).expect("the test waits for the answer");
        });
        let refused = outcome.recv_timeout(Duration::from_secs(8));
        stop.store(true, Ordering::Relaxed);
        toucher.join().expect("the toucher ends");
        drop(holder);
        assert_eq!(
            refused,
            Ok(true),
            "a holder that wrote the counter every 200 ms kept the wait going past its cap of 3 s: {refused:?}"
        );
    }

    /// The progress of the counter is read without following a link: another user can create `.run` as a link to a
    /// file that it touches each second, in a root-owned sticky folder. The link itself does not move, so the stall
    /// bound ends the wait.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn the_progress_of_the_run_counter_is_not_read_through_a_link() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};
        use std::time::Duration;
        let dir = TempDir::new("habilis-run-lock-link");
        let state = dir.path().join("session.json");
        let target = dir.path().join("touched");
        fs::write(&target, 1u64.to_le_bytes()).expect("a target");
        symlink(&target, state.with_extension("run")).expect("a link at the run path");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        let holder: fs::File = options
            .open(state.with_extension("run.lock"))
            .expect("the file of the holder");
        holder.lock().expect("the holder takes the lock");
        // the toucher thread and the test share the flag that stops the toucher
        let stop = Arc::new(AtomicBool::new(false));
        let toucher = {
            let (stop, target) = (Arc::clone(&stop), target);
            thread::spawn(move || {
                let mut count = 0u8;
                while !stop.load(Ordering::Relaxed) && count < 60 {
                    fs::write(&target, u64::from(count).to_le_bytes()).expect("a write");
                    count += 1;
                    thread::sleep(Duration::from_millis(200));
                }
            })
        };
        let (done, outcome) = mpsc::channel();
        let waiting = state;
        thread::spawn(move || {
            let refused = super::lock_run_counter_within(
                &waiting,
                Duration::from_secs(1),
                Duration::from_secs(30),
                &super::NEVER_CANCELLED,
            )
            .is_err();
            // the test has stopped waiting when this fails, and then nothing needs the answer
            done.send(refused).expect("the test waits for the answer");
        });
        let refused = outcome.recv_timeout(Duration::from_secs(6));
        stop.store(true, Ordering::Relaxed);
        toucher.join().expect("the toucher ends");
        drop(holder);
        assert_eq!(
            refused,
            Ok(true),
            "the touches of the target of a link kept the wait going: {refused:?}"
        );
    }

    /// The run lock does not wait for ever. Another holder that keeps `<state>.run.lock` (in a sticky folder, a
    /// user who made the file first and locked it) must not block the start: the lock is tried again for a short
    /// time, as the key lock is, and then the start fails and names the file.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_run_lock_that_another_holder_keeps_does_not_block_the_start_for_ever() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = TempDir::new("habilis-run-lock-held");
        let state = dir.path().join("session.json");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        let holder: fs::File = options
            .open(state.with_extension("run.lock"))
            .expect("the file of the holder");
        holder.lock().expect("the holder takes the lock");
        let (done, outcome) = mpsc::channel();
        thread::spawn(move || {
            let refused = super::next_run(Some(&state), false, &super::NEVER_CANCELLED).is_err();
            // the test has stopped waiting when this fails, and then nothing needs the answer
            done.send(refused).expect("the test waits for the answer");
        });
        let refused = outcome.recv_timeout(Duration::from_secs(5));
        assert_eq!(
            refused,
            Ok(true),
            "the start did not end in an error within 5 s while another holder kept the run lock: {refused:?}"
        );
        drop(holder);
    }

    /// A state folder that another user owns is refused, whatever its mode: its owner can unlink or rename the
    /// key file, the run file and the lock. The owner may be the user who starts the node, or root (the owner of
    /// `/tmp`, whose sticky bit protects the files of the others). The check is a pure function of the mode, the
    /// owner and the user, so it is tested with owners that a test cannot make with chown.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_state_folder_that_another_user_owns_is_refused_whatever_its_mode() {
        let (me, other, root) = (501, 4242, 0);

        assert_eq!(
            super::state_folder_problem(0o755, other, me),
            Some("is owned by another user"),
            "a folder of another user at mode 0755 was accepted"
        );
        assert_eq!(
            super::state_folder_problem(0o700, other, me),
            Some("is owned by another user"),
            "a folder of another user at mode 0700 was accepted"
        );
        assert_eq!(
            super::state_folder_problem(0o1777, other, me),
            Some("is owned by another user"),
            "a sticky folder of another user was accepted: its owner can remove our files"
        );
        assert_eq!(
            super::state_folder_problem(0o755, me, me),
            None,
            "a folder of this user was refused"
        );
        assert_eq!(
            super::state_folder_problem(0o1777, root, me),
            None,
            "the sticky folder of root (as /tmp) was refused"
        );
        assert_eq!(
            super::state_folder_problem(0o777, me, me),
            Some("can be written by other users (its group or the others) and has no sticky bit"),
            "a folder that others can write was accepted"
        );
    }

    /// A target with no files keeps no member key, no run count and no lock: each start is run 1, whatever
    /// the state path, and the start takes no lock. This is the coverage of the fallback that the tests of the
    /// key files, which need a file system, give up on such a target.
    #[cfg(not(all(unix, feature = "host")))]
    #[test]
    fn a_target_with_no_files_has_no_member_key_and_starts_at_run_1() {
        let dir = TempDir::new("habilis-no-files");
        let state = dir.path().join("session.json");
        assert_eq!(
            super::next_run(Some(&state), false, &super::NEVER_CANCELLED).expect("run"),
            1,
            "the first start is run 1"
        );
        assert_eq!(
            super::next_run(Some(&state), false, &super::NEVER_CANCELLED).expect("run"),
            1,
            "with no counter file the second start is run 1 as well"
        );
        assert!(
            super::member_key(Some(&state)).expect("keys").is_none(),
            "a target with no files keeps no member key"
        );
        assert!(
            super::hold_member_key_once(Some(&state))
                .expect("no lock")
                .is_none(),
            "a target with no files takes no lock"
        );
    }

    /// A restarted member keeps its identity: the same state file gives the same key, and a
    /// missing file gives a new one.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_restart_keeps_its_identity() {
        let dir = env::temp_dir().join(format!("habilis-identity-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("session.json");
        let first = super::load_or_create_identity(Some(&state)).expect("first start");
        let second = super::load_or_create_identity(Some(&state)).expect("restart");
        assert_eq!(
            first.author_key(),
            second.author_key(),
            "the restart keeps the key"
        );
        let fresh = super::load_or_create_identity(None).expect("no state file");
        assert_ne!(
            fresh.author_key(),
            first.author_key(),
            "no file means a new key"
        );
    }

    /// The run number rises at each start, and a clock that went back cannot lower it: the counter
    /// never reads the clock.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn the_run_number_rises_at_each_start() {
        let dir = TempDir::new("habilis-run-number");
        let state = dir.path().join("session.json");
        let runs: Vec<u64> = (0..3)
            .map(|_| {
                super::next_run(Some(&state), false, &super::NEVER_CANCELLED).expect("a run number")
            })
            .collect();
        assert_eq!(runs, [1, 2, 3], "each start counts one more");
        let ahead: u64 = 4_000_000_000_000;
        fs::write(state.with_extension("run"), ahead.to_le_bytes()).expect("a counter ahead");
        assert_eq!(
            super::next_run(Some(&state), false, &super::NEVER_CANCELLED).expect("a run number"),
            ahead + 1,
            "a counter ahead of any clock still rises"
        );
        assert_eq!(
            super::next_run(None, false, &super::NEVER_CANCELLED).expect("no state file"),
            1,
            "no file means run 1"
        );
    }

    /// A key file that another user could have planted or read is not loaded: its seed would become the
    /// identity of this member. A file of mode 0600, owned by this user, is the one that this code wrote.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_key_file_that_others_can_read_or_a_link_is_not_loaded() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let dir = TempDir::new("habilis-key-trust");
        let state = dir.path().join("session.json");
        let key = state.with_extension("key");
        fs::write(&key, [7u8; 40]).expect("a key file");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("a loose mode");
        let loose = super::load_or_create_identity(Some(&state));
        assert!(
            loose.is_err(),
            "a key file that group and others can read was loaded"
        );

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("a private mode");
        let private = super::load_or_create_identity(Some(&state)).expect("a private file loads");
        assert_eq!(
            private.seed().as_slice(),
            &[7u8; 32],
            "the seed of a trusted file is the identity"
        );

        fs::remove_file(&key).expect("remove the file");
        let target = dir.path().join("elsewhere.key");
        fs::write(&target, [9u8; 40]).expect("a target file");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("a private mode");
        symlink(&target, &key).expect("a link in place of the key file");
        assert!(
            super::load_or_create_identity(Some(&state)).is_err(),
            "a link in place of the key file was followed"
        );
    }

    /// The last run that the key file names is read from the bytes 40 to 48, and a file that is shorter names
    /// none. The seed in the first 32 bytes is not needed to read it.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn the_last_run_is_read_from_the_bytes_40_to_48_of_the_key_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("habilis-last-run");
        let key = dir.path().join("session.key");
        let mut named = vec![7u8; 40];
        named.extend_from_slice(&41u64.to_le_bytes());
        fs::write(&key, &named).expect("a key file with a run");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("a private mode");
        assert_eq!(
            super::last_recorded_run_in(&key),
            Some(41),
            "the run is named"
        );
        fs::write(&key, &named[..47]).expect("a key file one byte short");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("a private mode");
        assert_eq!(
            super::last_recorded_run_in(&key),
            None,
            "a file that is one byte short names no run"
        );
        fs::write(&key, [7u8; 40]).expect("a key file with no run");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("a private mode");
        assert_eq!(super::last_recorded_run_in(&key), None, "no run is named");
    }

    /// A key path that is a FIFO with no writer must be refused, not waited for: a read-only open of such a
    /// FIFO blocks until a writer comes, and the start would hang a worker of the runtime before the check of
    /// the file type could run. The load runs on its own thread so that a hang fails the test and not the run.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_key_path_that_is_a_fifo_with_no_writer_is_refused_and_does_not_block() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = TempDir::new("habilis-key-fifo");
        let state = dir.path().join("session.json");
        let made: process::ExitStatus = process::Command::new("mkfifo")
            .arg(state.with_extension("key"))
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a FIFO at the key path");
        let (done, outcome) = mpsc::channel();
        thread::spawn(move || {
            let refused = super::load_or_create_identity(Some(&state)).is_err();
            // the test has stopped waiting when this fails, and then nothing needs the answer
            done.send(refused).expect("the test waits for the answer");
        });
        let refused = outcome.recv_timeout(Duration::from_secs(2));
        assert_eq!(
            refused,
            Ok(true),
            "the load of a FIFO key path did not end in an error within 2 s: {refused:?}"
        );
    }

    /// The checks of the key file are on the open file, and the open does not follow a link: a link that is
    /// put at the path after a path check cannot make the write go to its target, and a file that others can
    /// read is not written over.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn the_key_file_is_opened_without_following_a_link_and_checked_on_the_open_file() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::lifecycle",
            "the last run could not be recorded",
        );
        let dir = TempDir::new("habilis-key-toctou");
        let key = dir.path().join("session.key");
        let target = dir.path().join("elsewhere");
        fs::write(&target, b"untouched").expect("a target file");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("a private mode");
        symlink(&target, &key).expect("a link in place of the key file");

        let written = super::write_key_file(&key, &[1u8; 32], 5);
        super::record_last_run(&key.with_extension("json"), 9);

        assert!(
            written.is_err(),
            "the write followed a link at the key path"
        );
        assert_eq!(
            fs::read(&target).expect("the target"),
            b"untouched",
            "a write went through the link to its target"
        );

        fs::remove_file(&key).expect("remove the link");
        fs::write(&key, b"old").expect("a wide file");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("a loose mode");
        let over_wide = super::write_key_file(&key, &[2u8; 32], 5);
        assert!(
            over_wide.is_err(),
            "a key file that others can read was written over"
        );
        assert_eq!(
            fs::read(&key).expect("the file"),
            b"old",
            "the file changed"
        );
    }

    /// Two starts that share a state path each get their own run: the read of the counter and the write
    /// of the next one are one step under a lock, so no two starts publish one run.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn starts_that_share_a_state_path_get_distinct_runs() {
        let dir = TempDir::new("habilis-run-race");
        let state = dir.path().join("session.json");
        let starts = 8;
        let rounds = 40;
        let mut runs: Vec<u64> = Vec::new();
        thread::scope(|scope| {
            let handles: Vec<_> = (0..starts)
                .map(|_| {
                    scope.spawn(|| {
                        let own: Vec<u64> = (0..rounds)
                            .map(|_| {
                                super::next_run(Some(&state), false, &super::NEVER_CANCELLED)
                                    .expect("a run number")
                            })
                            .collect();
                        own
                    })
                })
                .collect();
            for handle in handles {
                runs.extend(handle.join().expect("a start"));
            }
        });
        let total = runs.len();
        runs.sort_unstable();
        runs.dedup();
        assert_eq!(
            runs.len(),
            total,
            "two starts of one state path published one run: peers would keep different sessions"
        );
    }

    /// The member key file keeps the last run too. When the counter file is lost a second time, after the
    /// clock went back, the clock alone would give a run below the one that peers hold: the key file is
    /// the second record, and the new run is above the last run that it names.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_lost_counter_does_not_go_below_the_last_run_that_the_key_file_names() {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::lifecycle",
            "run counter file is unreadable",
        );
        let dir = TempDir::new("habilis-run-twice-lost");
        let state = dir.path().join("session.json");
        let key = state.with_extension("key");
        let ahead_of_the_clock: u64 = 4_000_000_000_000;
        let mut bytes = vec![7u8; 32];
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&ahead_of_the_clock.to_le_bytes());
        fs::write(&key, bytes).expect("a key file that names a last run");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("a private mode");

        let run =
            super::next_run(Some(&state), true, &super::NEVER_CANCELLED).expect("a run number");

        assert!(
            run > ahead_of_the_clock,
            "the run after a lost counter is {run}, not above the last run of the key file"
        );
    }

    /// The keys of a start whose process has ended: the lock on the member key went with it, so a
    /// later start of the same state path is a restart and not a second live daemon.
    #[cfg(all(unix, feature = "host"))]
    fn ended(keys: RunKeys) -> RunKeys {
        RunKeys {
            key_lock: None,
            ..keys
        }
    }

    /// The owner binding reads the path that the keys came from. A start with no state file of its
    /// own keeps its pair under the default path of the mesh, and the explicit state file is `None`
    /// there: a binding that read that field alone stamped nothing, and a later owner of the same
    /// pid kept the key and the run of this one.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn the_owner_binding_reads_the_path_that_the_keys_came_from() {
        let dir = TempDir::new("habilis-owner-default-path");
        // The path of the keys of a start that named no state file: the default path of its mesh.
        let state = dir.path().join("in-the-default-folder.state.json");
        let start = 1_700_000_123;
        let keys = super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("the keys");
        assert!(keys.member_new, "the premise: this start made the pair");

        // What the caller of this binding passed before: the explicit state file, which such a
        // start does not have.
        let unbound = super::bind_to_owner(keys.clone(), None, Some(start));
        assert_eq!(
            owner_in_key_file(&state),
            Some(0),
            "a binding without the path of the keys stamps no owner"
        );
        assert!(
            unbound.member.is_some(),
            "and it keeps the member key as it was"
        );

        let bound = super::bind_keys_to_owner(keys, Some(start));

        assert_eq!(
            owner_in_key_file(&state),
            Some(start),
            "the binding that reads the path of the keys stamps the owner of this start"
        );
        assert!(bound.member.is_some(), "the member key stays");
    }

    /// The start time of the owner that the key file of `state` names.
    #[cfg(all(unix, feature = "host"))]
    fn owner_in_key_file(state: &Path) -> Option<u64> {
        let bytes = fs::read(state.with_extension("key")).ok()?;
        let tail = bytes.get(32..40)?;
        let eight = <[u8; 8]>::try_from(tail).ok()?;
        Some(u64::from_le_bytes(eight))
    }

    /// Each start records its run in the key file, beside the counter file.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn each_start_records_its_run_in_the_key_file() {
        let dir = TempDir::new("habilis-run-recorded");
        let state = dir.path().join("session.json");
        let first =
            ended(super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("the first start"));
        let second =
            super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("the second start");

        let bytes = fs::read(state.with_extension("key")).expect("the key file");
        let named = bytes
            .get(40..48)
            .and_then(|tail| <[u8; 8]>::try_from(tail).ok())
            .map(u64::from_le_bytes);

        assert_eq!(first.run, 1, "the first start is run 1");
        assert_eq!(second.run, 2, "the second start is run 2");
        assert_eq!(named, Some(second.run), "the key file names the last run");
    }

    /// The wait for the run lock holds no thread of the runtime: while another start keeps the lock for 700 ms, a
    /// ticker on the same current-thread runtime keeps running. A blocking sleep on the runtime thread (up to 30 s)
    /// would stop every timer of a daemon that starts in the same process.
    #[cfg(all(unix, feature = "host"))]
    #[tokio::test]
    async fn the_wait_for_the_run_lock_does_not_stop_the_runtime() {
        use std::fs;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use tokio::task;
        let dir = TempDir::new("habilis-run-lock-runtime");
        let state = dir.path().join("session.json");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        let holder: fs::File = options
            .open(state.with_extension("run.lock"))
            .expect("the file of the holder");
        holder.lock().expect("the holder takes the lock");
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(700));
            drop(holder);
        });
        // the test and the ticker task share the count
        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker = {
            let ticks = Arc::clone(&ticks);
            tokio::spawn(async move {
                loop {
                    time::sleep(Duration::from_millis(20)).await;
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        // let the ticker start
        task::yield_now().await;

        let keys = super::run_keys_off_the_runtime(Some(state), None).await;

        ticker.abort();
        releaser.join().expect("the holder ends");
        assert!(
            keys.is_ok(),
            "the start did not get the lock after the holder let go"
        );
        let seen = ticks.load(Ordering::Relaxed);
        assert!(
            seen >= 10,
            "the wait for the run lock stopped the runtime: the ticker ran {seen} times in 700 ms"
        );
    }

    /// A setup that is cancelled while it waits for the run lock leaves nothing behind: the worker that waits stops
    /// at its next step. Else it keeps the member key lock that it holds, and when the holder lets go it takes the run
    /// lock and writes the run counter of a start that does not exist.
    #[cfg(all(unix, feature = "host"))]
    #[tokio::test]
    async fn a_cancelled_wait_for_the_run_lock_writes_no_run_counter() {
        use std::fs;
        use std::time::Duration;
        let dir = TempDir::new("habilis-run-lock-cancel");
        let state = dir.path().join("session.json");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        let holder: fs::File = options
            .open(state.with_extension("run.lock"))
            .expect("the file of the holder");
        holder.lock().expect("the holder takes the lock");
        let start = tokio::spawn(super::run_keys_off_the_runtime(Some(state.clone()), None));
        time::sleep(Duration::from_millis(150)).await;

        start.abort();
        time::sleep(Duration::from_millis(150)).await;
        drop(holder);
        time::sleep(Duration::from_millis(500)).await;

        assert!(
            !state.with_extension("run").exists(),
            "the cancelled start took the run lock when the holder let go, and wrote a run counter"
        );
    }

    /// A start that is cancelled before the lock is free writes no run counter either. The wait reads the flag
    /// only where it sleeps, so a lock that nobody holds is taken at the first try and the flag is never read.
    /// The run counter of a start that does not exist is then written, and the next real start skips a number.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_cancelled_start_that_finds_the_run_lock_free_writes_no_run_counter() {
        use std::sync::atomic::AtomicBool;
        let dir = TempDir::new("habilis-run-lock-cancel-free");
        let state = dir.path().join("session.json");
        let cancelled = AtomicBool::new(true);

        let run = super::next_run(Some(&state), false, &cancelled);

        assert!(
            run.is_err(),
            "a cancelled start counted a run on a free lock, and the run it counted is {run:?}"
        );
        assert!(
            !state.with_extension("run").exists(),
            "the cancelled start wrote the counter file, so the next real start skips a number"
        );
    }

    /// A daemon that the CLI started with no state file keeps its member key and counts its run on, in the
    /// default state path of its mesh, when the setup asks for it. Without the flag the keys stay ephemeral,
    /// and an explicit state file wins over the default.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_restart_with_no_state_file_keeps_its_member_key_in_the_default_state_path() {
        use crate::protocol::{MeshId, Nickname};
        let dir = TempDir::new("habilis-default-state");
        let base = dir.path();
        let (mesh, author) = (MeshId::from("test"), Nickname::from("alice"));
        let explicit = dir.path().join("explicit.json");

        let path = |state: Option<&Path>, on: bool| {
            super::keys_state_path(state, Some(base), &mesh, &author, on).expect("a state path")
        };
        let default = path(None, true).expect("the flag asks for the default state path");
        let first = ended(
            super::run_keys(Some(&default), &super::NEVER_CANCELLED).expect("the first start"),
        );
        let second = super::run_keys(Some(&default), &super::NEVER_CANCELLED).expect("the restart");

        assert!(
            default.starts_with(base),
            "the default path is under the runtime base"
        );
        assert_eq!(
            member_of(&first),
            member_of(&second),
            "the restart made a new member key"
        );
        assert_eq!(second.run, first.run + 1, "the run counts on");
        assert!(path(None, false).is_none(), "no flag keeps ephemeral keys");
        assert_eq!(
            path(Some(&explicit), true).as_deref(),
            Some(explicit.as_path()),
            "an explicit state file wins"
        );
    }

    /// The run counter file is read like the key file: no link is followed, a file that is not a regular file is
    /// refused, and no more than 16 bytes are read. In a folder that other users can write but cannot unlink
    /// from (the sticky bit, as on `/tmp`), another user can create our `.run` name first: as a link to a device
    /// that never ends, the read grew memory for ever, and as a FIFO with no writer the open waited for ever while
    /// the run lock was held.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn the_run_file_is_read_like_the_key_file() {
        use std::os::unix::fs::symlink;
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = TempDir::new("habilis-run-read");

        let target = dir.path().join("elsewhere");
        fs::write(&target, 99u64.to_le_bytes()).expect("a target with a counter");
        let link = dir.path().join("link.run");
        symlink(&target, &link).expect("a link at the run path");
        assert!(
            super::read_run_file(&link).is_err(),
            "the run file was read through a link"
        );

        let long = dir.path().join("long.run");
        fs::write(&long, vec![7u8; 1 << 20]).expect("a long file");
        let bytes = super::read_run_file(&long).unwrap_or_default();
        assert!(
            bytes.len() <= 16,
            "{} bytes of a long run file were read",
            bytes.len()
        );

        let whole = dir.path().join("whole.run");
        fs::write(&whole, 5u64.to_le_bytes()).expect("a counter file");
        assert_eq!(
            super::read_run_file(&whole).expect("a regular counter file"),
            5u64.to_le_bytes(),
            "a regular counter file of 8 bytes is read whole"
        );

        let fifo = dir.path().join("fifo.run");
        let made: process::ExitStatus = process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a FIFO at the run path");
        let (done, outcome) = mpsc::channel();
        thread::spawn(move || {
            let refused = super::read_run_file(&fifo).is_err();
            // the test has stopped waiting when this fails, and then nothing needs the answer
            done.send(refused).expect("the test waits for the answer");
        });
        let refused = outcome.recv_timeout(Duration::from_secs(2));
        assert_eq!(
            refused,
            Ok(true),
            "the read of a FIFO run file did not end in an error within 2 s: {refused:?}"
        );
    }

    /// A counter file that a crash cut short must not restart the count at 1: a peer that kept a
    /// higher run would refuse the live session. The next run then starts above any count of starts.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_cut_short_counter_file_does_not_restart_the_count() {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::lifecycle",
            "run counter file is unreadable",
        );
        let dir = TempDir::new("habilis-run-cut");
        let state = dir.path().join("session.json");
        fs::write(state.with_extension("run"), b"").expect("a cut short file");
        let run =
            super::next_run(Some(&state), false, &super::NEVER_CANCELLED).expect("a run number");
        assert!(
            run > 1_000_000_000,
            "the run after a cut short file is {run}"
        );
        let mode: u32 = fs::metadata(state.with_extension("run"))
            .expect("the file")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the counter file is private, like the key file"
        );
        assert!(
            !state.with_extension("run.tmp").exists(),
            "no temp file stays"
        );
    }

    /// A member whose run file is deleted keeps its member key. Peers hold the proof of its old
    /// session with a high run, and they refuse a proof of run 1 as a late copy, so the member would
    /// be admitted with no proof and its nickname would be free for a forger. The count restarts from
    /// the clock then, which is above any count of starts.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_member_whose_run_file_is_deleted_restarts_from_the_clock() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::lifecycle",
            "run counter file is unreadable",
        );
        let dir = TempDir::new("habilis-run-deleted");
        let state = dir.path().join("session.json");
        let first =
            ended(super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("the first start"));
        let second = ended(
            super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("the second start"),
        );
        assert_eq!(
            (first.run, second.run),
            (1, 2),
            "the first starts count 1, 2"
        );
        fs::remove_file(state.with_extension("run")).expect("the run file is deleted");

        let third = super::run_keys(Some(&state), &super::NEVER_CANCELLED)
            .expect("the start after the deletion");

        assert!(
            third.run > 1_000_000_000,
            "the run after a deleted file is {}, below the runs that peers hold",
            third.run
        );
    }

    /// A first start has no run file and no member key: the count starts at 1, with no warning.
    #[test]
    fn a_first_start_with_no_files_counts_from_1() {
        let dir = TempDir::new("habilis-run-first");
        let state = dir.path().join("session.json");
        let first =
            super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("the first start");
        assert_eq!(first.run, 1, "a new member starts at run 1");
    }

    /// The pair of files (the member key and the run counter) is bound to the start time of the process
    /// that owns the daemon. A restart of the same owner keeps it. Another process that got the same
    /// pid has another start time, and starts as a new member, at run 1.
    #[cfg(all(unix, feature = "host"))]
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_pair_of_files_from_another_owner_is_not_reused() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::lifecycle",
            "from another owner",
        );
        let dir = TempDir::new("habilis-owner");
        let state = dir.path().join("session.json");
        let first = ended(super::bind_to_owner(
            super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("first start"),
            Some(&state),
            Some(100),
        ));
        let restart = ended(super::bind_to_owner(
            super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("restart"),
            Some(&state),
            Some(100),
        ));
        assert_eq!(
            member_of(&first),
            member_of(&restart),
            "the same owner keeps the member key"
        );
        assert_eq!(restart.run, 2, "and the run counter goes on");

        let reused_pid = ended(super::bind_to_owner(
            super::run_keys(Some(&state), &super::NEVER_CANCELLED)
                .expect("a start of another process"),
            Some(&state),
            Some(200),
        ));

        assert_ne!(
            member_of(&first),
            member_of(&reused_pid),
            "another owner start time is a new member"
        );
        assert_eq!(reused_pid.run, 1, "and its run counter starts again");
        let next = super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("the start after");
        assert_eq!(
            member_of(&reused_pid),
            member_of(&next),
            "the new member key is kept, for the restarts of the new owner"
        );
    }

    /// An owner whose start time cannot be read gets no reuse of an old pair: the safe side. A pair
    /// that this start made is kept.
    #[cfg(all(unix, feature = "host"))]
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn with_no_start_time_an_old_pair_is_not_reused_and_a_new_one_is_kept() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::lifecycle",
            "from another owner",
        );
        let dir = TempDir::new("habilis-owner-none");
        let state = dir.path().join("session.json");
        let made = ended(super::bind_to_owner(
            super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("first start"),
            Some(&state),
            None,
        ));
        let old = super::run_keys(Some(&state), &super::NEVER_CANCELLED)
            .expect("a start with the pair of the first");
        let checked = super::bind_to_owner(old.clone(), Some(&state), None);

        assert_eq!(made.run, 1, "a pair made by this start is kept");
        assert_ne!(
            member_of(&old),
            member_of(&checked),
            "an old pair is not reused with no start time to check"
        );
    }

    /// The member key survives a restart and the session key does not: the session key signs the
    /// frames of the run, and a restart that kept it would sign as the old run.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_restart_keeps_the_member_key_and_changes_the_session_key() {
        let dir = env::temp_dir().join(format!("habilis-run-keys-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("session.json");
        let first =
            ended(super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("first start"));
        let second = super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("restart");
        assert_eq!(
            member_of(&first),
            member_of(&second),
            "the restart keeps the member key"
        );
        assert_ne!(
            first.session.author_key(),
            second.session.author_key(),
            "the restart makes a new session key"
        );
        assert_ne!(
            first.session.author_key(),
            member_of(&first),
            "the session key is not the member key"
        );
        assert_eq!(
            (first.run, second.run),
            (1, 2),
            "the run number counts the starts"
        );
    }

    /// Two live daemons cannot be one member: the second start of a state path that a live start
    /// holds fails, and says which path and the way out. Today it reads the same member key and
    /// takes the next run, so a peer drops the first session as an older run of the same member.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_second_start_on_a_state_path_that_a_live_start_holds_fails() {
        let dir = env::temp_dir().join(format!("habilis-key-lock-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("held.json");
        let first = super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("first start");
        let refused = super::run_keys(Some(&state), &super::NEVER_CANCELLED);
        let error = refused.expect_err("a second live start of one state path is refused");
        let text = format!("{error:#}");
        let key_file = state.with_extension("key").display().to_string();
        assert!(
            text.contains(&key_file)
                && text.contains("another nickname")
                && text.contains("--state-file"),
            "the error names the key file and the way out: {text}"
        );
        drop(first);
    }

    /// A restart that comes right after a leave meets the old daemon while it still stops: the start
    /// tries again for a short time instead of failing at once. The runtime has ONE thread, the one that
    /// the old daemon stops on: a wait that blocks the thread would keep it from stopping, and the start
    /// would wait the whole time and fail. The holder here ends after 300 ms, on that thread.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_start_that_meets_a_holder_that_is_stopping_waits_for_it_on_one_thread() {
        use std::time::Instant;
        let guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::run(guard, async {
            let dir = env::temp_dir().join(format!("habilis-key-lock-wait-{}", process::id()));
            fs::create_dir_all(&dir).expect("a temp dir");
            let state = dir.join("wait.json");
            let holder =
                super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("first start");
            let stopping = tokio::spawn(async move {
                time::sleep(Duration::from_millis(300)).await;
                drop(holder);
            });
            let started = Instant::now();
            let second = super::hold_member_key(Some(&state)).await;
            let waited = started.elapsed();
            stopping.await.expect("the holder task ends");
            assert!(
                second.is_ok(),
                "a start that meets a holder that is stopping works: {:?}",
                second.err()
            );
            assert!(
                waited >= Duration::from_millis(250) && waited < Duration::from_secs(2),
                "the start waited for the holder, and not for the whole retry: {waited:?}"
            );
        });
    }

    /// The lock goes with the daemon: when the holder is dropped (or dies, since the lock is an OS
    /// lock on a descriptor) the next start of the path works and keeps the member key. A child that
    /// the daemon spawned must not keep the lock after the daemon is gone, so the lock file is
    /// opened close-on-exec (the default of Rust): a child that outlives the holder frees the key.
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn a_start_after_the_holder_is_gone_works_even_while_a_child_of_it_lives() {
        use std::io::{BufRead, BufReader};
        let dir = env::temp_dir().join(format!("habilis-key-lock-child-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("child.json");
        let first = super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("first start");
        let first_member = member_of(&first);
        // The child says that it runs: before its exec it still holds a copy of every descriptor of this
        // process, the lock file too, and a holder that is dropped in that gap leaves the lock held for it.
        let mut child: process::Child = process::Command::new("sh")
            .args(["-c", "echo ready; sleep 30"])
            .stdout(process::Stdio::piped())
            .spawn()
            .expect("a child that outlives the holder");
        let mut ready = String::new();
        let pipe = child.stdout.take().expect("a pipe");
        BufRead::read_line(&mut BufReader::new(pipe), &mut ready)
            .expect("the child says that it runs");
        drop(first);
        let second = super::run_keys(Some(&state), &super::NEVER_CANCELLED);
        child.kill().expect("the child is stopped");
        child.wait().expect("the child is reaped");
        let second = second.expect("the child does not keep the lock");
        assert_eq!(
            (member_of(&second), second.run),
            (first_member, 2),
            "the restart keeps the member key and takes the next run"
        );
    }

    /// The failure this prevents: a restarted session starts its slices again at version 1. Each
    /// run signs with its own session key, so its slice is a new slot, and a replica that holds
    /// the first run takes the restarted run too.
    #[test]
    fn a_restarted_session_writes_its_slice_under_its_session_key() {
        use crate::daemon::state::RunKeys;
        use crate::doc::{SliceIngest, SliceLimits, SliceStore, worst_frame_overhead};
        use crate::protocol::{Channel, MeshId, Message, MessageBody};
        use crate::testing;
        use crate::util::clock::Instant;
        let dir = env::temp_dir().join(format!("habilis-restart-actor-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("session.json");
        let mesh = MeshId::from("💬test");
        let author = testing::nick("alice");
        let write = |keys: &RunKeys, version: u8| {
            let body = MessageBody::try_new(&format!(r#"{{"version":{version},"value":{{}}}}"#))
                .expect("a slice body");
            Message::new_channel_event(&mesh, &author, body, Channel::State).sign(&keys.session)
        };
        let before = write(
            &super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("first start"),
            5,
        );
        let after = write(
            &super::run_keys(Some(&state), &super::NEVER_CANCELLED).expect("restart"),
            1,
        );
        let mut replica = SliceStore::new(
            Channel::State,
            SliceLimits::default(),
            worst_frame_overhead(),
        );
        assert!(
            matches!(
                replica.ingest(&before, true, Instant::now()),
                SliceIngest::Applied
            ),
            "the replica takes the first run"
        );
        let outcome = replica.ingest(&after, true, Instant::now());
        assert!(
            matches!(outcome, SliceIngest::Applied),
            "the replica takes the restarted run, got {outcome:?}: the session key is new"
        );
    }

    use crate::daemon::node::SignalHandling;
    use crate::transport::PayloadPath;
    use crate::{embed, lookup, membership, transport};
    use tokio::time;
    /// A walking member keeps only the rung read as ours; the `discover` session, which never
    /// walks, leaves out only a rung read as foreign: a silent or refusing one may be its beacon.
    #[test]
    fn what_a_member_leaves_out_at_setup_follows_its_walk() {
        use super::{CoHostPolicy, ProbeAnswer, rungs_withheld_at_setup};

        let _guard = ::habilis_network_test_tracing::init();
        let read = [
            (4161, ProbeAnswer::Foreign),
            (5511, ProbeAnswer::Refused),
            (8450, ProbeAnswer::NoAnswer),
            (11743, ProbeAnswer::Ours),
        ];
        assert_eq!(
            rungs_withheld_at_setup(CoHostPolicy::Never, &read),
            vec![4161],
            "a never policy withholds the rungs of its walk at setup"
        );
        assert_eq!(
            rungs_withheld_at_setup(CoHostPolicy::Deferred, &read),
            vec![4161, 5511, 8450],
            "a deferred policy withholds its rungs at setup"
        );
        assert_eq!(
            rungs_withheld_at_setup(CoHostPolicy::Eager, &read),
            vec![4161, 5511, 8450],
            "an eager policy withholds its rungs at setup"
        );
    }

    use std::time::Duration;

    use crate::protocol::meshes::{LookupOpts, RelayChoice, Transport, TransportPolicy};

    // A browser has no UDP: it reaches a peer only through the relay, and a
    // data channel's handshake crosses the relay too. `validate` accepts
    // `udp,webrtc` with no relay lookup, because a native node can signal
    // over UDP.
    use crate::daemon::node;
    use crate::lookup::test_relay;
    use crate::protocol::meshes::Lookup;
    use crate::util::tuning;
    use tokio::sync::mpsc;
    #[test]
    fn a_browser_refuses_a_mesh_with_no_relay_lookup() {
        let _guard = ::habilis_network_test_tracing::init();
        let dht_only = LookupOpts::new(RelayChoice::Disabled).dht(true);
        let policy =
            TransportPolicy::try_from(&[Transport::Udp, Transport::WebRtc]).expect("valid");
        let transports = lookup::TransportOpts::default().within(&policy);
        let error = super::refuse_in_browser(&dht_only, &policy, transports)
            .expect_err("no path to signal on");
        assert_eq!(
            error.to_string(),
            super::BROWSER_NEEDS_RELAY_LOOKUP,
            "a browser refuses a mesh with no relay lookup with the browser message"
        );

        let relay = LookupOpts::new(RelayChoice::Pinned)
            .mdns(dht_only.mdns)
            .dht(dht_only.dht);
        super::refuse_in_browser(&relay, &policy, transports).expect("the relay signals");
    }

    // A native node without UDP signals its data channel over the relay, as a
    // browser does. `validate` checks the mesh's list, not this node's own
    // narrower paths.
    #[test]
    fn a_node_without_udp_refuses_a_mesh_with_no_relay_lookup() {
        let _guard = ::habilis_network_test_tracing::init();
        let dht_only = LookupOpts::new(RelayChoice::Disabled).dht(true);
        let policy =
            TransportPolicy::try_from(&[Transport::Udp, Transport::WebRtc]).expect("valid");
        let webrtc_only = lookup::TransportOpts::webrtc_only();
        super::member_transports(&dht_only, webrtc_only, &policy)
            .expect_err("no path to signal on");
        let relay = LookupOpts::new(RelayChoice::Pinned)
            .mdns(dht_only.mdns)
            .dht(dht_only.dht);
        super::member_transports(&relay, webrtc_only, &policy).expect("the relay signals");
    }

    // The relay lookup names a relay, but only this node's relay transport
    // can dial it: without one, a browser neither signals nor carries relay
    // payload.
    #[test]
    fn a_browser_refuses_a_node_with_no_relay_transport() {
        let _guard = ::habilis_network_test_tracing::init();
        let lookups = LookupOpts::new(RelayChoice::Pinned);
        let no_relay = |policy: &TransportPolicy| lookup::TransportOpts {
            relay: false,
            ..lookup::TransportOpts::default().within(policy)
        };
        let webrtc =
            TransportPolicy::try_from(&[Transport::Udp, Transport::WebRtc]).expect("valid");
        drop(
            super::refuse_in_browser(&lookups, &webrtc, no_relay(&webrtc))
                .expect_err("no relay to signal on"),
        );
        let relay_payload =
            TransportPolicy::try_from(&[Transport::Udp, Transport::Relay]).expect("valid");
        drop(
            super::refuse_in_browser(&lookups, &relay_payload, no_relay(&relay_payload))
                .expect_err("no relay to carry payload"),
        );
    }

    use tokio::sync::watch;

    use crate::testing::{errors_through_runtime_drop, silent_relay_rung};

    // The mesh policy decides multi-hop: the default list has it, a list that
    // leaves it out has none, and no flag says otherwise.
    #[test]
    fn multihop_follows_the_mesh_policy() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            for (list, expected) in [
                (vec![], true),
                (vec![Transport::Udp, Transport::WebRtc], false),
                (vec![Transport::Udp, Transport::Multihop], true),
            ] {
                let options = membership::JoinOptions {
                    transport: list.clone(),
                    ..membership::JoinOptions::default()
                };
                let (kind, author) = membership::resolve_kind(&options, None).expect("a kind");
                let config = super::setup_mesh(
                    kind,
                    super::SetupParams::new(author, embed::SilentSink).max_peers(8),
                )
                .await
                .expect("a loopback mesh sets up");
                assert_eq!(config.transports.multihop.is_some(), expected, "{list:?}");
                config
                    .endpoints
                    .router
                    .shutdown()
                    .await
                    .expect("the router stops");
                if let Some(handle) = config.transports.multihop.as_ref() {
                    handle.close().await;
                }
            }
        });
    }

    /// A child process that lives until the guard drops: a live pid for an owner.
    #[cfg(all(unix, feature = "host"))]
    struct Sleeper(process::Child);

    #[cfg(all(unix, feature = "host"))]
    impl Sleeper {
        fn spawn() -> Self {
            let child = process::Command::new("sleep")
                .arg("120")
                .spawn()
                .expect("a sleep process");
            // The start times of two processes differ by a tick at least.
            thread::sleep(Duration::from_millis(50));
            Self(child)
        }
    }

    #[cfg(all(unix, feature = "host"))]
    impl Drop for Sleeper {
        fn drop(&mut self) {
            drop(self.0.kill());
            drop(self.0.wait());
        }
    }

    /// The owner of the daemon, set through `set_owner_pid`, binds the pair of files: the same owner
    /// restarts with its member key and the run goes on, and another process with another start time
    /// that names the same state file starts as a new member at run 1.
    #[cfg(all(unix, feature = "host"))]
    #[cfg(all(unix, feature = "host"))]
    #[test]
    fn set_owner_pid_binds_the_member_key_to_its_owner() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::lifecycle",
                "from another owner",
            );
            let dir = TempDir::new("habilis-owner-wiring");
            let state = dir.path().join("session.json");
            let (first_owner, second_owner) = (Sleeper::spawn(), Sleeper::spawn());
            let start = |owner: u32| {
                let state = state.clone();
                async move {
                    let options = membership::JoinOptions::default();
                    let (kind, author) = membership::resolve_kind(&options, None).expect("a kind");
                    let params = super::SetupParams::new(author, embed::SilentSink)
                        .max_peers(8)
                        .state_file(state);
                    let config = super::setup_mesh(kind, params)
                        .await
                        .expect("a loopback mesh sets up");
                    let config = config.set_owner_pid(owner).expect("a live owner");
                    let keys = ended(config.mesh.keys.clone());
                    config
                        .endpoints
                        .router
                        .shutdown()
                        .await
                        .expect("the router stops");
                    if let Some(handle) = config.transports.multihop.as_ref() {
                        handle.close().await;
                    }
                    keys
                }
            };

            let first = start(first_owner.0.id()).await;
            let restart = start(first_owner.0.id()).await;
            let reused_pid = start(second_owner.0.id()).await;

            assert_eq!(
                member_key(&first),
                member_key(&restart),
                "the same owner keeps the member key"
            );
            assert_eq!((first.run, restart.run), (1, 2), "and the run goes on");
            assert_ne!(
                member_key(&first),
                member_key(&reused_pid),
                "another owner that names the same state file is a new member"
            );
            assert_eq!(reused_pid.run, 1, "at run 1");
        });
    }

    // A node without UDP takes part in multihop when the policy has it: the rule is that
    // a direct path exists, `udp` or `webrtc`, and not `udp` alone. With neither, the
    // underlay has no direct path to forward over, and there is no handle. A node may run with
    // fewer transports than the policy names, which is how a list with `webrtc` and `multihop`
    // meets a node that has no `udp`.
    #[test]
    fn a_member_without_udp_gets_a_multihop_handle_when_it_has_webrtc() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (relay_url, _relay) = test_relay::spawn_plain().await.expect("a local relay");
            for (transports, expected) in [
                (
                    lookup::TransportOpts {
                        udp: false,
                        ..lookup::TransportOpts::default()
                    },
                    true,
                ),
                (
                    lookup::TransportOpts {
                        udp: false,
                        webrtc: false,
                        ..lookup::TransportOpts::default()
                    },
                    false,
                ),
            ] {
                // A node without UDP needs the relay: it carries the offers of its data channels.
                let options = membership::JoinOptions {
                    transport: vec![Transport::WebRtc, Transport::Multihop],
                    lookup: vec![Lookup::Relay],
                    relay_urls: vec![relay_url.to_string()],
                    ..membership::JoinOptions::default()
                };
                let (kind, author) = membership::resolve_kind(&options, None).expect("a kind");
                let config = super::setup_mesh(
                    kind,
                    super::SetupParams::new(author, embed::SilentSink)
                        .max_peers(8)
                        .transports(transports),
                )
                .await
                .expect("a mesh sets up");
                assert_eq!(
                    config.transports.multihop.is_some(),
                    expected,
                    "{transports:?}"
                );
                if let Some(handle) = config.transports.multihop.as_ref() {
                    assert_eq!(handle.link_cost(), 10, "{transports:?}");
                }
                // Leave closes what setup bound, the endpoint, the underlay and the leg.
                leave_and_keep_handles(config).await;
            }
        });
    }

    // A node run without `udp` has no IP on any of its endpoints. Its underlay rides WebRTC and
    // the relay: it has no IP socket, and it has the WebRTC leg that carries its cells.
    #[test]
    fn the_underlay_of_a_member_without_udp_has_no_ip_socket_and_has_a_webrtc_leg() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (relay_url, _relay) = test_relay::spawn_plain().await.expect("a local relay");
            let options = membership::JoinOptions {
                transport: vec![Transport::WebRtc, Transport::Multihop],
                lookup: vec![Lookup::Relay],
                relay_urls: vec![relay_url.to_string()],
                ..membership::JoinOptions::default()
            };
            let (kind, author) = membership::resolve_kind(&options, None).expect("a kind");
            let config = super::setup_mesh(
                kind,
                super::SetupParams::new(author, embed::SilentSink)
                    .max_peers(8)
                    .transports(lookup::TransportOpts {
                        udp: false,
                        ..lookup::TransportOpts::default()
                    }),
            )
            .await
            .expect("a mesh sets up");
            let leg = config
                .transports
                .underlay_webrtc
                .as_ref()
                .expect("the underlay has a WebRTC leg");
            assert!(
                leg.endpoint.bound_sockets().is_empty(),
                "the underlay has no IP socket: {:?}",
                leg.endpoint.bound_sockets()
            );
            // Leave closes what setup bound, the endpoint, the underlay and the leg.
            leave_and_keep_handles(config).await;
        });
    }

    // G and C come from the caller, and `0` takes the default. Every option set
    // (`Opts`, the C struct, the browser object) ends in `setup_mesh`, so this is
    // the one place that has to hold.
    #[test]
    fn the_caps_follow_the_params_and_zero_takes_the_default() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::transport::MAX_DIRECT_PEERS;
            use crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY;

            for (max_peers, max_direct, want_g, want_c) in [
                (0, 0, GOSSIP_ACTIVE_VIEW_CAPACITY, MAX_DIRECT_PEERS),
                (5, 3, 5, 3),
            ] {
                let options = membership::JoinOptions::default();
                let (kind, author) = membership::resolve_kind(&options, None).expect("a kind");
                let config = super::setup_mesh(
                    kind,
                    super::SetupParams::new(author, embed::SilentSink)
                        .max_peers(max_peers)
                        .max_direct(max_direct),
                )
                .await
                .expect("a loopback mesh sets up");
                assert_eq!(config.runtime.max_peers, want_g, "G for {max_peers}");
                assert_eq!(
                    config.transports.webrtc_admission.cap(),
                    want_c,
                    "C for {max_direct}"
                );
                config
                    .endpoints
                    .router
                    .shutdown()
                    .await
                    .expect("the router stops");
                if let Some(handle) = config.transports.multihop.as_ref() {
                    handle.close().await;
                }
            }
        });
    }

    // The defaults of the two bounds: G is 32 gossip neighbors, and C (decision D11) is 64
    // direct peers, counting `WebRTC` sessions and unicast connections.
    #[test]
    fn the_default_bounds_are_32_neighbors_and_64_direct_peers() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
            32,
            "the gossip active view is capped at 32 neighbors"
        );
        assert_eq!(
            transport::MAX_DIRECT_PEERS,
            64,
            "the direct peer bound is 64"
        );
    }

    /// A multihop handle on `secret`, with its underlay on the key that the handle derives.
    async fn multihop_on(
        secret: &iroh::SecretKey,
        relay_payload: PayloadPath,
    ) -> habilis_network_iroh_multihop_transport::MultihopHandle {
        use habilis_network_iroh_multihop_transport::{MultihopHandle, underlay_secret};
        use iroh::endpoint::presets;

        let underlay: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(underlay_secret(secret))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind an underlay");
        MultihopHandle::new(
            secret,
            underlay,
            lookup::multihop_handle_config(relay_payload),
        )
        .expect("underlay on the derived key")
    }

    /// An endpoint a caller built to inject: the engine's wiring, a multihop
    /// handle with `relay_payload`, and one key.
    async fn injected(relay_payload: PayloadPath) -> super::InjectedEndpoint {
        let secret = iroh::SecretKey::from_bytes(&[91; 32]);
        let webrtc = lookup::build_webrtc_handle(secret.public());
        let handle = multihop_on(&secret, relay_payload).await;
        super::InjectedEndpoint::bind(
            &LookupOpts::loopback(),
            secret,
            Vec::new(),
            lookup::TransportHandles {
                multihop: Some(handle),
                webrtc: Some(webrtc),
                gossip: None,
                admission: None,
                underlay: false,
                options: lookup::TransportOpts::default(),
            },
            transport::MAX_DIRECT_PEERS,
        )
        .await
        .expect("the injected endpoint binds")
    }

    /// A handle made from a key other than the one the endpoint binds is refused
    /// by `bind`, both for the `WebRTC` transport and for the multihop handle.
    #[tokio::test]
    async fn an_injected_handle_on_another_key_is_refused_at_bind() {
        let secret = iroh::SecretKey::from_bytes(&[91; 32]);
        let other = iroh::SecretKey::from_bytes(&[5; 32]);
        let lookups = LookupOpts::loopback();
        let bind = |webrtc, multihop| {
            super::InjectedEndpoint::bind(
                &lookups,
                secret.clone(),
                Vec::new(),
                lookup::TransportHandles {
                    multihop,
                    webrtc,
                    gossip: None,
                    admission: None,
                    underlay: false,
                    options: lookup::TransportOpts::default(),
                },
                transport::MAX_DIRECT_PEERS,
            )
        };
        let own_webrtc = lookup::build_webrtc_handle(secret.public());
        let other_webrtc = lookup::build_webrtc_handle(other.public());

        let other_hop = multihop_on(&other, PayloadPath::DirectOnly).await;
        let hop_error = bind(Some(own_webrtc.clone()), Some(other_hop.clone()))
            .await
            .expect_err("a hop identity on another key");
        assert!(hop_error.to_string().contains("multihop"), "{hop_error}");
        other_hop.close().await;

        let webrtc_error = bind(Some(other_webrtc), None)
            .await
            .expect_err("a WebRTC handle on another key");
        assert!(
            webrtc_error.to_string().contains("WebRTC"),
            "{webrtc_error}"
        );

        // A refused handle is not bound, so the one that was refused is still free.
        let accepted = bind(Some(own_webrtc.clone()), None)
            .await
            .expect("handles on the bound key are accepted");
        accepted.endpoint.close().await;

        let table = transport::SignalAdmission::new(transport::MAX_DIRECT_PEERS);
        let table_error = super::InjectedEndpoint::bind(
            &lookups,
            secret.clone(),
            Vec::new(),
            lookup::TransportHandles {
                webrtc: Some(own_webrtc),
                admission: Some(table),
                ..lookup::TransportHandles::default()
            },
            transport::MAX_DIRECT_PEERS,
        )
        .await
        .expect_err("a caller's admission table");
        assert!(
            table_error.to_string().contains("admission"),
            "{table_error}"
        );
    }

    /// The hook of an injected endpoint reports its connections to the table the mesh
    /// enforces: a peer that dials it holds a direct slot there, and the count rises.
    #[tokio::test]
    async fn an_injected_endpoints_hook_reports_to_its_admission_table() {
        // Only the unicast ALPN counts against the ceiling; every connection still lands in the slot table.
        const ALPN: &[u8] = transport::UNICAST_ALPN;
        let secret = iroh::SecretKey::from_bytes(&[92; 32]);
        let injected: super::InjectedEndpoint = super::InjectedEndpoint::bind(
            &LookupOpts::loopback(),
            secret.clone(),
            vec![ALPN.to_vec()],
            lookup::TransportHandles {
                webrtc: Some(lookup::build_webrtc_handle(secret.public())),
                ..lookup::TransportHandles::default()
            },
            transport::MAX_DIRECT_PEERS,
        )
        .await
        .expect("the injected endpoint binds");
        assert_eq!(injected.admission.direct_units(), 0, "no peer dialed yet");

        let dialer = lookup::build_peer_endpoint(&LookupOpts::loopback())
            .await
            .expect("a dialer binds");
        let server = injected.endpoint.clone();
        let serving = tokio::spawn(async move {
            let incoming = server.accept().await.expect("an incoming connection");
            incoming.await.expect("the handshake completes")
        });
        let connection = dialer
            .connect(injected.endpoint.addr(), ALPN)
            .await
            .expect("the dial connects");
        let _served = serving.await.expect("the accept task");

        // The hook runs after the handshake, so the slot may land a moment after the dial.
        let mut units = 0;
        for _ in 0..200 {
            units = injected.admission.direct_units();
            if units > 0 {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            units, 1,
            "the endpoint's hook did not report the dialer to its table"
        );

        drop(connection);
        dialer.close().await;
        injected.endpoint.close().await;
    }

    async fn setup_with(
        list: Vec<Transport>,
        injected: super::InjectedEndpoint,
    ) -> anyhow::Result<super::EventLoopConfig> {
        let options = membership::JoinOptions {
            transport: list,
            ..membership::JoinOptions::default()
        };
        let (kind, author) = membership::resolve_kind(&options, None)?;
        super::setup_mesh(
            kind,
            super::SetupParams::new(author, embed::SilentSink)
                .max_peers(8)
                .endpoint(injected),
        )
        .await
        .map_err(anyhow::Error::from)
    }

    // An injected endpoint obeys the mesh policy too: a handle on a mesh whose
    // list has no `multihop` is dropped, so it advertises no link-state and takes
    // none in.
    #[test]
    fn an_injected_multihop_handle_is_dropped_when_the_mesh_has_no_multihop() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let first = injected(PayloadPath::DirectOnly).await;
            let (first_endpoint, first_handle) = (first.endpoint.clone(), first.multihop.clone());
            let config = setup_with(vec![Transport::Udp, Transport::WebRtc], first)
                .await
                .expect("a loopback mesh sets up");
            assert!(
                config.transports.multihop.is_none(),
                "no multihop on a udp,webrtc mesh"
            );
            config
                .endpoints
                .router
                .shutdown()
                .await
                .expect("the router stops");
            if let Some(handle) = first_handle {
                handle.close().await;
            }
            first_endpoint.close().await;

            let default_list = setup_with(Vec::new(), injected(PayloadPath::DirectOnly).await)
                .await
                .expect("a loopback mesh sets up");
            assert!(
                default_list.transports.multihop.is_some(),
                "the default list has it"
            );
            default_list
                .endpoints
                .router
                .shutdown()
                .await
                .expect("the router stops");
            if let Some(handle) = default_list.transports.multihop.as_ref() {
                handle.close().await;
            }
        });
    }

    // Whether the relay may carry cells is a rule of the mesh: a handle that lets
    // it, on a lookup-only mesh, is refused.
    #[test]
    fn an_injected_multihop_handle_that_lets_the_relay_carry_cells_is_refused() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let refused = injected(PayloadPath::RelayAllowed).await;
            let (endpoint, handle) = (refused.endpoint.clone(), refused.multihop.clone());
            let error = setup_with(Vec::new(), refused)
                .await
                .expect_err("relay cells on a lookup-only mesh");
            assert!(format!("{error:#}").contains("relay"), "{error:#}");
            if let Some(handle) = handle {
                handle.close().await;
            }
            endpoint.close().await;
        });
    }

    /// Regression for `Endpoint dropped without calling Endpoint::close` on a
    /// Ctrl-C in the first seconds of a run. The startup probe was detached,
    /// so `Node::leave` had nothing to wait for: `main` returned while the
    /// probe was still waiting for its relay, or still closing, and the runtime
    /// drop took its endpoint down open.
    #[test]
    fn a_departure_during_the_startup_rung_probe_closes_its_endpoint() {
        let _guard = ::habilis_network_test_tracing::init();
        let (_silent, rung) = silent_relay_rung();

        let errors = errors_through_runtime_drop(async {
            let probe = super::spawn_startup_rung_confirmation(vec![rung], watch::channel(None).0)
                .expect("a ladder to walk");
            // Let the probe bind and start waiting for its relay.
            time::sleep(Duration::from_millis(200)).await;
            probe.stop_and_wait().await;
        });

        assert!(
            !errors.contains("Endpoint dropped without calling"),
            "the startup rung probe's endpoint reached its drop open:\n{errors}"
        );
    }

    /// Spawn a node on `config`, give back the endpoint and the underlay handle it was
    /// set up with, and leave. The clones keep the answer readable after the node is gone.
    async fn leave_and_keep_handles(
        config: super::EventLoopConfig,
    ) -> (
        iroh::Endpoint,
        Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    ) {
        let endpoint = config.endpoints.endpoint.clone();
        let underlay = config.transports.multihop.clone();
        let (inbound_tx, _inbound_rx) = mpsc::channel(1);
        let node = node::Node::spawn(
            config,
            membership::MembershipApp::new(inbound_tx),
            None,
            SignalHandling::Leave,
        );
        node.leave().await.expect("the node leaves");
        (endpoint, underlay)
    }

    // The node closes what its setup bound, so iroh has nothing to log as dropped.
    #[test]
    fn leave_closes_the_endpoint_and_the_underlay_that_setup_bound() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let options = membership::JoinOptions::default();
            let (kind, author) = membership::resolve_kind(&options, None).expect("a kind");
            let config = super::setup_mesh(
                kind,
                super::SetupParams::new(author, embed::SilentSink).max_peers(8),
            )
            .await
            .expect("a loopback mesh sets up");
            let (endpoint, underlay) = leave_and_keep_handles(config).await;
            assert!(endpoint.is_closed(), "the endpoint is closed after leave");
            assert!(
                underlay.expect("the default list has multihop").is_closed(),
                "the underlay is closed after leave"
            );
        });
    }

    // An injected endpoint is the caller's, and it may carry protocols of the caller.
    #[test]
    fn leave_keeps_an_injected_endpoint_and_its_underlay_open() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let injected = injected(PayloadPath::DirectOnly).await;
            let config = setup_with(Vec::new(), injected)
                .await
                .expect("a loopback mesh sets up");
            let (endpoint, underlay) = leave_and_keep_handles(config).await;
            assert!(!endpoint.is_closed(), "the caller's endpoint stays open");
            let underlay = underlay.expect("the injected handle is used");
            assert!(!underlay.is_closed(), "the caller's underlay stays open");
            underlay.close().await;
            endpoint.close().await;
        });
    }
}

// The browser build of `build_member_endpoint` is the one that runs without `host`. A native test
// binary built without `host` runs it, with no IP on the node, as a browser would.
#[cfg(all(test, feature = "multihop", not(feature = "host")))]
mod browser_tests {
    use crate::protocol::meshes::{Lookup, Transport};

    #[test]
    fn a_browser_member_has_a_multihop_handle_with_the_link_cost_of_a_browser() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (relay_url, _relay) = crate::lookup::test_relay::spawn_plain()
                .await
                .expect("a local relay");
            let options = crate::membership::JoinOptions {
                transport: vec![Transport::WebRtc, Transport::Multihop],
                lookup: vec![Lookup::Relay],
                relay_urls: vec![relay_url.to_string()],
                ..crate::membership::JoinOptions::default()
            };
            let (kind, author) = crate::membership::resolve_kind(&options, None).expect("a kind");
            let mut config = super::setup_mesh(
                kind,
                super::SetupParams::new(author, crate::embed::SilentSink)
                    .max_peers(8)
                    .transports(crate::lookup::TransportOpts {
                        udp: false,
                        ..crate::lookup::TransportOpts::default()
                    }),
            )
            .await
            .expect("a mesh sets up");
            assert_eq!(
                config
                    .transports
                    .multihop
                    .as_ref()
                    .expect("a multihop handle")
                    .link_cost(),
                100,
                "a browser member's multihop handle carries the browser link cost"
            );
            // The router closes the endpoint that it serves on. The handle closes the underlay, the
            // WebRTC leg of the underlay has an endpoint of its own, and so has the startup rung probe.
            if let Some(probe) = config.rendezvous.rung_probe.take() {
                probe.stop_and_wait().await;
            }
            config.router.shutdown().await.expect("the router stops");
            if let Some(handle) = config.multihop.as_ref() {
                handle.close().await;
            }
            if let Some(leg) = config.underlay_webrtc.as_ref() {
                leg.endpoint.close().await;
            }
            config.endpoint.close().await;
        });
    }
}
