use crate::{beacon, transport};
use iroh_gossip::{api, net, proto};
#[cfg(not(all(unix, feature = "host")))]
use std::fs::File;
#[cfg(all(unix, feature = "host"))]
use std::fs::{File, OpenOptions};
#[cfg(all(unix, feature = "host"))]
use std::io;
use std::path::{Path, PathBuf};
use std::{mem, sync};
#[cfg(all(unix, feature = "host"))]
use std::{thread, time::Duration, time::Instant};
#[cfg(feature = "host")]
use tokio::task;
mod injected_endpoint;
mod setup_kind;
mod setup_params;

use crate::transport::UdpTransport;

#[cfg(all(unix, feature = "host"))]
use anyhow::Context as _;
use anyhow::Result;

use super::setup_error::SetupError;
use iroh::{Endpoint, RelayUrl};
use rand::RngCore;
use tokio::sync::{mpsc, watch};

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
///   the chosen relay **rung** (`params.bootstrap_relay` — the first
///   reachable rung of the ladder) — the beacon homes there
///   (`beacon::beacon_lookups`), so this is a real relay-direct dial, no
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
/// back-pressure the loop (a dropped frame heals via anti-entropy).
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
    /// True for the node that created the mesh: it has no peer to sync its state with.
    is_creator: bool,
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
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let seed: Option<[u8; 32]> = bytes
                .get(..32)
                .and_then(|seed| <[u8; 32]>::try_from(seed).ok());
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
    use rustix::fs::OFlags;
    use rustix::io::Errno;
    use rustix::process::geteuid;
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let flags = i32::try_from(OFlags::NOFOLLOW.bits()).unwrap_or(0);
    let file: File = options
        .custom_flags(flags)
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
fn next_run(state: Option<&Path>, member_known: bool) -> Result<u64> {
    use std::fs;
    use std::io::ErrorKind;
    let Some(state) = state else {
        return Ok(1);
    };
    let run_path = state.with_extension("run");
    // The read of the counter and the write of the next one are one step: two starts of one state path
    // would otherwise read one count and publish one run. The lock is on a file of its own, because the
    // counter file is replaced by a rename; it is held until `run_lock` drops at the end of the call.
    let run_lock = lock_run_counter(state)?;
    let run = match fs::read(&run_path) {
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
    use std::io::Read as _;
    let mut reading = OpenOptions::new();
    reading.read(true);
    let mut file = open_trusted_key_file(key_path, &mut reading).ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    let tail = bytes.get(40..48)?;
    <[u8; 8]>::try_from(tail).ok().map(u64::from_le_bytes)
}

/// Take the exclusive lock on `<state>.key.lock` and keep it as long as the returned file lives, so two
/// live starts of one state path cannot be one member: the second would read the same member key and take
/// the next run, and a peer would drop the first as an older run of that member. Each try is non-blocking, and
/// a held lock is tried again for `KEY_LOCK_RETRY`, in steps of `KEY_LOCK_STEP`, because a restart that comes
/// right after a leave meets the old daemon while it still stops; after that the start fails and names the way
/// out. It is an OS lock on the descriptor, so it goes with the process, and a crash frees the key. The file
/// is opened close-on-exec (the default of Rust), so a child of the daemon does not keep the lock after the
/// daemon is gone. No state path means no key to keep. A file system that has no file locks cannot start a
/// daemon with a member key: the error names the lock file.
#[cfg(all(unix, feature = "host"))]
// the lock is shared with every clone of the keys, and the last one to drop frees it
fn hold_member_key(state: Option<&Path>) -> Result<Option<sync::Arc<File>>> {
    use std::fs::TryLockError;
    use std::os::unix::fs::OpenOptionsExt as _;
    let Some(state) = state else {
        return Ok(None);
    };
    let lock_path = state.with_extension("key.lock");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false).mode(0o600);
    let lock = options
        .open(&lock_path)
        .with_context(|| format!("the lock file {} cannot be opened", lock_path.display()))?;
    let give_up = Instant::now() + KEY_LOCK_RETRY;
    loop {
        match lock.try_lock() {
            // shared with every clone of the keys: the lock goes when the last one drops
            Ok(()) => return Ok(Some(sync::Arc::new(lock))),
            Err(TryLockError::WouldBlock) if Instant::now() < give_up => {
                // a start is a one-time step and the wait is bounded, so the thread may sleep here
                thread::sleep(KEY_LOCK_STEP);
            }
            Err(TryLockError::WouldBlock) => anyhow::bail!(
                "another daemon still runs on this state file and holds the member key {}: wait for it to exit and retry, or use another nickname or --state-file",
                state.with_extension("key").display()
            ),
            Err(TryLockError::Error(error)) => {
                return Err(anyhow::Error::from(error).context(format!(
                    "the lock file {} cannot be locked: the file system may not support file locks, and a daemon with a member key cannot start there",
                    lock_path.display()
                )));
            }
        }
    }
}

/// How long a start tries again for the lock of the member key, while the daemon that holds it stops.
#[cfg(all(unix, feature = "host"))]
const KEY_LOCK_RETRY: Duration = Duration::from_secs(2);
/// The wait between two tries for the lock of the member key.
#[cfg(all(unix, feature = "host"))]
const KEY_LOCK_STEP: Duration = Duration::from_millis(50);

/// A target with no files keeps no member key, so it takes no lock.
#[cfg(not(all(unix, feature = "host")))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the version for a target with files"
)]
// the same type as the version for a target with files
fn hold_member_key(_state: Option<&Path>) -> Result<Option<sync::Arc<File>>> {
    Ok(None)
}

/// Take the exclusive lock on `<state>.run.lock`, which makes the allocation of a run one step across
/// processes and threads. It waits for the holder, and the lock goes with the returned file.
#[cfg(all(unix, feature = "host"))]
fn lock_run_counter(state: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false).mode(0o600);
    let lock = options.open(state.with_extension("run.lock"))?;
    lock.lock()?;
    Ok(lock)
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
fn next_run(_state: Option<&Path>, _member_known: bool) -> Result<u64> {
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
    let bytes = fs::read(&key_path).unwrap_or_default();
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

/// The keys of this run, under the state path that [`keys_state_path`] gives. `mesh` is the mesh id and the
/// nickname of this member.
fn run_keys_for(
    state_file: Option<&Path>,
    runtime_base: Option<&Path>,
    keys_in_default_state: bool,
    (mesh, author): (&MeshId, &Nickname),
) -> Result<RunKeys> {
    let keys_path = keys_state_path(
        state_file,
        runtime_base,
        mesh,
        author,
        keys_in_default_state,
    )?;
    run_keys(keys_path.as_deref())
}

/// The keys of this run. The member key comes from the state file. The session key is the one that
/// signs frames and names the automerge actor, so it must be new each run: a restart that reused it
/// would start the same actor again at sequence 1.
fn run_keys(state: Option<&Path>) -> Result<RunKeys> {
    // read before `member_key` makes the file: a member key that exists is from an earlier start
    let member_known = state.is_some_and(|state| state.with_extension("key").exists());
    // taken before the key file is read, so the second start fails before it takes a run
    let key_lock = hold_member_key(state)?;
    Ok(RunKeys {
        key_lock,
        // shared with the loop and its handlers, which hold clones
        session: sync::Arc::new(identity::Identity::generate()),
        member: member_key(state)?,
        run: next_run(state, member_known)?,
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
        per_peer_gate,
    } = params;
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

    let build = SetupBuild {
        author: &author,
        sink: sink.as_ref(),
        max_peers,
        max_direct,
        lookups: &lookups,
        unicast_acceptor: &unicast_acceptor,
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
        is_creator,
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

    let keys = match run_keys_for(
        state_file.as_deref(),
        runtime_base.as_deref(),
        keys_in_default_state,
        (&mesh_id, &author),
    ) {
        Ok(keys) => keys,
        Err(error) => {
            // The endpoint is bound already: close it, so a refused start (the state path is held by a
            // running node) does not drop it ungracefully.
            if let Err(close) = router.shutdown().await {
                tracing::debug!(target: "habilis_network::lifecycle", %close, "the router of a refused start did not stop cleanly");
            }
            #[cfg(feature = "multihop")]
            if let Some(handle) = multihop_handle.as_ref() {
                handle.close().await;
            }
            return Err(error.into());
        }
    };
    Ok(EventLoopConfig {
        mesh: MeshSpec {
            mesh: mesh_id,
            name: mesh_name,
            topic_string,
            mint_mesh,
            is_creator,
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
            per_peer_gate,
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
    let (gossip, router, address_book) = build_mesh(
        endpoint.clone(),
        build.max_peers,
        Some(unicast),
        webrtc_lane,
        build.take_protocols(),
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
        is_creator: true,
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
        is_creator: false,
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
    use crate::daemon::state::RunKeys;
    use crate::protocol::AuthorKey;
    use std::path::{Path, PathBuf};
    use std::{env, fs, process, thread};

    fn member_key(keys: &RunKeys) -> Option<AuthorKey> {
        let member = keys.member.as_ref();
        member.map(|member| member.author_key())
    }

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

    /// A restarted member keeps its identity: the same state file gives the same key, and a
    /// missing file gives a new one.
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
    #[test]
    fn the_run_number_rises_at_each_start() {
        let dir = TempDir::new("habilis-run-number");
        let state = dir.path().join("session.json");
        let runs: Vec<u64> = (0..3)
            .map(|_| super::next_run(Some(&state), false).expect("a run number"))
            .collect();
        assert_eq!(runs, [1, 2, 3], "each start counts one more");
        let ahead: u64 = 4_000_000_000_000;
        fs::write(state.with_extension("run"), ahead.to_le_bytes()).expect("a counter ahead");
        assert_eq!(
            super::next_run(Some(&state), false).expect("a run number"),
            ahead + 1,
            "a counter ahead of any clock still rises"
        );
        assert_eq!(
            super::next_run(None, false).expect("no state file"),
            1,
            "no file means run 1"
        );
    }

    /// A key file that another user could have planted or read is not loaded: its seed would become the
    /// identity of this member. A file of mode 0600, owned by this user, is the one that this code wrote.
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

    /// The checks of the key file are on the open file, and the open does not follow a link: a link that is
    /// put at the path after a path check cannot make the write go to its target, and a file that others can
    /// read is not written over.
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
                            .map(|_| super::next_run(Some(&state), false).expect("a run number"))
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

        let run = super::next_run(Some(&state), true).expect("a run number");

        assert!(
            run > ahead_of_the_clock,
            "the run after a lost counter is {run}, not above the last run of the key file"
        );
    }

    /// The keys of a start whose process has ended: the lock on the member key went with it, so a
    /// later start of the same state path is a restart and not a second live daemon.
    fn ended(keys: RunKeys) -> RunKeys {
        RunKeys {
            key_lock: None,
            ..keys
        }
    }

    /// Each start records its run in the key file, beside the counter file.
    #[test]
    fn each_start_records_its_run_in_the_key_file() {
        let dir = TempDir::new("habilis-run-recorded");
        let state = dir.path().join("session.json");
        let first = ended(super::run_keys(Some(&state)).expect("the first start"));
        let second = super::run_keys(Some(&state)).expect("the second start");

        let bytes = fs::read(state.with_extension("key")).expect("the key file");
        let named = bytes
            .get(40..48)
            .and_then(|tail| <[u8; 8]>::try_from(tail).ok())
            .map(u64::from_le_bytes);

        assert_eq!(first.run, 1, "the first start is run 1");
        assert_eq!(second.run, 2, "the second start is run 2");
        assert_eq!(named, Some(second.run), "the key file names the last run");
    }

    /// A daemon that the CLI started with no state file keeps its member key and counts its run on, in the
    /// default state path of its mesh, when the setup asks for it. Without the flag the keys stay ephemeral,
    /// and an explicit state file wins over the default.
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
        let first = ended(super::run_keys(Some(&default)).expect("the first start"));
        let second = super::run_keys(Some(&default)).expect("the restart");

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

    /// A counter file that a crash cut short must not restart the count at 1: a peer that kept a
    /// higher run would refuse the live session. The next run then starts above any count of starts.
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
        let run = super::next_run(Some(&state), false).expect("a run number");
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
    #[test]
    fn a_member_whose_run_file_is_deleted_restarts_from_the_clock() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network::lifecycle",
            "run counter file is unreadable",
        );
        let dir = TempDir::new("habilis-run-deleted");
        let state = dir.path().join("session.json");
        let first = ended(super::run_keys(Some(&state)).expect("the first start"));
        let second = ended(super::run_keys(Some(&state)).expect("the second start"));
        assert_eq!(
            (first.run, second.run),
            (1, 2),
            "the first starts count 1, 2"
        );
        fs::remove_file(state.with_extension("run")).expect("the run file is deleted");

        let third = super::run_keys(Some(&state)).expect("the start after the deletion");

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
        let first = super::run_keys(Some(&state)).expect("the first start");
        assert_eq!(first.run, 1, "a new member starts at run 1");
    }

    /// The pair of files (the member key and the run counter) is bound to the start time of the process
    /// that owns the daemon. A restart of the same owner keeps it. Another process that got the same
    /// pid has another start time, and starts as a new member, at run 1.
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
            super::run_keys(Some(&state)).expect("first start"),
            Some(&state),
            Some(100),
        ));
        let restart = ended(super::bind_to_owner(
            super::run_keys(Some(&state)).expect("restart"),
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
            super::run_keys(Some(&state)).expect("a start of another process"),
            Some(&state),
            Some(200),
        ));

        assert_ne!(
            member_of(&first),
            member_of(&reused_pid),
            "another owner start time is a new member"
        );
        assert_eq!(reused_pid.run, 1, "and its run counter starts again");
        let next = super::run_keys(Some(&state)).expect("the start after");
        assert_eq!(
            member_of(&reused_pid),
            member_of(&next),
            "the new member key is kept, for the restarts of the new owner"
        );
    }

    /// An owner whose start time cannot be read gets no reuse of an old pair: the safe side. A pair
    /// that this start made is kept.
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
            super::run_keys(Some(&state)).expect("first start"),
            Some(&state),
            None,
        ));
        let old = super::run_keys(Some(&state)).expect("a start with the pair of the first");
        let checked = super::bind_to_owner(old.clone(), Some(&state), None);

        assert_eq!(made.run, 1, "a pair made by this start is kept");
        assert_ne!(
            member_of(&old),
            member_of(&checked),
            "an old pair is not reused with no start time to check"
        );
    }

    /// The member key survives a restart and the session key does not: the session key is the
    /// automerge actor, and a restart that kept it would start the same actor again.
    #[test]
    fn a_restart_keeps_the_member_key_and_changes_the_session_key() {
        let dir = env::temp_dir().join(format!("habilis-run-keys-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("session.json");
        let first = ended(super::run_keys(Some(&state)).expect("first start"));
        let second = super::run_keys(Some(&state)).expect("restart");
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
    #[test]
    fn a_second_start_on_a_state_path_that_a_live_start_holds_fails() {
        let dir = env::temp_dir().join(format!("habilis-key-lock-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("held.json");
        let first = super::run_keys(Some(&state)).expect("first start");
        let refused = super::run_keys(Some(&state));
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
    /// tries again for a short time instead of failing at once. The holder here ends after 300 ms.
    #[test]
    fn a_start_that_meets_a_holder_that_is_stopping_waits_for_it() {
        use std::time::Instant;
        let dir = env::temp_dir().join(format!("habilis-key-lock-wait-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("wait.json");
        let holder = super::run_keys(Some(&state)).expect("first start");
        let stopping = thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            drop(holder);
        });
        let started = Instant::now();
        let second = super::run_keys(Some(&state));
        let waited = started.elapsed();
        stopping.join().expect("the holder thread ends");
        assert!(
            second.is_ok(),
            "a start that meets a holder that is stopping works: {:?}",
            second.err()
        );
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(2),
            "the start waited for the holder, and not for the whole retry: {waited:?}"
        );
    }

    /// The lock goes with the daemon: when the holder is dropped (or dies, since the lock is an OS
    /// lock on a descriptor) the next start of the path works and keeps the member key. A child that
    /// the daemon spawned must not keep the lock after the daemon is gone, so the lock file is
    /// opened close-on-exec (the default of Rust): a child that outlives the holder frees the key.
    #[test]
    fn a_start_after_the_holder_is_gone_works_even_while_a_child_of_it_lives() {
        let dir = env::temp_dir().join(format!("habilis-key-lock-child-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("child.json");
        let first = super::run_keys(Some(&state)).expect("first start");
        let first_member = member_of(&first);
        let mut child = process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("a child that outlives the holder");
        drop(first);
        let second = super::run_keys(Some(&state));
        child.kill().expect("the child is stopped");
        child.wait().expect("the child is reaped");
        let second = second.expect("the child does not keep the lock");
        assert_eq!(
            (member_of(&second), second.run),
            (first_member, 2),
            "the restart keeps the member key and takes the next run"
        );
    }

    /// The failure this prevents: after a restart the session starts a new document at sequence 1.
    /// Under the old actor, a replica that holds the first run refuses that change as a duplicate
    /// sequence number, and every write of the restarted member is lost.
    #[test]
    fn a_restarted_session_writes_under_a_new_actor() {
        use crate::daemon::state::RunKeys;
        use crate::doc::{Ingested, MeshDoc};
        use crate::protocol::{Channel, MeshId, Message};
        use crate::testing;
        let dir = env::temp_dir().join(format!("habilis-restart-actor-{}", process::id()));
        fs::create_dir_all(&dir).expect("a temp dir");
        let state = dir.join("session.json");
        let mesh = MeshId::from("💬test");
        let author = testing::nick("alice");
        let write = |keys: &RunKeys, value: u8| {
            let doc = MeshDoc::new_ungated();
            let seed = *keys.session.public().as_bytes();
            let change = doc
                .build_change(&serde_json::json!({ "k": value }), &seed)
                .expect("a JSON object merges")
                .expect("a non-empty merge yields a change");
            let (wire, _plain) = doc.compose_wire_body(&change, None).expect("wire body");
            Message::new_channel_event(&mesh, &author, wire, Channel::State).sign(&keys.session)
        };
        let before = write(&super::run_keys(Some(&state)).expect("first start"), 1);
        let after = write(&super::run_keys(Some(&state)).expect("restart"), 2);
        let mut replica = MeshDoc::new_ungated();
        assert!(
            matches!(replica.ingest(&before), Ingested::Applied { .. }),
            "the replica takes the first run"
        );
        let outcome = replica.ingest(&after);
        assert!(
            matches!(outcome, Ingested::Applied { .. }),
            "the replica takes the restarted run, got {outcome:?}: the actor is new"
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
    struct Sleeper(process::Child);

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

    impl Drop for Sleeper {
        fn drop(&mut self) {
            drop(self.0.kill());
            drop(self.0.wait());
        }
    }

    /// The owner of the daemon, set through `set_owner_pid`, binds the pair of files: the same owner
    /// restarts with its member key and the run goes on, and another process with another start time
    /// that names the same state file starts as a new member at run 1.
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
