use crate::transport::UdpTransport;
use std::path::PathBuf;

use anyhow::Result;

use super::setup_error::SetupError;
use iroh::{Endpoint, RelayUrl};
use rand::RngCore;
use tokio::sync::{mpsc, watch};

use crate::gossip::event::{NodeEvent, NodeSink};
#[cfg(feature = "multihop")]
use crate::lookup::build_peer_multihop_with;
use crate::lookup::{
    ProbeAnswer, StoppableTask, add_peer_addr, build_mesh, relay_ladder, select_bootstrap_rung,
};
use crate::protocol::crypto::Password;
use crate::protocol::mesh::{LookupOpts, Mesh, MeshConfig, MeshName};
use crate::protocol::{MeshId, Nickname};
use crate::util::tuning::{RELAY_RUNG_PROBE, SETUP_RUNG_READ};

use crate::beacon::RendezvousParams;
use crate::lifecycle;

use super::config::EndpointOwner;
use super::{CoHostPolicy, DriverMode, EventLoopConfig};

use crate::gossip::split;
use crate::protocol::identity;
use crate::protocol::mesh::RelayChoice;
#[cfg(any(feature = "host", feature = "multihop"))]
use crate::transport::underlay_webrtc;
use crate::transport::webrtc;
use crate::util::{consts, tuning};
use iroh::address_lookup::memory;
use std::sync::atomic;
/// What kind of mesh we're setting up — either minting a new one
/// (create) or attaching to an existing one (join).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SetupKind {
    /// Create a mesh.
    Create {
        /// The name of the mesh.
        name: MeshName,
        /// The mesh-wide config (lookups) baked into the minted id and
        /// mixed into the topic.
        config: MeshConfig,
        /// The directory this mesh advertises into, if any. Drives the
        /// `advertising on #<directory>` startup line; the re-broadcast
        /// task itself is spawned by the caller post-setup.
        advertise: Option<MeshName>,
        /// Password to protect the mesh with. Stretched *here* rather than
        /// by the frontend: the verifier's salt is the seed, which is
        /// minted below.
        password: Option<Password>,
        /// `--invite-only`: mint an invite root + issuer keypair here (the
        /// issuer pubkey is baked into the id) so the bare hash can't join —
        /// only creator-minted invites can.
        invite_only: bool,
    },
    /// Join a mesh.
    Join {
        /// The unlocked mesh to join.
        mesh: Mesh,
        /// The password the joiner presented (already verified + applied to
        /// `mesh`), retained so the daemon can key blob-ticket protection with
        /// it. `None` for a passwordless id.
        password: Option<Password>,
    },
    /// A `topic` mesh derived from a shared string. Identical to `Join`
    /// except the first peer must beacon: there is no distinguished creator,
    /// so it co-hosts the shared rendezvous eagerly-but-probed
    /// ([`CoHostPolicy::EagerProbed`]) rather than deferring.
    Topic {
        /// The mesh derived from `topic_string`.
        mesh: Mesh,
        /// The raw string the mesh was derived from. The derived name is
        /// lossy (URL scheme and query stripped, truncated), so the string
        /// is carried whole for every user-facing joined/left surface.
        topic_string: String,
    },
}

/// Build the `RendezvousParams` for a mesh. `id` is the well-known
/// rendezvous `EndpointId`; `bind_port` is `Some` only for private
/// meshes (the deterministic loopback port — public is ephemeral and
/// pkarr-discoverable).
fn rendezvous_params(
    mesh: &Mesh,
    topic_id: iroh_gossip::proto::TopicId,
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
    let bootstrap_relay = relay_ladder(&lookups.relay_lookup).first().cloned();
    RendezvousParams {
        topic_id,
        secret: mesh.rendezvous_secret(),
        bind_ports,
        id: mesh.rendezvous_id(),
        lookups: lookups.clone(),
        relay_transport: crate::transport::PayloadPath::from(
            mesh.config().transport.relay_transport,
        ),
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
    let Some(addr) = crate::beacon::rendezvous_addr_without(params, withheld) else {
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
    add_peer_addr(book, addr);
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
    relay_transport: crate::transport::PayloadPath,
) -> (
    mpsc::Receiver<bytes::Bytes>,
    crate::transport::UnicastAcceptor,
) {
    let (tx, rx) = mpsc::channel::<bytes::Bytes>(consts::UNICAST_INBOX_CAP);
    (
        rx,
        crate::transport::UnicastAcceptor::new(tx, relay_transport),
    )
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
) -> Result<(
    Endpoint,
    Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    crate::transport::SignalAdmission,
    Option<underlay_webrtc::UnderlayWebRtc>,
    Option<crate::lookup::MdnsHandle>,
)> {
    if let Some(injected) = build.injected.as_ref() {
        // Shared endpoint: no key to mint, nothing to bind. `InjectedEndpoint::bind`
        // built it, and checked that its handles carry its key. The mesh policy
        // decides multi-hop, as it does for an endpoint the engine builds: a handle
        // on a mesh whose list has no `multihop` (or on a node with no UDP) is
        // dropped, so no vector is advertised or taken in and no route resolves.
        let multihop = injected.multihop.as_ref().filter(|_| build.multihop);
        if injected.multihop.is_some() && multihop.is_none() {
            tracing::info!(
                target: "habilis_network::lookup",
                "the mesh policy has no multihop for this node: the injected multihop handle is not used"
            );
        }
        crate::lookup::check_injected_against_mesh(
            &injected.endpoint,
            multihop.is_some_and(
                habilis_network_iroh_multihop_transport::MultihopHandle::relay_payload,
            ),
            build.lookups,
            build.relay_transport.relay_allowed(),
        )?;
        // The caller built the underlay of its handle itself, so there is no
        // `WebRTC` leg on it.
        return Ok((
            injected.endpoint.clone(),
            multihop.cloned(),
            injected.webrtc.clone(),
            injected.admission.clone(),
            None,
            injected.mdns_handle(),
        ));
    }
    // Made before the endpoint, because the endpoint reports its connections
    // to this table from the first handshake on.
    let admission = crate::transport::SignalAdmission::new(build.max_direct);
    if build.multihop {
        // G caps the sessions of the underlay: it holds one to each known member that needs one.
        let (endpoint, handle, webrtc, underlay_webrtc, mdns) = build_peer_multihop_with(
            build.lookups,
            build.transports,
            Some(&admission),
            crate::lookup::multihop_handle_config(build.relay_transport),
            crate::lookup::underlay_cap(build.max_peers),
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
        let (endpoint, webrtc, mdns) = crate::lookup::build_peer_webrtc_with(
            build.lookups,
            build.transports,
            Some(&admission),
        )
        .await?;
        Ok((endpoint, None, webrtc, admission, None, mdns))
    }
}

/// Off a host (a browser): the multihop transport is built when the mesh policy has it and the
/// node has a direct path (`build.multihop`), with the link cost of a browser, so that routes
/// avoid it as a hop; otherwise the endpoint is the plain peer one. The underlay has no IP
/// sockets, and rides WebRTC and the relay.
#[cfg(not(feature = "host"))]
async fn build_member_endpoint(
    build: &SetupBuild<'_>,
) -> Result<(
    Endpoint,
    MultihopSlot,
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    crate::transport::SignalAdmission,
    UnderlaySlot,
    Option<crate::lookup::MdnsHandle>,
)> {
    if let Some(injected) = build.injected.as_ref() {
        // A browser has no multi-hop underlay, so a multihop handle that the caller
        // passed is ignored here, and the endpoint is used as it is.
        crate::lookup::check_injected_against_mesh(
            &injected.endpoint,
            false,
            build.lookups,
            build.relay_transport.relay_allowed(),
        )?;
        return Ok((
            injected.endpoint.clone(),
            None,
            injected.webrtc.clone(),
            injected.admission.clone(),
            None,
            injected.mdns,
        ));
    }
    let admission = crate::transport::SignalAdmission::new(build.max_direct);
    #[cfg(feature = "multihop")]
    if build.multihop {
        let (endpoint, handle, webrtc, underlay_webrtc, mdns) = build_peer_multihop_with(
            build.lookups,
            build.transports,
            Some(&admission),
            crate::lookup::browser_handle_config(build.relay_transport),
            crate::lookup::underlay_cap(build.max_peers),
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
        crate::lookup::build_peer_webrtc_with(build.lookups, build.transports, Some(&admission))
            .await?;
    Ok((endpoint, None, webrtc, admission, None, mdns))
}

/// An endpoint the caller already built, shared with the mesh.
///
/// Lets one process run an application protocol and a mesh node on **one**
/// identity instead of two. Without it a process that does both appears on the
/// network as two unrelated peers — which, among other things, makes any
/// per-peer count wrong: the same machine is reachable twice and there is
/// nothing to deduplicate on.
///
/// The fields are private, so [`InjectedEndpoint::bind`] is the only way to make
/// one. It installs the transports and binds the endpoint in one step, and the
/// connection hook reports to the admission table that it makes. The mesh checks
/// the rest when it is set up, because only then is the mesh known. The
/// `LookupOpts` given to `bind` must also match the ones the mesh id derives, or
/// the relay-direct rendezvous dial has no rung to ride.
///
/// A literal does not compile outside this module:
///
/// ```compile_fail,E0451
/// # use habilis_network::runtime::InjectedEndpoint;
/// # fn literal() -> InjectedEndpoint {
/// InjectedEndpoint { ..todo!() }
/// # }
/// ```
///
/// The constructor is the one that compiles:
///
/// ```no_run
/// # use habilis_network::net::TransportHandles;
/// # use habilis_network::runtime::InjectedEndpoint;
/// # use habilis_network::protocol::mesh::LookupOpts;
/// # async fn build() -> anyhow::Result<InjectedEndpoint> {
/// let secret = habilis_network::iroh::SecretKey::from_bytes(&[1; 32]);
/// InjectedEndpoint::bind(
///     &LookupOpts::loopback(),
///     secret,
///     Vec::new(),
///     TransportHandles::default(),
///     64,
/// )
/// .await
/// .map_err(anyhow::Error::from)
/// # }
/// ```
pub struct InjectedEndpoint {
    endpoint: Endpoint,
    webrtc: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    /// The multi-hop handle the endpoint was built with. `None` leaves this
    /// node without multi-hop, whatever the mesh policy allows: a transport
    /// cannot be added to an endpoint that is already bound. Only the host branch of
    /// `build_member_endpoint` reads it, so a browser build does not keep it.
    #[cfg(all(feature = "multihop", feature = "host"))]
    multihop: Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    /// The admission table the endpoint's connection hook reports to. The mesh
    /// enforces its direct-peer cap on this table, so a table made elsewhere would
    /// get no report from the hook.
    admission: crate::transport::SignalAdmission,
    /// The handle of the mDNS address lookup of the endpoint, when `bind` wired one.
    /// The mesh hears the other members of its mesh on the LAN through it, and marks
    /// the endpoint as a member in the record it announces.
    mdns: Option<crate::lookup::MdnsHandle>,
}

impl InjectedEndpoint {
    /// Binds an endpoint on `secret` with the transports of `transports`, and
    /// makes the admission table that its connection hook reports to.
    ///
    /// The keys of the handles are checked before anything is bound, so a
    /// refused handle is not spent on an endpoint. `max_direct` is the ceiling of
    /// direct connections, as in [`SetupParams::max_direct`].
    ///
    /// # Errors
    /// `transports` has no WebRTC handle, or it already has an admission table
    /// (this method makes the one). A handle was made from a key other than the one
    /// that `secret` derives, or the endpoint does not bind.
    pub async fn bind(
        lookups: &LookupOpts,
        secret: iroh::SecretKey,
        alpns: Vec<Vec<u8>>,
        transports: crate::lookup::TransportHandles,
        max_direct: usize,
    ) -> Result<Self, SetupError> {
        Self::bind_checked(lookups, secret, alpns, transports, max_direct)
            .await
            .map_err(SetupError::internal)
    }

    async fn bind_checked(
        lookups: &LookupOpts,
        secret: iroh::SecretKey,
        alpns: Vec<Vec<u8>>,
        mut transports: crate::lookup::TransportHandles,
        max_direct: usize,
    ) -> Result<Self> {
        anyhow::ensure!(
            transports.admission.is_none(),
            "an injected endpoint makes its own admission table: pass `max_direct`, not a table"
        );
        let webrtc = transports
            .webrtc
            .clone()
            .ok_or_else(|| anyhow::anyhow!("an injected endpoint needs a WebRTC transport"))?;
        let bound = secret.public();
        check_webrtc_key(bound, &webrtc)?;
        #[cfg(feature = "multihop")]
        check_hop_key(bound, transports.multihop.as_ref())?;
        let admission = crate::transport::SignalAdmission::new(max_direct);
        transports.admission = Some(admission.clone());
        #[cfg(all(feature = "multihop", feature = "host"))]
        let multihop = transports.multihop.clone();
        let (endpoint, mdns) = crate::lookup::build_endpoint_keeping_mdns(
            lookups,
            Some(secret),
            None,
            alpns,
            transports,
        )
        .await?;
        Ok(Self {
            endpoint,
            webrtc,
            #[cfg(all(feature = "multihop", feature = "host"))]
            multihop,
            admission,
            mdns,
        })
    }
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

impl InjectedEndpoint {
    /// A copy of the mDNS handle. Where mDNS is compiled in the handle is a clonable lookup, and
    /// where it is not the handle is `Infallible`, which is `Copy`: one `clone` call cannot suit
    /// both builds.
    #[cfg(all(feature = "host", feature = "mdns"))]
    fn mdns_handle(&self) -> Option<crate::lookup::MdnsHandle> {
        self.mdns.clone()
    }

    #[cfg(all(feature = "host", not(feature = "mdns")))]
    fn mdns_handle(&self) -> Option<crate::lookup::MdnsHandle> {
        self.mdns
    }
}

impl std::fmt::Debug for InjectedEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InjectedEndpoint")
            .field("id", &self.endpoint.id())
            .finish_non_exhaustive()
    }
}

/// The per-session inputs to [`setup_mesh`] that are independent of the
/// [`SetupKind`]: this member's identity/io/tuning and the localhost
/// binding request. Bundled so the one-shot assembly stays within the
/// argument budget.
#[non_exhaustive]
pub struct SetupParams {
    /// This member's nickname, the author of every message it sends.
    pub author: Nickname,
    /// G: the gossip active-view cap. `0` takes `tuning::GOSSIP_ACTIVE_VIEW_CAPACITY`.
    pub max_peers: usize,
    /// C: the ceiling of direct connections. `0` takes [`crate::transport::MAX_DIRECT_PEERS`].
    pub max_direct: usize,
    /// The consumer's per-user runtime base (see
    /// [`runtime_base`](crate::util::runtime_base)) — the root the socket, the
    /// default state file, and the default log dir live under. Supplied rather
    /// than derived: the engine is embedded by more than one binary and must not
    /// claim a `/tmp` path under any single one's name. `None` for an embedder
    /// that writes no files and binds no control socket.
    pub runtime_base: Option<PathBuf>,
    /// Where the daemon writes its identity and readiness JSON. `None` writes none.
    pub state_file: Option<PathBuf>,
    /// Where the node emits its events (`NodeEvent`).
    pub sink: std::sync::Arc<dyn NodeSink>,
    /// Share the caller's endpoint instead of minting one. `None` ⇒ the mesh
    /// builds its own, which is right for a standalone peer and wrong for a
    /// process that also speaks its own protocol.
    pub endpoint: Option<InjectedEndpoint>,
    /// ALPNs the caller wants served on the mesh's Router.
    ///
    /// Required rather than optional when sharing an endpoint: `Router::spawn`
    /// *overrides* the endpoint's ALPN list, and two `accept()` loops on one
    /// endpoint race for the same queue. One Router owns accept; everything
    /// else registers here.
    pub protocols: Vec<(Vec<u8>, Box<dyn iroh::protocol::DynProtocolHandler>)>,
    /// This node's own paths, narrowed to the mesh's list in `setup_mesh`.
    /// The shipped surfaces pass the default. Narrowing it by hand is the test
    /// harness's lever to force a relay-only path. Never part of the mesh id —
    /// see the type.
    pub transports: crate::lookup::TransportOpts,
    /// The `meta` channel's per-peer write gate, when the application keeps a
    /// per-peer map there (see [`crate::doc::SelfWriteGate`]). `None` leaves the
    /// channel free-form.
    pub per_peer_gate: Option<crate::doc::SelfWriteGate>,
    /// Override the co-host policy the [`SetupKind`] would imply. `None` keeps
    /// the derived one; a directory session passes its own (see
    /// [`DIRECTORY_ADVERTISER_COHOST`](super::config::DIRECTORY_ADVERTISER_COHOST)).
    pub cohost: Option<CoHostPolicy>,
    /// The shared live-peer counter a directory advertiser re-broadcasts from.
    /// Supplied up front rather than patched onto the returned config, so the
    /// config is complete the moment it exists.
    pub live_count: Option<std::sync::Arc<atomic::AtomicUsize>>,
}

impl SetupParams {
    /// The params of one member with every other field at its default: the engine's own caps, no
    /// runtime files, no shared endpoint, no ALPNs, and the default transports.
    #[must_use]
    pub fn new(author: Nickname, sink: std::sync::Arc<dyn NodeSink>) -> Self {
        Self {
            author,
            max_peers: 0,
            max_direct: 0,
            runtime_base: None,
            state_file: None,
            sink,
            endpoint: None,
            protocols: Vec::new(),
            transports: crate::lookup::TransportOpts::default(),
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        }
    }

    /// Set the ceiling of peers in the mesh.
    #[must_use]
    pub fn with_max_peers(self, max_peers: usize) -> Self {
        Self { max_peers, ..self }
    }

    /// Set the ceiling of direct connections.
    #[must_use]
    pub fn with_max_direct(self, max_direct: usize) -> Self {
        Self { max_direct, ..self }
    }

    /// Set the per-user runtime base.
    #[must_use]
    pub fn with_runtime_base(self, runtime_base: PathBuf) -> Self {
        Self {
            runtime_base: Some(runtime_base),
            ..self
        }
    }

    /// Set the default state file.
    #[must_use]
    pub fn with_state_file(self, state_file: PathBuf) -> Self {
        Self {
            state_file: Some(state_file),
            ..self
        }
    }

    /// Share the caller's endpoint instead of minting one.
    #[must_use]
    pub fn with_endpoint(self, endpoint: InjectedEndpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
            ..self
        }
    }

    /// Serve these ALPNs on the mesh's Router.
    #[must_use]
    pub fn with_protocols(
        self,
        protocols: Vec<(Vec<u8>, Box<dyn iroh::protocol::DynProtocolHandler>)>,
    ) -> Self {
        Self { protocols, ..self }
    }

    /// Narrow this node's own paths.
    #[must_use]
    pub fn with_transports(self, transports: crate::lookup::TransportOpts) -> Self {
        Self { transports, ..self }
    }

    /// Set the `meta` channel's per-peer write gate.
    #[must_use]
    pub fn with_per_peer_gate(self, per_peer_gate: crate::doc::SelfWriteGate) -> Self {
        Self {
            per_peer_gate: Some(per_peer_gate),
            ..self
        }
    }

    /// Override the co-host policy the [`SetupKind`] would imply.
    #[must_use]
    pub fn with_cohost(self, cohost: CoHostPolicy) -> Self {
        Self {
            cohost: Some(cohost),
            ..self
        }
    }

    /// Set the shared live-peer counter a directory advertiser re-broadcasts from.
    #[must_use]
    pub fn with_live_count(self, live_count: std::sync::Arc<atomic::AtomicUsize>) -> Self {
        Self {
            live_count: Some(live_count),
            ..self
        }
    }
}

impl std::fmt::Debug for SetupParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupParams").finish_non_exhaustive()
    }
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
    transports: crate::lookup::TransportOpts,
    policy: crate::protocol::TransportPolicy,
) -> Result<crate::lookup::TransportOpts> {
    let transports = transports.within(&policy);
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
fn reaches_relay(lookups: &LookupOpts, transports: crate::lookup::TransportOpts) -> bool {
    lookups.relay_lookup != RelayChoice::Disabled && transports.relay
}

/// Whether a browser, which has no UDP, can run with these lookups and paths
/// (already narrowed to `policy`).
///
/// # Errors
/// A browser that cannot reach the relay (`reaches_relay`). Or a list that
/// leaves both the data channel and relay payload out: nothing could carry
/// its payload.
pub fn refuse_in_browser(
    lookups: &LookupOpts,
    policy: crate::protocol::TransportPolicy,
    transports: crate::lookup::TransportOpts,
) -> Result<(), SetupError> {
    refuse_in_browser_checked(lookups, policy, transports).map_err(SetupError::internal)
}

fn refuse_in_browser_checked(
    lookups: &LookupOpts,
    policy: crate::protocol::TransportPolicy,
    transports: crate::lookup::TransportOpts,
) -> Result<()> {
    anyhow::ensure!(
        reaches_relay(lookups, transports),
        BROWSER_NEEDS_RELAY_LOOKUP
    );
    anyhow::ensure!(transports.carry_without_udp(&policy), BROWSER_HAS_NO_PATH);
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
    unicast_acceptor: &'build crate::transport::UnicastAcceptor,
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
    transports: crate::lookup::TransportOpts,
    injected: Option<InjectedEndpoint>,
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
    protocols: std::sync::Mutex<CallerProtocols>,
    rung_tx: &'build watch::Sender<Option<RelayUrl>>,
    /// The mesh's `transport.relay_transport`, for the accept gates.
    relay_transport: crate::transport::PayloadPath,
}

impl SetupBuild<'_> {
    /// Move the caller's ALPN handlers out, leaving the slot empty. Called
    /// exactly once, by whichever of create/join runs.
    fn take_protocols(&self) -> CallerProtocols {
        std::mem::take(
            &mut *self
                .protocols
                .lock()
                .expect("nothing panics while holding the protocols lock"),
        )
    }
}

/// The ALPN handlers a caller registers on the mesh's Router.
type CallerProtocols = Vec<(Vec<u8>, Box<dyn iroh::protocol::DynProtocolHandler>)>;

/// The freshly-assembled mesh handles a [`SetupKind`] arm produces.
struct Assembled {
    mesh_id: MeshId,
    mesh_name: MeshName,
    endpoint: Endpoint,
    router: iroh::protocol::Router,
    gossip: iroh_gossip::net::Gossip,
    topic: iroh_gossip::api::GossipTopic,
    rdv: RendezvousParams,
    cohost: CoHostPolicy,
    /// The raw mesh password (passworded mesh) — retained so the daemon can
    /// key blob tickets with it. `None` when passwordless.
    mesh_password: Option<Password>,
    /// The Argon2id-stretched mesh key — retained to derive the state/meta/
    /// broadcast content-encryption keys. `None` when passwordless. Wiped on drop.
    mesh_key: Option<crate::protocol::SymmetricKey>,
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
    lan_contacts: Option<mpsc::Receiver<crate::lookup::LanEvent>>,
    /// This peer's `WebRTC` transport handle, threaded into `EventLoopState` so
    /// the session manager can negotiate with peers as it learns of them, and
    /// so a consumer can read its live direct-peer count.
    webrtc: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    /// The negotiation-slot table the Router's signal acceptor was built with.
    /// Threaded on so `EventLoopState` gets the *same* one — the dialing side
    /// and the answering side must share a ceiling, or neither enforces it.
    webrtc_admission: crate::transport::SignalAdmission,
    /// The address book of the member endpoint: the one place its peers' addresses are registered.
    address_book: memory::MemoryLookup,
    /// How far ICE may reach — host-only on a loopback mesh. Derived from the
    /// mesh's own lookups, so it cannot disagree with them.
    webrtc_ice: crate::transport::IceProfile,
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
            crate::transport::MAX_DIRECT_PEERS
        } else {
            max_direct
        },
    )
}

/// # Errors
/// The join target fails to resolve, the password fails to verify, or the
/// endpoint cannot bind.
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

#[expect(
    clippy::too_many_lines,
    reason = "the one-shot assembly of a member: each step is a single call or a literal of the loop config, and splitting it would only scatter sequential setup across helpers"
)]
async fn setup_mesh_inner(kind: SetupKind, params: SetupParams) -> Result<EventLoopConfig> {
    let SetupParams {
        author,
        max_peers,
        max_direct,
        runtime_base,
        state_file,
        sink,
        cohost: cohost_override,
        live_count,
        endpoint: injected,
        protocols,
        transports,
        per_peer_gate,
    } = params;
    let endpoint_owner = if injected.is_none() {
        EndpointOwner::Engine
    } else {
        EndpointOwner::Caller
    };
    let (max_peers, max_direct) = resolve_caps(max_peers, max_direct);
    // The localhost binding is owned + bound by the caller; the engine only needs
    // the resolved port for the `ready` event. `Some(0)` (ephemeral) is resolved
    // caller-side and passed back in here as the real port.
    // Create mints the config from the caller's choices; join decodes it
    // from the id — one source of truth either way.
    let mesh_config = match &kind {
        SetupKind::Create { config, .. } => config,
        SetupKind::Join { mesh, .. } | SetupKind::Topic { mesh, .. } => mesh.config(),
    };
    // Decode already validated a joined id; a minted config has had no check
    // yet, and an invalid one would produce an id every joiner rejects.
    mesh_config.validate()?;
    let lookups = mesh_config.lookups.clone();
    let relay_transport =
        crate::transport::PayloadPath::from(mesh_config.transport.relay_transport);
    let transports = member_transports(&lookups, transports, mesh_config.transport)?;
    // The mesh policy's `multihop`, on a node that has a direct path for its underlay to
    // forward over: UDP, or a WebRTC data channel when IP is cleared. With neither there is
    // no direct path, and no handle.
    let multihop = mesh_config.transport.multihop && (transports.udp || transports.webrtc);

    // The off-loop rung channel: the backgrounded startup probe and the
    // beacon's liveness self-monitor publish a chosen rung here; the
    // event loop applies it (re-register + re-home) without ever running
    // a ladder walk on the sole loop. Initialized to the optimistic
    // rung 0 (empty ladder ⇒ `None`).
    let ladder = relay_ladder(&lookups.relay_lookup);
    let (rung_tx, rung_rx) = watch::channel(ladder.first().cloned());

    let (unicast_rx, unicast_acceptor) = unicast_inbox(relay_transport);

    // This member's per-author signing identity. Hoisted above the match so it is
    // available to both attach paths.
    let identity = std::sync::Arc::new(identity::Identity::generate());

    let build = SetupBuild {
        author: &author,
        sink: sink.as_ref(),
        max_peers,
        max_direct,
        lookups: &lookups,
        unicast_acceptor: &unicast_acceptor,
        multihop,
        transports,
        injected,
        protocols: std::sync::Mutex::new(protocols),
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
    } = match kind {
        SetupKind::Create {
            name,
            config,
            advertise,
            password,
            invite_only,
        } => {
            setup_create(
                &build,
                CreateSetup {
                    name,
                    config,
                    advertise,
                    password,
                    invite_only,
                },
            )
            .await?
        }
        kind @ (SetupKind::Join { .. } | SetupKind::Topic { .. }) => {
            setup_join(&build, kind).await?
        }
    };

    // Read out of `build` before anything below moves what it borrows
    // (`author`, `sink`, `rung_tx`).

    // Off the critical path: nothing below blocks `ready`, which `run` emits
    // once the IPC socket accepts. Confirm/correct the optimistic rung 0 in the
    // background (covers a joiner, which has no beacon self-monitor of its own).
    let rung_probe = spawn_startup_rung_confirmation(ladder, rung_tx);

    Ok(EventLoopConfig {
        per_peer_gate,
        topic,
        gossip,
        author,
        identity,
        mesh: mesh_id,
        name: mesh_name,
        topic_string,
        mesh_password,
        mesh_key,
        sink,
        mint_mesh,
        endpoint,
        endpoint_owner,
        router,
        max_peers,
        rendezvous_params: rdv,
        rung_rx,
        rung_probe,
        cohost: cohost_override.unwrap_or(cohost),
        runtime_base,
        state_file,
        #[cfg(feature = "multihop")]
        multihop: multihop_handle,
        #[cfg(feature = "multihop")]
        underlay_webrtc,
        lan_contacts,
        webrtc,
        webrtc_enabled: transports.webrtc,
        local_udp_transport: UdpTransport::from(transports.udp),
        webrtc_admission,
        address_book,
        webrtc_ice,
        unicast_rx,
        live_count,
        relay_transport,
        // Default to the CLI driver; the in-process sessions
        // overwrite `cfg.driver` before handing it to `daemon::run`.
        driver: DriverMode::Cli,
        #[cfg(feature = "host")]
        owner: None,
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
    admission: crate::transport::SignalAdmission,
) -> (
    iroh_gossip::net::Gossip,
    iroh::protocol::Router,
    crate::transport::SignalAdmission,
    memory::MemoryLookup,
    crate::transport::IceProfile,
) {
    let ice = crate::transport::IceProfile {
        host_only: mesh.is_loopback(),
    };
    let (gossip, router, address_book) = build_mesh(
        endpoint.clone(),
        build.max_peers,
        Some(
            build
                .unicast_acceptor
                .clone()
                .with_admission(admission.clone()),
        ),
        build
            .transports
            .webrtc
            .then(|| (webrtc.clone(), admission.clone(), ice)),
        build.take_protocols(),
        build.relay_transport.relay_allowed(),
        webrtc::local_needs_webrtc_lane(UdpTransport::from(build.transports.udp)),
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
async fn setup_create(build: &SetupBuild<'_>, create: CreateSetup) -> Result<Assembled> {
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
        build_member_endpoint(build).await?;

    let mut mesh = Mesh::try_new(
        crate::protocol::Seed::from_bytes(seed),
        name.clone(),
        config,
    )?;
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
            tokio::task::spawn_blocking(move || {
                let mut mesh = mesh;
                mesh.set_password(&password);
                (mesh, Some(password))
            })
            .await?
        }
        #[cfg(not(feature = "host"))]
        (Some(password), false) => {
            let mut mesh = mesh;
            mesh.set_password(&password);
            (mesh, Some(password))
        }
        (password, _) => (mesh, password),
    };
    let mesh_key = mesh.mesh_key();
    // The creator alone retains its full mesh (issuer key + root) to mint from.
    let mint_mesh = mesh.requires_invite().then(|| mesh.clone());
    let id_str = mesh.to_string();
    let mesh_id =
        MeshId::try_new(id_str.clone()).expect("Mesh::to_string always produces a valid MeshId");

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
    let topic_id = iroh_gossip::proto::TopicId::from_bytes(mesh.topic_id().to_bytes());
    let lan_contacts = crate::lookup::lan_contacts(&endpoint, mdns, &topic_id).await?;
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

    register_rendezvous(&address_book, &rdv, &crate::beacon::busy_rungs(&rdv));

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
async fn setup_join(build: &SetupBuild<'_>, kind: SetupKind) -> Result<Assembled> {
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
    let mesh_id =
        MeshId::try_new(id_str.clone()).expect("Mesh::to_string always produces a valid MeshId");
    // The one place the protocol's byte-shaped TopicId becomes iroh-gossip's.
    // Keeping the conversion here is what lets habilis-network-protocol build
    // without iroh-gossip at all (see habilis_network_protocol::topic).
    let topic_id = iroh_gossip::proto::TopicId::from_bytes(mesh.topic_id().to_bytes());

    #[cfg_attr(
        not(feature = "multihop"),
        expect(
            unused_variables,
            reason = "no multihop handle without the `multihop` feature — see `build_member_endpoint`"
        )
    )]
    let (endpoint, multihop, webrtc, admission, underlay_webrtc, mdns) =
        build_member_endpoint(build).await?;

    let lan_contacts = crate::lookup::lan_contacts(&endpoint, mdns, &topic_id).await?;
    let rdv = rendezvous_params(&mesh, topic_id, build.lookups, build.rung_tx.clone());
    let (gossip, router, webrtc_admission, address_book, webrtc_ice) =
        build_overlay(build, &mesh, &endpoint, &webrtc, admission);
    // Must precede the join (the subscribe below): the peer resolves the rendezvous id via
    // this registered address — the loopback port ladder (loopback-only) or
    // the chosen relay rung (reachable across machines).
    let read = crate::beacon::read_busy_rungs(&rdv, SETUP_RUNG_READ).await;
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
    // `transport::webrtc::rendezvous_graftable`); the heal tick grafts once
    // it is attached.
    let needs_session = webrtc::node_graft_needs_session(
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
    use crate::daemon::node::SignalHandling;
    use crate::transport::PayloadPath;
    /// A walking member keeps only the rung read as ours; the `discover` session, which never
    /// walks, leaves out only a rung read as foreign: a silent or refusing one may be its beacon.
    #[test]
    fn what_a_member_leaves_out_at_setup_follows_its_walk() {
        use super::{CoHostPolicy, ProbeAnswer, rungs_withheld_at_setup};

        let read = [
            (4161, ProbeAnswer::Foreign),
            (5511, ProbeAnswer::Refused),
            (8450, ProbeAnswer::NoAnswer),
            (11743, ProbeAnswer::Ours),
        ];
        assert_eq!(
            rungs_withheld_at_setup(CoHostPolicy::Never, &read),
            vec![4161]
        );
        assert_eq!(
            rungs_withheld_at_setup(CoHostPolicy::Deferred, &read),
            vec![4161, 5511, 8450]
        );
        assert_eq!(
            rungs_withheld_at_setup(CoHostPolicy::Eager, &read),
            vec![4161, 5511, 8450]
        );
    }

    use habilis_network_test_tracing::test;
    use std::time::Duration;

    use crate::protocol::mesh::{LookupOpts, RelayChoice, Transport, TransportPolicy};

    // A browser has no UDP: it reaches a peer only through the relay, and a
    // data channel's handshake crosses the relay too. `validate` accepts
    // `udp,webrtc` with no relay lookup, because a native node can signal
    // over UDP.
    use crate::daemon::node;
    use crate::lookup::test_relay;
    use crate::protocol::mesh::Lookup;
    use crate::util::tuning;
    use tokio::sync::mpsc;
    #[test]
    fn a_browser_refuses_a_mesh_with_no_relay_lookup() {
        let dht_only = LookupOpts::new(RelayChoice::Disabled).with_dht(true);
        let policy =
            TransportPolicy::from_transports(&[Transport::Udp, Transport::WebRtc]).expect("valid");
        let transports = crate::lookup::TransportOpts::default().within(&policy);
        let error = super::refuse_in_browser(&dht_only, policy, transports)
            .expect_err("no path to signal on");
        assert_eq!(error.to_string(), super::BROWSER_NEEDS_RELAY_LOOKUP);

        let relay = LookupOpts::new(RelayChoice::Pinned)
            .with_mdns(dht_only.mdns)
            .with_dht(dht_only.dht);
        super::refuse_in_browser(&relay, policy, transports).expect("the relay signals");
    }

    // A native node without UDP signals its data channel over the relay, as a
    // browser does. `validate` checks the mesh's list, not this node's own
    // narrower paths.
    #[test]
    fn a_node_without_udp_refuses_a_mesh_with_no_relay_lookup() {
        let dht_only = LookupOpts::new(RelayChoice::Disabled).with_dht(true);
        let policy =
            TransportPolicy::from_transports(&[Transport::Udp, Transport::WebRtc]).expect("valid");
        let webrtc_only = crate::lookup::TransportOpts::webrtc_only();
        super::member_transports(&dht_only, webrtc_only, policy).expect_err("no path to signal on");
        let relay = LookupOpts::new(RelayChoice::Pinned)
            .with_mdns(dht_only.mdns)
            .with_dht(dht_only.dht);
        super::member_transports(&relay, webrtc_only, policy).expect("the relay signals");
    }

    // The relay lookup names a relay, but only this node's relay transport
    // can dial it: without one, a browser neither signals nor carries relay
    // payload.
    #[test]
    fn a_browser_refuses_a_node_with_no_relay_transport() {
        let lookups = LookupOpts::new(RelayChoice::Pinned);
        let no_relay = |policy: &TransportPolicy| crate::lookup::TransportOpts {
            relay: false,
            ..crate::lookup::TransportOpts::default().within(policy)
        };
        let webrtc =
            TransportPolicy::from_transports(&[Transport::Udp, Transport::WebRtc]).expect("valid");
        drop(
            super::refuse_in_browser(&lookups, webrtc, no_relay(&webrtc))
                .expect_err("no relay to signal on"),
        );
        let relay_payload =
            TransportPolicy::from_transports(&[Transport::Udp, Transport::Relay]).expect("valid");
        drop(
            super::refuse_in_browser(&lookups, relay_payload, no_relay(&relay_payload))
                .expect_err("no relay to carry payload"),
        );
    }

    use tokio::sync::watch;

    use crate::testing::{errors_through_runtime_drop, silent_relay_rung};

    // The mesh policy decides multi-hop: the default list has it, a list that
    // leaves it out has none, and no flag says otherwise.
    #[test]
    async fn multihop_follows_the_mesh_policy() {
        for (list, expected) in [
            (vec![], true),
            (vec![Transport::Udp, Transport::WebRtc], false),
            (vec![Transport::Udp, Transport::Multihop], true),
        ] {
            let opts = crate::membership::Opts {
                transport: list.clone(),
                ..crate::membership::Opts::default()
            };
            let (kind, author) = crate::membership::resolve_kind(&opts, None).expect("a kind");
            let config = super::setup_mesh(
                kind,
                super::SetupParams::new(author, std::sync::Arc::new(crate::embed::SilentSink))
                    .with_max_peers(8),
            )
            .await
            .expect("a loopback mesh sets up");
            assert_eq!(config.multihop.is_some(), expected, "{list:?}");
            config.router.shutdown().await.expect("the router stops");
            if let Some(handle) = config.multihop.as_ref() {
                handle.close().await;
            }
        }
    }

    // A node without UDP takes part in multihop when the policy has it: the rule is that
    // a direct path exists, `udp` or `webrtc`, and not `udp` alone. With neither, the
    // underlay has no direct path to forward over, and there is no handle. A node may run with
    // fewer transports than the policy names, which is how a list with `webrtc` and `multihop`
    // meets a node that has no `udp`.
    #[test]
    async fn a_member_without_udp_gets_a_multihop_handle_when_it_has_webrtc() {
        let (relay_url, _relay) = test_relay::spawn_plain().await.expect("a local relay");
        for (transports, expected) in [
            (
                crate::lookup::TransportOpts {
                    udp: false,
                    ..crate::lookup::TransportOpts::default()
                },
                true,
            ),
            (
                crate::lookup::TransportOpts {
                    udp: false,
                    webrtc: false,
                    ..crate::lookup::TransportOpts::default()
                },
                false,
            ),
        ] {
            // A node without UDP needs the relay: it carries the offers of its data channels.
            let opts = crate::membership::Opts {
                transport: vec![Transport::WebRtc, Transport::Multihop],
                lookup: vec![Lookup::Relay],
                relay_urls: vec![relay_url.to_string()],
                ..crate::membership::Opts::default()
            };
            let (kind, author) = crate::membership::resolve_kind(&opts, None).expect("a kind");
            let config = super::setup_mesh(
                kind,
                super::SetupParams::new(author, std::sync::Arc::new(crate::embed::SilentSink))
                    .with_max_peers(8)
                    .with_transports(transports),
            )
            .await
            .expect("a mesh sets up");
            assert_eq!(config.multihop.is_some(), expected, "{transports:?}");
            if let Some(handle) = config.multihop.as_ref() {
                assert_eq!(handle.link_cost(), 10, "{transports:?}");
            }
            // Leave closes what setup bound, the endpoint, the underlay and the leg.
            leave_and_keep_handles(config).await;
        }
    }

    // A node run without `udp` has no IP on any of its endpoints. Its underlay rides WebRTC and
    // the relay: it has no IP socket, and it has the WebRTC leg that carries its cells.
    #[test]
    async fn the_underlay_of_a_member_without_udp_has_no_ip_socket_and_has_a_webrtc_leg() {
        let (relay_url, _relay) = test_relay::spawn_plain().await.expect("a local relay");
        let opts = crate::membership::Opts {
            transport: vec![Transport::WebRtc, Transport::Multihop],
            lookup: vec![Lookup::Relay],
            relay_urls: vec![relay_url.to_string()],
            ..crate::membership::Opts::default()
        };
        let (kind, author) = crate::membership::resolve_kind(&opts, None).expect("a kind");
        let config = super::setup_mesh(
            kind,
            super::SetupParams::new(author, std::sync::Arc::new(crate::embed::SilentSink))
                .with_max_peers(8)
                .with_transports(crate::lookup::TransportOpts {
                    udp: false,
                    ..crate::lookup::TransportOpts::default()
                }),
        )
        .await
        .expect("a mesh sets up");
        let leg = config
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
    }

    // G and C come from the caller, and `0` takes the default. Every option set
    // (`Opts`, the C struct, the browser object) ends in `setup_mesh`, so this is
    // the one place that has to hold.
    #[test]
    async fn the_caps_follow_the_params_and_zero_takes_the_default() {
        use crate::transport::MAX_DIRECT_PEERS;
        use crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY;

        for (max_peers, max_direct, want_g, want_c) in [
            (0, 0, GOSSIP_ACTIVE_VIEW_CAPACITY, MAX_DIRECT_PEERS),
            (5, 3, 5, 3),
        ] {
            let opts = crate::membership::Opts::default();
            let (kind, author) = crate::membership::resolve_kind(&opts, None).expect("a kind");
            let config = super::setup_mesh(
                kind,
                super::SetupParams::new(author, std::sync::Arc::new(crate::embed::SilentSink))
                    .with_max_peers(max_peers)
                    .with_max_direct(max_direct),
            )
            .await
            .expect("a loopback mesh sets up");
            assert_eq!(config.max_peers, want_g, "G for {max_peers}");
            assert_eq!(config.webrtc_admission.cap(), want_c, "C for {max_direct}");
            config.router.shutdown().await.expect("the router stops");
            if let Some(handle) = config.multihop.as_ref() {
                handle.close().await;
            }
        }
    }

    // The defaults of the two bounds: G is 32 gossip neighbors, and C (decision D11) is 64
    // direct peers, counting `WebRTC` sessions and unicast connections.
    #[test]
    fn the_default_bounds_are_32_neighbors_and_64_direct_peers() {
        assert_eq!(tuning::GOSSIP_ACTIVE_VIEW_CAPACITY, 32);
        assert_eq!(crate::transport::MAX_DIRECT_PEERS, 64);
    }

    /// A multihop handle on `secret`, with its underlay on the key that the handle derives.
    async fn multihop_on(
        secret: &iroh::SecretKey,
        relay_payload: PayloadPath,
    ) -> habilis_network_iroh_multihop_transport::MultihopHandle {
        use habilis_network_iroh_multihop_transport::{MultihopHandle, underlay_secret};
        use iroh::endpoint::presets;

        let underlay = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(underlay_secret(secret))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind an underlay");
        MultihopHandle::new(
            secret,
            underlay,
            crate::lookup::multihop_handle_config(relay_payload),
        )
        .expect("underlay on the derived key")
    }

    /// An endpoint a caller built to inject: the engine's wiring, a multihop
    /// handle with `relay_payload`, and one key.
    async fn injected(relay_payload: PayloadPath) -> super::InjectedEndpoint {
        let secret = iroh::SecretKey::from_bytes(&[91; 32]);
        let webrtc = crate::lookup::new_webrtc_handle(secret.public());
        let handle = multihop_on(&secret, relay_payload).await;
        super::InjectedEndpoint::bind(
            &LookupOpts::loopback(),
            secret,
            Vec::new(),
            crate::lookup::TransportHandles {
                multihop: Some(handle),
                webrtc: Some(webrtc),
                gossip: None,
                admission: None,
                underlay: false,
                opts: crate::lookup::TransportOpts::default(),
            },
            crate::transport::MAX_DIRECT_PEERS,
        )
        .await
        .expect("the injected endpoint binds")
    }

    /// A handle made from a key other than the one the endpoint binds is refused
    /// by `bind`, both for the WebRTC transport and for the multihop handle.
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
                crate::lookup::TransportHandles {
                    multihop,
                    webrtc,
                    gossip: None,
                    admission: None,
                    underlay: false,
                    opts: crate::lookup::TransportOpts::default(),
                },
                crate::transport::MAX_DIRECT_PEERS,
            )
        };
        let own_webrtc = crate::lookup::new_webrtc_handle(secret.public());
        let other_webrtc = crate::lookup::new_webrtc_handle(other.public());

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

        let table = crate::transport::SignalAdmission::new(crate::transport::MAX_DIRECT_PEERS);
        let table_error = super::InjectedEndpoint::bind(
            &lookups,
            secret.clone(),
            Vec::new(),
            crate::lookup::TransportHandles {
                webrtc: Some(own_webrtc),
                admission: Some(table),
                ..crate::lookup::TransportHandles::default()
            },
            crate::transport::MAX_DIRECT_PEERS,
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
        const ALPN: &[u8] = crate::transport::UNICAST_ALPN;
        let secret = iroh::SecretKey::from_bytes(&[92; 32]);
        let injected = super::InjectedEndpoint::bind(
            &LookupOpts::loopback(),
            secret.clone(),
            vec![ALPN.to_vec()],
            crate::lookup::TransportHandles {
                webrtc: Some(crate::lookup::new_webrtc_handle(secret.public())),
                ..crate::lookup::TransportHandles::default()
            },
            crate::transport::MAX_DIRECT_PEERS,
        )
        .await
        .expect("the injected endpoint binds");
        assert_eq!(injected.admission.direct_units(), 0, "no peer dialed yet");

        let dialer = crate::lookup::build_peer_endpoint(&LookupOpts::loopback())
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
            tokio::time::sleep(Duration::from_millis(10)).await;
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
        let opts = crate::membership::Opts {
            transport: list,
            ..crate::membership::Opts::default()
        };
        let (kind, author) = crate::membership::resolve_kind(&opts, None)?;
        super::setup_mesh(
            kind,
            super::SetupParams::new(author, std::sync::Arc::new(crate::embed::SilentSink))
                .with_max_peers(8)
                .with_endpoint(injected),
        )
        .await
        .map_err(anyhow::Error::from)
    }

    // An injected endpoint obeys the mesh policy too: a handle on a mesh whose
    // list has no `multihop` is dropped, so it advertises no link-state and takes
    // none in.
    #[test]
    async fn an_injected_multihop_handle_is_dropped_when_the_mesh_has_no_multihop() {
        let first = injected(PayloadPath::DirectOnly).await;
        let (first_endpoint, first_handle) = (first.endpoint.clone(), first.multihop.clone());
        let config = setup_with(vec![Transport::Udp, Transport::WebRtc], first)
            .await
            .expect("a loopback mesh sets up");
        assert!(
            config.multihop.is_none(),
            "no multihop on a udp,webrtc mesh"
        );
        config.router.shutdown().await.expect("the router stops");
        if let Some(handle) = first_handle {
            handle.close().await;
        }
        first_endpoint.close().await;

        let default_list = setup_with(Vec::new(), injected(PayloadPath::DirectOnly).await)
            .await
            .expect("a loopback mesh sets up");
        assert!(default_list.multihop.is_some(), "the default list has it");
        default_list
            .router
            .shutdown()
            .await
            .expect("the router stops");
        if let Some(handle) = default_list.multihop.as_ref() {
            handle.close().await;
        }
    }

    // Whether the relay may carry cells is a rule of the mesh: a handle that lets
    // it, on a lookup-only mesh, is refused.
    #[test]
    async fn an_injected_multihop_handle_that_lets_the_relay_carry_cells_is_refused() {
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
    }

    /// Regression for `Endpoint dropped without calling Endpoint::close` on a
    /// Ctrl-C in the first seconds of a run. The startup probe was detached,
    /// so `Node::leave` had nothing to wait for: `main` returned while the
    /// probe was still waiting for its relay, or still closing, and the runtime
    /// drop took its endpoint down open.
    #[test]
    fn a_departure_during_the_startup_rung_probe_closes_its_endpoint() {
        let (_silent, rung) = silent_relay_rung();

        let errors = errors_through_runtime_drop(async {
            let probe = super::spawn_startup_rung_confirmation(vec![rung], watch::channel(None).0)
                .expect("a ladder to walk");
            // Let the probe bind and start waiting for its relay.
            tokio::time::sleep(Duration::from_millis(200)).await;
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
        let endpoint = config.endpoint.clone();
        let underlay = config.multihop.clone();
        let (inbound_tx, _inbound_rx) = mpsc::channel(1);
        let node = node::Node::spawn(
            config,
            crate::membership::MembershipApp::new(inbound_tx),
            None,
            SignalHandling::Leave,
        );
        node.leave().await.expect("the node leaves");
        (endpoint, underlay)
    }

    // The node closes what its setup bound, so iroh has nothing to log as dropped.
    #[test]
    async fn leave_closes_the_endpoint_and_the_underlay_that_setup_bound() {
        let opts = crate::membership::Opts::default();
        let (kind, author) = crate::membership::resolve_kind(&opts, None).expect("a kind");
        let config = super::setup_mesh(
            kind,
            super::SetupParams::new(author, std::sync::Arc::new(crate::embed::SilentSink))
                .with_max_peers(8),
        )
        .await
        .expect("a loopback mesh sets up");
        let (endpoint, underlay) = leave_and_keep_handles(config).await;
        assert!(endpoint.is_closed(), "the endpoint is closed after leave");
        assert!(
            underlay.expect("the default list has multihop").is_closed(),
            "the underlay is closed after leave"
        );
    }

    // An injected endpoint is the caller's, and it may carry protocols of the caller.
    #[test]
    async fn leave_keeps_an_injected_endpoint_and_its_underlay_open() {
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
    }
}

// The browser build of `build_member_endpoint` is the one that runs without `host`. A native test
// binary built without `host` runs it, with no IP on the node, as a browser would.
#[cfg(all(test, feature = "multihop", not(feature = "host")))]
mod browser_tests {
    use crate::protocol::mesh::{Lookup, Transport};
    use habilis_network_test_tracing::test;

    #[test]
    async fn a_browser_member_has_a_multihop_handle_with_the_link_cost_of_a_browser() {
        let (relay_url, _relay) = crate::lookup::test_relay::spawn_plain()
            .await
            .expect("a local relay");
        let opts = crate::membership::Opts {
            transport: vec![Transport::WebRtc, Transport::Multihop],
            lookup: vec![Lookup::Relay],
            relay_urls: vec![relay_url.to_string()],
            ..crate::membership::Opts::default()
        };
        let (kind, author) = crate::membership::resolve_kind(&opts, None).expect("a kind");
        let mut config = super::setup_mesh(
            kind,
            super::SetupParams::new(author, std::sync::Arc::new(crate::embed::SilentSink))
                .with_max_peers(8)
                .with_transports(crate::lookup::TransportOpts {
                    udp: false,
                    ..crate::lookup::TransportOpts::default()
                }),
        )
        .await
        .expect("a mesh sets up");
        assert_eq!(
            config
                .multihop
                .as_ref()
                .expect("a multihop handle")
                .link_cost(),
            100
        );
        // The router closes the endpoint that it serves on. The handle closes the underlay, the
        // WebRTC leg of the underlay has an endpoint of its own, and so has the startup rung probe.
        if let Some(probe) = config.rung_probe.take() {
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
    }
}
