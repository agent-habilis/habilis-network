use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use iroh::{Endpoint, RelayUrl};
use rand::RngCore;
use tokio::sync::{mpsc, watch};

use crate::gossip::event::{NodeEvent, NodeSink};
#[cfg(feature = "host")]
use crate::lookup::build_peer_multihop;
use crate::lookup::{
    StoppableTask, add_peer_addr, build_mesh, relay_ladder, select_bootstrap_rung,
};
use crate::protocol::crypto::Password;
use crate::protocol::mesh::{LookupOpts, Mesh, MeshConfig, MeshName};
use crate::protocol::{MeshId, Nickname};
use crate::util::tuning::RELAY_RUNG_PROBE_SECS;

use crate::beacon::RendezvousParams;
use crate::lifecycle;

use super::{CoHostPolicy, DriverMode, EventLoopConfig};

/// What kind of mesh we're setting up — either minting a new one
/// (create) or attaching to an existing one (join).
#[derive(Debug)]
pub enum SetupKind {
    Create {
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
    Join {
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
        relay_transport: mesh.config.transport.relay_transport,
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
        let confirmed = select_bootstrap_rung(
            &ladder,
            Duration::from_secs(RELAY_RUNG_PROBE_SECS),
            Some(&stopped),
        )
        .await;
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
pub(crate) fn register_rendezvous(endpoint: &Endpoint, params: &RendezvousParams) {
    // Relay disabled (not in the allowlist) or private without a port ladder:
    // nothing to pre-register — joiners resolve the rendezvous id via
    // mDNS/DHT only.
    let Some(addr) = crate::beacon::rendezvous_addr(params) else {
        return;
    };
    if params.bind_ports.is_empty() {
        tracing::info!(
            target: "fofoca::lookup",
            relay = ?params.bootstrap_relay,
            "pre-registered rendezvous at the relay rung for zero-lookup dial"
        );
    } else {
        // Explicit target: needs RendezvousParams, so can't live in lookups.
        tracing::info!(
            target: "fofoca::lookup",
            rungs = params.bind_ports.len(),
            "pre-registered rendezvous on the loopback port ladder"
        );
    }
    let _ = add_peer_addr(endpoint, addr);
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
    relay_transport: bool,
) -> (
    mpsc::Receiver<bytes::Bytes>,
    crate::transport::UnicastAcceptor,
) {
    let (tx, rx) = mpsc::channel::<bytes::Bytes>(crate::util::consts::UNICAST_INBOX_CAP);
    (
        rx,
        crate::transport::UnicastAcceptor::new(tx, relay_transport),
    )
}

/// Build this member's peer endpoint, registering the multi-hop transport
/// (and standing up its underlay) when `--multihop` is set.
#[cfg(feature = "host")]
async fn build_member_endpoint(
    build: &SetupBuild<'_>,
) -> Result<(
    Endpoint,
    Option<fofoca_iroh_multihop_transport::MultihopHandle>,
    fofoca_iroh_webrtc_transport::WebRtcHandle,
)> {
    if let Some(injected) = build.injected.as_ref() {
        // Shared endpoint: no key to mint, nothing to bind. Multihop is not
        // available on this path — it pins the key for its own hop identity,
        // which is precisely what the caller has already done.
        anyhow::ensure!(
            !build.multihop,
            "multihop cannot share a caller-supplied endpoint: both need to pin the key"
        );
        crate::lookup::check_injected_identity(
            &injected.endpoint,
            &injected.webrtc,
            build.lookups,
        )?;
        return Ok((injected.endpoint.clone(), None, injected.webrtc.clone()));
    }
    if build.multihop {
        // Multihop pins the key for its own hop identity, so it cannot also be
        // the WebRTC transport's endpoint. The two are alternatives today; a
        // peer that wants both needs one key shared between them.
        let (endpoint, handle) = build_peer_multihop(build.lookups).await?;
        let webrtc = crate::lookup::detached_webrtc_handle(endpoint.id());
        Ok((endpoint, Some(handle), webrtc))
    } else {
        let (endpoint, webrtc) =
            crate::lookup::build_peer_webrtc(build.lookups, build.transports).await?;
        Ok((endpoint, None, webrtc))
    }
}

/// Off a host there is no multihop transport to register — it forwards real UDP
/// packets — so the endpoint is always the plain peer one. The `multihop` flag
/// is accepted and ignored rather than removed from `SetupParams`, so a caller
/// compiles unchanged for both targets.
#[cfg(not(feature = "host"))]
async fn build_member_endpoint(
    build: &SetupBuild<'_>,
) -> Result<(
    Endpoint,
    Option<()>,
    fofoca_iroh_webrtc_transport::WebRtcHandle,
)> {
    if let Some(injected) = build.injected.as_ref() {
        crate::lookup::check_injected_identity(
            &injected.endpoint,
            &injected.webrtc,
            build.lookups,
        )?;
        return Ok((injected.endpoint.clone(), None, injected.webrtc.clone()));
    }
    let (endpoint, webrtc) =
        crate::lookup::build_peer_webrtc(build.lookups, build.transports).await?;
    Ok((endpoint, None, webrtc))
}

/// An endpoint the caller already built, shared with the mesh.
///
/// Lets one process run an application protocol and a mesh node on **one**
/// identity instead of two. Without it a process that does both appears on the
/// network as two unrelated peers — which, among other things, makes any
/// per-peer count wrong: the same machine is reachable twice and there is
/// nothing to deduplicate on.
///
/// The endpoint must be built with the `WebRTC` transport already registered from
/// the same key it binds; [`check_injected_identity`](crate::net::check_injected_identity)
/// enforces that. Its `LookupOpts` must also match the ones the mesh id derives,
/// or the relay-direct rendezvous dial has no rung to ride.
pub struct InjectedEndpoint {
    pub endpoint: Endpoint,
    pub webrtc: fofoca_iroh_webrtc_transport::WebRtcHandle,
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
pub struct SetupParams {
    pub author: Nickname,
    pub max_peers: usize,
    /// The consumer's per-user runtime base (see
    /// [`runtime_base`](crate::util::runtime_base)) — the root the socket, the
    /// default state file, and the default log dir live under. Supplied rather
    /// than derived: the engine is embedded by more than one binary and must not
    /// claim a `/tmp` path under any single one's name. `None` for an embedder
    /// that writes no files and binds no control socket.
    pub runtime_base: Option<PathBuf>,
    pub state_file: Option<PathBuf>,
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
    /// Which transports this instance may carry data on. `Default` is
    /// everything; `TransportOpts::webrtc_only()` clears IP so a WebRTC-only
    /// run cannot silently fall back. Never part of the mesh id — see the type.
    pub transports: crate::lookup::TransportOpts,
    /// `--multihop`: register the multi-hop custom transport on the peer
    /// endpoint (a second underlay endpoint is stood up for hop-by-hop
    /// forwarding). Off by default on every path.
    pub multihop: bool,
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
    pub live_count: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl std::fmt::Debug for SetupParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupParams").finish_non_exhaustive()
    }
}

/// The kind-independent build inputs threaded into [`setup_create`] /
/// [`setup_join`]: the loop-shared refs both attach paths need to stand up
/// the endpoint, gossip overlay and rendezvous.
struct SetupBuild<'a> {
    author: &'a Nickname,
    sink: &'a dyn NodeSink,
    max_peers: usize,
    lookups: &'a LookupOpts,
    unicast_acceptor: &'a crate::transport::UnicastAcceptor,
    /// Register the multi-hop transport on the peer endpoint.
    #[cfg_attr(
        not(feature = "host"),
        expect(
            dead_code,
            reason = "accepted and ignored off a host — see `build_member_endpoint`"
        )
    )]
    multihop: bool,
    transports: crate::lookup::TransportOpts,
    injected: Option<InjectedEndpoint>,
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
    rung_tx: &'a watch::Sender<Option<RelayUrl>>,
    /// The mesh's `transport.relay_transport`, for the accept gates.
    relay_transport: bool,
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
    mesh_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// The invite-only creator's mesh (with its in-memory issuer key + root),
    /// retained so `invite` can mint. `Some` only on an invite-only creator.
    mint_mesh: Option<Mesh>,
    /// The multi-hop transport handle when `--multihop` registered it, threaded
    /// into `EventLoopState` so the link-state tick can feed its routing table.
    /// Host-only: the transport forwards real UDP packets, so off a host the
    /// field's own type does not exist.
    #[cfg(feature = "host")]
    multihop: Option<fofoca_iroh_multihop_transport::MultihopHandle>,
    /// This peer's `WebRTC` transport handle, threaded into `EventLoopState` so
    /// the session manager can negotiate with peers as it learns of them, and
    /// so a consumer can read its live direct-peer count.
    webrtc: fofoca_iroh_webrtc_transport::WebRtcHandle,
    /// The negotiation-slot table the Router's signal acceptor was built with.
    /// Threaded on so `EventLoopState` gets the *same* one — the dialing side
    /// and the answering side must share a ceiling, or neither enforces it.
    webrtc_admission: crate::transport::SignalAdmission,
    /// How far ICE may reach — host-only on a loopback mesh. Derived from the
    /// mesh's own lookups, so it cannot disagree with them.
    webrtc_ice: crate::transport::IceProfile,
    /// The raw topic string (`SetupKind::Topic` only); `None` for create/join.
    topic_string: Option<String>,
}

/// # Errors
/// The join target fails to resolve, the password fails to verify, or the
/// endpoint cannot bind.
pub async fn setup_mesh(kind: SetupKind, params: SetupParams) -> Result<EventLoopConfig> {
    let SetupParams {
        author,
        max_peers,
        runtime_base,
        state_file,
        sink,
        cohost: cohost_override,
        live_count,
        endpoint: injected,
        protocols,
        transports,
        multihop,
        per_peer_gate,
    } = params;
    // The localhost binding is owned + bound by the caller; the engine only needs
    // the resolved port for the `ready` event. `Some(0)` (ephemeral) is resolved
    // caller-side and passed back in here as the real port.
    // Create mints the config from the caller's choices; join decodes it
    // from the id — one source of truth either way.
    let mesh_config = match &kind {
        SetupKind::Create { config, .. } => config,
        SetupKind::Join { mesh, .. } | SetupKind::Topic { mesh, .. } => &mesh.config,
    };
    // Decode already validated a joined id; a minted config has had no check
    // yet, and an invalid one would produce an id every joiner rejects.
    mesh_config.validate()?;
    let lookups = mesh_config.lookups.clone();
    let relay_transport = mesh_config.transport.relay_transport;

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
    let identity = std::sync::Arc::new(crate::protocol::identity::Identity::generate());

    let build = SetupBuild {
        author: &author,
        sink: sink.as_ref(),
        max_peers,
        lookups: &lookups,
        unicast_acceptor: &unicast_acceptor,
        multihop,
        transports,
        injected,
        protocols: std::sync::Mutex::new(protocols),
        rung_tx: &rung_tx,
        relay_transport,
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
        #[cfg(feature = "host")]
            multihop: multihop_handle,
        webrtc,
        webrtc_admission,
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
        router,
        max_peers,
        rendezvous_params: rdv,
        rung_rx,
        rung_probe,
        cohost: cohost_override.unwrap_or(cohost),
        runtime_base,
        state_file,
        #[cfg(feature = "host")]
        multihop: multihop_handle,
        webrtc,
        webrtc_enabled: transports.webrtc,
        local_ip_transport: !cfg!(target_arch = "wasm32") && transports.ip,
        webrtc_admission,
        webrtc_ice,
        unicast_rx,
        live_count,
        relay_transport,
        // Default to the CLI driver; the in-process sessions
        // overwrite `cfg.driver` before handing it to `daemon::run`.
        driver: DriverMode::Cli,
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
    webrtc: &fofoca_iroh_webrtc_transport::WebRtcHandle,
) -> (
    iroh_gossip::net::Gossip,
    iroh::protocol::Router,
    crate::transport::SignalAdmission,
    crate::transport::IceProfile,
) {
    let admission = crate::transport::SignalAdmission::new(crate::transport::MAX_DIRECT_PEERS);
    let ice = crate::transport::IceProfile {
        host_only: mesh.is_loopback(),
    };
    let (gossip, router) = build_mesh(
        endpoint.clone(),
        build.max_peers,
        Some(build.unicast_acceptor.clone()),
        build
            .transports
            .webrtc
            .then(|| (webrtc.clone(), admission.clone(), ice)),
        build.take_protocols(),
        build.relay_transport,
    );
    (gossip, router, admission, ice)
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
        not(feature = "host"),
        expect(
            unused_variables,
            reason = "no multihop handle off a host — see `build_member_endpoint`"
        )
    )]
    let (endpoint, multihop, webrtc) = build_member_endpoint(build).await?;

    let mut mesh = Mesh::new(seed, name.clone(), config);
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
    let mesh_key = mesh.stretched_key().map(zeroize::Zeroizing::new);
    // The creator alone retains its full mesh (issuer key + root) to mint from.
    let mint_mesh = mesh.requires_invite().then(|| mesh.clone());
    let id_str = mesh.to_string();
    let mesh_id =
        MeshId::new(id_str.clone()).expect("Mesh::to_string always produces a valid MeshId");

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
    // Keeping the conversion here is what lets fofoca-protocol build
    // without iroh-gossip at all (see fofoca_protocol::topic).
    let topic_id = iroh_gossip::proto::TopicId::from_bytes(mesh.topic_id().to_bytes());
    lifecycle::log_ready(
        topic_id,
        name.as_str(),
        author.as_str(),
        mesh.network_label(),
    );

    let (gossip, router, webrtc_admission, webrtc_ice) =
        build_overlay(build, &mesh, &endpoint, &webrtc);
    // Creator has no peers yet — bootstrap is empty.
    let topic = gossip.subscribe(topic_id, vec![]).await?;

    let rdv = rendezvous_params(&mesh, topic_id, build.lookups, build.rung_tx.clone());
    register_rendezvous(&endpoint, &rdv);

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
        #[cfg(feature = "host")]
        multihop,
        webrtc,
        webrtc_admission,
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
    let mesh_key = mesh.stretched_key().map(zeroize::Zeroizing::new);
    let id_str = mesh.to_string();
    let mesh_id =
        MeshId::new(id_str.clone()).expect("Mesh::to_string always produces a valid MeshId");
    // The one place the protocol's byte-shaped TopicId becomes iroh-gossip's.
    // Keeping the conversion here is what lets fofoca-protocol build
    // without iroh-gossip at all (see fofoca_protocol::topic).
    let topic_id = iroh_gossip::proto::TopicId::from_bytes(mesh.topic_id().to_bytes());

    #[cfg_attr(
        not(feature = "host"),
        expect(
            unused_variables,
            reason = "no multihop handle off a host — see `build_member_endpoint`"
        )
    )]
    let (endpoint, multihop, webrtc) = build_member_endpoint(build).await?;

    let rdv = rendezvous_params(&mesh, topic_id, build.lookups, build.rung_tx.clone());
    // Must precede the join: the peer resolves the rendezvous id via
    // this registered address — the loopback port ladder (loopback-only) or
    // the chosen relay rung (reachable across machines).
    register_rendezvous(&endpoint, &rdv);

    let (gossip, router, webrtc_admission, webrtc_ice) =
        build_overlay(build, &mesh, &endpoint, &webrtc);
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
    let needs_session = crate::transport::webrtc::node_graft_needs_session(
        build.relay_transport,
        build.transports.ip,
    );
    let bootstrap = if needs_session { vec![] } else { vec![rdv.id] };
    let topic = gossip.subscribe(topic_id, bootstrap).await?;

    // `ready` is emitted by `run`, once the IPC socket accepts — not here.
    lifecycle::log_ready(
        topic_id,
        mesh.name.as_str(),
        author.as_str(),
        mesh.network_label(),
    );
    // A topic gossip announces the raw string, not the derived `#name` — the
    // name is lossy and the string is what a user shares to meet peers.
    sink.emit(NodeEvent::Info(match &topic_string {
        Some(raw_topic) => format!("joined topic {raw_topic} as <{author}>"),
        None => format!("joined #{} as <{author}>", mesh.name),
    }));

    Ok(Assembled {
        mesh_id,
        mesh_name: mesh.name,
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
        #[cfg(feature = "host")]
        multihop,
        webrtc,
        webrtc_admission,
        webrtc_ice,
        topic_string,
    })
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use std::time::Duration;

    use tokio::sync::watch;

    use crate::testing::{errors_through_runtime_drop, silent_relay_rung};

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
}
