//! The `select!` event loop itself — the bulk of the daemon.
//!
//! [`run`] sets up per-session state then drives [`event_loop`], which
//! multiplexes external inputs (stdin / IPC / gossip), time-driven
//! maintenance (heartbeat, sweep, heal, anti-entropy, reclaim), and
//! shutdown. The orchestration lives here; the behavioral subsystems are
//! crate-root siblings (`crate::{gossip,lifecycle,beacon,lookup}`), and
//! the daemon-internal plumbing (`config`/`ctx`/`ipc`/`state`/`timers`/
//! `setup`) are siblings under `super`.

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::daemon::state::TestHold;
use crate::daemon::state::{BeaconNote, RendezvousFlag, Standing};
#[cfg(feature = "multihop")]
use crate::protocol;
#[cfg(feature = "host")]
use crate::util;
use crate::{lookup, transport};
use iroh_gossip::net;
use n0_future::{task, time};
#[cfg(feature = "host")]
use serde::de;
use std::{future, path, process};
pub(super) mod ctx_parts;
mod event_loop_error;
pub(super) mod tick_gap;

#[cfg(feature = "multihop")]
use iroh::EndpointId;
#[cfg(feature = "multihop")]
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use iroh::{Endpoint, EndpointAddr, RelayUrl, Watcher as _};
use iroh_gossip::api::{ApiError, Event, GossipReceiver, GossipTopic};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

#[cfg(feature = "host")]
use crate::daemon::state_file::StateFile;
use crate::doc::SelfWriteGate;
use crate::gossip::event::{NodeEvent, NodeSink};
use crate::protocol::meshes::{Mesh, MeshName};
use crate::protocol::messages::{Authored, Verified};
use crate::protocol::{MeshId, Nickname, UnixSecs, identity};
use crate::transport::{IpcMessage, MeshSender};
use crate::util::clock::{Instant, millis_saturating};
// The timer-driver clock, distinct from `clock::Instant` off wasm32 (there it is
// `tokio::time::Instant`). Aliased rather than path-qualified, matching
// `daemon::state` / `daemon::app`.
use crate::util::tuning::{
    ALIVE_INTERVAL, LINKSTATE_INTERVAL, RECLAIM_INTERVAL, STATE_REFRESH, antientropy_interval,
    heal_interval, sweep_interval,
};
use n0_future::time::Instant as TokioInstant;
// Gated with `spawn_orphan_watch`, its only caller.
use crate::{beacon, gossip, lifecycle};

use super::app::NodeDriver;
use super::cohost_arm::{
    CohostArm, claims_at_startup, may_cohost, maybe_cohost, maybe_reclaim, note_rival_holds,
    offer_to_the_new_holder, probes_before_claim, release_rendezvous, schedule_rival_recheck,
    shed_rival_beacon_if_due, verdict_after_known_holders,
};
#[cfg(feature = "host")]
use super::config::RuntimeConfig;
use super::config::{CoHostPolicy, DriverMode, EventLoopConfig, MeshSpec, TransportSet};
use super::handler_ctx::HandlerCtx;
use super::heal::{GossipLink, ResubscribeEnv, apply_rung_change, resubscribe_tick, run_heal};
use super::node::SignalHandling;
#[cfg(feature = "host")]
use super::shutdown;
use super::shutdown::{OwnedEndpoints, QuitParams, announce_departure, never_quit};
use super::state::{EventLoopState, MeshSecrets};
use super::timers;
use crate::daemon::setup::LiveCount;
use ctx_parts::CtxParts;
pub use event_loop_error::EventLoopError;
use tick_gap::TickGap;

use crate::daemon::state;
use crate::protocol::messages;
#[cfg(feature = "host")]
use crate::transport::ipc;
#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;
use crate::transport::{outbox, probe, webrtc};
use crate::util::version;
use tokio::sync::Notify;
/// Never returns normally — exits the process on ctrl-c / SIGTERM.
///
/// The engine loop is generic over the application: `app` implements
/// [`NodeDriver`] (the shipped application supplies the only production impl), and its
/// two typed driver inputs — the in-process `session_rx` (in-process) and the
/// localhost binding's `http_rx` — are threaded here so the
/// loop never names an application payload type.
///
/// # Errors
/// Propagates a fatal setup/transport error that terminates the event loop.
///
/// # Examples
///
/// It runs the event loop of a node until it stops. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::NodeDriver;
/// use habilis_network::runtime::{EventLoopConfig, run};
///
/// # async fn demo<Driver: NodeDriver>(config: EventLoopConfig, app: Driver) {
/// let _ = run(config, app, None, None).await;
/// # }
/// ```
pub async fn run<Driver: NodeDriver>(
    config: EventLoopConfig,
    app: Driver,
    session_rx: Option<mpsc::Receiver<Driver::Session>>,
    http_rx: Option<mpsc::Receiver<Driver::Http>>,
) -> Result<(), EventLoopError> {
    run_checked(config, app, session_rx, http_rx)
        .await
        .map_err(EventLoopError::internal)
}

async fn run_checked<Driver: NodeDriver>(
    config: EventLoopConfig,
    app: Driver,
    session_rx: Option<mpsc::Receiver<Driver::Session>>,
    http_rx: Option<mpsc::Receiver<Driver::Http>>,
) -> Result<()> {
    let EventLoopConfig {
        mut mesh,
        transports,
        endpoints,
        rendezvous,
        mut runtime,
    } = config;

    // Every driver-derived fact in one place. Only the CLI exits the
    // process on quit and binds the unix socket; in-process drivers
    // (in-process: library API or MCP) take typed requests on `session_rx` instead.
    let exit_on_quit = matches!(runtime.driver, DriverMode::Cli);
    #[cfg(feature = "host")]
    let state_file = host_state_file(&app, &mesh, &mut runtime, exit_on_quit);
    #[cfg(not(feature = "host"))]
    let state_file = runtime.state_file;
    let (external_quit_rx, external_msg_tx, ipc_listener_disabled, handle_signals) =
        driver_channels(runtime.driver);
    let external_req_rx = session_rx;
    let started = Instant::now();
    let leave_label = leave_label(&mesh);
    let mut state: EventLoopState = initial_state(
        mesh.identity,
        MeshSecrets {
            password: mesh.mesh_password.take(),
            key: mesh.mesh_key.take(),
        },
        mesh.mint_mesh.take(),
        &transports,
        runtime.per_peer_gate.take(),
        started,
        state_file,
    );
    let owned = OwnedEndpoints {
        router: endpoints.router,
        owner: endpoints.endpoint_owner,
        // A handle that the caller injected is the caller's; `close` skips it with the endpoint.
        #[cfg(feature = "multihop")]
        multihop: transports.multihop.clone(),
    };
    let (direct_rx, path_rx, flush_failed_rx) = wire_transports(
        &mut state,
        &endpoints.endpoint,
        transports,
        runtime.live_count.take(),
        &rendezvous.rendezvous_params,
    );

    let (rendezvous_state, rival_probe, rung_reports) = start_rendezvous(
        &mut state,
        &rendezvous.rendezvous_params,
        &endpoints.endpoint,
        rendezvous.cohost,
    )
    .await;
    let (sender, receiver) = join_gossip(&mut state, endpoints.topic);

    let ipc_rx: Option<mpsc::Receiver<IpcMessage<Driver::Ipc>>> = control_socket(
        ipc_listener_disabled,
        runtime.runtime_base.as_deref(),
        &mesh.mesh,
        &mesh.author,
        &runtime.sink,
    );

    // Arrival announce is deferred to the first `NeighborUp` — see
    // `gossip::handle_gossip_event`.

    let intervals = build_maintenance_intervals().await;
    #[cfg(feature = "host")]
    let quit_rx = quit_channel(handle_signals, exit_on_quit, runtime.owner);
    #[cfg(not(feature = "host"))]
    let quit_rx = quit_channel(handle_signals, exit_on_quit);

    // Flip `ready` to `true` only once the daemon can actually serve, then
    // re-write the state file (the earlier write reported `ready: false`) and
    // emit the `ready` event.
    //
    // "Serving" means: in CLI mode the IPC socket is bound — `spawn_ipc_rx`
    // binds *synchronously*, so a `Some` receiver proves an accepting socket
    // exists and a gate that observes the flag is guaranteed a subsequent
    // `poll`/`msg` connect succeeds; a `None` here is a bind failure, and we
    // must NOT advertise readiness (the daemon still gossips, but has no IPC).
    // In-process mode (in-process) has no socket by design (`req_rx` drives it)
    // and no `--state-file`, so it is always considered serving.
    //
    // The event is emitted *here*, beside the flag, rather than in `setup`:
    // there it announced a socket that had not been bound, so a client acting
    // on `ready` could race the listener. The two readiness signals — the
    // stdout event and the state-file flag a readiness gate polls — now
    // have one source and cannot disagree.
    if ipc_listener_disabled || ipc_rx.is_some() {
        announce_ready(
            &mut state,
            runtime.sink.as_ref(),
            &mesh.mesh,
            &mesh.name,
            &mesh.author,
        );
    }

    // `router` stays owned in this scope so its accept loop outlives
    // the event loop below (dropping it makes the daemon unreachable
    // to new peers).
    //
    // `Box::pin` keeps the event-loop future off `run`'s stack frame, so
    // `run` — and every caller that awaits it up through `cli::dispatch`
    // — stays under clippy's `large_futures` threshold. The future's
    // size is target-dependent (it crosses the limit on x86_64-linux but
    // not aarch64-macOS), so boxing the single await is more robust than
    // shaving struct fields.
    Box::pin(event_loop(EventLoop {
        sender,
        receiver,
        gossip: endpoints.gossip,
        endpoint: endpoints.endpoint,
        mesh: mesh.mesh,
        name: mesh.name,
        leave_label,
        author: mesh.author,
        sink: runtime.sink,
        max_peers: runtime.max_peers,
        state,
        app,
        ipc_rx,
        intervals,
        rendezvous: rendezvous_state,
        rival_probe,
        rendezvous_params: rendezvous.rendezvous_params,
        rung_rx: rendezvous.rung_rx,
        rung_probe: rendezvous.rung_probe,
        rung_reports,
        cohost: rendezvous.cohost,
        started,
        external_quit_rx,
        external_req_rx,
        external_msg_tx,
        quit_rx,
        exit_on_quit,
        http_rx,
        unicast_rx: Some(endpoints.unicast_rx),
        lan_contacts: endpoints.lan_contacts,
        direct_rx,
        path_rx,
        flush_failed_rx,
        owned,
    }))
    .await
}

/// What the driver hands the loop: its quit and message channels, whether the loop binds the unix
/// socket, and how it handles signals.
fn driver_channels(
    driver: DriverMode,
) -> (
    Option<mpsc::Receiver<()>>,
    Option<broadcast::Sender<Authored>>,
    bool,
    SignalHandling,
) {
    match driver {
        DriverMode::Cli => (None, None, false, SignalHandling::Handle),
        DriverMode::InProcess {
            msg_tx,
            quit_rx,
            handle_signals,
        } => (Some(quit_rx), msg_tx, true, handle_signals),
    }
}

/// The control socket of the daemon, bound here, before the caller marks the session ready. `None`
/// when the driver has no socket: in-process drivers take requests on their own channel.
#[cfg(feature = "host")]
fn control_socket<Ipc: de::DeserializeOwned + Send + 'static>(
    disabled: bool,
    runtime_base: Option<&path::Path>,
    mesh_id: &MeshId,
    author: &Nickname,
    // The IPC task keeps a handle to the sink after this call returns.
    sink: &Arc<dyn NodeSink>,
) -> Option<mpsc::Receiver<IpcMessage<Ipc>>> {
    spawn_ipc_rx(disabled, runtime_base, mesh_id, author, sink)
}

/// A browser binds no control socket. The loop keeps its IPC `select!` arm — `IpcMessage` is
/// portable — and the arm simply never fires.
#[cfg(not(feature = "host"))]
fn control_socket<Ipc>(
    _disabled: bool,
    _runtime_base: Option<&path::Path>,
    _mesh_id: &MeshId,
    _author: &Nickname,
    // Same shape as the host variant, which shares this sink with the IPC task.
    _sink: &Arc<dyn NodeSink>,
) -> Option<mpsc::Receiver<IpcMessage<Ipc>>> {
    None
}

/// The loop's quit channel. A session inside a foreground command that owns its own lifetime
/// (a `--advertise` transfer, a directory browse) must not register process-wide signal
/// handlers — doing so suppresses the OS default-terminate forever and the host command stops
/// dying on ctrl-c. Give the loop a quit channel that never fires instead; shutdown comes from
/// `external_quit_rx` / drop. A browser is always this case: there are no process signals to
/// listen for.
#[cfg(feature = "host")]
fn quit_channel(
    handle_signals: SignalHandling,
    exit_on_quit: bool,
    owner: Option<shutdown::Owner>,
) -> mpsc::Receiver<()> {
    if handle_signals == SignalHandling::Handle {
        shutdown::spawn_quit_signal_tasks(exit_on_quit, owner)
    } else {
        never_quit()
    }
}

#[cfg(not(feature = "host"))]
fn quit_channel(handle_signals: SignalHandling, _exit_on_quit: bool) -> mpsc::Receiver<()> {
    let _ = handle_signals;
    never_quit()
}

/// The state file of a host daemon, seeded by the app. `None` when there is no file to write: an
/// in-process session that keeps no file.
#[cfg(feature = "host")]
fn host_state_file<Driver: NodeDriver>(
    app: &Driver,
    mesh: &MeshSpec,
    runtime: &mut RuntimeConfig,
    exit_on_quit: bool,
) -> Option<StateFile> {
    let state_file: Option<StateFile> = runtime
        .state_file
        .take()
        .or_else(|| {
            let base = runtime.runtime_base.as_deref()?;
            exit_on_quit.then(|| {
                util::mesh_runtime_dir(base, mesh.mesh.as_str())
                    .join(format!("{}.state.json", mesh.author))
            })
        })
        .map(|path| {
            let owner_pid = runtime.owner.map(shutdown::Owner::pid);
            let file = StateFile::new(path, &mesh.mesh, &mesh.author, &mesh.name)
                .base(runtime.runtime_base.clone());
            file.topic(mesh.topic_string.as_deref())
                .owner_pid(owner_pid)
        });
    // Seed the state file with the application's own discovery fields before readiness is
    // advertised: the local client reads them from this mode-600 file.
    app.init_state_file(state_file.as_ref());
    state_file
}

/// The label of the departure line: a topic gossip shows `topic` plus the raw string it was
/// derived from (the name is lossy, and the wording mirrors the `joined topic …` startup line),
/// every other gossip its `#name`.
fn leave_label(mesh: &MeshSpec) -> String {
    mesh.topic_string.as_deref().map_or_else(
        || format!("#{}", mesh.name),
        |raw_topic| format!("topic {raw_topic}"),
    )
}

/// The state file a daemon seeds its state with: a host daemon has one, and a browser keeps its path.
#[cfg(feature = "host")]
type StateFileSeed = Option<StateFile>;
#[cfg(not(feature = "host"))]
type StateFileSeed = Option<path::PathBuf>;

/// The event loop's state, with the mesh's identity and secrets moved in. The state file goes
/// with it, so the first write the loop makes lands in the right place.
fn initial_state(
    // The loop holds the identity across `&mut state`, so it keeps a shared handle.
    identity: Arc<identity::Identity>,
    secrets: MeshSecrets,
    mint_mesh: Option<Mesh>,
    transports: &TransportSet,
    per_peer_gate: Option<SelfWriteGate>,
    started: Instant,
    state_file: StateFileSeed,
) -> EventLoopState {
    #[cfg(not(feature = "host"))]
    drop(state_file);
    let mut state: EventLoopState = EventLoopState::new(
        state::StateInit {
            #[cfg(feature = "host")]
            state_file,
            identity,
            secrets,
            per_peer_gate,
            // The *same* table the Router's signal acceptor holds, not a fresh
            // one: the cap only counts if both roles count against it together.
            webrtc_admission: transports.webrtc_admission.clone(),
            address_book: transports.address_book.clone(),
            webrtc_ice: transports.webrtc_ice,
        },
        started,
    );
    state.mint_mesh = mint_mesh; // creator-only: backs the `invite` command
    state
}

/// Wires the transports into the state, and returns the receivers of the three channels that
/// report back to the loop: the direct-path probes, the path watchers and the failed flushes.
fn wire_transports(
    state: &mut EventLoopState,
    endpoint: &Endpoint,
    transports: TransportSet,
    live_count: Option<LiveCount>,
    rendezvous_params: &beacon::RendezvousParams,
) -> (
    mpsc::UnboundedReceiver<probe::DirectOutcome>,
    mpsc::UnboundedReceiver<probe::PathChange>,
    mpsc::UnboundedReceiver<(Verified, messages::WireFrame)>,
) {
    #[cfg(feature = "multihop")]
    {
        state.multihop = transports.multihop; // the mesh policy's multihop: the registered transport's handle
        state.underlay_webrtc = transports.underlay_webrtc;
    }
    // The direct-path transport the session manager fills; `None` leaves
    // every pair to iroh's own paths.
    state.webrtc = transports.webrtc_enabled.then_some(transports.webrtc);
    // The gossip transport of the member endpoint, when the mesh has gossip: the admission table
    // made it with the endpoint and keeps it, to tell it which peers are established and which
    // pairs a higher rung carries.
    state.gossip_handle = state.webrtc_admission.gossip_handle();
    state.unicast_pool =
        transport::UnicastPool::new(endpoint.clone(), transports.relay_transport.relay_allowed());
    state
        .unicast_pool
        .set_admission(state.webrtc_admission.clone());
    // Before the first write, so the initial advertisement carries a real count.
    state.live_count = live_count;
    state.relay_transport = transports.relay_transport;
    if webrtc::session_policy::node_graft_needs_session(
        transports.relay_transport.relay_allowed(),
        transports.local_udp_transport,
    ) {
        state
            .rendezvous_flags
            .insert(RendezvousFlag::GraftNeedsSession);
    } else {
        state
            .rendezvous_flags
            .remove(&RendezvousFlag::GraftNeedsSession);
    }
    state.local_udp_transport = transports.local_udp_transport;
    // Direct-path probes report here; the loop grafts on the verdict.
    let (direct_tx, direct_rx) = mpsc::unbounded_channel();
    state.direct_proven = direct_tx;
    state
        .webrtc_admission
        .set_proven_sink(state.direct_proven.clone());
    // Path watchers report here; the loop re-races or detaches on it.
    let (path_tx, path_rx) = mpsc::unbounded_channel();
    state.webrtc_admission.set_path_sink(path_tx.clone());
    state.path_changes = path_tx;
    // A flushed frame whose dial failed comes back here; the loop buffers it again.
    let (flush_failed_tx, flush_failed_rx) = mpsc::unbounded_channel();
    state.flush_failed = flush_failed_tx;
    state.rendezvous_id = Some(rendezvous_params.id);
    if rendezvous_params.answers_jsep() {
        state.rendezvous_flags.insert(RendezvousFlag::AnswersJsep);
    } else {
        state.rendezvous_flags.remove(&RendezvousFlag::AnswersJsep);
    }
    state.write_peer_count();
    (direct_rx, path_rx, flush_failed_rx)
}

/// Starts the rendezvous: an eager member co-hosts from t=0, and everyone else defers to the heal
/// gate. Returns the beacon, the probe of a claim that is still open, and the rung reports.
async fn start_rendezvous(
    state: &mut EventLoopState,
    rendezvous_params: &beacon::RendezvousParams,
    endpoint: &Endpoint,
    cohost: CoHostPolicy,
) -> (
    Option<beacon::Rendezvous>,
    Option<beacon::RivalProbe>,
    mpsc::UnboundedReceiver<beacon::RungReport>,
) {
    // An eager member co-hosts from t=0 so a beacon exists before any
    // joiner subscribes; everyone else defers to the heal gate
    // (`may_cohost`). `Eager` skips the probe (a brand-new mesh has no
    // peers to self-collide with); `EagerProbed` probes first, so several
    // advertisers sharing one directory `rendezvous_id` don't bind
    // duplicate copies. Why: `EventLoopConfig::cohost`.
    let mut rendezvous: Option<beacon::Rendezvous> = None;
    // The probe tasks of the private ladder report here; the loop notes the reading and walks.
    let (rung_report_tx, rung_reports) = mpsc::unbounded_channel();
    state.rungs = beacon::RungWatch::new(rung_report_tx);
    // The outstanding probe-before-claim, if any. Owned here beside the
    // beacon it decides, because a probe outlives the tick that started it:
    // its verdict arrives on the loop's own arm, up to `HEAL_PROBE`
    // later.
    let mut rival_probe: Option<beacon::RivalProbe> = None;
    if claims_at_startup(cohost) {
        let claimed = beacon::walk_ladder(
            rendezvous_params,
            endpoint,
            &state.address_book,
            &mut rendezvous,
            probes_before_claim(cohost),
            &mut rival_probe,
            &mut state.rungs,
        )
        .await
            == beacon::Held::Claimed;
        if claimed {
            schedule_rival_recheck(state, cohost, rendezvous_params, endpoint);
        }
    } else if !rendezvous_params.bind_ports.is_empty() {
        // A member that does not claim at startup walks first on the reclaim ticker, and its book
        // left the busy rungs out: read them now, so its first link does not wait for that tick.
        beacon::read_ladder(
            rendezvous_params,
            endpoint,
            &state.address_book,
            &mut state.rungs,
        )
        .await;
    }

    // Open the fast reclaim window for the first few seconds of the loop's
    // life, so bootstrap gets the same event-driven retry that failover
    // does.
    //
    // Every other path into this window is armed by a `NeighborDown`
    // (`gossip::recv::arms_reclaim`), which a node that has *never* linked
    // never receives. That node is not a hypothetical: two peers starting
    // together race the beacon's own bind, and the one that dials the
    // rendezvous in the millisecond before it accepts gets nothing, has no
    // link to lose, and so arms nothing. Recovery then waited out the 15s
    // heal cadence — long enough that a two-peer mesh looks simply broken.
    // With the window open, `maybe_reclaim` re-grafts within
    // `RECLAIM_INTERVAL` instead, and stops as soon as the link is up.
    state.arm_reclaim(Instant::now());
    (rendezvous, rival_probe, rung_reports)
}

/// Joins the gossip topic and starts the tasks that carry its frames: the split of the receiver,
/// and the drain of the digest answers, so that the loop never waits for the gossip actor.
fn join_gossip(
    state: &mut EventLoopState,
    topic: GossipTopic,
) -> (MeshSender, gossip::split::MeshReceiver<GossipReceiver>) {
    let (gossip_sender, receiver) = topic.split();
    if let Some(handle) = &state.gossip_handle {
        handle.attach_gossip(gossip_sender.clone());
    }
    let receiver = gossip::split::spawn_split(receiver, state.gossip_handle.clone());

    let sender = MeshSender::new(gossip_sender);
    // The task that sends the digest answers, so that the loop never waits for
    // the gossip actor to take them.
    if let Some(resends) = state.resend_receiver.take() {
        task::spawn(outbox::drain(
            resends,
            sender.clone(),
            state.unicast_pool.clone(),
        ));
    }
    (sender, receiver)
}

/// Marks the loop ready and emits the `ready` event. See the call site for why it waits for the
/// IPC socket.
fn announce_ready(
    state: &mut EventLoopState,
    sink: &dyn NodeSink,
    mesh: &MeshId,
    name: &MeshName,
    author: &Nickname,
) {
    state.standing.insert(Standing::Ready);
    state.write_peer_count();
    sink.emit(NodeEvent::Ready {
        mesh: mesh.clone(),
        name: name.clone(),
        nickname: author.clone(),
    });
}

/// The alive tick: note the gap, broadcast the keepalive presence, then pay a held-back `PeerInfo` flood.
async fn alive_arm(
    anchors: &mut TickAnchors,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    timers::note_tick_gap(
        "alive",
        &mut anchors.alive,
        &mut anchors.alive_wall,
        ALIVE_INTERVAL,
    );
    lifecycle::heartbeat::tick_alive(state, context.sender, context.mesh, context.author).await;
    // A neighbor that came up inside the window of a flood is owed our address.
    if state.take_deferred_peerinfo(Instant::now()) {
        gossip::broadcast_peer_info(state, context).await;
        state.last_sent_at = Instant::now();
    }
}

/// The anti-entropy tick: note the gap, advertise the chat digest, then both
/// channel digests, so peers can request anything we hold that they miss.
async fn antientropy_arm(
    anchors: &mut TickAnchors,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    timers::note_tick_gap(
        "antientropy",
        &mut anchors.antientropy,
        &mut anchors.antientropy_wall,
        antientropy_interval(),
    );
    gossip::antientropy::broadcast_digest(state, context.sender, context.mesh, context.author)
        .await;
    gossip::antientropy::broadcast_state_digests(
        state,
        context.sender,
        context.mesh,
        context.author,
        gossip::antientropy::DigestTrigger::Tick,
    )
    .await;
}

/// The multihop link-state tick: re-broadcast our own links (one per direct
/// neighbour and one per member with a live underlay session, carrying our underlay dial address) so every peer keeps a fresh
/// routing graph for the multihop transport. Each link carries the cost of the handle
/// (`HandleConfig::link_cost`; a browser's is higher), until live telemetry (RTT, delivery) is
/// wired into the metric. No-op until meshed, or when the multihop transport is off — a vector
/// with no consumer helps no one — and while the underlay has no address a neighbor could dial.
/// Without the `multihop` feature the transport does not exist, so the tick has nothing
/// to broadcast. A no-op stub rather than a `cfg` at the `select!` arm, so the loop
/// body reads the same with and without the feature.
#[cfg(not(feature = "multihop"))]
fn linkstate_arm(state: &mut EventLoopState, context: &HandlerCtx<'_>) -> impl Future<Output = ()> {
    let _ = (state, context);
    future::ready(())
}

/// The edges that our link-vector advertises: one per gossip neighbour, and one per member
/// whose underlay holds a live session with us (`held`), whether or not a gossip link to it is
/// up. The relay watcher closes a gossip link on purpose, and a gossip dial that came before the
/// session of its pair was refused, so a session that carries a route must not lose its edge
/// with the link. A hop that the underlay holds stuck is still dropped by `link_vector`.
#[cfg(feature = "multihop")]
fn advertised_links(
    linked: &HashSet<EndpointId>,
    held: &[EndpointId],
    cost: u32,
) -> Vec<(EndpointId, u32)> {
    let mut members: BTreeSet<EndpointId> = linked.iter().copied().collect();
    members.extend(held.iter().copied());
    members.into_iter().map(|member| (member, cost)).collect()
}

#[cfg(feature = "multihop")]
pub(crate) async fn linkstate_arm(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    advertise_links(state, context, false).await;
}

/// Advertise the links of this node. The tick sends whatever the set is, as the vector is also
/// what keeps our edges alive in the graph of the others; `only_if_changed` is for a link that
/// came up (see [`linkstate_now`]).
#[cfg(feature = "multihop")]
async fn advertise_links(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    only_if_changed: bool,
) {
    // Before the early return, and before our own vector goes in: a peer that has
    // stopped advertising must not keep its edges in the graph, and a node that is
    // not meshed yet keeps hearing vectors it will route over once it is.
    if let Some(handle) = state.multihop.as_ref() {
        let _ = handle.expire_stale();
    }
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    {
        if state.test_holds.contains(&TestHold::LinkState) {
            return;
        }
    }
    if !state.standing.contains(&Standing::Meshed) || state.multihop.is_none() {
        return;
    }
    let handle = state.multihop.as_ref().expect("checked above");
    // A vector names the address of our underlay, and a neighbor dials that address. An
    // underlay with no IP and no relay yet has none: wait for the next tick.
    if handle.underlay_addr().addrs.is_empty() {
        return;
    }
    let held = state
        .underlay_webrtc
        .as_ref()
        .map(|underlay| underlay_webrtc::held_members(state, underlay))
        .unwrap_or_default();
    let links = advertised_links(&state.linked_endpoints, &held, handle.link_cost());
    if only_if_changed && !advertised_changed(state.last_advertised.as_deref(), &links) {
        return;
    }
    state.last_advertised = Some(links.clone());
    let edges: Vec<_> = links
        .iter()
        .map(|&(id, cost)| {
            (
                habilis_network_iroh_multihop_transport::AppId::new(id),
                cost,
            )
        })
        .collect();
    let vector = handle.link_vector(edges);
    // Fold our own vector into our own routing table: gossip never loops a
    // broadcast back, and without our outbound edges the local graph can't
    // source a route (`route_to(self, …)` would always be empty).
    let updated = handle.feed_topology(vector.clone());
    // Our own links changed the topology: a route may exist now that did not at the last tick.
    if updated {
        probe::nudge_climbing_pairs(state, context, true);
    }
    let Some(body) = gossip::json_body(&vector) else {
        return;
    };
    state.idle.broadcasts += 1;
    // Not retained in the log, unlike a chat message: the next tick's vector
    // replaces this one, and peers never log what they receive (see
    // `is_loggable`), so a retained copy would be one that nobody else holds and
    // that every digest asks us for again.
    let vector_msg =
        protocol::Message::new_link_state(context.mesh, context.author, body).sign(&state.identity);
    gossip::broadcast_msg(context.sender, &vector_msg).await;
    // The vector that this node just sent is what a peer that turned our offer away lacked: the
    // wait that its turn-aways earned ends, and the underlay offers again at once. One offer per
    // vector sent: a link event, or the tick.
    if let Some(underlay) = state.underlay_webrtc.as_ref() {
        underlay.admission.forget_not_a_neighbor();
    }
    underlay_webrtc::tick_now(state);
}

/// Whether the links of a vector are another set than the last one that went out. None went
/// out yet: it is another one.
#[cfg(feature = "multihop")]
fn advertised_changed(last: Option<&[(EndpointId, u32)]>, links: &[(EndpointId, u32)]) -> bool {
    last != Some(links)
}

/// [`linkstate_arm`] now, for a link that came up: the vector of this node is what lets a
/// neighbor offer a session on the underlay and route over its edges, and the first tick is
/// `LINKSTATE_INTERVAL` away. It sends only when the links are another set than the last
/// vector had: a second link that comes up 100 ms after the first goes out at once, and a link
/// that flaps back to the set that went out sends nothing.
#[cfg(feature = "multihop")]
pub(crate) async fn linkstate_now(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    advertise_links(state, context, true).await;
}

/// The sweep-tick arm: note the gap, then evict silent peers. The app's own
/// timers that ride this cadence run via [`NodeDriver::on_tick`] right after.
fn sweep_arm(anchors: &mut TickAnchors, state: &mut EventLoopState, sink: &dyn NodeSink) {
    timers::note_tick_gap(
        "sweep",
        &mut anchors.sweep,
        &mut anchors.sweep_wall,
        sweep_interval(),
    );
    lifecycle::heartbeat::tick_sweep(state, sink);
}

/// Owned working set for [`event_loop`]. `run` does setup, fills this,
/// and hands it over; the loop destructures it back into the same
/// locals the orchestrator used to hold inline. Splitting the 11-arm
/// `select!` out keeps both functions within the readability budget
/// (clippy `too_many_lines`) without an `#[allow]`.
struct EventLoop<Driver: NodeDriver> {
    sender: MeshSender,
    receiver: gossip::split::MeshReceiver<GossipReceiver>,
    /// The gossip frontend, kept so the loop can re-subscribe the topic
    /// after the stream terminally ends (see the heal arm) — without it
    /// a closed subscription (e.g. lag-evicted by the actor) would
    /// leave the daemon permanently deaf.
    gossip: net::Gossip,
    endpoint: Endpoint,
    mesh: MeshId,
    name: MeshName,
    /// The departure line's label: the raw topic string for a topic
    /// gossip (the derived name is lossy), `#name` otherwise.
    leave_label: String,
    author: Nickname,
    // trait object: the loop, its app output and the IPC server share one sink
    sink: Arc<dyn NodeSink>,
    max_peers: usize,
    state: EventLoopState,
    /// Application state behind the [`NodeDriver`] seam, disjoint from the mesh
    /// `state` and threaded as its own `&mut` through the app callbacks.
    app: Driver,
    ipc_rx: Option<mpsc::Receiver<IpcMessage<Driver::Ipc>>>,
    intervals: MaintenanceIntervals,
    rendezvous: Option<beacon::Rendezvous>,
    /// The outstanding probe-before-claim, whose verdict the loop applies on
    /// its own arm (`beacon::probe_verdict`). Off-loop by construction: a
    /// free rendezvous is only provably free once the dial exhausts its
    /// budget, and paying that inline froze the whole loop for ~5s a tick.
    rival_probe: Option<beacon::RivalProbe>,
    rendezvous_params: beacon::RendezvousParams,
    /// Bootstrap rung chosen off-loop (startup probe + beacon
    /// self-monitor); the loop applies changes via the rung-update arm.
    rung_rx: watch::Receiver<Option<RelayUrl>>,
    /// The startup probe behind `rung_rx`, released with the rendezvous.
    rung_probe: Option<lookup::StoppableTask>,
    /// What the probe tasks of the private ladder found, and the walk that asked for it.
    rung_reports: mpsc::UnboundedReceiver<beacon::RungReport>,
    /// When this member may serve the rendezvous (see [`CoHostPolicy`]).
    cohost: CoHostPolicy,
    /// Event-loop start, for the unmeshed-joiner co-host grace.
    started: Instant,
    external_quit_rx: Option<mpsc::Receiver<()>>,
    /// The in-process typed session channel (in-process: library API or MCP); `None` on the CLI.
    external_req_rx: Option<mpsc::Receiver<Driver::Session>>,
    external_msg_tx: Option<broadcast::Sender<Authored>>,
    quit_rx: mpsc::Receiver<()>,
    exit_on_quit: bool,
    /// The application's localhost HTTP binding request channel; `None` off.
    http_rx: Option<mpsc::Receiver<Driver::Http>>,
    /// Inbound unicast frames from the `UNICAST_ALPN` acceptor, drained into
    /// `gossip::ingest` (same validation + dedup path as gossip). `Option` so
    /// the `select!` arm can disable itself if the channel ever closes.
    unicast_rx: Option<mpsc::Receiver<bytes::Bytes>>,
    /// The members of this mesh that the LAN announces (`gossip::lan`). `Option` so the arm is
    /// off without an mDNS handle and when the channel closes.
    lan_contacts: Option<mpsc::Receiver<lookup::LanEvent>>,
    /// Direct-path probe verdicts (`transport::probe`). Never closes: `state`
    /// holds a sender for the loop's lifetime.
    direct_rx: mpsc::UnboundedReceiver<probe::DirectOutcome>,
    /// Path watcher reports (`transport::probe::on_path_change`). Never closes,
    /// like `direct_rx`.
    path_rx: mpsc::UnboundedReceiver<probe::PathChange>,
    /// Flushed frames whose dial failed (`gossip::requeue_failed`). Never closes, like `direct_rx`.
    flush_failed_rx: mpsc::UnboundedReceiver<(Verified, messages::WireFrame)>,
    /// Closed with the rendezvous as the loop ends.
    owned: OwnedEndpoints,
}

/// The daemon's `select!` loop. Never returns normally on the CLI
/// path (ctrl-c / SIGTERM `std::process::exit`s); in-process drivers
/// break out via their external quit channel and get `Ok(())`.
/// Log the one per-daemon build-stamp line into the always-on file (one log
/// file == one process == one build). The `ready` JSON event carries the same
/// `version`; this is the file-log counterpart. Explicit pinned target so it
/// survives a release build's `error` base.
fn log_daemon_start(author: &Nickname) {
    tracing::info!(
        target: "habilis_network::lifecycle",
        version = version::build_string(),
        nickname = %author,
        "daemon starting"
    );
}

/// The state that the loop's `select!` arms read and write, and the handles they wait on. The
/// arms borrow its fields one at a time, so each arm can touch the fields it needs.
struct Loop<'node, Driver: NodeDriver> {
    parts: CtxParts<'node>,
    sender: MeshSender,
    receiver: gossip::split::MeshReceiver<GossipReceiver>,
    gossip: net::Gossip,
    mesh_name: MeshName,
    leave_label: String,
    state: EventLoopState,
    app: Driver,
    ipc_rx: Option<mpsc::Receiver<IpcMessage<Driver::Ipc>>>,
    intervals: MaintenanceIntervals,
    rendezvous: Option<beacon::Rendezvous>,
    rival_probe: Option<beacon::RivalProbe>,
    rendezvous_params: beacon::RendezvousParams,
    rung_rx: watch::Receiver<Option<RelayUrl>>,
    rung_probe: Option<lookup::StoppableTask>,
    rung_reports: mpsc::UnboundedReceiver<beacon::RungReport>,
    cohost: CoHostPolicy,
    started: Instant,
    external_quit_rx: Option<mpsc::Receiver<()>>,
    external_req_rx: Option<mpsc::Receiver<Driver::Session>>,
    quit_rx: mpsc::Receiver<()>,
    exit_on_quit: bool,
    http_rx: Option<mpsc::Receiver<Driver::Http>>,
    unicast_rx: Option<mpsc::Receiver<bytes::Bytes>>,
    lan_contacts: Option<mpsc::Receiver<lookup::LanEvent>>,
    direct_rx: mpsc::UnboundedReceiver<probe::DirectOutcome>,
    path_rx: mpsc::UnboundedReceiver<probe::PathChange>,
    flush_failed_rx: mpsc::UnboundedReceiver<(Verified, messages::WireFrame)>,
    anchors: TickAnchors,
    resubscribe_attempts: u32,
    owned: OwnedEndpoints,
}
impl<Driver: NodeDriver> Loop<'_, Driver> {
    /// The app's startup hook, and the first offer of the rendezvous.
    async fn start(&mut self) {
        let context = self.parts.handler_ctx(&self.sender);
        self.app.on_startup(&mut self.state, &context).await;
        webrtc::rendezvous::offer_rendezvous_off_tick(&mut self.state, &context);
    }

    /// Releases the beacon and the endpoints that the loop owns, then exits the process when the
    /// run asked for it. An error ends the run as it returns.
    async fn finish(mut self, outcome: Result<bool>) -> Result<()> {
        release_rendezvous(
            &mut self.rendezvous,
            &mut self.rival_probe,
            &mut self.rung_probe,
            &mut self.state.rungs,
            self.owned,
        )
        .await;
        match outcome {
            Ok(exit_after_release) => {
                if exit_after_release {
                    process::exit(0);
                }
                Ok(())
            }
            Err(error) => {
                // The CLI exits with code 1 once everything is released.
                #[cfg(not(feature = "dhat-heap"))]
                if self.exit_on_quit {
                    process::exit(1);
                }
                Err(error)
            }
        }
    }

    /// The checks of every turn before the loop waits: the beacon's own flags, the arrivals on
    /// the beacon, and the `PeerInfo` that carries the beacon flag.
    async fn turn_start(&mut self) {
        #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
        super::cohost_arm::shed_on_request(
            &mut self.state,
            &self.rendezvous_params,
            &mut self.rendezvous,
        );
        #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
        super::cohost_arm::stall_on_request(&mut self.state, self.rendezvous.as_ref());
        // Whether this process hosts the beacon is read here, once per turn,
        // from the one place that owns it, so that no path that claims or sheds
        // the beacon has to remember to say so.
        if self.rendezvous.is_some() {
            self.state
                .rendezvous_flags
                .insert(RendezvousFlag::HostsRendezvous);
        } else {
            self.state
                .rendezvous_flags
                .remove(&RendezvousFlag::HostsRendezvous);
        }
        // A member that links to our beacon and that we do not know is a sign of another group.
        if let Some(held) = self.rendezvous.as_mut() {
            for arrived in held.take_arrivals() {
                if arrived != self.parts.endpoint.id()
                    && !self.state.known_endpoints.contains(&arrived)
                {
                    self.state
                        .note_second_group_sign(self.parts.endpoint.id(), Instant::now());
                }
            }
        }
        // Said in our `PeerInfo` from here, for the same reason: no claim or shed path has to
        // remember to send it again.
        if self
            .state
            .rendezvous_flags
            .contains(&RendezvousFlag::HostsRendezvous)
            != self.state.beacon_notes.contains(&BeaconNote::FlagFlooded)
        {
            if self
                .state
                .rendezvous_flags
                .contains(&RendezvousFlag::HostsRendezvous)
            {
                self.state.beacon_notes.insert(BeaconNote::FlagFlooded);
            } else {
                self.state.beacon_notes.remove(&BeaconNote::FlagFlooded);
            }
            let context = self.parts.handler_ctx(&self.sender);
            gossip::broadcast_peer_info(&mut self.state, &context).await;
        }
    }

    /// Finalizes the ping round at its deadline.
    fn ping_deadline(&mut self) {
        self.state.idle.ext.deadlines += 1;
        finalize_ping_round(&mut self.state, self.parts.sink);
    }

    /// Sends the second probe of the ping round.
    async fn second_probe(&mut self) {
        self.state.idle.ext.deadlines += 1;
        let context = self.parts.handler_ctx(&self.sender);
        gossip::send_second_probe(&mut self.state, &context).await;
    }

    fn poll_deadline(&mut self) {
        self.state.idle.ext.deadlines += 1;
        self.app.poll_deadline_elapsed();
    }

    fn expire_deadlines(&mut self) {
        self.state.idle.ext.deadlines += 1;
        self.app.expire_deadlines(TokioInstant::now());
    }

    async fn ipc(&mut self, (command, response): IpcMessage<Driver::Ipc>) {
        self.state.idle.ext.ipc += 1;
        let context = self.parts.handler_ctx(&self.sender);
        let request = super::app::IpcRequest {
            command,
            response,
            name: &self.mesh_name,
        };
        if self
            .app
            .handle_ipc(request, &mut self.state, &context)
            .await
        {
            self.state.last_sent_at = Instant::now();
        }
    }

    async fn http(&mut self, request: Driver::Http) {
        self.state.idle.ext.http += 1;
        let context = self.parts.handler_ctx(&self.sender);
        self.app
            .handle_http(request, &mut self.state, &context)
            .await;
    }

    async fn gossip_event(&mut self, event: Option<Result<Event, ApiError>>) {
        self.state.idle.ext.note_gossip(event.as_ref());
        let context = self.parts.handler_ctx(&self.sender);
        gossip::handle_gossip_event(event, &mut self.state, &mut self.app, &context).await;
    }

    async fn direct_outcome(&mut self, outcome: probe::DirectOutcome) {
        self.state.idle.ext.direct_rx += 1;
        let context = self.parts.handler_ctx(&self.sender);
        probe::on_outcome(outcome, &mut self.state, &context).await;
        probe::ensure_watchers(
            &mut self.state,
            context.endpoint.id(),
            context.rendezvous_id,
        );
    }

    fn flush_failed(&mut self, (message, bytes): (Verified, messages::WireFrame)) {
        self.state.idle.ext.other += 1;
        let context = self.parts.handler_ctx(&self.sender);
        gossip::requeue_failed(&mut self.state, &context, message, bytes);
    }

    /// A lane slot freed: the offers that waited for it are made now.
    async fn top_up_lanes(&mut self) {
        self.state.idle.ext.other += 1;
        let context = self.parts.handler_ctx(&self.sender);
        probe::top_up_lane_offers(&mut self.state, &context).await;
    }

    /// A round of the multihop underlay ended, offered or answered: an offer that its
    /// answerer turned away, because our link vector had not reached it yet, is made again
    /// now, and not at the alive tick. A session that the round attached is an edge of this
    /// node: its vector goes out at once, and nothing goes out when the set did not change.
    #[cfg(feature = "multihop")]
    async fn underlay_round_ended(&mut self) {
        underlay_webrtc::tick_now(&self.state);
        let context = self.parts.handler_ctx(&self.sender);
        linkstate_now(&mut self.state, &context).await;
    }

    /// The gate of the multihop underlay began to refuse a hop, or admitted one that it refused:
    /// the best first hop to a pair on the relay can be another now, and waiting for the stuck
    /// deadline and a link-state tick would cost 20 s or more.
    fn route_wake(&mut self) {
        self.state.idle.ext.other += 1;
        let context = self.parts.handler_ctx(&self.sender);
        route_wake_arm(&mut self.state, &context);
    }

    async fn lan_event(&mut self, event: lookup::LanEvent) {
        self.state.idle.ext.other += 1;
        let context = self.parts.handler_ctx(&self.sender);
        gossip::lan::on_lan_event(event, &mut self.state, &context).await;
    }

    async fn path_change(&mut self, change: probe::PathChange) {
        self.state.idle.ext.path_rx += 1;
        let context = self.parts.handler_ctx(&self.sender);
        if Some(change.peer) == self.state.rendezvous_id {
            webrtc::rendezvous::offer_rendezvous_on_path_loss(&mut self.state, &context);
        } else {
            probe::on_path_change(change, &mut self.state, &context).await;
        }
    }

    /// Inbound unicast rides the *same* validate + dedup path as gossip (`ingest`).
    async fn unicast(&mut self, bytes: bytes::Bytes) {
        self.state.idle.ext.unicast += 1;
        let context = self.parts.handler_ctx(&self.sender);
        gossip::ingest(bytes, &mut self.state, &mut self.app, &context).await;
    }

    fn prune(&mut self) {
        self.state.idle.prune += 1;
        timers::tick_prune(&mut self.state, self.parts.sink);
    }

    async fn alive(&mut self) {
        self.state.idle.alive += 1;
        let context = self.parts.handler_ctx(&self.sender);
        alive_arm(&mut self.anchors, &mut self.state, &context).await;
        // Retry WebRTC negotiation for any peer we still have no
        // session with. Without this a pair gets exactly one attempt
        // ever: negotiation fires on `PeerInfo`, and once the pair is
        // linked, `PeerInfo` stops re-flooding — so a first attempt
        // lost to a transient (the peer not yet reachable, an ICE
        // hiccup) is never retried, and the pair stays relay-only for
        // the life of the link. Observed exactly that, CLI↔browser.
        webrtc::retry::retry_sessions(&mut self.state, &context);
        // The same for the sessions of the multihop underlay, which open
        // only to a neighbor that has no IP path to us.
        #[cfg(feature = "multihop")]
        if let Some(underlay) = &self.state.underlay_webrtc {
            underlay_webrtc::tick(&self.state, underlay);
        }
        // Same cadence for the direct-path probes a lookup-only relay
        // holds grafts on: a peer whose punch missed the deadline, or
        // whose session attached since, gets another look.
        probe::retry_direct(&mut self.state, &context, false).await;
        probe::ensure_watchers(
            &mut self.state,
            context.endpoint.id(),
            context.rendezvous_id,
        );
        probe::nudge_webrtc_riders(&mut self.state, &context);
    }

    async fn sweep(&mut self) {
        self.state.idle.sweep += 1;
        sweep_arm(&mut self.anchors, &mut self.state, self.parts.sink);
        let context = self.parts.handler_ctx(&self.sender);
        probe::prove_routed_pairs(&mut self.state, &context).await;
        self.app.on_tick(&mut self.state, &context).await;
    }

    /// The heal tick: heal the mesh while the gossip stream lives, else resubscribe the topic.
    /// An error ends the loop, which releases the beacon first.
    async fn heal(&mut self) -> Result<()> {
        self.state.idle.heal += 1;
        let (mono_gap, wall_gap) = timers::note_tick_gap(
            "heal",
            &mut self.anchors.heal,
            &mut self.anchors.heal_wall,
            heal_interval(),
        );
        if self.state.standing.contains(&Standing::GossipOpen) {
            let context = self.parts.handler_ctx(&self.sender);
            run_heal(
                TickGap {
                    mono: mono_gap,
                    wall: wall_gap,
                },
                &mut self.state,
                &context,
                &self.rendezvous_params,
            )
            .await;
            maybe_cohost(
                &mut self.state,
                &context,
                &CohostArm {
                    policy: self.cohost,
                    params: &self.rendezvous_params,
                    started: self.started,
                },
                &mut self.rendezvous,
                &mut self.rival_probe,
            )
            .await;
        } else {
            // Stream ended: resubscribe instead of healing a dead topic
            // (see `resubscribe_tick`); the beacon keeps the mesh joinable.
            resubscribe_tick(
                &ResubscribeEnv {
                    gossip: &self.gossip,
                    params: &self.rendezvous_params,
                    parts: &self.parts,
                },
                &mut self.state,
                &mut self.app,
                GossipLink {
                    sender: &mut self.sender,
                    receiver: &mut self.receiver,
                    attempts: &mut self.resubscribe_attempts,
                },
            )
            .await?;
            let context = self.parts.handler_ctx(&self.sender);
            maybe_cohost(
                &mut self.state,
                &context,
                &CohostArm {
                    policy: self.cohost,
                    params: &self.rendezvous_params,
                    started: self.started,
                },
                &mut self.rendezvous,
                &mut self.rival_probe,
            )
            .await;
        }
        Ok(())
    }

    /// A bootstrap rung chosen off-loop (startup probe / beacon self-monitor); apply it cheaply.
    fn rung_change(&mut self) {
        self.state.idle.ext.rung_change += 1;
        apply_rung_change(
            &mut self.state,
            &mut self.rendezvous_params,
            &mut self.rendezvous,
            &self.rung_rx,
        );
    }

    /// The off-loop probe-before-claim answered. Its own arm rather than a poll at the next heal
    /// tick: the probe already cost up to `HEAL_PROBE`, and making a free rendezvous wait out
    /// another 15s interval before anyone binds it would hand back the claim latency this change
    /// was meant to leave untouched.
    async fn probe_verdict(&mut self, found_rival: bool) {
        self.state.idle.ext.probe_verdict += 1;
        let found_rival = verdict_after_known_holders(found_rival, &self.state);
        let spread = rand::Rng::random_range(&mut rand::rng(), -1.0..=1.0);
        self.state
            .probe_backoff
            .note_verdict(found_rival, Instant::now(), spread);
        // One free verdict is not enough to claim: a live beacon's
        // rival re-check periodically releases the rendezvous to
        // re-probe it, and a probe landing inside that window reads
        // "free" while a holder is about to re-bind. Claiming on it
        // stands up a rival copy, and two copies shed each other
        // longer than most joins are willing to wait. Two frees in a
        // row (the next reclaim tick re-probes) squares those odds
        // away; a genuinely dead beacon costs one extra probe round.
        if !found_rival
            && !self
                .state
                .rendezvous_flags
                .contains(&RendezvousFlag::ProbeReadFree)
        {
            self.state
                .rendezvous_flags
                .insert(RendezvousFlag::ProbeReadFree);
        } else {
            self.state
                .rendezvous_flags
                .remove(&RendezvousFlag::ProbeReadFree);
            let claimed = beacon::claim_after_probe(
                &self.rendezvous_params,
                self.parts.endpoint,
                &self.state.address_book,
                &mut self.rendezvous,
                found_rival,
                &mut self.state.rungs,
            )
            .await;
            if claimed {
                // Still from the brisk base: two joiners that start
                // together both read free twice and claim in the same
                // instant, and the first re-check is what merges that
                // split.
                schedule_rival_recheck(
                    &mut self.state,
                    self.cohost,
                    &self.rendezvous_params,
                    self.parts.endpoint,
                );
                // The new rendezvous never dials us; the reclaim tick re-grafts it.
                self.state.arm_reclaim(Instant::now());
                offer_to_the_new_holder(&mut self.state, &self.parts.handler_ctx(&self.sender));
            } else if found_rival {
                // A rival holds the identity: this arbitration epoch is
                // settled, so a later claim (the rival died) starts the
                // re-check backoff from its brisk base again.
                self.state.rival_recheck_rounds = 0;
                note_rival_holds(&mut self.state, &self.parts.handler_ctx(&self.sender));
            }
        }
    }

    /// A probe task of the private ladder answered. Its own arm, so that the walk that asked for
    /// it walks again at once and no tick has to wait.
    async fn rung_report(&mut self, report: beacon::RungReport) {
        self.state.idle.ext.rung_report += 1;
        self.state.rungs.note(report, Instant::now());
        let context = self.parts.handler_ctx(&self.sender);
        let arm = CohostArm {
            policy: self.cohost,
            params: &self.rendezvous_params,
            started: self.started,
        };
        maybe_reclaim(
            &mut self.state,
            &context,
            &arm,
            &mut self.rendezvous,
            &mut self.rival_probe,
        )
        .await;
        maybe_cohost(
            &mut self.state,
            &context,
            &arm,
            &mut self.rendezvous,
            &mut self.rival_probe,
        )
        .await;
        // Outside the reclaim window and before the grace, no walk acts on the reading:
        // a joiner that is not meshed yet applies it itself.
        if !self.state.standing.contains(&Standing::Meshed)
            && !may_cohost(
                self.cohost,
                self.state.standing.contains(&Standing::Meshed),
                self.started,
            )
            && !self.rendezvous_params.bind_ports.is_empty()
        {
            beacon::read_ladder(
                &self.rendezvous_params,
                context.endpoint,
                &self.state.address_book,
                &mut self.state.rungs,
            )
            .await;
        }
    }

    async fn beacon_closed(&mut self) {
        // The beacon that the re-check shed is closed: the id is free of our own corpse, so
        // the re-probe starts now. The reclaim tick below stays as the net.
        self.state.beacon_closing = None;
        self.state.idle.reclaim += 1;
        let context = self.parts.handler_ctx(&self.sender);
        let arm = CohostArm {
            policy: self.cohost,
            params: &self.rendezvous_params,
            started: self.started,
        };
        maybe_reclaim(
            &mut self.state,
            &context,
            &arm,
            &mut self.rendezvous,
            &mut self.rival_probe,
        )
        .await;
    }

    async fn reclaim(&mut self) {
        self.state.idle.reclaim += 1;
        let context = self.parts.handler_ctx(&self.sender);
        let arm = CohostArm {
            policy: self.cohost,
            params: &self.rendezvous_params,
            started: self.started,
        };
        // The rival re-check shed rides this ticker, NOT the heal tick:
        // simultaneous joiners' heal tickers align, and a shed deadline
        // quantized to a shared multi-second boundary re-synchronizes
        // the very sheds whose ms-scale phase offsets must differ for
        // one holder to catch the other still up (observed lockstep:
        // both shed within 5ms, both probe into the gap, both re-bind,
        // forever). At this cadence the offsets survive; the next tick
        // (~RECLAIM_INTERVAL later, after the dropped endpoint has
        // unmapped) runs the re-probe via `maybe_reclaim`.
        if !shed_rival_beacon_if_due(
            &mut self.state,
            &arm,
            &mut self.rendezvous,
            context.endpoint.id(),
        ) {
            maybe_reclaim(
                &mut self.state,
                &context,
                &arm,
                &mut self.rendezvous,
                &mut self.rival_probe,
            )
            .await;
        }
        probe::regraft_due(&mut self.state, &context).await;
        probe::refill_isolated(&mut self.state, &context).await;
        webrtc::session_policy::detach_sessions_under_udp(&mut self.state, &context).await;
        gossip::antientropy::resume_fast_rounds(&mut self.state, &context).await;
    }

    async fn antientropy(&mut self) {
        self.state.idle.antientropy += 1;
        let context = self.parts.handler_ctx(&self.sender);
        antientropy_arm(&mut self.anchors, &mut self.state, &context).await;
    }

    // Counted before the census reads them, so the tick that reports an
    // interval is itself in that interval's numbers.
    async fn state_refresh(&mut self) {
        self.state.idle.state_refresh += 1;
        timers::tick_state_refresh(&mut self.state, self.parts.endpoint).await;
    }

    async fn linkstate(&mut self) {
        self.state.idle.linkstate += 1;
        let context = self.parts.handler_ctx(&self.sender);
        linkstate_arm(&mut self.state, &context).await;
    }

    async fn session_request(&mut self, request: Driver::Session) {
        self.state.idle.ext.session += 1;
        let context = self.parts.handler_ctx(&self.sender);
        if self
            .app
            .handle_session(request, &mut self.state, &context)
            .await
        {
            self.state.last_sent_at = Instant::now();
        }
    }

    /// A quit from the app (MCP): never hard-exit.
    async fn external_quit(&mut self) {
        let context = self.parts.handler_ctx(&self.sender);
        announce_departure(
            &mut self.state,
            &mut self.app,
            &context,
            QuitParams {
                name: &self.mesh_name,
                leave_label: &self.leave_label,
                exit_on_quit: false,
            },
        )
        .await;
    }

    /// A CLI quit. The result says whether the process exits once the beacon is released.
    async fn quit(&mut self) -> bool {
        let context = self.parts.handler_ctx(&self.sender);
        announce_departure(
            &mut self.state,
            &mut self.app,
            &context,
            QuitParams {
                name: &self.mesh_name,
                leave_label: &self.leave_label,
                exit_on_quit: self.exit_on_quit,
            },
        )
        .await
    }
}

async fn event_loop<Driver: NodeDriver>(loop_state: EventLoop<Driver>) -> Result<()> {
    let EventLoop {
        sender,
        receiver,
        gossip,
        endpoint,
        mesh: mesh_str,
        name: mesh_name,
        leave_label,
        author,
        sink,
        max_peers,
        state,
        app,
        ipc_rx,
        intervals,
        rendezvous,
        rival_probe,
        rendezvous_params,
        rung_rx,
        rung_probe,
        rung_reports,
        cohost,
        started,
        external_quit_rx,
        external_req_rx,
        external_msg_tx,
        quit_rx,
        exit_on_quit,
        http_rx,
        unicast_rx,
        lan_contacts,
        direct_rx,
        path_rx,
        flush_failed_rx,
        owned,
    } = loop_state;

    log_daemon_start(&author);
    let slot_freed = state.webrtc_admission.slot_freed();
    let underlay_slot_freed = underlay_slot_freed_of(&state);
    let route_wake = route_wake_of(&state);

    // The surfaced-events ring (`poll`/`fetch` history) lives app-side, fed by
    // the tap the caller attached to `output` before handing it in (both this
    // `output` and the app's own `Output` are clones of that one tapped sink,
    // so events interleave in surfacing order). The loop drives the ring
    // through the app's `drain_surfaced` / poll-deadline hooks — the engine
    // never names the ring's element type.

    let anchors = TickAnchors::now();

    // The loop and each per-arm context hold this clone, so they borrow the identity while `state` is mutably borrowed.
    let identity = Arc::clone(&state.identity);
    // Our own author key, computed once for the per-message self-echo compare.
    let our_pubkey = identity.author_key();
    // Everything a HandlerCtx needs *except* the sender. The ctx itself
    // is built per-arm (`parts.handler_ctx(&sender)`) rather than once out here:
    // a loop-lifetime ctx would borrow `sender` forever, and the
    // resubscribe path must replace `sender`/`receiver` when the gossip
    // stream ends.
    let parts = CtxParts {
        endpoint: &endpoint,
        mesh: &mesh_str,
        author: &author,
        identity: identity.as_ref(),
        our_pubkey,
        max_peers,
        rendezvous_id: rendezvous_params.id,
        external_msg_tx: external_msg_tx.as_ref(),
        sink: sink.as_ref(),
    };

    // Consecutive failed resubscribe attempts (reset on success); at
    // `RESUBSCRIBE_MAX_ATTEMPTS` the gossip actor itself is gone and the
    // daemon shuts down rather than pretend to be a live member.
    let resubscribe_attempts: u32 = 0;

    // Our own address changes (the home relay arrives after the arrival flood, an
    // interface changes): a `PeerInfo` that was flooded without it is repaired by
    // the next flood, and the watcher keeps only the latest value.
    let mut address_changes = endpoint.watch_addr().stream_updates_only();

    // A CLI quit sets it: the process exits once the beacon and the endpoints are released.
    let mut lp = Loop {
        parts,
        sender,
        receiver,
        gossip,
        mesh_name,
        leave_label,
        state,
        app,
        ipc_rx,
        intervals,
        rendezvous,
        rival_probe,
        rendezvous_params,
        rung_rx,
        rung_probe,
        rung_reports,
        cohost,
        started,
        external_quit_rx,
        external_req_rx,
        quit_rx,
        exit_on_quit,
        http_rx,
        unicast_rx,
        lan_contacts,
        direct_rx,
        path_rx,
        flush_failed_rx,
        anchors,
        resubscribe_attempts,
        owned,
    };
    lp.start().await;
    let outcome = run_loop(
        &mut lp,
        &mut address_changes,
        &slot_freed,
        &underlay_slot_freed,
        &route_wake,
    )
    .await;
    lp.finish(outcome).await
}

/// The daemon's `select!` loop. Returns whether the process exits once the beacon is released:
/// a CLI quit does, and so does the loop's one error exit, which the caller releases before it returns.
async fn run_loop<Driver: NodeDriver>(
    lp: &mut Loop<'_, Driver>,
    address_changes: &mut (impl n0_future::Stream<Item = EndpointAddr> + Unpin),
    slot_freed: &Notify,
    underlay_slot_freed: &Notify,
    route_wake: &Notify,
) -> Result<bool> {
    use n0_future::StreamExt as _;
    let mut exit_after_release = false;
    loop {
        lp.turn_start().await;
        tokio::select! {
            () = sleep_until_opt(lp.state.ping_round.as_ref().map(|round| round.deadline)) => { lp.ping_deadline(); },
            () = sleep_until_opt(lp.state.ping_round.as_ref().and_then(|round| round.second_probe_at())) => {
                lp.second_probe().await;
            }
            () = sleep_until_opt(lp.app.earliest_poll_deadline()) => { lp.poll_deadline(); },
            () = sleep_until_opt(lp.app.earliest_deadline()) => { lp.expire_deadlines(); },
            ipc_message = recv_opt(&mut lp.ipc_rx) => match ipc_message {
                None => { lp.ipc_rx = None; },
                Some(message) => { lp.ipc(message).await; },
            },
            http_req = recv_opt(&mut lp.http_rx) => match http_req {
                None => { lp.http_rx = None; },
                Some(request) => { lp.http(request).await; },
            },
            event = lp.receiver.next(), if lp.state.standing.contains(&Standing::GossipOpen) => {
                lp.gossip_event(event).await;
            }
            Some(outcome) = lp.direct_rx.recv() => { lp.direct_outcome(outcome).await; },
            Some(failed) = lp.flush_failed_rx.recv() => { lp.flush_failed(failed); },
            () = slot_freed.notified() => { lp.top_up_lanes().await; },
            () = underlay_slot_freed.notified() => {
                lp.state.idle.ext.other += 1;
                #[cfg(feature = "multihop")]
                lp.underlay_round_ended().await;
            }
            () = route_wake.notified() => { lp.route_wake(); },
            lan_event = recv_opt(&mut lp.lan_contacts) => match lan_event {
                None => { lp.lan_contacts = None; },
                Some(event) => { lp.lan_event(event).await; },
            },
            Some(address) = address_changes.next() => {
                lp.state.idle.ext.address += 1;
                if lp.state.address_flood_due(&address) {
                    let context = lp.parts.handler_ctx(&lp.sender);
                    gossip::broadcast_peer_info(&mut lp.state, &context).await;
                    lp.state.last_sent_at = Instant::now();
                }
            }
            Some(change) = lp.path_rx.recv() => { lp.path_change(change).await; },
            frame = recv_opt(&mut lp.unicast_rx) => match frame {
                Some(bytes) => { lp.unicast(bytes).await; },
                None => { lp.unicast_rx = None; },
            },
            _ = lp.intervals.prune.tick() => { lp.prune(); },
            _ = lp.intervals.alive.tick() => { lp.alive().await; },
            _ = lp.intervals.sweep.tick() => { lp.sweep().await; },
            _ = lp.intervals.heal.tick() => { lp.heal().await?; },
            Ok(()) = lp.rung_rx.changed() => { lp.rung_change(); },
            found_rival = beacon::probe_verdict(&mut lp.rival_probe) => { lp.probe_verdict(found_rival).await; },
            Some(report) = lp.rung_reports.recv() => { lp.rung_report(report).await; },
            () = closed_opt(&mut lp.state.beacon_closing) => { lp.beacon_closed().await; },
            _ = lp.intervals.reclaim.tick() => { lp.reclaim().await; },
            _ = lp.intervals.antientropy.tick() => { lp.antientropy().await; },
            _ = lp.intervals.state_refresh.tick() => { lp.state_refresh().await; },
            _ = lp.intervals.linkstate.tick() => { lp.linkstate().await; },
            _ = recv_opt(&mut lp.external_quit_rx) => {
                lp.external_quit().await;
                break;
            }
            request = recv_opt(&mut lp.external_req_rx) => match request {
                None => { lp.external_req_rx = None; },
                Some(request) => { lp.session_request(request).await; },
            },
            _ = lp.quit_rx.recv() => {
                exit_after_release = lp.quit().await;
                break;
            }
        }
        lp.state.idle.wakeups += 1;
        lp.app.drain_surfaced();
    }
    Ok(exit_after_release)
}

/// Resolve the IPC receiver: reuse a pre-wired channel (MCP / library API) or,
/// for the CLI, spawn the unix-socket listener and own the channel.
/// Returning `Option` keeps the loop's `select!` arm uniform.
///
/// `disabled` is set by the in-process drivers (library API / MCP), which use
/// the typed `session_rx` and bind no socket.
#[cfg(feature = "host")]
fn spawn_ipc_rx<Cmd: de::DeserializeOwned + Send + 'static>(
    disabled: bool,
    runtime_base: Option<&path::Path>,
    mesh: &MeshId,
    author: &Nickname,
    // the IPC server takes its own clone of the shared sink
    sink: &Arc<dyn NodeSink>,
) -> Option<mpsc::Receiver<IpcMessage<Cmd>>> {
    // In-process mode (in-process: library API or MCP): no socket. Returning `None` leaves
    // the loop's IPC `select!` arm inert (it pends forever), so the
    // unix-socket listener is never bound — those drivers use the typed
    // `session_rx` instead.
    if disabled {
        return None;
    }
    // No base, no socket: an embedder that configured no runtime root has
    // nowhere to put one. Same inert `select!` arm as the in-process drivers.
    let base = runtime_base?;
    // Bind synchronously here, *before* the caller marks the session ready,
    // so an accepting socket always exists by the time the readiness flag
    // flips. Only the (always-running) accept loop is spawned. A bind
    // failure is non-fatal — the daemon still gossips; it just can't take
    // IPC — matching the prior best-effort behavior, only now observed
    // before readiness rather than racing it.
    let listener = match ipc::bind(base, mesh, author) {
        Ok(listener) => listener,
        Err(error) => {
            sink.emit(NodeEvent::Error(format!("IPC: {error}")));
            tracing::warn!(%error, "IPC: failed to bind socket");
            return None;
        }
    };
    let (ipc_tx, rx): (
        mpsc::Sender<IpcMessage<Cmd>>,
        mpsc::Receiver<IpcMessage<Cmd>>,
    ) = mpsc::channel(32);
    tokio::spawn(ipc::serve(listener, ipc_tx, Arc::clone(sink)));
    Some(rx)
}

/// Sleep until a ping round's deadline, or pend forever when no round
/// is active. Lets the event loop's `select!` carry a ping-finalize arm
/// that only fires while a round is in flight, without borrowing
/// `state` across the await (the deadline is copied out beforehand).
async fn sleep_until_opt(deadline: Option<TokioInstant>) {
    if let Some(at) = deadline {
        time::sleep_until(at).await;
    } else {
        let forever: future::Pending<()> = future::pending();
        forever.await;
    }
}

/// The route-wake arm: the gate of the multihop underlay began to refuse a hop, or admitted
/// one that it refused, so the best first hop to a pair on the relay can be another now.
/// The pass dials the pairs whose route changed.
pub(crate) fn route_wake_arm(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    probe::nudge_climbing_pairs(state, context, true);
}

/// The wake of the multihop handle, which rings when its relay rule starts to refuse a
/// hop and when it admits one that it refused.
#[cfg(feature = "multihop")]
// the wake is the multihop handle's, which the loop and the handle share
fn route_wake_of(state: &EventLoopState) -> Arc<Notify> {
    state.multihop.as_ref().map_or_else(
        // without a handle, a fresh wake that nothing rings
        || Arc::new(Notify::new()),
        habilis_network_iroh_multihop_transport::MultihopHandle::route_wake,
    )
}

/// Without the `multihop` feature there is no multihop transport: the wake never rings.
#[cfg(not(feature = "multihop"))]
// without the feature, a fresh wake that nothing rings
fn route_wake_of(_state: &EventLoopState) -> Arc<Notify> {
    // without the feature, a fresh wake that nothing rings
    Arc::new(Notify::new())
}

/// The wake of the admission table of the multihop underlay, which rings when a round of the
/// underlay ends, whatever its end. It is the table of the underlay, not `webrtc_admission`.
#[cfg(feature = "multihop")]
// the wake is the underlay admission's, which the loop and the underlay share
fn underlay_slot_freed_of(state: &EventLoopState) -> Arc<Notify> {
    state.underlay_webrtc.as_ref().map_or_else(
        // without an underlay, a fresh wake that nothing rings
        || Arc::new(Notify::new()),
        |underlay| underlay.admission.slot_freed(),
    )
}

/// Without the `multihop` feature there is no underlay: the wake never rings.
#[cfg(not(feature = "multihop"))]
// without the feature, a fresh wake that nothing rings
fn underlay_slot_freed_of(_state: &EventLoopState) -> Arc<Notify> {
    // without the feature, a fresh wake that nothing rings
    Arc::new(Notify::new())
}

/// Build and emit the `ping_report` for the elapsed round, then clear
/// it. RTT is each pong's local arrival minus the probe broadcast time.
fn finalize_ping_round(state: &mut EventLoopState, sink: &dyn NodeSink) {
    let Some(round) = state.ping_round.take() else {
        return;
    };
    // (Live per-neighbour RTT/delivery telemetry once fed the link metric; the
    // multihop transport currently advertises a flat link cost, so the ping round
    // only produces the user-facing report below. Re-wiring telemetry into the
    // multihop metric is a future enhancement.)
    let mut peers: Vec<(Nickname, u64)> = round
        .pongs
        .into_iter()
        .map(|(nickname, rtt)| (nickname, millis_saturating(rtt)))
        .collect();
    peers.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
    // The in-process `ping` request waits on this channel (no event stream to
    // read the report from); the CLI/IPC path leaves it unset and consumes the
    // `ping_report` event below instead.
    if let Some(response) = round.response {
        let _ = response.send(peers.clone());
    }
    // `known` must never be less than the number that responded: a peer can
    // pong and then leave the roster before this ~10s finalize, which would
    // otherwise report responded > known. Clamp so the count stays coherent.
    let known = state.peers.len().max(peers.len());
    sink.emit(NodeEvent::PingReport { peers, known });
}

/// Per-timer gap anchors; the heal gap also drives the resume-edge hard
/// re-bootstrap. Each timer carries a monotonic anchor AND a wall-clock
/// anchor: on macOS the monotonic clock pauses in lockstep with a
/// sleeping process, so only the wall gap reveals a suspend (see
/// `note_tick_gap` / `run_heal`).
#[derive(Clone, Copy)]
struct TickAnchors {
    alive: Instant,
    sweep: Instant,
    heal: Instant,
    antientropy: Instant,
    alive_wall: UnixSecs,
    sweep_wall: UnixSecs,
    heal_wall: UnixSecs,
    antientropy_wall: UnixSecs,
}

impl TickAnchors {
    fn now() -> Self {
        let mono = Instant::now();
        let wall = UnixSecs::now();
        Self {
            alive: mono,
            sweep: mono,
            heal: mono,
            antientropy: mono,
            alive_wall: wall,
            sweep_wall: wall,
            heal_wall: wall,
            antientropy_wall: wall,
        }
    }
}

/// The time-driven maintenance tickers.
struct MaintenanceIntervals {
    prune: time::Interval,
    alive: time::Interval,
    sweep: time::Interval,
    heal: time::Interval,
    /// Fast event-driven failover burst; only does work while
    /// `state.reclaim_until` is open (armed on `NeighborDown`).
    reclaim: time::Interval,
    /// Periodic anti-entropy digest broadcast (recover messages missed
    /// while partitioned/asleep).
    antientropy: time::Interval,
    state_refresh: time::Interval,
    /// Periodic relay link-state re-broadcast (our own measured links), so peers
    /// keep a fresh routing graph.
    linkstate: time::Interval,
}

/// Build the maintenance tickers, eating the first immediate tick on
/// the ones that must wait a full period (we just announced `Joined`).
///
/// Every ticker uses `MissedTickBehavior::Skip`: after the monotonic clock
/// jumps (an App Nap throttle, a SIGSTOP freeze), a default `Burst` ticker
/// fires a catch-up salvo — several anti-entropy digests back-to-back, a
/// heal immediately after the hard re-bootstrap it just ran, a prune replaying
/// its backlog — and poisons the tick-gap telemetry (the burst ticks report a
/// ~0 gap). Each tick here means "do the maintenance now", so a skipped tick is
/// free; `Skip` collapses the salvo to one tick on the next aligned boundary.
async fn build_maintenance_intervals() -> MaintenanceIntervals {
    use n0_future::time::MissedTickBehavior::Skip;

    let mut prune = time::interval(Duration::from_mins(1));
    prune.set_missed_tick_behavior(Skip);
    let mut alive = time::interval(ALIVE_INTERVAL);
    alive.set_missed_tick_behavior(Skip);
    alive.tick().await;
    let mut sweep = time::interval(sweep_interval());
    sweep.set_missed_tick_behavior(Skip);
    sweep.tick().await;
    let mut heal = time::interval(heal_interval());
    heal.set_missed_tick_behavior(Skip);
    heal.tick().await;
    let mut reclaim = time::interval(RECLAIM_INTERVAL);
    reclaim.set_missed_tick_behavior(Skip);
    reclaim.tick().await;
    let mut antientropy = time::interval(antientropy_interval());
    antientropy.set_missed_tick_behavior(Skip);
    antientropy.tick().await;
    let mut state_refresh = time::interval(STATE_REFRESH);
    state_refresh.set_missed_tick_behavior(Skip);
    state_refresh.tick().await;
    let mut linkstate = time::interval(LINKSTATE_INTERVAL);
    linkstate.set_missed_tick_behavior(Skip);
    linkstate.tick().await;
    MaintenanceIntervals {
        prune,
        alive,
        sweep,
        heal,
        reclaim,
        antientropy,
        state_refresh,
        linkstate,
    }
}

/// `select!`-friendly receive over an optional mpsc channel: yields
/// the next item, `None` once the channel closes, and pends forever
/// when the channel is absent so the arm stays inert for drivers that
/// don't wire it (CLI/MCP). Shared by the ipc / external-quit /
/// external-send arms so the idiom isn't written three ways.
/// Pends while no shed runs; resolves once when the close of the shed beacon is done. A receiver
/// whose sender was dropped also resolves, so a lost close task cannot hold the re-probe back.
async fn closed_opt(rx: &mut Option<oneshot::Receiver<()>>) {
    if let Some(rx) = rx.as_mut() {
        let _ = rx.await;
    } else {
        let forever: future::Pending<()> = future::pending();
        forever.await;
    }
}

async fn recv_opt<T>(rx: &mut Option<mpsc::Receiver<T>>) -> Option<T> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::oneshot;

    use n0_future::time;
    /// The wake for the close of a shed beacon: pending with no shed, ready when the close reports,
    /// ready when the close task is lost.
    async fn wakes_within_a_moment(closing: &mut Option<oneshot::Receiver<()>>) -> bool {
        time::timeout(Duration::from_millis(100), super::closed_opt(closing))
            .await
            .is_ok()
    }

    #[test]
    fn no_shed_does_not_wake_the_loop() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            assert!(
                !wakes_within_a_moment(&mut None).await,
                "no shed does not wake the loop"
            );
        });
    }

    #[test]
    fn the_close_of_the_shed_beacon_wakes_the_loop() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (done, closed) = oneshot::channel();
            let mut closing = Some(closed);
            assert!(
                !wakes_within_a_moment(&mut closing).await,
                "pends while it closes"
            );

            done.send(()).expect("the receiver is held");

            assert!(
                wakes_within_a_moment(&mut closing).await,
                "the close of the shed beacon wakes the loop"
            );
        });
    }

    #[test]
    fn a_lost_close_task_does_not_hold_the_re_probe_back() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (done, closed): (oneshot::Sender<()>, oneshot::Receiver<()>) = oneshot::channel();
            let mut closing = Some(closed);

            drop(done);

            assert!(
                wakes_within_a_moment(&mut closing).await,
                "a lost close task does not hold the re-probe back"
            );
        });
    }
}

#[cfg(all(test, feature = "host"))]
mod route_wake_tests {
    use crate::daemon::state::Standing;
    use habilis_network_iroh_multihop_transport::{HandleConfig, MultihopHandle, underlay_secret};
    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};

    use super::{linkstate_arm, route_wake_arm};
    use crate::testing::{LaneNode, nick};
    use crate::transport::probe::{PathKind, nudge_climbing_pairs};

    use crate::testing;
    async fn multihop_handle() -> MultihopHandle {
        let secret = SecretKey::generate();
        let underlay: Endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(underlay_secret(&secret))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind an underlay");
        MultihopHandle::new(&secret, underlay, HandleConfig::default()).expect("a handle")
    }

    /// One link-state tick of a meshed node with one linked peer, on a handle with `underlay` and
    /// `config`; what the node holds in its own routing view afterwards: the metric of each link
    /// that leaves it.
    async fn own_links_after_a_tick(
        underlay: Endpoint,
        secret: &SecretKey,
        config: HandleConfig,
    ) -> Vec<u32> {
        let node = LaneNode::start().await;
        let context = node.context();
        let mut state = node.state();
        let me = MultihopHandle::new(secret, underlay, config).expect("a handle");
        state.multihop = Some(me.clone());
        state.standing.insert(Standing::Meshed);
        state
            .linked_endpoints
            .insert(SecretKey::generate().public());
        linkstate_arm(&mut state, &context).await;
        let own = me.app_id().to_string();
        let view = me.topology_view();
        let costs: Vec<u32> = view
            .edges
            .iter()
            .filter(|edge| edge.from == own)
            .map(|edge| edge.metric)
            .collect();
        state.webrtc_admission.close();
        me.close().await;
        node.endpoint.close().await;
        costs
    }

    async fn loopback_underlay(secret: &SecretKey) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(underlay_secret(secret))
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind an underlay")
    }

    /// The cost on the links that a node advertises is the one of its handle, so that a browser
    /// (a handle made with `for_browser`) costs more as a hop in the middle of a route.
    #[test]
    fn the_link_state_arm_advertises_the_link_cost_of_its_handle() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                for (config, expected) in [
                    (HandleConfig::default(), 10),
                    (HandleConfig::for_browser(), 100),
                ] {
                    let secret = SecretKey::generate();
                    let underlay = loopback_underlay(&secret).await;
                    assert_eq!(
                        Box::pin(own_links_after_a_tick(underlay, &secret, config)).await,
                        vec![expected],
                        "{config:?}"
                    );
                }
            },
        );
    }

    /// A vector names the address of the underlay, and a neighbor dials that address. An
    /// underlay with no IP and no relay yet has none: a vector that names it points nowhere, so
    /// the tick says nothing until the underlay has one.
    #[test]
    fn the_link_state_arm_says_nothing_while_the_underlay_has_no_address() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                // A browser underlay: no IP socket, and a relay that it has not reached yet, so it
                // binds and has no address. (An endpoint with neither does not bind at all.) The relay
                // here is a listener that never answers.
                let (_silent, relay) = testing::silent_relay_rung();
                let secret = SecretKey::generate();
                let builder = Endpoint::builder(presets::Minimal)
                    .secret_key(underlay_secret(&secret))
                    .relay_mode(iroh::RelayMode::custom([relay]));
                let underlay: Endpoint = builder
                    .clear_ip_transports()
                    .bind()
                    .await
                    .expect("bind an underlay with no address yet");
                assert!(underlay.addr().addrs.is_empty(), "the premise: no address");
                assert!(
                    Box::pin(own_links_after_a_tick(
                        underlay,
                        &secret,
                        HandleConfig::default()
                    ))
                    .await
                    .is_empty(),
                    "no link of ours is advertised"
                );
            },
        );
    }

    /// A pair on the relay has the direct route dialed. The gate then refuses the
    /// destination as a first hop: the wake makes the pass dial the route through a
    /// third member within the same turn, without waiting for the stuck deadline and a
    /// link-state tick.
    #[test]
    fn a_refused_first_hop_moves_the_dial_of_a_pair_on_the_relay_to_a_route_through_a_third() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let node = LaneNode::start().await;
                let context = node.context();
                let mut state = node.state();
                let (me, via, dst) = (
                    multihop_handle().await,
                    multihop_handle().await,
                    multihop_handle().await,
                );
                assert!(
                    me.feed_topology(via.link_vector(vec![(dst.app_id(), 1)])),
                    "a refused first hop moves the relay dial to a route through a third peer"
                );
                assert!(
                    me.feed_topology(dst.link_vector(vec![])),
                    "the route through the third peer is fed to the topology"
                );
                assert!(
                    me.feed_topology(me.link_vector(vec![(dst.app_id(), 1), (via.app_id(), 1)])),
                    "the topology carries the route through the third peer"
                );
                state.multihop = Some(me.clone());
                state.note_peer_endpoint(nick("dst"), EndpointAddr::new(dst.app_id().get()));
                state.path_kinds.insert(dst.app_id().get(), PathKind::Relay);

                nudge_climbing_pairs(&mut state, &context, true);
                let dst_key = dst.app_id().get();
                let direct: TransportAddr = state
                    .route_dialed
                    .get(&dst_key)
                    .cloned()
                    .expect("the direct route is dialed");

                me.refuse_hop_for_test(dst.app_id());
                route_wake_arm(&mut state, &context);

                let dialed: TransportAddr = state
                    .route_dialed
                    .get(&dst_key)
                    .cloned()
                    .expect("a route is dialed");
                assert_ne!(dialed, direct, "the route through the third is dialed");
                assert_eq!(
                    Some(dialed),
                    me.route_addr(dst.app_id()).map(TransportAddr::Custom),
                    "and it is the route that the handle chooses now"
                );
                state.webrtc_admission.close();
                me.close().await;
                via.close().await;
                dst.close().await;
                node.endpoint.close().await;
            },
        );
    }
}

#[cfg(all(test, feature = "multihop"))]
mod advertised_changed_tests {
    use std::collections::HashSet;

    use iroh::{EndpointId, SecretKey};

    use super::{advertised_changed, advertised_links};

    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn a_node_that_advertised_nothing_yet_has_a_new_set() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            advertised_changed(None, &[(id(1), 10)]),
            "a node that advertised nothing has a new set"
        );
    }

    /// The links of a node come up 0.1 to 0.4 s apart. The vector of the second one must go
    /// out at once: held back to the tick, the route over its edge would wait 15 s.
    #[test]
    fn a_second_link_that_comes_up_is_a_new_set() {
        let _guard = ::habilis_network_test_tracing::init();
        let first = [(id(1), 10)];
        let both = [(id(1), 10), (id(2), 10)];
        assert!(
            advertised_changed(Some(&first), &both),
            "a second link that comes up is a new set"
        );
    }

    /// A round of the underlay that attached a session adds an edge without a gossip link: the
    /// set changes, and the vector follows the end of the round. Without a change, nothing goes.
    #[test]
    fn a_session_that_attached_is_a_new_set() {
        let _guard = ::habilis_network_test_tracing::init();
        let linked = HashSet::from([id(1)]);
        let before = advertised_links(&linked, &[], 10);
        let after = advertised_links(&linked, &[id(2)], 10);
        assert!(
            advertised_changed(Some(&before), &after),
            "a session that attached is a new set"
        );
        assert!(
            !advertised_changed(Some(&after), &after),
            "the same set after the attach is not new"
        );
    }

    /// A link that flaps and comes back leaves the set that went out: no second broadcast.
    #[test]
    fn a_link_that_comes_back_is_the_set_that_went_out() {
        let _guard = ::habilis_network_test_tracing::init();
        let both = [(id(1), 10), (id(2), 10)];
        assert!(
            !advertised_changed(Some(&both), &both),
            "a link that comes back does not change the set"
        );
    }
}

#[cfg(all(test, feature = "multihop"))]
mod advertised_links_tests {
    use std::collections::HashSet;

    use iroh::{EndpointId, SecretKey};

    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn sorted(mut links: Vec<(EndpointId, u32)>) -> Vec<(EndpointId, u32)> {
        links.sort_unstable();
        links
    }

    /// The route graph of every member is built from these links. A pair whose gossip dial
    /// was refused before its session, or whose gossip link the relay watcher closed, still
    /// has a session on the underlay that carries cells: without its edge, no route to the
    /// member exists, and the pair is locked out until the gossip link comes back.
    #[test]
    fn a_member_with_a_held_session_and_no_gossip_link_is_an_edge() {
        let _guard = ::habilis_network_test_tracing::init();
        let linked = HashSet::from([id(1)]);
        let links = super::advertised_links(&linked, &[id(2)], 10);
        assert_eq!(
            sorted(links),
            sorted(vec![(id(1), 10), (id(2), 10)]),
            "a held session with no gossip link is an edge"
        );
    }

    #[test]
    fn a_member_that_is_linked_and_held_is_one_edge() {
        let _guard = ::habilis_network_test_tracing::init();
        let linked = HashSet::from([id(1)]);
        let links = super::advertised_links(&linked, &[id(1)], 10);
        assert_eq!(
            links,
            vec![(id(1), 10)],
            "a linked and held member is one edge"
        );
    }

    #[test]
    fn with_no_held_session_the_edges_are_the_gossip_links() {
        let _guard = ::habilis_network_test_tracing::init();
        let linked = HashSet::from([id(1), id(2)]);
        let links = super::advertised_links(&linked, &[], 100);
        assert_eq!(
            sorted(links),
            sorted(vec![(id(1), 100), (id(2), 100)]),
            "with no held session the edges are the gossip links"
        );
    }
}

#[cfg(test)]
mod chain_tests {

    use super::EventLoopError;

    use std::io;
    use std::io::ErrorKind;
    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let io = io::Error::new(ErrorKind::AddrInUse, "Address already in use");
        let cause = anyhow::Error::new(io).context("bind the endpoint");
        let error = anyhow::Error::new(EventLoopError::internal(cause));
        let text = format!("{error:#}");
        assert!(
            text.contains("Address already in use"),
            "the io cause of EventLoopError is lost: {text}"
        );
    }
}
