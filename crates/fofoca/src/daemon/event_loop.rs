//! The `select!` event loop itself — the bulk of the daemon.
//!
//! [`run`] sets up per-session state then drives [`event_loop`], which
//! multiplexes external inputs (stdin / IPC / gossip), time-driven
//! maintenance (heartbeat, sweep, heal, anti-entropy, reclaim), and
//! shutdown. The orchestration lives here; the behavioral subsystems are
//! crate-root siblings (`crate::{gossip,lifecycle,beacon,lookup}`), and
//! the daemon-internal plumbing (`config`/`ctx`/`ipc`/`state`/`timers`/
//! `setup`) are siblings under `super`.

use std::time::Duration;

use anyhow::Result;
use futures_util::StreamExt;
use iroh::{Endpoint, EndpointId, RelayUrl};
use iroh_gossip::api::GossipReceiver;
use tokio::sync::{broadcast, mpsc, watch};

#[cfg(feature = "host")]
use crate::daemon::state_file::StateFile;
use crate::gossip::event::{NodeEvent, NodeSink};
use crate::protocol::mesh::MeshName;
use crate::protocol::{MeshId, Message, Nickname};
use crate::transport::IpcMessage;
use crate::transport::MeshSender;
use crate::util::clock::{Instant, millis_saturating};
// The timer-driver clock, distinct from `clock::Instant` off wasm32 (there it is
// `tokio::time::Instant`). Aliased rather than path-qualified, matching
// `daemon::state` / `daemon::app`.
use crate::util::tuning::{
    ALIVE_INTERVAL_SECS, LINKSTATE_INTERVAL_SECS, RECLAIM_INTERVAL_MS, STATE_REFRESH_SECS,
    antientropy_interval_secs, heal_interval_secs, sweep_interval_secs,
};
use n0_future::time::Instant as TokioInstant;
// Gated with `spawn_orphan_watch`, its only caller.
use crate::{beacon, gossip, lifecycle};

use super::app::NodeDriver;
use super::beacon_arm::{
    CohostArm, claims_at_startup, maybe_cohost, maybe_reclaim, probes_before_claim,
    release_rendezvous, schedule_rival_recheck, shed_rival_beacon_if_due,
};
use super::config::{CoHostPolicy, DriverMode, EventLoopConfig};
use super::ctx::HandlerCtx;
use super::heal::{GossipLink, ResubscribeEnv, apply_rung_change, resubscribe_tick, run_heal};
#[cfg(feature = "host")]
use super::shutdown::spawn_quit_signal_tasks;
use super::shutdown::{QuitParams, announce_and_maybe_exit, never_quit};
use super::state::{EventLoopState, MeshSecrets};
use super::timers;

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
#[expect(
    clippy::too_many_lines,
    reason = "session setup + secrets + sender/receiver wiring before handing off to event_loop; each step is a single call, and splitting further would only scatter sequential setup across helpers"
)]
pub async fn run<A: NodeDriver>(
    cfg: EventLoopConfig,
    app: A,
    session_rx: Option<mpsc::Receiver<A::Session>>,
    http_rx: Option<mpsc::Receiver<A::Http>>,
) -> Result<()> {
    let EventLoopConfig {
        topic,
        gossip,
        author,
        identity,
        mesh: mesh_str,
        name: mesh_name,
        topic_string,
        mesh_password,
        mesh_key,
        sink,
        mint_mesh,
        endpoint,
        router: _router,
        max_peers,
        rendezvous_params,
        rung_rx,
        rung_probe,
        cohost,
        runtime_base,
        state_file,
        #[cfg(feature = "host")]
        multihop,
        webrtc,
        webrtc_enabled,
        local_ip_transport,
        webrtc_admission,
        webrtc_ice,
        unicast_rx,
        live_count,
        relay_transport,
        driver,
        per_peer_gate,
    } = cfg;

    // Every driver-derived fact in one place. Only the CLI exits the
    // process on quit and binds the unix socket; in-process drivers
    // (in-process: library API or MCP) take typed requests on `session_rx` instead.
    let (external_quit_rx, external_msg_tx, ipc_listener_disabled, exit_on_quit, handle_signals) =
        match driver {
            DriverMode::Cli => (None, None, false, true, true),
            DriverMode::InProcess {
                msg_tx,
                quit_rx,
                handle_signals,
            } => (Some(quit_rx), msg_tx, true, false, handle_signals),
        };
    let external_req_rx = session_rx;

    let started = Instant::now();
    // CLI `create`/`join` daemons default their state file into the mesh's
    // runtime folder (`<prefix>/<nick>.state.json`, beside the socket + log)
    // when no `--state-file` override is given. In-process in-process sessions
    // (`!exit_on_quit`) keep writing nothing.
    // Host-only: a browser node has no filesystem to write the session file to.
    // The path is still carried on the config (a `PathBuf` costs nothing off
    // wasm), it is only the `StateFile` that cannot exist.
    #[cfg(feature = "host")]
    let state_file = state_file
        .or_else(|| {
            let base = runtime_base.as_deref()?;
            exit_on_quit.then(|| {
                crate::util::mesh_runtime_dir(base, mesh_str.as_str())
                    .join(format!("{author}.state.json"))
            })
        })
        .map(|path| {
            StateFile::new(path, &mesh_str, &author, &mesh_name)
                .with_base(runtime_base.clone())
                .with_topic(topic_string.as_deref())
        });
    #[cfg(not(feature = "host"))]
    drop(state_file);
    // The departure line's label: a topic gossip shows `topic` plus the raw
    // string it was derived from (the name is lossy, and the wording mirrors
    // the `joined topic …` startup line), every other gossip its `#name`.
    let leave_label = topic_string.map_or_else(
        || format!("#{mesh_name}"),
        |raw_topic| format!("topic {raw_topic}"),
    );
    // Seed the state file with the application's own discovery fields before
    // readiness is advertised — the local client reads them from this mode-600
    // file. What those fields are is the app's business; the engine only writes.
    #[cfg(feature = "host")]
    app.init_state_file(state_file.as_ref());
    let mut state = EventLoopState::new(
        crate::daemon::state::StateInit {
            #[cfg(feature = "host")]
            state_file,
            identity,
            secrets: MeshSecrets {
                password: mesh_password,
                key: mesh_key,
            },
            per_peer_gate,
            // The *same* table the Router's signal acceptor holds, not a fresh
            // one: the cap only counts if both roles count against it together.
            webrtc_admission,
            webrtc_ice,
        },
        started,
    );
    state.mint_mesh = mint_mesh; // creator-only: backs the `invite` command
    #[cfg(feature = "host")]
    {
        state.multihop = multihop; // `--multihop`: the registered transport's handle
    }
    // The direct-path transport the session manager fills; `None` leaves
    // every pair to iroh's own paths.
    state.webrtc = webrtc_enabled.then_some(webrtc);
    state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), relay_transport);
    // Before the first write, so the initial advertisement carries a real count.
    state.live_count = live_count;
    state.relay_transport = relay_transport;
    state.rendezvous_graft_needs_session =
        crate::transport::webrtc::node_graft_needs_session(relay_transport, local_ip_transport);
    state.local_ip_transport = local_ip_transport;
    // Direct-path probes report here; the loop grafts on the verdict.
    let (direct_tx, direct_rx) = mpsc::unbounded_channel();
    state.direct_proven = direct_tx;
    state.rendezvous_id = Some(rendezvous_params.id);
    state.write_peer_count();

    // An eager member co-hosts from t=0 so a beacon exists before any
    // joiner subscribes; everyone else defers to the heal gate
    // (`may_cohost`). `Eager` skips the probe (a brand-new mesh has no
    // peers to self-collide with); `EagerProbed` probes first, so several
    // advertisers sharing one directory `rendezvous_id` don't bind
    // duplicate copies. Why: `EventLoopConfig::cohost`.
    let mut rendezvous: Option<beacon::Rendezvous> = None;
    // The outstanding probe-before-claim, if any. Owned here beside the
    // beacon it decides, because a probe outlives the tick that started it:
    // its verdict arrives on the loop's own arm, up to `HEAL_PROBE_SECS`
    // later.
    let mut rival_probe: Option<beacon::RivalProbe> = None;
    if claims_at_startup(cohost) {
        let claimed = beacon::ensure(
            &rendezvous_params,
            &endpoint,
            &mut rendezvous,
            probes_before_claim(cohost),
            &mut rival_probe,
        )
        .await;
        if claimed {
            schedule_rival_recheck(&mut state, cohost, &rendezvous_params, &endpoint);
        }
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
    // `RECLAIM_INTERVAL_MS` instead, and stops as soon as the link is up.
    state.arm_reclaim(Instant::now());

    let (gossip_sender, receiver) = topic.split();

    let sender = MeshSender::new(gossip_sender);

    #[cfg(feature = "host")]
    let ipc_rx = spawn_ipc_rx::<A::Ipc>(
        ipc_listener_disabled,
        runtime_base.as_deref(),
        &mesh_str,
        &author,
        &sink,
    );
    // A browser binds no control socket. The loop keeps its IPC `select!` arm —
    // `IpcMessage` is portable — and the arm simply never fires.
    #[cfg(not(feature = "host"))]
    let ipc_rx: Option<mpsc::Receiver<IpcMessage<A::Ipc>>> = {
        drop(runtime_base);
        None
    };

    // Arrival announce is deferred to the first `NeighborUp` — see
    // `gossip::handle_gossip_event`.

    let intervals = build_maintenance_intervals().await;
    // A session inside a foreground command that owns its own lifetime
    // (a `--advertise` transfer, a directory browse) must not register
    // process-wide signal handlers — doing so suppresses the OS
    // default-terminate forever and the host command stops dying on
    // ctrl-c. Give the loop a quit channel that never fires instead;
    // shutdown comes from `external_quit_rx` / drop. A browser is always this
    // case: there are no process signals to listen for.
    #[cfg(feature = "host")]
    let quit_rx = if handle_signals {
        spawn_quit_signal_tasks(exit_on_quit)
    } else {
        never_quit()
    };
    #[cfg(not(feature = "host"))]
    let quit_rx = {
        let _ = handle_signals;
        never_quit()
    };

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
        state.ready = true;
        state.write_peer_count();
        sink.emit(NodeEvent::Ready {
            mesh: mesh_str.clone(),
            name: mesh_name.clone(),
            nickname: author.clone(),
        });
    }

    // `_router` stays owned in this scope so its accept loop outlives
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
        cohost,
        started,
        external_quit_rx,
        external_req_rx,
        external_msg_tx,
        quit_rx,
        exit_on_quit,
        http_rx,
        unicast_rx: Some(unicast_rx),
        direct_rx,
    }))
    .await
}

/// The alive tick: note the gap, then broadcast the keepalive presence.
async fn alive_arm(anchors: &mut TickAnchors, state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    timers::note_tick_gap(
        "alive",
        &mut anchors.alive,
        &mut anchors.alive_wall,
        Duration::from_secs(ALIVE_INTERVAL_SECS),
    );
    lifecycle::heartbeat::tick_alive(state, ctx.sender, ctx.mesh, ctx.author).await;
}

/// The anti-entropy tick: note the gap, advertise the chat digest, then both
/// channel digests, so peers can request anything we hold that they miss.
async fn antientropy_arm(
    anchors: &mut TickAnchors,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) {
    timers::note_tick_gap(
        "antientropy",
        &mut anchors.antientropy,
        &mut anchors.antientropy_wall,
        Duration::from_secs(antientropy_interval_secs()),
    );
    gossip::antientropy::broadcast_digest(state, ctx.sender, ctx.mesh, ctx.author).await;
    gossip::antientropy::broadcast_state_digests(state, ctx.sender, ctx.mesh, ctx.author).await;
}

/// Default per-link routing cost we advertise for our own neighbours until live
/// telemetry (RTT / delivery) is wired into the multihop metric.
#[cfg(feature = "host")]
const MULTIHOP_LINK_COST: u32 = 10;

/// The multihop link-state tick: re-broadcast our own links (one per direct
/// neighbour, carrying our underlay dial address) so every peer keeps a fresh
/// routing graph for the multihop transport. No-op until meshed, or when the
/// multihop transport is off — a vector with no consumer helps no one.
/// Off a host the multihop transport does not exist, so the tick has nothing to
/// broadcast. A no-op stub rather than a `cfg` at the `select!` arm, so the loop
/// body reads the same on both targets.
#[cfg(not(feature = "host"))]
#[expect(
    clippy::unused_async,
    reason = "the `host` body awaits; the signatures must match so the select! arm reads the same on both targets"
)]
async fn linkstate_arm(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    let _ = (state, ctx);
}

#[cfg(feature = "host")]
async fn linkstate_arm(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    if !state.meshed || state.multihop.is_none() {
        return;
    }
    state.link_state_seq += 1;
    let seq = state.link_state_seq;
    let links: Vec<_> = state
        .linked_endpoints
        .iter()
        .map(|eid| (*eid, MULTIHOP_LINK_COST))
        .collect();
    let handle = state.multihop.as_ref().expect("checked above");
    let vector = handle.link_vector(seq, links);
    // Fold our own vector into our own routing table: gossip never loops a
    // broadcast back, and without our outbound edges the local graph can't
    // source a route (`route_to(self, …)` would always be empty).
    handle.feed_topology(vector.clone());
    let Some(body) = gossip::json_body(&vector) else {
        return;
    };
    state.idle.broadcasts += 1;
    // Retained locally for the same reason the vector is fed into our own
    // routing table above: gossip never loops a broadcast back. Every tick
    // mints a fresh `seq`, so an unretained vector is one more message our
    // peers re-send to us on every anti-entropy round for as long as the log
    // holds it (see `gossip::recv::retain_own_broadcast`).
    let vector_msg = Message::new_link_state(ctx.mesh, ctx.author, body).signed(&state.identity);
    gossip::broadcast_msg(ctx.sender, &vector_msg).await;
    gossip::retain_own_broadcast(state, &vector_msg);
}

/// The sweep-tick arm: note the gap, then evict silent peers. The app's own
/// timers that ride this cadence run via [`NodeDriver::on_tick`] right after.
fn sweep_arm(anchors: &mut TickAnchors, state: &mut EventLoopState, sink: &dyn NodeSink) {
    timers::note_tick_gap(
        "sweep",
        &mut anchors.sweep,
        &mut anchors.sweep_wall,
        Duration::from_secs(sweep_interval_secs()),
    );
    lifecycle::heartbeat::tick_sweep(state, sink);
}

/// Owned working set for [`event_loop`]. `run` does setup, fills this,
/// and hands it over; the loop destructures it back into the same
/// locals the orchestrator used to hold inline. Splitting the 11-arm
/// `select!` out keeps both functions within the readability budget
/// (clippy `too_many_lines`) without an `#[allow]`.
struct EventLoop<A: NodeDriver> {
    sender: MeshSender,
    receiver: GossipReceiver,
    /// The gossip frontend, kept so the loop can re-subscribe the topic
    /// after the stream terminally ends (see the heal arm) — without it
    /// a closed subscription (e.g. lag-evicted by the actor) would
    /// leave the daemon permanently deaf.
    gossip: iroh_gossip::net::Gossip,
    endpoint: Endpoint,
    mesh: MeshId,
    name: MeshName,
    /// The departure line's label: the raw topic string for a topic
    /// gossip (the derived name is lossy), `#name` otherwise.
    leave_label: String,
    author: Nickname,
    sink: std::sync::Arc<dyn NodeSink>,
    max_peers: usize,
    state: EventLoopState,
    /// Application state behind the [`NodeDriver`] seam, disjoint from the mesh
    /// `state` and threaded as its own `&mut` through the app callbacks.
    app: A,
    ipc_rx: Option<mpsc::Receiver<IpcMessage<A::Ipc>>>,
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
    rung_probe: Option<crate::lookup::StoppableTask>,
    /// When this member may serve the rendezvous (see [`CoHostPolicy`]).
    cohost: CoHostPolicy,
    /// Event-loop start, for the unmeshed-joiner co-host grace.
    started: Instant,
    external_quit_rx: Option<mpsc::Receiver<()>>,
    /// The in-process typed session channel (in-process: library API or MCP); `None` on the CLI.
    external_req_rx: Option<mpsc::Receiver<A::Session>>,
    external_msg_tx: Option<broadcast::Sender<Message>>,
    quit_rx: mpsc::Receiver<()>,
    exit_on_quit: bool,
    /// The application's localhost HTTP binding request channel; `None` off.
    http_rx: Option<mpsc::Receiver<A::Http>>,
    /// Inbound unicast frames from the `UNICAST_ALPN` acceptor, drained into
    /// `gossip::ingest` (same validation + dedup path as gossip). `Option` so
    /// the `select!` arm can disable itself if the channel ever closes.
    unicast_rx: Option<mpsc::Receiver<bytes::Bytes>>,
    /// Direct-path probe verdicts (`transport::probe`). Never closes: `state`
    /// holds a sender for the loop's lifetime.
    direct_rx: mpsc::UnboundedReceiver<crate::transport::probe::DirectOutcome>,
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
        target: "fofoca::lifecycle",
        version = crate::util::version::build_version(),
        nickname = %author,
        "daemon starting"
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "the daemon's central select! loop: one arm per event source (ipc, http, gossip, the maintenance ticks, quit); each arm delegates to a helper, but the arm list itself is irreducibly long"
)]
async fn event_loop<A: NodeDriver>(loop_state: EventLoop<A>) -> Result<()> {
    let EventLoop {
        mut sender,
        mut receiver,
        gossip,
        endpoint,
        mesh: mesh_str,
        name: mesh_name,
        leave_label,
        author,
        sink,
        max_peers,
        mut state,
        mut app,
        mut ipc_rx,
        mut intervals,
        mut rendezvous,
        mut rival_probe,
        mut rendezvous_params,
        mut rung_rx,
        mut rung_probe,
        cohost,
        started,
        mut external_quit_rx,
        mut external_req_rx,
        external_msg_tx,
        mut quit_rx,
        exit_on_quit,
        mut http_rx,
        mut unicast_rx,
        mut direct_rx,
    } = loop_state;

    log_daemon_start(&author);

    // The surfaced-events ring (`poll`/`fetch` history) lives app-side, fed by
    // the tap the caller attached to `output` before handing it in (both this
    // `output` and the app's own `Output` are clones of that one tapped sink,
    // so events interleave in surfacing order). The loop drives the ring
    // through the app's `drain_surfaced` / poll-deadline hooks — the engine
    // never names the ring's element type.

    let mut anchors = TickAnchors::now();

    // Owned Arc clone so the per-arm ctx can borrow it without colliding with `&mut state`.
    let identity = state.identity.clone();
    // Our own pubkey hex, computed once for the per-message self-echo compare.
    let our_pubkey = crate::protocol::identity::encode_pubkey(&identity.public());
    // Everything a HandlerCtx needs *except* the sender. The ctx itself
    // is built per-arm (`parts.ctx(&sender)`) rather than once out here:
    // a loop-lifetime ctx would borrow `sender` forever, and the
    // resubscribe path must replace `sender`/`receiver` when the gossip
    // stream ends.
    let parts = CtxParts {
        endpoint: &endpoint,
        mesh: &mesh_str,
        author: &author,
        identity: identity.as_ref(),
        our_pubkey: &our_pubkey,
        max_peers,
        rendezvous_id: rendezvous_params.id,
        external_msg_tx: external_msg_tx.as_ref(),
        sink: sink.as_ref(),
    };

    // Consecutive failed resubscribe attempts (reset on success); at
    // `RESUBSCRIBE_MAX_ATTEMPTS` the gossip actor itself is gone and the
    // daemon shuts down rather than pretend to be a live member.
    let mut resubscribe_attempts: u32 = 0;

    {
        let ctx = parts.ctx(&sender);
        app.on_startup(&mut state, &ctx).await;
        crate::transport::webrtc::offer_rendezvous_at_start(&mut state, &ctx);
    }

    loop {
        tokio::select! {
            () = sleep_until_opt(state.ping_round.as_ref().map(|round| round.deadline)) => {
                state.idle.external += 1;
                finalize_ping_round(&mut state, sink.as_ref());
            }
            () = sleep_until_opt(app.earliest_poll_deadline()) => {
                state.idle.external += 1;
                app.poll_deadline_elapsed();
            }
            () = sleep_until_opt(app.earliest_deadline()) => {
                state.idle.external += 1;
                app.expire_deadlines(TokioInstant::now());
            }
            ipc_msg = recv_opt(&mut ipc_rx) => match ipc_msg {
                None => ipc_rx = None,
                Some((cmd, resp_tx)) => {
                    state.idle.external += 1;
                    let ctx = parts.ctx(&sender);
                    let req = super::app::IpcRequest {
                        cmd,
                        resp: resp_tx,
                        name: &mesh_name,
                    };
                    if app.handle_ipc(req, &mut state, &ctx).await {
                        state.last_sent_at = Instant::now();
                    }
                }
            },
            http_req = recv_opt(&mut http_rx) => match http_req {
                None => http_rx = None,
                Some(req) => {
                    state.idle.external += 1;
                    let ctx = parts.ctx(&sender);
                    app.handle_http(req, &mut state, &ctx).await;
                }
            },
            event = receiver.next(), if state.gossip_open => {
                state.idle.external += 1;
                let ctx = parts.ctx(&sender);
                gossip::handle_gossip_event(event, &mut state, &mut app, &ctx).await;
            }
            Some(outcome) = direct_rx.recv() => {
                state.idle.external += 1;
                let ctx = parts.ctx(&sender);
                crate::transport::probe::on_outcome(outcome, &mut state, &ctx).await;
            }
            // Inbound unicast rides the *same* validate + dedup path as gossip (`ingest`).
            frame = recv_opt(&mut unicast_rx) => match frame {
                Some(bytes) => {
                    state.idle.external += 1;
                    gossip::ingest(bytes, &mut state, &mut app, &parts.ctx(&sender)).await;
                }
                None => unicast_rx = None,
            },
            _ = intervals.prune.tick() => {
                state.idle.prune += 1;
                timers::tick_prune(&mut state, sink.as_ref());
            }
            _ = intervals.alive.tick() => {
                state.idle.alive += 1;
                let ctx = parts.ctx(&sender);
                alive_arm(&mut anchors, &mut state, &ctx).await;
                // Retry WebRTC negotiation for any peer we still have no
                // session with. Without this a pair gets exactly one attempt
                // ever: negotiation fires on `PeerInfo`, and once the pair is
                // linked, `PeerInfo` stops re-flooding — so a first attempt
                // lost to a transient (the peer not yet reachable, an ICE
                // hiccup) is never retried, and the pair stays relay-only for
                // the life of the link. Observed exactly that, CLI↔browser.
                crate::transport::webrtc::retry_sessions(&mut state, &ctx);
                // Same cadence for the direct-path probes a lookup-only relay
                // holds grafts on: a peer whose punch missed the deadline, or
                // whose session attached since, gets another look.
                crate::transport::probe::retry_direct(&mut state, &ctx, false).await;
            }
            _ = intervals.sweep.tick() => {
                state.idle.sweep += 1;
                sweep_arm(&mut anchors, &mut state, sink.as_ref());
                let ctx = parts.ctx(&sender);
                app.on_tick(&mut state, &ctx).await;
            }
            _ = intervals.heal.tick() => {
                state.idle.heal += 1;
                let (mono_gap, wall_gap) = timers::note_tick_gap("heal", &mut anchors.heal, &mut anchors.heal_wall, Duration::from_secs(heal_interval_secs()));
                if state.gossip_open {
                    let ctx = parts.ctx(&sender);
                    run_heal(TickGap { mono: mono_gap, wall: wall_gap }, &mut state, &ctx, &rendezvous_params).await;
                    maybe_cohost(&mut state, &ctx, &CohostArm { policy: cohost, params: &rendezvous_params, started }, &mut rendezvous, &mut rival_probe).await;
                } else {
                    // Stream ended: resubscribe instead of healing a dead topic
                    // (see `resubscribe_tick`); the beacon keeps the mesh joinable.
                    // The loop's one error exit, and it must release the
                    // beacon on the way out for the same reason the normal
                    // one does — see `release_rendezvous`.
                    if let Err(error) = resubscribe_tick(
                        &ResubscribeEnv { gossip: &gossip, params: &rendezvous_params, parts: &parts, exit_on_quit },
                        &mut state,
                        &mut app,
                        GossipLink { sender: &mut sender, receiver: &mut receiver, attempts: &mut resubscribe_attempts },
                    ).await {
                        release_rendezvous(&mut rendezvous, &mut rival_probe, &mut rung_probe).await;
                        return Err(error);
                    }
                    let ctx = parts.ctx(&sender);
                    maybe_cohost(&mut state, &ctx, &CohostArm { policy: cohost, params: &rendezvous_params, started }, &mut rendezvous, &mut rival_probe).await;
                }
            }
            // A bootstrap rung chosen off-loop (startup probe / beacon self-monitor); apply it cheaply.
            // `Ok(())` only: a closed channel (impossible while the beacon params live) disables the arm.
            // Counted `external`: like the probe verdict below it is beacon
            // work driven from off-loop, not by one of our maintenance tickers,
            // and it is silent on a settled daemon — so `external` still reads
            // 0 when idle while `wakeups` stays equal to the column sum.
            Ok(()) = rung_rx.changed() => {
                state.idle.external += 1;
                apply_rung_change(&mut state, &mut rendezvous_params, &endpoint, &mut rendezvous, &rung_rx);
            }
            // The off-loop probe-before-claim answered. Its own arm rather
            // than a poll at the next heal tick: the probe already cost up to
            // `HEAL_PROBE_SECS`, and making a free rendezvous wait out another
            // 15s interval before anyone binds it would hand back the claim
            // latency this change was meant to leave untouched.
            found_rival = beacon::probe_verdict(&mut rival_probe) => {
                state.idle.external += 1;
                // One free verdict is not enough to claim: a live beacon's
                // rival re-check periodically releases the rendezvous to
                // re-probe it, and a probe landing inside that window reads
                // "free" while a holder is about to re-bind. Claiming on it
                // stands up a rival copy, and two copies shed each other
                // longer than most joins are willing to wait. Two frees in a
                // row (the next reclaim tick re-probes) squares those odds
                // away; a genuinely dead beacon costs one extra probe round.
                if !found_rival && !state.rendezvous_probe_read_free {
                    state.rendezvous_probe_read_free = true;
                } else {
                    state.rendezvous_probe_read_free = false;
                    let claimed = beacon::claim_after_probe(&rendezvous_params, &endpoint, &mut rendezvous, found_rival).await;
                    if claimed {
                        // Still from the brisk base: two joiners that start
                        // together both read free twice and claim in the same
                        // instant, and the first re-check is what merges that
                        // split.
                        schedule_rival_recheck(&mut state, cohost, &rendezvous_params, &endpoint);
                        // The new rendezvous never dials us; the reclaim tick re-grafts it.
                        state.arm_reclaim(Instant::now());
                    } else if found_rival {
                        // A rival holds the identity: this arbitration epoch is
                        // settled, so a later claim (the rival died) starts the
                        // re-check backoff from its brisk base again.
                        state.rival_recheck_rounds = 0;
                    }
                }
            }
            _ = intervals.reclaim.tick() => {
                state.idle.reclaim += 1;
                let ctx = parts.ctx(&sender);
                let arm = CohostArm { policy: cohost, params: &rendezvous_params, started };
                // The rival re-check shed rides this ticker, NOT the heal tick:
                // simultaneous joiners' heal tickers align, and a shed deadline
                // quantized to a shared multi-second boundary re-synchronizes
                // the very sheds whose ms-scale phase offsets must differ for
                // one holder to catch the other still up (observed lockstep:
                // both shed within 5ms, both probe into the gap, both re-bind,
                // forever). At this cadence the offsets survive; the next tick
                // (~RECLAIM_INTERVAL_MS later, after the dropped endpoint has
                // unmapped) runs the re-probe via `maybe_reclaim`.
                if !shed_rival_beacon_if_due(&mut state, &arm, &mut rendezvous) {
                    maybe_reclaim(&mut state, &ctx, &arm, &mut rendezvous, &mut rival_probe).await;
                }
            }
            _ = intervals.antientropy.tick() => {
                state.idle.antientropy += 1;
                let ctx = parts.ctx(&sender);
                antientropy_arm(&mut anchors, &mut state, &ctx).await;
            }
            // Counted before the census reads them, so the tick that reports an
            // interval is itself in that interval's numbers.
            _ = intervals.state_refresh.tick() => {
                state.idle.state_refresh += 1;
                timers::tick_state_refresh(&mut state, &endpoint).await;
            }
            _ = intervals.linkstate.tick() => {
                state.idle.linkstate += 1;
                let ctx = parts.ctx(&sender);
                linkstate_arm(&mut state, &ctx).await;
            }
            _ = recv_opt(&mut external_quit_rx) => {
                // External quit is always in-process (MCP): never hard-exit (`false`).
                let ctx = parts.ctx(&sender);
                announce_and_maybe_exit(&mut state, &mut app, &ctx, QuitParams { name: &mesh_name, leave_label: &leave_label, exit_on_quit: false }).await;
                break;
            }
            req = recv_opt(&mut external_req_rx) => match req {
                None => external_req_rx = None,
                Some(req) => {
                    state.idle.external += 1;
                    let ctx = parts.ctx(&sender);
                    if app.handle_session(req, &mut state, &ctx).await {
                        state.last_sent_at = Instant::now();
                    }
                }
            },
            _ = quit_rx.recv() => {
                let ctx = parts.ctx(&sender);
                announce_and_maybe_exit(&mut state, &mut app, &ctx, QuitParams { name: &mesh_name, leave_label: &leave_label, exit_on_quit }).await;
                break;
            }
        }
        state.idle.wakeups += 1;
        app.drain_surfaced();
    }

    release_rendezvous(&mut rendezvous, &mut rival_probe, &mut rung_probe).await;
    Ok(())
}

/// Resolve the IPC receiver: reuse a pre-wired channel (MCP / library API) or,
/// for the CLI, spawn the unix-socket listener and own the channel.
/// Returning `Option` keeps the loop's `select!` arm uniform.
///
/// `disabled` is set by the in-process drivers (library API / MCP), which use
/// the typed `session_rx` and bind no socket.
#[cfg(feature = "host")]
fn spawn_ipc_rx<C: serde::de::DeserializeOwned + Send + 'static>(
    disabled: bool,
    runtime_base: Option<&std::path::Path>,
    mesh: &MeshId,
    author: &Nickname,
    sink: &std::sync::Arc<dyn NodeSink>,
) -> Option<mpsc::Receiver<IpcMessage<C>>> {
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
    let listener = match crate::transport::ipc::bind(base, mesh, author) {
        Ok(listener) => listener,
        Err(error) => {
            sink.emit(NodeEvent::Error(format!("IPC: {error}")));
            tracing::warn!(%error, "IPC: failed to bind socket");
            return None;
        }
    };
    let (ipc_tx, rx) = mpsc::channel::<IpcMessage<C>>(32);
    tokio::spawn(crate::transport::ipc::serve::<C>(
        listener,
        ipc_tx,
        std::sync::Arc::clone(sink),
    ));
    Some(rx)
}

/// Sleep until a ping round's deadline, or pend forever when no round
/// is active. Lets the event loop's `select!` carry a ping-finalize arm
/// that only fires while a round is in flight, without borrowing
/// `state` across the await (the deadline is copied out beforehand).
async fn sleep_until_opt(deadline: Option<TokioInstant>) {
    match deadline {
        Some(at) => n0_future::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
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
        .iter()
        .map(|(nickname, arrival)| {
            let rtt_ms = millis_saturating(arrival.duration_since(round.t1));
            (nickname.clone(), rtt_ms)
        })
        .collect();
    peers.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
    // The in-process `ping` request waits on this channel (no event stream to
    // read the report from); the CLI/IPC path leaves it unset and consumes the
    // `ping_report` event below instead.
    if let Some(resp) = round.resp {
        let _ = resp.send(peers.clone());
    }
    // `known` must never be less than the number that responded: a peer can
    // pong and then leave the roster before this ~10s finalize, which would
    // otherwise report responded > known. Clamp so the count stays coherent.
    let known = state.peers.len().max(peers.len());
    sink.emit(NodeEvent::PingReport { peers, known });
}

/// A tick's elapsed-time gap on both clocks: monotonic (throttle-blind) and
/// wall (the only one a macOS suspend shows up on) — see [`is_resume`] /
/// [`is_wall_resume`].
#[derive(Clone, Copy)]
pub(super) struct TickGap {
    pub(super) mono: Duration,
    pub(super) wall: Duration,
}

/// Per-timer gap anchors; the heal gap also drives the resume-edge hard
/// re-bootstrap. Each timer carries a monotonic anchor AND a wall-clock
/// anchor: on macOS the monotonic clock pauses in lockstep with a
/// sleeping process, so only the wall gap reveals a suspend (see
/// `note_tick_gap` / `run_heal`).
struct TickAnchors {
    alive: Instant,
    sweep: Instant,
    heal: Instant,
    antientropy: Instant,
    alive_wall: i64,
    sweep_wall: i64,
    heal_wall: i64,
    antientropy_wall: i64,
}

impl TickAnchors {
    fn now() -> Self {
        let mono = Instant::now();
        let wall = crate::util::clock::unix_secs();
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

/// Everything a [`HandlerCtx`] needs except the gossip sender. The loop
/// holds one of these and builds the ctx per-arm (`parts.ctx(&sender)`):
/// a loop-lifetime ctx would borrow `sender` forever, and the
/// resubscribe path must be able to replace it.
pub(super) struct CtxParts<'a> {
    pub(super) endpoint: &'a Endpoint,
    pub(super) mesh: &'a MeshId,
    pub(super) author: &'a Nickname,
    pub(super) identity: &'a crate::protocol::identity::Identity,
    pub(super) our_pubkey: &'a str,
    pub(super) max_peers: usize,
    pub(super) rendezvous_id: EndpointId,
    pub(super) external_msg_tx: Option<&'a broadcast::Sender<Message>>,
    pub(super) sink: &'a dyn NodeSink,
}

impl<'a> CtxParts<'a> {
    pub(super) fn ctx<'b>(&'b self, sender: &'b MeshSender) -> HandlerCtx<'b>
    where
        'a: 'b,
    {
        HandlerCtx {
            sender,
            endpoint: self.endpoint,
            mesh: self.mesh,
            author: self.author,
            identity: self.identity,
            our_pubkey: self.our_pubkey,
            max_peers: self.max_peers,
            rendezvous_id: self.rendezvous_id,
            external_msg_tx: self.external_msg_tx,
            sink: self.sink,
        }
    }
}

/// The time-driven maintenance tickers.
struct MaintenanceIntervals {
    prune: n0_future::time::Interval,
    alive: n0_future::time::Interval,
    sweep: n0_future::time::Interval,
    heal: n0_future::time::Interval,
    /// Fast event-driven failover burst; only does work while
    /// `state.reclaim_until` is open (armed on `NeighborDown`).
    reclaim: n0_future::time::Interval,
    /// Periodic anti-entropy digest broadcast (recover messages missed
    /// while partitioned/asleep).
    antientropy: n0_future::time::Interval,
    state_refresh: n0_future::time::Interval,
    /// Periodic relay link-state re-broadcast (our own measured links), so peers
    /// keep a fresh routing graph.
    linkstate: n0_future::time::Interval,
}

/// Build the maintenance tickers, eating the first immediate tick on
/// the ones that must wait a full period (we just announced `Joined`).
///
/// Every ticker uses [`MissedTickBehavior::Skip`]: after the monotonic clock
/// jumps (an App Nap throttle, a SIGSTOP freeze), a default `Burst` ticker
/// fires a catch-up salvo — several anti-entropy digests back-to-back, a
/// heal immediately after the hard re-bootstrap it just ran, a prune replaying
/// its backlog — and poisons the tick-gap telemetry (the burst ticks report a
/// ~0 gap). Each tick here means "do the maintenance now", so a skipped tick is
/// free; `Skip` collapses the salvo to one tick on the next aligned boundary.
async fn build_maintenance_intervals() -> MaintenanceIntervals {
    use n0_future::time::MissedTickBehavior::Skip;

    let mut prune = n0_future::time::interval(Duration::from_mins(1));
    prune.set_missed_tick_behavior(Skip);
    let mut alive = n0_future::time::interval(Duration::from_secs(ALIVE_INTERVAL_SECS));
    alive.set_missed_tick_behavior(Skip);
    alive.tick().await;
    let mut sweep = n0_future::time::interval(Duration::from_secs(sweep_interval_secs()));
    sweep.set_missed_tick_behavior(Skip);
    sweep.tick().await;
    let mut heal = n0_future::time::interval(Duration::from_secs(heal_interval_secs()));
    heal.set_missed_tick_behavior(Skip);
    heal.tick().await;
    let mut reclaim = n0_future::time::interval(Duration::from_millis(RECLAIM_INTERVAL_MS));
    reclaim.set_missed_tick_behavior(Skip);
    reclaim.tick().await;
    let mut antientropy =
        n0_future::time::interval(Duration::from_secs(antientropy_interval_secs()));
    antientropy.set_missed_tick_behavior(Skip);
    antientropy.tick().await;
    let mut state_refresh = n0_future::time::interval(Duration::from_secs(STATE_REFRESH_SECS));
    state_refresh.set_missed_tick_behavior(Skip);
    state_refresh.tick().await;
    let mut linkstate = n0_future::time::interval(Duration::from_secs(LINKSTATE_INTERVAL_SECS));
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
async fn recv_opt<T>(rx: &mut Option<mpsc::Receiver<T>>) -> Option<T> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {}
