//! The relay leg of the lookup layer: the default **relay ladder** (n0
//! prod), how a [`RelayChoice`] maps to an iroh [`RelayMode`] of one rung, and the
//! deterministic "home on the first reachable rung" bootstrap selection
//! plus its steady-state failover decision.
//!
//! Why a ladder (vs a single pinned relay, or iroh's latency-pick over
//! the set): the cold-join bootstrap needs every member to meet at the
//! *same* relay, and iroh does not reliably race multiple relay
//! candidates in an `EndpointAddr`. So members agree on a fixed order
//! and home on the first reachable rung — under equal relay visibility
//! that is a global function, so all converge on the same rung and fail
//! over together. The public analog of the private loopback-port ladder
//! (`beacon::RendezvousParams::bind_ports`).

use std::future;
mod default_rung;
mod return_watch;
mod rung_decision;
mod rung_follower;
mod rung_path;
mod rung_refresh;
mod stoppable_task;

use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use futures_util::future as future_util;
use futures_util::stream::FuturesUnordered;
use iroh::defaults::DEFAULT_RELAY_QUIC_PORT;
use iroh::endpoint::{RelayStatus, presets};
use iroh::{Endpoint, RelayConfig, RelayMode, RelayUrl, Watcher};
use tokio::sync::watch;

pub use default_rung::DefaultRung;
pub(crate) use rung_decision::{Generation, RungDecision};
use rung_follower::RungFollower;
pub use rung_path::RungPath;
pub(crate) use rung_refresh::RungRefresh;
pub(crate) use stoppable_task::StoppableTask;

use crate::protocol::meshes::RelayChoice;
use crate::util::tuning::{
    RELAY_LIVENESS_FAILS_TO_EVICT, RELAY_LIVENESS_INTERVAL, RELAY_REPROBE_BACKOFF_MAX,
    RELAY_REPROBE_BACKOFF_MIN, RELAY_RETURN_HOLD, RELAY_RETURN_PROBE_INTERVAL, RELAY_RUNG_PROBE,
    RELAY_RUNG_STAGGER,
};
use n0_future::time::Instant;
use n0_future::{task as n0future_task, time as n0future_time};

/// The default relay **ladder** — n0's prod relay set, in fixed
/// preference order. The beacon homes on the first reachable rung
/// (`select_bootstrap_rung`) and the joiner pre-registers
/// `rendezvous_id` at that same rung — `EndpointAddr::new(rendezvous_id)
/// .with_relay_url(rung)` — for a **zero-address-lookup** relay-direct
/// dial: a creator-independent bootstrap that needs no address lookup to
/// reach the rendezvous.
///
/// Rungs 0..3 are our relays, 1 URL for each relay host and path. That must
/// stay so: iroh opens one relay session per URL, a dial to a peer homed on
/// another rung opens a session on that rung too, and a relay drops the older
/// session of an endpoint id, so 2 URLs of one relay process make an endpoint
/// drop its own session. Rung 0 is direct: it answers QUIC address discovery,
/// so a member homed on it learns its public address. Rungs 1 and 2 are
/// tunnels, and a tunnel host has no direct name: the tunnel carries no UDP,
/// so they answer no QUIC address discovery, and an endpoint that asked them
/// for it would wait 3 s for its first net report. Rungs 3..7 are iroh
/// `defaults::prod`, which are direct.
///
/// Hardcoded, **not** `defaults::prod::default_relay_map()`, so members on
/// different iroh versions still agree on the *same* ladder. Relay infra is
/// versioned and not cross-compatible (sendme #121): an iroh bump can move
/// `defaults::prod` off these hosts. `pinned_ladder_matches_iroh_prod` is
/// the tripwire: it fails on such a move so we review the n0 rungs before
/// the bump ships.
pub const RENDEZVOUS_RELAY_LADDER: &[DefaultRung] = &[
    // No trailing-dot FQDN on any rung. Safari rejects the certificate of a
    // dotted host, so a browser member could reach none of them. Our tunnel
    // rungs have a second reason: the tunnel routes by exact Host header and
    // 404s the dotted form (including the /relay websocket upgrade).
    DefaultRung {
        url: "https://nyc-relay1.agent-habilis.com/",
        path: DIRECT,
    },
    DefaultRung {
        url: "https://nyc-relay2.habilis.network/",
        path: RungPath::Tunnel,
    },
    DefaultRung {
        url: "https://slz-relay1.habilis.network/",
        path: RungPath::Tunnel,
    },
    DefaultRung {
        url: "https://use1-1.relay.n0.iroh.link/",
        path: DIRECT,
    },
    DefaultRung {
        url: "https://usw1-1.relay.n0.iroh.link/",
        path: DIRECT,
    },
    DefaultRung {
        url: "https://euc1-1.relay.n0.iroh.link/",
        path: DIRECT,
    },
    DefaultRung {
        url: "https://aps1-1.relay.n0.iroh.link/",
        path: DIRECT,
    },
];

/// The path of a direct rung of the default ladder: QUIC address discovery on the default port.
const DIRECT: RungPath = RungPath::Direct {
    qad_port: DEFAULT_RELAY_QUIC_PORT,
};

/// The relay config of each rung of the default ladder, parsed once.
static RENDEZVOUS_RELAY_LADDER_CONFIGS: LazyLock<Vec<RelayConfig>> = LazyLock::new(|| {
    RENDEZVOUS_RELAY_LADDER
        .iter()
        .map(|rung| {
            let url: RelayUrl = rung
                .url()
                .parse()
                .expect("RENDEZVOUS_RELAY_LADDER entries are valid relay URL constants");
            config_with_qad(url, rung.path().qad_port())
        })
        .collect()
});

/// The URLs of the default ladder, in order. `RelayUrl` clones are `Arc`-backed (cheap).
static RENDEZVOUS_RELAY_LADDER_URLS: LazyLock<Vec<RelayUrl>> = LazyLock::new(|| {
    RENDEZVOUS_RELAY_LADDER_CONFIGS
        .iter()
        .map(|config| config.url.clone())
        .collect()
});

/// Resolve a [`RelayChoice`] into the ordered relay **ladder**:
/// `Disabled` ⇒ empty (no relay), `Pinned` ⇒ the default ladder
/// ([`RENDEZVOUS_RELAY_LADDER`]: our fleet, then the n0 prod rungs), `Custom` ⇒ the operator ladder (`--relay a,b,c`, order
/// preserved). The beacon homes on, and the joiner pre-registers at, the
/// first reachable rung (`select_bootstrap_rung`) — the beacon leg of
/// `peer_relay_mode` and `daemon::setup::register_rendezvous` must agree or
/// the relay-direct bootstrap dial finds nothing.
///
/// # Examples
///
/// A disabled relay choice has no relay on its ladder.
///
/// ```
/// use habilis_network::net::relay_ladder;
/// use habilis_network::protocol::meshes::RelayChoice;
///
/// assert_eq!(relay_ladder(&RelayChoice::Disabled).count(), 0);
/// ```
pub fn relay_ladder(choice: &RelayChoice) -> impl Iterator<Item = RelayUrl> {
    let rungs = match choice {
        RelayChoice::Pinned => RENDEZVOUS_RELAY_LADDER_URLS.clone(),
        RelayChoice::Custom(ladder) => ladder.clone(),
        RelayChoice::Disabled | _ => Vec::new(),
    };
    rungs.into_iter()
}

/// The relay config of one rung, with the QUIC address discovery that the relay answers. An
/// endpoint that asks a relay for QUIC address discovery that it does not answer holds its first
/// net report until the 3 s probe timeout of iroh, and has no home relay until then.
///
/// The setting belongs to the relay, so it follows the URL: a rung of the default ladder takes its
/// [`RungPath`] wherever a ladder names it, a one-rung custom ladder of the beacon too. A custom
/// ladder is URLs only, on the wire and in the API, so a custom rung that the default ladder does
/// not name takes the rule of its scheme. An `https://` rung asks for QUIC address discovery on
/// the default port. An `http://` rung has no TLS, and QUIC needs TLS, so it asks for none.
fn rung_config(url: &RelayUrl) -> RelayConfig {
    if let Some(config) = RENDEZVOUS_RELAY_LADDER_CONFIGS
        .iter()
        .find(|config| config.url == *url)
    {
        return config.clone();
    }
    let qad_port = (url.scheme() == "https").then_some(DEFAULT_RELAY_QUIC_PORT);
    config_with_qad(url.clone(), qad_port)
}

/// The relay config of `url`, with QUIC address discovery on `qad_port`, or none. The QUIC config
/// of iroh has no public constructor here, so the port is set on the one that `RelayConfig::from`
/// makes.
fn config_with_qad(url: RelayUrl, qad_port: Option<u16>) -> RelayConfig {
    let mut config = RelayConfig::from(url);
    let template = config.quic.take();
    config.quic = qad_port.and_then(|port| {
        template.map(|mut quic| {
            quic.port = port;
            quic
        })
    });
    config
}

/// The relay mode of an endpoint homed on `rung` alone, or with no relay. An endpoint never holds 2
/// rungs in its map: iroh homes on the relay with the lowest latency, not on the first one.
fn one_rung_mode(rung: Option<&RelayUrl>) -> RelayMode {
    let Some(rung) = rung else {
        tracing::debug!("relay disabled (not in the lookup allowlist)");
        return RelayMode::Disabled;
    };
    tracing::debug!(relay = %rung, "endpoint homed on one relay rung");
    RelayMode::Custom([rung_config(rung)].into_iter().collect())
}

/// The relay mode of a peer endpoint, and the ladder it must follow when its rung does not connect.
///
/// iroh homes on the relay with the lowest latency and ignores the order of the map, so a map
/// that holds the whole ladder does not make rung 0 the home. A peer homes the way the beacon
/// does: on one rung, alone in its map. The bind does not wait for a probe: the endpoint starts on
/// rung 0, and [`Homing::follow`] moves it to the first reachable rung when rung 0 does not
/// connect. A one-rung ladder has no choice to make, and an empty one has no relay: neither gets a
/// [`Homing`]. The beacon homes on its rung through a one-rung ladder.
pub(super) fn peer_relay_mode(choice: &RelayChoice) -> (RelayMode, Option<Homing>) {
    let ladder: Vec<RelayUrl> = relay_ladder(choice).collect();
    let mode = one_rung_mode(ladder.first());
    let homing: Option<RelayUrl> = ladder.first().filter(|_| ladder.len() > 1).cloned();
    (mode, homing.map(|rung| Homing { ladder, rung }))
}

/// The ladder of a peer endpoint, and the rung that it homes on.
#[derive(Debug)]
pub(super) struct Homing {
    ladder: Vec<RelayUrl>,
    rung: RelayUrl,
}

/// The times of a member that follows its ladder, as parameters so that a test runs it in seconds.
#[derive(Debug, Clone, Copy)]
struct HomingTimes {
    /// The window of one probe of a rung.
    probe: Duration,
    /// How often the member reads the liveness of its rung.
    interval: Duration,
    /// How often a member on a later rung probes the rungs below it, while one of them answers.
    return_every: Duration,
    /// The longest wait between 2 return rounds that found no lower rung.
    return_backoff_max: Duration,
    /// How long a lower rung must answer every probe round before the member returns to it.
    return_hold: Duration,
}

impl HomingTimes {
    /// The times of a real member.
    const LIVE: Self = Self {
        probe: RELAY_RUNG_PROBE,
        interval: RELAY_LIVENESS_INTERVAL,
        return_every: RELAY_RETURN_PROBE_INTERVAL,
        return_backoff_max: RELAY_REPROBE_BACKOFF_MAX,
        return_hold: RELAY_RETURN_HOLD,
    };
}

impl Homing {
    /// Follow the ladder until the endpoint closes ([`follow_rung`]). The endpoint swaps its own
    /// relay map in place, because a peer endpoint cannot be rebuilt under its owner.
    pub(super) fn follow(self, endpoint: Endpoint) {
        drop(self.follow_with(endpoint, HomingTimes::LIVE));
    }

    /// [`Self::follow`] with its times as parameters. It returns the task, which ends when the
    /// endpoint closes.
    fn follow_with(self, endpoint: Endpoint, times: HomingTimes) -> n0future_task::JoinHandle<()> {
        n0future_task::spawn(async move {
            follow_rung(
                &endpoint,
                &self.ladder,
                self.rung,
                times,
                Mover::InPlace,
                None,
            )
            .await;
        })
    }
}

/// What a member does with a rung that its follower picks.
#[derive(Debug, Clone, Copy)]
enum Mover<'tx> {
    /// A peer endpoint moves its own relay map, and keeps following.
    InPlace,
    /// The beacon publishes the rung. The event loop re-homes the beacon on it, and starts a new
    /// follower, so this one ends.
    Publish(&'tx watch::Sender<RungDecision>, Generation),
}

/// Follow the ladder from `rung` until the endpoint closes or `stop`'s sender is dropped. The peer
/// endpoint and the beacon run this one loop, and differ only in their [`Mover`].
///
/// A rung is alive when the status of the home relay says that the relay connection is up, and,
/// off the browser, the net report of iroh still has a preferred relay. Neither signal is enough
/// alone. A relay that answers its HTTP probe and refuses the relay connection can keep a preferred
/// relay but has no connection. A relay that dies keeps its connection in the status for minutes,
/// and the probes of the net report find it dead. A browser has no net report, so the status alone
/// decides there. A rung that has not connected when the probe time of a rung ends counts as dead
/// at once. A later read counts one failure per interval. After [`RELAY_LIVENESS_FAILS_TO_EVICT`]
/// failures in a row, the member walks the ladder.
///
/// A walk that finds no rung (a full outage: a sleep, Wi-Fi off) keeps the member on its rung, the
/// peer and the beacon alike. The next failed reads walk again, and the first rung that comes back
/// wins. The beacon is not demoted to no relay: that would drop its endpoint and wait out the
/// backoff of the relay-less monitor (30 s to 5 min) after the outage, while the peers stay. The
/// rendezvous address names every rung, so a beacon on its dead rung costs a joiner nothing.
///
/// On a later rung, the member probes the rungs below it each [`RELAY_RETURN_PROBE_INTERVAL`], in a
/// task beside the liveness reads, so a slow round never holds back a read. It returns to the
/// lowest rung that answered every round for [`RELAY_RETURN_HOLD`]. A round that finds no lower
/// rung doubles the wait to the next round, up to [`RELAY_REPROBE_BACKOFF_MAX`].
async fn follow_rung(
    endpoint: &Endpoint,
    ladder: &[RelayUrl],
    rung: RelayUrl,
    times: HomingTimes,
    mover: Mover<'_>,
    stop: Option<&watch::Receiver<()>>,
) {
    let mut status = endpoint.home_relay_status();
    let connected_at_start = tokio::select! {
        connected = n0future_time::timeout(
            times.probe,
            wait_for_home_connection(&mut status, &rung),
        ) => matches!(connected, Ok(true)),
        () = ended(endpoint, stop) => return,
    };
    let mut follower = RungFollower::new(ladder, rung, times, connected_at_start, Instant::now());
    let mut round: Option<ReturnRound> = None;
    loop {
        if let Some(walk) = follower.walk_due() {
            cancel_round(&mut round).await;
            let selected = walk_until_ended(endpoint, stop, |walk_stopped| async move {
                select_bootstrap_rung(&walk, times.probe, Some(&walk_stopped)).await
            })
            .await;
            if is_ended(endpoint, stop) {
                return;
            }
            match follower.walked(selected, Instant::now()) {
                Some(next) => {
                    let Some(next) = mover.take(endpoint, follower.rung(), next, "next").await
                    else {
                        return;
                    };
                    follower.moved(next, Instant::now());
                }
                None => {
                    tracing::info!(target: "habilis_network::lookup", relay = %follower.rung(), "the walk found no other relay rung; staying on it");
                }
            }
        }
        let until_read = follower.read_at().saturating_duration_since(Instant::now());
        match next_wake(until_read, &mut round, endpoint, stop).await {
            Wake::Read => {
                let alive =
                    home_connected(&status.get(), follower.rung()) && probes_answer(endpoint);
                follower.read(alive, Instant::now());
            }
            Wake::Round(answered, ended_at) => {
                if let Some(lower) = follower.round_ended(&answered, ended_at, Instant::now()) {
                    let Some(next) = mover.take(endpoint, follower.rung(), lower, "lower").await
                    else {
                        return;
                    };
                    follower.moved(next, Instant::now());
                }
            }
            Wake::Ended => {
                cancel_round(&mut round).await;
                return;
            }
        }
        if let Some(below) = follower.round_due(Instant::now()) {
            round = Some(ReturnRound::spawn(below, times.probe));
        }
    }
}

/// What the follower waited for between 2 passes of its loop.
enum Wake {
    /// The next liveness read is due.
    Read,
    /// The return round ended: the rungs that answered, and the time at which it ended.
    Round(Vec<RelayUrl>, Instant),
    /// The endpoint closed, or the stop was given.
    Ended,
}

/// Wait until a read is due, the return round ends, or the follower ends. An end wins over a round
/// that ended with it: a follower that was stopped (its beacon was shed) acts on nothing.
async fn next_wake(
    until_read: Duration,
    round: &mut Option<ReturnRound>,
    endpoint: &Endpoint,
    stop: Option<&watch::Receiver<()>>,
) -> Wake {
    tokio::select! {
        biased;
        () = ended(endpoint, stop) => Wake::Ended,
        (answered, ended_at) = round_answers(round) => Wake::Round(answered, ended_at),
        () = n0future_time::sleep(until_read) => Wake::Read,
    }
}

impl Mover<'_> {
    /// Take `next` in place of `rung`. Returns the rung that the follower goes on with, or `None`
    /// when the follower ends. `kind` names the move in the log: the next rung, or a lower one.
    async fn take(
        self,
        endpoint: &Endpoint,
        rung: &RelayUrl,
        next: RelayUrl,
        kind: &str,
    ) -> Option<RelayUrl> {
        match self {
            Self::InPlace => {
                tracing::info!(target: "habilis_network::lookup", from = %rung, to = %next, kind, "peer endpoint moves to another relay rung");
                // The relay actor of iroh shares the config of a relay.
                let config = Arc::new(rung_config(&next));
                endpoint.insert_relay(next.clone(), config).await;
                endpoint.remove_relay(rung).await;
                Some(next)
            }
            Self::Publish(rung_tx, generation) => {
                tracing::info!(target: "habilis_network::lookup", from = %rung, to = %next, kind, "beacon moves to another relay rung");
                let _ = rung_tx.send(RungDecision {
                    from: Some(generation),
                    rung: Some(next),
                });
                None
            }
        }
    }
}

/// One probe round of the rungs below the home, in a task of its own beside the liveness reads.
#[derive(Debug)]
struct ReturnRound {
    stop: watch::Sender<()>,
    /// The rungs that answered, and the time at which the round ended.
    task: n0future_task::JoinHandle<(Vec<RelayUrl>, Instant)>,
}

impl ReturnRound {
    /// Start a round that probes each of `below`.
    fn spawn(below: Vec<RelayUrl>, probe: Duration) -> Self {
        let (stop, stopped) = watch::channel(());
        let task = n0future_task::spawn(async move {
            let answered = probe_lower_rungs(&below, probe, &stopped).await;
            (answered, Instant::now())
        });
        Self { stop, task }
    }
}

/// The rungs that answered the round in flight, and the time at which it ended, once it ends. A
/// round that panicked answers none, at the time that it is read. Never resolves without a round.
async fn round_answers(round: &mut Option<ReturnRound>) -> (Vec<RelayUrl>, Instant) {
    let Some(running) = round.as_mut() else {
        return future::pending().await;
    };
    let ended = (&mut running.task)
        .await
        .unwrap_or_else(|_| (Vec::new(), Instant::now()));
    *round = None;
    ended
}

/// Stop the round in flight, and wait until its probes have closed their endpoints.
async fn cancel_round(round: &mut Option<ReturnRound>) {
    if let Some(ReturnRound { stop, task }) = round.take() {
        drop(stop);
        drop(task.await);
    }
}

/// The wait before the next return round. A round that found a lower rung keeps the rounds at
/// `return_every`, so the hold is counted. A round that found none doubles the wait, up to
/// `return_backoff_max`: a member on a later rung while the lower rungs stay down probes them ever
/// more sparsely. The first wait is the return interval of 1 minute, above the 30 s floor of the
/// relay-less backoff, so the floor plays no part here.
fn next_return_wait(current: Duration, found: bool, times: HomingTimes) -> Duration {
    if found {
        times.return_every
    } else {
        current.saturating_mul(2).min(times.return_backoff_max)
    }
}

/// Resolves once `endpoint` closes, or once `stop`'s sender is dropped.
async fn ended(endpoint: &Endpoint, stop: Option<&watch::Receiver<()>>) {
    tokio::select! {
        _closed = endpoint.closed() => {}
        () = stopped(stop.cloned()) => {}
    }
}

/// Whether `endpoint` closed, or `stop`'s sender is gone.
fn is_ended(endpoint: &Endpoint, stop: Option<&watch::Receiver<()>>) -> bool {
    endpoint.is_closed() || stop.is_some_and(is_stopped)
}

/// Run `walk` with a stop that fires when `endpoint` closes or `stop`'s sender is dropped, and
/// return what it selects. On an end the walk still ends, and closes its probe endpoints, before
/// this returns.
async fn walk_until_ended<Walk, Fut>(
    endpoint: &Endpoint,
    stop: Option<&watch::Receiver<()>>,
    walk: Walk,
) -> Option<RelayUrl>
where
    Walk: FnOnce(watch::Receiver<()>) -> Fut,
    Fut: Future<Output = Option<RelayUrl>>,
{
    let (stop_walk, stopped_walk) = watch::channel(());
    let walking = walk(stopped_walk);
    tokio::pin!(walking);
    tokio::select! {
        selected = &mut walking => selected,
        () = ended(endpoint, stop) => {
            drop(stop_walk);
            walking.await;
            None
        }
    }
}

/// Probe each of `rungs` at once, and return the rungs that answered, in their order. Each rung
/// that answers counts, not only the lowest one, so that a rung that flaps does not hold back a
/// steady rung above it ([`return_watch::ReturnWatch`]). Once `stop`'s sender is dropped, every probe ends and
/// closes its endpoint before this returns.
async fn probe_lower_rungs(
    rungs: &[RelayUrl],
    probe: Duration,
    stop: &watch::Receiver<()>,
) -> Vec<RelayUrl> {
    let probes = rungs
        .iter()
        .map(|rung| relay_rung_reachable(rung, probe, Some(stop.clone())));
    let answers: Vec<bool> = future_util::join_all(probes).await;
    let mut answered = Vec::new();
    let paired = rungs.iter().zip(answers);
    for (rung, answer) in paired {
        if answer {
            answered.push(rung.clone());
        }
    }
    answered
}

/// The rungs of `ladder` below `home`. Empty when `home` is rung 0, or is not on the ladder.
fn rungs_below<'ladder>(ladder: &'ladder [RelayUrl], home: &RelayUrl) -> &'ladder [RelayUrl] {
    let position = ladder.iter().position(|rung| rung == home).unwrap_or(0);
    ladder.get(..position).unwrap_or_default()
}

/// The rungs that a walk probes: the whole ladder, or without `rung` when it never connected.
fn rungs_to_walk(ladder: &[RelayUrl], rung: &RelayUrl, skip_rung: bool) -> Vec<RelayUrl> {
    ladder
        .iter()
        .filter(|other| !skip_rung || *other != rung)
        .cloned()
        .collect()
}

/// Whether the last net report of the endpoint has a preferred relay, or none has run yet.
#[cfg(not(target_arch = "wasm32"))]
fn probes_answer(endpoint: &Endpoint) -> bool {
    endpoint
        .net_report()
        .get()
        .is_none_or(|report| report.preferred_relay.is_some())
}

/// A browser has no net report: the status of the home relay decides alone. A relay that dies keeps
/// its connection in the status for minutes, so a browser peer stays on a dead rung for that long.
#[cfg(target_arch = "wasm32")]
fn probes_answer(_endpoint: &Endpoint) -> bool {
    true
}

/// Whether the endpoint holds a live relay connection to `rung`.
fn home_connected(statuses: &[RelayStatus], rung: &RelayUrl) -> bool {
    statuses
        .iter()
        .any(|status| status.url() == rung && status.is_connected())
}

/// Wait until the endpoint holds a live relay connection to `rung`. `false` once the watcher ends.
async fn wait_for_home_connection(
    status: &mut impl Watcher<Value = Vec<RelayStatus>>,
    rung: &RelayUrl,
) -> bool {
    loop {
        if home_connected(&status.get(), rung) {
            return true;
        }
        if status.updated().await.is_err() {
            return false;
        }
    }
}

/// Walk a relay ladder and return the first **reachable** rung
/// — the deterministic bootstrap relay every member converges on under
/// equal visibility. Reachability is "an endpoint pinned to this single
/// relay reaches `online()` within `per_rung`": iroh pings the relay and
/// only reports online once a home relay is chosen, so a successful
/// `online()` against a one-relay `RelayMode` *is* that rung being live.
///
/// The walk starts the probe of each rung [`RELAY_RUNG_STAGGER`] after the one
/// below it, or at once when the rung below says no. A healthy rung 0 answers
/// before rung 1 starts, so the later rungs see no probe. A ladder of silent
/// rungs costs one window of `per_rung` plus the staggers, not one window for
/// each rung. Eight concurrent probes cost about the CPU of eight probes in
/// order, and about 80 sockets at the peak.
///
/// `None` ⇒ the ladder is empty (relay disabled) or every rung was
/// unreachable; the caller then leans on mDNS/DHT (the other reliability
/// layers). Also `None` once `stop`'s sender is dropped: the walk ends
/// early, but every probe endpoint is still closed before this returns.
pub(crate) async fn select_bootstrap_rung(
    ladder: &[RelayUrl],
    per_rung: Duration,
    stop: Option<&watch::Receiver<()>>,
) -> Option<RelayUrl> {
    let probe = |rung: RelayUrl, probes_stopped| async move {
        let reachable = relay_rung_reachable(&rung, per_rung, Some(probes_stopped)).await;
        if !reachable {
            tracing::debug!(target: "habilis_network::lookup", relay = %rung, "bootstrap relay rung did not answer");
        }
        reachable
    };
    let selected = select_first_reachable(ladder, stop, RELAY_RUNG_STAGGER, probe).await;
    match &selected {
        Some(rung) => {
            tracing::info!(target: "habilis_network::lookup", relay = %rung, "selected bootstrap relay rung");
        }
        None if !ladder.is_empty() => {
            tracing::info!(target: "habilis_network::lookup", rungs = ladder.len(), "no relay ladder rung reachable; relying on mDNS/DHT");
        }
        None => {}
    }
    selected
}

/// The pure ladder walk behind [`select_bootstrap_rung`]: start the probe of
/// rung 0 at once, and of each later rung `stagger` after the one before it,
/// or at once when a rung says no. Return the lowest rung for which
/// `reachable` is `true`, else `None`. A rung wins only when every rung
/// below it said no, so a lower rung that answers late still beats a higher
/// rung that answers early. That is what makes the selection deterministic
/// across members, and what makes a recovered earlier rung win over a later
/// one on every (re)selection.
///
/// A rung that answered while a lower rung was still silent has waited for it, and can be offline
/// by the time that the lower rung says no. The walk asks that rung again before it takes it, and
/// falls through to the next rung if it says no. A rung whose own answer arrives after every rung
/// below it said no is taken at once: rung 0 is one probe.
///
/// Each probe gets a receiver whose sender the walk drops once it decides, or
/// once `stop`'s sender is dropped. The walk then starts no more probes and
/// waits for every probe to end, so no probe outlives it. Generic over the
/// reachability probe so the order logic is unit tested without touching the
/// network.
async fn select_first_reachable<Probe, Fut>(
    ladder: &[RelayUrl],
    stop: Option<&watch::Receiver<()>>,
    stagger: Duration,
    mut reachable: Probe,
) -> Option<RelayUrl>
where
    Probe: FnMut(RelayUrl, watch::Receiver<()>) -> Fut,
    Fut: Future<Output = bool>,
{
    use futures_util::StreamExt as _;

    let (stop_probes, probes_stopped) = watch::channel(());
    let mut stop_probes = Some(stop_probes);
    let mut probes = FuturesUnordered::new();
    let mut unstarted = ladder.iter().enumerate();
    let mut next_start = Instant::now();
    let mut answers: Vec<Option<bool>> = vec![None; ladder.len()];
    let mut selected = None;
    loop {
        let may_start = stop_probes.is_some() && unstarted.len() > 0;
        if may_start && (probes.is_empty() || Instant::now() >= next_start) {
            if let Some((index, rung)) = unstarted.next() {
                let probe = reachable(rung.clone(), probes_stopped.clone());
                probes.push(answer_of(index, probe));
            }
            next_start = Instant::now() + stagger;
            continue;
        }
        if probes.is_empty() {
            return selected;
        }
        let until_next_start = next_start.saturating_duration_since(Instant::now());
        let next = tokio::select! {
            next = probes.next() => next,
            () = n0future_time::sleep(until_next_start), if may_start => continue,
            () = stopped(stop.cloned()), if stop_probes.is_some() => {
                stop_probes = None;
                continue;
            }
        };
        let Some((index, answer)) = next else {
            continue;
        };
        if let Some(slot) = answers.get_mut(index) {
            *slot = Some(answer);
        }
        if !answer {
            next_start = Instant::now();
        }
        if stop_probes.is_none() {
            continue;
        }
        match lowest_reachable(&answers) {
            WalkVerdict::Waiting => {}
            // The rung answered itself, with every rung below it already said no: its answer is
            // fresh.
            WalkVerdict::Rung(lowest) if lowest == index => {
                selected = ladder.get(lowest).cloned();
                stop_probes = None;
            }
            // A rung below said no after this one answered, and the answer waited behind it. The
            // rung can be offline now, as the old walk, which probed one rung after the other,
            // would have found: ask it again, and take the rung above if it says no.
            WalkVerdict::Rung(lowest) => {
                if let Some(rung) = ladder.get(lowest)
                    && let Some(slot) = answers.get_mut(lowest)
                {
                    *slot = None;
                    let probe = reachable(rung.clone(), probes_stopped.clone());
                    probes.push(answer_of(lowest, probe));
                }
            }
            WalkVerdict::NoRung => stop_probes = None,
        }
    }
}

/// The answer of one probe, with the index of the rung that it probed.
async fn answer_of(index: usize, probe: impl Future<Output = bool>) -> (usize, bool) {
    (index, probe.await)
}

/// What the answers of a walk so far decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkVerdict {
    /// A rung below the first answer has not answered yet.
    Waiting,
    /// The lowest rung that answered, now that every rung below it said no.
    Rung(usize),
    /// Every rung said no.
    NoRung,
}

/// What the answers of a walk so far decide, rung by rung from the first.
fn lowest_reachable(answers: &[Option<bool>]) -> WalkVerdict {
    let Some(first_open) = answers.iter().position(|answer| *answer != Some(false)) else {
        return WalkVerdict::NoRung;
    };
    if answers.get(first_open) == Some(&Some(true)) {
        WalkVerdict::Rung(first_open)
    } else {
        WalkVerdict::Waiting
    }
}

/// Probe every rung of `ladder` for reachability, in order, returning each
/// rung's online status. Unlike `select_bootstrap_rung` this does **not**
/// short-circuit at the first reachable rung — `doctor --mesh` shows the full
/// ladder's health, not just the bootstrap pick.
///
/// # Examples
///
/// It probes each relay of a ladder and reports which ones answer. The doc test compiles it but does not run it.
///
/// ```no_run
/// use std::time::Duration;
///
/// use habilis_network::iroh::RelayUrl;
/// use habilis_network::net::probe_ladder;
///
/// # async fn demo(ladder: &[RelayUrl]) -> usize {
/// probe_ladder(ladder, Duration::from_secs(1)).await.count()
/// # }
/// ```
pub async fn probe_ladder(
    ladder: &[RelayUrl],
    per_rung: Duration,
) -> impl Iterator<Item = (RelayUrl, bool)> {
    let mut statuses = Vec::with_capacity(ladder.len());
    for rung in ladder {
        let reachable = relay_rung_reachable(rung, per_rung, None).await;
        statuses.push((rung.clone(), reachable));
    }
    statuses.into_iter()
}

/// The relay mode of a probe endpoint: this one rung, without QUIC address discovery. The probe
/// asks whether the relay answers. When the QUIC port of the relay is out of reach (behind a
/// proxy, or blocked), the first net report waits for the 3 s probe timeout of iroh, and
/// `online()` with it: 4 s for each probe, against 0.4 s without the discovery.
fn probe_relay_mode(rung: &RelayUrl) -> RelayMode {
    let mut config = rung_config(rung);
    config.quic = None;
    RelayMode::Custom([config].into_iter().collect())
}

/// Probe a single relay rung: bind an ephemeral endpoint pinned to just
/// this relay and wait for `online()` within `timeout`, or until `stop`'s
/// sender is dropped. Closes the probe endpoint before returning either way.
async fn relay_rung_reachable(
    rung: &RelayUrl,
    timeout: Duration,
    stop: Option<watch::Receiver<()>>,
) -> bool {
    if stop.as_ref().is_some_and(is_stopped) {
        return false;
    }
    let Ok(endpoint) = Endpoint::builder(presets::Minimal)
        .relay_mode(probe_relay_mode(rung))
        .bind()
        .await
    else {
        return false;
    };
    let reachable = tokio::select! {
        online = n0future_time::timeout(timeout, endpoint.online()) => online.is_ok(),
        () = stopped(stop) => false,
    };
    endpoint.close().await;
    reachable
}

/// Resolves once `stop`'s sender is dropped; never without a `stop`.
async fn stopped(stop: Option<watch::Receiver<()>>) {
    match stop {
        Some(mut stop) => while stop.changed().await.is_ok() {},
        None => future::pending().await,
    }
}

/// Whether `stop`'s sender is gone.
fn is_stopped(stop: &watch::Receiver<()>) -> bool {
    stop.has_changed().is_err()
}

/// Compare the freshly-selected rung against the one we are homed on.
/// Pure (no IO, no beacon/relay-enabled gating — that is the caller's
/// concern) so the change-detection policy is unit-tested directly:
/// `Rehome` iff the rung differs (the current one died, an earlier
/// preferred one recovered, or every rung is now down → `Rehome(None)`).
#[must_use]
pub(crate) fn plan_rung_refresh(
    current: Option<&RelayUrl>,
    selected: Option<RelayUrl>,
) -> RungRefresh {
    if selected.as_ref() == current {
        RungRefresh::NoChange
    } else {
        RungRefresh::Rehome(selected)
    }
}

/// Debounce for the beacon's rung-liveness self-monitor: should
/// `consecutive_fails` failed `online()` polls count as the rung being
/// gone? `>=` [`RELAY_LIVENESS_FAILS_TO_EVICT`] so a single transient
/// blip (iroh auto-reconnects its home relay within a tick) is ignored
/// and only a sustained outage triggers a re-walk. Pure, so the
/// threshold behaviour is unit-tested without the network.
fn should_evict_rung(consecutive_fails: u32) -> bool {
    consecutive_fails >= RELAY_LIVENESS_FAILS_TO_EVICT
}

/// The next inter-round backoff for the relay-less rediscovery loop:
/// double `current`, saturating at [`RELAY_REPROBE_BACKOFF_MAX`].
/// The first wait is [`RELAY_REPROBE_BACKOFF_MIN`] (the caller
/// seeds `current` with it); thereafter the beacon keeps re-walking the
/// ladder forever, just ever more sparsely while every rung stays down.
/// Pure, so the progression is unit-tested.
fn next_relay_backoff(current: Duration) -> Duration {
    let max = RELAY_REPROBE_BACKOFF_MAX;
    current.saturating_mul(2).min(max)
}

/// Spawn the relay-rung liveness/discovery monitor — one per co-hosted
/// beacon, run as its **own** task so relay probes never stall the
/// gossip co-host or the event loop. It **never stops probing**:
///
/// - **Homed** (`home`, the rung the event loop homed the beacon on):
///   follow the ladder with the signal and the times of a peer endpoint
///   ([`follow_rung`]). On a sustained outage, re-walk the ladder once and
///   publish the rung it picks; the event loop re-homes the beacon on it.
///   A walk that picks the same rung, or finds no rung, publishes nothing,
///   and the beacon goes on following on its rung. On a later rung, publish the lowest rung below it
///   once it answered every round for [`RELAY_RETURN_HOLD`]. The
///   rendezvous address names every rung, so a joiner still reaches the
///   beacon while it moves.
/// - **Relay-less** (no rung): re-walk the ladder; a reachable rung ⇒
///   publish it; an empty round ⇒ back off ([`next_relay_backoff`]) and
///   loop.
///
/// Every publish flows to the event loop's rung-update arm, which
/// re-homes the beacon (drop + rebuild) — spawning a fresh monitor for
/// the new state. So the monitor returns after publishing a change, or
/// once `beacon::Rendezvous` stops it, publishing nothing.
#[must_use]
pub(crate) fn spawn_relay_monitor(
    endpoint: Endpoint,
    ladder: Vec<RelayUrl>,
    rung_tx: watch::Sender<RungDecision>,
    home: Option<RelayUrl>,
    generation: Generation,
) -> StoppableTask {
    StoppableTask::spawn(|stop| async move {
        let mover = Mover::Publish(&rung_tx, generation);
        match home {
            Some(home) => {
                follow_rung(
                    &endpoint,
                    &ladder,
                    home,
                    HomingTimes::LIVE,
                    mover,
                    Some(&stop),
                )
                .await;
            }
            None => {
                monitor_relay_less(&ladder, &rung_tx, generation, RELAY_RUNG_PROBE, &stop).await;
            }
        }
    })
}

/// Relay-less: keep re-walking the ladder to rediscover a rung, backing off
/// after each fruitless round so an all-down ladder isn't hammered. Never
/// stops. Split out of [`spawn_relay_monitor`] so the loop body is not
/// nested in its spawned future.
async fn monitor_relay_less(
    ladder: &[RelayUrl],
    rung_tx: &watch::Sender<RungDecision>,
    generation: Generation,
    probe: Duration,
    stop: &watch::Receiver<()>,
) {
    let mut backoff = RELAY_REPROBE_BACKOFF_MIN;
    loop {
        let selected = select_bootstrap_rung(ladder, probe, Some(stop)).await;
        if is_stopped(stop) {
            return;
        }
        if let Some(rung) = selected {
            tracing::info!(
                target: "habilis_network::lookup",
                relay = %rung,
                "relay-less beacon rediscovered a reachable rung"
            );
            let _ = rung_tx.send(RungDecision {
                from: Some(generation),
                rung: Some(rung),
            });
            return;
        }
        tokio::select! {
            () = n0future_time::sleep(backoff) => {}
            () = stopped(Some(stop.clone())) => return,
        }
        backoff = next_relay_backoff(backoff);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RELAY_LIVENESS_FAILS_TO_EVICT, RENDEZVOUS_RELAY_LADDER_URLS, RelayChoice, RelayUrl,
        RungDecision, RungRefresh, next_relay_backoff, plan_rung_refresh, relay_ladder,
        select_bootstrap_rung, select_first_reachable, should_evict_rung,
    };
    use crate::lookup::{TransportOpts, build_peer_endpoint, build_peer_webrtc};
    use crate::protocol::meshes::LookupOpts;
    use iroh::defaults::DEFAULT_RELAY_QUIC_PORT;
    use iroh::{RelayMode, Watcher as _};
    use iroh_relay::server::Server;
    use n0_future::task as n0future_task;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::net::{TcpListener as AsyncListener, TcpStream};
    use tokio::sync::watch;
    use tokio::task::JoinHandle;

    use crate::lookup::test_relay;
    use crate::util::tuning;
    use iroh::endpoint::{Builder, presets};
    use std::cell;
    use std::time::Duration as std_Duration;
    use tokio::time;
    /// Tripwire: the last rungs of our pinned rendezvous ladder must stay
    /// equal to iroh's `defaults::prod` relay hosts, **in order** (NA-east
    /// first). The rungs before them are our own fleet and are excluded here.
    /// Relay infra is versioned and not cross-compatible (sendme #121); if an
    /// iroh bump moves a prod relay off these hosts, the relay-direct bootstrap
    /// silently breaks for members on a different iroh version. Failing here
    /// forces a manual review (are these hosts still served?) before the bump
    /// ships.
    #[test]
    fn pinned_ladder_matches_iroh_prod() {
        use iroh::defaults::prod;
        let _guard = ::habilis_network_test_tracing::init();
        let expected = [
            prod::NA_EAST_RELAY_HOSTNAME,
            prod::NA_WEST_RELAY_HOSTNAME,
            prod::EU_RELAY_HOSTNAME,
            prod::AP_RELAY_HOSTNAME,
        ];
        let fleet_rungs = RENDEZVOUS_RELAY_LADDER_URLS.len() - expected.len();
        let ours: Vec<&str> = RENDEZVOUS_RELAY_LADDER_URLS
            .iter()
            .skip(fleet_rungs)
            .map(|url| {
                url.host_str()
                    .expect("ladder relay URL has a host")
                    .trim_end_matches('.')
            })
            .collect();
        let theirs: Vec<&str> = expected
            .iter()
            .map(|host| host.trim_end_matches('.'))
            .collect();
        assert_eq!(
            ours, theirs,
            "RENDEZVOUS_RELAY_LADDER drifted from iroh's prod relay set \
             (sendme #121): review the RENDEZVOUS_RELAY_LADDER doc comment before bumping iroh"
        );
    }

    /// Every member homes on the first reachable rung, so rung 0 carries the
    /// bootstrap load of every mesh on the default ladder. It is a direct rung,
    /// so a member homed on it learns its public address.
    #[test]
    fn rung_zero_is_a_direct_rung_with_qad() {
        let _guard = ::habilis_network_test_tracing::init();
        let rung_zero = &RENDEZVOUS_RELAY_LADDER_URLS[0];
        assert_eq!(
            rung_zero.as_str(),
            "https://nyc-relay1.agent-habilis.com/",
            "rung 0 of the default ladder"
        );
        assert_eq!(
            qad_port(rung_zero),
            Some(DEFAULT_RELAY_QUIC_PORT),
            "rung 0 asks for QUIC address discovery on the default port"
        );
    }

    /// The QUIC address discovery port of the relay config of a rung, if any.
    fn qad_port(url: &RelayUrl) -> Option<u16> {
        super::rung_config(url).quic.map(|quic| quic.port)
    }

    /// **The default ladder, in order, with the QUIC address discovery of each rung.**
    ///
    /// A direct rung answers QUIC address discovery. A tunnel rung carries no UDP, so an endpoint
    /// that asks it for the discovery waits 3 s for its first net report and has no home relay
    /// until then.
    #[test]
    fn the_default_ladder_is_typed_rung_by_rung() {
        let _guard = ::habilis_network_test_tracing::init();
        let direct = Some(DEFAULT_RELAY_QUIC_PORT);
        let expected = [
            ("https://nyc-relay1.agent-habilis.com/", direct),
            ("https://nyc-relay2.habilis.network/", None),
            ("https://slz-relay1.habilis.network/", None),
            ("https://use1-1.relay.n0.iroh.link/", direct),
            ("https://usw1-1.relay.n0.iroh.link/", direct),
            ("https://euc1-1.relay.n0.iroh.link/", direct),
            ("https://aps1-1.relay.n0.iroh.link/", direct),
        ];
        let actual: Vec<(&str, Option<u16>)> = RENDEZVOUS_RELAY_LADDER_URLS
            .iter()
            .map(|url| (url.as_str(), qad_port(url)))
            .collect();
        assert_eq!(
            actual, expected,
            "each default rung, in order, with its QUIC address discovery port"
        );
    }

    /// The QUIC address discovery port of a beacon homed on `raw`: its one-rung custom ladder.
    fn beacon_qad(raw: &str) -> Option<u16> {
        let rung: RelayUrl = raw.parse().expect("a literal https URL parses");
        let relay_map = super::one_rung_mode(Some(&rung)).relay_map();
        let config = relay_map.get(&rung).expect("the rung is in the relay map");
        config.quic.as_ref().map(|quic| quic.port)
    }

    /// **A beacon on a default rung asks for the QUIC address discovery of that rung.**
    ///
    /// The beacon homes on its rung through a one-rung custom ladder
    /// (`beacon::beacon_lookups`), so the setting follows the URL of the rung, not the choice that
    /// names it.
    #[test]
    fn a_beacon_on_a_default_rung_gets_the_qad_of_that_rung() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            beacon_qad("https://nyc-relay1.agent-habilis.com/"),
            Some(DEFAULT_RELAY_QUIC_PORT),
            "a beacon on a direct rung asks for QUIC address discovery"
        );
        assert_eq!(
            beacon_qad("https://nyc-relay2.habilis.network/"),
            None,
            "a beacon on a tunnel rung asks for no QUIC address discovery"
        );
    }

    /// **A custom rung that the default ladder does not name keeps the rule of its scheme.**
    ///
    /// A custom ladder is URLs only, on the wire and in the API. An https rung asks for QUIC
    /// address discovery on the default port. An http rung has no TLS, and QUIC needs TLS, so it
    /// asks for none.
    #[test]
    fn a_custom_rung_takes_the_qad_of_its_scheme() {
        let _guard = ::habilis_network_test_tracing::init();
        let https: RelayUrl = "https://custom.example/"
            .parse()
            .expect("a literal https URL parses");
        let http: RelayUrl = "http://custom.example/"
            .parse()
            .expect("a literal http URL parses");
        assert_eq!(
            qad_port(&https),
            Some(DEFAULT_RELAY_QUIC_PORT),
            "a custom https rung asks for QUIC address discovery on the default port"
        );
        assert_eq!(
            qad_port(&http),
            None,
            "a custom http rung asks for no QUIC address discovery"
        );
    }

    /// **A new default ladder changes no mesh id.**
    ///
    /// The default choice puts one flag byte in the mesh config and no relay URL. An old build and
    /// a new build with a different default ladder derive the same mesh id and the same topic. A
    /// custom ladder is the case that puts URLs on the wire.
    #[test]
    fn the_default_ladder_is_not_on_the_wire() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut pinned = Vec::new();
        LookupOpts::new(RelayChoice::Pinned).encode_into(&mut pinned);
        assert_eq!(
            pinned,
            [0b0100],
            "the default choice is one flag byte: relay on, no custom ladder"
        );
        let url: RelayUrl = "https://a.example/"
            .parse()
            .expect("a literal https URL parses");
        let mut custom = Vec::new();
        LookupOpts::new(RelayChoice::Custom(vec![url])).encode_into(&mut custom);
        assert!(
            custom.len() > pinned.len(),
            "a custom ladder puts its URLs on the wire"
        );
    }

    /// Safari refuses the TLS certificate of a host written with a trailing
    /// dot, so a browser member could reach no dotted rung at all.
    #[test]
    fn no_ladder_rung_has_a_trailing_dot() {
        let _guard = ::habilis_network_test_tracing::init();
        let hosts = RENDEZVOUS_RELAY_LADDER_URLS
            .iter()
            .filter_map(|url| url.host_str());
        let dotted: Vec<&str> = hosts.filter(|host| host.ends_with('.')).collect();
        assert!(dotted.is_empty(), "dotted ladder hosts: {dotted:?}");
    }

    #[test]
    fn pinned_ladder_resolves_to_prod_set() {
        let _guard = ::habilis_network_test_tracing::init();
        let pinned: Vec<_> = relay_ladder(&RelayChoice::Pinned).collect();
        assert_eq!(
            pinned, *RENDEZVOUS_RELAY_LADDER_URLS,
            "Pinned ⇒ the full default ladder"
        );
        assert!(
            relay_ladder(&RelayChoice::Disabled).next().is_none(),
            "a disabled choice has an empty ladder"
        );
        let url: RelayUrl = "https://a.example./"
            .parse()
            .expect("a literal https URL parses");
        let custom = vec![url];
        let ladder: Vec<_> = relay_ladder(&RelayChoice::Custom(custom.clone())).collect();
        assert_eq!(
            ladder, custom,
            "a pinned ladder resolves to the given rungs"
        );
    }

    // --- the home rung of a peer endpoint -----------------------------
    //
    // A WAN test showed a mesh endpoint homed on `use1-1.relay.n0.iroh.link`: iroh picks its home
    // relay by latency and ignores the order of the map, so a peer can home on a rung that is
    // not the first one. A peer endpoint homes on the first reachable rung of its ladder.

    /// **A peer on the default choice starts on rung 0 alone, and follows the whole ladder.**
    ///
    /// iroh homes on the relay with the lowest latency, so a map with 2 rungs could home on rung
    /// 1. The map holds rung 0 alone, and the ladder that the endpoint follows holds every rung.
    #[test]
    fn a_default_peer_starts_on_rung_0_alone_and_follows_the_whole_ladder() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mode, homing) = super::peer_relay_mode(&RelayChoice::Pinned);
        let held: Vec<RelayUrl> = mode.relay_map().urls();
        assert_eq!(
            held,
            vec![RENDEZVOUS_RELAY_LADDER_URLS[0].clone()],
            "the relay map of a default peer holds rung 0 alone"
        );
        let homing = homing.expect("a ladder of 7 rungs has a choice to make");
        assert_eq!(
            homing.ladder, *RENDEZVOUS_RELAY_LADDER_URLS,
            "the endpoint follows the whole default ladder"
        );
    }

    #[test]
    fn the_rungs_below_a_home() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder = rungs(&["a", "b", "c"]);
        assert_eq!(
            super::rungs_below(&ladder, &rung("c")),
            &ladder[..2],
            "the rungs below rung 2 are rungs 0 and 1"
        );
        assert!(
            super::rungs_below(&ladder, &rung("a")).is_empty(),
            "rung 0 has no rung below it"
        );
        assert!(
            super::rungs_below(&ladder, &rung("elsewhere")).is_empty(),
            "a home that is not on the ladder has no rung below it"
        );
    }

    /// **A probe endpoint does not wait for QUIC address discovery.**
    ///
    /// The probe asks one question: does this relay answer? An endpoint with QUIC address discovery
    /// on holds its first net report until the 3 s probe timeout of iroh when the QUIC port of the
    /// relay is out of reach (behind a proxy, or blocked), so `online()` took 4 s on every rung,
    /// every time an endpoint was built. The probe needs the relay connection, not the discovery.
    #[test]
    fn a_probe_endpoint_does_not_wait_for_quic_address_discovery() {
        let _guard = ::habilis_network_test_tracing::init();
        let rung = rung("probe.example");
        let relay_map = super::probe_relay_mode(&rung).relay_map();
        let config = relay_map.get(&rung).expect("the rung is in the relay map");
        assert!(
            config.quic.is_none(),
            "the probe of a rung does not ask for QUIC address discovery"
        );
    }

    /// A dial by an address that names a relay the dialer does not hold in its map. If it
    /// completes, two endpoints on different home relays still reach each other, so a split home
    /// relay does not explain a failed dial.
    #[test]
    fn a_dial_reaches_a_peer_homed_on_a_relay_that_is_not_in_the_map_of_the_dialer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            const ALPN: &[u8] = b"habilis-network/test-dial";
            let (relay_a, _server_a) = test_relay::spawn_plain().await.expect("a local relay");
            let (relay_b, _server_b) = test_relay::spawn_plain().await.expect("a local relay");
            let producer_builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::custom([relay_a.clone()]))
                .alpns(vec![ALPN.to_vec()]);
            let producer = producer_builder.bind().await.expect("bind the producer");
            let consumer_builder =
                iroh::Endpoint::builder(presets::Minimal).relay_mode(RelayMode::custom([relay_b]));
            let consumer = consumer_builder.bind().await.expect("bind the consumer");
            producer.online().await;
            consumer.online().await;
            let accepting = producer.clone();
            let accept = n0future_task::spawn(async move {
                if let Some(incoming) = accepting.accept().await
                    && let Ok(connection) = incoming.await
                {
                    connection.closed().await;
                }
            });

            let address = iroh::EndpointAddr::new(producer.id()).with_relay_url(relay_a);
            let dialed =
                time::timeout(std_Duration::from_secs(15), consumer.connect(address, ALPN)).await;

            consumer.close().await;
            producer.close().await;
            accept.abort();
            assert!(
                matches!(dialed, Ok(Ok(_))),
                "the dial across 2 relays failed: {dialed:?}"
            );
        });
    }

    /// The home relay of an endpoint, once it is online.
    async fn home_of(endpoint: &iroh::Endpoint) -> Vec<RelayUrl> {
        time::timeout(std_Duration::from_secs(15), endpoint.online())
            .await
            .expect("the endpoint is online within 15 s");
        endpoint.addr().relay_urls().cloned().collect()
    }

    /// **A peer endpoint does not wait for the relay probes to bind.**
    ///
    /// The choice of the rung used to run before the bind, one probe of up to 10 s after the other.
    /// With every rung of the ladder out of reach, the bind took the sum of the probes, and the
    /// member was not ready for that long. The choice now runs after the bind.
    #[test]
    fn a_peer_endpoint_binds_at_once_when_every_rung_is_out_of_reach() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            let lookups = lookups_on(vec![refused_rung(), refused_rung()]);

            let built =
                time::timeout(std_Duration::from_secs(3), build_peer_endpoint(&lookups)).await;

            let endpoint = built
                .expect("the bind returns within 3 s")
                .expect("a peer endpoint");
            endpoint.close().await;
        });
    }

    /// **A rung that answers a plain request and refuses the relay connection does not hold the
    /// endpoint.**
    ///
    /// The relay in front of a real one forwards until the flag turns on. Then it cuts the open
    /// connections, still forwards a plain request, and refuses the relay upgrade with 403. The
    /// probe of the net report gets a real answer. The net report still drops its preferred relay
    /// in the end: the mutation that ignores the status of the home relay passes this test too,
    /// about 20 s later (51 s against 31 s). So the test pins the behavior, not the signal.
    #[test]
    #[ignore = "60 s: waits for the endpoint to judge the rung dead and walk the ladder"]
    fn a_peer_endpoint_leaves_a_rung_that_refuses_the_relay_connection() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Failed to connect to relay server",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Lost connection to relay server",
            );
            let (real, _real_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (front, half_open) = spawn_switchable_relay(&real).await;
            let (second, _second_server) = test_relay::spawn_plain().await.expect("a local relay");
            let endpoint = build_peer_endpoint(&lookups_on(vec![front.clone(), second.clone()]))
                .await
                .expect("a peer endpoint");
            assert_eq!(
                home_of(&endpoint).await,
                vec![front],
                "the first home relay"
            );

            half_open.store(true, Ordering::SeqCst);

            let moved = time::timeout(
                std_Duration::from_secs(90),
                home_becomes(&endpoint, &second),
            )
            .await;
            endpoint.close().await;
            assert!(
                moved.is_ok(),
                "the endpoint stayed on a rung that refuses the relay connection"
            );
        });
    }

    /// Short times for a test of the return to a lower rung: a probe of 2 s, a liveness read and
    /// a return probe each second, and a hold of `hold`.
    fn return_times(hold: std_Duration) -> super::HomingTimes {
        super::HomingTimes {
            probe: std_Duration::from_secs(2),
            interval: std_Duration::from_secs(1),
            return_every: std_Duration::from_secs(1),
            return_backoff_max: std_Duration::from_hours(1),
            return_hold: hold,
        }
    }

    /// **A peer endpoint returns to rung 0 once rung 0 answers again for the hold time.**
    ///
    /// Rung 0 refuses the relay connection, so the endpoint moves to rung 1. Then rung 0 comes
    /// back. A move on failure alone keeps the endpoint on rung 1 for good: rung 1 never fails.
    /// The endpoint probes the rungs below its own, and returns once rung 0 answered every round
    /// for the hold time, not before: about 6 s after rung 0 comes back, with a hold of 4 s. The
    /// bound is 15 s, well before a later walk of the ladder could find rung 0 by another path.
    #[test]
    fn a_peer_endpoint_returns_to_rung_0_after_the_hold() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Failed to connect to relay server",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Lost connection to relay server",
            );
            let (real, _real_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (front, half_open) = spawn_switchable_relay(&real).await;
            let (second, _second_server) = test_relay::spawn_plain().await.expect("a local relay");
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&front)));
            let endpoint = builder.bind().await.expect("bind the endpoint");
            let homing = super::Homing {
                ladder: vec![front.clone(), second.clone()],
                rung: front.clone(),
            };
            let hold = std_Duration::from_secs(4);
            let follower = homing.follow_with(endpoint.clone(), return_times(hold));
            assert_eq!(
                home_of(&endpoint).await,
                vec![front.clone()],
                "the first home relay"
            );

            half_open.store(true, Ordering::SeqCst);
            let moved = time::timeout(
                std_Duration::from_secs(30),
                home_becomes(&endpoint, &second),
            )
            .await;
            half_open.store(false, Ordering::SeqCst);
            let back_at = time::Instant::now();
            let returned =
                time::timeout(std_Duration::from_secs(15), home_becomes(&endpoint, &front)).await;
            let took = back_at.elapsed();
            endpoint.close().await;
            drop(follower.await);

            assert!(moved.is_ok(), "the endpoint never left the dead rung 0");
            assert!(
                returned.is_ok(),
                "the endpoint stayed on rung 1 for 15 s after rung 0 came back"
            );
            assert!(
                took >= hold,
                "the endpoint returned {took:?} after rung 0 came back, before the hold of {hold:?}"
            );
        });
    }

    /// **A beacon on a later rung publishes rung 0 once rung 0 answers for the hold time.**
    ///
    /// The event loop re-homes the beacon on the rung that the monitor publishes. A monitor that
    /// acts only on a failure of its own rung never publishes while rung 1 is healthy, so the
    /// beacon stays on rung 1 for good.
    #[test]
    fn a_beacon_on_a_later_rung_publishes_rung_0_after_the_hold() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (first, _first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (second, _second_server) = test_relay::spawn_plain().await.expect("a local relay");
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&second)));
            let endpoint = builder.bind().await.expect("bind the beacon endpoint");
            let (rung_tx, rung_rx) = watch::channel(RungDecision::at_startup(Some(second.clone())));
            let (_stop, stopped) = watch::channel(());
            let hold = std_Duration::from_secs(3);
            let ladder = [first.clone(), second.clone()];

            let started = time::Instant::now();
            let published = time::timeout(
                std_Duration::from_secs(30),
                super::follow_rung(
                    &endpoint,
                    &ladder,
                    second,
                    return_times(hold),
                    super::Mover::Publish(&rung_tx, super::Generation::next()),
                    Some(&stopped),
                ),
            )
            .await;
            let took = started.elapsed();
            endpoint.close().await;

            assert!(
                published.is_ok(),
                "the monitor of a healthy rung 1 published nothing for 30 s"
            );
            assert_eq!(
                rung_rx.borrow().rung,
                Some(first),
                "the monitor publishes rung 0"
            );
            assert!(
                took >= hold,
                "the monitor published rung 0 after {took:?}, before the hold of {hold:?}"
            );
        });
    }

    /// **A peer on a healthy rung without QUIC address discovery is not evicted.**
    ///
    /// iroh measures a relay in an incremental net report by QUIC address discovery only. A rung
    /// without it, a tunnel rung or a plain `http://` rung, gets no latency there, so every second
    /// periodic report, every 20 to 26 s, has no preferred relay for one period. A liveness read
    /// that takes that as a dead rung evicts a healthy rung and walks the ladder.
    ///
    /// A walk probes rung 0 first, at once, with an endpoint of its own, and that endpoint is a new
    /// client key of the relay. The endpoint under test is the only other client of rung 0, so a
    /// count of 1 says that no walk started. The count of rung 1 cannot say it: a healthy rung 0
    /// answers inside the stagger, the walk stops there, and rung 1 sees nothing.
    #[test]
    #[ignore = "60 s: waits for 2 periods of the net report of iroh"]
    fn a_peer_on_a_healthy_rung_without_qad_is_not_evicted() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (first, first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (second, _second_server) = test_relay::spawn_plain().await.expect("a local relay");
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&first)));
            let endpoint = builder.bind().await.expect("bind the endpoint");
            let homing = super::Homing {
                ladder: vec![first.clone(), second],
                rung: first.clone(),
            };
            let follower =
                homing.follow_with(endpoint.clone(), return_times(std_Duration::from_hours(1)));
            assert_eq!(home_of(&endpoint).await, vec![first], "the home relay");

            time::sleep(std_Duration::from_secs(60)).await;
            let clients = relay_clients(&first_server);
            endpoint.close().await;
            drop(follower.await);

            assert_eq!(
                clients, 1,
                "the endpoint judged its healthy rung dead and walked the ladder: a probe endpoint of the walk joined rung 0"
            );
        });
    }

    /// **A home on rung 0 starts no return round; a later home starts one when it is due.**
    #[test]
    fn a_return_round_starts_only_below_a_later_home() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (silent, _held) = spawn_silent_rung().await;
            let mut times = return_times(std_Duration::from_hours(1));
            times.return_every = std_Duration::ZERO;
            let ladder = vec![silent.clone(), rung("later")];
            let now = time::Instant::now();

            let mut on_rung_0 = super::RungFollower::new(&ladder, silent, times, true, now);
            assert_eq!(
                on_rung_0.round_due(now),
                None,
                "rung 0 has no rung below it"
            );

            let mut on_rung_1 = super::RungFollower::new(&ladder, rung("later"), times, true, now);
            let below = on_rung_1
                .round_due(now)
                .expect("a due round of a later home starts");
            let mut round = Some(super::ReturnRound::spawn(below, times.probe));
            super::cancel_round(&mut round).await;
            assert!(round.is_none(), "a cancel ends the round");
        });
    }

    /// **A return round reports every lower rung that answers, not only the lowest.**
    #[test]
    fn a_return_round_reports_every_rung_that_answers() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (first, _first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (silent, _held) = spawn_silent_rung().await;
            let (third, _third_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (_stop, stopped) = watch::channel(());

            let answered = super::probe_lower_rungs(
                &[first.clone(), silent, third.clone()],
                std_Duration::from_secs(2),
                &stopped,
            )
            .await;

            assert_eq!(
                answered,
                vec![first, third],
                "the 2 live rungs answer, and the silent rung between them does not"
            );
        });
    }

    /// **A follower that is stopped acts on no return round that ended at the same time.**
    ///
    /// The event loop stops the monitor of a beacon that it sheds. A round that ended before the
    /// stop is read by the monitor after it, and a decision on it would move the registration of
    /// the beacon that the loop holds next. Both are ready: the stop must win, every time.
    #[test]
    fn a_stop_wins_over_a_return_round_that_ended_with_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .bind()
                .await
                .expect("bind an endpoint without a relay");
            let (stop, stopped) = watch::channel(());
            drop(stop);
            for pass in 0..64 {
                let task = n0future_task::spawn(async { (Vec::new(), time::Instant::now()) });
                let mut round = Some(super::ReturnRound {
                    stop: watch::channel(()).0,
                    task,
                });
                while !round.as_ref().is_some_and(|round| round.task.is_finished()) {
                    time::sleep(std_Duration::from_millis(1)).await;
                }

                let wake = super::next_wake(
                    std_Duration::from_hours(1),
                    &mut round,
                    &endpoint,
                    Some(&stopped),
                )
                .await;

                assert!(
                    matches!(wake, super::Wake::Ended),
                    "pass {pass}: the follower read a round after it was stopped"
                );
                super::cancel_round(&mut round).await;
            }
            endpoint.close().await;
        });
    }

    /// **A return round that is stopped ends at once, and closes its probes.**
    ///
    /// iroh logs an error for an endpoint that is dropped open, and the test fails on it.
    #[test]
    fn a_stopped_return_round_ends_at_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (one, _held_one) = spawn_silent_rung().await;
            let (two, _held_two) = spawn_silent_rung().await;
            let (stop, stopped) = watch::channel(());
            let stopping = async {
                time::sleep(std_Duration::from_millis(200)).await;
                drop(stop);
            };

            let started = time::Instant::now();
            let silent = [one, two];
            let (answered, ()) = tokio::join!(
                super::probe_lower_rungs(&silent, std_Duration::from_secs(30), &stopped),
                stopping
            );
            let took = started.elapsed();

            assert!(answered.is_empty(), "a stopped round reports no rung");
            assert!(
                took < std_Duration::from_secs(5),
                "the stopped round of 30 s probes took {took:?}"
            );
        });
    }

    /// **A beacon leaves a rung that dies silently, in the bound of a peer.**
    ///
    /// A relay that dies keeps its connection in the status for minutes, and `online()` reads that
    /// status, so a beacon that asks `online()` only stays on the dead rung while the peers move.
    /// The net report finds the dead relay at its next run, every 20 to 26 s.
    #[test]
    #[ignore = "60 s: waits for a net report of iroh to find the dead relay"]
    fn a_beacon_leaves_a_rung_that_dies_silently() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh_relay::server::http_server",
                "error accepting upgraded connection",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Failed to connect to relay server",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Lost connection to relay server",
            );
            let (first, first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (second, _second_server) = test_relay::spawn_plain().await.expect("a local relay");
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&first)));
            let endpoint = builder.bind().await.expect("bind the beacon endpoint");
            assert_eq!(
                home_of(&endpoint).await,
                vec![first.clone()],
                "the first home relay"
            );
            let (rung_tx, rung_rx) = watch::channel(RungDecision::at_startup(Some(first.clone())));
            let (_stop, stopped) = watch::channel(());
            let ladder = [first.clone(), second.clone()];

            drop(first_server);
            let published = time::timeout(
                std_Duration::from_secs(60),
                super::follow_rung(
                    &endpoint,
                    &ladder,
                    first,
                    return_times(std_Duration::from_hours(1)),
                    super::Mover::Publish(&rung_tx, super::Generation::next()),
                    Some(&stopped),
                ),
            )
            .await;
            endpoint.close().await;

            assert!(
                published.is_ok(),
                "the beacon stayed on its dead rung for 60 s"
            );
            assert_eq!(
                rung_rx.borrow().rung,
                Some(second),
                "the beacon moves to rung 1"
            );
        });
    }

    /// **A slow return round does not hold back the liveness read of the home rung.**
    ///
    /// Rung 0 accepts connections and never answers, so each return round waits its full probe
    /// window of 8 s. While a round runs, the home rung starts to refuse the relay connection.
    /// The endpoint must judge it dead within 2 reads, not after the round: then the walk of 8 s
    /// finds rung 2, about 10 s after the refusal. A round that blocks the reads adds its 8 s.
    #[test]
    #[ignore = "25 s: waits for a return round and a walk of 8 s each"]
    fn a_slow_return_round_does_not_hold_back_the_liveness_read() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Failed to connect to relay server",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Lost connection to relay server",
            );
            let (silent, _held) = spawn_silent_rung().await;
            let (real, _real_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (front, half_open) = spawn_switchable_relay(&real).await;
            let (third, _third_server) = test_relay::spawn_plain().await.expect("a local relay");
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&front)));
            let endpoint = builder.bind().await.expect("bind the endpoint");
            let homing = super::Homing {
                ladder: vec![silent, front.clone(), third.clone()],
                rung: front.clone(),
            };
            let times = super::HomingTimes {
                probe: std_Duration::from_secs(8),
                interval: std_Duration::from_secs(1),
                return_every: std_Duration::from_secs(1),
                return_backoff_max: std_Duration::from_hours(1),
                return_hold: std_Duration::from_hours(1),
            };
            let follower = homing.follow_with(endpoint.clone(), times);
            assert_eq!(
                home_of(&endpoint).await,
                vec![front],
                "the first home relay"
            );
            // The first return round starts after 1 s and runs until about 9 s.
            time::sleep(std_Duration::from_secs(3)).await;

            half_open.store(true, Ordering::SeqCst);
            let refused_at = time::Instant::now();
            let moved =
                time::timeout(std_Duration::from_secs(30), home_becomes(&endpoint, &third)).await;
            let took = refused_at.elapsed();
            endpoint.close().await;
            drop(follower.await);

            assert!(moved.is_ok(), "the endpoint never left the refusing rung");
            assert!(
                took < std_Duration::from_secs(13),
                "the endpoint left the refusing rung {took:?} after the refusal: the round held \
                 back the liveness read"
            );
        });
    }

    /// The warnings of a test whose rungs refuse the relay connection on purpose.
    fn allow_refused_rung_warnings() {
        ::habilis_network_test_tracing::allow_warn("iroh::net_report::reportgen", "probe failed");
        ::habilis_network_test_tracing::allow_warn(
            "iroh::socket::transports::relay::actor",
            "Failed to connect to relay server",
        );
        ::habilis_network_test_tracing::allow_warn(
            "iroh::socket::transports::relay::actor",
            "Lost connection to relay server",
        );
    }

    /// **A walk that finds no rung keeps the follower of a peer alive.**
    ///
    /// Both rungs refuse connections, as in a full outage (a sleep, Wi-Fi off). The walk finds no
    /// rung. The follower must stay on its rung and go on, or the peer never leaves a dead rung
    /// again, and never returns to a lower one.
    #[test]
    fn a_walk_that_finds_no_rung_keeps_the_follower_alive() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            allow_refused_rung_warnings();
            let first = refused_rung();
            let (second, walk_probes) = spawn_closing_rung().await;
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&first)));
            let endpoint = builder.bind().await.expect("bind the endpoint");
            let homing = super::Homing {
                ladder: vec![first.clone(), second],
                rung: first,
            };
            let follower =
                homing.follow_with(endpoint.clone(), return_times(std_Duration::from_hours(1)));

            // The first walk starts after the 2 s that the rung gets to connect, and ends at once.
            time::sleep(std_Duration::from_secs(8)).await;
            let alive = !follower.is_finished();
            let walked = walk_probes.load(Ordering::SeqCst);
            endpoint.close().await;
            drop(follower.await);

            assert!(walked > 0, "no walk ran in 8 s, so the test proves nothing");
            assert!(alive, "the follower ended while its endpoint was open");
        });
    }

    /// **After a walk that finds no rung, a peer moves to the first rung that comes back.**
    #[test]
    #[ignore = "20 s: waits for a walk with no rung, then for the next one"]
    fn a_peer_moves_to_a_rung_that_comes_back_after_a_full_outage() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            allow_refused_rung_warnings();
            let (real_one, _real_one_server) =
                test_relay::spawn_plain().await.expect("a local relay");
            let (real_two, _real_two_server) =
                test_relay::spawn_plain().await.expect("a local relay");
            let (first, first_refuses) = spawn_switchable_relay(&real_one).await;
            let (second, second_refuses) = spawn_switchable_relay(&real_two).await;
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&first)));
            let endpoint = builder.bind().await.expect("bind the endpoint");
            let homing = super::Homing {
                ladder: vec![first.clone(), second.clone()],
                rung: first.clone(),
            };
            let follower =
                homing.follow_with(endpoint.clone(), return_times(std_Duration::from_hours(1)));
            assert_eq!(
                home_of(&endpoint).await,
                vec![first],
                "the first home relay"
            );

            first_refuses.store(true, Ordering::SeqCst);
            second_refuses.store(true, Ordering::SeqCst);
            // 2 failed reads and a walk of refused rungs: the walk finds no rung.
            time::sleep(std_Duration::from_secs(8)).await;
            second_refuses.store(false, Ordering::SeqCst);
            let moved = time::timeout(
                std_Duration::from_secs(30),
                home_becomes(&endpoint, &second),
            )
            .await;
            endpoint.close().await;
            drop(follower.await);

            assert!(
                moved.is_ok(),
                "the peer stayed on its dead rung after rung 1 came back"
            );
        });
    }

    /// **A walk that finds no rung does not demote the beacon.**
    ///
    /// The peers stay on their rung through a short full outage, and so does the beacon: it
    /// publishes no `None`, which would make the event loop rebuild it with no relay and wait out
    /// the backoff of the relay-less monitor (30 s to 5 min). When a rung comes back, the beacon
    /// publishes it.
    #[test]
    #[ignore = "20 s: waits for a walk with no rung, then for the next one"]
    fn a_walk_that_finds_no_rung_does_not_demote_the_beacon() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            allow_refused_rung_warnings();
            let (real_one, _real_one_server) =
                test_relay::spawn_plain().await.expect("a local relay");
            let (real_two, _real_two_server) =
                test_relay::spawn_plain().await.expect("a local relay");
            let (first, first_refuses) = spawn_switchable_relay(&real_one).await;
            let (second, second_refuses) = spawn_switchable_relay(&real_two).await;
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&first)));
            let endpoint = builder.bind().await.expect("bind the beacon endpoint");
            assert_eq!(
                home_of(&endpoint).await,
                vec![first.clone()],
                "the first home relay"
            );
            let (rung_tx, mut rung_rx) =
                watch::channel(RungDecision::at_startup(Some(first.clone())));
            let (_stop, stopped) = watch::channel(());
            let ladder = [first.clone(), second.clone()];

            first_refuses.store(true, Ordering::SeqCst);
            second_refuses.store(true, Ordering::SeqCst);
            let following = super::follow_rung(
                &endpoint,
                &ladder,
                first.clone(),
                return_times(std_Duration::from_hours(1)),
                super::Mover::Publish(&rung_tx, super::Generation::next()),
                Some(&stopped),
            );
            tokio::pin!(following);
            let early = time::timeout(std_Duration::from_secs(8), &mut following).await;
            let published_early = rung_rx.has_changed().unwrap_or(false);
            let held = rung_rx.borrow_and_update().clone();
            second_refuses.store(false, Ordering::SeqCst);
            let later = if early.is_err() {
                time::timeout(std_Duration::from_secs(30), &mut following)
                    .await
                    .is_ok()
            } else {
                false
            };
            endpoint.close().await;

            assert!(early.is_err(), "the beacon follower ended in the outage");
            assert!(
                !published_early,
                "the beacon published {held:?} in the outage"
            );
            assert!(later, "the beacon never left its dead rung");
            assert_eq!(
                rung_rx.borrow().rung,
                Some(second),
                "the beacon publishes the rung that came back"
            );
        });
    }

    /// A relay URL in front of `real`. While the flag is off, it forwards every connection. When
    /// the flag turns on, it cuts the open connections, still forwards a plain request, and
    /// refuses the relay upgrade with 403.
    async fn spawn_switchable_relay(real: &RelayUrl) -> (RelayUrl, Arc<AtomicBool>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, copy_bidirectional};
        let host = real.host_str().expect("the relay URL has a host");
        let real_port = real.port().expect("the relay URL has a port");
        let upstream = format!("{host}:{real_port}");
        let listener: AsyncListener = AsyncListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("a free loopback port");
        let address = listener.local_addr().expect("the bound address");
        let port: u16 = address.port();
        // The flag is shared with the connection tasks of the fake relay and with the test.
        let half_open = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&half_open);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    return;
                };
                let flag = Arc::clone(&flag);
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    if !flag.load(Ordering::SeqCst) {
                        let Ok(mut onward) = TcpStream::connect(&upstream).await else {
                            return;
                        };
                        tokio::select! {
                            _copied = copy_bidirectional(&mut stream, &mut onward) => {}
                            () = async {
                                while !flag.load(Ordering::SeqCst) {
                                    time::sleep(std_Duration::from_millis(100)).await;
                                }
                            } => {}
                        }
                        return;
                    }
                    let mut request = [0_u8; 2048];
                    let request_len = stream.read(&mut request).await.unwrap_or(0);
                    let upgrade = request[..request_len]
                        .windows(7)
                        .any(|window| window.eq_ignore_ascii_case(b"upgrade"));
                    if upgrade {
                        let reply = "HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                        drop(stream.write_all(reply.as_bytes()).await);
                        return;
                    }
                    // A plain request, like the probe of the net report, gets the real answer.
                    let Ok(mut onward) = TcpStream::connect(&upstream).await else {
                        return;
                    };
                    drop(onward.write_all(&request[..request_len]).await);
                    drop(copy_bidirectional(&mut stream, &mut onward).await);
                });
            }
        });
        let url = format!("http://127.0.0.1:{port}/")
            .parse()
            .expect("a literal http URL parses");
        (url, half_open)
    }

    /// **The rung walk stops when its endpoint closes.**
    ///
    /// The rung of the endpoint never connects, so the follower walks the ladder, and every other
    /// rung accepts the connection and never answers: each probe waits out its time. A fetch that
    /// closes its endpoint during the walk must not leave the task to bind and probe the rungs that
    /// remain. The task ends soon after the close, and the probe in flight closes its own endpoint
    /// (iroh logs an error for an endpoint that is dropped open, and the test fails on it).
    #[test]
    fn the_rung_walk_stops_when_its_endpoint_closes() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Failed to connect to relay server",
            );
            let mut ladder = vec![refused_rung()];
            let mut silent = Vec::new();
            for _ in 0..3 {
                let (rung, listener) = spawn_silent_rung().await;
                ladder.push(rung);
                silent.push(listener);
            }
            let first = ladder[0].clone();
            let builder: Builder = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(super::one_rung_mode(Some(&first)));
            let endpoint = builder.bind().await.expect("bind the endpoint");
            let homing = super::Homing {
                ladder,
                rung: first,
            };
            let probe = std_Duration::from_secs(3);
            let times = super::HomingTimes {
                probe,
                interval: std_Duration::from_secs(1),
                return_every: std_Duration::from_hours(1),
                return_backoff_max: std_Duration::from_hours(1),
                return_hold: std_Duration::from_hours(1),
            };
            let follower = homing.follow_with(endpoint.clone(), times);

            // The first walk starts after the 3 s that the rung gets to connect, and it takes 9 s.
            time::sleep(std_Duration::from_millis(4500)).await;
            endpoint.close().await;
            let ended = time::timeout(std_Duration::from_secs(2), follower).await;

            assert!(
                ended.is_ok(),
                "the walk went on for more than 2 s after its endpoint closed"
            );
        });
    }

    /// A relay URL on a local port that accepts connections and never answers.
    async fn spawn_silent_rung() -> (RelayUrl, JoinHandle<()>) {
        let listener: AsyncListener = AsyncListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("a free loopback port");
        let address = listener.local_addr().expect("the bound address");
        let port: u16 = address.port();
        let holder = tokio::spawn(async move {
            let mut held: Vec<TcpStream> = Vec::new();
            while let Ok((stream, _peer)) = listener.accept().await {
                held.push(stream);
            }
        });
        let url = format!("http://127.0.0.1:{port}/")
            .parse()
            .expect("a literal http URL parses");
        (url, holder)
    }

    /// **A walk after a false failure of a live rung can stay on it.**
    ///
    /// Under load the net report drops the preferred relay of a live rung for two intervals. The
    /// walk that follows must probe that rung too: if it answers, the endpoint stays. A walk that
    /// skips it makes every false failure a move, for good. Only the first walk of a rung that
    /// never connected leaves it out, to save the wait of a probe that cannot answer.
    #[test]
    fn a_walk_after_a_false_failure_probes_the_current_rung_too() {
        let _guard = ::habilis_network_test_tracing::init();
        let first = rung("first.example");
        let second = rung("second.example");
        let ladder = vec![first.clone(), second.clone()];

        assert_eq!(
            super::rungs_to_walk(&ladder, &first, false),
            ladder,
            "the walk of a rung that connected probes the whole ladder"
        );
        assert_eq!(
            super::rungs_to_walk(&ladder, &first, true),
            vec![second],
            "the first walk of a rung that never connected leaves it out"
        );
    }

    /// Wait until the home relay of the endpoint is `rung`.
    async fn home_becomes(endpoint: &iroh::Endpoint, rung: &RelayUrl) {
        loop {
            let home: Vec<RelayUrl> = endpoint.addr().relay_urls().cloned().collect();
            if home == [rung.clone()] {
                return;
            }
            time::sleep(std_Duration::from_millis(500)).await;
        }
    }

    /// How many distinct endpoints connected to a relay as clients. A probe endpoint of a walk is
    /// a new one each time.
    fn relay_clients(server: &Server) -> u64 {
        server.metrics().server.unique_client_keys.get()
    }

    /// How many HTTP connections a relay accepted. An endpoint that holds a relay in its map
    /// connects to it to measure the latency, even when it does not home on it.
    fn http_connections(server: &Server) -> u64 {
        server.metrics().server.http_connections.get()
    }

    /// A relay URL on a local port that accepts each connection, counts it, and closes it at once.
    /// The endpoint holds only its own rung, so each connection to this rung is a probe of a walk.
    async fn spawn_closing_rung() -> (RelayUrl, Arc<AtomicUsize>) {
        let listener: AsyncListener = AsyncListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("a free loopback port");
        let address = listener.local_addr().expect("the bound address");
        let port: u16 = address.port();
        // The count is shared with the accept task and with the test.
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        n0future_task::spawn(async move {
            while let Ok((stream, _peer)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let url = format!("http://127.0.0.1:{port}/")
            .parse()
            .expect("a literal http URL parses");
        (url, accepted)
    }

    /// A relay URL on a local port that refuses connections.
    fn refused_rung() -> RelayUrl {
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free loopback port");
        let port = socket.local_addr().expect("the bound address").port();
        drop(socket);
        format!("http://127.0.0.1:{port}/")
            .parse()
            .expect("a literal http URL parses")
    }

    fn lookups_on(ladder: Vec<RelayUrl>) -> LookupOpts {
        let mut lookups = LookupOpts::loopback();
        lookups.relay_lookup = RelayChoice::Custom(ladder);
        lookups
    }

    /// **A default peer endpoint homes on rung 0 and learns its public address.**
    ///
    /// Rung 0 is a direct rung: it answers QUIC address discovery, so the net report has a public
    /// address and `udp_v4`. This test needs the internet.
    #[test]
    #[ignore = "needs the internet, and the direct relay of rung 0 deployed: it builds a peer endpoint on the default ladder"]
    fn a_default_peer_endpoint_homes_on_rung_0_and_has_a_public_address() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let endpoint = build_peer_endpoint(&LookupOpts::new(RelayChoice::Pinned))
                .await
                .expect("a peer endpoint");
            let home = home_of(&endpoint).await;
            time::sleep(std_Duration::from_secs(5)).await;
            let mut net_report = endpoint.net_report();
            let report = net_report
                .get()
                .expect("a net report 5 s after the endpoint is online");
            let global_v4 = report.global_v4;
            let udp_v4 = report.udp_v4;
            endpoint.close().await;

            assert_eq!(
                home,
                vec![RENDEZVOUS_RELAY_LADDER_URLS[0].clone()],
                "the home relay is not rung 0"
            );
            assert!(udp_v4, "the net report has no udp_v4");
            assert!(global_v4.is_some(), "the net report has no public address");
        });
    }

    #[test]
    fn a_peer_endpoint_homes_on_rung_0_when_rung_0_is_up() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (first, _first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (second, second_server) = test_relay::spawn_plain().await.expect("a local relay");
            let endpoint = build_peer_endpoint(&lookups_on(vec![first.clone(), second]))
                .await
                .expect("a peer endpoint");

            assert_eq!(home_of(&endpoint).await, vec![first], "the home relay");
            assert_eq!(
                http_connections(&second_server),
                0,
                "a later rung never sees the endpoint"
            );
            endpoint.close().await;
        });
    }

    /// The walk probes every rung at once, so its own throwaway probe endpoints reach the last
    /// rung. The endpoint itself must hold no rung after its home: an endpoint that holds a relay
    /// in its map probes it in each net report, every 20 to 26 s. So the count of the last relay
    /// is read once the endpoint is home and the walk has closed its probes, and must not grow
    /// over one net report period.
    #[test]
    #[ignore = "40 s: waits for the probe budget of the dead rung, then one net report period"]
    fn a_peer_endpoint_homes_on_the_next_rung_when_rung_0_is_down() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // Rung 0 refuses connections on purpose, so the probe of its latency fails.
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            let (next, _next_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (last, last_server) = test_relay::spawn_plain().await.expect("a local relay");
            let endpoint =
                build_peer_endpoint(&lookups_on(vec![refused_rung(), next.clone(), last]))
                    .await
                    .expect("a peer endpoint");

            assert_eq!(home_of(&endpoint).await, vec![next], "the home relay");
            let after_the_walk = http_connections(&last_server);
            time::sleep(std_Duration::from_secs(30)).await;
            let later = http_connections(&last_server);
            endpoint.close().await;
            assert_eq!(
                later, after_the_walk,
                "a rung after the first reachable one sees the endpoint after the walk"
            );
        });
    }

    #[test]
    #[ignore = "60 s: waits for the relay monitor to judge the rung dead and walk the ladder"]
    fn a_peer_endpoint_moves_to_the_next_rung_when_its_rung_dies() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // Killing the home rung is the point of the test, so its probes and sockets fail.
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh_relay::server::http_server",
                "error accepting upgraded connection",
            );
            let (first, first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (second, _second_server) = test_relay::spawn_plain().await.expect("a local relay");
            let endpoint = build_peer_endpoint(&lookups_on(vec![first.clone(), second.clone()]))
                .await
                .expect("a peer endpoint");
            assert_eq!(
                home_of(&endpoint).await,
                vec![first],
                "the first home relay"
            );

            drop(first_server);

            let moved = time::timeout(
                std_Duration::from_secs(120),
                home_becomes(&endpoint, &second),
            )
            .await;
            endpoint.close().await;
            assert!(moved.is_ok(), "the endpoint never moved to the next rung");
        });
    }

    #[test]
    fn the_member_and_the_blob_endpoint_share_one_home_rung() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (first, _first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (second, second_server) = test_relay::spawn_plain().await.expect("a local relay");
            let lookups = lookups_on(vec![first.clone(), second]);
            let blob = build_peer_endpoint(&lookups)
                .await
                .expect("a blob endpoint");
            let (member, _handle) = build_peer_webrtc(&lookups, TransportOpts::default())
                .await
                .expect("a member endpoint");

            assert_eq!(
                home_of(&blob).await,
                vec![first.clone()],
                "the blob endpoint"
            );
            assert_eq!(home_of(&member).await, vec![first], "the member endpoint");
            assert_eq!(
                http_connections(&second_server),
                0,
                "a later rung sees neither endpoint"
            );
            blob.close().await;
            member.close().await;
        });
    }

    /// **A healthy rung 0 leaves the later rungs unprobed.**
    ///
    /// The walk starts rung 1 a stagger after rung 0, and a healthy rung 0 answers before that.
    /// A walk that starts every rung at once sends a probe to every relay of the ladder, the n0
    /// relays too, each time a member walks.
    #[test]
    fn a_healthy_rung_0_leaves_the_later_rungs_unprobed() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (first, _first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (second, second_server) = test_relay::spawn_plain().await.expect("a local relay");

            let selected =
                select_bootstrap_rung(&[first.clone(), second], std_Duration::from_secs(2), None)
                    .await;

            assert_eq!(selected, Some(first), "the walk picks rung 0");
            assert_eq!(
                http_connections(&second_server),
                0,
                "rung 1 saw a probe, though rung 0 answered"
            );
        });
    }

    /// **A walk over silent rungs costs about one window, not one window for each rung.**
    ///
    /// A walk that probes one rung after the other waits a full window for each silent rung
    /// before it reaches a live one: 3 silent rungs cost 3 windows. The walk starts each rung a
    /// stagger after the one below it, so it waits one window plus the staggers for the silent
    /// rungs below the live one, and every member still picks the same rung.
    #[test]
    fn the_walk_of_silent_rungs_costs_about_one_window() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::net_report::reportgen",
                "probe failed",
            );
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Failed to connect to relay server",
            );
            let mut ladder = Vec::new();
            let mut silent = Vec::new();
            for _ in 0..3 {
                let (rung, listener) = spawn_silent_rung().await;
                ladder.push(rung);
                silent.push(listener);
            }
            let (live, _live_server) = test_relay::spawn_plain().await.expect("a local relay");
            ladder.push(live.clone());
            let window = std_Duration::from_secs(2);

            let probe = |rung: RelayUrl, probes_stopped| async move {
                super::relay_rung_reachable(&rung, window, Some(probes_stopped)).await
            };

            let started = time::Instant::now();
            let stagger = std_Duration::from_millis(200);
            let selected = select_first_reachable(&ladder, None, stagger, probe).await;
            let took = started.elapsed();

            assert_eq!(selected, Some(live), "the walk picks the live rung");
            assert!(
                took < window * 2,
                "3 silent rungs and a live one took {took:?}, more than 2 windows of {window:?}"
            );
        });
    }

    #[test]
    fn select_bootstrap_rung_empty_ladder_is_none() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // Relay disabled / private ⇒ empty ladder ⇒ no probing, `None`
            // (joiners fall back to mDNS/DHT). The ordering/fall-through
            // logic is unit-tested via `select_first_reachable` below; the
            // down-detection primitive by `unreachable_rung_*` below.
            assert!(
                select_bootstrap_rung(&[], std_Duration::from_secs(1), None)
                    .await
                    .is_none(),
                "an empty ladder selects no bootstrap rung"
            );
        });
    }

    // --- liveness primitive (verify-first, CI-safe) -----------------
    //
    // The hardening's whole correctness rests on "online() within the
    // probe budget == this rung is genuinely connected". We can't kill a
    // real relay in CI (no iroh test-utils dep), but we CAN prove the
    // negative half without the network: an endpoint pinned to an
    // unreachable relay never reaches `online()`, so the timeout fires
    // and the rung is correctly judged down. (The positive/up→down
    // transition is the documented manual/local check.)

    #[test]
    fn unreachable_rung_is_detected_as_down() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // RFC-5737 TEST-NET-1, never routable ⇒ the relay handshake can
            // never connect ⇒ `select_bootstrap_rung` finds no reachable rung.
            let bogus: RelayUrl = "https://192.0.2.1./"
                .parse()
                .expect("a literal https URL parses");
            let selected = select_bootstrap_rung(&[bogus], std_Duration::from_secs(2), None).await;
            assert!(
                selected.is_none(),
                "an unreachable relay must not be selected as a live rung"
            );
        });
    }

    // --- liveness debounce (`should_evict_rung`) --------------------

    #[test]
    fn one_failed_poll_does_not_evict() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !should_evict_rung(0),
            "one failed poll does not evict a rung"
        );
        assert!(!should_evict_rung(1), "a single blip must not re-home");
    }

    #[test]
    fn sustained_failures_evict() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            should_evict_rung(RELAY_LIVENESS_FAILS_TO_EVICT),
            "sustained failures evict a rung"
        );
        assert!(
            should_evict_rung(RELAY_LIVENESS_FAILS_TO_EVICT + 5),
            "failures beyond the eviction count still evict"
        );
    }

    /// **A return round that finds no lower rung backs off; one that finds a rung resets.**
    #[test]
    fn a_return_round_that_finds_no_rung_backs_off() {
        let _guard = ::habilis_network_test_tracing::init();
        let times = super::HomingTimes::LIVE;
        let every = times.return_every;
        let after_a_miss = super::next_return_wait(every, false, times);
        assert_eq!(
            after_a_miss,
            every * 2,
            "a round with no answer doubles the wait"
        );
        let mut wait = every;
        for _ in 0..10 {
            wait = super::next_return_wait(wait, false, times);
        }
        assert_eq!(
            wait, times.return_backoff_max,
            "the wait saturates at the backoff cap"
        );
        assert_eq!(
            super::next_return_wait(wait, true, times),
            every,
            "a round that finds a lower rung goes back to the return interval"
        );
    }

    #[test]
    fn backoff_doubles_then_saturates_at_max() {
        let _guard = ::habilis_network_test_tracing::init();
        let max = super::RELAY_REPROBE_BACKOFF_MAX;
        let min = tuning::RELAY_REPROBE_BACKOFF_MIN;
        // Doubles each round...
        let mut backoff = min;
        let next = next_relay_backoff(backoff);
        assert_eq!(next, (min * 2).min(max), "first step doubles");
        // ...and walking it forward saturates at MAX, never beyond.
        for _ in 0..20 {
            backoff = next_relay_backoff(backoff);
        }
        assert_eq!(backoff, max, "backoff saturates at MAX");
        assert_eq!(next_relay_backoff(max), max, "stays capped at MAX");
    }

    // --- ladder walk (`select_first_reachable`) ---------------------
    //
    // Network-free coverage of the walk: a fake probe answers after a delay,
    // up or down, and ends early when the walk stops it. We assert which rung
    // wins, which rungs started, and which probes the walk stopped.

    fn rungs(hosts: &[&str]) -> Vec<RelayUrl> {
        hosts.iter().map(|host| rung(host)).collect()
    }

    fn short_host(url: &RelayUrl) -> String {
        let host = url.host_str().expect("the test URLs carry a host");
        host.trim_end_matches('.')
            .trim_end_matches(".example")
            .to_string()
    }

    fn host_of(rung: Option<&RelayUrl>) -> Option<String> {
        rung.map(short_host)
    }

    /// The fake answer of one rung: after `delay`, up or down.
    struct FakeRung {
        host: &'static str,
        delay: std_Duration,
        up: bool,
    }

    /// What a walk over fake rungs did. `started` is in the order the probes started, and
    /// `stopped` is sorted.
    struct Walk {
        selected: Option<String>,
        started: Vec<String>,
        stopped: Vec<String>,
    }

    /// The stagger of the fake walks: a rung that answers in 10 ms answers before the next starts.
    const FAKE_STAGGER: std_Duration = std_Duration::from_millis(100);

    /// Run the ladder walk over fake rungs, with `stop` as the stop of the caller.
    async fn walk_with(
        fakes: &[FakeRung],
        stop: Option<&watch::Receiver<()>>,
        stagger: std_Duration,
    ) -> Walk {
        let hosts: Vec<&str> = fakes.iter().map(|fake| fake.host).collect();
        let ladder = rungs(&hosts);
        let started = cell::RefCell::new(Vec::new());
        let stopped = cell::RefCell::new(Vec::new());
        let selected = select_first_reachable(&ladder, stop, stagger, |rung, probes_stopped| {
            let host = short_host(&rung);
            let fake = fakes
                .iter()
                .find(|fake| fake.host == host)
                .expect("each rung has a fake");
            let (delay, up) = (fake.delay, fake.up);
            started.borrow_mut().push(host.clone());
            let stopped = &stopped;
            async move {
                let answer = tokio::select! {
                    () = time::sleep(delay) => Some(up),
                    () = super::stopped(Some(probes_stopped)) => None,
                };
                if answer.is_none() {
                    stopped.borrow_mut().push(host);
                }
                answer.unwrap_or(false)
            }
        })
        .await;
        let mut stopped = stopped.into_inner();
        stopped.sort();
        Walk {
            selected: host_of(selected.as_ref()),
            started: started.into_inner(),
            stopped,
        }
    }

    async fn walk(fakes: &[FakeRung]) -> Walk {
        walk_with(fakes, None, FAKE_STAGGER).await
    }

    fn fake(host: &'static str, delay: std_Duration, up: bool) -> FakeRung {
        FakeRung { host, delay, up }
    }

    #[test]
    fn ladder_picks_first_when_all_reachable() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let walked = walk(&[
                fake("a", std_Duration::from_millis(400), true),
                fake("b", std_Duration::from_millis(10), true),
                fake("c", std_Duration::from_millis(10), true),
            ])
            .await;
            assert_eq!(
                walked.selected.as_deref(),
                Some("a"),
                "the first rung is picked when all are reachable, though it answers last"
            );
            assert_eq!(
                walked.started,
                vec!["a", "b", "c"],
                "a slow rung 0 lets the later rungs start, one stagger after the other"
            );
        });
    }

    #[test]
    fn ladder_falls_through_to_next_reachable() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // rung 0 down → rung 1 wins once rung 0 said no; the slow rung 2 is stopped.
            let walked = walk(&[
                fake("a", std_Duration::from_millis(300), false),
                fake("b", std_Duration::from_millis(10), true),
                fake("c", std_Duration::from_millis(5000), true),
            ])
            .await;
            assert_eq!(
                walked.selected.as_deref(),
                Some("b"),
                "the ladder falls through to the next reachable rung"
            );
            assert_eq!(
                walked.stopped,
                vec!["c"],
                "the walk stops the probe of a higher rung once it decides"
            );
        });
    }

    #[test]
    fn ladder_skips_multiple_dead_prefix_rungs() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let walked = walk(&[
                fake("a", std_Duration::from_millis(30), false),
                fake("b", std_Duration::from_millis(30), false),
                fake("c", std_Duration::from_millis(10), true),
            ])
            .await;
            assert_eq!(
                walked.selected.as_deref(),
                Some("c"),
                "the ladder skips multiple dead prefix rungs"
            );
            assert_eq!(
                walked.started,
                vec!["a", "b", "c"],
                "the walk starts each rung in order"
            );
        });
    }

    #[test]
    fn ladder_prefers_first_rung_when_it_recovers() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // "reset and start from the first": the walk always re-picks the
            // earliest reachable rung, so a recovered rung 0 wins over a
            // still-up rung 1.
            let walked = walk(&[
                fake("a", std_Duration::from_millis(5), true),
                fake("b", std_Duration::from_millis(5), true),
                fake("c", std_Duration::from_millis(5), true),
            ])
            .await;
            assert_eq!(
                walked.selected.as_deref(),
                Some("a"),
                "the first rung is preferred again once it recovers"
            );
            assert_eq!(
                walked.started,
                vec!["a"],
                "a rung 0 that answers within the stagger starts no later rung"
            );
        });
    }

    #[test]
    fn ladder_all_down_is_none() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let walked = walk(&[
                fake("a", std_Duration::from_millis(10), false),
                fake("b", std_Duration::from_millis(10), false),
                fake("c", std_Duration::from_millis(10), false),
            ])
            .await;
            assert!(
                walked.selected.is_none(),
                "every rung down ⇒ None (use mDNS/DHT)"
            );
            assert_eq!(
                walked.started,
                vec!["a", "b", "c"],
                "probes the whole ladder"
            );
        });
    }

    #[test]
    fn ladder_empty_is_none_without_probing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let walked = walk(&[]).await;
            assert!(walked.selected.is_none(), "an empty ladder selects nothing");
            assert!(walked.started.is_empty(), "an empty ladder probes nothing");
        });
    }

    /// **A rung that says no starts the next rung at once, not after the stagger.**
    #[test]
    fn a_rung_that_says_no_starts_the_next_at_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let started = time::Instant::now();
            let fakes = [
                fake("a", std_Duration::from_millis(10), false),
                fake("b", std_Duration::from_millis(10), true),
            ];
            let walked = walk_with(&fakes, None, std_Duration::from_secs(10)).await;
            let took = started.elapsed();
            assert_eq!(walked.selected.as_deref(), Some("b"), "rung 1 answers");
            assert!(
                took < std_Duration::from_secs(1),
                "the walk waited {took:?} for a stagger of 10 s after rung 0 said no"
            );
        });
    }

    /// **A walk that its caller stops ends every probe before it returns.**
    #[test]
    fn the_walk_stops_every_probe_when_its_caller_stops() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (stop, stopped) = watch::channel(());
            let stopping = async {
                time::sleep(std_Duration::from_millis(300)).await;
                drop(stop);
            };
            let fakes = [
                fake("a", std_Duration::from_millis(5000), true),
                fake("b", std_Duration::from_millis(5000), true),
            ];
            let (walked, ()) =
                tokio::join!(walk_with(&fakes, Some(&stopped), FAKE_STAGGER), stopping);
            assert!(walked.selected.is_none(), "a stopped walk selects nothing");
            assert_eq!(
                walked.stopped,
                vec!["a", "b"],
                "the walk stops every probe in flight"
            );
        });
    }

    /// The script of one fake rung: what each probe of it answers, after how many milliseconds.
    /// The probe that is the n-th of the rung takes the n-th answer, or the last one when the
    /// script is shorter.
    type Script = (&'static str, &'static [(u64, bool)]);

    /// Run the ladder walk over scripted rungs on paused time. Returns the selected rung and the
    /// rungs of the probes, in the order that they started.
    async fn walk_scripted(
        script: &[Script],
        stagger: std_Duration,
    ) -> (Option<String>, Vec<String>) {
        time::pause();
        let hosts: Vec<&str> = script.iter().map(|(host, _)| *host).collect();
        let ladder = rungs(&hosts);
        let started = cell::RefCell::new(Vec::new());
        let selected = select_first_reachable(&ladder, None, stagger, |rung, probes_stopped| {
            let host = short_host(&rung);
            let (_, answers) = script
                .iter()
                .find(|(scripted, _)| *scripted == host)
                .expect("each rung has a script");
            let nth: usize = started
                .borrow()
                .iter()
                .filter(|seen| **seen == host)
                .count();
            let scripted = answers.get(nth).or_else(|| answers.last());
            let (delay, up) = scripted
                .copied()
                .expect("each rung scripts one answer at least");
            let delay = std_Duration::from_millis(delay);
            started.borrow_mut().push(host);
            async move {
                tokio::select! {
                    () = time::sleep(delay) => up,
                    () = super::stopped(Some(probes_stopped)) => false,
                }
            }
        })
        .await;
        (host_of(selected.as_ref()), started.into_inner())
    }

    /// **A rung that answered while a lower rung was still silent is asked again before the walk
    /// takes it.**
    ///
    /// Rung 0 is silent for 3 s. Rung 1 answers at 1.5 s, and is offline again when rung 0 says
    /// no. Rung 2 stays up. The old sequential walk first probed rung 1 after rung 0 timed out,
    /// found it dead, and fell through to rung 2.
    #[test]
    fn a_rung_that_answered_behind_a_silent_one_is_asked_again() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (selected, started) = walk_scripted(
                &[
                    ("a", &[(3000, false)]),
                    ("b", &[(1500, true), (10, false)]),
                    ("c", &[(2000, true)]),
                ],
                std_Duration::from_secs(1),
            )
            .await;
            assert_eq!(
                selected.as_deref(),
                Some("c"),
                "rung 1 went offline while rung 0 was silent: the walk falls through to rung 2"
            );
            assert_eq!(
                started,
                vec!["a", "b", "c", "b"],
                "rung 1 is asked again when rung 0 says no"
            );
        });
    }

    /// **A rung that still answers when it is asked again is the pick.**
    #[test]
    fn a_rung_that_answers_again_behind_a_silent_one_is_picked() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (selected, started) = walk_scripted(
                &[
                    ("a", &[(3000, false)]),
                    ("b", &[(1500, true), (10, true)]),
                    ("c", &[(2000, true)]),
                ],
                std_Duration::from_secs(1),
            )
            .await;
            assert_eq!(selected.as_deref(), Some("b"), "rung 1 is still up");
            assert_eq!(
                started,
                vec!["a", "b", "c", "b"],
                "rung 1 is asked once more, after rung 0 says no"
            );
        });
    }

    /// **A rung 0 that answers at once is picked on its first answer.**
    ///
    /// The fast path stays: no later rung is probed, and nothing is asked twice.
    #[test]
    fn a_rung_that_answers_first_with_nothing_below_it_is_not_asked_again() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (selected, started) = walk_scripted(
                &[("a", &[(10, true)]), ("b", &[(10, true)])],
                std_Duration::from_secs(1),
            )
            .await;
            assert_eq!(selected.as_deref(), Some("a"), "rung 0 answers");
            assert_eq!(started, vec!["a"], "one probe, and no later rung");
        });
    }

    /// **A rung that answers after every lower rung said no is picked on its first answer.**
    #[test]
    fn a_rung_that_answers_after_the_lower_ones_said_no_is_not_asked_again() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (selected, started) = walk_scripted(
                &[("a", &[(10, false)]), ("b", &[(10, true)])],
                std_Duration::from_secs(1),
            )
            .await;
            assert_eq!(selected.as_deref(), Some("b"), "rung 1 answers");
            assert_eq!(started, vec!["a", "b"], "each rung is probed once");
        });
    }

    // --- steady-state failover decision (`plan_rung_refresh`) -------
    //
    // The beacon-held / relay-enabled gate lives in the event loop (it
    // owns that state); here we cover only the pure change-detection.

    fn rung(host: &str) -> RelayUrl {
        format!("https://{host}.example./")
            .parse()
            .expect("a test host forms a valid https URL")
    }

    #[test]
    fn refresh_no_op_when_current_rung_still_first_reachable() {
        let _guard = ::habilis_network_test_tracing::init();
        let action = plan_rung_refresh(Some(rung("a")).as_ref(), Some(rung("a")));
        assert_eq!(
            action,
            RungRefresh::NoChange,
            "no change when the current rung is still the first reachable"
        );
    }

    /// A rung over plain `http://` has no TLS, and QUIC needs TLS, so it cannot serve QUIC
    /// address discovery. An endpoint that probes the default QUIC port of such a rung waits for
    /// the 3 s probe timeout of iroh before its first net report, and has no home relay until
    /// then: a peer that dials it through the relay in that time meets a relay that drops the
    /// packet.
    #[tokio::test]
    async fn an_endpoint_on_a_plain_http_rung_is_online_without_the_probe_timeout() {
        let (url, _server) = test_relay::spawn_plain()
            .await
            .expect("a plain local relay");
        let endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(super::one_rung_mode(Some(&url)))
            .bind()
            .await
            .expect("bind an endpoint on the rung");

        let online = time::timeout(std_Duration::from_secs(2), endpoint.online())
            .await
            .is_ok();
        endpoint.close().await;

        assert!(online, "no home relay after 2 s");
    }

    #[test]
    fn refresh_rehomes_when_current_rung_died() {
        // current rung a is gone; the walk now returns b → re-home to b.
        let _guard = ::habilis_network_test_tracing::init();
        let action = plan_rung_refresh(Some(rung("a")).as_ref(), Some(rung("b")));
        assert_eq!(
            action,
            RungRefresh::Rehome(Some(rung("b"))),
            "the refresh rehomes when the current rung died"
        );
    }

    #[test]
    fn refresh_rehomes_back_to_earlier_recovered_rung() {
        // we were on b (a had been down); a recovered → reset to a.
        let _guard = ::habilis_network_test_tracing::init();
        let action = plan_rung_refresh(Some(rung("b")).as_ref(), Some(rung("a")));
        assert_eq!(
            action,
            RungRefresh::Rehome(Some(rung("a"))),
            "the refresh rehomes back to the recovered earlier rung"
        );
    }

    #[test]
    fn refresh_rehomes_to_none_when_all_rungs_die() {
        // every rung unreachable → drop the relay, lean on mDNS/DHT.
        let _guard = ::habilis_network_test_tracing::init();
        let action = plan_rung_refresh(Some(rung("a")).as_ref(), None);
        assert_eq!(
            action,
            RungRefresh::Rehome(None),
            "the refresh rehomes to no rung when all rungs die"
        );
    }

    #[test]
    fn refresh_rehomes_when_relay_recovers_from_none() {
        // we had no rung (all were down); one came back → adopt it.
        let _guard = ::habilis_network_test_tracing::init();
        let action = plan_rung_refresh(None, Some(rung("a")));
        assert_eq!(
            action,
            RungRefresh::Rehome(Some(rung("a"))),
            "the refresh rehomes from none when the relay recovers"
        );
    }
}
