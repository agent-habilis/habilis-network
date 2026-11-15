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
mod rung_path;
mod rung_refresh;
mod stoppable_task;

use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use iroh::defaults::DEFAULT_RELAY_QUIC_PORT;
use iroh::endpoint::{RelayStatus, presets};
use iroh::{Endpoint, RelayConfig, RelayMode, RelayUrl, Watcher};
use tokio::sync::watch;

pub use default_rung::DefaultRung;
use return_watch::ReturnWatch;
pub use rung_path::RungPath;
pub(crate) use rung_refresh::RungRefresh;
pub(crate) use stoppable_task::StoppableTask;

use crate::protocol::meshes::RelayChoice;
use crate::util::tuning::{
    RELAY_LIVENESS_FAILS_TO_EVICT, RELAY_LIVENESS_INTERVAL, RELAY_REPROBE_BACKOFF_MAX,
    RELAY_REPROBE_BACKOFF_MIN, RELAY_RETURN_HOLD, RELAY_RETURN_PROBE_INTERVAL, RELAY_RUNG_PROBE,
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
/// Rungs 0..4 are our relays. Rungs 1 and 2 name one relay process, by its
/// direct path and by its tunnel. iroh opens one relay session per URL, and a
/// relay drops the older session of an endpoint id, so a relay map that holds
/// both names makes an endpoint drop its own session. No map holds 2 rungs: an
/// endpoint homes on one rung, alone in its map ([`peer_relay_mode`]). Rungs
/// 0..2 are direct: each relay answers QUIC address discovery, so a member
/// homed on it learns its public address. Rungs 2..4 are tunnels: the tunnel
/// carries no UDP, so they answer no QUIC address discovery, and an endpoint
/// that asked them for it would wait 3 s for its first net report. Rungs 4..8
/// are iroh `defaults::prod`, which are direct.
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
        url: "https://nyc-relay2.agent-habilis.com/",
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
    /// How often a member on a later rung probes the rungs below it.
    return_every: Duration,
    /// How long a lower rung must answer every probe round before the member returns to it.
    return_hold: Duration,
}

impl HomingTimes {
    /// The times of a real member.
    const LIVE: Self = Self {
        probe: RELAY_RUNG_PROBE,
        interval: RELAY_LIVENESS_INTERVAL,
        return_every: RELAY_RETURN_PROBE_INTERVAL,
        return_hold: RELAY_RETURN_HOLD,
    };
}

impl Homing {
    /// Move the endpoint to the first reachable rung each time its rung does not connect, until
    /// the endpoint closes. The endpoint swaps its own relay map in place, because a peer endpoint
    /// cannot be rebuilt under its owner.
    ///
    /// A rung is alive when the status of the home relay says that the relay connection is up,
    /// and, off the browser, the net report of iroh still has a preferred relay. Neither signal is
    /// enough alone. A relay that answers its HTTP probe and refuses the relay connection can keep a
    /// preferred relay but has no connection. A relay that dies keeps its connection in the status
    /// for minutes, and the probes of the net report find it dead. A browser has no net report, so
    /// the status alone decides there. A rung that has not connected when the probe time of a
    /// rung ends counts as dead at once. A later read counts one failure per interval.
    ///
    /// On a later rung, the endpoint probes the rungs below it each [`RELAY_RETURN_PROBE_INTERVAL`],
    /// and returns to the lowest one once it answered every round for [`RELAY_RETURN_HOLD`]. A
    /// move on failure alone would keep the endpoint on a later rung after rung 0 comes back.
    pub(super) fn follow(self, endpoint: Endpoint) {
        drop(self.follow_with(endpoint, HomingTimes::LIVE));
    }

    /// [`Self::follow`] with its times as parameters. It returns the task, which ends when the
    /// endpoint closes.
    fn follow_with(self, endpoint: Endpoint, times: HomingTimes) -> n0future_task::JoinHandle<()> {
        n0future_task::spawn(async move {
            let mut status = endpoint.home_relay_status();
            let connected_at_start = tokio::select! {
                connected = n0future_time::timeout(
                    times.probe,
                    wait_for_home_connection(&mut status, &self.rung),
                ) => matches!(connected, Ok(true)),
                _closed = endpoint.closed() => return,
            };
            self.follow_ladder(&endpoint, &mut status, connected_at_start, times)
                .await;
        })
    }

    /// The loop of [`Self::follow_with`] after the first connection of the rung. Returns when the
    /// endpoint closes.
    async fn follow_ladder(
        self,
        endpoint: &Endpoint,
        status: &mut impl Watcher<Value = Vec<RelayStatus>>,
        connected_at_start: bool,
        times: HomingTimes,
    ) {
        let Self { ladder, mut rung } = self;
        let mut fails: u32 = if connected_at_start {
            0
        } else {
            RELAY_LIVENESS_FAILS_TO_EVICT
        };
        // The first walk of a rung that never connected does not probe it again: the probe
        // would wait out its time. A later walk probes the whole ladder, because a net report
        // under load can drop the preferred relay of a live rung, and the walk must be able
        // to stay on it.
        let mut skip_rung = !connected_at_start;
        let mut returning = ReturnWatch::default();
        let mut next_return_probe = Instant::now() + times.return_every;
        loop {
            if should_evict_rung(fails) {
                fails = 0;
                let walk = rungs_to_walk(&ladder, &rung, skip_rung);
                skip_rung = false;
                let selected = walk_until_closed(endpoint, |stop| async move {
                    select_bootstrap_rung(&walk, times.probe, Some(&stop)).await
                })
                .await;
                if endpoint.is_closed() {
                    return;
                }
                if let Some(next) = selected.filter(|next| *next != rung) {
                    tracing::info!(target: "habilis_network::lookup", from = %rung, to = %next, "peer endpoint moves to the next relay rung");
                    move_home(endpoint, &rung, &next).await;
                    rung = next;
                    returning = ReturnWatch::default();
                }
            }
            tokio::select! {
                () = n0future_time::sleep(times.interval) => {}
                _closed = endpoint.closed() => return,
            }
            fails = if home_connected(&status.get(), &rung) && probes_answer(endpoint) {
                0
            } else {
                fails + 1
            };
            if fails > 0 || Instant::now() < next_return_probe {
                continue;
            }
            next_return_probe = Instant::now() + times.return_every;
            let lower = walk_until_closed(endpoint, |stop| {
                probe_return(&rung, &ladder, &mut returning, times, stop)
            })
            .await;
            if endpoint.is_closed() {
                return;
            }
            if let Some(lower) = lower {
                tracing::info!(target: "habilis_network::lookup", from = %rung, to = %lower, "peer endpoint returns to a lower relay rung");
                move_home(endpoint, &rung, &lower).await;
                rung = lower;
            }
        }
    }
}

/// Move the home of `endpoint` from the rung `from` to the rung `to`.
async fn move_home(endpoint: &Endpoint, from: &RelayUrl, to: &RelayUrl) {
    // The relay actor of iroh shares the config of a relay.
    let config = Arc::new(rung_config(to));
    endpoint.insert_relay(to.clone(), config).await;
    endpoint.remove_relay(from).await;
}

/// Run `walk` with a stop that fires when `endpoint` closes, and return what it selects. On a close
/// the walk still ends, and closes its probe endpoints, before this returns.
async fn walk_until_closed<Walk, Fut>(endpoint: &Endpoint, walk: Walk) -> Option<RelayUrl>
where
    Walk: FnOnce(watch::Receiver<()>) -> Fut,
    Fut: Future<Output = Option<RelayUrl>>,
{
    let (stop_walk, stopped_walk) = watch::channel(());
    let walking = walk(stopped_walk);
    tokio::pin!(walking);
    tokio::select! {
        selected = &mut walking => selected,
        _closed = endpoint.closed() => {
            drop(stop_walk);
            walking.await;
            None
        }
    }
}

/// One probe round of the rungs below `home`. Returns the lowest of them once it answered every
/// round for the hold time of `times`, and `None` before that, or once `stop`'s sender is dropped.
async fn probe_return(
    home: &RelayUrl,
    ladder: &[RelayUrl],
    returning: &mut ReturnWatch,
    times: HomingTimes,
    stop: watch::Receiver<()>,
) -> Option<RelayUrl> {
    let below = rungs_below(ladder, home);
    if below.is_empty() {
        return None;
    }
    let lowest = select_first_reachable(below, Some(&stop), |rung, probes_stopped| async move {
        relay_rung_reachable(&rung, times.probe, Some(probes_stopped)).await
    })
    .await;
    if is_stopped(&stop) {
        return None;
    }
    returning.observe(lowest, Instant::now(), times.return_hold)
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
/// The walk probes every rung at once, so a ladder of silent rungs costs one
/// window of `per_rung`, not one window for each rung. Eight concurrent probes
/// cost about the CPU of eight probes in order, and about 80 sockets at the
/// peak.
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
    let selected = select_first_reachable(ladder, stop, |rung, probes_stopped| async move {
        let reachable = relay_rung_reachable(&rung, per_rung, Some(probes_stopped)).await;
        if !reachable {
            tracing::debug!(target: "habilis_network::lookup", relay = %rung, "bootstrap relay rung did not answer");
        }
        reachable
    })
    .await;
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
/// every rung at once, and return the lowest rung for which `reachable` is
/// `true`, else `None`. A rung wins only when every rung below it said no, so a
/// lower rung that answers late still beats a higher rung that answers early.
/// That is what makes the selection deterministic across members, and what
/// makes a recovered earlier rung win over a later one on every (re)selection.
///
/// Each probe gets a receiver whose sender the walk drops once it decides, or
/// once `stop`'s sender is dropped. The walk then waits for every probe to end,
/// so no probe outlives it. Generic over the reachability probe so the order
/// logic is unit tested without touching the network.
async fn select_first_reachable<Probe, Fut>(
    ladder: &[RelayUrl],
    stop: Option<&watch::Receiver<()>>,
    mut reachable: Probe,
) -> Option<RelayUrl>
where
    Probe: FnMut(RelayUrl, watch::Receiver<()>) -> Fut,
    Fut: Future<Output = bool>,
{
    use futures_util::StreamExt as _;

    let (stop_probes, probes_stopped) = watch::channel(());
    let mut stop_probes = Some(stop_probes);
    let mut probes: FuturesUnordered<_> = ladder
        .iter()
        .enumerate()
        .map(|(index, rung)| {
            let probe = reachable(rung.clone(), probes_stopped.clone());
            async move { (index, probe.await) }
        })
        .collect();
    let mut answers: Vec<Option<bool>> = vec![None; ladder.len()];
    let mut selected = None;
    loop {
        let next = tokio::select! {
            next = probes.next() => next,
            () = stopped(stop.cloned()), if stop_probes.is_some() => {
                stop_probes = None;
                continue;
            }
        };
        let Some((index, answer)) = next else {
            return selected;
        };
        if let Some(slot) = answers.get_mut(index) {
            *slot = Some(answer);
        }
        if stop_probes.is_none() {
            continue;
        }
        match lowest_reachable(&answers) {
            WalkVerdict::Waiting => {}
            WalkVerdict::Rung(lowest) => {
                selected = ladder.get(lowest).cloned();
                stop_probes = None;
            }
            WalkVerdict::NoRung => stop_probes = None,
        }
    }
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
/// - **Homed** (`homed`, built with a rung): poll our own
///   `endpoint.online()` every [`RELAY_LIVENESS_INTERVAL`] — cheap,
///   reuses the live relay connection. `online()` resolves only when a
///   relay handshake is connected, so a `timeout` failure means the rung
///   is unreachable; [`should_evict_rung`] debounces transient blips
///   (iroh auto-reconnects within a tick). On a sustained outage, re-walk
///   the ladder once and publish the result (`Some` ⇒ re-home, `None` ⇒
///   demote to relay-less). On a later rung, also probe the rungs below
///   it each [`RELAY_RETURN_PROBE_INTERVAL`], and publish the lowest one
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
    rung_tx: watch::Sender<Option<RelayUrl>>,
    homed: bool,
) -> StoppableTask {
    StoppableTask::spawn(|stop| async move {
        if homed {
            monitor_homed_rung(&endpoint, &ladder, &rung_tx, HomingTimes::LIVE, &stop).await;
        } else {
            monitor_relay_less(&ladder, &rung_tx, RELAY_RUNG_PROBE, &stop).await;
        }
    })
}

/// Poll the rung we're homed on until a sustained outage, then re-walk the
/// ladder once and publish the result. On a later rung, publish the lowest
/// rung below it once that rung answered every probe round for the hold
/// time. Split out of [`spawn_relay_monitor`] so the loop body isn't nested
/// inside the spawned future's `if homed`.
async fn monitor_homed_rung(
    endpoint: &Endpoint,
    ladder: &[RelayUrl],
    rung_tx: &watch::Sender<Option<RelayUrl>>,
    times: HomingTimes,
    stop: &watch::Receiver<()>,
) {
    // The event loop homes the beacon on the rung of `rung_tx`.
    let home: Option<RelayUrl> = rung_tx.borrow().clone();
    let mut fails: u32 = 0;
    let mut returning = ReturnWatch::default();
    let mut next_return_probe = Instant::now() + times.return_every;
    loop {
        let poll = async {
            n0future_time::sleep(times.interval).await;
            n0future_time::timeout(times.probe, endpoint.online())
                .await
                .is_ok()
        };
        let online = tokio::select! {
            online = poll => online,
            () = stopped(Some(stop.clone())) => return,
        };
        fails = if online { 0 } else { fails + 1 };
        if should_evict_rung(fails) {
            tracing::info!(
                target: "habilis_network::lookup",
                fails,
                "beacon relay rung unreachable; re-walking the ladder"
            );
            let selected = select_bootstrap_rung(ladder, times.probe, Some(stop)).await;
            if !is_stopped(stop) {
                let _ = rung_tx.send(selected);
            }
            return;
        }
        let Some(home) = home.as_ref().filter(|_| online) else {
            continue;
        };
        if Instant::now() < next_return_probe {
            continue;
        }
        next_return_probe = Instant::now() + times.return_every;
        let lower = probe_return(home, ladder, &mut returning, times, stop.clone()).await;
        if is_stopped(stop) {
            return;
        }
        if let Some(lower) = lower {
            tracing::info!(
                target: "habilis_network::lookup",
                from = %home,
                to = %lower,
                "beacon returns to a lower relay rung"
            );
            let _ = rung_tx.send(Some(lower));
            return;
        }
    }
}

/// Relay-less: keep re-walking the ladder to rediscover a rung, backing off
/// after each fruitless round so an all-down ladder isn't hammered. Never
/// stops. Split out of [`spawn_relay_monitor`] for the same reason as
/// [`monitor_homed_rung`].
async fn monitor_relay_less(
    ladder: &[RelayUrl],
    rung_tx: &watch::Sender<Option<RelayUrl>>,
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
            let _ = rung_tx.send(Some(rung));
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
        RungRefresh, next_relay_backoff, plan_rung_refresh, relay_ladder, select_bootstrap_rung,
        select_first_reachable, should_evict_rung,
    };
    use crate::lookup::{TransportOpts, build_peer_endpoint, build_peer_webrtc};
    use crate::protocol::meshes::LookupOpts;
    use iroh::defaults::DEFAULT_RELAY_QUIC_PORT;
    use iroh::{RelayMode, Watcher as _};
    use iroh_relay::server::Server;
    use n0_future::task as n0future_task;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
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
            ("https://nyc-relay2.agent-habilis.com/", direct),
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
        let homing = homing.expect("a ladder of 8 rungs has a choice to make");
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
            let (rung_tx, rung_rx) = watch::channel(Some(second.clone()));
            let (_stop, stopped) = watch::channel(());
            let hold = std_Duration::from_secs(3);
            let ladder = [first.clone(), second];

            let started = time::Instant::now();
            let published = time::timeout(
                std_Duration::from_secs(30),
                super::monitor_homed_rung(
                    &endpoint,
                    &ladder,
                    &rung_tx,
                    return_times(hold),
                    &stopped,
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
                *rung_rx.borrow(),
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
    /// that takes that as a dead rung evicts a healthy rung and walks the ladder. The walk probes
    /// every rung, so the count of the second relay grows.
    #[test]
    #[ignore = "60 s: waits for 2 periods of the net report of iroh"]
    fn a_peer_on_a_healthy_rung_without_qad_is_not_evicted() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (first, _first_server) = test_relay::spawn_plain().await.expect("a local relay");
            let (second, second_server) = test_relay::spawn_plain().await.expect("a local relay");
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
            let walked = http_connections(&second_server);
            endpoint.close().await;
            drop(follower.await);

            assert_eq!(
                walked, 0,
                "the endpoint judged its healthy rung dead and walked the ladder"
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

    /// How many HTTP connections a relay accepted. An endpoint that holds a relay in its map
    /// connects to it to measure the latency, even when it does not home on it.
    fn http_connections(server: &Server) -> u64 {
        server.metrics().server.http_connections.get()
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

    /// **The walk probes every rung at once.**
    ///
    /// A walk that probes one rung after the other waits a full window for each silent rung
    /// before it reaches a live one: 3 silent rungs cost 3 windows. The walk probes every rung at
    /// once, so it waits one window for the silent rungs below the live one, and every member
    /// still picks the same rung.
    #[test]
    fn the_walk_probes_every_rung_at_once() {
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

            let started = time::Instant::now();
            let selected = select_bootstrap_rung(&ladder, window, None).await;
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
    // wins, how many probes ran at once, and which probes the walk stopped.

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

    /// The fake answer of one rung: after `delay_ms`, up or down.
    struct FakeRung {
        host: &'static str,
        delay_ms: u64,
        up: bool,
    }

    /// What a walk over fake rungs did. `stopped` is sorted.
    struct Walk {
        selected: Option<String>,
        most_at_once: usize,
        stopped: Vec<String>,
    }

    /// Run the ladder walk over fake rungs, with `stop` as the stop of the caller.
    async fn walk_with(fakes: &[FakeRung], stop: Option<&watch::Receiver<()>>) -> Walk {
        let hosts: Vec<&str> = fakes.iter().map(|fake| fake.host).collect();
        let ladder = rungs(&hosts);
        let in_flight = cell::Cell::new(0_usize);
        let most_at_once = cell::Cell::new(0_usize);
        let stopped = cell::RefCell::new(Vec::new());
        let selected = select_first_reachable(&ladder, stop, |rung, probes_stopped| {
            let host = short_host(&rung);
            let fake = fakes
                .iter()
                .find(|fake| fake.host == host)
                .expect("each rung has a fake");
            let (delay, up) = (std_Duration::from_millis(fake.delay_ms), fake.up);
            let (in_flight, most_at_once, stopped) = (&in_flight, &most_at_once, &stopped);
            async move {
                in_flight.set(in_flight.get() + 1);
                most_at_once.set(most_at_once.get().max(in_flight.get()));
                let answer = tokio::select! {
                    () = time::sleep(delay) => Some(up),
                    () = super::stopped(Some(probes_stopped)) => None,
                };
                in_flight.set(in_flight.get() - 1);
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
            most_at_once: most_at_once.get(),
            stopped,
        }
    }

    async fn walk(fakes: &[FakeRung]) -> Walk {
        walk_with(fakes, None).await
    }

    fn fake(host: &'static str, delay_ms: u64, up: bool) -> FakeRung {
        FakeRung { host, delay_ms, up }
    }

    #[test]
    fn ladder_picks_first_when_all_reachable() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let walked = walk(&[
                fake("a", 100, true),
                fake("b", 10, true),
                fake("c", 10, true),
            ])
            .await;
            assert_eq!(
                walked.selected.as_deref(),
                Some("a"),
                "the first rung is picked when all are reachable, though it answers last"
            );
            assert_eq!(walked.most_at_once, 3, "every rung is probed at once");
        });
    }

    #[test]
    fn ladder_falls_through_to_next_reachable() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // rung 0 down → rung 1 wins once rung 0 said no; the slow rung 2 is stopped.
            let walked = walk(&[
                fake("a", 50, false),
                fake("b", 10, true),
                fake("c", 1000, true),
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
                fake("a", 30, false),
                fake("b", 30, false),
                fake("c", 10, true),
            ])
            .await;
            assert_eq!(
                walked.selected.as_deref(),
                Some("c"),
                "the ladder skips multiple dead prefix rungs"
            );
            assert_eq!(
                walked.most_at_once, 3,
                "the dead rungs and the live one are probed at once"
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
                fake("a", 10, true),
                fake("b", 10, true),
                fake("c", 10, true),
            ])
            .await;
            assert_eq!(
                walked.selected.as_deref(),
                Some("a"),
                "the first rung is preferred again once it recovers"
            );
        });
    }

    #[test]
    fn ladder_all_down_is_none() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let walked = walk(&[
                fake("a", 10, false),
                fake("b", 10, false),
                fake("c", 10, false),
            ])
            .await;
            assert!(
                walked.selected.is_none(),
                "every rung down ⇒ None (use mDNS/DHT)"
            );
            assert_eq!(walked.most_at_once, 3, "probes the whole ladder at once");
        });
    }

    #[test]
    fn ladder_empty_is_none_without_probing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let walked = walk(&[]).await;
            assert!(walked.selected.is_none(), "an empty ladder selects nothing");
            assert_eq!(walked.most_at_once, 0, "an empty ladder probes nothing");
        });
    }

    /// **A walk that its caller stops ends every probe before it returns.**
    #[test]
    fn the_walk_stops_every_probe_when_its_caller_stops() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (stop, stopped) = watch::channel(());
            let stopping = async {
                time::sleep(std_Duration::from_millis(20)).await;
                drop(stop);
            };
            let fakes = [fake("a", 1000, true), fake("b", 1000, true)];
            let (walked, ()) = tokio::join!(walk_with(&fakes, Some(&stopped)), stopping);
            assert!(walked.selected.is_none(), "a stopped walk selects nothing");
            assert_eq!(
                walked.stopped,
                vec!["a", "b"],
                "the walk stops every probe in flight"
            );
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
