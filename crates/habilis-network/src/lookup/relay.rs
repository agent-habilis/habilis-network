//! The relay leg of the lookup layer: the default **relay ladder** (n0
//! prod), how a [`RelayChoice`] maps to an iroh [`RelayMode`], and the
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
mod rung_refresh;
mod stoppable_task;

use std::future::Future;
use std::sync::LazyLock;
use std::time::Duration;

use iroh::endpoint::{default_relay_mode, presets};
use iroh::{Endpoint, RelayConfig, RelayMode, RelayUrl};
use tokio::sync::watch;

pub(crate) use rung_refresh::RungRefresh;
pub(crate) use stoppable_task::StoppableTask;

use crate::protocol::meshes::RelayChoice;
use crate::util::tuning::{
    RELAY_LIVENESS_FAILS_TO_EVICT, RELAY_LIVENESS_INTERVAL, RELAY_REPROBE_BACKOFF_MAX,
    RELAY_REPROBE_BACKOFF_MIN, RELAY_RUNG_PROBE,
};
use n0_future::time as n0future_time;

/// The default relay **ladder** — n0's prod relay set, in fixed
/// preference order. The beacon homes on the first reachable rung
/// (`select_bootstrap_rung`) and the joiner pre-registers
/// `rendezvous_id` at that same rung — `EndpointAddr::new(rendezvous_id)
/// .with_relay_url(rung)` — for a **zero-address-lookup** relay-direct
/// dial: a creator-independent bootstrap that needs no address lookup to
/// reach the rendezvous.
///
/// rung 0 is our own operated relay; rungs 1..4 are iroh `defaults::prod`
/// (NA-east, NA-west, EU, AP) as the resilient fallback. Hardcoded,
/// **not** `defaults::prod::default_relay_map()`, so members on different
/// iroh versions still agree on the *same* ladder. Relay infra is
/// versioned and not cross-compatible (sendme #121): an iroh bump can
/// move `defaults::prod` off these hosts, silently breaking the
/// relay-direct bootstrap for members on a different iroh version.
/// `pinned_ladder_matches_iroh_prod` is the tripwire — it fails
/// on such a move so we review (do these hosts still operate?) before
/// shipping the bump.
///
/// Last such move: iroh 1.0.1 retired the `iroh-canary` infix for the
/// stable `*.relay.n0.iroh.link` hosts. Mixed-ladder meshes (binaries
/// from before/after that bump) still rendezvous via rung 0, which is
/// ladder-version-independent; only the fallback rungs diverge. The
/// `relay.agent-habilis.com` cutover then moved rung 0 itself: binaries
/// from before it home on the retired `swarm-relay.…` host, so they
/// cannot relay-direct rendezvous with binaries from after.
pub const RENDEZVOUS_RELAY_LADDER: [&str; 5] = [
    // No trailing-dot FQDN on any rung. Safari rejects the certificate of a
    // dotted host, so a browser member could reach none of them. Rung 0 has
    // a second reason: Cloudflare routes by exact Host header and 404s the
    // dotted form (including the /relay websocket upgrade).
    "https://relay.agent-habilis.com/",   // ours (rung 0)
    "https://use1-1.relay.n0.iroh.link/", // NA-east
    "https://usw1-1.relay.n0.iroh.link/", // NA-west
    "https://euc1-1.relay.n0.iroh.link/", // EU
    "https://aps1-1.relay.n0.iroh.link/", // AP
];

/// Parsed once; `RelayUrl` clones are `Arc`-backed (cheap).
static RENDEZVOUS_RELAY_LADDER_URLS: LazyLock<Vec<RelayUrl>> = LazyLock::new(|| {
    RENDEZVOUS_RELAY_LADDER
        .iter()
        .map(|raw| {
            raw.parse()
                .expect("RENDEZVOUS_RELAY_LADDER entries are valid relay URL constants")
        })
        .collect()
});

/// Resolve a [`RelayChoice`] into the ordered relay **ladder**:
/// `Disabled` ⇒ empty (no relay), `Pinned` ⇒ the default n0 prod
/// ladder, `Custom` ⇒ the operator ladder (`--relay a,b,c`, order
/// preserved). The beacon homes on, and the joiner pre-registers at, the
/// first reachable rung (`select_bootstrap_rung`) — the beacon leg of
/// `relay_mode` and `daemon::setup::register_rendezvous` must agree or
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

/// The relay config of one rung. A rung over plain `http://` has no TLS, and QUIC needs TLS, so
/// it cannot serve QUIC address discovery. Probing its default QUIC port holds the first net
/// report until the 3 s probe timeout of iroh, and the endpoint has no home relay until then.
fn rung_config(url: &RelayUrl) -> RelayConfig {
    let mut config = RelayConfig::from(url.clone());
    if url.scheme() == "http" {
        config.quic = None;
    }
    config
}

/// Map a [`RelayChoice`] to the iroh [`RelayMode`] for an endpoint.
///
/// - **Beacon** homes on exactly **one** rung — the deterministic relay
///   joiners pre-register. The caller encodes that by passing a
///   one-element `Custom([rung])` (the rung `select_bootstrap_rung`
///   chose), so the beacon never reaches the multi-relay `Pinned` arm.
/// - **Peer** on `Pinned` uses iroh's resilient multi-relay
///   `default_relay_mode()` (the n0 prod set): pinning a peer to
///   one relay made `bind()` block on that relay's handshake and dropped
///   iroh's relay fallback — a `Default` peer still reaches the
///   beacon at its rung and skips relays entirely same-LAN via mDNS. A
///   `Custom` ladder pins the peer to that whole set.
///
/// So `Custom(ladder)` covers both: a 1-rung beacon and a multi-rung
/// peer alike map to `RelayMode::Custom`.
pub(super) fn relay_mode(choice: &RelayChoice) -> RelayMode {
    match choice {
        RelayChoice::Disabled => {
            tracing::debug!("relay disabled (not in the lookup allowlist)");
            RelayMode::Disabled
        }
        RelayChoice::Custom(ladder) => {
            tracing::debug!(rungs = ladder.len(), "endpoint pinned to relay ladder");
            RelayMode::Custom(ladder.iter().map(rung_config).collect())
        }
        RelayChoice::Pinned => {
            tracing::debug!("peer on iroh resilient multi-relay default");
            default_relay_mode()
        }
        _ => RelayMode::Disabled,
    }
}

/// Walk a relay ladder in order and return the first **reachable** rung
/// — the deterministic bootstrap relay every member converges on under
/// equal visibility. Reachability is "an endpoint pinned to this single
/// relay reaches `online()` within `per_rung`": iroh pings the relay and
/// only reports online once a home relay is chosen, so a successful
/// `online()` against a one-relay `RelayMode` *is* that rung being live.
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
    let selected = select_first_reachable(ladder, |rung| async move {
        let reachable = relay_rung_reachable(&rung, per_rung, stop.cloned()).await;
        if !reachable {
            tracing::debug!(target: "habilis_network::lookup", relay = %rung, "bootstrap relay rung unreachable; trying next");
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

/// The pure ladder walk behind [`select_bootstrap_rung`]: probe rungs
/// **in order from the first** and return the first for which `reachable`
/// is `true`, else `None`. Always restarting at index 0 is what makes
/// the selection deterministic across members and gives "reset the
/// ladder and try again from the first rung" on every (re)selection — a
/// recovered earlier rung is preferred over a later one. Generic over
/// the reachability probe so the ordering/short-circuit logic is unit
/// tested without touching the network.
async fn select_first_reachable<Probe, Fut>(
    ladder: &[RelayUrl],
    mut reachable: Probe,
) -> Option<RelayUrl>
where
    Probe: FnMut(RelayUrl) -> Fut,
    Fut: Future<Output = bool>,
{
    for rung in ladder {
        if reachable(rung.clone()).await {
            return Some(rung.clone());
        }
    }
    None
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
        .relay_mode(RelayMode::custom([rung.clone()]))
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
///   demote to relay-less). Sticky: a healthy rung is polled forever;
///   other rungs are never probed.
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
    let probe = RELAY_RUNG_PROBE;
    StoppableTask::spawn(|stop| async move {
        if homed {
            monitor_homed_rung(&endpoint, &ladder, &rung_tx, probe, &stop).await;
        } else {
            monitor_relay_less(&ladder, &rung_tx, probe, &stop).await;
        }
    })
}

/// Poll the rung we're homed on until a sustained outage, then re-walk the
/// ladder once and publish the result. Split out of [`spawn_relay_monitor`]
/// so the loop body isn't nested inside the spawned future's `if homed`.
async fn monitor_homed_rung(
    endpoint: &Endpoint,
    ladder: &[RelayUrl],
    rung_tx: &watch::Sender<Option<RelayUrl>>,
    probe: Duration,
    stop: &watch::Receiver<()>,
) {
    let mut fails: u32 = 0;
    loop {
        let poll = async {
            n0future_time::sleep(RELAY_LIVENESS_INTERVAL).await;
            n0future_time::timeout(probe, endpoint.online())
                .await
                .is_ok()
        };
        let online = tokio::select! {
            online = poll => online,
            () = stopped(Some(stop.clone())) => return,
        };
        if online {
            fails = 0;
            continue;
        }
        fails += 1;
        if !should_evict_rung(fails) {
            continue;
        }
        tracing::info!(
            target: "habilis_network::lookup",
            fails,
            "beacon relay rung unreachable; re-walking the ladder"
        );
        let selected = select_bootstrap_rung(ladder, probe, Some(stop)).await;
        if !is_stopped(stop) {
            let _ = rung_tx.send(selected);
        }
        return;
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
    use std::collections::HashSet;

    use crate::lookup::test_relay;
    use crate::util::tuning;
    use iroh::endpoint::presets;
    use std::cell;
    use std::time::Duration as std_Duration;
    use tokio::time;
    /// Tripwire: the iroh fallback rungs of our pinned rendezvous ladder
    /// must stay equal to iroh's `defaults::prod` relay hosts, **in
    /// order** (rung 1 = NA-east). Rung 0 is our own operated relay and
    /// is excluded here. Relay infra is versioned and not cross-compatible
    /// (sendme #121); if an iroh bump moves a prod relay off these hosts,
    /// the relay-direct bootstrap silently breaks for members on a
    /// different iroh version. Failing here forces a manual review (are
    /// these hosts still served?) before the bump ships.
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
        // Skip rung 0 (our own relay); the rest must track iroh's prod set.
        let ours: Vec<&str> = RENDEZVOUS_RELAY_LADDER_URLS
            .iter()
            .skip(1)
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
            "Pinned ⇒ the full n0 prod ladder"
        );
        assert!(
            relay_ladder(&RelayChoice::Disabled).next().is_none(),
            "a disabled choice has an empty ladder"
        );
        let url: RelayUrl = "https://a.example./".parse().unwrap();
        let custom = vec![url];
        let ladder: Vec<_> = relay_ladder(&RelayChoice::Custom(custom.clone())).collect();
        assert_eq!(
            ladder, custom,
            "a pinned ladder resolves to the given rungs"
        );
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
            let bogus: RelayUrl = "https://192.0.2.1./".parse().unwrap();
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
    // Exhaustive, network-free coverage of "reset and start from the
    // first rung": a fake reachability predicate marks chosen rungs
    // down, and we assert which rung wins and how many were probed.

    fn rungs(hosts: &[&str]) -> Vec<RelayUrl> {
        hosts.iter().map(|host| rung(host)).collect()
    }

    fn short_host(url: &RelayUrl) -> String {
        let host = url.host_str().unwrap();
        host.trim_end_matches('.')
            .trim_end_matches(".example")
            .to_string()
    }

    fn host_of(rung: Option<&RelayUrl>) -> Option<String> {
        rung.map(short_host)
    }

    /// Run the ladder walk with a set of hosts treated as unreachable;
    /// returns `(selected, probed_in_order)`.
    async fn walk(ladder: &[RelayUrl], down: &[&str]) -> (Option<RelayUrl>, Vec<String>) {
        let down: HashSet<String> = down.iter().map(|host| (*host).to_string()).collect();
        let probed = cell::RefCell::new(Vec::new());
        let selected = select_first_reachable(ladder, |rung| {
            let host = short_host(&rung);
            probed.borrow_mut().push(host.clone());
            let up = !down.contains(&host);
            async move { up }
        })
        .await;
        (selected, probed.into_inner())
    }

    #[test]
    fn ladder_picks_first_when_all_reachable() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let ladder = rungs(&["a", "b", "c"]);
            let (selected, probed) = walk(&ladder, &[]).await;
            assert_eq!(
                host_of(selected.as_ref()).as_deref(),
                Some("a"),
                "the first rung is picked when all are reachable"
            );
            assert_eq!(probed, vec!["a"], "stops at the first reachable rung");
        });
    }

    #[test]
    fn ladder_falls_through_to_next_reachable() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let ladder = rungs(&["a", "b", "c"]);
            // rung 0 down → rung 1 wins, having probed a then b.
            let (selected, probed) = walk(&ladder, &["a"]).await;
            assert_eq!(
                host_of(selected.as_ref()).as_deref(),
                Some("b"),
                "the ladder falls through to the next reachable rung"
            );
            assert_eq!(
                probed,
                vec!["a", "b"],
                "the ladder probes the dead first rung and then the second"
            );
        });
    }

    #[test]
    fn ladder_skips_multiple_dead_prefix_rungs() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let ladder = rungs(&["a", "b", "c"]);
            let (selected, probed) = walk(&ladder, &["a", "b"]).await;
            assert_eq!(
                host_of(selected.as_ref()).as_deref(),
                Some("c"),
                "the ladder skips multiple dead prefix rungs"
            );
            assert_eq!(
                probed,
                vec!["a", "b", "c"],
                "the ladder probes each dead rung in order"
            );
        });
    }

    #[test]
    fn ladder_prefers_first_rung_when_it_recovers() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // "reset and start from the first": the walk always re-picks the
            // earliest reachable rung, so a recovered rung 0 wins over a
            // still-up rung 1.
            let ladder = rungs(&["a", "b", "c"]);
            let (selected, _) = walk(&ladder, &[]).await;
            assert_eq!(
                host_of(selected.as_ref()).as_deref(),
                Some("a"),
                "the first rung is preferred again once it recovers"
            );
        });
    }

    #[test]
    fn ladder_all_down_is_none() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let ladder = rungs(&["a", "b", "c"]);
            let (selected, probed) = walk(&ladder, &["a", "b", "c"]).await;
            assert!(selected.is_none(), "every rung down ⇒ None (use mDNS/DHT)");
            assert_eq!(probed, vec!["a", "b", "c"], "probes the whole ladder");
        });
    }

    #[test]
    fn ladder_empty_is_none_without_probing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (selected, probed) = walk(&[], &[]).await;
            assert!(selected.is_none(), "an empty ladder selects nothing");
            assert!(probed.is_empty(), "an empty ladder probes nothing");
        });
    }

    // --- steady-state failover decision (`plan_rung_refresh`) -------
    //
    // The beacon-held / relay-enabled gate lives in the event loop (it
    // owns that state); here we cover only the pure change-detection.

    fn rung(host: &str) -> RelayUrl {
        format!("https://{host}.example./").parse().unwrap()
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
            .relay_mode(super::relay_mode(&RelayChoice::Custom(vec![url])))
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
