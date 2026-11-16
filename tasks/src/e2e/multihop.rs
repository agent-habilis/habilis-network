//! `cargo task e2e --suite multihop` — a tab reached through a native hop.
//!
//! Two in-process native peers, A and B, and one real browser tab, T, all on one local plain-HTTP
//! relay and one mesh whose transports are `udp,webrtc,multihop` (relay as a lookup only, so the
//! relay carries no payload). A and B have an IP link. T has no IP, so T to A is a `WebRTC` session.
//! T to B must have no direct path at all: B refuses T's session in both roles
//! (`Blocking::DenyPeer`), so the only way from T to B is the multihop route through A.
//!
//! The cell moves a directed message each way and reads A's `forwarded_cells` after each one: A
//! carried cells for a pair that it is not part of. It is the proof that the tab takes part in
//! multihop, both as an endpoint and as the neighbor that the route starts with.
//!
//! A second cell puts the tab at its cap and lets a native join late. Natives A and C and a tab with a
//! cap of 2 (`maxConnections=2`) form a mesh: the tab holds sessions with A and C, and its ceiling is
//! full. A native D joins then. The tab must dial D for nothing (the gates of the ceiling keep a probe
//! and a courtesy dial away), and a send of the tab to D must take a route of a connected native and
//! pin D (the debug line `dialing through multihop and pinning the peer` in the tab console). D
//! answers. Between the join of D and the answer, no dial may evict a connection of the tab: an
//! eviction that a gossip neighbor causes is the design, and the others are counted.
//!
//! The deny is on B alone. A tab has no test hook, so T cannot be told to refuse B; it does not
//! need to be: a session needs both ends, and B answers every offer of T, and makes none, with a
//! refusal. Two native members would be denied on both sides.

use std::path::Path;
use std::time::Duration;

use crate::TaskOutcome;
use crate::util::page::{rand_token, wait_ready};
use crate::util::{output, repo_root, target_dir, wait_for};

use habilis_network::membership;
use habilis_network::protocol::Transport;

use super::mesh::{
    BunServer, LINK_TIMEOUT, Native, PAYLOAD_TIMEOUT, drain_logs, init_logging, launch_page,
    logs_contain, native_send_with_retry,
};
use super::page::{Page, call_page, urlencode};
use super::{Args, Skip, build};

use habilis_network::net::test_relay;
use habilis_network::util::tuning;
use std::fs;
use tokio::time::{Instant, Instant as tokio_Instant};
use tokio::{runtime, time};
/// The route is learned from link vectors (15 s apart) and the underlay session of the tab comes
/// on the next tick after that, so a message may wait a few ticks for its route.
const ROUTE_TIMEOUT: Duration = Duration::from_mins(3);

/// What the tab logs when a dial at its cap takes the route of a connected peer and pins the peer.
/// What a member logs when it evicts a direct connection at its ceiling, and the cause that a gossip
/// neighbor leaves on that line.
const EVICTION_LINE: &str = "evicting a direct connection at the ceiling";
const NEIGHBOR_CAUSE: &str = "cause=\"a gossip neighbor\"";
/// How long the sessions of a tab settle at its cap, before the late member joins and before the
/// evictions are counted.
const SETTLE: Duration = Duration::from_secs(20);
/// The cap of the tab in the late-member cell: A and C fill it.
const TAB_CAP: usize = 2;
/// How long the tab may take to print a census after the exchange: it prints one every 10 s.
const CENSUS_TIMEOUT: Duration = Duration::from_secs(40);

const TRANSPORTS: [Transport; 3] = [Transport::Udp, Transport::WebRtc, Transport::Multihop];

struct CellFailure(String);

fn fail(message: String) -> CellFailure {
    CellFailure(message)
}

fn transports() -> String {
    TRANSPORTS
        .iter()
        .map(|transport| transport.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn native_opts(nick: &str, topic: &str, relay_url: &str) -> membership::JoinOptions {
    membership::JoinOptions::default()
        .topic(Some(topic.to_owned()))
        .nick(Some(nick.to_owned()))
        .relay_urls(vec![relay_url.to_owned()])
        .transport(TRANSPORTS.to_vec())
}

fn page_url(base: &str, relay_url: &str, topic: &str, cap: Option<usize>) -> String {
    let cap = cap.map_or_else(String::new, |cap| format!("&maxConnections={cap}"));
    format!(
        "{base}/?topic={topic}&nick=tab&relay={}&transport={}{cap}&log=habilis_network=debug,iroh_gossip=debug",
        urlencode(relay_url),
        transports(),
    )
}

/// A's count of the cells it passed on for other members.
async fn forwarded_cells(alpha: &Native) -> Result<u64, CellFailure> {
    alpha
        .request(|reply| {
            membership::Request::Routing(membership::Routing::ForwardedCells { reply })
        })
        .await
        .map_err(|error| CellFailure(format!("A's forwarded-cell count is unreadable: {error}")))
}

/// The `WebRTC` sessions on A's multihop underlay. The tab has no IP, so A reaches it only over one.
async fn underlay_sessions(alpha: &Native) -> String {
    alpha
        .request(|reply| {
            membership::Request::Routing(membership::Routing::UnderlaySessions { reply })
        })
        .await
        .map_or_else(
            |error| format!("unreadable: {error}"),
            |count| count.to_string(),
        )
}

/// Whether B learns a route to the tab, through A, before the window ends.
async fn route_to_tab(bravo: &Native) -> bool {
    let deadline = tokio_Instant::now() + ROUTE_TIMEOUT;
    loop {
        let has_route = bravo
            .request(|reply| {
                membership::Request::InspectHost(membership::InspectHost::HasRoute {
                    peer: "tab".to_owned(),
                    reply,
                })
            })
            .await
            .unwrap_or(false);
        if has_route {
            return true;
        }
        if tokio_Instant::now() >= deadline {
            return false;
        }
        time::sleep(Duration::from_secs(1)).await;
    }
}

/// B sends the tab a directed message. The tab must show it, and A must have carried cells for it.
/// Returns A's forwarded cells before the message and after it.
async fn b_to_tab(page: &Page, alpha: &Native, bravo: &Native) -> Result<(u64, u64), CellFailure> {
    let before = forwarded_cells(alpha).await?;
    native_send_with_retry(bravo, Some("tab"), "b-to-tab")
        .await
        .map_err(|error| fail(format!("B's directed message was refused: {error}")))?;
    let arrived = wait_for(ROUTE_TIMEOUT, Duration::from_millis(500), || {
        page.evaluate("(document.getElementById('messages')||{}).textContent||''")
            .contains("b-to-tab")
            .then_some(())
    });
    if arrived.is_none() {
        let now = forwarded_cells(alpha).await?;
        return Err(fail(format!(
            "B's message never reached the tab (A's forwarded cells: {before} then {now}; A's underlay sessions: {})",
            underlay_sessions(alpha).await
        )));
    }
    let after_down = forwarded_cells(alpha).await?;
    if after_down <= before {
        return Err(fail(format!(
            "B's message reached the tab, but A passed on no cells for it ({before} then {after_down}): the pair was not on a multihop route"
        )));
    }
    Ok((before, after_down))
}

/// The tab sends B a directed message. B must receive it, and A must have carried cells for it.
/// Returns A's forwarded cells after the message.
async fn tab_to_b(
    page: &Page,
    alpha: &Native,
    bravo: &mut Native,
    after_down: u64,
) -> Result<u64, CellFailure> {
    let deadline = tokio_Instant::now() + ROUTE_TIMEOUT;
    loop {
        // A send before the tab has its route is refused or held; try again until the window ends.
        let _ = call_page(page, "harness", "send('bravo', 'tab-to-b')");
        if bravo.saw_msg("tab-to-b", true) {
            break;
        }
        if Instant::now() >= deadline {
            let now = forwarded_cells(alpha).await?;
            return Err(fail(format!(
                "the tab's message never reached B (A's forwarded cells: {after_down} then {now}; A's underlay sessions: {})",
                underlay_sessions(alpha).await
            )));
        }
        time::sleep(Duration::from_secs(1)).await;
    }
    let after_up = forwarded_cells(alpha).await?;
    if after_up <= after_down {
        return Err(fail(format!(
            "the tab's message reached B, but A passed on no cells for it ({after_down} then {after_up})"
        )));
    }
    Ok(after_up)
}

async fn run_cell(
    relay_url: &str,
    harness: &BunServer,
    page: &Page,
) -> Result<String, CellFailure> {
    let topic = format!("multihop-cell-{}", rand_token());
    drain_logs();

    // A claims the beacon first; B and the tab join a live one.
    let mut alpha = Native::open(&native_opts("alpha", &topic, relay_url))
        .await
        .map_err(|Skip(reason)| fail(reason))?;
    let claimed = wait_for(Duration::from_secs(25), Duration::from_millis(500), || {
        logs_contain("beacon role active").then_some(())
    });
    if claimed.is_none() {
        return Err(fail("A never claimed the beacon".to_owned()));
    }
    let mut bravo = Native::open(&native_opts("bravo", &topic, relay_url))
        .await
        .map_err(|Skip(reason)| fail(reason))?;
    page.navigate(&page_url(&harness.url, relay_url, &topic, None));
    let ready = wait_ready(page, Duration::from_secs(30), Duration::from_millis(500))
        .ok_or_else(|| fail("the harness page never became ready".to_owned()))?;
    ready.map_err(|error| fail(format!("the tab failed to open the mesh: {error}")))?;

    // Everyone sees everyone. Then B refuses the tab, before the pair can go direct, and a session
    // that slipped in is ended by the request.
    let tab_sees = |nick: &str| {
        page.evaluate("(document.getElementById('peers')||{}).textContent||''")
            .contains(&format!("\"{nick}\""))
    };
    let linked = wait_for(LINK_TIMEOUT, Duration::from_secs(1), || {
        (alpha.saw_event("joined", "tab")
            && bravo.saw_event("joined", "tab")
            && tab_sees("alpha")
            && tab_sees("bravo"))
        .then_some(())
    });
    if linked.is_none() {
        return Err(fail(format!(
            "the three never saw each other (A saw tab: {}, B saw tab: {}, tab saw A: {}, tab saw B: {})",
            alpha.saw_event("joined", "tab"),
            bravo.saw_event("joined", "tab"),
            tab_sees("alpha"),
            tab_sees("bravo"),
        )));
    }
    bravo
        .request(|reply| {
            membership::Request::Blocking(membership::Blocking::DenyPeer {
                peer: "tab".to_owned(),
                denied: true,
                reply,
            })
        })
        .await
        .map_err(|error| fail(format!("B could not deny the tab: {error}")))?
        .map_err(|error| fail(format!("B could not deny the tab: {error}")))?;

    if !route_to_tab(&bravo).await {
        return Err(fail("B never learned a route to the tab".to_owned()));
    }
    let (before, after_down) = b_to_tab(page, &alpha, &bravo).await?;
    let after_up = tab_to_b(page, &alpha, &mut bravo, after_down).await?;

    // The leave is heard on both natives, so the cell ends on a clean mesh.
    call_page(page, "harness", "close()").map_err(fail)?;
    let left = wait_for(PAYLOAD_TIMEOUT, Duration::from_secs(1), || {
        (alpha.saw_event("left", "tab") && bravo.saw_event("left", "tab")).then_some(())
    });
    if left.is_none() {
        return Err(fail(
            "the tab left but a native never surfaced it".to_owned(),
        ));
    }
    Ok(format!(
        "both ways through A (forwarded cells {before} → {after_down} → {after_up})"
    ))
}

/// The console of the tab, in one string.
fn tab_console(page: &Page) -> String {
    page.evaluate("(window.harnessLog||[]).join('\\n')")
}

/// The `direct_units` and `over_ceiling` of each mesh census line in `log`, in order.
fn census_units(log: &str) -> Vec<(usize, usize)> {
    let field = |line: &str, name: &str| -> Option<usize> {
        let (_, rest) = line.split_once(name)?;
        rest.split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    };
    let lines = log.lines().filter(|line| line.contains("mesh census"));
    let mut found: Vec<(usize, usize)> = Vec::new();
    for line in lines {
        if let (Some(units), Some(over)) =
            (field(line, "direct_units="), field(line, "over_ceiling="))
        {
            found.push((units, over));
        }
    }
    found
}

/// The evictions at a ceiling in `log` that a dial or a session caused. A new gossip neighbor takes
/// the unit of a cached peer by design, so that cause is not counted.
fn dial_evictions(log: &str) -> usize {
    let evictions = log.lines().filter(|line| line.contains(EVICTION_LINE));
    evictions
        .filter(|line| !line.contains(NEIGHBOR_CAUSE))
        .count()
}

/// The cell of a tab at its cap, and a native that joins late.
async fn run_late_member_cell(
    relay_url: &str,
    harness: &BunServer,
    page: &Page,
) -> Result<String, CellFailure> {
    let topic = format!("multihop-late-{}", rand_token());
    drain_logs();

    let mut alpha = Native::open(&native_opts("alpha", &topic, relay_url))
        .await
        .map_err(|Skip(reason)| fail(reason))?;
    let claimed = wait_for(Duration::from_secs(25), Duration::from_millis(500), || {
        logs_contain("beacon role active").then_some(())
    });
    if claimed.is_none() {
        return Err(fail("A never claimed the beacon".to_owned()));
    }
    let _charlie = Native::open(&native_opts("charlie", &topic, relay_url))
        .await
        .map_err(|Skip(reason)| fail(reason))?;
    page.navigate(&page_url(&harness.url, relay_url, &topic, Some(TAB_CAP)));
    let ready = wait_ready(page, Duration::from_secs(30), Duration::from_millis(500))
        .ok_or_else(|| fail("the harness page never became ready".to_owned()))?;
    ready.map_err(|error| fail(format!("the tab failed to open the mesh: {error}")))?;
    let tab_sees = |nick: &str| {
        page.evaluate("(document.getElementById('peers')||{}).textContent||''")
            .contains(&format!("\"{nick}\""))
    };
    let linked = wait_for(LINK_TIMEOUT, Duration::from_secs(1), || {
        (alpha.saw_event("joined", "tab") && tab_sees("alpha") && tab_sees("charlie")).then_some(())
    });
    if linked.is_none() {
        return Err(fail("the tab never saw A and C".to_owned()));
    }

    // The tab is at its cap. The late member comes now, and the evictions are counted from here.
    time::sleep(SETTLE).await;
    let console_before: usize = tab_console(page).len();
    let evictions_before = dial_evictions(&tab_console(page)) + dial_evictions(&drain_logs());
    let mut delta = Native::open(&native_opts("delta", &topic, relay_url))
        .await
        .map_err(|Skip(reason)| fail(reason))?;
    let joined = wait_for(LINK_TIMEOUT, Duration::from_secs(1), || {
        (delta.saw_event("joined", "tab") && tab_sees("delta")).then_some(())
    });
    if joined.is_none() {
        return Err(fail("the tab and D never saw each other".to_owned()));
    }
    time::sleep(SETTLE).await;

    // The tab sends to D, which it holds no connection to: the dial pins D on a route.
    let before = forwarded_cells(&alpha).await?;
    let deadline = tokio_Instant::now() + ROUTE_TIMEOUT;
    loop {
        let _ = call_page(page, "harness", "send('delta', 'tab-to-d')");
        if delta.saw_msg("tab-to-d", true) {
            break;
        }
        if Instant::now() >= deadline {
            return Err(fail(format!(
                "the message of the tab never reached D (A's forwarded cells: {before})"
            )));
        }
        time::sleep(Duration::from_secs(1)).await;
    }
    native_send_with_retry(&delta, Some("tab"), "d-to-tab")
        .await
        .map_err(|error| fail(format!("D's message to the tab was refused: {error}")))?;
    let answered = wait_for(ROUTE_TIMEOUT, Duration::from_millis(500), || {
        page.evaluate("(document.getElementById('messages')||{}).textContent||''")
            .contains("d-to-tab")
            .then_some(())
    });
    if answered.is_none() {
        return Err(fail("D's answer never reached the tab".to_owned()));
    }
    let exchange_at: usize = tab_console(page).len();
    // D holds no unit of the tab: a connection that fits no unit is an extra. The tab prints its
    // census every few seconds, so the cell waits for one that comes after the exchange, and no
    // census since D joined may show the tab over its cap.
    let census_seen = wait_for(CENSUS_TIMEOUT, Duration::from_millis(500), || {
        let console = tab_console(page);
        let since_join = console.get(console_before..).unwrap_or_default();
        let after_exchange = since_join.get(exchange_at.saturating_sub(console_before)..);
        after_exchange
            .is_some_and(|log| !census_units(log).is_empty())
            .then_some(())
    });
    if census_seen.is_none() {
        return Err(fail(
            "the tab printed no census after the exchange with D".to_owned(),
        ));
    }
    let console = tab_console(page);
    let census: Vec<(usize, usize)> =
        census_units(console.get(console_before..).unwrap_or_default());
    if let Some((units, over)) = census
        .iter()
        .find(|(units, over)| *units > TAB_CAP || *over > 0)
    {
        return Err(fail(format!(
            "D took a unit of the tab at its cap: {units} units, {over} over a cap of {TAB_CAP}"
        )));
    }
    let evictions_after = dial_evictions(&console) + dial_evictions(&drain_logs());
    if evictions_after != evictions_before {
        return Err(fail(format!(
            "a dial evicted a connection at a ceiling for the late member ({evictions_before} then {evictions_after})"
        )));
    }

    call_page(page, "harness", "close()").map_err(fail)?;
    Ok(
        "the tab at its cap held the late member D as an extra; both ways, no unit taken, no dial evicted"
            .to_owned(),
    )
}

pub(super) fn run(args: &Args) -> TaskOutcome {
    if args.list {
        output::verbatim("multihop: tab T to native B through native A  would run");
        output::verbatim("multihop-late: tab T at its cap, native D joins late  would run");
        return Ok(());
    }

    let target = target_dir()?;
    build::ensure_bun("the multihop suite serves its harness with bun")?;
    // The suite owns its wasm: a stale glue tests the previous engine.
    build::build_browser_peer()?;

    init_logging();
    // As in the mesh suite: the beacon re-check is parked beyond the cell, which measures the mesh's
    // steady state.
    tuning::init(
        tuning::Tuning::DEFAULTS
            .rival_recheck_first(Duration::from_hours(1))
            .rival_recheck(Duration::from_hours(1))
            .rival_recheck_meshed(Duration::from_hours(1)),
    );
    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no tokio runtime: {error}"))?;
    let (relay_url, _relay_server) = runtime
        .block_on(test_relay::spawn_plain())
        .map_err(|error| format!("no local relay: {error:#}"))?;
    let harness = BunServer::serve(
        &repo_root().join("packages/habilis-network-wasm"),
        "harness/serve.ts",
        "the harness",
    )
    .map_err(|Skip(reason)| reason)?;
    output::status(
        "Serving",
        &format!("relay {relay_url} · harness {}", harness.url),
    );

    let page = launch_page(args.page_browser()).map_err(|Skip(reason)| reason)?;
    // Each cell runs, and a cell that fails does not hide the next: the suite fails at the end.
    let mut failures: Vec<String> = Vec::new();
    output::status("Running", "tab T to native B through native A");
    match runtime.block_on(run_cell(relay_url.as_str(), &harness, &page)) {
        Ok(detail) => {
            output::status("ok", &detail);
            output::detail(&page.version());
        }
        Err(CellFailure(reason)) => failures.push(report_failure(&target, &page, &reason)),
    }
    output::status("Running", "tab T at its cap, native D joins late");
    match runtime.block_on(run_late_member_cell(relay_url.as_str(), &harness, &page)) {
        Ok(detail) => output::status("ok", &detail),
        Err(CellFailure(reason)) => failures.push(report_failure(&target, &page, &reason)),
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

/// Report a failed cell, and keep its logs. Returns the reason.
fn report_failure(target: &Path, page: &Page, reason: &str) -> String {
    output::failure("FAILED", reason);
    let logs = drain_logs();
    let dump = target.join("multihop-cell.log");
    let browser = page.evaluate("(window.harnessLog||[]).join('\\n')");
    let _ = fs::write(&dump, format!("── browser console ──\n{browser}\n{logs}"));
    output::detail(&format!("full log: {}", dump.display()));
    reason.to_owned()
}
