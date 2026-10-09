//! `cargo task e2e --suite multihop` — a tab reached through a native hop.
//!
//! Two in-process native peers, A and B, and one real browser tab, T, all on one local plain-HTTP
//! relay and one mesh whose transports are `udp,webrtc,multihop` (relay as a lookup only, so the
//! relay carries no payload). A and B have an IP link. T has no IP, so T to A is a WebRTC session.
//! T to B must have no direct path at all: B refuses T's session in both roles
//! (`Request::DenyPeer`), so the only way from T to B is the multihop route through A.
//!
//! The cell moves a directed message each way and reads A's `forwarded_cells` after each one: A
//! carried cells for a pair that it is not part of. It is the proof that the tab takes part in
//! multihop, both as an endpoint and as the neighbor that the route starts with.
//!
//! The deny is on B alone. A tab has no test hook, so T cannot be told to refuse B; it does not
//! need to be: a session needs both ends, and B answers every offer of T, and makes none, with a
//! refusal. Two native members would be denied on both sides.

use std::time::Duration;

use crate::TaskOutcome;
use crate::util::page::{rand_token, wait_ready};
use crate::util::{output, repo_root, wait_for};

use habilis_network::membership;
use habilis_network::protocol::Transport;

use super::mesh::{
    BunServer, LINK_TIMEOUT, Native, PAYLOAD_TIMEOUT, drain_logs, init_logging, launch_page,
    logs_contain, native_send_with_retry,
};
use super::page::{Page, call_page, urlencode};
use super::{Args, Skip, build};

/// The route is learned from link vectors (15 s apart) and the underlay session of the tab comes
/// on the next tick after that, so a message may wait a few ticks for its route.
const ROUTE_TIMEOUT: Duration = Duration::from_mins(3);

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

fn native_opts(nick: &str, topic: &str, relay_url: &str) -> membership::Opts {
    membership::Opts {
        topic: Some(topic.to_owned()),
        nick: Some(nick.to_owned()),
        relay_urls: vec![relay_url.to_owned()],
        transport: TRANSPORTS.to_vec(),
        ..membership::Opts::default()
    }
}

fn page_url(base: &str, relay_url: &str, topic: &str) -> String {
    format!(
        "{base}/?topic={topic}&nick=tab&relay={}&transport={}&log=habilis_network=debug,iroh_gossip=debug",
        urlencode(relay_url),
        transports(),
    )
}

/// A's count of the cells it passed on for other members.
async fn forwarded_cells(alpha: &Native) -> Result<u64, CellFailure> {
    alpha
        .request(|reply| membership::Request::ForwardedCells { reply })
        .await
        .map_err(|error| CellFailure(format!("A's forwarded-cell count is unreadable: {error}")))
}

/// The WebRTC sessions on A's multihop underlay. The tab has no IP, so A reaches it only over one.
async fn underlay_sessions(alpha: &Native) -> String {
    alpha
        .request(|reply| membership::Request::UnderlaySessions { reply })
        .await
        .map_or_else(
            |error| format!("unreadable: {error}"),
            |count| count.to_string(),
        )
}

/// Whether B learns a route to the tab, through A, before the window ends.
async fn route_to_tab(bravo: &Native) -> bool {
    let deadline = tokio::time::Instant::now() + ROUTE_TIMEOUT;
    loop {
        let has_route = bravo
            .request(|reply| membership::Request::HasRoute {
                peer: "tab".to_owned(),
                reply,
            })
            .await
            .unwrap_or(false);
        if has_route {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
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
    let deadline = tokio::time::Instant::now() + ROUTE_TIMEOUT;
    loop {
        // A send before the tab has its route is refused or held; try again until the window ends.
        let _ = call_page(page, "harness", "send('bravo', 'tab-to-b')");
        if bravo.saw_msg("tab-to-b", true) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let now = forwarded_cells(alpha).await?;
            return Err(fail(format!(
                "the tab's message never reached B (A's forwarded cells: {after_down} then {now}; A's underlay sessions: {})",
                underlay_sessions(alpha).await
            )));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
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
    page.navigate(&page_url(&harness.url, relay_url, &topic));
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
        .request(|reply| membership::Request::DenyPeer {
            peer: "tab".to_owned(),
            denied: true,
            reply,
        })
        .await
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

pub(super) fn run(args: &Args) -> TaskOutcome {
    if args.list {
        output::verbatim("multihop: tab T to native B through native A  would run");
        return Ok(());
    }

    build::ensure_bun("the multihop suite serves its harness with bun")?;
    // The suite owns its wasm: a stale glue tests the previous engine.
    build::build_browser_peer()?;

    init_logging();
    // As in the mesh suite: the beacon re-check is parked beyond the cell, which measures the mesh's
    // steady state.
    habilis_network::util::tuning::init(habilis_network::util::tuning::Tuning {
        rival_recheck_first_secs: 3600,
        rival_recheck_secs: 3600,
        rival_recheck_meshed_secs: 3600,
        ..habilis_network::util::tuning::Tuning::DEFAULTS
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no tokio runtime: {error}"))?;
    let (relay_url, _relay_server) = runtime
        .block_on(habilis_network::net::test_relay::spawn_plain())
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
    output::status("Running", "tab T to native B through native A");
    match runtime.block_on(run_cell(relay_url.as_str(), &harness, &page)) {
        Ok(detail) => {
            output::status("ok", &detail);
            output::detail(&page.version());
            Ok(())
        }
        Err(CellFailure(reason)) => {
            output::failure("FAILED", &reason);
            let logs = drain_logs();
            let dump = repo_root().join("target").join("multihop-cell.log");
            let browser = page.evaluate("(window.harnessLog||[]).join('\\n')");
            let _ = std::fs::write(&dump, format!("── browser console ──\n{browser}\n{logs}"));
            output::detail(&format!("full log: {}", dump.display()));
            Err(reason.into())
        }
    }
}
