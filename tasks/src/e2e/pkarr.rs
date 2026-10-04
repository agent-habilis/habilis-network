//! `cargo task e2e --suite pkarr` — the pkarr lookup across every pair of
//! native and browser peers.
//!
//! Each cell creates a mesh with `lookup: relay,pkarr` on one side and joins
//! it by id on the other, over one local relay and a fresh local pkarr relay.
//! A browser needs the relay lookup for its WebRTC handshake, and a joiner can
//! reach the beacon through the relay rung, so a link alone does not prove
//! that pkarr works. The cell therefore also reads the pkarr relay: it must
//! hold the record of each member's endpoint (the id each side logs as it
//! binds) and of the rendezvous id, and must have answered a lookup.

use std::fmt;
use std::time::Duration;

use crate::TaskOutcome;
use crate::util::page::{call_page_within, wait_ready};
use crate::util::{output, repo_root, wait_for};

use habilis_network::iroh::{EndpointId, RelayUrl};
use habilis_network::membership;
use habilis_network::net::test_pkarr::{self, TestPkarr};
use habilis_network::net::{DEFAULT_PKARR_URLS, probe_pkarr, probe_record};
use habilis_network::protocol::{Lookup, Mesh, Url};

use super::mesh::{
    BunServer, Native, drain_logs, init_logging, launch_page, logs_contain, logs_snapshot,
};
use super::page::{Page, call_page, urlencode};
use super::{Args, Skip, build};

const LINK_TIMEOUT: Duration = Duration::from_mins(4);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Native,
    Web,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Web => "web",
        }
    }
}

/// The creator, then the joiner.
const CELLS: [(Kind, Kind); 4] = [
    (Kind::Native, Kind::Native),
    (Kind::Native, Kind::Web),
    (Kind::Web, Kind::Native),
    (Kind::Web, Kind::Web),
];

fn label((creator, joiner): (Kind, Kind)) -> String {
    format!("{}-{}", creator.label(), joiner.label())
}

struct CellFailure(String);

impl fmt::Display for CellFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One member of a cell, whichever kind it is.
enum Side {
    Native(Box<Native>),
    Web(Page),
}

struct Urls<'a> {
    relay: &'a str,
    pkarr: &'a str,
    harness: &'a str,
}

impl Side {
    async fn create(kind: Kind, nick: &str, urls: &Urls<'_>, only: &str) -> Result<Self, String> {
        match kind {
            Kind::Native => {
                let opts = membership::Opts {
                    nick: Some(nick.to_owned()),
                    lookup: vec![Lookup::Relay, Lookup::Pkarr],
                    relay_urls: vec![urls.relay.to_owned()],
                    pkarr_urls: vec![urls.pkarr.to_owned()],
                    ..membership::Opts::default()
                };
                Native::open(&opts)
                    .await
                    .map(|native| Self::Native(Box::new(native)))
                    .map_err(|Skip(reason)| reason)
            }
            Kind::Web => {
                let page = launch_page(only).map_err(|Skip(reason)| reason)?;
                page.navigate(&format!(
                    "{}/?lookup=relay,pkarr&nick={nick}&relay={}&pkarr={}&log=habilis_network=info",
                    urls.harness,
                    urlencode(urls.relay),
                    urlencode(urls.pkarr),
                ));
                Self::ready(page)
            }
        }
    }

    async fn join(
        kind: Kind,
        nick: &str,
        id: &str,
        urls: &Urls<'_>,
        only: &str,
    ) -> Result<Self, String> {
        match kind {
            Kind::Native => {
                let opts = membership::Opts {
                    nick: Some(nick.to_owned()),
                    mesh: Some(id.to_owned()),
                    ..membership::Opts::default()
                };
                Native::open(&opts)
                    .await
                    .map(|native| Self::Native(Box::new(native)))
                    .map_err(|Skip(reason)| reason)
            }
            Kind::Web => {
                let page = launch_page(only).map_err(|Skip(reason)| reason)?;
                page.navigate(&format!(
                    "{}/?mesh={}&nick={nick}&relay={}&log=habilis_network=info",
                    urls.harness,
                    urlencode(id),
                    urlencode(urls.relay),
                ));
                Self::ready(page)
            }
        }
    }

    fn ready(page: Page) -> Result<Self, String> {
        match wait_ready(&page, Duration::from_secs(30), Duration::from_millis(500)) {
            Some(Ok(())) => Ok(Self::Web(page)),
            Some(Err(error)) => Err(format!("the tab failed to open the mesh: {error}")),
            None => Err("the tab never became ready".to_owned()),
        }
    }

    fn mesh_id(&self) -> String {
        match self {
            Self::Native(native) => native.membership.node.mesh_id().to_string(),
            Self::Web(page) => page.evaluate("document.getElementById('ready').dataset.id"),
        }
    }

    /// The creator holds the beacon before the joiner starts, as in the mesh
    /// suite: a joiner that probes during the claim reads the id as free.
    fn claimed_beacon(&self) -> bool {
        match self {
            Self::Native(_) => logs_contain("beacon role active"),
            Self::Web(page) => page
                .evaluate("(document.getElementById('log')||{}).textContent||''")
                .contains("beacon role active"),
        }
    }

    /// This side's log. A native side reads the in-process buffer from
    /// `from`, so a second native peer skips the first one's lines.
    fn log(&self, from: usize) -> String {
        match self {
            Self::Native(_) => logs_snapshot().get(from..).unwrap_or_default().to_owned(),
            Self::Web(page) => page.evaluate("(window.harnessLog||[]).join('\\n')"),
        }
    }

    fn sees(&mut self, nick: &str) -> bool {
        match self {
            Self::Native(native) => native.saw_event("joined", nick),
            Self::Web(page) => page
                .evaluate("(document.getElementById('peers')||{}).textContent||''")
                .contains(&format!("\"{nick}\"")),
        }
    }

    async fn broadcast(&self, text: &str) -> Result<(), String> {
        match self {
            Self::Native(native) => native.send(None, text).await,
            Self::Web(page) => {
                call_page(page, "harness", &format!("send(null, '{text}')")).map(drop)
            }
        }
    }

    fn received(&mut self, text: &str) -> bool {
        match self {
            Self::Native(native) => native.saw_msg(text, false),
            Self::Web(page) => page
                .evaluate("(document.getElementById('messages')||{}).textContent||''")
                .contains(text),
        }
    }
}

async fn run_cell(
    (creator_kind, joiner_kind): (Kind, Kind),
    urls: &Urls<'_>,
    pkarr: &TestPkarr,
    only: &str,
) -> Result<String, CellFailure> {
    let fail = CellFailure;
    drain_logs();

    let mut creator = Side::create(creator_kind, "creator", urls, only)
        .await
        .map_err(fail)?;
    let claimed = wait_for(Duration::from_mins(1), Duration::from_millis(500), || {
        creator.claimed_beacon().then_some(())
    });
    if claimed.is_none() {
        return Err(fail("the creator never claimed the beacon".to_owned()));
    }
    let id = creator.mesh_id();
    let joiner_log_start = logs_snapshot().len();
    let mut joiner = Side::join(joiner_kind, "joiner", &id, urls, only)
        .await
        .map_err(fail)?;

    let linked = wait_for(LINK_TIMEOUT, Duration::from_secs(1), || {
        (creator.sees("joiner") && joiner.sees("creator")).then_some(())
    });
    if linked.is_none() {
        return Err(fail(format!(
            "the pair never linked (creator saw joiner: {}, joiner saw creator: {})",
            creator.sees("joiner"),
            joiner.sees("creator"),
        )));
    }

    // A frame can race the path it needs right after the link, so each side
    // resends until the other has it, inside one deadline.
    let deadline = tokio::time::Instant::now() + PAYLOAD_TIMEOUT;
    loop {
        let _ = creator.broadcast("from-creator").await;
        let _ = joiner.broadcast("from-joiner").await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        if joiner.received("from-creator") && creator.received("from-joiner") {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(fail(format!(
                "a broadcast did not arrive (joiner got creator's: {}, creator got joiner's: {})",
                joiner.received("from-creator"),
                creator.received("from-joiner"),
            )));
        }
    }

    let rendezvous = id
        .parse::<Mesh>()
        .map_err(|error| fail(format!("the mesh id does not parse: {error}")))?
        .rendezvous_id()
        .to_z32();
    let keys = [
        ("creator", published_peer(&creator.log(0))),
        ("joiner", published_peer(&joiner.log(joiner_log_start))),
        ("rendezvous", Some(rendezvous)),
    ];
    let home: RelayUrl = urls
        .relay
        .parse()
        .map_err(|error| fail(format!("the relay url does not parse: {error}")))?;
    for (who, key) in &keys {
        let key = key
            .clone()
            .ok_or_else(|| fail(format!("the {who} logged no pkarr endpoint")))?;
        let record = pkarr.info(&key).ok_or_else(|| {
            fail(format!(
                "the pkarr relay holds no record for the {who} ({key})"
            ))
        })?;
        // A record without the home relay is one nobody can dial from.
        if record.data.relay_urls().collect::<Vec<_>>() != [&home] {
            return Err(fail(format!(
                "the record of the {who} does not name the home relay {home}: {:?}",
                record.data
            )));
        }
        if record.data.ip_addrs().next().is_some() {
            return Err(fail(format!("the record of the {who} leaks an address")));
        }
    }
    // A 409 on the shared rendezvous key is normal: co-hosts of one mesh
    // publish it, and the relay keeps only the newest write. A 409 on a peer
    // key is a client that republished a record that was not newer, and every
    // 400 is a record that did not verify, so those fail the cell.
    let peer_keys: Vec<&String> = keys
        .iter()
        .filter(|(who, _)| *who != "rendezvous")
        .filter_map(|(_, key)| key.as_ref())
        .collect();
    let refused: Vec<(String, u16)> = pkarr
        .refusals()
        .into_iter()
        .filter(|(key, status)| *status == 400 || peer_keys.contains(&key))
        .collect();
    if !refused.is_empty() {
        return Err(fail(format!(
            "the pkarr relay refused {} write(s) that it should not have: {refused:?}",
            refused.len()
        )));
    }
    if pkarr.hits() == 0 {
        return Err(fail("the pkarr relay answered no lookup".to_owned()));
    }
    Ok(format!(
        "linked, broadcast both ways; pkarr holds creator, joiner and rendezvous ({} keys), {} lookups answered",
        pkarr.records(),
        pkarr.hits()
    ))
}

/// The record key of the first peer endpoint in `log` that publishes to
/// pkarr: the engine logs `endpoint bound` with the id and the lookups.
fn published_peer(log: &str) -> Option<String> {
    log.lines()
        .filter(|line| {
            line.contains("endpoint bound")
                && (line.contains("role=\"peer\"") || line.contains("role=peer"))
                && !line.contains("pkarr=Disabled")
        })
        .find_map(|line| {
            let (_, rest) = line.split_once("endpoint_id=")?;
            let hex: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            hex.parse::<EndpointId>().ok().map(|id| id.to_z32())
        })
}

pub(super) fn run(args: &Args) -> TaskOutcome {
    if args.list {
        for cell in CELLS {
            output::verbatim(&format!("{}  would run", label(cell)));
        }
        return Ok(());
    }
    build::ensure_bun("the pkarr suite serves its harness with bun")?;
    build::build_browser_peer()?;
    init_logging();
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
    let only = args.page_browser().to_owned();

    let mut failures = 0usize;
    for cell in CELLS {
        output::status("Running", &label(cell));
        // A fresh pkarr relay per cell, so its counts are this cell's alone.
        let (pkarr_url, pkarr) = runtime
            .block_on(test_pkarr::spawn_plain())
            .map_err(|error| format!("no local pkarr relay: {error:#}"))?;
        let urls = Urls {
            relay: relay_url.as_str(),
            pkarr: pkarr_url.as_str(),
            harness: &harness.url,
        };
        match runtime.block_on(run_cell(cell, &urls, &pkarr, &only)) {
            Ok(detail) => output::status("ok", &format!("{}  {detail}", label(cell))),
            Err(CellFailure(reason)) => {
                failures += 1;
                output::failure("FAILED", &format!("{}  {reason}", label(cell)));
                let dump = repo_root()
                    .join("target")
                    .join(format!("pkarr-cell-{}.log", label(cell)));
                let _ = std::fs::write(&dump, drain_logs());
                output::detail(&format!("native log: {}", dump.display()));
            }
        }
    }
    if failures > 0 {
        return Err(format!("{failures} pkarr cell(s) failed").into());
    }
    Ok(())
}

/// What one probe of a public relay found, per side.
struct LiveRow {
    url: String,
    native: Result<(), String>,
    web: Result<(), String>,
}

/// The verdict of the page's probe: `{put, get, same}` as JSON, where `put`
/// and `get` are an HTTP status or an error, and `same` says the record read
/// back is the one put. A browser reaches the relay only if the relay's CORS
/// answers allow it, so a pass here is the CORS check too.
fn judge_web(reply: &str) -> Result<(), String> {
    let json: serde_json::Value = serde_json::from_str(reply)
        .map_err(|error| format!("the page answered something else ({error}): {reply}"))?;
    let step = |name: &str| json.get(name).and_then(serde_json::Value::as_str);
    if let Some(error) = json.get("error").and_then(serde_json::Value::as_str) {
        return Err(format!("{error} (a refused CORS preflight shows up here)"));
    }
    if step("put") != Some("204") && step("put") != Some("200") {
        return Err(format!("PUT answered {}", step("put").unwrap_or("nothing")));
    }
    if step("get") != Some("200") {
        return Err(format!("GET answered {}", step("get").unwrap_or("nothing")));
    }
    if json.get("same").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err("the relay returned a different record than the one put".to_owned());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// `cargo task e2e --suite pkarr-live`: the three default public pkarr relays,
/// from a native client and from a browser tab. Each side puts a throwaway
/// signed record, resolves it back, and the tab's success proves the CORS
/// answers too. It reaches the internet and so it is never run in CI: a public
/// relay's outage must not turn a change red.
pub(super) fn run_live(args: &Args) -> TaskOutcome {
    let urls: Vec<String> = DEFAULT_PKARR_URLS
        .iter()
        .map(|url| (*url).to_owned())
        .collect();
    if args.list {
        for url in &urls {
            output::verbatim(&format!("{url}  would run (native, web)"));
        }
        return Ok(());
    }
    build::ensure_bun("the live pkarr suite serves its harness with bun")?;
    build::build_browser_peer()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no tokio runtime: {error}"))?;
    let harness = BunServer::serve(
        &repo_root().join("packages/habilis-network-wasm"),
        "harness/serve.ts",
        "the harness",
    )
    .map_err(|Skip(reason)| reason)?;
    let page = launch_page(args.page_browser()).map_err(|Skip(reason)| reason)?;
    page.navigate(&format!("{}/?probe=pkarr", harness.url));
    match wait_ready(&page, Duration::from_secs(30), Duration::from_millis(500)) {
        Some(Ok(())) => {}
        Some(Err(error)) => return Err(format!("the probe page failed to open: {error}").into()),
        None => return Err("the probe page never became ready".into()),
    }

    let mut rows = Vec::new();
    for url in urls {
        output::status("Probing", &url);
        let parsed: Url = url
            .parse()
            .map_err(|error| format!("{url} is not a URL: {error}"))?;
        let probe = runtime.block_on(probe_pkarr(&parsed));
        let native = probe.published.and(probe.resolved);
        let record = probe_record();
        let call = format!(
            "pkarr('{url}', '{}', '{}')",
            record.key,
            hex(&record.payload)
        );
        let web = call_page_within(&page, "harness", &call, Duration::from_secs(45))
            .and_then(|reply| judge_web(&reply));
        rows.push(LiveRow { url, native, web });
    }

    let mut failures = 0usize;
    for row in &rows {
        for (side, outcome) in [("native", &row.native), ("web", &row.web)] {
            match outcome {
                Ok(()) => output::status("ok", &format!("{side:<6} {}  PUT, resolve", row.url)),
                Err(reason) => {
                    failures += 1;
                    output::failure("FAILED", &format!("{side:<6} {}  {reason}", row.url));
                }
            }
        }
    }
    if failures > 0 {
        return Err(format!("{failures} live pkarr check(s) failed").into());
    }
    Ok(())
}
