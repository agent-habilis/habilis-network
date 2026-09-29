//! `cargo task e2e --suite mesh` — the native↔browser matrix.
//!
//! One local plain-HTTP relay both sides can reach, one in-process native
//! peer (`habilis_network::membership`), one real browser on the harness page
//! (`packages/habilis-network-wasm/harness`), driven cell by cell:
//!
//! - **policy** — the mesh's `relay_transport`, on or off;
//! - **paths** — the mesh's transport list: UDP and WebRTC, WebRTC only, or
//!   UDP only, to force the punch, the data channel, and the refusal in turn;
//! - **join mode** — both derive from a topic, the browser joins the id the
//!   native side minted, or the browser opens the topic first;
//! - **discovery** — the relay, or Nostr as the only lookup: no iroh relay
//!   at all, so discovery and JSEP ride an in-process Nostr relay. A topic
//!   always uses every lookup, so these cells join by id, and one of them
//!   pairs two tabs with no native member. A relay cell's topic has the
//!   Nostr lookup too; it points at the same in-process relay, never a
//!   public one.
//!
//! Every linked cell must move payload **both ways** on every lane —
//! broadcast, directed, state merge — and agree on the roster. The three
//! UDP-only lookup-only cells must not open at all: the tab refuses a mesh it
//! has no path in, and says why (`BROWSER_HAS_NO_PATH`).

use std::fmt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::TaskOutcome;
use crate::util::cdp;
use crate::util::page::{rand_token, wait_ready};
use crate::util::webdriver;
use crate::util::{output, repo_root, wait_for};

use habilis_network::membership;
use habilis_network::protocol::{Lookup, Transport};

use super::page::{Page, call_page, urlencode};
use super::{Args, Skip, build};

/// A linked pair has to survive the beacon claim (~8 s), a WebRTC
/// negotiation or a hole punch, and one alive-tick retry.
const LINK_TIMEOUT: Duration = Duration::from_mins(4);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    LookupOnly,
    RelayTransport,
}

/// The direct paths in the mesh's transport list. Mesh-wide, so the browser
/// and the native side run the same ones.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Paths {
    UdpAndWebRtc,
    WebRtcOnly,
    /// No data channel: a browser has no path of its own.
    UdpOnly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Discovery {
    Relay,
    NostrOnly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinMode {
    /// Native first, browser second, both deriving one topic.
    Topic,
    /// Native mints a mesh; the browser joins the printed id.
    IdFromNative,
    /// The browser opens the topic first and briefly runs the mesh alone.
    TopicBrowserFirst,
    /// Native mints an id and leaves; the browser opens it, then native
    /// joins it again. How "browser first" looks with no topic.
    IdBrowserFirst,
    /// Two tabs join an id native minted and left; no native member.
    BrowserPair,
}

struct Cell {
    discovery: Discovery,
    policy: Policy,
    paths: Paths,
    join: JoinMode,
}

impl Cell {
    /// The one cell with no mesh to link in: the browser has no direct path
    /// and the relay may not carry payload, so the tab refuses the mesh.
    fn expects_link(&self) -> bool {
        !(self.policy == Policy::LookupOnly && self.paths == Paths::UdpOnly)
    }

    fn transports(&self) -> Vec<Transport> {
        let mut transports = match self.paths {
            Paths::UdpAndWebRtc => vec![Transport::Udp, Transport::WebRtc],
            Paths::WebRtcOnly => vec![Transport::WebRtc],
            Paths::UdpOnly => vec![Transport::Udp],
        };
        if self.policy == Policy::RelayTransport {
            transports.push(Transport::Relay);
        }
        transports
    }

    fn label(&self) -> String {
        format!(
            "{}{} / {} / {}",
            match self.discovery {
                Discovery::Relay => "",
                Discovery::NostrOnly => "nostr-only / ",
            },
            match self.policy {
                Policy::LookupOnly => "lookup-only",
                Policy::RelayTransport => "relay-transport",
            },
            match self.paths {
                Paths::UdpAndWebRtc => "udp+webrtc",
                Paths::WebRtcOnly => "webrtc",
                Paths::UdpOnly => "udp",
            },
            match self.join {
                JoinMode::Topic => "topic",
                JoinMode::IdFromNative => "id",
                JoinMode::TopicBrowserFirst | JoinMode::IdBrowserFirst => "browser-first",
                JoinMode::BrowserPair => "browser-pair",
            },
        )
    }
}

fn cells(quick: bool) -> Vec<Cell> {
    let mut cells = Vec::new();
    for policy in [Policy::LookupOnly, Policy::RelayTransport] {
        for paths in [Paths::UdpAndWebRtc, Paths::WebRtcOnly, Paths::UdpOnly] {
            for join in [
                JoinMode::Topic,
                JoinMode::IdFromNative,
                JoinMode::TopicBrowserFirst,
            ] {
                cells.push(Cell {
                    discovery: Discovery::Relay,
                    policy,
                    paths,
                    join,
                });
            }
        }
    }
    // Nostr alone: no relay, so no relay transport, and a browser always has
    // the data channel.
    for paths in [Paths::UdpAndWebRtc, Paths::WebRtcOnly] {
        for join in [JoinMode::IdFromNative, JoinMode::IdBrowserFirst] {
            cells.push(Cell {
                discovery: Discovery::NostrOnly,
                policy: Policy::LookupOnly,
                paths,
                join,
            });
        }
    }
    cells.push(Cell {
        discovery: Discovery::NostrOnly,
        policy: Policy::LookupOnly,
        paths: Paths::UdpAndWebRtc,
        join: JoinMode::BrowserPair,
    });
    if quick {
        // The cells that cover every mechanism once: both policies on the
        // default transports, the WebRTC-only mesh, the refusal, and Nostr
        // alone for a native and a browser pair.
        cells.retain(|cell| match cell.discovery {
            Discovery::Relay => {
                cell.join == JoinMode::Topic
                    && (cell.paths == Paths::UdpAndWebRtc || cell.policy == Policy::LookupOnly)
            }
            Discovery::NostrOnly => {
                cell.paths == Paths::UdpAndWebRtc
                    && matches!(cell.join, JoinMode::IdFromNative | JoinMode::BrowserPair)
            }
        });
    }
    cells
}

// ── the captured engine log ─────────────────────────────────────────────

/// Every tracing line the in-process native peer emits, for grep-shaped
/// assertions (`relay-only path refused`, the census). One global buffer:
/// the subscriber is process-wide, and cells run serially.
fn log_buffer() -> &'static Arc<Mutex<String>> {
    static BUFFER: OnceLock<Arc<Mutex<String>>> = OnceLock::new();
    BUFFER.get_or_init(|| Arc::new(Mutex::new(String::new())))
}

struct BufferWriter;

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut buffer) = log_buffer().lock() {
            buffer.push_str(&String::from_utf8_lossy(buf));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logging() {
    use tracing_subscriber::fmt::MakeWriter;
    struct Make;
    impl<'a> MakeWriter<'a> for Make {
        type Writer = BufferWriter;
        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter
        }
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "habilis_network=info,habilis_network::lifecycle=debug".into()),
        )
        .with_ansi(false)
        .with_writer(Make)
        .try_init();
}

/// Peek without draining — for waiting on a native-side line mid-cell.
fn logs_contain(needle: &str) -> bool {
    log_buffer()
        .lock()
        .is_ok_and(|buffer| buffer.contains(needle))
}

fn drain_logs() -> String {
    log_buffer()
        .lock()
        .map(|mut buffer| std::mem::take(&mut *buffer))
        .unwrap_or_default()
}

// ── the native peer ─────────────────────────────────────────────────────

/// The in-process side of a cell: a live membership plus everything a check
/// reads — inbound messages, surfaced events, the roster on demand.
struct Native {
    membership: membership::Membership,
    events: tokio::sync::mpsc::UnboundedReceiver<String>,
    seen_events: Vec<serde_json::Value>,
    seen_msgs: Vec<membership::Inbound>,
}

impl Native {
    async fn open(opts: &membership::Opts) -> Result<Self, Skip> {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink)
            .await
            .map_err(|error| Skip(format!("native peer failed to open: {error:#}")))?;
        Ok(Self {
            membership,
            events,
            seen_events: Vec::new(),
            seen_msgs: Vec::new(),
        })
    }

    fn pump(&mut self) {
        while let Ok(json) = self.events.try_recv() {
            if let Ok(event) = serde_json::from_str(&json) {
                self.seen_events.push(event);
            }
        }
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(msg);
        }
    }

    fn saw_event(&mut self, kind: &str, nick: &str) -> bool {
        self.pump();
        self.seen_events.iter().any(|event| {
            event.get("kind").and_then(serde_json::Value::as_str) == Some(kind)
                && event.get("nick").and_then(serde_json::Value::as_str) == Some(nick)
        })
    }

    fn saw_msg(&mut self, text: &str, directed: bool) -> bool {
        self.pump();
        self.seen_msgs
            .iter()
            .any(|msg| msg.directed == directed && msg.text == text)
    }

    async fn request<T>(
        &self,
        build: impl FnOnce(tokio::sync::oneshot::Sender<T>) -> membership::Request,
    ) -> Result<T, String> {
        self.membership.request(build).await
    }

    async fn roster_json(&self) -> String {
        self.request(|reply| membership::Request::Peers { reply })
            .await
            .unwrap_or_default()
    }

    async fn send(&self, to: Option<&str>, text: &str) -> Result<(), String> {
        let to = membership::parse_to(to).map_err(|error| error.to_string())?;
        let body = membership::msg_body(text).map_err(|error| error.to_string())?;
        self.request(|reply| membership::Request::Send { to, body, reply })
            .await?
    }

    async fn state_merge(&self, merge: serde_json::Value) -> Result<(), String> {
        self.request(|reply| membership::Request::StateMerge { merge, reply })
            .await?
    }

    async fn state_json(&self) -> String {
        self.request(|reply| membership::Request::StateJson { reply })
            .await
            .unwrap_or_default()
    }
}

/// Every payload lane, both directions: broadcast, directed, state merge.
/// Send from the native side, retrying inside the payload window. The first
/// directed frame to a fresh peer can race the very path it needs — a dial
/// cooldown burned by a pre-link probe, a punch still landing — and a cell
/// measures the mesh's steady state, not that race. The receipt checks below
/// keep their own deadline, so a send that only succeeds at the end of the
/// window still fails the cell if the frame never lands.
async fn native_send_with_retry(
    native: &Native,
    to: Option<&str>,
    text: &str,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + PAYLOAD_TIMEOUT;
    loop {
        let Err(error) = native.send(to, text).await else {
            return Ok(());
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(error);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn check_payload_lanes(page: &Page, native: &mut Native) -> Result<(), CellFailure> {
    let fail = |message: String| CellFailure(message);
    let messages_text =
        || page.evaluate("(document.getElementById('messages')||{}).textContent||''");

    // ── broadcast both ways ─────────────────────────────────────────
    native_send_with_retry(native, None, "native-broadcast")
        .await
        .map_err(|error| fail(format!("native broadcast refused: {error}")))?;
    call_page(page, "harness", "send(null, 'browser-broadcast')").map_err(&fail)?;
    let broadcast_both = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(500), || {
        (messages_text().contains("native-broadcast") && native.saw_msg("browser-broadcast", false))
            .then_some(())
    });
    if broadcast_both.is_none() {
        return Err(fail(format!(
            "a broadcast did not arrive on both sides (browser got native's: {}, native got browser's: {})",
            messages_text().contains("native-broadcast"),
            native.saw_msg("browser-broadcast", false),
        )));
    }

    // ── directed both ways ──────────────────────────────────────────
    native_send_with_retry(native, Some("browser"), "native-directed")
        .await
        .map_err(|error| fail(format!("native directed send refused: {error}")))?;
    call_page(page, "harness", "send('native', 'browser-directed')").map_err(&fail)?;
    let directed_both = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(500), || {
        (messages_text().contains("native-directed") && native.saw_msg("browser-directed", true))
            .then_some(())
    });
    if directed_both.is_none() {
        return Err(fail(
            "a directed message did not arrive on both sides".to_owned(),
        ));
    }

    // ── state merge both ways ───────────────────────────────────────
    native
        .state_merge(serde_json::json!({ "fromNative": 1 }))
        .await
        .map_err(|error| fail(format!("native state merge refused: {error}")))?;
    call_page(page, "harness", "stateMerge('{\"fromBrowser\":2}')").map_err(&fail)?;
    let converged = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(500), || {
        let browser_state = page.evaluate("(document.getElementById('state')||{}).textContent||''");
        (browser_state.contains("fromNative") && browser_state.contains("fromBrowser"))
            .then_some(())
    });
    if converged.is_none() {
        return Err(fail("the state documents never converged".to_owned()));
    }
    let deadline = tokio::time::Instant::now() + PAYLOAD_TIMEOUT;
    loop {
        let state = native.state_json().await;
        if state.contains("fromNative") && state.contains("fromBrowser") {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(fail(format!(
                "the native state never converged with the browser's: {state}"
            )));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// ── the served page ─────────────────────────────────────────────────────

/// A Bun dev server (the harness page, the chat page), killed when it goes
/// out of scope. Stderr is discarded — the old piped-but-never-read handle
/// could only ever stall the child on a full pipe.
pub(super) struct BunServer {
    child: Child,
    pub(super) url: String,
}

impl Drop for BunServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl BunServer {
    pub(super) fn serve(dir: &std::path::Path, script: &str, what: &str) -> Result<Self, Skip> {
        let port = free_port()?;
        let child = Command::new("bun")
            .arg("run")
            .arg(script)
            .arg(port.to_string())
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Skip(format!("could not start bun for {what}: {error}")))?;
        let server = Self {
            child,
            url: format!("http://127.0.0.1:{port}"),
        };
        let up = wait_for(Duration::from_secs(30), Duration::from_millis(250), || {
            crate::util::reachable(&server.url).then_some(())
        });
        if up.is_none() {
            return Err(Skip(format!("the {what} server never came up")));
        }
        Ok(server)
    }
}

pub(super) use crate::util::webdriver::free_port;

// ── one cell ────────────────────────────────────────────────────────────

struct CellFailure(String);

impl fmt::Display for CellFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn native_opts(cell: &Cell, urls: &Urls, selector: NativeSelector<'_>) -> membership::Opts {
    let mut opts = membership::Opts::default();
    match selector {
        NativeSelector::Topic(topic) => opts.topic = Some(topic.to_owned()),
        NativeSelector::Id(id) => opts.mesh = Some(id.to_owned()),
        // A topic always uses every lookup; a create names its own, and the
        // relay lists below need theirs among them.
        NativeSelector::Create => {
            opts.lookup = vec![match cell.discovery {
                Discovery::Relay => Lookup::Relay,
                Discovery::NostrOnly => Lookup::Nostr,
            }];
        }
    }
    opts.nick = Some("native".to_owned());
    match cell.discovery {
        Discovery::Relay => opts.relay_urls = vec![urls.relay.clone()],
        Discovery::NostrOnly => opts.nostr_urls = vec![urls.nostr.clone()],
    }
    // A topic always has the Nostr lookup: point it at the sweep's relay, not
    // the public ones. The list is in the id, so the page passes it too.
    if matches!(selector, NativeSelector::Topic(_)) {
        opts.nostr_urls = vec![urls.nostr.clone()];
    }
    opts.transport = cell.transports();
    opts
}

#[derive(Clone, Copy)]
enum NativeSelector<'a> {
    Topic(&'a str),
    Id(&'a str),
    Create,
}

/// The two meeting points a sweep serves: the iroh relay and the Nostr relay.
struct Urls {
    relay: String,
    nostr: String,
    /// The Nostr relay itself, so a cell can check that it was used.
    nostr_relay: habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay,
}

fn page_url(base: &str, cell: &Cell, urls: &Urls, selector: &str, nick: &str) -> String {
    let meeting = match cell.discovery {
        // A topic's id carries the Nostr relays too (see `native_opts`).
        Discovery::Relay if matches!(cell.join, JoinMode::Topic | JoinMode::TopicBrowserFirst) => {
            format!(
                "relay={}&nostr={}",
                urlencode(&urls.relay),
                urlencode(&urls.nostr)
            )
        }
        Discovery::Relay => format!("relay={}", urlencode(&urls.relay)),
        Discovery::NostrOnly => format!("nostr={}", urlencode(&urls.nostr)),
    };
    format!(
        "{base}/?{selector}&nick={nick}&{meeting}&transport={}&log=habilis_network=debug,iroh_gossip=debug",
        cell.transports()
            .into_iter()
            .map(Transport::as_str)
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// The refusal cell: the tab must refuse a mesh it could carry no payload in,
/// and say why, rather than join and sit unlinked.
fn refused_by_the_tab(
    cell: &Cell,
    urls: &Urls,
    harness: &BunServer,
    page: &Page,
    topic: &str,
) -> Result<String, CellFailure> {
    page.navigate(&page_url(
        &harness.url,
        cell,
        urls,
        &format!("topic={topic}"),
        "browser",
    ));
    let failed = wait_for(Duration::from_secs(30), Duration::from_millis(500), || {
        let failed = page_text(page, "failed");
        (!failed.is_empty()).then_some(failed)
    })
    .ok_or_else(|| CellFailure("the tab opened a mesh it has no path in".to_owned()))?;
    if !failed.contains(habilis_network::runtime::BROWSER_HAS_NO_PATH) {
        return Err(CellFailure(format!(
            "the tab failed for another reason: {failed}"
        )));
    }
    Ok("refused by the tab".to_owned())
}

/// The line the offering side logs when a session's offer and answer rode
/// Nostr. Only the offerer logs it at INFO, and either side can offer.
const NOSTR_ATTACH: &str = "webrtc session attached (nostr)";

fn page_text(page: &Page, id: &str) -> String {
    page.evaluate(&format!(
        "(document.getElementById('{id}')||{{}}).textContent||''"
    ))
}

/// Every console line the tab mirrored, not only the tail `#log` shows.
fn page_log(page: &Page) -> String {
    page.evaluate("(window.harnessLog||[]).join('\\n')")
}

/// Wait for the harness page to open its mesh, or say why it did not.
fn wait_page_ready(page: &Page) -> Result<(), CellFailure> {
    let ready = wait_ready(page, Duration::from_secs(30), Duration::from_millis(500))
        .ok_or_else(|| CellFailure("the harness page never became ready".to_owned()))?;
    ready.map_err(|error| CellFailure(format!("the harness page failed to open the mesh: {error}")))
}

/// Mint a mesh id on the native side and leave it, so a browser can be the
/// first member of a mesh with no topic.
async fn mint_id(cell: &Cell, urls: &Urls) -> Result<String, CellFailure> {
    let minted = Native::open(&native_opts(cell, urls, NativeSelector::Create))
        .await
        .map_err(|Skip(reason)| CellFailure(reason))?;
    let id = minted.membership.node.mesh_id().to_string();
    minted
        .membership
        .node
        .leave()
        .await
        .map_err(|error| CellFailure(format!("the minting peer failed to leave: {error:#}")))?;
    Ok(id)
}

/// Stand the two sides of a cell up in its order, and point the page at the
/// mesh.
async fn open_pair(
    cell: &Cell,
    urls: &Urls,
    harness: &BunServer,
    page: &Page,
    topic: &str,
) -> Result<Native, CellFailure> {
    let fail = |message: String| CellFailure(message);
    let (native, selector) = match cell.join {
        JoinMode::Topic | JoinMode::TopicBrowserFirst => {
            let selector = format!("topic={topic}");
            if cell.join == JoinMode::TopicBrowserFirst {
                page.navigate(&page_url(&harness.url, cell, urls, &selector, "browser"));
                // "Browser first" means the tab *holds the beacon* when the
                // native side arrives — and a claim takes two 5s probes plus
                // tick cadence, so the fixed 12s nap this replaced raced the
                // claim and the native side usually won it anyway. The tab's
                // console mirrors INFO lines into `#log`; wait for its word.
                let claimed = wait_for(Duration::from_mins(1), Duration::from_millis(500), || {
                    page_text(page, "log")
                        .contains("beacon role active")
                        .then_some(())
                });
                if claimed.is_none() {
                    return Err(fail("the tab never claimed the beacon".to_owned()));
                }
            }
            let native = Native::open(&native_opts(cell, urls, NativeSelector::Topic(topic)))
                .await
                .map_err(|Skip(reason)| fail(reason))?;
            (native, selector)
        }
        JoinMode::IdFromNative => {
            let native = Native::open(&native_opts(cell, urls, NativeSelector::Create))
                .await
                .map_err(|Skip(reason)| fail(reason))?;
            let id = native.membership.node.mesh_id().to_string();
            (
                native,
                format!("mesh={urlencoded}", urlencoded = urlencode(&id)),
            )
        }
        JoinMode::IdBrowserFirst => {
            let id = mint_id(cell, urls).await?;
            let selector = format!("mesh={}", urlencode(&id));
            page.navigate(&page_url(&harness.url, cell, urls, &selector, "browser"));
            wait_page_ready(page)?;
            let native = Native::open(&native_opts(cell, urls, NativeSelector::Id(&id)))
                .await
                .map_err(|Skip(reason)| fail(reason))?;
            (native, selector)
        }
        JoinMode::BrowserPair => {
            return Err(fail("a browser pair runs in run_browser_pair".to_owned()));
        }
    };
    if !matches!(
        cell.join,
        JoinMode::TopicBrowserFirst | JoinMode::IdBrowserFirst
    ) {
        // Wait for the native side's beacon before the tab starts: a joiner
        // probing while the claim is still in flight reads the rendezvous as
        // free, claims a second copy, and the two shed each other for the
        // whole cell. Real joins land on a live beacon; so does the cell. A
        // Nostr-only mesh has no beacon to wait for.
        if cell.discovery == Discovery::Relay {
            let claimed = wait_for(Duration::from_secs(25), Duration::from_millis(500), || {
                logs_contain("beacon role active").then_some(())
            });
            if claimed.is_none() {
                return Err(fail("the native side never claimed the beacon".to_owned()));
            }
        }
        page.navigate(&page_url(&harness.url, cell, urls, &selector, "browser"));
    }
    Ok(native)
}

async fn run_cell(
    cell: &Cell,
    urls: &Urls,
    harness: &BunServer,
    page: &Page,
) -> Result<String, CellFailure> {
    let fail = |message: String| CellFailure(message);
    let topic = format!("mesh-matrix-{}", rand_token());
    drain_logs();

    if !cell.expects_link() {
        return refused_by_the_tab(cell, urls, harness, page, &topic);
    }

    let nostr_before = urls.nostr_relay.accepted();
    let mut native = open_pair(cell, urls, harness, page, &topic).await?;
    wait_page_ready(page)?;

    // ── link expectation ────────────────────────────────────────────
    let browser_sees_native = || page_text(page, "peers").contains("\"native\"");
    let linked = wait_for(LINK_TIMEOUT, Duration::from_secs(1), || {
        (native.saw_event("joined", "browser") && browser_sees_native()).then_some(())
    });
    if linked.is_none() {
        return Err(fail(format!(
            "the pair never linked (native saw browser: {}, browser saw native: {})",
            native.saw_event("joined", "browser"),
            browser_sees_native(),
        )));
    }

    // ── lanes: wait for the pair's own direct session ───────────────
    // Rostered is not direct: the two meet through the beacon's overlay
    // first (`reach: "gossip"`), and their own JSEP round and graft follow
    // on the retry ticks. On a lookup-only mesh a directed frame is *held*
    // until then, so the payload checks below need the `unicast` lane.
    let deadline = tokio::time::Instant::now() + LINK_TIMEOUT;
    loop {
        let native_roster = native.roster_json().await;
        if !native_roster.contains("\"browser\"") {
            return Err(fail(format!(
                "the native roster lost the browser peer: {native_roster}"
            )));
        }
        if native_roster.contains("\"transport\":\"unicast\"") {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(fail(format!(
                "the pair rostered but never went direct: {native_roster}"
            )));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    check_payload_lanes(page, &mut native).await?;

    if cell.discovery == Discovery::NostrOnly
        && !logs_contain(NOSTR_ATTACH)
        && !page_log(page).contains(NOSTR_ATTACH)
    {
        return Err(fail(format!(
            "the pair linked, but neither side logged `{NOSTR_ATTACH}`"
        )));
    }

    // ── leave: the browser departs, the native side hears it ────────
    call_page(page, "harness", "close()").map_err(&fail)?;
    let left = wait_for(PAYLOAD_TIMEOUT, Duration::from_secs(1), || {
        native.saw_event("left", "browser").then_some(())
    });
    if left.is_none() {
        return Err(fail(
            "the browser left but the native side never surfaced it".to_owned(),
        ));
    }

    // A topic id always carries the Nostr lookup. Its Nostr relays must be
    // the sweep's own, or the cell signals over the public ones: it would
    // then need the internet and pass for a reason the cell does not test.
    if matches!(cell.join, JoinMode::Topic | JoinMode::TopicBrowserFirst)
        && urls.nostr_relay.accepted() == nostr_before
    {
        return Err(fail(
            "the topic's Nostr signalling never reached the local Nostr relay".to_owned(),
        ));
    }

    Ok("linked, all lanes both ways".to_owned())
}

/// A page's send, retried inside the payload window. The first directed
/// message can race the pair's own session, like the native side's.
fn page_send_with_retry(page: &Page, to: Option<&str>, text: &str) -> Result<(), CellFailure> {
    let to = to.map_or_else(|| "null".to_owned(), |nick| format!("'{nick}'"));
    let call = format!("send({to}, '{text}')");
    let deadline = std::time::Instant::now() + PAYLOAD_TIMEOUT;
    loop {
        match call_page(page, "harness", &call) {
            Ok(_) => return Ok(()),
            Err(error) if std::time::Instant::now() >= deadline => {
                return Err(CellFailure(error));
            }
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    }
}

/// Two tabs and no native member: they find each other and exchange the
/// offer and answer over Nostr alone. Broadcast and directed, both ways.
async fn run_browser_pair(
    cell: &Cell,
    urls: &Urls,
    harness: &BunServer,
    first: &Page,
    second: &Page,
) -> Result<String, CellFailure> {
    let fail = |message: String| CellFailure(message);
    drain_logs();
    let id = mint_id(cell, urls).await?;
    let selector = format!("mesh={}", urlencode(&id));
    first.navigate(&page_url(&harness.url, cell, urls, &selector, "tab-a"));
    wait_page_ready(first)?;
    second.navigate(&page_url(&harness.url, cell, urls, &selector, "tab-b"));
    wait_page_ready(second)?;

    let linked = wait_for(LINK_TIMEOUT, Duration::from_secs(1), || {
        (page_text(first, "peers").contains("\"tab-b\"")
            && page_text(second, "peers").contains("\"tab-a\""))
        .then_some(())
    });
    if linked.is_none() {
        return Err(fail(format!(
            "the tabs never linked (a saw b: {}, b saw a: {})",
            page_text(first, "peers").contains("\"tab-b\""),
            page_text(second, "peers").contains("\"tab-a\""),
        )));
    }

    for (from, to, nick) in [(first, second, "tab-b"), (second, first, "tab-a")] {
        let broadcast = format!("broadcast-to-{nick}");
        let directed = format!("directed-to-{nick}");
        page_send_with_retry(from, None, &broadcast)?;
        page_send_with_retry(from, Some(nick), &directed)?;
        let arrived = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(500), || {
            let messages = page_text(to, "messages");
            (messages.contains(&broadcast) && messages.contains(&directed)).then_some(())
        });
        if arrived.is_none() {
            return Err(fail(format!("{nick} never got both messages")));
        }
    }

    if !page_log(first).contains(NOSTR_ATTACH) && !page_log(second).contains(NOSTR_ATTACH) {
        return Err(fail(format!(
            "the tabs linked, but neither logged `{NOSTR_ATTACH}`"
        )));
    }
    call_page(first, "harness", "close()").map_err(&fail)?;
    call_page(second, "harness", "close()").map_err(&fail)?;
    Ok("linked, broadcast and directed both ways".to_owned())
}

// ── the sweep ───────────────────────────────────────────────────────────

pub(super) fn run(args: &Args) -> TaskOutcome {
    let cells = cells(args.quick);
    if args.list {
        for cell in &cells {
            output::verbatim(&format!("{}  would run", cell.label()));
        }
        return Ok(());
    }

    build::ensure_bun("the mesh suite serves its harness with bun")?;

    // The suite owns its wasm: a stale glue silently tests the previous
    // engine, which is how two of this suite's own findings hid at first.
    build::build_browser_peer()?;

    init_logging();
    // The cells stagger the browser behind the native side's `beacon role
    // active`, so the native peer always claims round 0 — and a rival
    // re-check that sheds a healthy two-member beacon mid-cell forces the
    // browser through a full JSEP+graft rebuild that eats the cell budget
    // (observed: shed at T+30s, re-claim at T+150s, pair session attached
    // one second before the deadline). Park the re-check beyond any cell:
    // the matrix measures the mesh's steady state, and same-id split repair
    // has the engine's own tests. In-process only — the browser side never
    // claims under the stagger, so its defaults stay untouched.
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

    // One relay, one Nostr relay and one harness server for the whole sweep;
    // topics and ids are random, so cells never meet each other.
    let (relay_url, _relay_server) = runtime
        .block_on(habilis_network::net::test_relay::spawn_plain())
        .map_err(|error| format!("no local relay: {error:#}"))?;
    let nostr_relay = runtime
        .block_on(habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay::spawn())
        .map_err(|error| format!("no local Nostr relay: {error:#}"))?;
    let urls = Urls {
        relay: relay_url.to_string(),
        nostr: nostr_relay.url().to_string(),
        nostr_relay,
    };
    let harness = BunServer::serve(
        &repo_root().join("packages/habilis-network-wasm"),
        "harness/serve.ts",
        "the harness",
    )
    .map_err(|Skip(reason)| reason)?;
    output::status(
        "Serving",
        &format!(
            "relay {} · nostr {} · harness {}",
            urls.relay, urls.nostr, harness.url
        ),
    );

    let only = args.page_browser().to_owned();
    // `MESH_CELL=<substring>` narrows the sweep to matching cell labels —
    // for iterating on one failing cell without paying for the rest.
    let cell_filter = std::env::var("MESH_CELL").ok();
    let mut failures = 0usize;
    for cell in &cells {
        if let Some(filter) = &cell_filter
            && !cell.label().contains(filter.as_str())
        {
            continue;
        }
        output::status("Running", &cell.label());
        // A fresh browser per cell: harness state is per-page, and a leave
        // must not bleed into the next cell.
        let page = match launch_page(&only) {
            Ok(page) => page,
            Err(Skip(reason)) => {
                output::caution("skip", &format!("{}  {reason}", cell.label()));
                continue;
            }
        };
        let outcome = if cell.join == JoinMode::BrowserPair {
            match launch_page(&only) {
                Ok(second) => {
                    runtime.block_on(run_browser_pair(cell, &urls, &harness, &page, &second))
                }
                Err(Skip(reason)) => {
                    output::caution("skip", &format!("{}  {reason}", cell.label()));
                    continue;
                }
            }
        } else {
            runtime.block_on(run_cell(cell, &urls, &harness, &page))
        };
        match outcome {
            Ok(detail) => output::status("ok", &format!("{}  {detail}", cell.label())),
            Err(CellFailure(reason)) => {
                failures += 1;
                output::failure("FAILED", &format!("{}  {reason}", cell.label()));
                // The whole native log plus the browser's DOM state, to a
                // file — twenty lines of tail answered nothing twice.
                let logs = drain_logs();
                let browser = [
                    (
                        "failed",
                        "(document.getElementById('failed')||{}).textContent||''",
                    ),
                    (
                        "peers",
                        "(document.getElementById('peers')||{}).textContent||''",
                    ),
                    (
                        "events",
                        "(document.getElementById('events')||{}).textContent||''",
                    ),
                    (
                        "messages",
                        "(document.getElementById('messages')||{}).textContent||''",
                    ),
                    ("console", "(window.harnessLog||[]).join('\\n')"),
                ]
                .map(|(name, expr)| {
                    format!(
                        "\u{2500}\u{2500} browser {name} \u{2500}\u{2500}\n{}\n",
                        page.evaluate(expr)
                    )
                });
                let dump = repo_root().join("target").join(format!(
                    "mesh-cell-{}.log",
                    cell.label().replace([' ', '/'], "_")
                ));
                let _ = std::fs::write(&dump, format!("{}\n{logs}", browser.join("\n")));
                output::detail(&format!("full log: {}", dump.display()));
            }
        }
        output::detail(&page.version());
    }

    if failures > 0 {
        return Err(format!("{failures} mesh cell(s) failed").into());
    }
    Ok(())
}

pub(super) fn launch_page(only: &str) -> Result<Page, Skip> {
    if "cft".contains(only) || only.contains("cft") {
        return Ok(Page::Cdp(Box::new(cdp::Browser::launch()?)));
    }
    for browser in super::browsers() {
        if !browser.name.contains(only) {
            continue;
        }
        if browser.binary.is_empty() {
            return Err(Skip(format!(
                "{}: set $CHROME_BIN and $CHROMEDRIVER to run it",
                browser.name
            )));
        }
        if !PathBuf::from(&browser.binary).exists() {
            return Err(Skip(format!("not installed: {}", browser.binary)));
        }
        return match browser.backend {
            super::Backend::Cdp => Ok(Page::Cdp(Box::new(cdp::Browser::launch()?))),
            super::Backend::WebDriver => Ok(Page::WebDriver(webdriver::Session::open(
                browser.name,
                &browser.binary,
            )?)),
        };
    }
    Err(Skip(format!("no browser matches --only {only}")))
}
