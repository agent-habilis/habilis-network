//! `cargo task e2e --suite mesh` — the native↔browser matrix.
//!
//! One local plain-HTTP relay both sides can reach, one in-process native
//! peer (`fofoca::membership`), one real browser on the harness page
//! (`packages/fofoca-wasm/harness`), driven cell by cell:
//!
//! - **policy** — the mesh's `relay_transport`, on or off;
//! - **native transports** — everything / WebRTC only / relay only, to force
//!   the punch, the data channel, and the refusal in turn;
//! - **join mode** — both derive from a topic, the browser joins the id the
//!   native side minted, or the browser opens the topic first.
//!
//! Every linked cell must move payload **both ways** on every lane —
//! broadcast, directed, state merge — and agree on the roster. The one
//! non-linking cell (policy off × native relay-only) must *never* link, and
//! must say why in the engine's own words (`relay-only path refused`).

use std::fmt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::TaskOutcome;
use crate::util::{output, repo_root, wait_for};

use fofoca::membership;
use fofoca::net::PathFlags;
use fofoca::protocol::Transport;

use super::{Args, Skip, build, cdp, webdriver};

/// A linked pair has to survive the beacon claim (~8 s), a WebRTC
/// negotiation or a hole punch, and one alive-tick retry.
const LINK_TIMEOUT: Duration = Duration::from_mins(4);
/// The accept gate holds a relayed connection for 15 s; this outlasts the
/// hold plus one heal-tick retry, so a link would have had every chance.
const REFUSAL_WINDOW: Duration = Duration::from_secs(40);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    LookupOnly,
    RelayTransport,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NativeTransports {
    Default,
    WebRtcOnly,
    RelayOnly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinMode {
    /// Native first, browser second, both deriving one topic.
    Topic,
    /// Native mints a mesh; the browser joins the printed id.
    IdFromNative,
    /// The browser opens the topic first and briefly runs the mesh alone.
    TopicBrowserFirst,
}

struct Cell {
    policy: Policy,
    native: NativeTransports,
    join: JoinMode,
}

impl Cell {
    /// The one cell that must not link: no direct path can exist and the
    /// relay may not carry payload.
    fn expects_link(&self) -> bool {
        !(self.policy == Policy::LookupOnly && self.native == NativeTransports::RelayOnly)
    }

    fn label(&self) -> String {
        format!(
            "{} / {} / {}",
            match self.policy {
                Policy::LookupOnly => "lookup-only",
                Policy::RelayTransport => "relay-transport",
            },
            match self.native {
                NativeTransports::Default => "native-all",
                NativeTransports::WebRtcOnly => "native-webrtc",
                NativeTransports::RelayOnly => "native-relay-only",
            },
            match self.join {
                JoinMode::Topic => "topic",
                JoinMode::IdFromNative => "id",
                JoinMode::TopicBrowserFirst => "browser-first",
            },
        )
    }
}

fn cells(quick: bool) -> Vec<Cell> {
    let mut cells = Vec::new();
    for policy in [Policy::LookupOnly, Policy::RelayTransport] {
        for native in [
            NativeTransports::Default,
            NativeTransports::WebRtcOnly,
            NativeTransports::RelayOnly,
        ] {
            for join in [
                JoinMode::Topic,
                JoinMode::IdFromNative,
                JoinMode::TopicBrowserFirst,
            ] {
                cells.push(Cell {
                    policy,
                    native,
                    join,
                });
            }
        }
    }
    if quick {
        // The four cells that cover every mechanism once: both policies on
        // the default transports, the WebRTC-only lane, and the refusal.
        cells.retain(|cell| {
            cell.join == JoinMode::Topic
                && (cell.native == NativeTransports::Default || cell.policy == Policy::LookupOnly)
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
                .unwrap_or_else(|_| "fofoca=info,fofoca::lifecycle=debug".into()),
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

// ── the browser page ────────────────────────────────────────────────────

/// One browser on the harness page, behind whichever driver reaches it.
pub(super) enum Page {
    Cdp(cdp::Browser),
    WebDriver(webdriver::Session),
}

impl Page {
    pub(super) fn navigate(&self, url: &str) {
        match self {
            Self::Cdp(browser) => browser.navigate(url),
            Self::WebDriver(session) => session.navigate(url),
        }
    }

    /// [`Page::navigate`], recording the console for `window` where the
    /// driver can. `WebDriver` has no console stream, so it only navigates.
    pub(super) fn navigate_watching_console(&self, url: &str, window: Duration) {
        match self {
            Self::Cdp(browser) => browser.navigate_watching_console(url, window),
            Self::WebDriver(session) => session.navigate(url),
        }
    }

    /// What [`Page::navigate_watching_console`] recorded; blocks until its
    /// window is over.
    pub(super) fn console(&self) -> String {
        match self {
            Self::Cdp(browser) => browser.console(),
            Self::WebDriver(_) => String::new(),
        }
    }

    /// Evaluate a JS expression (no `return`), reading its value as a string.
    pub(super) fn evaluate(&self, expression: &str) -> String {
        match self {
            Self::Cdp(browser) => browser.evaluate(expression),
            Self::WebDriver(session) => session.execute(&format!("return ({expression});")),
        }
    }

    fn version(&self) -> String {
        match self {
            Self::Cdp(browser) => browser.version(),
            Self::WebDriver(session) => session.version(),
        }
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

/// A page object's promise-returning controls (`window.harness`,
/// `window.chat`), awaited via a completion flag the driver polls — neither
/// backend can await a JS promise directly.
pub(super) fn call_page(page: &Page, object: &str, call: &str) -> Result<(), String> {
    let token = format!("call{}", rand_token());
    let expression = format!(
        "window.{token}='pending',window.{object}.{call}.then(()=>window.{token}='ok',(e)=>window.{token}='error: '+e),'started'"
    );
    let started = page.evaluate(&expression);
    if started != "started" {
        return Err(format!("{object} call {call} did not start: {started:?}"));
    }
    let outcome = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(250), || {
        let state = page.evaluate(&format!("window.{token}"));
        (state != "pending").then_some(state)
    })
    .ok_or_else(|| format!("{object} call {call} never settled"))?;
    if outcome == "ok" {
        return Ok(());
    }
    Err(format!("{object} call {call} failed: {outcome}"))
}

pub(super) fn rand_token() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.subsec_nanos().into())
        .unwrap_or_default()
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
            super::server::reachable(&server.url).then_some(())
        });
        if up.is_none() {
            return Err(Skip(format!("the {what} server never came up")));
        }
        Ok(server)
    }
}

pub(super) use super::webdriver::free_port;

// ── one cell ────────────────────────────────────────────────────────────

struct CellFailure(String);

impl fmt::Display for CellFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn native_opts(cell: &Cell, relay_url: &str, selector: NativeSelector<'_>) -> membership::Opts {
    let mut opts = membership::Opts::default();
    match selector {
        NativeSelector::Topic(topic) => opts.topic = Some(topic.to_owned()),
        NativeSelector::Create => {}
    }
    opts.nick = Some("native".to_owned());
    opts.relay_urls = vec![relay_url.to_owned()];
    opts.transport = match cell.policy {
        Policy::RelayTransport => vec![Transport::P2p, Transport::Relay],
        Policy::LookupOnly => vec![Transport::P2p],
    };
    opts.paths = match cell.native {
        NativeTransports::Default => PathFlags {
            ip: true,
            webrtc: true,
        },
        NativeTransports::WebRtcOnly => PathFlags {
            ip: false,
            webrtc: true,
        },
        NativeTransports::RelayOnly => PathFlags {
            ip: false,
            webrtc: false,
        },
    };
    opts
}

#[derive(Clone, Copy)]
enum NativeSelector<'a> {
    Topic(&'a str),
    Create,
}

fn page_url(base: &str, cell: &Cell, relay_url: &str, selector: &str) -> String {
    format!(
        "{base}/?{selector}&nick=browser&relay={}&transport={}&log=fofoca=debug,iroh_gossip=debug",
        urlencode(relay_url),
        match cell.policy {
            Policy::RelayTransport => "p2p,relay",
            Policy::LookupOnly => "p2p",
        },
    )
}

pub(super) fn urlencode(raw: &str) -> String {
    raw.replace('%', "%25")
        .replace('&', "%26")
        .replace('+', "%2B")
        .replace('#', "%23")
}

async fn run_cell(
    cell: &Cell,
    relay_url: &str,
    harness: &BunServer,
    page: &Page,
) -> Result<String, CellFailure> {
    let fail = |message: String| CellFailure(message);
    let topic = format!("mesh-matrix-{}", rand_token());
    drain_logs();

    // Stand the two sides up in the cell's order.
    let (native, selector) = match cell.join {
        JoinMode::Topic | JoinMode::TopicBrowserFirst => {
            let selector = format!("topic={topic}");
            if cell.join == JoinMode::TopicBrowserFirst {
                page.navigate(&page_url(&harness.url, cell, relay_url, &selector));
                // "Browser first" means the tab *holds the beacon* when the
                // native side arrives — and a claim takes two 5s probes plus
                // tick cadence, so the fixed 12s nap this replaced raced the
                // claim and the native side usually won it anyway. The tab's
                // console mirrors INFO lines into `#log`; wait for its word.
                let claimed = wait_for(Duration::from_mins(1), Duration::from_millis(500), || {
                    page.evaluate("(document.getElementById('log')||{}).textContent||''")
                        .contains("beacon role active")
                        .then_some(())
                });
                if claimed.is_none() {
                    return Err(fail("the tab never claimed the beacon".to_owned()));
                }
            }
            let native = Native::open(&native_opts(cell, relay_url, NativeSelector::Topic(&topic)))
                .await
                .map_err(|Skip(reason)| fail(reason))?;
            (native, selector)
        }
        JoinMode::IdFromNative => {
            let native = Native::open(&native_opts(cell, relay_url, NativeSelector::Create))
                .await
                .map_err(|Skip(reason)| fail(reason))?;
            let id = native.membership.node.mesh_id().to_string();
            (
                native,
                format!("mesh={urlencoded}", urlencoded = urlencode(&id)),
            )
        }
    };
    let mut native = native;
    if cell.join != JoinMode::TopicBrowserFirst {
        // Wait for the native side's beacon before the tab starts: a joiner
        // probing while the claim is still in flight reads the rendezvous as
        // free, claims a second copy, and the two shed each other for the
        // whole cell. Real joins land on a live beacon; so does the cell.
        let claimed = wait_for(Duration::from_secs(25), Duration::from_millis(500), || {
            logs_contain("beacon role active").then_some(())
        });
        if claimed.is_none() {
            return Err(fail("the native side never claimed the beacon".to_owned()));
        }
        page.navigate(&page_url(&harness.url, cell, relay_url, &selector));
    }

    // The page must open the mesh — even the refusal cell (the mesh opens;
    // the *pair* never links).
    let ready = wait_for(Duration::from_secs(30), Duration::from_millis(500), || {
        let failed = page.evaluate("(document.getElementById('failed')||{}).textContent||''");
        if !failed.is_empty() {
            return Some(Err(failed));
        }
        let ready = page.evaluate("document.getElementById('ready')?'1':'0'");
        (ready == "1").then_some(Ok(()))
    })
    .ok_or_else(|| fail("the harness page never became ready".to_owned()))?;
    ready.map_err(|error| fail(format!("the harness page failed to open the mesh: {error}")))?;

    // ── link expectation ────────────────────────────────────────────
    let browser_sees_native = || {
        page.evaluate("(document.getElementById('peers')||{}).textContent||''")
            .contains("\"native\"")
    };
    if cell.expects_link() {
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
    } else {
        tokio::time::sleep(REFUSAL_WINDOW).await;
        if native.saw_event("joined", "browser") || browser_sees_native() {
            return Err(fail(
                "a relay-only pair linked although the relay is lookup only".to_owned(),
            ));
        }
        // Whichever side holds the beacon does the refusing: native-first
        // cells log it natively, browser-first cells log it in the tab.
        let logs = drain_logs();
        let browser_log = page.evaluate("(document.getElementById('log')||{}).textContent||''");
        if !logs.contains("relay-only path refused")
            && !browser_log.contains("relay-only path refused")
        {
            return Err(fail(
                "the pair stayed unlinked but the engine never logged the refusal".to_owned(),
            ));
        }
        return Ok("held apart, refusal logged".to_owned());
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

    Ok("linked, all lanes both ways".to_owned())
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
    fofoca::util::tuning::init(fofoca::util::tuning::Tuning {
        rival_recheck_first_secs: 3600,
        rival_recheck_secs: 3600,
        rival_recheck_meshed_secs: 3600,
        ..fofoca::util::tuning::Tuning::DEFAULTS
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no tokio runtime: {error}"))?;

    // One relay and one harness server for the whole sweep; topics are
    // random, so cells never meet each other.
    let (relay_url, _relay_server) = runtime
        .block_on(fofoca::net::test_relay::spawn_plain())
        .map_err(|error| format!("no local relay: {error:#}"))?;
    let harness = BunServer::serve(
        &repo_root().join("packages/fofoca-wasm"),
        "harness/serve.ts",
        "the harness",
    )
    .map_err(|Skip(reason)| reason)?;
    output::status(
        "Serving",
        &format!("relay {relay_url} · harness {}", harness.url),
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
        let outcome = runtime.block_on(run_cell(cell, relay_url.as_str(), &harness, &page));
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
        return Ok(Page::Cdp(cdp::Browser::launch()?));
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
            super::Backend::Cdp => Ok(Page::Cdp(cdp::Browser::launch()?)),
            super::Backend::WebDriver => Ok(Page::WebDriver(webdriver::Session::open(
                browser.name,
                &browser.binary,
            )?)),
        };
    }
    Err(Skip(format!("no browser matches --only {only}")))
}
