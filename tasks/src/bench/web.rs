//! The browser cells: real browser processes, one per tab — Chrome for
//! Testing over CDP, Safari Technology Preview over `WebDriver` —
//! with the JSEP envelopes ferried between them by this runner.
//!
//! Two processes rather than two endpoints in one tab, because the one-tab
//! case is the easiest that exists (one event loop, loopback ICE) and the
//! number wanted is what two real browsers get. The runner reads the offer
//! from one tab's `bench.offer()` and hands it to the other's
//! `bench.answer()` as a string literal, so no signaling server is needed.

use std::time::{Duration, Instant};

use fofoca_iroh_webrtc_transport::bench::{BENCH_ALPN, Bench};
use fofoca_iroh_webrtc_transport::iroh::protocol::Router;
use fofoca_iroh_webrtc_transport::{IceConfig, SignalEnvelope, answer_with};

use crate::util::page::{Evaluate, await_call, call_page_within, start_call, wait_ready};
use crate::util::webdriver::{self, SAFARI_TP};
use crate::util::{Skip, cdp, output};

use super::Args;
use super::native::{JSEP_DEADLINE, WebRtcPeer};
use super::run::{Measured, Outcome, Sample, TRANSFER_TIMEOUT};
use super::serve::Static;

/// The wasm page has to fetch and instantiate the module before `#ready`.
const PAGE_TIMEOUT: Duration = Duration::from_mins(1);

/// Which browser a tab runs in.
#[derive(Clone, Copy)]
pub(crate) enum Engine {
    Chrome,
    Safari,
}

/// The driver behind one tab.
enum Driver {
    Chrome(Box<cdp::Browser>),
    Safari(webdriver::Session),
}

impl Driver {
    fn navigate(&self, url: &str) {
        match self {
            Self::Chrome(browser) => browser.navigate(url),
            Self::Safari(session) => session.navigate(url),
        }
    }

    fn version(&self) -> String {
        match self {
            Self::Chrome(browser) => browser.version(),
            Self::Safari(session) => session.version(),
        }
    }
}

impl Evaluate for Driver {
    fn evaluate(&self, expression: &str) -> String {
        match self {
            Self::Chrome(browser) => browser.evaluate(expression),
            Self::Safari(session) => session.execute(&format!("return ({expression});")),
        }
    }
}

/// One browser process on a benchmark page.
struct Tab {
    page: Driver,
    /// What the page reported as its endpoint id (`raw` for the bare page).
    id: String,
}

impl Tab {
    fn open(engine: Engine, server: &Static, page: &str) -> Result<Self, Skip> {
        let page_obj = match engine {
            Engine::Chrome => Driver::Chrome(Box::new(cdp::Browser::launch()?)),
            Engine::Safari => Driver::Safari(webdriver::Session::open("safari-tp", SAFARI_TP)?),
        };
        page_obj.navigate(&format!("{}/{page}", server.url));
        wait_ready(&page_obj, PAGE_TIMEOUT, Duration::from_millis(250))
            .ok_or_else(|| Skip(format!("the {page} page never became ready")))?
            .map_err(|error| Skip(format!("the {page} page failed to load: {error}")))?;
        let id = page_obj.evaluate("document.getElementById('ready').dataset.id||''");
        Ok(Self { page: page_obj, id })
    }

    fn call(&self, call: &str) -> Result<String, String> {
        call_page_within(&self.page, "bench", call, TRANSFER_TIMEOUT)
    }
}

/// A Rust string as a JS string literal, so an SDP or an id survives being
/// pasted into an expression.
fn literal(value: &str) -> String {
    serde_json::to_string(value).expect("a string always serialises")
}

/// The JSEP round between two tabs. The answerer's `complete` is started
/// before the offerer's and awaited after: it waits on `ondatachannel`,
/// which only fires once the offerer has applied the answer.
fn negotiate(offerer: &Tab, answerer: &Tab) -> Result<f64, String> {
    let started = Instant::now();
    let offer = offerer.call("offer()")?;
    let answer = answerer.call(&format!("answer({})", literal(&offer)))?;
    let answerer_done = start_call(&answerer.page, "bench", "complete('')")?;
    offerer.call(&format!("complete({})", literal(&answer)))?;
    await_call(&answerer.page, &answerer_done, JSEP_DEADLINE)
        .map_err(|error| format!("answerer complete: {error}"))?;
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

/// Warm-up plus `rounds` transfers, each timed by the page. `message` is
/// the raw page's message size; the wasm page ignores a fourth argument.
fn rounds(
    client: &Tab,
    remote: &str,
    args: &Args,
    message: Option<usize>,
) -> Result<Vec<Sample>, String> {
    let mut samples = Vec::with_capacity(args.rounds + 1);
    for _ in 0..=args.rounds {
        let reply = client.call(&format!(
            "download({}, {}, '{}'{})",
            literal(remote),
            args.bytes,
            args.direction.protocol().label(),
            message.map(|size| format!(", {size}")).unwrap_or_default(),
        ))?;
        let value: serde_json::Value = serde_json::from_str(&reply)
            .map_err(|error| format!("unreadable sample {reply:?}: {error}"))?;
        let field = |name: &str| value.get(name).cloned().unwrap_or_default();
        samples.push(Sample {
            bytes: usize::try_from(field("bytes").as_u64().unwrap_or_default()).unwrap_or_default(),
            elapsed_ms: field("elapsed_ms").as_f64().unwrap_or_default(),
            path: field("path").as_str().unwrap_or("other").to_owned(),
        });
    }
    Ok(samples)
}

/// What every browser cell needs: the page server and the run's arguments.
pub(crate) struct Browser<'a> {
    pub(crate) server: &'a Static,
    pub(crate) args: &'a Args,
}

impl Browser<'_> {
    /// Browser↔browser, on `page` (`index.html` for fofoca, `raw.html` for
    /// the bare channel, with `message` as its message size). The `server`
    /// tab serves, the `client` tab downloads.
    pub(crate) fn web_web(
        &self,
        client_engine: Engine,
        server_engine: Engine,
        page: &str,
        message: Option<usize>,
    ) -> Outcome {
        let args = self.args;
        let tabs = Tab::open(client_engine, self.server, page).and_then(|client| {
            Tab::open(server_engine, self.server, page).map(|server| (client, server))
        });
        let (client, server_tab) = match tabs {
            Ok(tabs) => tabs,
            Err(skip) => return skip.into(),
        };
        output::detail(&format!(
            "             {} ↔ {}",
            client.page.version(),
            server_tab.page.version()
        ));

        let run = || -> Result<Measured, String> {
            let negotiate_ms = negotiate(&client, &server_tab)?;
            server_tab.call("serve()")?;
            let samples = rounds(&client, &server_tab.id, args, message)?;
            Measured::from_samples(negotiate_ms, samples)
        };
        run().into()
    }

    /// Browser↔native: the tab offers and downloads, a str0m endpoint in
    /// this process answers and serves — the lane a real deployment uses.
    pub(crate) async fn web_native(&self, engine: Engine) -> Outcome {
        let args = self.args;
        let client = match Tab::open(engine, self.server, "index.html") {
            Ok(tab) => tab,
            Err(skip) => return skip.into(),
        };
        output::detail(&format!("             {}", client.page.version()));

        let run = async {
            let peer = WebRtcPeer::bind().await?;
            let _router = Router::builder(peer.endpoint.clone())
                .accept(BENCH_ALPN, Bench)
                .spawn();

            let started = Instant::now();
            let offer = client.call("offer()")?;
            let offer: SignalEnvelope = serde_json::from_str(&offer)
                .map_err(|error| format!("unreadable offer: {error}"))?;
            let remote = offer
                .claimed_endpoint()
                .map_err(|error| format!("offer names no endpoint: {error}"))?;
            let (pending, answer) = answer_with(peer.id, &offer, &IceConfig::host_only())
                .await
                .map_err(|error| format!("native answer failed: {error:#}"))?;
            let answer = serde_json::to_string(&answer).map_err(|error| error.to_string())?;
            // Started, not awaited: the native side has to complete
            // concurrently, and `call` would block this thread until the tab
            // settled.
            let client_done = start_call(
                &client.page,
                "bench",
                &format!("complete({})", literal(&answer)),
            )?;
            let session = Box::pin(pending.complete(JSEP_DEADLINE))
                .await
                .map_err(|error| format!("native complete failed: {error:#}"))?;
            peer.transport
                .attach(remote, session)
                .map_err(|error| format!("attach failed: {error:#}"))?;
            await_call(&client.page, &client_done, JSEP_DEADLINE)
                .map_err(|error| format!("browser complete: {error}"))?;
            let negotiate_ms = started.elapsed().as_secs_f64() * 1000.0;

            let samples = rounds(&client, &peer.id.to_string(), args, None)?;
            Measured::from_samples(negotiate_ms, samples)
        };
        Box::pin(run).await.into()
    }
}
