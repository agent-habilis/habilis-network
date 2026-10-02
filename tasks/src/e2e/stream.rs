//! `cargo task e2e --suite stream` — a stream end to end: the real
//! `habilis-network-stream` binary and the real stream web page, each as producer and
//! each as reader, over a local relay.
//!
//! The chat suite proves lines both ways; this proves *bytes in order*: a
//! payload wider than the CLI's stdin chunk, with a multibyte character
//! straddling the chunk boundary, must come out of the other end byte-exact,
//! followed by the end of stream. The reader page is opened at the URL the
//! CLI printed, so the fragment contract is on the line too.

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::TaskOutcome;
use crate::util::output;
use crate::util::{repo_root, wait_for};

use super::mesh::{BunServer, launch_page};
use super::page::{Page, call_page, urlencode};
use super::{Args, Skip, build};

type Failure = Box<dyn std::error::Error>;

/// Lookup over the relay, JSEP and the direct path on a cold pair; generous
/// like the mesh suite's link budget, for the same reason.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(150);
/// The whole payload on an attached pair.
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the tab's console is recorded: past the page's open and the
/// attach wait, so a failure at either still has the whole console.
const CONSOLE_WINDOW: Duration =
    Duration::from_secs(60 + ATTACH_TIMEOUT.as_secs() + PAYLOAD_TIMEOUT.as_secs());
/// The stream closing plus the process winding down.
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
/// The CLI's stdin chunk (`CHUNK` in its `main.rs`).
const CLI_CHUNK: usize = 64 * 1024;

// ── the terminal half ───────────────────────────────────────────────────

/// The CLI as the suite drives it: stdout collected as bytes (it is the
/// stream, not lines), stderr collected as robot JSON where it parses and as
/// the engine log where it does not.
struct Cli {
    child: Child,
    /// The producer's stdin, for [`Input::Open`]: the suite appends to it
    /// the way a file grows under `tail -f`.
    stdin: Option<ChildStdin>,
    stdout: mpsc::Receiver<Vec<u8>>,
    stderr_lines: mpsc::Receiver<String>,
    received: Vec<u8>,
    seen: Vec<serde_json::Value>,
    engine_log: String,
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What the CLI's stdin gets.
enum Input {
    /// Nothing: a reader.
    Nothing,
    /// These bytes, from a thread, then EOF: a producer reads stdin only once
    /// its reader attaches, so a write from here would block on the full pipe.
    Bytes(Vec<u8>),
    /// A pipe the suite holds open and appends to.
    Open,
}

impl Cli {
    /// Start the CLI with `args` and `input` on its stdin.
    fn spawn(binary: &Path, args: &[&str], input: Input) -> Result<Self, Skip> {
        let mut child = Command::new(binary)
            .args(args)
            .arg("--robot")
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "habilis_network=info".to_owned()),
            )
            .stdin(if matches!(input, Input::Nothing) {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Skip(format!("could not start habilis-network-stream: {error}")))?;
        let pipe = child.stdin.take();
        let stdin = match input {
            Input::Nothing => None,
            Input::Bytes(bytes) => {
                let mut pipe = pipe
                    .ok_or_else(|| Skip("habilis-network-stream has no stdin pipe".to_owned()))?;
                std::thread::spawn(move || {
                    let _ = pipe.write_all(&bytes);
                });
                None
            }
            Input::Open => Some(
                pipe.ok_or_else(|| Skip("habilis-network-stream has no stdin pipe".to_owned()))?,
            ),
        };
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| Skip("habilis-network-stream has no stdout pipe".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Skip("habilis-network-stream has no stderr pipe".to_owned()))?;
        let (bytes_tx, bytes) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            while let Ok(len) = stdout.read(&mut buf)
                && len > 0
                && bytes_tx.send(buf[..len].to_vec()).is_ok()
            {}
        });
        let (stderr_tx, stderr_lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if stderr_tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            stdout: bytes,
            stderr_lines,
            received: Vec::new(),
            seen: Vec::new(),
            engine_log: String::new(),
        })
    }

    /// Append to an [`Input::Open`] stdin. A few lines fit the pipe's buffer,
    /// so this does not block on a producer that has not started reading.
    fn append(&mut self, bytes: &[u8]) -> Result<(), String> {
        let stdin = self.stdin.as_mut().ok_or("stdin is not open")?;
        stdin
            .write_all(bytes)
            .and_then(|()| stdin.flush())
            .map_err(|error| format!("writing to habilis-network-stream: {error}"))
    }

    /// End an [`Input::Open`] stdin: the producer's EOF.
    fn end_input(&mut self) {
        self.stdin = None;
    }

    fn pump(&mut self) {
        while let Ok(chunk) = self.stdout.try_recv() {
            self.received.extend_from_slice(&chunk);
        }
        while let Ok(line) = self.stderr_lines.try_recv() {
            if let Ok(value) = serde_json::from_str(&line) {
                self.seen.push(value);
            } else {
                self.engine_log.push_str(&line);
                self.engine_log.push('\n');
            }
        }
    }

    fn saw_kind(&mut self, kind: &str) -> Option<serde_json::Value> {
        self.pump();
        self.seen
            .iter()
            .find(|value| value.get("kind").and_then(serde_json::Value::as_str) == Some(kind))
            .cloned()
    }

    fn received(&mut self) -> &[u8] {
        self.pump();
        &self.received
    }

    fn exit_code(&mut self) -> Option<i32> {
        self.child
            .try_wait()
            .ok()
            .flatten()
            .and_then(|status| status.code())
    }

    fn transcript(&mut self) -> String {
        self.pump();
        let lines: Vec<String> = self.seen.iter().map(ToString::to_string).collect();
        format!(
            "\u{2500}\u{2500} cli robot lines \u{2500}\u{2500}\n{}\n\u{2500}\u{2500} cli stdout ({} bytes) \u{2500}\u{2500}\n{}\n\u{2500}\u{2500} cli engine log \u{2500}\u{2500}\n{}",
            lines.join("\n"),
            self.received.len(),
            String::from_utf8_lossy(&self.received),
            self.engine_log
        )
    }
}

// ── driving the page ────────────────────────────────────────────────────

fn page_text(page: &Page, id: &str) -> String {
    page.evaluate(&format!(
        "(document.getElementById('{id}')||{{}}).textContent||''"
    ))
}

fn dataset(page: &Page, selector: &str, key: &str) -> String {
    page.evaluate(&format!(
        "((document.querySelector('{selector}')||{{}}).dataset||{{}}).{key}||''"
    ))
}

fn view_selector(own: bool) -> String {
    format!("#streams pre[data-self=\"{own}\"]")
}

fn view_text(page: &Page, own: bool) -> String {
    page.evaluate(&format!(
        "(document.querySelector('{}')||{{}}).textContent||''",
        view_selector(own)
    ))
}

fn view_complete(page: &Page, own: bool) -> bool {
    dataset(page, &view_selector(own), "complete") == "true"
}

/// Open `url` in a fresh tab and wait for its stream end to open. A reader's
/// end opens only after the lookup, the JSEP round and the direct-path wait,
/// so it gets the attach budget; a producer's needs only its bind.
fn open_page(url: &str, role: &str, browser: &str) -> Result<Page, String> {
    let page = launch_page(browser).map_err(|Skip(reason)| reason)?;
    page.navigate_watching_console(url, CONSOLE_WINDOW);
    let budget = if role == "reader" {
        ATTACH_TIMEOUT
    } else {
        Duration::from_mins(1)
    };
    let ready = wait_for(budget, Duration::from_millis(500), || {
        (dataset(&page, "#ready", "role") == role).then_some(())
    });
    if ready.is_none() {
        return Err(format!(
            "the page never opened as a {role}: {}",
            page_text(&page, "failed")
        ));
    }
    Ok(page)
}

/// A payload wider than the CLI's stdin chunk, with a four-byte character
/// placed to straddle the first chunk boundary, and no trailing newline: the
/// shape that catches a per-chunk decode or a lost last chunk.
fn payload() -> String {
    let mut text = String::new();
    let mut line = 0;
    while text.len() < CLI_CHUNK - 2 {
        let _ = writeln!(
            text,
            "line {line:05} the quick brown fox jumps over the lazy dog"
        );
        line += 1;
    }
    text.truncate(CLI_CHUNK - 2);
    text.push('\u{1F30A}');
    while text.len() < CLI_CHUNK * 2 + 100 {
        let _ = writeln!(
            text,
            "line {line:05} pack my box with five dozen liquor jugs"
        );
        line += 1;
    }
    text.push_str("the end");
    text
}

// ── the scenarios ───────────────────────────────────────────────────────

pub(super) fn run(args: &Args) -> TaskOutcome {
    if args.list {
        output::detail(
            "two scenarios: `habilis-network-stream` \u{2192} the page, the page \u{2192} `habilis-network-stream`",
        );
        return Ok(());
    }
    build::ensure_bun("the stream suite serves its page with bun")?;
    build::build_browser_peer()?;
    output::status("Building", "habilis-network-stream");
    let cli_binary = build::build_binary("habilis-network-stream-cli", "habilis-network-stream")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no tokio runtime: {error}"))?;
    let (relay_url, _relay_server) = runtime
        .block_on(habilis_network::net::test_relay::spawn_plain())
        .map_err(|error| format!("no local relay: {error:#}"))?;
    let server = BunServer::serve(
        &repo_root().join("packages/habilis-network-stream-web"),
        "serve.ts",
        "the stream page",
    )
    .map_err(|Skip(reason)| reason)?;
    output::status(
        "Serving",
        &format!("relay {relay_url} · stream {}", server.url),
    );
    let web_url = format!("{}/", server.url);

    output::status("Running", "habilis-network-stream \u{2192} the stream page");
    cli_to_page(
        &cli_binary,
        relay_url.as_str(),
        &web_url,
        args.page_browser(),
    )?;
    output::status(
        "ok",
        "habilis-network-stream \u{2192} the stream page  byte-exact, ended, exited clean",
    );

    output::status("Running", "the stream page \u{2192} habilis-network-stream");
    page_to_cli(
        &cli_binary,
        relay_url.as_str(),
        &web_url,
        args.page_browser(),
    )?;
    output::status(
        "ok",
        "the stream page \u{2192} habilis-network-stream  byte-exact, ended, exited clean",
    );

    output::status("Running", "a growing input, as `tail -f` feeds it");
    tail_to_page(
        &cli_binary,
        relay_url.as_str(),
        &web_url,
        args.page_browser(),
    )?;
    output::status(
        "ok",
        "a growing input, as `tail -f` feeds it  both lines, in order, then the end",
    );

    output::status("Running", "the stream page closes with no reader");
    unread_close(
        &cli_binary,
        relay_url.as_str(),
        &web_url,
        args.page_browser(),
    )?;
    output::status(
        "ok",
        "the stream page closes with no reader  settled, hash refused",
    );
    Ok(())
}

/// The CLI produces from stdin; the page reads at the URL the CLI printed.
fn cli_to_page(
    binary: &Path,
    relay_url: &str,
    web_url: &str,
    browser: &str,
) -> Result<(), Failure> {
    let sent = payload();
    // Stdin is written and closed *now*, before any reader exists: the way a
    // person pipes. The CLI, not the caller, waits for the reader.
    let mut cli = Cli::spawn(
        binary,
        &[
            "--lookup",
            "relay",
            "--relay-url",
            relay_url,
            "--web-url",
            web_url,
        ],
        Input::Bytes(sent.clone().into_bytes()),
    )
    .map_err(|Skip(reason)| reason)?;

    let Some(ready) = wait_for(Duration::from_mins(1), Duration::from_millis(250), || {
        cli.saw_kind("ready")
    }) else {
        return fail(&mut cli, None, "the cli never reported its stream");
    };
    let hash = ready
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let url = ready
        .get("url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if hash.is_empty() || url != format!("{web_url}#{hash}") {
        return fail(&mut cli, None, &format!("unexpected ready line {ready}"));
    }

    // The fragment stays exactly as printed; the log filter rides the query.
    let page = match open_page(
        &format!("{web_url}?log=habilis_network=info#{hash}"),
        "reader",
        browser,
    ) {
        Ok(page) => page,
        Err(reason) => return fail(&mut cli, None, &reason),
    };

    let landed = wait_for(ATTACH_TIMEOUT, Duration::from_millis(500), || {
        (view_text(&page, false).len() >= sent.len()).then_some(())
    });
    let got = view_text(&page, false);
    if landed.is_none() || got != sent {
        let reason = format!(
            "the payload did not land whole on the page ({} of {} bytes)",
            got.len(),
            sent.len()
        );
        return fail(&mut cli, Some(&page), &reason);
    }
    let ended = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(250), || {
        view_complete(&page, false).then_some(())
    });
    if ended.is_none() {
        return fail(
            &mut cli,
            Some(&page),
            "the page never saw the end of stream",
        );
    }

    // `stream.read` on the tab: the payload as one item, then the end.
    call_page(
        &page,
        "stream",
        "read({ waitMs: 0 }).then(r => { window.__read = JSON.stringify(r) })",
    )
    .or_else(|error| fail(&mut cli, Some(&page), &error))?;
    let read = page.evaluate("window.__read||''");
    let parsed: serde_json::Value = serde_json::from_str(&read)
        .map_err(|error| format!("stream.read returned no JSON ({error}): {read}"))?;
    let items = parsed
        .get("items")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let text = items
        .first()
        .and_then(|item| item.get("text"))
        .and_then(serde_json::Value::as_str);
    let eof = items
        .last()
        .and_then(|item| item.get("eof"))
        .and_then(serde_json::Value::as_bool);
    if items.len() != 2 || text != Some(sent.as_str()) || eof != Some(true) {
        let reason = format!(
            "stream.read did not return the payload then the end ({} items, first {} bytes)",
            items.len(),
            text.map_or(0, str::len)
        );
        return fail(&mut cli, Some(&page), &reason);
    }

    let exited = wait_for(EXIT_TIMEOUT, Duration::from_millis(250), || cli.exit_code());
    if exited != Some(0) {
        let reason = format!("the cli did not exit 0 after the stream ended (exit {exited:?})");
        return fail(&mut cli, Some(&page), &reason);
    }
    Ok(())
}

/// The page produces; the CLI reads the hash the page shows to stdout.
fn page_to_cli(
    binary: &Path,
    relay_url: &str,
    web_url: &str,
    browser: &str,
) -> Result<(), Failure> {
    let page = open_page(
        &format!(
            "{web_url}?relay={}&log=habilis_network=info",
            urlencode(relay_url)
        ),
        "producer",
        browser,
    )?;
    let hash = dataset(&page, "#share", "hash");
    if hash.is_empty() {
        return Err(format!("the page showed no hash: {}", page_text(&page, "share")).into());
    }

    let mut cli =
        Cli::spawn(binary, &[hash.as_str()], Input::Nothing).map_err(|Skip(reason)| reason)?;
    let attached = wait_for(ATTACH_TIMEOUT, Duration::from_millis(500), || {
        (dataset(&page, "#share", "attached") == "true").then_some(())
    });
    if attached.is_none() {
        return fail(
            &mut cli,
            Some(&page),
            "the cli never attached to the page's stream",
        );
    }

    // Through the same runtime the WebMCP tools call. The literal is JSON, so
    // it is a valid JS string.
    let sent = payload();
    let literal = serde_json::to_string(&sent)?;
    call_page(&page, "stream", &format!("write({literal})"))
        .or_else(|error| fail(&mut cli, Some(&page), &error))?;
    call_page(&page, "stream", "close()").or_else(|error| fail(&mut cli, Some(&page), &error))?;

    let landed = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(250), || {
        (cli.received().len() >= sent.len()).then_some(())
    });
    if landed.is_none() || cli.received() != sent.as_bytes() {
        let reason = format!(
            "the page's bytes did not land whole on stdout ({} of {} bytes)",
            cli.received().len(),
            sent.len()
        );
        return fail(&mut cli, Some(&page), &reason);
    }
    let exited = wait_for(EXIT_TIMEOUT, Duration::from_millis(250), || cli.exit_code());
    if exited != Some(0) {
        let reason = format!("the cli did not exit 0 at the end of stream (exit {exited:?})");
        return fail(&mut cli, Some(&page), &reason);
    }
    // The tab shows what it wrote, whoever asked for it.
    let shown = wait_for(Duration::from_secs(5), Duration::from_millis(250), || {
        view_complete(&page, true).then_some(())
    });
    if shown.is_none() || view_text(&page, true) != sent {
        return fail(
            &mut cli,
            Some(&page),
            "the tab did not show its own write, ended",
        );
    }
    Ok(())
}

/// The shape of `examples/tail`: the producer's input grows after the reader
/// attaches, and what is appended then reaches the reader too.
fn tail_to_page(
    binary: &Path,
    relay_url: &str,
    web_url: &str,
    browser: &str,
) -> Result<(), Failure> {
    let mut cli = Cli::spawn(
        binary,
        &[
            "--lookup",
            "relay",
            "--relay-url",
            relay_url,
            "--web-url",
            web_url,
        ],
        Input::Open,
    )
    .map_err(|Skip(reason)| reason)?;
    cli.append(b"before the reader\n")?;
    let Some(ready) = wait_for(Duration::from_mins(1), Duration::from_millis(250), || {
        cli.saw_kind("ready")
    }) else {
        return fail(&mut cli, None, "the cli never reported its stream");
    };
    let hash = ready
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let page = match open_page(
        &format!("{web_url}?log=habilis_network=info#{hash}"),
        "reader",
        browser,
    ) {
        Ok(page) => page,
        Err(reason) => return fail(&mut cli, None, &reason),
    };

    let first = "before the reader\n";
    if wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(250), || {
        (view_text(&page, false) == first).then_some(())
    })
    .is_none()
    {
        return fail(&mut cli, Some(&page), "the first line never arrived");
    }
    cli.append(b"after the reader\n")?;
    let both = "before the reader\nafter the reader\n";
    if wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(250), || {
        (view_text(&page, false) == both).then_some(())
    })
    .is_none()
    {
        let reason = format!(
            "the appended line never arrived (page holds {:?})",
            view_text(&page, false)
        );
        return fail(&mut cli, Some(&page), &reason);
    }
    if view_complete(&page, false) {
        return fail(
            &mut cli,
            Some(&page),
            "the stream ended while its input was open",
        );
    }

    cli.end_input();
    let ended = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(250), || {
        view_complete(&page, false).then_some(())
    });
    if ended.is_none() {
        return fail(
            &mut cli,
            Some(&page),
            "the page never saw the end of stream",
        );
    }
    let exited = wait_for(EXIT_TIMEOUT, Duration::from_millis(250), || cli.exit_code());
    if exited != Some(0) {
        let reason = format!("the cli did not exit 0 at the end of input (exit {exited:?})");
        return fail(&mut cli, Some(&page), &reason);
    }
    Ok(())
}

/// A producer page closes before any reader arrives: the close settles, and
/// the stream is abandoned, so a reader that comes later is refused.
fn unread_close(
    binary: &Path,
    relay_url: &str,
    web_url: &str,
    browser: &str,
) -> Result<(), Failure> {
    let page = open_page(
        &format!(
            "{web_url}?relay={}&log=habilis_network=info",
            urlencode(relay_url)
        ),
        "producer",
        browser,
    )?;
    let hash = dataset(&page, "#share", "hash");
    call_page(&page, "stream", "close()")?;

    let mut cli =
        Cli::spawn(binary, &[hash.as_str()], Input::Nothing).map_err(|Skip(reason)| reason)?;
    let exited = wait_for(ATTACH_TIMEOUT, Duration::from_millis(250), || {
        cli.exit_code()
    });
    if exited.is_none_or(|code| code == 0) {
        let reason = format!("a reader of an abandoned stream did not fail (exit {exited:?})");
        return fail(&mut cli, Some(&page), &reason);
    }
    if !cli.transcript().contains("no open stream has this hash") {
        return fail(
            &mut cli,
            Some(&page),
            "the reader failed, but not as refused",
        );
    }
    Ok(())
}

/// Dump both surfaces to a file and fail the suite.
fn fail<T>(cli: &mut Cli, page: Option<&Page>, reason: &str) -> Result<T, Failure> {
    // The page first, the console last among them: the console blocks until
    // its window closes, and the native transcript is read after it so both
    // logs cover the same stretch of time.
    let mut browser = String::new();
    if let Some(page) = page {
        for id in ["status", "webmcp", "share", "streams"] {
            let _ = write!(
                browser,
                "\n\u{2500}\u{2500} browser {id} \u{2500}\u{2500}\n{}\n",
                page_text(page, id)
            );
        }
        let _ = write!(
            browser,
            "\n\u{2500}\u{2500} browser console \u{2500}\u{2500}\n{}\n",
            page.console()
        );
    }
    let dump = cli.transcript() + &browser;
    let path = repo_root().join("target/stream-e2e.log");
    let _ = std::fs::write(&path, dump);
    output::detail(&format!("full log: {}", path.display()));
    Err(format!("stream e2e failed: {reason}").into())
}
