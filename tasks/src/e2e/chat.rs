//! `cargo task e2e --suite chat` — the chat example end to end: the real
//! native terminal chat (`--robot`) and the real browser chat page, meeting
//! on one lookup-only topic over a local relay.
//!
//! The mesh suite proves the engine cell by cell; this proves the
//! *application* a person actually runs, through its own surfaces — lines on
//! stdin/stdout on one side, the DOM on the other. One scenario, both
//! payload directions, broadcast and directed.

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::TaskOutcome;
use crate::util::output;
use crate::util::page::rand_token;
use crate::util::{repo_root, wait_for};

use super::mesh::{BunServer, launch_page};
use super::page::{Page, call_page, urlencode};
use super::{Args, Skip, build};

/// Beacon claim + JSEP + graft on a cold pair; generous like the mesh
/// suite's link budget, for the same reason.
const LINK_TIMEOUT: Duration = Duration::from_secs(150);
/// One payload hop on a linked pair.
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the tab's console is recorded: past the page's one-minute open
/// and the link wait, so a failure at either still has the whole console.
const CONSOLE_WINDOW: Duration =
    Duration::from_secs(60 + LINK_TIMEOUT.as_secs() + PAYLOAD_TIMEOUT.as_secs());

// ── the terminal half ───────────────────────────────────────────────────

/// The chat example as the suite drives it: `--robot` stdout collected as
/// JSON values, stderr collected as the engine log (the stagger reads
/// "beacon role active" from it, exactly like the mesh suite's log buffer).
struct Robot {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    stderr_lines: mpsc::Receiver<String>,
    seen: Vec<serde_json::Value>,
    engine_log: String,
}

impl Drop for Robot {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Robot {
    fn spawn(binary: &PathBuf, topic: &str, relay_url: &str) -> Result<Self, Skip> {
        let mut child = Command::new(binary)
            .args([
                "--topic",
                topic,
                "--nick",
                "terminal",
                "--relay-url",
                relay_url,
                "--robot",
            ])
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "fofoca=info".to_owned()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Skip(format!("could not start the chat example: {error}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Skip("the chat example has no stdin pipe".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Skip("the chat example has no stdout pipe".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Skip("the chat example has no stderr pipe".to_owned()))?;
        let (lines_tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if lines_tx.send(line).is_err() {
                    break;
                }
            }
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
            lines,
            stderr_lines,
            seen: Vec::new(),
            engine_log: String::new(),
        })
    }

    fn pump(&mut self) {
        while let Ok(line) = self.lines.try_recv() {
            if let Ok(value) = serde_json::from_str(&line) {
                self.seen.push(value);
            }
        }
        while let Ok(line) = self.stderr_lines.try_recv() {
            self.engine_log.push_str(&line);
            self.engine_log.push('\n');
        }
    }

    fn saw(&mut self, pred: impl Fn(&serde_json::Value) -> bool) -> bool {
        self.pump();
        self.seen.iter().any(pred)
    }

    fn saw_msg(&mut self, text: &str, directed: bool) -> bool {
        self.saw(|value| {
            value.get("kind").and_then(serde_json::Value::as_str) == Some("msg")
                && value.get("text").and_then(serde_json::Value::as_str) == Some(text)
                && value.get("directed").and_then(serde_json::Value::as_bool) == Some(directed)
        })
    }

    /// A `/peers` reply — the one non-event line the robot prints — showing
    /// `nick` reachable over the unicast lane.
    fn saw_peer_unicast(&mut self, nick: &str) -> bool {
        self.saw(|value| {
            value
                .get("peers")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|peers| {
                    peers.iter().any(|peer| {
                        peer.get("nickname").and_then(serde_json::Value::as_str) == Some(nick)
                            && peer.get("transport").and_then(serde_json::Value::as_str)
                                == Some("unicast")
                    })
                })
        })
    }

    fn engine_log_contains(&mut self, needle: &str) -> bool {
        self.pump();
        self.engine_log.contains(needle)
    }

    fn send_line(&mut self, line: &str) -> Result<(), String> {
        writeln!(self.stdin, "{line}").map_err(|error| format!("robot stdin write failed: {error}"))
    }

    fn transcript(&mut self) -> String {
        self.pump();
        let lines: Vec<String> = self.seen.iter().map(ToString::to_string).collect();
        format!(
            "\u{2500}\u{2500} robot lines \u{2500}\u{2500}\n{}\n\u{2500}\u{2500} robot engine log \u{2500}\u{2500}\n{}",
            lines.join("\n"),
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

// ── the scenario ────────────────────────────────────────────────────────

pub(super) fn run(args: &Args) -> TaskOutcome {
    if args.list {
        output::detail("one scenario: terminal \u{2194} browser chat on a lookup-only topic");
        return Ok(());
    }
    build::ensure_bun("the chat suite serves its page with bun")?;
    build::build_browser_peer()?;
    output::status("Building", "the native chat example");
    let chat_binary = build::build_binary("chat", "chat")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no tokio runtime: {error}"))?;
    let (relay_url, _relay_server) = runtime
        .block_on(fofoca::net::test_relay::spawn_plain())
        .map_err(|error| format!("no local relay: {error:#}"))?;
    let server = BunServer::serve(
        &repo_root().join("examples/chat/web"),
        "serve.ts",
        "the chat page",
    )
    .map_err(|Skip(reason)| reason)?;
    output::status(
        "Serving",
        &format!("relay {relay_url} · chat {}", server.url),
    );

    let topic = format!("chat-e2e-{}", rand_token());
    let mut robot =
        Robot::spawn(&chat_binary, &topic, relay_url.as_str()).map_err(|Skip(reason)| reason)?;

    // The stagger the mesh suite proved out: the terminal claims the beacon
    // before the tab even opens, so the pair never races the claim.
    if wait_for(Duration::from_mins(1), Duration::from_millis(500), || {
        robot
            .engine_log_contains("beacon role active")
            .then_some(())
    })
    .is_none()
    {
        return fail(&mut robot, None, "the terminal never claimed the beacon");
    }

    let page = launch_page(args.page_browser()).map_err(|Skip(reason)| reason)?;
    page.navigate_watching_console(
        &format!(
            "{}/?topic={topic}&nick=browser&relay={}&log=fofoca=info",
            server.url,
            urlencode(relay_url.as_str()),
        ),
        CONSOLE_WINDOW,
    );
    output::status("Running", "terminal \u{2194} browser chat");

    if wait_for(Duration::from_mins(1), Duration::from_millis(500), || {
        (!page_text(&page, "ready").is_empty()).then_some(())
    })
    .is_none()
    {
        let reason = format!(
            "the page never opened its mesh: {}",
            page_text(&page, "failed")
        );
        return fail(&mut robot, Some(&page), &reason);
    }

    // Rostered both ways, and the pair link proven from both surfaces: the
    // page's roster shows the terminal on the unicast lane, and the
    // terminal's `/peers` reply says the same of the browser.
    let rostered = wait_for(LINK_TIMEOUT, Duration::from_secs(1), || {
        let _ = robot.send_line("/peers");
        (page_text(&page, "peers").contains("\"unicast\"") && robot.saw_peer_unicast("browser"))
            .then_some(())
    });
    if rostered.is_none() {
        let reason = format!(
            "the pair never linked for payload (page peers: {})",
            page_text(&page, "peers")
        );
        return fail(&mut robot, Some(&page), &reason);
    }

    // Broadcast both ways: send once per side, then wait on receipt alone.
    // Re-sending inside the receipt poll looked like a retry but was not —
    // the page call itself blocks up to the payload budget, so one iteration
    // consumed the window while duplicate messages piled into the mesh.
    robot.send_line("hello-from-terminal")?;
    if let Err(error) = call_page(&page, "chat", "send('hello-from-web')") {
        return fail(&mut robot, Some(&page), &error);
    }
    let broadcast = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(500), || {
        (page_text(&page, "messages").contains("hello-from-terminal")
            && robot.saw_msg("hello-from-web", false))
        .then_some(())
    });
    if broadcast.is_none() {
        return fail(
            &mut robot,
            Some(&page),
            "a broadcast did not arrive on both sides",
        );
    }

    // Directed both ways, same shape.
    robot.send_line("/msg browser direct-from-terminal")?;
    if let Err(error) = call_page(&page, "chat", "send('/msg terminal direct-from-web')") {
        return fail(&mut robot, Some(&page), &error);
    }
    let directed = wait_for(PAYLOAD_TIMEOUT, Duration::from_millis(500), || {
        (page_text(&page, "messages").contains("direct-from-terminal")
            && robot.saw_msg("direct-from-web", true))
        .then_some(())
    });
    if directed.is_none() {
        return fail(
            &mut robot,
            Some(&page),
            "a directed message did not arrive on both sides",
        );
    }

    let _ = call_page(&page, "chat", "close()");
    let _ = robot.send_line("/quit");
    output::status(
        "ok",
        "terminal \u{2194} browser chat  linked, chatted both ways",
    );
    Ok(())
}

/// Dump both surfaces to a file and fail the suite — twenty lines of tail
/// answered nothing, twice, in the mesh suite's bring-up.
fn fail(robot: &mut Robot, page: Option<&Page>, reason: &str) -> TaskOutcome {
    // The page first, the console last among them: the console blocks until
    // its window closes, and the native transcript is read after it so both
    // logs cover the same stretch of time.
    let mut browser = String::new();
    if let Some(page) = page {
        for id in ["status", "messages", "peers", "events"] {
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
    let dump = robot.transcript() + &browser;
    let path = repo_root().join("target/chat-e2e.log");
    let _ = std::fs::write(&path, dump);
    output::detail(&format!("full log: {}", path.display()));
    Err(format!("chat e2e failed: {reason}").into())
}
