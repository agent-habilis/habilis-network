//! The CDP backend: Chrome for Testing, launched and driven by this runner.
//!
//! No helper tool sits between the runner and Chrome: [`Browser::launch`]
//! starts Chrome with `--remote-debugging-port=0`, reads the port Chrome
//! chose from `DevToolsActivePort` in its profile, and keeps one `WebSocket`
//! to the page for the whole run. One session means console events are
//! collected as they happen, and the Chrome flags are ours to choose. The
//! binary is Chrome for Testing, downloaded into `target/` on first use
//! ([`chrome_for_testing`]), or the one `CHROME_FOR_TESTING` names.

use std::cell::{Cell, RefCell};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use super::{Harvest, Skip, server};

/// How long a single CDP call may take before the runner gives up on it.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// A launched headless Chrome, killed when it goes out of scope.
#[derive(Debug)]
pub(super) struct Browser {
    chrome: Child,
    profile: PathBuf,
    port: u16,
    page: RefCell<WebSocket<MaybeTlsStream<TcpStream>>>,
    next_id: Cell<u64>,
    /// Console calls, exceptions and log entries, in arrival order. Between
    /// calls they wait in the socket's receive buffer; a run that went minutes
    /// without a call on a console-heavy page would stall Chrome's sends, not
    /// lose events.
    events: RefCell<Vec<serde_json::Value>>,
    /// Why the page socket closed, once it has: a read that failed for any
    /// reason but a timeout. A dead socket otherwise reads as a page that
    /// never published.
    dead: RefCell<Option<String>>,
}

impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.page.get_mut().close(None);
        let _ = self.chrome.kill();
        let _ = self.chrome.wait();
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// The Chrome for Testing binary: `CHROME_FOR_TESTING` if set, else the stable
/// build of the day it was first needed, downloaded into
/// `target/chrome-for-testing`. Delete that folder to take a newer one.
///
/// # Errors
/// A [`Skip`] naming the step that failed: the version lookup, the download
/// or the unpack.
pub(super) fn chrome_for_testing() -> Result<PathBuf, Skip> {
    if let Some(binary) = std::env::var_os("CHROME_FOR_TESTING") {
        return Ok(PathBuf::from(binary));
    }
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "mac-arm64",
        ("macos", _) => "mac-x64",
        ("linux", _) => "linux64",
        (os, arch) => return Err(Skip(format!("no Chrome for Testing build for {os}/{arch}"))),
    };
    let root = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/chrome-for-testing"
    ));
    let binary = root.join(match platform {
        "linux64" => "chrome-linux64/chrome".to_owned(),
        mac => format!(
            "chrome-{mac}/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
        ),
    });
    if binary.exists() {
        return Ok(binary);
    }
    let index = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json",
        ])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice::<serde_json::Value>(&output.stdout).ok())
        .ok_or_else(|| Skip("could not look up Chrome for Testing".to_owned()))?;
    let url = index
        .pointer("/channels/Stable/downloads/chrome")
        .and_then(serde_json::Value::as_array)
        .and_then(|builds| {
            builds.iter().find(|build| {
                build.get("platform").and_then(serde_json::Value::as_str) == Some(platform)
            })
        })
        .and_then(|build| build.get("url").and_then(serde_json::Value::as_str))
        .ok_or_else(|| Skip(format!("no Chrome for Testing download for {platform}")))?;
    std::fs::create_dir_all(&root)
        .map_err(|error| Skip(format!("could not create {}: {error}", root.display())))?;
    // Per-process names, then one rename into place: two runners on one
    // checkout can download at once, and the loser of the rename finds the
    // winner's copy.
    let zip = root.join(format!("chrome.{}.zip", std::process::id()));
    let unpack = root.join(format!(".unpack-{}", std::process::id()));
    let fetched = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--output",
        ])
        .arg(&zip)
        .arg(url)
        .status()
        .is_ok_and(|status| status.success());
    let unpacked = fetched
        && Command::new("unzip")
            .args(["-q", "-o"])
            .arg(&zip)
            .arg("-d")
            .arg(&unpack)
            .status()
            .is_ok_and(|status| status.success());
    if unpacked {
        let folder = format!("chrome-{platform}");
        // A folder without the binary is stale, not a winner: a CI cache step
        // that prunes `target/` restores the folder with the binary gone, and
        // the rename below cannot replace a folder that is not empty.
        if !binary.exists() {
            let _ = std::fs::remove_dir_all(root.join(&folder));
        }
        let _ = std::fs::rename(unpack.join(&folder), root.join(&folder));
    }
    let _ = std::fs::remove_file(&zip);
    let _ = std::fs::remove_dir_all(&unpack);
    if !binary.exists() {
        return Err(Skip(format!(
            "could not download Chrome for Testing from {url}"
        )));
    }
    if let Some(version) = index
        .pointer("/channels/Stable/version")
        .and_then(serde_json::Value::as_str)
    {
        let _ = std::fs::write(root.join("VERSION"), version);
    }
    Ok(binary)
}

impl Browser {
    pub(super) fn launch() -> Result<Self, Skip> {
        let binary = chrome_for_testing()?;
        let profile = std::env::temp_dir().join(format!(
            "fofoca-cdp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&profile)
            .map_err(|error| Skip(format!("could not create the Chrome profile: {error}")))?;
        let mut chrome = Command::new(&binary);
        // A Linux CI runner cannot grant the user-namespace sandbox Chrome
        // wants, as the `chrome-ci` driver's arguments note.
        if cfg!(target_os = "linux") {
            chrome.arg("--no-sandbox");
        }
        let mut chrome = chrome
            .args([
                "--headless=new",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
                // Never ask the OS keychain for Chrome's storage key: on macOS
                // that is a password dialog in front of the user mid-run.
                "--use-mock-keychain",
                "--password-store=basic",
                // Chrome hides its host IP behind a `.local` name that it
                // resolves with its own multicast client, and multicast from an
                // agent session fails here (`EHOSTUNREACH`). Two peer
                // connections in one tab, such as a tab's member linking to
                // the rendezvous the same tab hosts, then never connect.
                "--disable-features=WebRtcHideLocalIpsWithMdns",
            ])
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg("about:blank")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Skip(format!("could not start {}: {error}", binary.display())))?;
        let connected = devtools_port(&profile, &mut chrome).and_then(|port| {
            let (page, _) = tungstenite::connect(page_socket(port)?)
                .map_err(|error| Skip(format!("could not open the page's CDP socket: {error}")))?;
            if let MaybeTlsStream::Plain(stream) = page.get_ref() {
                let _ = stream.set_read_timeout(Some(CALL_TIMEOUT));
            }
            Ok((port, page))
        });
        let (port, page) = match connected {
            Ok(connected) => connected,
            Err(skip) => {
                let _ = chrome.kill();
                let _ = chrome.wait();
                let _ = std::fs::remove_dir_all(&profile);
                return Err(skip);
            }
        };
        let browser = Self {
            chrome,
            profile,
            port,
            page: RefCell::new(page),
            next_id: Cell::new(1),
            events: RefCell::new(Vec::new()),
            dead: RefCell::new(None),
        };
        browser.call("Runtime.enable", &serde_json::json!({}));
        browser.call("Log.enable", &serde_json::json!({}));
        Ok(browser)
    }

    /// Open `url` in the launched window.
    #[cfg(feature = "mesh")]
    pub(super) fn navigate(&self, url: &str) {
        self.call("Page.navigate", &serde_json::json!({ "url": url }));
    }

    /// Open `url`. The console is recorded from launch on, over the one
    /// session, so `window` is unused here; both backends take the same call.
    #[cfg(feature = "mesh")]
    pub(super) fn navigate_watching_console(&self, url: &str, _window: Duration) {
        self.navigate(url);
    }

    /// The console lines recorded so far.
    #[cfg(feature = "mesh")]
    pub(super) fn console(&self) -> String {
        self.drain();
        let lines = console_lines(&serde_json::Value::Array(self.events.borrow().clone()));
        match self.dead.borrow().as_deref() {
            Some(why) => format!("{lines}\n(Chrome's CDP socket closed: {why})"),
            None => lines,
        }
    }

    /// One CDP call on the page session. Events that arrive before its reply
    /// are kept for [`Browser::console`].
    fn call(&self, method: &str, params: &serde_json::Value) -> Option<serde_json::Value> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let request = serde_json::json!({ "id": id, "method": method, "params": params });
        if self.dead.borrow().is_some() {
            return None;
        }
        let mut page = self.page.borrow_mut();
        if let Err(error) = page.send(Message::text(request.to_string())) {
            self.note_dead(&error);
            return None;
        }
        let deadline = Instant::now() + CALL_TIMEOUT;
        while Instant::now() < deadline {
            let message = match page.read() {
                Ok(message) => message,
                Err(error) => {
                    self.note_dead(&error);
                    return None;
                }
            };
            let Message::Text(text) = message else {
                continue;
            };
            let Ok(reply) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            if reply.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                return reply.get("result").cloned();
            }
            self.keep_event(reply);
        }
        None
    }

    /// Read what is already waiting on the socket, keeping its events.
    #[cfg(feature = "mesh")]
    fn drain(&self) {
        let mut page = self.page.borrow_mut();
        if let MaybeTlsStream::Plain(stream) = page.get_ref() {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        }
        loop {
            match page.read() {
                Ok(Message::Text(text)) => {
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&text) {
                        self.keep_event(event);
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    self.note_dead(&error);
                    break;
                }
            }
        }
        if let MaybeTlsStream::Plain(stream) = page.get_ref() {
            let _ = stream.set_read_timeout(Some(CALL_TIMEOUT));
        }
    }

    /// Record a read or write error unless it is a timeout.
    fn note_dead(&self, error: &tungstenite::Error) {
        let timed_out = matches!(
            error,
            tungstenite::Error::Io(io)
                if matches!(io.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
        );
        if !timed_out && self.dead.borrow().is_none() {
            *self.dead.borrow_mut() = Some(error.to_string());
        }
    }

    fn keep_event(&self, event: serde_json::Value) {
        let kept = matches!(
            event.get("method").and_then(serde_json::Value::as_str),
            Some("Runtime.consoleAPICalled" | "Runtime.exceptionThrown" | "Log.entryAdded")
        );
        if kept {
            self.events.borrow_mut().push(event);
        }
    }

    /// `Runtime.evaluate`, flattened to the string the expression produced.
    pub(super) fn evaluate(&self, expression: &str) -> String {
        let params = serde_json::json!({ "expression": expression, "returnByValue": true });
        self.call("Runtime.evaluate", &params)
            .and_then(|reply| reply.pointer("/result/value").map(super::json_to_string))
            .unwrap_or_default()
    }

    /// What actually answered, never the name we gave it.
    pub(super) fn version(&self) -> String {
        ureq::get(format!("http://127.0.0.1:{}/json/version", self.port))
            .call()
            .ok()
            .and_then(|mut reply| reply.body_mut().read_json::<serde_json::Value>().ok())
            .and_then(|version| {
                version
                    .get("Browser")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unknown".to_owned())
    }

    /// Wait until `selector` matches, polling the page.
    fn wait_for(&self, selector: &str, timeout: Duration) -> bool {
        let expression = format!(
            "!!document.querySelector({})",
            serde_json::Value::from(selector)
        );
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline && self.dead.borrow().is_none() {
            if self.evaluate(&expression) == "true" {
                return true;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        false
    }
}

/// The port Chrome chose, from the first line of `DevToolsActivePort`.
fn devtools_port(profile: &Path, chrome: &mut Child) -> Result<u16, Skip> {
    // A cold first launch on a loaded machine can take a while.
    let deadline = Instant::now() + Duration::from_mins(1);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = chrome.try_wait() {
            return Err(Skip(format!("Chrome exited at launch: {status}")));
        }
        if let Some(port) = std::fs::read_to_string(profile.join("DevToolsActivePort"))
            .ok()
            .and_then(|file| file.lines().next()?.trim().parse().ok())
        {
            return Ok(port);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(Skip("Chrome never opened its debugging port".to_owned()))
}

/// The page target's `WebSocket` URL.
fn page_socket(port: u16) -> Result<String, Skip> {
    let targets: serde_json::Value = ureq::get(format!("http://127.0.0.1:{port}/json/list"))
        .call()
        .and_then(|mut reply| reply.body_mut().read_json())
        .map_err(|error| Skip(format!("could not list Chrome's targets: {error}")))?;
    targets
        .as_array()
        .into_iter()
        .flatten()
        .find(|target| target.get("type").and_then(serde_json::Value::as_str) == Some("page"))
        .and_then(|target| {
            target
                .get("webSocketDebuggerUrl")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_owned)
        .ok_or_else(|| Skip("Chrome has no page to drive".to_owned()))
}

/// One line per console call. A `%c` in the first argument styles the text
/// and takes the next argument as its CSS, so both are dropped.
#[cfg(feature = "mesh")]
fn console_lines(events: &serde_json::Value) -> String {
    let events = events.as_array().map(Vec::as_slice).unwrap_or_default();
    let lines: Vec<String> = events
        .iter()
        .filter_map(|event| {
            let params = event.get("params")?;
            let at = time_of_day(params);
            let Some(args) = params.get("args").and_then(serde_json::Value::as_array) else {
                return params
                    .pointer("/exceptionDetails/exception/description")
                    .or_else(|| params.pointer("/entry/text"))
                    .map(|text| format!("{at} {}", super::json_to_string(text)));
            };
            let mut texts = args.iter().map(|arg| {
                arg.get("value")
                    .or_else(|| arg.get("description"))
                    .map(super::json_to_string)
                    .unwrap_or_default()
            });
            let first = texts.next().unwrap_or_default();
            let styles = first.matches("%c").count();
            let line = std::iter::once(first.replace("%c", ""))
                .chain(texts.skip(styles))
                .collect::<Vec<_>>()
                .join(" ");
            Some(format!("{at} {line}"))
        })
        .collect();
    lines.join("\n")
}

/// An event's UTC time of day, spelled as the native log spells it, so the
/// two logs line up. CDP stamps console calls in epoch milliseconds, and log
/// entries under `entry`.
#[cfg(feature = "mesh")]
fn time_of_day(params: &serde_json::Value) -> String {
    let millis = params
        .get("timestamp")
        .or_else(|| params.pointer("/entry/timestamp"))
        .and_then(serde_json::Value::as_f64)
        .unwrap_or_default();
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "an epoch-millisecond stamp is positive and far inside u64"
    )]
    let millis = millis as u64;
    let seconds = millis / 1000 % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        millis % 1000
    )
}

/// Run one cell and harvest what the page published.
pub(super) fn run(pressure: u32, timeout: Duration) -> Result<Harvest, Skip> {
    let browser = Browser::launch()?;
    let version = browser.version();

    // The pressure level rides the URL: the page creates the contention itself,
    // and its deadlines have to scale with it or a slow cell reads as a stalled
    // one.
    let url = format!("{}/?pressure={pressure}", server::URL);
    browser.call("Page.navigate", &serde_json::json!({ "url": url }));
    let published = browser.wait_for(super::DONE_SELECTOR, timeout);

    Ok(Harvest {
        table: browser.evaluate(super::TABLE_EXPRESSION),
        failed: super::normalise_failed(&browser.evaluate(super::FAILED_EXPRESSION)),
        version,
        published,
    })
}
