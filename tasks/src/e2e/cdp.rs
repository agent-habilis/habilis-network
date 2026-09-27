//! The CDP backend: `agent-browse`, which is **Chrome-for-Testing only**.
//!
//! Two things were tried first and do not work, recorded so nobody spends the
//! afternoon again:
//!
//! - **Pointing `agent-browse launch` at another Chrome.** There is no such
//!   option, and a `CHROME_PATH` in the environment is ignored — so a cell
//!   labelled `chrome-canary` silently ran Chrome for Testing and reported
//!   Canary. A matrix that mislabels which browser it tested is worse than one
//!   that skips the cell, which is why [`Browser::version`] reads the answer
//!   back out of the browser and the summary prints it beside every result.
//! - **Launching another Chrome with `--remote-debugging-port` and driving it
//!   with `agent-browse cdp --port`.** That refuses a bare port ("can't drive a
//!   `WebSocket`-only Chrome"), and `agent-browse connect` auto-discovers *a*
//!   Chrome rather than the one just launched.
//!
//! So Chrome for Testing gets CDP and every other browser takes the `WebDriver`
//! backend. The pressure axis is created inside the page either way, so no
//! browser is short-changed by which transport drives it.

#[cfg(feature = "mesh")]
use std::cell::RefCell;
use std::path::PathBuf;
use std::process::Command;
#[cfg(feature = "mesh")]
use std::process::{Child, Stdio};
use std::time::Duration;

use super::{Harvest, Skip, server};

/// A launched headless window, quit when it goes out of scope.
#[derive(Debug)]
pub(super) struct Browser {
    folder: PathBuf,
    /// The console watch [`Browser::navigate_watching_console`] started.
    #[cfg(feature = "mesh")]
    console: RefCell<Option<Child>>,
}

impl Drop for Browser {
    fn drop(&mut self) {
        #[cfg(feature = "mesh")]
        if let Some(mut watch) = self.console.get_mut().take() {
            let _ = watch.kill();
            let _ = watch.wait();
        }
        let _ = Command::new("agent-browse")
            .arg("quit")
            .arg(&self.folder)
            .output();
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

impl Browser {
    pub(super) fn launch() -> Result<Self, Skip> {
        let folder = std::env::temp_dir().join(format!(
            "fofoca-matrix-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis())
                .unwrap_or_default()
        ));
        // The folder has to exist first: `agent-browse` keys a session to a real
        // directory and refuses a path it cannot resolve. Getting this wrong
        // produced "could not launch Chrome" and sent its own author looking at
        // Chrome, which is why the failure below carries the tool's own words.
        std::fs::create_dir_all(&folder).map_err(|error| {
            Skip(format!(
                "could not create the browser session folder: {error}"
            ))
        })?;

        let launched = Command::new("agent-browse")
            .args(["launch", "--headless"])
            .arg(&folder)
            .output()
            .map_err(|error| Skip(format!("could not run agent-browse: {error}")))?;

        if !launched.status.success() {
            let said = String::from_utf8_lossy(&launched.stderr);
            let said = said.trim().lines().next_back().unwrap_or_default();
            return Err(Skip(format!(
                "agent-browse could not launch Chrome for Testing{}",
                if said.is_empty() {
                    String::new()
                } else {
                    format!(": {said}")
                }
            )));
        }
        Ok(Self {
            folder,
            #[cfg(feature = "mesh")]
            console: RefCell::new(None),
        })
    }

    /// Open `url` in the launched window.
    #[cfg(feature = "mesh")]
    pub(super) fn navigate(&self, url: &str) {
        self.cdp(
            "Page.navigate",
            &serde_json::json!({ "url": url }).to_string(),
        );
    }

    /// Open `url` and record the page's console for `window`. A CDP init
    /// script would catch the first line too, but it dies with the call that
    /// added it, and each `agent-browse cdp` is its own connection. `watch`
    /// navigates on the connection it listens on, so nothing is missed.
    #[cfg(feature = "mesh")]
    pub(super) fn navigate_watching_console(&self, url: &str, window: Duration) {
        let watch = Command::new("agent-browse")
            .arg("watch")
            .arg("--folder")
            .arg(&self.folder)
            .args(["--group", "console"])
            .arg(window.as_millis().to_string())
            .arg(url)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        match watch {
            Ok(watch) => *self.console.borrow_mut() = Some(watch),
            Err(_) => self.navigate(url),
        }
    }

    /// The console lines the watch recorded. `watch` prints only when its
    /// window closes, and an interrupt discards what it held, so this blocks
    /// until the window is over.
    #[cfg(feature = "mesh")]
    pub(super) fn console(&self) -> String {
        let Some(watch) = self.console.borrow_mut().take() else {
            return String::new();
        };
        watch
            .wait_with_output()
            .ok()
            .and_then(|output| serde_json::from_slice(&output.stdout).ok())
            .map(|events| console_lines(&events))
            .unwrap_or_default()
    }

    /// One raw CDP call, as JSON.
    fn cdp(&self, method: &str, params: &str) -> Option<serde_json::Value> {
        let output = Command::new("agent-browse")
            .arg("cdp")
            .arg("--folder")
            .arg(&self.folder)
            .args([method, params])
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| serde_json::from_slice(&output.stdout).ok())
            .flatten()
    }

    /// `Runtime.evaluate`, flattened to the string the expression produced.
    pub(super) fn evaluate(&self, expression: &str) -> String {
        let params = serde_json::json!({ "expression": expression, "returnByValue": true });
        self.cdp("Runtime.evaluate", &params.to_string())
            .and_then(|reply| reply.pointer("/result/value").map(super::json_to_string))
            .unwrap_or_default()
    }

    /// What actually answered, never the name we gave it.
    pub(super) fn version(&self) -> String {
        self.cdp("Browser.getVersion", "{}")
            .and_then(|reply| {
                reply
                    .get("product")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unknown".to_owned())
    }
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
    browser.cdp(
        "Page.navigate",
        &serde_json::json!({ "url": url }).to_string(),
    );

    let published = Command::new("agent-browse")
        .arg("wait")
        .arg("--folder")
        .arg(&browser.folder)
        .args(["--selector", super::DONE_SELECTOR])
        .arg("--timeout")
        .arg(timeout.as_millis().to_string())
        .output()
        .is_ok_and(|waited| waited.status.success());

    Ok(Harvest {
        table: browser.evaluate(super::TABLE_EXPRESSION),
        failed: super::normalise_failed(&browser.evaluate(super::FAILED_EXPRESSION)),
        version,
        published,
    })
}
