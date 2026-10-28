use std::cell::{Cell, RefCell};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::util::{Skip, json_to_string};

use std::sync::atomic;
use std::sync::atomic::Ordering;

/// A launched headless Chrome, killed when it goes out of scope.
#[derive(Debug)]
pub(crate) struct Browser {
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

impl Browser {
    pub(crate) fn launch() -> Result<Self, Skip> {
        // A counter beside the timestamp: the benchmark launches two of these
        // back to back, and one Chrome per profile is the whole mechanism.
        static LAUNCHES: atomic::AtomicU32 = atomic::AtomicU32::new(0);
        let binary = super::chrome_for_testing()?;
        let launch = LAUNCHES.fetch_add(1, Ordering::Relaxed);
        let profile = std::env::temp_dir().join(format!(
            "habilis-network-cdp-{}-{}-{launch}",
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
        let connected = super::devtools_port(&profile, &mut chrome).and_then(|port| {
            let (page, _) = tungstenite::connect(super::page_socket(port)?)
                .map_err(|error| Skip(format!("could not open the page's CDP socket: {error}")))?;
            if let MaybeTlsStream::Plain(stream) = page.get_ref() {
                let _ = stream.set_read_timeout(Some(super::CALL_TIMEOUT));
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
    pub(crate) fn navigate(&self, url: &str) {
        self.call("Page.navigate", &serde_json::json!({ "url": url }));
    }

    /// Open `url`. The console is recorded from launch on, over the one
    /// session, so `window` is unused here; both backends take the same call.
    #[cfg(feature = "mesh")]
    pub(crate) fn navigate_watching_console(&self, url: &str, _window: Duration) {
        self.navigate(url);
    }

    /// The console lines recorded so far.
    #[cfg(feature = "mesh")]
    pub(crate) fn console(&self) -> String {
        self.drain();
        let lines = super::console_lines(&serde_json::Value::Array(self.events.borrow().clone()));
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
        let deadline = Instant::now() + super::CALL_TIMEOUT;
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
            let _ = stream.set_read_timeout(Some(super::CALL_TIMEOUT));
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
    pub(crate) fn evaluate(&self, expression: &str) -> String {
        let params = serde_json::json!({ "expression": expression, "returnByValue": true });
        self.call("Runtime.evaluate", &params)
            .and_then(|reply| reply.pointer("/result/value").map(json_to_string))
            .unwrap_or_default()
    }

    /// What actually answered, never the name we gave it.
    pub(crate) fn version(&self) -> String {
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
    pub(crate) fn wait_for(&self, selector: &str, timeout: Duration) -> bool {
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
