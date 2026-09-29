//! The W3C `WebDriver` client, for every browser CDP cannot reach: start a
//! driver, open a session, navigate, run a script. The e2e matrix and the
//! benchmark both drive Safari through it.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::{Skip, reachable, wait_for};

/// Safari Technology Preview's app binary, which its own `safaridriver` drives.
pub(crate) const SAFARI_TP: &str =
    "/Applications/Safari Technology Preview.app/Contents/MacOS/Safari Technology Preview";

/// A free port, taken fresh for each driver.
///
/// This used to be a fixed 9615, and the fixed port let someone else's driver
/// answer for ours. A run killed with SIGKILL leaves its driver behind — the
/// `Drop` guard below never runs — and the next run's readiness probe cannot
/// tell that corpse from the process it just spawned. A cell duly came back
/// reporting a browser it had never launched, which is only visible at all
/// because the version is read back from whatever answered rather than taken
/// from the cell's name.
///
/// Binding to port 0 and immediately releasing leaves a window where something
/// else could take it. That window is microseconds and the alternative is a
/// collision that lasts as long as the stale process does.
pub(crate) fn free_port() -> Result<u16, Skip> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .map_err(|error| {
            Skip(format!(
                "could not find a free port for the driver: {error}"
            ))
        })
}

/// A running driver, killed when it goes out of scope.
#[derive(Debug)]
pub(crate) struct Driver {
    child: Child,
    pub(crate) url: String,
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `$CHROMEDRIVER` before `$PATH`, so a driver downloaded next to the run works
/// without installing anything system-wide — the same courtesy the wasm-bindgen
/// runner extends via the same variable.
fn locate(env_var: &str, binary: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(env_var).map(PathBuf::from)
        && path.is_file()
    {
        return Some(path);
    }
    let found = Command::new("which").arg(binary).output().ok()?;
    found
        .status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&found.stdout).trim().to_owned()))
}

impl Driver {
    pub(crate) fn start(browser: &str) -> Result<Self, Skip> {
        let port = free_port()?;
        let mut command = match browser {
            "chrome-151" | "chrome-ci" => {
                // A chromedriver whose version matches the Chrome it drives. A
                // mismatch fails session creation with a bare HTTP 404 and no
                // hint that the version is what is wrong.
                let driver = locate("CHROMEDRIVER", "chromedriver").ok_or_else(|| {
                    Skip(format!(
                        "no chromedriver for {browser} — set $CHROMEDRIVER to a matching build"
                    ))
                })?;
                let mut command = Command::new(driver);
                command.arg(format!("--port={port}"));
                command
            }
            "safari" | "safari-tp" => {
                let driver = PathBuf::from(safaridriver(browser));
                if !driver.is_file() {
                    return Err(Skip(format!(
                        "safaridriver is missing at {}",
                        driver.display()
                    )));
                }
                let mut command = Command::new(driver);
                command.args(["-p", &port.to_string()]);
                command
            }
            other => return Err(Skip(format!("no driver wired up for {other}"))),
        };

        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| Skip(format!("could not start the {browser} driver: {error}")))?;
        let mut driver = Self {
            child,
            url: format!("http://127.0.0.1:{port}"),
        };

        // Give up the moment the child dies, rather than polling a port it was
        // never going to open. Combined with the fresh port above, a `/status`
        // that answers is now necessarily *this* driver's.
        let status_url = format!("{}/status", driver.url);
        let ready = wait_for(Duration::from_secs(10), Duration::from_millis(250), || {
            if matches!(driver.child.try_wait(), Ok(Some(_))) {
                return Some(false);
            }
            reachable(&status_url).then_some(true)
        });
        match ready {
            Some(true) => Ok(driver),
            Some(false) => Err(Skip(format!(
                "the {browser} driver exited before it was ready"
            ))),
            None => Err(Skip(format!("the {browser} driver never became ready"))),
        }
    }

    pub(crate) fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        ureq::post(format!("{}{path}", self.url))
            .config()
            .timeout_global(Some(Duration::from_mins(1)))
            .build()
            .send_json(body)
            .map_err(|error| error.to_string())?
            .body_mut()
            .read_json::<serde_json::Value>()
            .map_err(|error| error.to_string())
    }
}

/// Every browser needs its own way of being told to stop hiding local IPs
/// behind mDNS; without it the only host candidate is a `.local` name a
/// headless browser cannot resolve, and ICE never leaves `new`. Real tabs are
/// unaffected — this is a property of the harness, not of the transport.
pub(crate) fn capabilities(browser: &str, binary: &str) -> serde_json::Value {
    match browser {
        "chrome-151" => serde_json::json!({ "capabilities": { "alwaysMatch": {
            "goog:chromeOptions": {
                "binary": binary,
                "args": [
                    "--headless=new",
                    "--disable-gpu",
                    "--disable-features=WebRtcHideLocalIpsWithMdns",
                ],
            },
        }}}),
        // A Linux CI runner: its Chrome runs without the user-namespace
        // sandbox the runner cannot grant.
        "chrome-ci" => serde_json::json!({ "capabilities": { "alwaysMatch": {
            "goog:chromeOptions": {
                "binary": binary,
                "args": [
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--disable-features=WebRtcHideLocalIpsWithMdns",
                ],
            },
        }}}),
        // Safari has no such switch and no headless mode either, so it runs
        // visibly and pairs on whatever it is willing to gather.
        _ => serde_json::json!({ "capabilities": { "alwaysMatch": {} } }),
    }
}

/// A live `WebDriver` session on one browser, for a suite that drives the page
/// itself rather than harvesting a published table. The driver dies with the
/// session (its `Drop` kills the process), which also closes the window.
#[cfg(any(feature = "mesh", feature = "bench"))]
#[derive(Debug)]
pub(crate) struct Session {
    driver: Driver,
    id: String,
    version: String,
}

#[cfg(any(feature = "mesh", feature = "bench"))]
impl Session {
    pub(crate) fn open(browser: &str, binary: &str) -> Result<Self, Skip> {
        let driver = Driver::start(browser)?;
        let created = driver
            .post("/session", &capabilities(browser, binary))
            .map_err(|error| session_refused(browser, &error))?;
        let id = created
            .pointer("/value/sessionId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                let detail = created
                    .pointer("/value/message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("no message");
                session_refused(browser, detail)
            })?
            .to_owned();
        let capability = |key: &str| {
            created
                .pointer(&format!("/value/capabilities/{key}"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_owned()
        };
        let version = format!(
            "{}/{}",
            capability("browserName"),
            capability("browserVersion")
        );
        Ok(Self {
            driver,
            id,
            version,
        })
    }

    pub(crate) fn navigate(&self, url: &str) {
        let _ = self.driver.post(
            &format!("/session/{}/url", self.id),
            &serde_json::json!({ "url": url }),
        );
    }

    /// Run a script body (`return …;`) and read its value as a string.
    pub(crate) fn execute(&self, script: &str) -> String {
        self.driver
            .post(
                &format!("/session/{}/execute/sync", self.id),
                &serde_json::json!({ "script": script, "args": [] }),
            )
            .ok()
            .and_then(|reply| reply.get("value").map(super::json_to_string))
            .unwrap_or_default()
    }

    pub(crate) fn version(&self) -> String {
        self.version.clone()
    }
}

/// Each Safari app has its own driver, and its own Remote Automation toggle
/// that only that driver sets.
fn safaridriver(browser: &str) -> &'static str {
    if browser == "safari" {
        "/usr/bin/safaridriver"
    } else {
        "/Applications/Safari Technology Preview.app/Contents/MacOS/safaridriver"
    }
}

/// A refusal and a hang want different fixes, so they get different messages.
/// Safari's needs a one-time `--enable` under sudo, per Safari app, and a
/// running copy that hangs the handshake quit.
pub(crate) fn session_refused(browser: &str, detail: &str) -> Skip {
    if browser.starts_with("safari") {
        return Skip(format!(
            "safaridriver would not start a session ({detail}) — run `sudo \"{}\" --enable` \
             once, and quit a running copy that hangs the handshake",
            safaridriver(browser)
        ));
    }
    Skip(format!("no session from the {browser} driver: {detail}"))
}
