//! The W3C `WebDriver` client, for every browser CDP cannot reach: start a
//! driver, open a session, navigate, run a script. The e2e matrix and the
//! benchmark both drive Safari through it.

use std::{env, net};
mod driver;
#[cfg(any(feature = "mesh", feature = "bench"))]
mod session;

pub(crate) use driver::Driver;
#[cfg(any(feature = "mesh", feature = "bench"))]
pub(crate) use session::Session;

use std::path::PathBuf;
use std::process::Command;

use super::Skip;

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
    net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .map_err(|error| {
            Skip(format!(
                "could not find a free port for the driver: {error}"
            ))
        })
}

/// `$CHROMEDRIVER` before `$PATH`, so a driver downloaded next to the run works
/// without installing anything system-wide — the same courtesy the wasm-bindgen
/// runner extends via the same variable.
pub(super) fn locate(env_var: &str, binary: &str) -> Option<PathBuf> {
    if let Some(path) = env::var_os(env_var).map(PathBuf::from)
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

/// Each Safari app has its own driver, and its own Remote Automation toggle
/// that only that driver sets.
pub(super) fn safaridriver(browser: &str) -> &'static str {
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
