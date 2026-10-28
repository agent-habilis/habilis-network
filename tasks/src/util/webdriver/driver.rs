//! A running `WebDriver` server process.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::super::{Skip, reachable, wait_for};
use super::{free_port, locate, safaridriver};

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
