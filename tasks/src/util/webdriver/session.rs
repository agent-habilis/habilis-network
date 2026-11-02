//! A live `WebDriver` session on one browser.

use super::super::{Skip, json_to_string};
use super::driver::Driver;
use super::{capabilities, session_refused};

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
            .and_then(|reply| reply.get("value").map(json_to_string))
            .unwrap_or_default()
    }

    pub(crate) fn version(&self) -> String {
        self.version.clone()
    }
}
