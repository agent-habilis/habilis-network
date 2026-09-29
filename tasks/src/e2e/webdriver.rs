//! The `WebDriver` cells of the matrix: one session per cell through
//! [`crate::util::webdriver`], harvesting the table its page publishes.

use std::time::Duration;

use crate::util::wait_for;
use crate::util::webdriver::{Driver, capabilities, session_refused};

use super::{Harvest, Skip, server};

/// Run one cell and harvest what the page published.
pub(super) fn run(
    driver: &Driver,
    browser: &str,
    binary: &str,
    pressure: u32,
    timeout: Duration,
) -> Result<Harvest, Skip> {
    let created = driver
        .post("/session", &capabilities(browser, binary))
        .map_err(|error| session_refused(browser, &error))?;

    let session = created
        .pointer("/value/sessionId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            let detail = created
                .pointer("/value/message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("no message");
            session_refused(browser, detail)
        })?;

    // Same reason the CDP path reads `Browser.getVersion`: the label is our
    // intent, this is what answered.
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

    let execute = |script: &str| -> String {
        driver
            .post(
                &format!("/session/{session}/execute/sync"),
                &serde_json::json!({ "script": script, "args": [] }),
            )
            .ok()
            .and_then(|reply| reply.get("value").map(super::json_to_string))
            .unwrap_or_default()
    };

    let url = format!("{}/?pressure={pressure}", server::URL);
    let _ = driver.post(
        &format!("/session/{session}/url"),
        &serde_json::json!({ "url": url }),
    );

    let published = wait_for(timeout, Duration::from_secs(3), || {
        (execute(super::DONE_EXPRESSION) == "1").then_some(())
    })
    .is_some();

    let harvest = Harvest {
        table: execute(super::TABLE_SCRIPT),
        failed: super::normalise_failed(&execute(super::FAILED_SCRIPT)),
        version,
        published,
    };

    let _ = ureq::delete(format!("{}/session/{session}", driver.url))
        .config()
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .call();

    Ok(harvest)
}
