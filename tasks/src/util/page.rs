//! Calling into a page the runner drives. No driver can await a JS promise
//! directly, so a call parks its outcome on `window` and the runner polls for
//! it; everything here needs only a way to evaluate an expression.

use std::time::Duration;

use super::evaluate::Evaluate;
use super::started::{await_call, start_call};
use super::wait_for;

/// A page object's promise-returning control (`window.harness`,
/// `window.chat`, `window.bench`), awaited for at most `timeout`. Resolves to
/// the call's value, rendered as a string.
pub(crate) fn call_page_within(
    page: &impl Evaluate,
    object: &str,
    call: &str,
    timeout: Duration,
) -> Result<String, String> {
    let started = start_call(page, object, call)?;
    await_call(page, &started, timeout)
        .map_err(|error| format!("{object} call {}: {error}", shown(call)))
}

/// A call as an error message shows it: whole when short, or only its method
/// when the arguments are long (a JSEP call carries a full SDP).
pub(super) fn shown(call: &str) -> String {
    const LONGEST: usize = 60;
    match call.split_once('(') {
        Some((method, _)) if call.len() > LONGEST => format!("{method}(…)"),
        _ => call.to_owned(),
    }
}

/// Wait for the page's `#ready` or a non-empty `#failed`, handing back the
/// failure's text. `None` if neither shows up within `timeout`.
pub(crate) fn wait_ready(
    page: &impl Evaluate,
    timeout: Duration,
    poll: Duration,
) -> Option<Result<(), String>> {
    wait_for(timeout, poll, || {
        let failed = page.evaluate("(document.getElementById('failed')||{}).textContent||''");
        if !failed.is_empty() {
            return Some(Err(failed));
        }
        let ready = page.evaluate("document.getElementById('ready')?'1':'0'");
        (ready == "1").then_some(Ok(()))
    })
}

pub(crate) fn rand_token() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.subsec_nanos().into())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use std::time::Duration;

    use super::{call_page_within, shown};
    use crate::util::evaluate::Evaluate;

    /// A page whose every call starts, then fails with `boom`.
    struct Failing;

    impl Evaluate for Failing {
        fn evaluate(&self, expression: &str) -> String {
            if expression.ends_with("'started'") {
                "started".to_owned()
            } else {
                "error: boom".to_owned()
            }
        }
    }

    #[test]
    fn a_failed_call_names_the_method_not_its_arguments() {
        let sdp = "x".repeat(2000);
        let error = call_page_within(
            &Failing,
            "bench",
            &format!("complete(\"{sdp}\")"),
            Duration::from_secs(1),
        )
        .expect_err("the page fails the call");
        assert!(error.contains("complete(…)"), "{error}");
        assert!(error.contains("boom"), "{error}");
        assert!(error.len() < 200, "{} bytes: {error}", error.len());
    }

    #[test]
    fn a_short_call_or_one_without_arguments_stays_whole() {
        assert_eq!(shown("offer()"), "offer()");
        let bare = "x".repeat(100);
        assert_eq!(shown(&bare), bare);
    }
}
