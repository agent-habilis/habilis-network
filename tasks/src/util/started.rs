//! A call on a page object that has started but not settled.

use std::time::Duration;

use super::evaluate::Evaluate;
use super::page::{rand_token, shown};
use super::wait_for;

/// A call on a page object that has started but not settled: the token
/// [`await_call`] reads the outcome from.
pub(crate) struct Started(String);

/// Start `window.{object}.{call}` without waiting for it.
///
/// Split from [`await_call`] because two pages sometimes have to be in flight
/// at once — a JSEP answerer waits on `ondatachannel`, which only fires once
/// the offerer applies the answer, so awaiting either side alone deadlocks.
/// `Promise.resolve` around the call lets a plain function ride the same path
/// as a promise-returning one.
pub(crate) fn start_call(
    page: &impl Evaluate,
    object: &str,
    call: &str,
) -> Result<Started, String> {
    let token = format!("call{}", rand_token());
    let expression = format!(
        "window.{token}='pending',Promise.resolve().then(()=>window.{object}.{call}).then((v)=>window.{token}='ok:'+(v===undefined?'':String(v)),(e)=>window.{token}='error: '+e),'started'"
    );
    let started = page.evaluate(&expression);
    if started != "started" {
        return Err(format!(
            "{object} call {} did not start: {started:?}",
            shown(call)
        ));
    }
    Ok(Started(token))
}

/// Wait for a started call, handing back what it resolved to.
pub(crate) fn await_call(
    page: &impl Evaluate,
    started: &Started,
    timeout: Duration,
) -> Result<String, String> {
    let Started(token) = started;
    let outcome = wait_for(timeout, Duration::from_millis(250), || {
        let state = page.evaluate(&format!("window.{token}"));
        (state != "pending").then_some(state)
    })
    .ok_or_else(|| format!("page call {token} never settled"))?;
    outcome
        .strip_prefix("ok:")
        .map(str::to_owned)
        .ok_or_else(|| format!("page call failed: {outcome}"))
}
