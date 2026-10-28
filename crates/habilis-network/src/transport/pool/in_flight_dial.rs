//! A dial that is in flight, so that concurrent sends share one connection attempt.

use iroh::EndpointId;
use tokio::sync::watch;

use super::unicast_pool::{DialOutcome, UnicastPool};

/// An endpoint's entry in the in-flight dial map, removed on drop: a dial that panics or is dropped
/// with its runtime must not leave the peer marked in flight, which would make every later cold send
/// to it wait for a dial that is gone. A dial that ends without an outcome publishes one, so that
/// its waiters wake with an error.
pub(crate) struct InFlightDial {
    pub(in crate::transport::pool) pool: UnicastPool,
    pub(in crate::transport::pool) eid: EndpointId,
    pub(in crate::transport::pool) outcome_tx: watch::Sender<DialOutcome>,
}

impl InFlightDial {
    /// Tell the waiters how the dial ended.
    pub(in crate::transport::pool) fn publish(&self, outcome: Result<(), String>) {
        self.outcome_tx.send_replace(Some(outcome));
    }
}

impl Drop for InFlightDial {
    fn drop(&mut self) {
        self.pool
            .inner
            .dialing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.eid);
        self.outcome_tx.send_if_modified(|outcome| {
            if outcome.is_some() {
                return false;
            }
            *outcome = Some(Err("the dial was cancelled".to_owned()));
            true
        });
    }
}
