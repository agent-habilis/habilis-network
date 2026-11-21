//! A dial that is in flight, so that concurrent sends share one connection attempt.

use std::collections::HashMap;

use iroh::EndpointId;
use tokio::sync::watch;

use super::unicast_pool::{DialOutcome, UnicastPool};

/// An endpoint's entry in the in-flight dial map, removed on drop: a dial that panics or is dropped
/// with its runtime must not leave the peer marked in flight, which would make every later cold send
/// to it wait for a dial that is gone. A dial that ends without an outcome publishes one, so that
/// its waiters wake with an error.
#[derive(Debug, Clone)]
#[must_use]
pub(crate) struct InFlightDial {
    pub(in crate::transport::pool) pool: UnicastPool,
    pub(in crate::transport::pool) eid: EndpointId,
    pub(in crate::transport::pool) outcome_tx: watch::Sender<DialOutcome>,
}

impl InFlightDial {
    /// Tell the waiters how the dial ended. The plan of the dial is released and the entry leaves
    /// the map in the same step, under its lock: a send that registers after the outcome is a new
    /// dialer and plans its own dial, and the release of the old plan, which is by peer, cannot
    /// reach the plan of that new dial. It does not take the outcome of a dial that ended before it
    /// asked either.
    pub(in crate::transport::pool) fn publish(&self, outcome: Result<(), String>) {
        let mut dialing = self.pool.inner.dialing.lock();
        self.release_plan_once();
        self.leave(&mut dialing);
        self.outcome_tx.send_replace(Some(outcome));
    }

    /// The dial planned a unit or a pin, and a dial that ends with no connection gives it back. A
    /// connection that the dial opened holds its own unit and pin in the ledger already. Only a
    /// dial that has not published releases: after the outcome, the plan was released with the
    /// entry, and the plan of a later dial of the peer is not ours. The caller holds the lock of
    /// `dialing`, as the plan of a dial is made under it (`register_planned_dial`).
    fn release_plan_once(&self) {
        if self.outcome_tx.borrow().is_none() {
            self.pool.release_plan(self.eid);
        }
    }

    /// Remove the entry of this dial from `dialing`, and not the entry of a later dial of the peer.
    fn leave(&self, dialing: &mut HashMap<EndpointId, watch::Receiver<DialOutcome>>) {
        let ours = self.outcome_tx.subscribe();
        if dialing
            .get(&self.eid)
            .is_some_and(|entry| entry.same_channel(&ours))
        {
            dialing.remove(&self.eid);
        }
    }
}

impl Drop for InFlightDial {
    fn drop(&mut self) {
        {
            let mut dialing = self.pool.inner.dialing.lock();
            self.release_plan_once();
            self.leave(&mut dialing);
        }
        self.outcome_tx.send_if_modified(|outcome| {
            if outcome.is_some() {
                return false;
            }
            *outcome = Some(Err("the dial was cancelled".to_owned()));
            true
        });
    }
}
