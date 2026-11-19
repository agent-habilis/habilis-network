//! The reservation of a dial that no send planned, given back when the dial ends with no
//! connection.

use iroh::EndpointId;

use super::unicast_pool::UnicastPool;

/// Holds the unit that a probe reserved. If the probe drops before it is disarmed, because its dial
/// failed or its task was cancelled, the unit goes back to the ledger.
#[must_use]
pub(in crate::transport::pool) struct PlanRelease<'pool> {
    pool: &'pool UnicastPool,
    eid: EndpointId,
    armed: bool,
}

impl<'pool> PlanRelease<'pool> {
    pub(in crate::transport::pool) fn new(pool: &'pool UnicastPool, eid: EndpointId) -> Self {
        Self {
            pool,
            eid,
            armed: true,
        }
    }

    /// The dial opened a connection: it holds its own unit in the ledger now.
    pub(in crate::transport::pool) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for PlanRelease<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.pool.release_plan(self.eid);
        }
    }
}
