//! The guard that holds a busy slot.

use iroh::EndpointId;

use crate::util::clock::Instant;

use super::SignalAdmission;

/// Marks a connection busy for as long as it lives.
#[derive(Debug)]
#[must_use = "dropping the guard ends the busy mark"]
pub(crate) struct BusyGuard {
    pub(crate) admission: SignalAdmission,
    pub(crate) peer: EndpointId,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.admission
            .lock()
            .ceiling
            .busy_end(self.peer, Instant::now());
    }
}
