//! The guard that holds an admitted connection.

use iroh::EndpointId;

use super::SignalAdmission;

/// Holds a peer's negotiation slot for as long as the round runs.
///
/// Released on `Drop`, not on a `return`. That is the whole point: a round can
/// end by being aborted — Router shutdown, a dropped future — and a release
/// written as a statement at the end of the task never runs on that path.
#[derive(Debug)]
#[must_use = "dropping the guard releases the peer's negotiation slot"]
pub(crate) struct AdmissionGuard {
    pub(crate) admission: SignalAdmission,
    pub(crate) peer: EndpointId,
    pub(crate) epoch: u64,
}

impl AdmissionGuard {
    /// Which round of the peer this guard holds.
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.admission.release(self.peer, self.epoch);
    }
}
