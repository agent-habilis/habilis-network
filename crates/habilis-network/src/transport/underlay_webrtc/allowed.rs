//! The members a `WebRTC` underlay is allowed to reach.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use iroh::EndpointId;

/// The underlay ids that may open a session with us now: the underlay ids of the
/// members we hold a link vector from. The event loop refreshes it on each tick.
#[derive(Debug, Clone, Default)]
// the allowed set is shared by the plan and its clones
pub(crate) struct Allowed(Arc<Mutex<HashSet<EndpointId>>>);

impl Allowed {
    pub(crate) fn replace(&self, ids: HashSet<EndpointId>) {
        *self.0.lock().expect("allowed set poisoned") = ids;
    }

    pub(crate) fn contains(&self, id: &EndpointId) -> bool {
        self.0.lock().expect("allowed set poisoned").contains(id)
    }
}
