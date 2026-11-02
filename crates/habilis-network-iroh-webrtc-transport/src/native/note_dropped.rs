//! Visibility for the lossy queues.

use iroh::EndpointId;

/// Rate-limited visibility for the lossy queues. `total` is the counter value
/// *after* the increment.
pub(crate) fn note_dropped(remote: &EndpointId, total: u64, context: &str) {
    if crate::should_log_drop(total) {
        if crate::drops_are_sustained(total) {
            tracing::warn!(%remote, total, "webrtc lane dropping datagrams ({context})");
        } else {
            tracing::debug!(%remote, total, "webrtc lane dropping datagrams ({context})");
        }
    }
}
