use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use bytes::Bytes;
use iroh::EndpointId;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::registry::Registry;

pub(crate) struct InboundPacket {
    pub(crate) from: EndpointId,
    pub(crate) payload: Bytes,
}

/// Rate-limited visibility for the lossy queues. `total` is the counter value
/// *after* the increment.
pub(crate) fn note_dropped(remote: &EndpointId, total: u64, context: &str) {
    if crate::should_log_drop(total) {
        tracing::warn!(%remote, total, "webrtc lane dropping datagrams ({context})");
    }
}

/// Aborts the session driver task when the handle leaves the registry, so
/// a `detach` (or dropping the whole transport) reliably stops the str0m
/// loop instead of detaching it.
///
/// Not at once: dropping the handle also closes the driver's outbound queue,
/// and the driver answers that by closing the data channel, which is how the
/// far side learns of the detach. [`CLOSE_GRACE`] lets that close go out; a
/// driver still running after it is aborted.
struct AbortOnDrop(JoinHandle<()>);

const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        let abort = self.0.abort_handle();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    tokio::time::sleep(CLOSE_GRACE).await;
                    abort.abort();
                });
            }
            Err(_) => abort.abort(),
        }
    }
}

pub(crate) struct SessionHandle {
    pub(crate) out_tx: mpsc::Sender<Bytes>,
    pub(crate) dropped_tx: Arc<AtomicU64>,
    /// Aborts the driver when the registry drops this handle.
    _task: AbortOnDrop,
}

impl SessionHandle {
    pub(crate) fn new(
        out_tx: mpsc::Sender<Bytes>,
        dropped_tx: Arc<AtomicU64>,
        task: JoinHandle<()>,
    ) -> Self {
        Self {
            out_tx,
            dropped_tx,
            _task: AbortOnDrop(task),
        }
    }
}

/// The native session registry.
///
/// A type alias, not a second implementation: this was a verbatim copy of
/// [`crate::registry::Registry`] — same `Slot`, same `AtomicU64` generation,
/// same `reserve` / `fulfil` / `remove_if_generation` — differing only in names
/// and in reaching into the payload for `outbound_for`. Its own doc said so.
pub(crate) type SessionRegistry = Registry<SessionHandle>;

#[cfg(test)]
mod tests {
    use super::{SessionHandle, SessionRegistry};
    use iroh::{EndpointId, SecretKey};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::sync::mpsc;

    fn eid(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// **A driver that dies before its slot is recorded must leave nothing.**
    ///
    /// `attach` spawns the driver and records the session afterwards, so a
    /// session that fails immediately retires its own generation against an
    /// empty registry — the removal finds nothing and is lost. The insert then
    /// lands on top, and the entry is permanent: `has_session` stays true,
    /// every send reports `NotConnected`, and re-attach is refused because a
    /// live session supposedly already exists.
    #[tokio::test]
    async fn a_driver_that_dies_before_its_insert_leaves_no_phantom() {
        let registry = SessionRegistry::new();
        let remote = eid(1);
        let reservation = registry
            .reserve(remote)
            .expect("a fresh remote is claimable");
        let generation = reservation.generation();

        // The driver's self-cleanup, arriving before `attach` recorded it.
        registry.remove_if_generation(&remote, generation);

        let (out_tx, _out_rx) = mpsc::channel(1);
        let task = tokio::spawn(async {});
        assert!(
            reservation
                .fulfil(SessionHandle::new(
                    out_tx,
                    Arc::new(AtomicU64::new(0)),
                    task
                ))
                .is_none(),
            "a retired reservation must refuse its own late insert"
        );

        assert!(
            !registry.is_live(&remote),
            "a retired generation must not be resurrected by its own late insert"
        );
    }

    /// The ordinary path must still work: reserve, insert, and the session is
    /// live until something removes it.
    #[tokio::test]
    async fn a_session_that_attaches_normally_is_live() {
        let registry = SessionRegistry::new();
        let remote = eid(2);
        let reservation = registry
            .reserve(remote)
            .expect("a fresh remote is claimable");
        let generation = reservation.generation();
        assert!(
            !registry.is_live(&remote),
            "a reservation is not yet a usable session"
        );
        let (out_tx, _out_rx) = mpsc::channel(1);
        let task = tokio::spawn(async {});
        reservation
            .fulfil(SessionHandle::new(
                out_tx,
                Arc::new(AtomicU64::new(0)),
                task,
            ))
            .expect("a fresh remote attaches")
            .commit();
        assert!(registry.is_live(&remote));

        registry.remove_if_generation(&remote, generation);
        assert!(!registry.is_live(&remote), "its own driver may retire it");
    }
}
