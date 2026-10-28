//! The native session registry.

use crate::native::session_handle::SessionHandle;
use crate::registry::Registry;

/// The native session registry.
///
/// A type alias, not a second implementation: this was a verbatim copy of
/// [`crate::registry::Registry`] — same `Slot`, same `AtomicU64` generation,
/// same `reserve` / `fulfil` / `remove_if_generation` — differing only in names
/// and in reaching into the payload for `outbound_for`. Its own doc said so.
pub(crate) type SessionRegistry = Registry<SessionHandle>;

#[cfg(test)]
mod tests {
    use super::SessionRegistry;
    use crate::native::session_handle::SessionHandle;
    use habilis_network_test_tracing::test;
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
    #[test]
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
    #[test]
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
