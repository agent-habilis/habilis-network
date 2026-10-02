//! A session slot table where a half-built session cannot be observed and a
//! dead session cannot evict its replacement.
//!
//! Payload-generic and free of every `WebRTC` type on purpose: the browser
//! backend cannot be tested — `RTCPeerConnection` does not exist in node and CI
//! runs no webdriver — so the logic that needs testing is pulled out here,
//! into the crate's always-compiled half, where `cargo test` reaches it.
//!
//! # The two failures this exists to make impossible
//!
//! **A phantom slot.** Attaching has to happen *before* the data channel opens,
//! because the browser gives you no inbound buffer: a QUIC Initial that arrives
//! before `onmessage` is installed is gone. So the window between "inserted"
//! and "usable" is real, and the browser hub used to hold it open with a plain
//! insert — a negotiation that then failed to open its channel left the entry
//! behind forever, because a channel that never opened never fires `onclose`
//! either. The entry counted toward the direct-peer total, answered
//! `has_session` so the pair was never retried, and told QUIC it was a valid
//! send address while silently dropping every datagram.
//!
//! [`Reservation`] and [`SessionGuard`] close that by construction. Failure is
//! a `Drop`, not a cleanup branch — which matters because these futures are
//! driven from `spawn_local` and a dropped future runs no cleanup you wrote.
//!
//! **A stale removal.** The self-removal hook a session installs on its own
//! data channel outlives the session if that session is ever replaced. Every
//! removal here is therefore generation-scoped: a hook can only remove the slot
//! it was born into, never the one that took its place.
//!
//! # Reserved is not live
//!
//! [`Registry::is_live`], [`Registry::live_len`] and [`Registry::with_live`]
//! ignore reserved slots, and callers must route "is there a usable path"
//! questions through them. Telling QUIC that a reserved slot is a valid send
//! address would hand it a channel with no pump behind it. [`Registry::reserve`]
//! is the only method that treats reserved and live alike, because for
//! admission they are the same answer: someone already has this peer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use iroh_base::EndpointId;

/// One peer's slot: reserved while `value` is `None`, live once it is `Some`.
#[derive(Debug)]
struct Slot<T> {
    generation: u64,
    value: Option<T>,
}

/// Session slots keyed by remote peer, with generation-scoped removal.
#[derive(Debug)]
pub(crate) struct Registry<T> {
    slots: Mutex<HashMap<EndpointId, Slot<T>>>,
    next_generation: AtomicU64,
}

impl<T> Registry<T> {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(0),
        })
    }

    /// Claim `remote`'s slot, or `None` if anyone already holds it.
    ///
    /// Refuses against reserved *and* live slots: an in-flight attach owns the
    /// peer just as much as a finished one.
    pub(crate) fn reserve(self: &Arc<Self>, remote: EndpointId) -> Option<Reservation<T>> {
        let mut slots = self.lock();
        if slots.contains_key(&remote) {
            return None;
        }
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        slots.insert(
            remote,
            Slot {
                generation,
                value: None,
            },
        );
        drop(slots);
        Some(Reservation {
            registry: Arc::clone(self),
            remote,
            generation,
        })
    }

    /// Whether a *usable* session for `remote` exists. A reservation is not one.
    pub(crate) fn is_live(&self, remote: &EndpointId) -> bool {
        self.lock()
            .get(remote)
            .is_some_and(|slot| slot.value.is_some())
    }

    /// How many usable sessions this registry holds.
    pub(crate) fn live_len(&self) -> usize {
        self.lock()
            .values()
            .filter(|slot| slot.value.is_some())
            .count()
    }

    /// Endpoint ids of every *usable* session (reservations excluded).
    pub(crate) fn live_ids(&self) -> Vec<EndpointId> {
        self.lock()
            .iter()
            .filter(|(_, slot)| slot.value.is_some())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Run `f` against `remote`'s payload, if it is live.
    ///
    /// A closure rather than a returned reference: the lock cannot outlive the
    /// call, so no caller can accidentally hold it across an await.
    pub(crate) fn with_live<R>(
        &self,
        remote: &EndpointId,
        read: impl FnOnce(&T) -> R,
    ) -> Option<R> {
        self.lock()
            .get(remote)
            .and_then(|slot| slot.value.as_ref())
            .map(read)
    }

    /// Drop `remote`'s slot whatever its generation. Returns whether the slot
    /// removed was live.
    ///
    /// This is the caller-initiated detach. It also takes a reservation, so a
    /// shutdown cannot leave one stranded.
    pub(crate) fn remove(&self, remote: &EndpointId) -> bool {
        self.lock()
            .remove(remote)
            .is_some_and(|slot| slot.value.is_some())
    }

    /// Drop `remote`'s slot only if it is still the one stamped `generation`.
    ///
    /// The whole point of the generation. A session's own close hook, and an
    /// uncommitted guard, both come here — and both are no-ops once a newer
    /// session has taken the peer.
    pub(crate) fn remove_if_generation(&self, remote: &EndpointId, generation: u64) -> bool {
        let mut slots = self.lock();
        let Some(slot) = slots.get(remote) else {
            return false;
        };
        if slot.generation != generation {
            return false;
        }
        slots
            .remove(remote)
            .is_some_and(|removed| removed.value.is_some())
    }

    /// Drop every slot. Returns how many of them were live.
    pub(crate) fn clear(&self) -> usize {
        let mut slots = self.lock();
        let live = slots.values().filter(|slot| slot.value.is_some()).count();
        slots.clear();
        live
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<EndpointId, Slot<T>>> {
        self.slots.lock().expect("session registry poisoned")
    }
}

/// A claimed but unfilled slot. Dropping it releases the claim.
#[derive(Debug)]
#[must_use = "dropping a reservation releases the peer's slot"]
pub(crate) struct Reservation<T> {
    registry: Arc<Registry<T>>,
    remote: EndpointId,
    generation: u64,
}

impl<T> Reservation<T> {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Put the session in the slot, handing the release obligation to the
    /// returned guard.
    ///
    /// `None` when the reservation is no longer the slot's owner: it was
    /// retired while outstanding, or a newer one replaced it. That is exactly
    /// the case a reservation exists for — a driver that failed and retired its
    /// own generation while the spawn was still returning. Re-inserting there
    /// would record a session nothing is driving; instead `value` drops here,
    /// running whatever teardown it owns.
    pub(crate) fn fulfil(self, value: T) -> Option<SessionGuard<T>> {
        let registry = Arc::clone(&self.registry);
        let remote = self.remote;
        let generation = self.generation;
        // Take the reservation apart without running its `Drop`, which would
        // release the very slot we are about to fill.
        std::mem::forget(self);

        {
            let mut sessions = registry.lock();
            let slot = sessions.get_mut(&remote)?;
            if slot.generation != generation || slot.value.is_some() {
                return None;
            }
            slot.value = Some(value);
        }
        Some(SessionGuard {
            registry,
            remote,
            generation,
            committed: false,
        })
    }
}

impl<T> Drop for Reservation<T> {
    fn drop(&mut self) {
        self.registry
            .remove_if_generation(&self.remote, self.generation);
    }
}

/// A live-but-unproven session. Dropping it uncommitted tears the session down.
///
/// Held across the wait for the data channel to open. Committing says the
/// channel is carrying traffic and the registry now owns the session outright;
/// dropping says it never got there, and the payload's own `Drop` — closing the
/// channel and the peer connection — runs on the way out.
#[derive(Debug)]
#[must_use = "an uncommitted session guard tears the session down when dropped"]
pub(crate) struct SessionGuard<T> {
    registry: Arc<Registry<T>>,
    remote: EndpointId,
    generation: u64,
    committed: bool,
}

impl<T> SessionGuard<T> {
    pub(crate) fn remote(&self) -> EndpointId {
        self.remote
    }

    /// The generation this session was attached under.
    ///
    /// Test-only: production hooks capture the generation from the
    /// [`Reservation`], before the guard exists.
    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Keep the session: the registry owns it from here.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl<T> Drop for SessionGuard<T> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.registry
            .remove_if_generation(&self.remote, self.generation);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    fn peer(byte: u8) -> EndpointId {
        iroh_base::SecretKey::from_bytes(&[byte; 32]).public()
    }

    /// Flips a shared flag when dropped, so a test can prove the payload's own
    /// teardown ran — which in production is what closes the peer connection.
    struct Probe(Rc<Cell<bool>>);

    impl Drop for Probe {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    fn probe() -> (Probe, Rc<Cell<bool>>) {
        let dropped = Rc::new(Cell::new(false));
        (Probe(Rc::clone(&dropped)), dropped)
    }

    #[test]
    fn a_reservation_is_not_live() {
        let registry = Registry::<Probe>::new();
        let reservation = registry.reserve(peer(1)).expect("first reserve");
        assert!(!registry.is_live(&peer(1)));
        assert_eq!(registry.live_len(), 0);
        drop(reservation);
    }

    #[test]
    fn dropping_a_reservation_frees_the_slot() {
        let registry = Registry::<Probe>::new();
        drop(registry.reserve(peer(1)).expect("first reserve"));
        assert!(
            registry.reserve(peer(1)).is_some(),
            "the slot must be claimable again"
        );
    }

    #[test]
    fn reserve_refuses_while_reserved_and_while_live() {
        let registry = Registry::<Probe>::new();
        let reservation = registry.reserve(peer(1)).expect("first reserve");
        assert!(registry.reserve(peer(1)).is_none(), "reserved");

        let guard = reservation.fulfil(probe().0).expect("slot is ours");
        assert!(registry.reserve(peer(1)).is_none(), "live");
        guard.commit();
        assert!(registry.reserve(peer(1)).is_none(), "still live");
    }

    #[test]
    fn dropping_an_uncommitted_guard_removes_the_slot_and_drops_the_payload() {
        let registry = Registry::new();
        let (payload, dropped) = probe();
        let guard = registry
            .reserve(peer(1))
            .expect("first reserve")
            .fulfil(payload)
            .expect("slot is ours");

        assert!(registry.is_live(&peer(1)));
        drop(guard);

        assert!(!registry.is_live(&peer(1)), "the slot must be gone");
        assert!(dropped.get(), "the payload's own teardown must have run");
    }

    #[test]
    fn a_committed_guard_leaves_the_session_live() {
        let registry = Registry::new();
        let (payload, dropped) = probe();
        registry
            .reserve(peer(1))
            .expect("first reserve")
            .fulfil(payload)
            .expect("slot is ours")
            .commit();

        assert!(registry.is_live(&peer(1)));
        assert_eq!(registry.live_len(), 1);
        assert!(!dropped.get(), "committing must not tear the session down");
    }

    /// The booby trap: a session that lost a duplicate race, or whose channel
    /// died late, must not take out the session that replaced it.
    #[test]
    fn a_stale_guard_does_not_evict_a_newer_session() {
        let registry = Registry::new();

        let (first, first_dropped) = probe();
        let stale = registry
            .reserve(peer(1))
            .expect("first reserve")
            .fulfil(first)
            .expect("slot is ours");
        registry.remove(&peer(1));
        assert!(first_dropped.get());

        let (second, second_dropped) = probe();
        registry
            .reserve(peer(1))
            .expect("second reserve")
            .fulfil(second)
            .expect("slot is ours")
            .commit();

        drop(stale);

        assert!(registry.is_live(&peer(1)), "the newer session must survive");
        assert!(!second_dropped.get());
    }

    /// The same guarantee for the close/error hook a session installs on its
    /// own data channel, which is what actually fires in production.
    #[test]
    fn a_stale_close_hook_is_a_no_op() {
        let registry = Registry::new();
        let stale_generation = {
            let guard = registry
                .reserve(peer(1))
                .expect("first reserve")
                .fulfil(probe().0)
                .expect("slot is ours");
            let generation = guard.generation();
            guard.commit();
            generation
        };
        registry.remove(&peer(1));
        registry
            .reserve(peer(1))
            .expect("second reserve")
            .fulfil(probe().0)
            .expect("slot is ours")
            .commit();

        assert!(!registry.remove_if_generation(&peer(1), stale_generation));
        assert!(registry.is_live(&peer(1)), "the newer session must survive");
    }

    #[test]
    fn with_live_skips_a_reservation() {
        let registry = Registry::<Probe>::new();
        let reservation = registry.reserve(peer(1)).expect("first reserve");
        assert!(registry.with_live(&peer(1), |_| ()).is_none());

        let guard = reservation.fulfil(probe().0).expect("slot is ours");
        assert!(registry.with_live(&peer(1), |_| ()).is_some());
        guard.commit();
    }

    #[test]
    fn clear_takes_reservations_too_and_counts_only_live_ones() {
        let registry = Registry::<Probe>::new();
        let reservation = registry.reserve(peer(1)).expect("reserve one");
        registry
            .reserve(peer(2))
            .expect("reserve two")
            .fulfil(probe().0)
            .expect("slot is ours")
            .commit();

        assert_eq!(registry.clear(), 1, "only the live one counts");
        assert!(registry.reserve(peer(1)).is_some(), "no slot left stranded");
        drop(reservation);
    }
}
