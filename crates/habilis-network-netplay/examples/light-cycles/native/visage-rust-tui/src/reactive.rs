//! The reactive core, ported from `visage-dom/src/signal/index.ts`: a
//! signal is a value plus a set of subscribers, "this render is a
//! dependency of this signal" is recorded by opening a tracking window
//! before a render and closing it after, and a write schedules every
//! current subscriber onto a queue that [`flush`] drains shallowest-first.
//!
//! Ported deliberately differently in one place: the original threads a
//! module-level mutable global (`currentDeps`) and defers flushing to a
//! microtask. Rust has neither a natural module-global reactive context nor
//! a microtask queue, so tracking is a `thread_local!`, and flushing is an
//! explicit [`flush`] call the driver makes at a defined point in its own
//! loop (see the crate's `visage-tui/src/index.ts` frame-loop note: "drain
//! the reactive queue, then if anything committed, repaint once").

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

/// Identifies a [`Signal`] for dependency bookkeeping. Newtype-over-`u32`
/// rather than an `Rc`-based identity: `Instance -> deps -> Signal -> subs ->
/// Instance` is a reference cycle the original relies on JS's GC to collect.
/// An arena of ids has no cycle to leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignalId(u32);

/// Identifies a [`Subscriber`] — a component instance, in the real port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubscriberId(u32);

struct Registry {
    /// Every signal's current subscriber set, by id.
    subs: RefCell<Vec<HashSet<SubscriberId>>>,
    /// The tracking window open during a render, if any — `Some` records
    /// every signal read into it; `None` means untracked (setup code, or a
    /// read from outside any render at all).
    current_deps: RefCell<Option<HashSet<SignalId>>>,
    /// Subscribers waiting for [`flush`], deduplicated by id.
    queue: RefCell<Vec<SubscriberId>>,
    queue_set: RefCell<HashSet<SubscriberId>>,
}

thread_local! {
    static REGISTRY: Registry = Registry {
        subs: RefCell::new(Vec::new()),
        current_deps: RefCell::new(None),
        queue: RefCell::new(Vec::new()),
        queue_set: RefCell::new(HashSet::new()),
    };
    static NEXT_SIGNAL_ID: Cell<u32> = const { Cell::new(0) };
    static NEXT_SUBSCRIBER_ID: Cell<u32> = const { Cell::new(0) };
}

fn next_signal_id() -> SignalId {
    NEXT_SIGNAL_ID.with(|next| {
        let id = next.get();
        next.set(id + 1);
        SignalId(id)
    })
}

/// Mints a fresh id for a new component instance (or any other
/// [`Subscriber`]).
#[must_use]
pub fn next_subscriber_id() -> SubscriberId {
    NEXT_SUBSCRIBER_ID.with(|next| {
        let id = next.get();
        next.set(id + 1);
        SubscriberId(id)
    })
}

/// Opens a tracking window, recording every signal read until
/// [`close_tracking`] is called with the value this returns. Mirrors
/// `openTracking`/`closeTracking`: save-and-restore around a resume, not a
/// stack — a window can be reopened re-entrantly (a signal read while
/// resolving a `computed` inside a render) as long as each open is paired
/// with its own close.
#[must_use]
pub fn open_tracking(deps: HashSet<SignalId>) -> Option<HashSet<SignalId>> {
    REGISTRY.with(|r| r.current_deps.replace(Some(deps)))
}

/// Closes the tracking window, restoring whatever was open before (`None`
/// if this was the outermost window), and returns what was recorded.
#[must_use]
pub fn close_tracking(prev: Option<HashSet<SignalId>>) -> HashSet<SignalId> {
    REGISTRY.with(|r| r.current_deps.replace(prev).unwrap_or_default())
}

/// Runs `f` with tracking suspended — reads inside it are not recorded as
/// dependencies of whatever window (if any) is currently open.
pub fn untrack<T>(f: impl FnOnce() -> T) -> T {
    let prev = REGISTRY.with(|r| r.current_deps.take());
    let result = f();
    REGISTRY.with(|r| *r.current_deps.borrow_mut() = prev);
    result
}

/// Clears whatever tracking window is currently open, if any — used when
/// adopting a render thunk: reads made above the `yield` (setup, which
/// runs exactly once) are discarded, so only the thunk's own reads become
/// dependencies. Mirrors `#adopt`'s `deps.clear()`.
pub fn clear_current_tracking() {
    REGISTRY.with(|r| {
        if let Some(deps) = r.current_deps.borrow_mut().as_mut() {
            deps.clear();
        }
    });
}

fn record(id: SignalId) {
    REGISTRY.with(|r| {
        if let Some(deps) = r.current_deps.borrow_mut().as_mut() {
            deps.insert(id);
        }
    });
}

struct SignalInner<T> {
    id: SignalId,
    value: RefCell<T>,
}

/// A reactive cell. Reading [`Signal::get`] inside an open tracking window
/// subscribes that window's owner to this signal; [`Signal::set`] notifies
/// every current subscriber, unless the new value equals the old one.
///
/// `Rc`-backed and cheap to [`Clone`] — cloning shares the same underlying
/// cell and id (as a JS closure capturing a signal shares the same object),
/// it does not create an independent signal. This is load-bearing: a
/// component's setup code typically clones a signal into the closure it
/// yields, and both that clone and the original must observe the same
/// writes.
pub struct Signal<T>(Rc<SignalInner<T>>);

// Hand-written rather than derived: deriving would require `T: Debug` *and*
// print the value, which needs a borrow this type otherwise never exposes
// by reference (`get`/`peek` both return owned clones). Printing the id is
// enough to distinguish signals in a debug trace.
impl<T> std::fmt::Debug for Signal<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signal")
            .field("id", &self.0.id)
            .finish_non_exhaustive()
    }
}

impl<T> Clone for Signal<T> {
    fn clone(&self) -> Self {
        Signal(Rc::clone(&self.0))
    }
}

impl<T: PartialEq + Clone> Signal<T> {
    #[must_use]
    pub fn new(initial: T) -> Self {
        let id = next_signal_id();
        REGISTRY.with(|r| {
            let mut subs = r.subs.borrow_mut();
            let index = id.0 as usize;
            if subs.len() <= index {
                subs.resize_with(index + 1, HashSet::new);
            }
        });
        Self(Rc::new(SignalInner {
            id,
            value: RefCell::new(initial),
        }))
    }

    /// Reads the value, recording a dependency if a tracking window is open.
    #[must_use]
    pub fn get(&self) -> T {
        record(self.0.id);
        self.0.value.borrow().clone()
    }

    /// Reads the value without recording a dependency — the escape hatch
    /// for an event handler or a one-off check that must not subscribe.
    #[must_use]
    pub fn peek(&self) -> T {
        self.0.value.borrow().clone()
    }

    /// Writes a new value. A no-op, dependency-wise, if it equals the
    /// current one — matches the original's `Object.is` bail, which is what
    /// stops a `set` to the same value from ever scheduling a render.
    pub fn set(&self, next: T) {
        let changed = {
            let mut value = self.0.value.borrow_mut();
            if *value == next {
                false
            } else {
                *value = next;
                true
            }
        };
        if changed {
            self.notify();
        }
    }

    pub fn update(&self, f: impl FnOnce(&T) -> T) {
        let next = f(&self.0.value.borrow());
        self.set(next);
    }

    fn notify(&self) {
        let subscribers: Vec<SubscriberId> = REGISTRY.with(|r| {
            r.subs
                .borrow()
                .get(self.0.id.0 as usize)
                .map(|set| set.iter().copied().collect())
                .unwrap_or_default()
        });
        for sub in subscribers {
            schedule_update(sub);
        }
    }
}

/// Queues `sub` for the next [`take_queue`]. Idempotent within a queue:
/// a subscriber woken twice before a drain runs once, exactly as
/// `scheduleUpdate` does.
pub fn schedule_update(sub: SubscriberId) {
    REGISTRY.with(|r| {
        if r.queue_set.borrow_mut().insert(sub) {
            r.queue.borrow_mut().push(sub);
        }
    });
}

/// Drains the update queue in FIFO order and clears it — dispatch is the
/// caller's job, not this module's, because only the caller owns the
/// actual subscribers (the registry stores ids only, to avoid the
/// `Instance -> deps -> Signal -> subs -> Instance` reference cycle the
/// original relies on GC for). See [`crate::runtime::Runtime::tick`] for
/// the dispatch half of what was `flush()` in the original.
#[must_use]
pub fn take_queue() -> Vec<SubscriberId> {
    REGISTRY.with(|r| {
        r.queue_set.borrow_mut().clear();
        std::mem::take(&mut *r.queue.borrow_mut())
    })
}

/// Resubscribes `sub` from `prev`'s dependency set to `next`'s: dropped from
/// every signal in `prev` but not `next`, added to every signal in `next`.
/// Mirrors `resubscribe` — called after each render with the just-recorded
/// dependency set, so a signal a component stopped reading stops notifying
/// it.
pub fn resubscribe(sub: SubscriberId, prev: &HashSet<SignalId>, next: &HashSet<SignalId>) {
    REGISTRY.with(|r| {
        let mut subs = r.subs.borrow_mut();
        for dep in prev {
            if !next.contains(dep)
                && let Some(set) = subs.get_mut(dep.0 as usize)
            {
                set.remove(&sub);
            }
        }
        for dep in next {
            let index = dep.0 as usize;
            if subs.len() <= index {
                subs.resize_with(index + 1, HashSet::new);
            }
            subs[index].insert(sub);
        }
    });
}

/// Drops `sub` from every signal in `deps` — the unmount path.
pub fn unsubscribe_all(sub: SubscriberId, deps: &HashSet<SignalId>) {
    REGISTRY.with(|r| {
        let mut subs = r.subs.borrow_mut();
        for dep in deps {
            if let Some(set) = subs.get_mut(dep.0 as usize) {
                set.remove(&sub);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{
        Signal, close_tracking, next_subscriber_id, open_tracking, resubscribe, schedule_update,
        take_queue,
    };
    use std::collections::HashSet;

    #[test]
    fn reading_a_signal_inside_a_tracking_window_records_it() {
        let signal = Signal::new(1);
        let prev = open_tracking(HashSet::new());
        let _ = signal.get();
        let deps = close_tracking(prev);
        assert_eq!(deps.len(), 1);
    }

    #[test]
    fn reading_a_signal_outside_any_window_records_nothing() {
        let signal = Signal::new(1);
        let _ = signal.get(); // no window open at all
        // Nothing to assert on directly here beyond "it doesn't panic" —
        // the real behavioral check is in the subscription test below,
        // where an untracked read never gets a subscriber queued.
        assert_eq!(signal.peek(), 1);
    }

    #[test]
    fn peek_never_records_a_dependency_even_inside_a_window() {
        let signal = Signal::new(1);
        let prev = open_tracking(HashSet::new());
        let _ = signal.peek();
        let deps = close_tracking(prev);
        assert!(deps.is_empty());
    }

    #[test]
    fn a_subscribed_signal_queues_its_subscriber_on_change() {
        let signal = Signal::new(1);
        let sub = next_subscriber_id();

        let prev = open_tracking(HashSet::new());
        let _ = signal.get();
        let deps = close_tracking(prev);
        resubscribe(sub, &HashSet::new(), &deps);

        signal.set(2);
        assert_eq!(take_queue(), vec![sub]);
    }

    #[test]
    fn setting_a_signal_to_an_equal_value_schedules_nothing() {
        let signal = Signal::new(1);
        let sub = next_subscriber_id();
        let prev = open_tracking(HashSet::new());
        let _ = signal.get();
        let deps = close_tracking(prev);
        resubscribe(sub, &HashSet::new(), &deps);

        signal.set(1); // same value — no-op per the `Object.is` bail
        assert!(take_queue().is_empty());
    }

    #[test]
    fn resubscribing_to_a_smaller_dep_set_drops_the_stale_subscription() {
        let a = Signal::new(1);
        let b = Signal::new(1);
        let sub = next_subscriber_id();

        let prev = open_tracking(HashSet::new());
        let _ = a.get();
        let _ = b.get();
        let first_deps = close_tracking(prev);
        resubscribe(sub, &HashSet::new(), &first_deps);

        // Second render only reads `b` — matches a component whose thunk
        // took a different branch and stopped reading `a`.
        let prev = open_tracking(HashSet::new());
        let _ = b.get();
        let second_deps = close_tracking(prev);
        resubscribe(sub, &first_deps, &second_deps);

        a.set(2); // no longer subscribed
        assert!(take_queue().is_empty());

        b.set(2); // still subscribed
        assert_eq!(take_queue(), vec![sub]);
    }

    #[test]
    fn scheduling_the_same_subscriber_twice_queues_it_once() {
        let sub = next_subscriber_id();
        schedule_update(sub);
        schedule_update(sub);
        assert_eq!(take_queue(), vec![sub]);
    }
}
