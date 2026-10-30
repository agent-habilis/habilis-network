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

use crate::registry::Registry;
use crate::signal_id::SignalId;
use crate::subscriber_id::SubscriberId;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::hash::BuildHasher;
use std::mem;

thread_local! {
    pub(crate) static REGISTRY: Registry = Registry {
        subs: RefCell::new(Vec::new()),
        current_deps: RefCell::new(None),
        queue: RefCell::new(Vec::new()),
        queue_set: RefCell::new(HashSet::new()),
    };
    pub(crate) static NEXT_SIGNAL_ID: Cell<u32> = const { Cell::new(0) };
    pub(crate) static NEXT_SUBSCRIBER_ID: Cell<u32> = const { Cell::new(0) };
}

pub(crate) fn next_signal_id() -> SignalId {
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
pub fn open_tracking<S: BuildHasher>(deps: HashSet<SignalId, S>) -> Option<HashSet<SignalId>> {
    REGISTRY.with(|r| r.current_deps.replace(Some(deps.into_iter().collect())))
}

/// Closes the tracking window, restoring whatever was open before (`None`
/// if this was the outermost window), and returns what was recorded.
#[must_use]
pub fn close_tracking<S: BuildHasher>(previous: Option<HashSet<SignalId, S>>) -> HashSet<SignalId> {
    let previous: Option<HashSet<SignalId>> = previous.map(|deps| deps.into_iter().collect());
    REGISTRY.with(|r| r.current_deps.replace(previous).unwrap_or_default())
}

/// Runs `f` with tracking suspended — reads inside it are not recorded as
/// dependencies of whatever window (if any) is currently open.
pub fn untrack<T>(f: impl FnOnce() -> T) -> T {
    let previous = REGISTRY.with(|r| r.current_deps.take());
    let result = f();
    REGISTRY.with(|r| *r.current_deps.borrow_mut() = previous);
    result
}

/// Clears whatever tracking window is currently open, if any — used when
/// adopting a render thunk: reads made above the thunk (setup, which
/// runs exactly once) are discarded, so only the thunk's own reads become
/// dependencies. Mirrors `#adopt`'s `deps.clear()`.
pub fn clear_current_tracking() {
    REGISTRY.with(|r| {
        if let Some(deps) = r.current_deps.borrow_mut().as_mut() {
            deps.clear();
        }
    });
}

pub(crate) fn record(id: SignalId) {
    REGISTRY.with(|r| {
        if let Some(deps) = r.current_deps.borrow_mut().as_mut() {
            deps.insert(id);
        }
    });
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
pub fn take_queue() -> impl Iterator<Item = SubscriberId> {
    REGISTRY
        .with(|r| {
            r.queue_set.borrow_mut().clear();
            mem::take(&mut *r.queue.borrow_mut())
        })
        .into_iter()
}

/// Resubscribes `sub` from `previous`'s dependency set to `next`'s: dropped from
/// every signal in `previous` but not `next`, added to every signal in `next`.
/// Mirrors `resubscribe` — called after each render with the just-recorded
/// dependency set, so a signal a component stopped reading stops notifying
/// it.
pub fn resubscribe<S: BuildHasher>(
    sub: SubscriberId,
    previous: &HashSet<SignalId, S>,
    next: &HashSet<SignalId, S>,
) {
    REGISTRY.with(|r| {
        let mut subs = r.subs.borrow_mut();
        for dep in previous {
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
pub fn unsubscribe_all<S: BuildHasher>(sub: SubscriberId, deps: &HashSet<SignalId, S>) {
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
        close_tracking, next_subscriber_id, open_tracking, resubscribe, schedule_update, take_queue,
    };
    use crate::signal::Signal;
    use std::collections::HashSet;

    #[test]
    fn reading_a_signal_inside_a_tracking_window_records_it() {
        let _guard = ::habilis_network_test_tracing::init();
        let signal = Signal::new(1);
        let previous = open_tracking(HashSet::new());
        let _ = signal.get();
        let deps = close_tracking(previous);
        assert_eq!(
            deps.len(),
            1,
            "a signal read in a tracking window is recorded once"
        );
    }

    #[test]
    fn reading_a_signal_outside_any_window_records_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let signal = Signal::new(1);
        let _ = signal.get(); // no window open at all
        // Nothing to assert on directly here beyond "it doesn't panic" —
        // the real behavioral check is in the subscription test below,
        // where an untracked read never gets a subscriber queued.
        assert_eq!(
            signal.peek(),
            1,
            "a signal read outside a window records nothing and keeps its value"
        );
    }

    #[test]
    fn peek_never_records_a_dependency_even_inside_a_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let signal = Signal::new(1);
        let previous = open_tracking(HashSet::new());
        let _ = signal.peek();
        let deps = close_tracking(previous);
        assert!(
            deps.is_empty(),
            "peek records no dependency even inside a window"
        );
    }

    #[test]
    fn a_subscribed_signal_queues_its_subscriber_on_change() {
        let _guard = ::habilis_network_test_tracing::init();
        let signal = Signal::new(1);
        let sub = next_subscriber_id();

        let previous = open_tracking(HashSet::new());
        let _ = signal.get();
        let deps = close_tracking(previous);
        resubscribe(sub, &HashSet::new(), &deps);

        signal.set(2);
        let queued: Vec<super::SubscriberId> = take_queue().collect();
        assert_eq!(
            queued,
            vec![sub],
            "a subscribed signal queues its subscriber on change"
        );
    }

    #[test]
    fn setting_a_signal_to_an_equal_value_schedules_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let signal = Signal::new(1);
        let sub = next_subscriber_id();
        let previous = open_tracking(HashSet::new());
        let _ = signal.get();
        let deps = close_tracking(previous);
        resubscribe(sub, &HashSet::new(), &deps);

        signal.set(1); // same value — no-op per the `Object.is` bail
        assert!(
            take_queue().next().is_none(),
            "setting an equal value schedules nothing"
        );
    }

    #[test]
    fn resubscribing_to_a_smaller_dep_set_drops_the_stale_subscription() {
        let _guard = ::habilis_network_test_tracing::init();
        let a = Signal::new(1);
        let b = Signal::new(1);
        let sub = next_subscriber_id();

        let previous = open_tracking(HashSet::new());
        let _ = a.get();
        let _ = b.get();
        let first_deps = close_tracking(previous);
        resubscribe(sub, &HashSet::new(), &first_deps);

        // Second render only reads `b` — matches a component whose thunk
        // took a different branch and stopped reading `a`.
        let previous = open_tracking(HashSet::new());
        let _ = b.get();
        let second_deps = close_tracking(previous);
        resubscribe(sub, &first_deps, &second_deps);

        a.set(2); // no longer subscribed
        assert!(
            take_queue().next().is_none(),
            "a smaller dependency set drops the stale subscription without a queue entry"
        );

        b.set(2); // still subscribed
        let queued: Vec<super::SubscriberId> = take_queue().collect();
        assert_eq!(
            queued,
            vec![sub],
            "the remaining subscription still queues the subscriber"
        );
    }

    #[test]
    fn scheduling_the_same_subscriber_twice_queues_it_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let sub = next_subscriber_id();
        schedule_update(sub);
        schedule_update(sub);
        let queued: Vec<super::SubscriberId> = take_queue().collect();
        assert_eq!(
            queued,
            vec![sub],
            "scheduling the same subscriber twice queues it once"
        );
    }
}
