use crate::reactive::{REGISTRY, next_signal_id, record, schedule_update};
use crate::signal_inner::SignalInner;
use crate::subscriber_id::SubscriberId;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;

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
pub struct Signal<T>(pub(crate) Rc<SignalInner<T>>);

// Hand-written rather than derived: deriving would require `T: Debug` *and*
// print the value, which needs a borrow this type otherwise never exposes
// by reference (`get`/`peek` both return owned clones). Printing the id is
// enough to distinguish signals in a debug trace.
impl<T> fmt::Debug for Signal<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    pub(crate) fn notify(&self) {
        let subscribers: Vec<SubscriberId> = REGISTRY.with(|r| {
            let subs = r.subs.borrow();
            let found = subs.get(self.0.id.0 as usize);
            let members: Option<Vec<SubscriberId>> = found.map(|set| set.iter().copied().collect());
            members.unwrap_or_default()
        });
        for sub in subscribers {
            schedule_update(sub);
        }
    }
}
