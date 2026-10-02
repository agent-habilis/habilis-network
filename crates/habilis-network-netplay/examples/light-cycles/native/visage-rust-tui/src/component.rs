//! The generator-driven component runtime: a component is a native Rust
//! coroutine (`#![feature(coroutines, coroutine_trait)]`, the bare `yield`
//! keyword — see the crate root) that either produces every view itself
//! (the **loop** shape) or yields a render thunk once and parks (the
//! **thunk** shape) — ported from `visage-dom`'s `Instance`/`#adopt`.
//!
//! A component is written directly with `yield`, no `co.yield_(x).await`
//! indirection:
//!
//! ```ignore
//! Instance::new(#[coroutine] move || {
//!     loop {
//!         yield Yield::View(View::text(format!("count is {}", count.get())));
//!     }
//! })
//! ```
//!
//! Two places this cannot be a faithful 1:1 port of the original, both
//! flagged by the port report and accepted as v1 scope, not oversights:
//! - **No generator-resumed error boundary.** JS's `gen.throw()` resumes a
//!   generator *at its suspension point*, so a lexical `try`/`catch`
//!   around a `yield` acts as one. Rust's `Coroutine` trait has no
//!   analogue; a boundary here would need an explicit `on_error` callback
//!   walked up a parent chain. Not built in v1 — nothing in this crate
//!   needs it yet.
//! - **Dropping the coroutine approximates `gen.return()`'s "unwind
//!   `using` scopes" role**, via ordinary `Drop` on whatever was alive at
//!   its suspension point — not a perfect match (no equivalent of a
//!   `finally` block that itself yields), but correct for the common case
//!   of a guard value that just needs dropping.

use std::collections::HashSet;
use std::ops::{Coroutine, CoroutineState};
use std::pin::Pin;
use std::rc::Rc;

use crate::reactive::{self, SignalId, SubscriberId};
use crate::view::View;

/// What a component yields. Mirrors `#adopt`'s `typeof yielded ===
/// 'function'` classification — Rust has no such runtime check on an
/// arbitrary value, so the two shapes are explicit variants instead of one
/// dynamically-typed one.
pub enum Yield {
    /// The **loop** shape: a plain view. The coroutine remains in control;
    /// resuming it produces the next view.
    View(View),
    /// The **thunk** shape: parks the coroutine. Every subsequent render
    /// calls this closure directly — the coroutine is never resumed again
    /// unless the component is torn down and rebuilt.
    Thunk(Rc<dyn Fn() -> View>),
}

// Hand-written: `Rc<dyn Fn() -> View>` has no `Debug` impl to derive from.
impl std::fmt::Debug for Yield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Yield::View(view) => f.debug_tuple("View").field(view).finish(),
            Yield::Thunk(_) => f.debug_tuple("Thunk").field(&"<closure>").finish(),
        }
    }
}

/// The trait object a component's body coerces to. `Return = ()` — a
/// well-behaved component loops forever and never actually completes; see
/// `Instance::resume_sync` for what happens if one does. `pub`: a
/// component function that yields nested components (see `view::View::
/// component`) returns `Pin<Box<ComponentCoroutine>>`, so callers outside
/// this module need to name the type.
pub type ComponentCoroutine = dyn Coroutine<(), Yield = Yield, Return = ()>;

/// One running component instance.
// `Debug` is hand-written below: `Pin<Box<ComponentCoroutine>>` (a `dyn
// Coroutine`) and `Rc<dyn Fn() -> View>` have no `Debug` to derive from.
pub struct Instance {
    id: SubscriberId,
    finished: bool,
    coro: Pin<Box<ComponentCoroutine>>,
    thunk: Option<Rc<dyn Fn() -> View>>,
    deps: HashSet<SignalId>,
    deps_alt: HashSet<SignalId>,
}

impl Instance {
    /// Builds a component from its coroutine body. Does not render yet —
    /// call [`Instance::mount`] for the first view.
    pub fn new(coro: impl Coroutine<(), Yield = Yield, Return = ()> + 'static) -> Self {
        Self::boxed(Box::pin(coro))
    }

    /// As [`Instance::new`], but for a coroutine a caller has already
    /// boxed — the shape [`crate::view::View::component`]'s builder
    /// produces, since a nested component's concrete coroutine type isn't
    /// nameable at the call site that mounts it.
    #[must_use]
    pub fn boxed(coro: Pin<Box<ComponentCoroutine>>) -> Self {
        Self {
            id: reactive::next_subscriber_id(),
            finished: false,
            coro,
            thunk: None,
            deps: HashSet::new(),
            deps_alt: HashSet::new(),
        }
    }

    #[must_use]
    pub fn subscriber_id(&self) -> SubscriberId {
        self.id
    }

    /// First render.
    pub fn mount(&mut self) -> Option<View> {
        self.resume_sync()
    }

    /// Re-renders: calls the parked thunk directly if there is one,
    /// otherwise resumes the coroutine and classifies what it yields.
    /// `None` means the component's coroutine returned — not expected of
    /// a well-behaved component (which loops forever), but not a panic
    /// either; the caller simply stops re-rendering it.
    pub fn render(&mut self) -> Option<View> {
        self.resume_sync()
    }

    fn resume_sync(&mut self) -> Option<View> {
        let mut deps = std::mem::take(&mut self.deps_alt);
        deps.clear();
        let prev = reactive::open_tracking(deps);

        let thunk = self.thunk.clone();
        let view = if let Some(thunk) = thunk {
            Some(thunk())
        } else {
            match self.coro.as_mut().resume(()) {
                CoroutineState::Yielded(yielded) => Some(self.adopt(yielded)),
                CoroutineState::Complete(()) => None,
            }
        };

        let deps = reactive::close_tracking(prev);
        reactive::resubscribe(self.id, &self.deps, &deps);
        self.deps_alt = std::mem::replace(&mut self.deps, deps);

        if view.is_none() {
            self.finished = true;
            reactive::unsubscribe_all(self.id, &self.deps);
        }
        view
    }

    /// Classifies a freshly-yielded value. Adopting a thunk clears the
    /// tracking window *first*: reads made above the yield (setup, which
    /// runs exactly once) are not dependencies — rerunning setup would
    /// always reproduce the same view — only the thunk's own reads are.
    fn adopt(&mut self, yielded: Yield) -> View {
        match yielded {
            Yield::View(view) => {
                self.thunk = None;
                view
            }
            Yield::Thunk(thunk) => {
                self.thunk = Some(Rc::clone(&thunk));
                reactive::clear_current_tracking();
                thunk()
            }
        }
    }
}

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instance")
            .field("id", &self.id)
            .field("finished", &self.finished)
            .field("parked", &self.thunk.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{Instance, Yield};
    use crate::reactive::Signal;
    use crate::view::View;

    #[test]
    fn a_loop_component_re_renders_from_the_coroutine_on_every_resume() {
        let count = Signal::new(0);
        let count_in_component = count.clone();
        let mut instance = Instance::new(
            #[coroutine]
            move || {
                loop {
                    let n = count_in_component.get();
                    yield Yield::View(View::text(format!("count is {n}")));
                }
            },
        );

        let View::Text(first) = instance.mount().unwrap() else {
            panic!("expected text");
        };
        assert_eq!(&*first, "count is 0");

        count.set(5);
        let View::Text(second) = instance.render().unwrap() else {
            panic!("expected text");
        };
        assert_eq!(&*second, "count is 5");
    }

    #[test]
    fn a_thunk_component_parks_and_is_called_directly_on_rerender() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let count = Signal::new(0);
        let count_in_component = count.clone();
        let resumes = Rc::new(RefCell::new(0));
        let resumes_in_component = Rc::clone(&resumes);
        let mut instance = Instance::new(
            #[coroutine]
            move || {
                *resumes_in_component.borrow_mut() += 1; // setup: runs once
                yield Yield::Thunk(Rc::new(move || {
                    View::text(format!("count is {}", count_in_component.get()))
                }));
                unreachable!("a parked thunk component is never resumed again");
            },
        );

        let View::Text(first) = instance.mount().unwrap() else {
            panic!("expected text");
        };
        assert_eq!(&*first, "count is 0");
        assert_eq!(*resumes.borrow(), 1);

        count.set(1);
        let View::Text(second) = instance.render().unwrap() else {
            panic!("expected text");
        };
        assert_eq!(&*second, "count is 1");
        // Setup never ran again — the coroutine itself was never resumed.
        assert_eq!(*resumes.borrow(), 1);
    }
}
