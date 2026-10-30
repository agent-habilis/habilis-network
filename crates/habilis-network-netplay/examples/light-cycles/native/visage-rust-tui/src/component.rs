//! The component runtime: a component is a value that the runtime steps. It
//! either produces every view itself (the **loop** shape) or returns a render
//! thunk once and parks (the **thunk** shape) — ported from `visage-dom`'s
//! `Instance`/`#adopt`.
//!
//! A component implements [`Component`]. Its `step` returns the next [`Step`].
//! A component with more than one step keeps its position in a `Phase` enum,
//! and `step` is a match on it:
//!
//! ```ignore
//! struct Count(Signal<i32>);
//!
//! impl Component for Count {
//!     fn step(&mut self) -> Option<Step> {
//!         Some(Step::View(View::text(format!("count is {}", self.0.get()))))
//!     }
//! }
//! ```
//!
//! Two places this cannot be a faithful 1:1 port of the original, both
//! accepted as v1 scope, not oversights:
//! - **No error boundary.** JS's `gen.throw()` resumes a generator at its
//!   suspension point, so a `try`/`catch` around a `yield` acts as one. A
//!   component has no such resume point; a boundary would need an explicit
//!   `on_error` callback walked up a parent chain. Nothing in this crate
//!   needs it yet.
//! - **Dropping a component approximates `gen.return()`**: ordinary `Drop`
//!   runs on its fields. That is correct for a guard value that just needs
//!   dropping, but there is no equivalent of a `finally` block that itself
//!   produces a step.

use std::collections::HashSet;
use std::rc::Rc;

use crate::reactive::{self, SignalId, SubscriberId};
use crate::view::View;

use std::{fmt, mem};
/// What a component produces. Mirrors `#adopt`'s `typeof yielded ===
/// 'function'` classification — Rust has no such runtime check on an
/// arbitrary value, so the two shapes are explicit variants instead of one
/// dynamically-typed one.
pub enum Step {
    /// The **loop** shape: a plain view. The component stays in control; the
    /// next step produces the next view.
    View(View),
    /// The **thunk** shape: parks the component. Every subsequent render
    /// calls this closure directly — `step` is never called again unless the
    /// component is torn down and rebuilt.
    Thunk(Rc<dyn Fn() -> View>),
}

// Hand-written: `Rc<dyn Fn() -> View>` has no `Debug` impl to derive from.
impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::View(view) => {
                let mut tuple = f.debug_tuple("View");
                tuple.field(view);
                tuple.finish()
            }
            Step::Thunk(_) => {
                let mut tuple = f.debug_tuple("Thunk");
                tuple.field(&"<closure>");
                tuple.finish()
            }
        }
    }
}

/// A component: the runtime calls `step` for each render. `None` means the
/// component is finished. A well-behaved component never returns it, since it
/// loops forever; see `Instance::resume_sync` for what happens if one does.
pub trait Component {
    fn step(&mut self) -> Option<Step>;
}

/// A boxed component, the shape a nested component's builder produces, since
/// its concrete type isn't nameable at the call site that mounts it.
pub type ComponentBox = Box<dyn Component>;

/// One running component instance.
// `Debug` is hand-written below: `Rc<dyn Fn() -> View>` has no `Debug` to
// derive from.
pub struct Instance {
    id: SubscriberId,
    finished: bool,
    component: ComponentBox,
    thunk: Option<Rc<dyn Fn() -> View>>,
    deps: HashSet<SignalId>,
    deps_alt: HashSet<SignalId>,
}

impl Instance {
    /// Builds a component. Does not render yet — call [`Instance::mount`] for
    /// the first view.
    pub fn new(component: impl Component + 'static) -> Self {
        Self::boxed(Box::new(component))
    }

    /// As [`Instance::new`], for a component a caller has already boxed.
    #[must_use]
    pub fn boxed(component: ComponentBox) -> Self {
        Self {
            id: reactive::next_subscriber_id(),
            finished: false,
            component,
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

    /// Re-renders: calls the parked thunk directly if there is one, otherwise
    /// steps the component and classifies what it produces. `None` means the
    /// component finished — not expected of a well-behaved component (which
    /// loops forever), but not a panic either; the caller simply stops
    /// re-rendering it.
    pub fn render(&mut self) -> Option<View> {
        self.resume_sync()
    }

    fn resume_sync(&mut self) -> Option<View> {
        let mut deps = mem::take(&mut self.deps_alt);
        deps.clear();
        let prev = reactive::open_tracking(deps);

        let thunk = self.thunk.clone();
        let view = if let Some(thunk) = thunk {
            Some(thunk())
        } else {
            self.component.step().map(|step| self.adopt(step))
        };

        let deps = reactive::close_tracking(prev);
        reactive::resubscribe(self.id, &self.deps, &deps);
        self.deps_alt = mem::replace(&mut self.deps, deps);

        if view.is_none() {
            self.finished = true;
            reactive::unsubscribe_all(self.id, &self.deps);
        }
        view
    }

    /// Classifies a freshly-produced step. Adopting a thunk clears the
    /// tracking window *first*: reads made above the thunk (setup, which runs
    /// exactly once) are not dependencies — rerunning setup would always
    /// reproduce the same view — only the thunk's own reads are.
    fn adopt(&mut self, step: Step) -> View {
        match step {
            Step::View(view) => {
                self.thunk = None;
                view
            }
            Step::Thunk(thunk) => {
                self.thunk = Some(Rc::clone(&thunk));
                reactive::clear_current_tracking();
                thunk()
            }
        }
    }
}

impl fmt::Debug for Instance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Instance");
        debug
            .field("id", &self.id)
            .field("finished", &self.finished);
        debug
            .field("parked", &self.thunk.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{Component, Instance, Step};
    use crate::reactive::Signal;
    use crate::view::View;

    use std::{cell, rc};
    struct Shown(Signal<i32>);

    impl Component for Shown {
        fn step(&mut self) -> Option<Step> {
            Some(Step::View(View::text(format!("count is {}", self.0.get()))))
        }
    }

    #[test]
    fn a_loop_component_re_renders_on_every_step() {
        let _guard = ::habilis_network_test_tracing::init();
        let count = Signal::new(0);
        let mut instance = Instance::new(Shown(count.clone()));

        let View::Text(first) = instance
            .mount()
            .expect("the test component mounts without a failing step")
        else {
            panic!("expected text");
        };
        assert_eq!(
            &*first, "count is 0",
            "the first render of a loop component shows count 0"
        );

        count.set(5);
        let View::Text(second) = instance
            .render()
            .expect("the test component renders without a failing step")
        else {
            panic!("expected text");
        };
        assert_eq!(
            &*second, "count is 5",
            "a resumed loop component renders count 5"
        );
    }

    enum ParkedPhase {
        Setup,
        Parked,
    }

    struct Parked {
        count: Signal<i32>,
        resumes: rc::Rc<cell::RefCell<i32>>,
        phase: ParkedPhase,
    }

    impl Component for Parked {
        fn step(&mut self) -> Option<Step> {
            match self.phase {
                ParkedPhase::Setup => {
                    *self.resumes.borrow_mut() += 1; // setup: runs once
                    self.phase = ParkedPhase::Parked;
                    let count = self.count.clone();
                    Some(Step::Thunk(rc::Rc::new(move || {
                        View::text(format!("count is {}", count.get()))
                    })))
                }
                ParkedPhase::Parked => {
                    unreachable!("a parked thunk component is never resumed again")
                }
            }
        }
    }

    #[test]
    fn a_thunk_component_parks_and_is_called_directly_on_rerender() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let _guard = ::habilis_network_test_tracing::init();
        let count = Signal::new(0);
        let resumes = Rc::new(RefCell::new(0));
        let mut instance = Instance::new(Parked {
            count: count.clone(),
            resumes: Rc::clone(&resumes),
            phase: ParkedPhase::Setup,
        });

        let View::Text(first) = instance
            .mount()
            .expect("the test component mounts without a failing step")
        else {
            panic!("expected text");
        };
        assert_eq!(
            &*first, "count is 0",
            "the first render of a thunk component shows count 0"
        );
        assert_eq!(
            *resumes.borrow(),
            1,
            "the thunk component steps once on the first render"
        );

        count.set(1);
        let View::Text(second) = instance
            .render()
            .expect("the test component renders without a failing step")
        else {
            panic!("expected text");
        };
        assert_eq!(
            &*second, "count is 1",
            "the rerender of the thunk component shows count 1"
        );
        // Setup never ran again — the component itself was never stepped.
        assert_eq!(
            *resumes.borrow(),
            1,
            "the thunk component still stepped only once after rerender"
        );
    }
}
