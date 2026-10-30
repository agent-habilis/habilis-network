//! Ties [`reactive`], [`component`], [`reconcile`], and a [`Host`]
//! together into a running app. The root is mounted the same way any
//! nested [`crate::view::View::component`] is — a
//! [`reconcile::ComponentMount`] — so [`Runtime::tick`]'s dirty-set walk
//! treats the whole tree uniformly: whichever instance's own signal
//! changed is the one that re-renders, root or nested, ancestor or leaf.

use crate::component::Component;
use crate::host::Host;
use crate::reactive::{self, SubscriberId};
use crate::reconcile::{self, Mounted};
use crate::tui;
use std::collections::HashSet;

use std::{fmt, mem};

/// A running app.
pub struct Runtime<H: Host> {
    host: H,
    root: H::Node,
    mounted: Mounted<H::Node>,
}

// Manual, so a `Host` backend need not implement `Debug` to make a `Runtime` printable.
impl<H: Host> fmt::Debug for Runtime<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Runtime").finish_non_exhaustive()
    }
}

impl<H: Host> Runtime<H> {
    /// Mounts `component` as the root component and does the first render.
    pub fn new(mut host: H, root: H::Node, component: impl Component + 'static) -> Self {
        let mounted = reconcile::mount_root(&mut host, root, component);
        Self {
            host,
            root,
            mounted,
        }
    }

    #[must_use]
    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Re-renders and patches whichever instances (root, nested, or both)
    /// have a signal change queued since the last call — see the module
    /// doc. Returns whether anything was queued at all, i.e. whether a
    /// repaint might be needed.
    pub fn tick(&mut self) -> bool {
        let dirty: HashSet<SubscriberId> = reactive::take_queue().into_iter().collect();
        if dirty.is_empty() {
            return false;
        }
        let old = self.take_mounted();
        self.mounted = reconcile::patch_dirty(&mut self.host, self.root, old, &dirty);
        true
    }

    fn take_mounted(&mut self) -> Mounted<H::Node> {
        // `Mounted` has no `Default`/empty state to swap in temporarily,
        // so this exists to move it out of `&mut self` for `patch_dirty`'s
        // by-value signature without a placeholder allocation.
        mem::replace(&mut self.mounted, Mounted::Hole(self.root))
    }
}

impl Runtime<tui::host_impl::TuiHost> {
    /// Convenience for the terminal backend: builds a `TuiHost`, creates
    /// its root node, and mounts `component` — the one-liner a real terminal
    /// app calls.
    pub fn terminal(component: impl Component + 'static) -> Self {
        let mut host = tui::host_impl::TuiHost::new();
        let root = host.create_root();
        Self::new(host, root, component)
    }
}

/// The sequencing a real terminal app uses each frame: layout (needs
/// `&mut` for the measure cache), then paint (read-only), then diff
/// against the previous frame (`None` on the first call). A free function
/// rather than a `Runtime` method, because layout needs `&mut
/// runtime.host_mut().arena` while paint only needs `&runtime.host().arena`
/// — a method taking `&mut self` throughout would over-borrow for no
/// reason paint actually needs.
pub fn render_frame(
    runtime: &mut Runtime<tui::host_impl::TuiHost>,
    layout_state: &mut tui::layout::LayoutState,
    previous: Option<&tui::paint::ScreenBuffer>,
    width: i32,
    height: i32,
) -> (String, tui::paint::ScreenBuffer) {
    let root = runtime.root;
    layout_state.layout(&mut runtime.host_mut().arena, root, width, height);
    let mut buffer = tui::paint::ScreenBuffer::new(width, height);
    tui::paint::paint(&mut buffer, &runtime.host().arena, root);
    let bytes = tui::diff::diff(previous, &buffer);
    (bytes, buffer)
}

#[cfg(test)]
mod tests {
    use crate::component::{Component, Step};
    use crate::reactive::Signal;
    use crate::runtime::Runtime;
    use crate::tui::layout::LayoutState;
    use crate::view::{BoxProps, View};

    use crate::component;
    use crate::tui::paint;
    use std::{cell, rc};
    struct Counter(Signal<i32>);

    impl Component for Counter {
        fn step(&mut self) -> Option<Step> {
            let n = self.0.get();
            Some(Step::View(View::boxed(
                BoxProps::default(),
                vec![View::text(&format!("count is {n}"))],
            )))
        }
    }

    #[test]
    fn a_running_app_repaints_only_after_a_signal_changes() {
        let _guard = ::habilis_network_test_tracing::init();
        let count = Signal::new(0);
        let mut app = Runtime::terminal(Counter(count.clone()));

        let mut layout_state = LayoutState::new();
        let (first_bytes, first_buffer) =
            super::render_frame(&mut app, &mut layout_state, None, 20, 1);
        assert!(
            first_bytes.contains("count is 0"),
            "the first frame shows the initial count"
        );
        assert_eq!(
            row_text(&first_buffer).trim_end(),
            "count is 0",
            "the first buffer reads count is 0"
        );

        // No signal change: tick reports nothing to repaint.
        assert!(!app.tick(), "no repaint happens before a signal changes");

        count.set(9);
        assert!(app.tick(), "a repaint happens after a signal changes");
        // The diff against `first_buffer` is deliberately minimal — only
        // the changed digit is re-emitted, not the whole string — so the
        // real assertion is against the freshly painted buffer, not the
        // diff bytes.
        let (second_bytes, second_buffer) =
            super::render_frame(&mut app, &mut layout_state, Some(&first_buffer), 20, 1);
        assert!(
            second_bytes.contains('9'),
            "the second frame shows the changed digit"
        );
        assert!(
            !second_bytes.contains("count is 9"),
            "the second frame does not show the old count"
        ); // the unchanged prefix is not re-emitted
        assert_eq!(
            row_text(&second_buffer).trim_end(),
            "count is 9",
            "the second buffer reads the new count"
        );
    }

    struct Parent {
        renders: rc::Rc<cell::RefCell<i32>>,
        child_count: Signal<i32>,
    }

    impl Component for Parent {
        fn step(&mut self) -> Option<Step> {
            *self.renders.borrow_mut() += 1;
            let child_count = self.child_count.clone();
            Some(Step::View(View::boxed(
                BoxProps::default(),
                vec![View::component(child_component, child_count)],
            )))
        }
    }

    #[test]
    fn a_nested_components_own_signal_change_never_re_renders_its_parent() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let _guard = ::habilis_network_test_tracing::init();
        let parent_renders = Rc::new(RefCell::new(0));
        let child_count = Signal::new(0);

        let mut app = Runtime::terminal(Parent {
            renders: Rc::clone(&parent_renders),
            child_count: child_count.clone(),
        });

        let mut layout_state = LayoutState::new();
        let (_bytes, buffer) = super::render_frame(&mut app, &mut layout_state, None, 20, 1);
        assert_eq!(
            *parent_renders.borrow(),
            1,
            "the parent renders only on the first frame"
        );
        assert_eq!(
            row_text(&buffer).trim_end(),
            "child sees 0",
            "the nested buffer shows the updated child text"
        );

        // The CHILD's own signal changes — the parent must not be stepped
        // again; only the child re-renders.
        child_count.set(7);
        assert!(app.tick(), "the tick after the child change repaints");
        assert_eq!(
            *parent_renders.borrow(),
            1,
            "parent re-rendered when only the child's signal changed"
        );

        let (_bytes, new_buffer) =
            super::render_frame(&mut app, &mut layout_state, Some(&buffer), 20, 1);
        assert_eq!(
            row_text(&new_buffer).trim_end(),
            "child sees 7",
            "the new buffer shows the updated text"
        );
    }

    struct Child(Signal<i32>);

    impl Component for Child {
        fn step(&mut self) -> Option<Step> {
            Some(Step::View(View::text(&format!(
                "child sees {}",
                self.0.get()
            ))))
        }
    }

    fn child_component(count: Signal<i32>) -> component::ComponentBox {
        Box::new(Child(count))
    }

    fn row_text(buffer: &paint::ScreenBuffer) -> String {
        buffer
            .chars
            .iter()
            .map(|cell| if cell.is_empty() { "" } else { cell.as_str() })
            .collect()
    }
}
