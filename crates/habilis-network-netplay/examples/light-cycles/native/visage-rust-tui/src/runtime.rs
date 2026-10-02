//! Ties [`reactive`], [`component`], [`reconcile`], and a [`Host`]
//! together into a running app. The root is mounted the same way any
//! nested [`crate::view::View::component`] is — a
//! [`reconcile::ComponentMount`] — so [`Runtime::tick`]'s dirty-set walk
//! treats the whole tree uniformly: whichever instance's own signal
//! changed is the one that re-renders, root or nested, ancestor or leaf.

use std::collections::HashSet;
use std::ops::Coroutine;

use crate::component::Yield;
use crate::host::Host;
use crate::reactive::{self, SubscriberId};
use crate::reconcile::{self, Mounted};
use crate::tui;

/// A running app.
// No `Debug` derive: it would force a `H: Debug` bound onto every `Host`
// backend for a trace nobody's asked for yet. Add one (manual, printing
// the instance and node count) if a debugging need actually shows up.
#[allow(missing_debug_implementations)]
pub struct Runtime<H: Host> {
    host: H,
    root: H::Node,
    mounted: Mounted<H::Node>,
}

impl<H: Host> Runtime<H> {
    /// Mounts `coro` as the root component and does the first render.
    pub fn new(
        mut host: H,
        root: H::Node,
        coro: impl Coroutine<(), Yield = Yield, Return = ()> + 'static,
    ) -> Self {
        let mounted = reconcile::mount_root(&mut host, root, coro);
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
        std::mem::replace(&mut self.mounted, Mounted::Hole(self.root))
    }
}

impl Runtime<tui::host_impl::TuiHost> {
    /// Convenience for the terminal backend: builds a `TuiHost`, creates
    /// its root node, and mounts `coro` — the one-liner a real terminal
    /// app calls.
    pub fn terminal(coro: impl Coroutine<(), Yield = Yield, Return = ()> + 'static) -> Self {
        let mut host = tui::host_impl::TuiHost::new();
        let root = host.create_root();
        Self::new(host, root, coro)
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
    use super::render_frame;
    use crate::component::Yield;
    use crate::reactive::Signal;
    use crate::runtime::Runtime;
    use crate::tui::layout::LayoutState;
    use crate::view::{BoxProps, View};

    #[test]
    fn a_running_app_repaints_only_after_a_signal_changes() {
        let count = Signal::new(0);
        let count_in_component = count.clone();
        let mut app = Runtime::terminal(
            #[coroutine]
            move || {
                loop {
                    let n = count_in_component.get();
                    yield Yield::View(View::boxed(
                        BoxProps::default(),
                        vec![View::text(format!("count is {n}"))],
                    ));
                }
            },
        );

        let mut layout_state = LayoutState::new();
        let (first_bytes, first_buffer) = render_frame(&mut app, &mut layout_state, None, 20, 1);
        assert!(first_bytes.contains("count is 0"));
        assert_eq!(row_text(&first_buffer).trim_end(), "count is 0");

        // No signal change: tick reports nothing to repaint.
        assert!(!app.tick());

        count.set(9);
        assert!(app.tick());
        // The diff against `first_buffer` is deliberately minimal — only
        // the changed digit is re-emitted, not the whole string — so the
        // real assertion is against the freshly painted buffer, not the
        // diff bytes.
        let (second_bytes, second_buffer) =
            render_frame(&mut app, &mut layout_state, Some(&first_buffer), 20, 1);
        assert!(second_bytes.contains('9'));
        assert!(!second_bytes.contains("count is 9")); // the unchanged prefix is not re-emitted
        assert_eq!(row_text(&second_buffer).trim_end(), "count is 9");
    }

    #[test]
    fn a_nested_components_own_signal_change_never_re_renders_its_parent() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let parent_renders = Rc::new(RefCell::new(0));
        let child_count = Signal::new(0);

        let parent_renders_in_component = Rc::clone(&parent_renders);
        let child_count_for_child = child_count.clone();
        let mut app = Runtime::terminal(
            #[coroutine]
            move || {
                loop {
                    *parent_renders_in_component.borrow_mut() += 1;
                    let child_count_for_child = child_count_for_child.clone();
                    yield Yield::View(View::boxed(
                        BoxProps::default(),
                        vec![View::component(child_component, child_count_for_child)],
                    ));
                }
            },
        );

        let mut layout_state = LayoutState::new();
        let (_bytes, buffer) = render_frame(&mut app, &mut layout_state, None, 20, 1);
        assert_eq!(*parent_renders.borrow(), 1);
        assert_eq!(row_text(&buffer).trim_end(), "child sees 0");

        // The CHILD's own signal changes — the parent's coroutine must
        // not be resumed again; only the child re-renders.
        child_count.set(7);
        assert!(app.tick());
        assert_eq!(
            *parent_renders.borrow(),
            1,
            "parent re-rendered when only the child's signal changed"
        );

        let (_bytes, new_buffer) = render_frame(&mut app, &mut layout_state, Some(&buffer), 20, 1);
        assert_eq!(row_text(&new_buffer).trim_end(), "child sees 7");
    }

    fn child_component(
        count: Signal<i32>,
    ) -> std::pin::Pin<Box<crate::component::ComponentCoroutine>> {
        Box::pin(
            #[coroutine]
            move || {
                loop {
                    let n = count.get();
                    yield Yield::View(View::text(format!("child sees {n}")));
                }
            },
        )
    }

    fn row_text(buffer: &crate::tui::paint::ScreenBuffer) -> String {
        buffer
            .chars
            .iter()
            .map(|cell| if cell.is_empty() { "" } else { cell.as_str() })
            .collect()
    }
}
