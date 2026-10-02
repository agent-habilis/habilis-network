//! Patches a [`Host`] tree to match a new [`View`], reusing nodes where
//! the shape matches — including nested **components**, each its own
//! independent [`Instance`], re-rendered only when its own signal changes
//! (see [`patch_dirty`]), not whenever an ancestor happens to re-render.
//!
//! Every function here takes `View` by value, never by reference: a
//! `Component` owns a one-shot `FnOnce` builder that can only ever be
//! consumed, not read through a shared reference, so there is no
//! borrowed-`View` variant of `mount`/`patch` to have alongside the owned
//! one — only one, uniformly owned, path exists.
//!
//! Deliberately **not** a port of `visage-dom`'s fiber/patch system (fiber
//! kinds, keyed-list diffing via longest-increasing-subsequence, moves) —
//! that machinery is explicitly out of v1 scope per the plan's
//! `visage-rust-tui` section ("keyed-list reconciliation edge cases... not
//! v1 here"). Sibling lists are matched **positionally**: index `i` of the
//! new view patches index `i` of the old one if both exist, a longer new
//! list mounts the extra tail fresh, a shorter one unmounts the old tail.
//! A reordered list therefore remounts rather than moves — correct, not
//! optimal, fine for a grid + HUD whose structure is mostly static.

use std::collections::HashSet;
use std::ops::Coroutine;
use std::rc::Rc;

use crate::component::{Instance, Yield};
use crate::host::Host;
use crate::reactive::SubscriberId;
use crate::view::{BoxProps, ComponentView, View};

/// One mounted component: its own running [`Instance`], and the subtree
/// its own last render produced. Components introduce no host node of
/// their own — `child` is what actually occupies this position in the
/// tree, exactly as `visage-dom`'s `comp` fiber is transparent and
/// `domOf` walks straight through to its child.
pub struct ComponentMount<N> {
    id: SubscriberId,
    type_key: usize,
    instance: Instance,
    child: Box<Mounted<N>>,
}

// Hand-written rather than derived: deriving would require `N: Debug`, a
// bound this type otherwise has no reason to carry (a `Host::Node` like
// `NodeId` happens to implement it, but nothing here should depend on
// that).
impl<N> std::fmt::Debug for ComponentMount<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComponentMount")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The host-tree shadow of a [`View`], remembered so the next render knows
/// what shape (and, for `Component`, *which* instance) produced each
/// node — the minimum a non-keyed reconciler needs to decide "patch in
/// place" vs "replace".
pub enum Mounted<N> {
    Text(N, Rc<str>),
    Box(N, BoxProps, Vec<Mounted<N>>),
    Hole(N),
    Component(ComponentMount<N>),
}

// Hand-written for the same reason as `ComponentMount`'s: no need to
// require `N: Debug` just for a trace.
impl<N> std::fmt::Debug for Mounted<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mounted::Text(_, text) => f.debug_tuple("Text").field(text).finish(),
            Mounted::Box(_, props, children) => f
                .debug_tuple("Box")
                .field(props)
                .field(&children.len())
                .finish(),
            Mounted::Hole(_) => write!(f, "Hole"),
            Mounted::Component(c) => f.debug_tuple("Component").field(c).finish(),
        }
    }
}

/// The host node a `Mounted` subtree actually starts at — for `Component`,
/// its child's, recursively, since a component is transparent.
fn node_of<N: Copy>(mounted: &Mounted<N>) -> N {
    match mounted {
        Mounted::Text(n, _) | Mounted::Box(n, _, _) | Mounted::Hole(n) => *n,
        Mounted::Component(c) => node_of(&c.child),
    }
}

/// Mounts `view` fresh under `parent`, immediately before `before`.
pub fn mount<H: Host>(
    host: &mut H,
    parent: H::Node,
    before: Option<H::Node>,
    view: View,
) -> Mounted<H::Node> {
    match view {
        View::Text(text) => {
            let node = host.create_text(&text);
            host.insert(parent, node, before);
            Mounted::Text(node, text)
        }
        View::Box(props, children) => {
            let node = host.create_box(&props);
            host.insert(parent, node, before);
            let mounted_children = children
                .into_iter()
                .map(|child| mount(host, node, None, child))
                .collect();
            Mounted::Box(node, props, mounted_children)
        }
        View::Hole => {
            let node = host.create_hole();
            host.insert(parent, node, before);
            Mounted::Hole(node)
        }
        View::Component(comp) => mount_component(host, parent, before, comp),
    }
}

/// Constructs and mounts a nested component from an owned [`ComponentView`]
/// — the one path that actually calls its builder.
fn mount_component<H: Host>(
    host: &mut H,
    parent: H::Node,
    before: Option<H::Node>,
    comp: ComponentView,
) -> Mounted<H::Node> {
    let ComponentView { type_key, build } = comp;
    let mut instance = Instance::boxed(build());
    let id = instance.subscriber_id();
    let view = instance.mount().unwrap_or(View::Hole);
    let child = Box::new(mount(host, parent, before, view));
    Mounted::Component(ComponentMount {
        id,
        type_key,
        instance,
        child,
    })
}

/// Mounts the tree's root component directly from a coroutine, with no
/// parent to ever compare identity against — unlike a nested
/// [`ComponentView`] (built via [`View::component`]), the root is never
/// re-mounted-vs-reused by a `patch` call, so it needs no `type_key` and
/// no props-capturing builder indirection.
///
/// [`View::component`]: crate::view::View::component
///
/// # Panics
///
/// If the root component's coroutine completes instead of yielding on its
/// very first resume — every real component loops forever, so this would
/// indicate a broken coroutine body, not a normal outcome.
pub fn mount_root<H: Host>(
    host: &mut H,
    root: H::Node,
    coro: impl Coroutine<(), Yield = Yield, Return = ()> + 'static,
) -> Mounted<H::Node> {
    let mut instance = Instance::new(coro);
    let id = instance.subscriber_id();
    let view = instance
        .mount()
        .expect("the root component must yield a view on mount");
    let child = Box::new(mount(host, root, None, view));
    Mounted::Component(ComponentMount {
        id,
        type_key: 0,
        instance,
        child,
    })
}

/// Tears down a mounted subtree. For a `Component`, dropping its
/// `Instance` (via `ComponentMount`'s own field, once this whole value is
/// dropped) is what approximates `gen.return()`'s cleanup role — see
/// `component.rs`'s module doc.
pub fn unmount<H: Host>(host: &mut H, mounted: &Mounted<H::Node>) {
    match mounted {
        Mounted::Component(c) => unmount(host, &c.child),
        Mounted::Text(..) | Mounted::Box(..) | Mounted::Hole(_) => host.remove(node_of(mounted)),
    }
}

/// Patches `old` to match `view`, reusing its node(s) when the shape
/// (variant, and for `Component` the component identity — see
/// [`View::component`](crate::view::View::component)) matches, replacing
/// otherwise. For a `Component` that *is* reused, the new `ComponentView`'s
/// builder is simply dropped unused: reuse means keeping the already-
/// running instance and its own state exactly as it was, not feeding it
/// anything from this render (v1 has no live-props channel — see the
/// crate's port-report notes).
pub fn patch<H: Host>(
    host: &mut H,
    parent: H::Node,
    old: Mounted<H::Node>,
    view: View,
) -> Mounted<H::Node> {
    match (old, view) {
        (Mounted::Text(node, prev_text), View::Text(next_text)) => {
            if prev_text.as_ref() != next_text.as_ref() {
                host.set_text(node, &next_text);
            }
            Mounted::Text(node, next_text)
        }
        (Mounted::Box(node, prev_props, prev_children), View::Box(next_props, next_children)) => {
            if prev_props != next_props {
                host.set_box_props(node, &next_props);
            }
            let children = patch_children(host, node, prev_children, next_children);
            Mounted::Box(node, next_props, children)
        }
        (Mounted::Hole(node), View::Hole) => Mounted::Hole(node),
        (Mounted::Component(old_comp), View::Component(new_comp))
            if old_comp.type_key == new_comp.type_key =>
        {
            // Same slot, same component: keep the running instance as-is.
            Mounted::Component(old_comp)
        }
        (old, view) => {
            // Shape (or component identity) changed: replace in place —
            // mount the new node right before whatever used to follow the
            // old one, then remove it.
            let before = host.next_sibling(node_of(&old));
            unmount(host, &old);
            mount(host, parent, before, view)
        }
    }
}

fn patch_children<H: Host>(
    host: &mut H,
    parent: H::Node,
    old_children: Vec<Mounted<H::Node>>,
    new_children: Vec<View>,
) -> Vec<Mounted<H::Node>> {
    let mut old_iter = old_children.into_iter();
    let mut result = Vec::with_capacity(new_children.len());
    for view in new_children {
        match old_iter.next() {
            Some(old_child) => result.push(patch(host, parent, old_child, view)),
            None => result.push(mount(host, parent, None, view)),
        }
    }
    for leftover in old_iter {
        unmount(host, &leftover);
    }
    result
}

/// Walks the whole mounted tree once, re-rendering and re-patching only
/// the components whose id is in `dirty` — the rest of the tree, and any
/// component not in `dirty`, is left completely untouched. This is what
/// makes children "yield independently": a leaf component's own signal
/// write re-renders *only* that component, never an ancestor.
///
/// A full tree walk every call rather than a cursor straight to the dirty
/// node(s) — simpler, and for a game HUD's tree size the walk itself costs
/// nothing next to the render/paint/diff work already happening every
/// tick. `dirty` membership is what keeps the *work* (calling `render()`)
/// proportional to what actually changed, which is the property that
/// matters.
pub fn patch_dirty<H: Host>(
    host: &mut H,
    parent: H::Node,
    mounted: Mounted<H::Node>,
    dirty: &HashSet<SubscriberId>,
) -> Mounted<H::Node> {
    match mounted {
        Mounted::Component(mut comp) => {
            if dirty.contains(&comp.id)
                && let Some(view) = comp.instance.render()
            {
                let old_child = *comp.child;
                // `patch` already handles every case a re-rendered
                // instance's new view can present against its previous
                // child: same shape (including a nested Component whose
                // identity matches) reuses in place, anything else mounts
                // fresh and unmounts the old one.
                comp.child = Box::new(patch(host, parent, old_child, view));
            }
            // Recurse regardless of whether *this* component just
            // rendered — a nested descendant can be dirty independent of
            // its ancestors. A component never changes which host node
            // its content lives under, so `parent` (not some node of the
            // component's own) is still the right parent for its child.
            let old_child = *comp.child;
            comp.child = Box::new(patch_dirty(host, parent, old_child, dirty));
            Mounted::Component(comp)
        }
        Mounted::Box(node, props, children) => {
            let children = children
                .into_iter()
                .map(|c| patch_dirty(host, node, c, dirty))
                .collect();
            Mounted::Box(node, props, children)
        }
        other @ (Mounted::Text(..) | Mounted::Hole(..)) => other, // no nested instances to walk into
    }
}

#[cfg(test)]
mod tests {
    use super::{Mounted, mount, patch};
    use crate::tui::host_impl::TuiHost;
    use crate::view::{BoxProps, View};

    #[test]
    fn mounting_a_text_view_creates_one_text_node() {
        let mut host = TuiHost::new();
        let root = host.create_root();
        let mounted = mount(&mut host, root, None, View::text("hi"));
        assert_eq!(host.arena.children(root).count(), 1);
        let _ = mounted;
    }

    #[test]
    fn patching_the_same_shape_reuses_the_node_and_updates_content() {
        let mut host = TuiHost::new();
        let root = host.create_root();
        let mounted = mount(&mut host, root, None, View::text("first"));
        let before_ids: Vec<_> = host.arena.children(root).collect();

        let mounted = patch(&mut host, root, mounted, View::text("second"));
        let after_ids: Vec<_> = host.arena.children(root).collect();

        assert_eq!(before_ids, after_ids); // same node reused
        let text_node = after_ids[0];
        assert_eq!(host.arena.get(text_node).text.as_deref(), Some("second"));
        let _ = mounted;
    }

    #[test]
    fn patching_a_different_shape_replaces_the_node() {
        let mut host = TuiHost::new();
        let root = host.create_root();
        let mounted = mount(&mut host, root, None, View::text("hi"));
        let text_node = host.arena.children(root).next().unwrap();

        let mounted = patch(
            &mut host,
            root,
            mounted,
            View::boxed(BoxProps::default(), vec![]),
        );
        let box_node = host.arena.children(root).next().unwrap();

        assert_ne!(text_node, box_node);
        let _ = mounted;
    }

    #[test]
    fn a_shorter_child_list_unmounts_the_tail() {
        let mut host = TuiHost::new();
        let root = host.create_root();
        let view = View::boxed(
            BoxProps::default(),
            vec![View::text("a"), View::text("b"), View::text("c")],
        );
        let mounted = mount(&mut host, root, None, view);

        let view2 = View::boxed(BoxProps::default(), vec![View::text("a")]);
        let mounted = patch(&mut host, root, mounted, view2);

        let Mounted::Box(box_node, _, _) = &mounted else {
            panic!("expected a box");
        };
        assert_eq!(host.arena.children(*box_node).count(), 1);
    }

    #[test]
    fn a_longer_child_list_mounts_the_extra_tail() {
        let mut host = TuiHost::new();
        let root = host.create_root();
        let view = View::boxed(BoxProps::default(), vec![View::text("a")]);
        let mounted = mount(&mut host, root, None, view);

        let view2 = View::boxed(BoxProps::default(), vec![View::text("a"), View::text("b")]);
        let mounted = patch(&mut host, root, mounted, view2);

        let Mounted::Box(box_node, _, _) = &mounted else {
            panic!("expected a box");
        };
        assert_eq!(host.arena.children(*box_node).count(), 2);
    }

    #[test]
    fn a_nested_component_can_appear_as_a_boxs_child() {
        // Not a full Instance-isolation test (that lives in `runtime.rs`,
        // which has a real reactive loop to drive) — just confirms
        // `mount`/`patch` don't hit the old borrowed-`View` split's
        // unreachable panic when a Component sits inside a Box's children.
        use crate::component::Yield;
        use std::pin::Pin;

        fn child() -> Pin<Box<crate::component::ComponentCoroutine>> {
            Box::pin(
                #[coroutine]
                || {
                    yield Yield::View(View::text("child"));
                },
            )
        }

        let mut host = TuiHost::new();
        let root = host.create_root();
        let view = View::boxed(BoxProps::default(), vec![View::component(|()| child(), ())]);
        let mounted = mount(&mut host, root, None, view);
        let Mounted::Box(box_node, _, _) = &mounted else {
            panic!("expected a box");
        };
        assert_eq!(host.arena.children(*box_node).count(), 1);
    }
}
