//! The declarative output of a component's render — what to show, not how.
//! `Host`-agnostic in principle, though v1 only ever targets the terminal
//! `Host`. Scoped to what a grid + HUD needs: `box`/`text` per the plan,
//! not visage-tui's full `TuiNode` prop set (colors as packed `i32`s from
//! `tui::color`, absolute-cell sizing only — no percentages, no `auto` vs
//! explicit distinction beyond `Option`).

use std::pin::Pin;
use std::rc::Rc;

use crate::component::ComponentCoroutine;
use crate::tui::color::DEFAULT_COLOR;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    #[default]
    Column,
    Row,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Justify {
    #[default]
    Start,
    Center,
    End,
    Between,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Align {
    Start,
    Center,
    End,
    #[default]
    Stretch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Border {
    #[default]
    None,
    Single,
    Round,
    Double,
    Bold,
    Ascii,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Padding {
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
    pub left: u16,
}

impl Padding {
    #[must_use]
    pub fn all(n: u16) -> Self {
        Self {
            top: n,
            right: n,
            bottom: n,
            left: n,
        }
    }
}

/// A `box` node's props. `width`/`height` of `None` means "auto" (sized
/// from content, per `visage-tui`'s `-1` sentinel); `Some(n)` is an
/// absolute cell count — no percentage sizing in v1.
#[derive(Debug, Clone, PartialEq)]
pub struct BoxProps {
    pub direction: Direction,
    pub width: Option<u16>,
    pub height: Option<u16>,
    /// 0 = does not grow/shrink to fill leftover space.
    pub flex: u16,
    pub padding: Padding,
    pub gap: u16,
    pub justify: Justify,
    pub align: Align,
    pub border: Border,
    /// Packed color (see `tui::color`); `DEFAULT_COLOR` inherits.
    pub fg: i32,
    pub bg: i32,
}

impl Default for BoxProps {
    fn default() -> Self {
        Self {
            direction: Direction::default(),
            width: None,
            height: None,
            flex: 0,
            padding: Padding::default(),
            gap: 0,
            justify: Justify::default(),
            align: Align::default(),
            border: Border::default(),
            fg: DEFAULT_COLOR,
            bg: DEFAULT_COLOR,
        }
    }
}

/// A nested component: its own independent coroutine, mounted (or
/// reused) as a first-class part of the tree — this is what makes
/// children generators too, matching `visage-dom`'s `comp` fiber, rather
/// than plain declarative data the parent alone re-renders wholesale.
///
/// `type_key` is how the reconciler decides "the same component slot as
/// last render" (reuse the already-running instance, preserving its own
/// signal state) from "a different one" (tear down, mount fresh) — see
/// [`View::component`] for where it comes from and why a bare closure
/// can't serve this role in Rust the way a component's function
/// reference does in JS.
pub struct ComponentView {
    pub(crate) type_key: usize,
    pub(crate) build: Box<dyn FnOnce() -> Pin<Box<ComponentCoroutine>>>,
}

/// A declarative view tree, as yielded by a component. Not `Clone` as a
/// whole (`Component` owns a one-shot builder closure, consumed exactly
/// once when it's actually mounted) — nothing in this crate needs to
/// clone a whole `View`; `patch()` takes one by reference and clones only
/// `Text`/`Box`'s own inner fields (`Rc<str>`, `BoxProps`) where needed.
#[derive(Debug)]
pub enum View {
    Text(Rc<str>),
    Box(BoxProps, Vec<View>),
    /// A `null`/`false` child — occupies nothing, matches `#hole`.
    Hole,
    Component(ComponentView),
}

impl std::fmt::Debug for ComponentView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComponentView")
            .field("type_key", &self.type_key)
            .finish_non_exhaustive()
    }
}

impl View {
    #[must_use]
    pub fn text(value: impl Into<Rc<str>>) -> Self {
        View::Text(value.into())
    }

    #[must_use]
    pub fn boxed(props: BoxProps, children: Vec<View>) -> Self {
        View::Box(props, children)
    }

    /// Yields a nested component: `component_fn` is a plain function
    /// (never a closure) so its pointer is stable across every render —
    /// the same identity JS gets for free by comparing a component's
    /// function reference. `props` is captured once, at the moment this
    /// component is first mounted; a parent re-rendering with the *same*
    /// `component_fn` reuses the already-running child instance as-is
    /// rather than feeding it new props (v1 does not port `visage-dom`'s
    /// live-props channel — see the crate's port-report notes on why the
    /// `Proxy`-based mechanism doesn't translate to Rust). Ongoing data
    /// into an already-mounted child flows through a shared [`Signal`]
    /// captured by both sides, the same as any other reactive read.
    ///
    /// [`Signal`]: crate::reactive::Signal
    pub fn component<P: 'static>(
        component_fn: fn(P) -> Pin<Box<ComponentCoroutine>>,
        props: P,
    ) -> Self {
        View::Component(ComponentView {
            type_key: component_fn as usize,
            build: Box::new(move || component_fn(props)),
        })
    }
}
