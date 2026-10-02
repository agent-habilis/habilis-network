//! The seam between a reconciled [`View`](crate::view::View) tree and a
//! concrete backend. Ported down from `visage-dom/src/host/index.ts`'s
//! fifteen-operation interface to what v1's non-keyed reconciler actually
//! calls — no refs, no fragments, no portals, no `commit` hook. `Host`
//! being a trait rather than a dynamically-typed `object` (the original's
//! `HostNode = object`) gives the same "the reconciler cannot call
//! backend-specific methods it wasn't given" guarantee for free.

use crate::view::BoxProps;

pub trait Host {
    /// An opaque handle to a node this `Host` owns.
    type Node: Copy + Eq;

    fn create_box(&mut self, props: &BoxProps) -> Self::Node;
    fn create_text(&mut self, value: &str) -> Self::Node;
    fn create_hole(&mut self) -> Self::Node;

    fn set_text(&mut self, node: Self::Node, value: &str);
    fn set_box_props(&mut self, node: Self::Node, props: &BoxProps);

    /// Inserts `node` into `parent`'s children, immediately before
    /// `before` (`None` appends).
    fn insert(&mut self, parent: Self::Node, node: Self::Node, before: Option<Self::Node>);
    /// Removes `node` from wherever it currently is — self-locating, like
    /// the DOM's.
    fn remove(&mut self, node: Self::Node);
    /// Drops every child of `parent` in one op.
    fn clear(&mut self, parent: Self::Node);

    fn next_sibling(&self, node: Self::Node) -> Option<Self::Node>;
    fn first_child(&self, parent: Self::Node) -> Option<Self::Node>;
}
