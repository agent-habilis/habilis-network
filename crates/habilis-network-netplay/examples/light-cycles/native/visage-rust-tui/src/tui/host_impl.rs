//! The terminal's [`Host`] implementation — one per root, mirroring
//! `createTuiHost`. Every op is a handful of [`Arena`] pointer writes; the
//! interesting work (layout, paint, diff) lives in the sibling modules.

use crate::host::Host;
use crate::tui::node::{Arena, NodeId, Tag, TuiNode};
use crate::view::BoxProps;

#[derive(Debug)]
pub struct TuiHost {
    pub arena: Arena,
}

impl TuiHost {
    #[must_use]
    pub fn new() -> Self {
        Self {
            arena: Arena::new(),
        }
    }

    /// Creates the tree's root node — a plain box with no props of its
    /// own; layout is invoked with this as the starting frame.
    pub fn create_root(&mut self) -> NodeId {
        self.arena.create(Tag::Root)
    }
}

impl Default for TuiHost {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_box_props(node: &mut TuiNode, props: &BoxProps) {
    node.direction = props.direction;
    node.width = props.width.map_or(-1, i32::from);
    node.height = props.height.map_or(-1, i32::from);
    node.flex = props.flex;
    node.padding = props.padding;
    node.gap = props.gap;
    node.justify = props.justify;
    node.align = props.align;
    node.border = props.border;
    node.fg = props.fg;
    node.bg = props.bg;
}

impl Host for TuiHost {
    type Node = NodeId;

    fn create_box(&mut self, props: &BoxProps) -> NodeId {
        let id = self.arena.create(Tag::Box);
        apply_box_props(self.arena.get_mut(id), props);
        id
    }

    fn create_text(&mut self, value: &str) -> NodeId {
        let id = self.arena.create(Tag::Text);
        self.arena.get_mut(id).text = Some(value.to_string());
        id
    }

    fn create_hole(&mut self) -> NodeId {
        self.arena.create(Tag::Hole)
    }

    fn set_text(&mut self, node: NodeId, value: &str) {
        self.arena.get_mut(node).text = Some(value.to_string());
    }

    fn set_box_props(&mut self, node: NodeId, props: &BoxProps) {
        apply_box_props(self.arena.get_mut(node), props);
    }

    fn insert(&mut self, parent: NodeId, node: NodeId, before: Option<NodeId>) {
        self.arena.insert_before(parent, node, before);
    }

    fn remove(&mut self, node: NodeId) {
        self.arena.detach(node);
    }

    fn clear(&mut self, parent: NodeId) {
        self.arena.clear_children(parent);
    }

    fn next_sibling(&self, node: NodeId) -> Option<NodeId> {
        self.arena.get(node).next
    }

    fn first_child(&self, parent: NodeId) -> Option<NodeId> {
        self.arena.get(parent).first_child
    }
}
