use crate::tui::node_id::NodeId;
use crate::tui::tag::Tag;
use crate::tui::tui_node::TuiNode;
use std::iter;

/// Owns every node in a tree by index — see the module doc for why.
#[derive(Debug, Default)]
pub struct Arena {
    pub(crate) nodes: Vec<TuiNode>,
}

impl Arena {
    #[must_use]
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// # Panics
    ///
    /// If the arena already holds `u32::MAX` nodes — not a real limit any
    /// game session's UI tree approaches.
    pub fn create(&mut self, tag: Tag) -> NodeId {
        let id = NodeId(u32::try_from(self.nodes.len()).expect("arena has room for u32 nodes"));
        self.nodes.push(TuiNode::new(tag));
        id
    }

    #[must_use]
    pub fn get(&self, id: NodeId) -> &TuiNode {
        &self.nodes[id.0 as usize]
    }

    pub fn node_mut(&mut self, id: NodeId) -> &mut TuiNode {
        &mut self.nodes[id.0 as usize]
    }

    /// Standard doubly-linked unlink. A no-op on an already-detached node.
    pub fn detach(&mut self, id: NodeId) {
        let (parent, previous, next) = {
            let node = self.get(id);
            (node.parent, node.previous, node.next)
        };
        match previous {
            Some(p) => self.node_mut(p).next = next,
            None => {
                if let Some(par) = parent {
                    self.node_mut(par).first_child = next;
                }
            }
        }
        match next {
            Some(n) => self.node_mut(n).previous = previous,
            None => {
                if let Some(par) = parent {
                    self.node_mut(par).last_child = previous;
                }
            }
        }
        if let Some(par) = parent {
            self.node_mut(par).child_count -= 1;
        }
        let node = self.node_mut(id);
        node.parent = None;
        node.previous = None;
        node.next = None;
    }

    /// Inserts `node` into `parent`'s child list, immediately before
    /// `before` (`None` appends). Detaches `node` first, so this doubles as
    /// a move. A `before == Some(node)` no-op guard runs first, matching
    /// the original — otherwise a self-reference would splice into its own
    /// former position and produce an infinite list walk.
    pub fn insert_before(&mut self, parent: NodeId, node: NodeId, before: Option<NodeId>) {
        if before == Some(node) {
            return;
        }
        self.detach(node);
        match before {
            None => {
                let last = self.get(parent).last_child;
                self.node_mut(node).previous = last;
                self.node_mut(node).next = None;
                match last {
                    Some(l) => self.node_mut(l).next = Some(node),
                    None => self.node_mut(parent).first_child = Some(node),
                }
                self.node_mut(parent).last_child = Some(node);
            }
            Some(before_id) => {
                let previous = self.get(before_id).previous;
                self.node_mut(node).previous = previous;
                self.node_mut(node).next = Some(before_id);
                self.node_mut(before_id).previous = Some(node);
                match previous {
                    Some(p) => self.node_mut(p).next = Some(node),
                    None => self.node_mut(parent).first_child = Some(node),
                }
            }
        }
        self.node_mut(node).parent = Some(parent);
        self.node_mut(parent).child_count += 1;
    }

    pub fn append(&mut self, parent: NodeId, node: NodeId) {
        self.insert_before(parent, node, None);
    }

    /// Orphans every child of `parent` in one op, without freeing arena
    /// slots (see the module doc).
    pub fn clear_children(&mut self, parent: NodeId) {
        let mut child = self.get(parent).first_child;
        while let Some(id) = child {
            let next = self.get(id).next;
            let node = self.node_mut(id);
            node.parent = None;
            node.previous = None;
            node.next = None;
            child = next;
        }
        let node = self.node_mut(parent);
        node.first_child = None;
        node.last_child = None;
        node.child_count = 0;
    }

    /// Iterates `parent`'s children in order, front to back.
    pub fn children(&self, parent: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        iter::successors(self.get(parent).first_child, |id| self.get(*id).next)
    }
}
