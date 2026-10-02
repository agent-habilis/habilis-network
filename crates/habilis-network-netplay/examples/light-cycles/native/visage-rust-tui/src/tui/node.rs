//! The terminal node tree — an arena rather than the original's doubly-
//! linked `Rc<RefCell<..>>` list. Per the port report: "the doubly-linked
//! child list with a parent back-pointer is the single biggest Rust
//! impedance mismatch here... strongly recommend an arena/slotmap," since
//! it makes the layout pass's mutation of `lx/ly/lw/lh` trivially
//! borrow-checkable and needs no `Weak`/reference-counting at all.
//!
//! Known simplification: a detached node's arena slot is never freed or
//! reused (there is no free-list). Acceptable for a game session's UI tree,
//! which doesn't churn node counts anywhere near what would make this
//! matter — worth revisiting only if that stops being true.

use crate::tui::color::DEFAULT_COLOR;
use crate::tui::width::{Truncate, Wrap};
use crate::view::{Align, Border, Direction, Justify, Padding};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Box,
    Text,
    /// A `null`/`false` child: occupies zero rows, skipped by measure,
    /// arrange, and paint.
    Hole,
    Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAlign {
    Left,
    Center,
    Right,
}

#[derive(Debug, Clone)]
pub struct TuiNode {
    pub tag: Tag,

    // Tree — doubly-linked list of children, arena-indexed.
    pub parent: Option<NodeId>,
    pub prev: Option<NodeId>,
    pub next: Option<NodeId>,
    pub first_child: Option<NodeId>,
    pub last_child: Option<NodeId>,
    pub child_count: u32,

    // Box model.
    pub direction: Direction,
    /// Absolute cells, or -1 for "auto". No percentage sizing in v1.
    pub width: i32,
    pub height: i32,
    pub flex: u16,
    pub padding: Padding,
    pub gap: u16,
    pub justify: Justify,
    pub align: Align,
    pub border: Border,
    pub border_fg: i32,
    pub title: Option<String>,
    pub visible: bool,

    // Style.
    pub fg: i32,
    pub bg: i32,
    pub attrs: u8,

    // Text.
    /// A `text` node's own text prop, or a `#text` leaf's data.
    pub text: Option<String>,
    pub wrap: Wrap,
    pub truncate: Truncate,
    pub text_align: TextAlign,

    // Written by the layout pass — absolute cell coordinates of the
    // BORDER box.
    pub lx: i32,
    pub ly: i32,
    pub lw: i32,
    pub lh: i32,
    pub lines: Option<Vec<String>>,

    // Measure cache.
    pub mw: i32,
    pub mh: i32,
    pub m_epoch: i64,
    pub m_avail_w: i32,
    pub m_avail_h: i32,
}

impl TuiNode {
    fn new(tag: Tag) -> Self {
        Self {
            tag,
            parent: None,
            prev: None,
            next: None,
            first_child: None,
            last_child: None,
            child_count: 0,
            direction: Direction::Column,
            width: -1,
            height: -1,
            flex: 0,
            padding: Padding::default(),
            gap: 0,
            justify: Justify::Start,
            align: Align::Stretch,
            border: Border::None,
            border_fg: DEFAULT_COLOR,
            title: None,
            visible: true,
            fg: DEFAULT_COLOR,
            bg: DEFAULT_COLOR,
            attrs: 0,
            text: None,
            wrap: Wrap::None,
            truncate: Truncate::End,
            text_align: TextAlign::Left,
            lx: 0,
            ly: 0,
            lw: 0,
            lh: 0,
            lines: None,
            mw: 0,
            mh: 0,
            m_epoch: -1,
            m_avail_w: -1,
            m_avail_h: -1,
        }
    }
}

/// Owns every node in a tree by index — see the module doc for why.
#[derive(Debug, Default)]
pub struct Arena {
    nodes: Vec<TuiNode>,
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

    pub fn get_mut(&mut self, id: NodeId) -> &mut TuiNode {
        &mut self.nodes[id.0 as usize]
    }

    /// Standard doubly-linked unlink. A no-op on an already-detached node.
    pub fn detach(&mut self, id: NodeId) {
        let (parent, prev, next) = {
            let node = self.get(id);
            (node.parent, node.prev, node.next)
        };
        match prev {
            Some(p) => self.get_mut(p).next = next,
            None => {
                if let Some(par) = parent {
                    self.get_mut(par).first_child = next;
                }
            }
        }
        match next {
            Some(n) => self.get_mut(n).prev = prev,
            None => {
                if let Some(par) = parent {
                    self.get_mut(par).last_child = prev;
                }
            }
        }
        if let Some(par) = parent {
            self.get_mut(par).child_count -= 1;
        }
        let node = self.get_mut(id);
        node.parent = None;
        node.prev = None;
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
                self.get_mut(node).prev = last;
                self.get_mut(node).next = None;
                match last {
                    Some(l) => self.get_mut(l).next = Some(node),
                    None => self.get_mut(parent).first_child = Some(node),
                }
                self.get_mut(parent).last_child = Some(node);
            }
            Some(before_id) => {
                let prev = self.get(before_id).prev;
                self.get_mut(node).prev = prev;
                self.get_mut(node).next = Some(before_id);
                self.get_mut(before_id).prev = Some(node);
                match prev {
                    Some(p) => self.get_mut(p).next = Some(node),
                    None => self.get_mut(parent).first_child = Some(node),
                }
            }
        }
        self.get_mut(node).parent = Some(parent);
        self.get_mut(parent).child_count += 1;
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
            let node = self.get_mut(id);
            node.parent = None;
            node.prev = None;
            node.next = None;
            child = next;
        }
        let node = self.get_mut(parent);
        node.first_child = None;
        node.last_child = None;
        node.child_count = 0;
    }

    /// Iterates `parent`'s children in order, front to back.
    pub fn children(&self, parent: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        std::iter::successors(self.get(parent).first_child, |id| self.get(*id).next)
    }
}

#[cfg(test)]
mod tests {
    use super::{Arena, Tag};

    #[test]
    fn append_builds_order_front_to_back() {
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        let c = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        arena.append(parent, c);
        assert_eq!(arena.children(parent).collect::<Vec<_>>(), vec![a, b, c]);
        assert_eq!(arena.get(parent).child_count, 3);
    }

    #[test]
    fn insert_before_splices_into_the_middle() {
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        let c = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, c);
        arena.insert_before(parent, b, Some(c));
        assert_eq!(arena.children(parent).collect::<Vec<_>>(), vec![a, b, c]);
    }

    #[test]
    fn detach_removes_from_the_middle_and_relinks_neighbors() {
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        let c = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        arena.append(parent, c);
        arena.detach(b);
        assert_eq!(arena.children(parent).collect::<Vec<_>>(), vec![a, c]);
        assert_eq!(arena.get(parent).child_count, 2);
        assert_eq!(arena.get(b).parent, None);
    }

    #[test]
    fn insert_before_doubles_as_a_move() {
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        // Move `a` to the end.
        arena.insert_before(parent, a, None);
        assert_eq!(arena.children(parent).collect::<Vec<_>>(), vec![b, a]);
    }

    #[test]
    fn before_self_is_a_no_op() {
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        arena.insert_before(parent, a, Some(a));
        assert_eq!(arena.children(parent).collect::<Vec<_>>(), vec![a, b]);
    }

    #[test]
    fn clear_children_orphans_everyone_without_freeing_slots() {
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        arena.clear_children(parent);
        assert_eq!(arena.children(parent).count(), 0);
        assert_eq!(arena.get(parent).child_count, 0);
        assert_eq!(arena.get(a).parent, None);
    }
}
