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

#[cfg(test)]
mod tests {
    use crate::tui::arena::Arena;
    use crate::tui::tag::Tag;

    #[test]
    fn append_builds_order_front_to_back() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        let c = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        arena.append(parent, c);
        let kids_1: Vec<_> = arena.children(parent).collect();
        assert_eq!(
            kids_1,
            vec![a, b, c],
            "appended children stay in front-to-back order"
        );
        assert_eq!(
            arena.get(parent).child_count,
            3,
            "the parent counts three children after appends"
        );
    }

    #[test]
    fn insert_before_splices_into_the_middle() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        let c = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, c);
        arena.insert_before(parent, b, Some(c));
        let kids_1: Vec<_> = arena.children(parent).collect();
        assert_eq!(
            kids_1,
            vec![a, b, c],
            "insert before splices a child into the middle"
        );
    }

    #[test]
    fn detach_removes_from_the_middle_and_relinks_neighbors() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        let c = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        arena.append(parent, c);
        arena.detach(b);
        let kids_1: Vec<_> = arena.children(parent).collect();
        assert_eq!(kids_1, vec![a, c], "detach removes a child from the middle");
        assert_eq!(
            arena.get(parent).child_count,
            2,
            "the parent counts two children after the detach"
        );
        assert_eq!(arena.get(b).parent, None, "a detached child has no parent");
    }

    #[test]
    fn insert_before_doubles_as_a_move() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        // Move `a` to the end.
        arena.insert_before(parent, a, None);
        let kids_1: Vec<_> = arena.children(parent).collect();
        assert_eq!(kids_1, vec![b, a], "insert before a child moves it");
    }

    #[test]
    fn before_self_is_a_no_op() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        arena.insert_before(parent, a, Some(a));
        let kids_1: Vec<_> = arena.children(parent).collect();
        assert_eq!(kids_1, vec![a, b], "insert before itself changes nothing");
    }

    #[test]
    fn clear_children_orphans_everyone_without_freeing_slots() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut arena = Arena::new();
        let parent = arena.create(Tag::Box);
        let a = arena.create(Tag::Box);
        let b = arena.create(Tag::Box);
        arena.append(parent, a);
        arena.append(parent, b);
        arena.clear_children(parent);
        assert_eq!(
            arena.children(parent).count(),
            0,
            "clear children leaves the parent with no children"
        );
        assert_eq!(
            arena.get(parent).child_count,
            0,
            "the parent's child count is zero after clear"
        );
        assert_eq!(arena.get(a).parent, None, "a cleared child has no parent");
    }
}
