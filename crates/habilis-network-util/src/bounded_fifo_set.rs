//! A fixed-capacity set with FIFO eviction: the bounded building block for
//! long-lived state sets (`EventLoopState::known_endpoints`, `quiet`) so they
//! cannot grow without limit under churn / a sybil stream of one-shot ids.
//!
//! Pairs a `HashSet` (membership / O(1) lookup) with a `VecDeque` (insertion
//! order / eviction). Re-inserting an existing entry is a no-op (no recency
//! bump — recency isn't load-bearing for any caller, only "have we seen
//! this"). A caller that wants the opposite answer — "was this a duplicate" —
//! negates [`insert`](BoundedFifoSet::insert); the engine's message dedup does
//! exactly that.

use std::borrow::Borrow;
use std::collections::{HashSet, VecDeque};
use std::hash::Hash;

/// A set that holds at most `capacity` items. When an insert goes past the limit, the oldest item
/// is dropped.
#[derive(Debug, Clone)]
pub struct BoundedFifoSet<T> {
    capacity: usize,
    set: HashSet<T>,
    order: VecDeque<T>,
}

impl<T: Clone + Eq + Hash> BoundedFifoSet<T> {
    /// A capacity of 0 is raised to 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            // Clamp to >= 1 (mirrors `BoundedIdSet`): a 0 capacity would make
            // every insert immediately evict itself, leaving the set
            // permanently empty while reporting inserts as "new" — silently
            // broken membership.
            capacity: capacity.max(1),
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Insert `item`; `true` if newly added, `false` if already present.
    /// Evicts the oldest entry when this pushes past `capacity`.
    pub fn insert(&mut self, item: T) -> bool {
        if !self.set.insert(item.clone()) {
            return false;
        }
        self.order.push_back(item);
        if self.order.len() > self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        true
    }

    /// Remove `item`, keeping the eviction queue consistent. `true` if present.
    pub fn remove<Query>(&mut self, item: &Query) -> bool
    where
        T: Borrow<Query>,
        Query: Eq + Hash + ?Sized,
    {
        if self.set.remove(item) {
            self.order.retain(|queued| queued.borrow() != item);
            true
        } else {
            false
        }
    }

    /// Whether the set holds the item.
    pub fn contains<Query>(&self, item: &Query) -> bool
    where
        T: Borrow<Query>,
        Query: Eq + Hash + ?Sized,
    {
        self.set.contains(item)
    }

    /// The items, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.set.iter()
    }

    #[must_use]
    /// The number of items.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    #[must_use]
    /// Whether the set holds no items.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedFifoSet;

    #[test]
    fn insert_reports_novelty_and_dedupes() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut set = BoundedFifoSet::new(8);
        assert!(set.insert(1u32), "first insert is new");
        assert!(!set.insert(1u32), "re-insert is a dup, no-op");
        assert_eq!(
            set.len(),
            1,
            "inserting a duplicate reports no novelty and keeps one entry"
        );
    }

    #[test]
    fn evicts_oldest_past_capacity() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut set = BoundedFifoSet::new(3);
        for value in 0..3u32 {
            set.insert(value);
        }
        // Pushing a 4th evicts the oldest (0), FIFO; length stays capped.
        assert!(set.insert(99), "a new entry is novel past capacity");
        assert_eq!(set.len(), 3, "the set keeps its capacity of three");
        assert!(!set.contains(&0), "oldest evicted");
        assert!(
            set.contains(&99) && set.contains(&2),
            "the newest entry and the newest survivor are kept"
        );
    }

    #[test]
    fn stays_capped_under_churn() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut set = BoundedFifoSet::new(10);
        for value in 0..1000u32 {
            set.insert(value);
        }
        assert_eq!(set.len(), 10, "never exceeds capacity");
    }

    #[test]
    fn remove_clears_set_and_order() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut set = BoundedFifoSet::new(8);
        set.insert(1u32);
        set.insert(2u32);
        assert!(set.remove(&1), "removing an entry clears it from the set");
        assert!(!set.contains(&1), "a removed entry is no longer contained");
        assert!(!set.remove(&1), "second remove is a no-op");
        // Re-inserting the removed value works (order queue stayed consistent).
        assert!(set.insert(1u32), "a removed entry can be inserted again");
        assert_eq!(set.len(), 2, "the set holds two entries after the reinsert");
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let _guard = ::habilis_network_test_tracing::init();
        // A 0 capacity must not yield a set that holds nothing yet reports
        // inserts as new: it's clamped to 1, so membership actually works.
        let mut set = BoundedFifoSet::new(0);
        assert!(set.insert(7u32), "first insert is new");
        assert!(set.contains(&7), "the inserted item is actually retained");
        assert_eq!(set.len(), 1, "zero capacity is clamped to one entry");
    }

    #[test]
    fn remove_by_borrowed_form() {
        let _guard = ::habilis_network_test_tracing::init();
        // The `Borrow<Q>` bound lets a `String` set be queried/removed by `&str`.
        let mut set: BoundedFifoSet<String> = BoundedFifoSet::new(4);
        set.insert("alice".to_owned());
        assert!(set.contains("alice"), "a borrowed key is contained");
        assert!(set.remove("alice"), "a borrowed key removes its entry");
        assert!(set.is_empty(), "removing the only entry empties the set");
    }
}
