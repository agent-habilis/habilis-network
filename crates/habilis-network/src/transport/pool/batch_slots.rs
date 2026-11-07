//! The answer batches that are in flight, in all and to each peer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iroh::EndpointId;

/// How many batches may go to one peer at once: a node sends its state and its meta digests back to
/// back, so a holder answers it twice at once, and a second round of asks can start while the first
/// answers are still being written. A peer that holds 4 batches draws no more until one is written.
pub(super) const BATCHES_PER_ENDPOINT: usize = 4;
/// How many batches may be in flight in all. A batch holds its frames, up to about 245 KB, until the
/// last one is written, and a peer that withholds flow-control credit keeps them there, so this is
/// the memory that peers can pin: 32 batches, about 8 MB, and 4 of them, about 1 MB, for one peer.
pub(super) const BATCHES_TOTAL: usize = 32;

/// The batches in flight. A slot is held for as long as its batch is, and a full table refuses the
/// next batch, which the caller answers on gossip as it does for a batch that cannot start.
#[derive(Debug, Clone, Default)]
pub(crate) struct BatchSlots {
    // the batches in flight in all, and for each peer that has one: at most `BATCHES_TOTAL` entries
    counts: Arc<Mutex<Counts>>,
}

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    per_endpoint: HashMap<EndpointId, usize>,
}

/// One batch in flight. The slot is free again when this is dropped.
#[derive(Debug)]
#[must_use = "a slot that is dropped at once frees its batch at once"]
pub(crate) struct Slot {
    slots: BatchSlots,
    endpoint: EndpointId,
}

impl BatchSlots {
    /// A slot for a batch to `endpoint`, or `None` when that peer has its share or the table is full.
    pub(crate) fn take(&self, endpoint: EndpointId) -> Option<Slot> {
        let mut counts = self.counts.lock().ok()?;
        let held = counts.per_endpoint.get(&endpoint).copied().unwrap_or(0);
        if counts.total >= BATCHES_TOTAL || held >= BATCHES_PER_ENDPOINT {
            return None;
        }
        counts.total += 1;
        *counts.per_endpoint.entry(endpoint).or_default() += 1;
        Some(Slot {
            slots: self.clone(),
            endpoint,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let Ok(mut counts) = self.slots.counts.lock() else {
            return;
        };
        counts.total = counts.total.saturating_sub(1);
        if let Some(held) = counts.per_endpoint.get_mut(&self.endpoint) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                counts.per_endpoint.remove(&self.endpoint);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BATCHES_PER_ENDPOINT, BATCHES_TOTAL, BatchSlots};
    use crate::testing;

    /// One peer holds its share of slots and no more, however many batches it draws.
    #[test]
    fn a_peer_holds_its_share_of_slots_and_no_more() {
        let slots = BatchSlots::default();
        let peer = testing::endpoint_id(1);
        let held: Vec<_> = (0..10).filter_map(|_| slots.take(peer)).collect();
        assert_eq!(
            held.len(),
            BATCHES_PER_ENDPOINT,
            "10 batches to one peer hold {BATCHES_PER_ENDPOINT} slots"
        );
    }

    /// Many peers share the whole table: the total is capped, and a peer past it gets none.
    #[test]
    fn all_peers_together_hold_the_total_and_no_more() {
        let slots = BatchSlots::default();
        let mut held = Vec::new();
        for seed in 1..=200u8 {
            let peer = testing::endpoint_id(seed);
            held.extend((0..BATCHES_PER_ENDPOINT).filter_map(|_| slots.take(peer)));
        }
        assert_eq!(held.len(), BATCHES_TOTAL, "the table holds its total");
    }

    /// A finished batch frees its slot, so the next batch to that peer goes.
    #[test]
    fn a_dropped_slot_is_free_again() {
        let slots = BatchSlots::default();
        let peer = testing::endpoint_id(1);
        let mut held: Vec<_> = (0..BATCHES_PER_ENDPOINT)
            .filter_map(|_| slots.take(peer))
            .collect();
        assert!(slots.take(peer).is_none(), "the peer has its share");
        held.pop();
        assert!(slots.take(peer).is_some(), "a freed slot is taken again");
    }
}
