//! The sender-side re-serve source for big outbound groups.

use std::collections::VecDeque;

use habilis_network_util::consts::SHARD_CACHE_BUDGET_BYTES;

use crate::ShardGroup;
use crate::message::WireFrame;

/// The sender-side re-serve source for big (unlogged) outbound groups: their
/// serialized, signed shard frames, kept so a receiver's `shard/repair`
/// request can be answered. Big groups skip the message log (one huge body
/// must not evict the anti-entropy history), so without this cache a lost
/// gossip frame would make the whole body unrecoverable. Byte-budgeted with
/// whole-group FIFO eviction — the bounded-everything discipline.
#[derive(Debug, Default)]
pub struct ShardCache {
    groups: VecDeque<CachedGroup>,
    bytes: usize,
}

#[derive(Debug)]
struct CachedGroup {
    group: ShardGroup,
    frames: Vec<WireFrame>,
}

impl ShardCache {
    /// Cache one just-sent group's frames (indexed by shard `idx`), evicting
    /// the oldest groups past the byte budget. The newest group always stays.
    pub fn insert(&mut self, group: ShardGroup, frames: Vec<WireFrame>) {
        self.bytes += frames.iter().map(WireFrame::len).sum::<usize>();
        self.groups.push_back(CachedGroup { group, frames });
        while self.groups.len() > 1 && self.bytes > SHARD_CACHE_BUDGET_BYTES {
            if let Some(evicted) = self.groups.pop_front() {
                self.bytes = self
                    .bytes
                    .saturating_sub(evicted.frames.iter().map(WireFrame::len).sum::<usize>());
            }
        }
    }

    /// The cached frames for `group` at the requested indexes (missing or
    /// out-of-range indexes are skipped; empty when the group was evicted).
    pub fn frames<'a>(
        &'a self,
        group: &ShardGroup,
        idxs: &'a [u32],
    ) -> impl Iterator<Item = WireFrame> + 'a {
        self.groups
            .iter()
            .find(|entry| entry.group == *group)
            .into_iter()
            .flat_map(move |cached| {
                idxs.iter()
                    .filter_map(move |index| cached.frames.get(*index as usize).cloned())
            })
    }
}
