//! The sender-side re-serve source for big outbound groups.

use std::collections::VecDeque;

use habilis_network_util::consts::SHARD_CACHE_BUDGET_BYTES;

use crate::ShardGroup;
use crate::messages::WireFrame;

/// The sender-side re-serve source for big outbound groups: their
/// serialized, signed shard frames, kept so a receiver's `shard/repair`
/// request can be answered. No log keeps the shards of a big group, so without
/// this cache a lost gossip frame would make the whole body unrecoverable.
/// Byte-budgeted with whole-group FIFO eviction — the bounded-everything discipline.
///
/// # Examples
///
/// It keeps the frames of recent groups for repair. It takes a `ShardGroup`, which is in the private shard module, so this is not compiled.
///
/// ```ignore
/// let mut cache = ShardCache::default();
/// cache.insert(group, frames);
/// ```
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
    /// The groups that the cache holds, and the wire bytes of their frames.
    #[must_use]
    pub fn size(&self) -> (usize, usize) {
        (self.groups.len(), self.bytes)
    }

    /// Cache one just-sent group's frames (indexed by shard `idx`), evicting
    /// the oldest groups past the byte budget. The newest group always stays.
    pub fn insert(&mut self, group: ShardGroup, frames: Vec<WireFrame>) {
        let added: usize = frames.iter().map(WireFrame::len).sum();
        self.bytes += added;
        self.groups.push_back(CachedGroup { group, frames });
        while self.groups.len() > 1 && self.bytes > SHARD_CACHE_BUDGET_BYTES {
            if let Some(evicted) = self.groups.pop_front() {
                let freed: usize = evicted.frames.iter().map(WireFrame::len).sum();
                self.bytes = self.bytes.saturating_sub(freed);
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
