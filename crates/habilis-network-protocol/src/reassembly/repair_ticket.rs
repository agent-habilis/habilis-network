//! The repair ask for one stalled multipart group.

use crate::{AuthorKey, ShardGroup};

/// One stalled big group's repair ask: which author key to query and which shard
/// indexes we still lack.
///
/// # Examples
///
/// A store with no incomplete group asks for no repair.
///
/// ```
/// use std::time::Instant;
///
/// use habilis_network_protocol::reassembly::{ReassemblyStore, RepairTicket};
///
/// let mut store = ReassemblyStore::default();
/// let tickets: Vec<RepairTicket> = store.repair_tickets(Instant::now()).collect();
/// assert!(tickets.is_empty());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RepairTicket {
    /// The key that sent the shards. A nickname can name two keys, so the ask goes to this key.
    pub author: AuthorKey,
    /// The group of the missing shards.
    pub group: ShardGroup,
    /// The positions of the missing shards.
    pub missing: Vec<u32>,
}
