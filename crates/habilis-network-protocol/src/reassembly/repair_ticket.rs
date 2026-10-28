//! The repair ask for one stalled multipart group.

use crate::{Nickname, ShardGroup};

/// One stalled big group's repair ask: which author to query and which shard
/// indexes we still lack.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RepairTicket {
    /// The member that sent the missing shards.
    pub author: Nickname,
    /// The group of the missing shards.
    pub group: ShardGroup,
    /// The positions of the missing shards.
    pub missing: Vec<u32>,
}
