//! Multipart body reassembly with byte budgets.
//!
//! Folded in from its own crate for the same reason as [`crate::directory`].

mod reassembly_store;
pub use reassembly_store::{ReassemblyStore, slot_charge, synthesize_from};
mod repair_ticket;
pub use repair_ticket::RepairTicket;
mod shard_cache;
pub use shard_cache::ShardCache;
mod shard_ingest;
pub use shard_ingest::ShardIngest;

#[cfg(test)]
mod tests;
