//! Filesystem backends: one that keeps chunks, one that borrows them.
//!
//! The split is the crate's central asymmetry made concrete.
//!
//! - [`DiskStore`] **owns** its chunks. A mirror, a seeder, anyone who fetched
//!   bytes from the network and has nowhere else to put them.
//! - [`DiskOrigin`] **borrows** them. It serves the user's own files where they
//!   already sit, holding nothing but addresses and offsets, so publishing a
//!   500 GB tree costs a `stat` walk rather than a copy of it.
//!
//! `DiskOrigin` implements [`ChunkSource`] and not [`ChunkStore`], and that is
//! the honest shape rather than a missing feature: `put` on an origin would
//! have to copy the caller's bytes into a store — the one thing this design
//! exists to avoid — or silently do nothing.
//!
//! # Crash consistency
//!
//! Coverage is **derived, never stored**: a chunk is held exactly when its file
//! is on disk. That deletes the failure the rule below usually guards against —
//! there is no separate range set that can outlive the data it describes and
//! leave this peer advertising bytes it cannot serve. What remains is making a
//! chunk file appear whole or not at all, which is what the temp-file-then-
//! rename in [`DiskStore::put`] is for. A half-written chunk under its final name
//! would be a peer that lies.

mod disk_origin;
mod disk_store;

pub use disk_origin::{DiskOrigin, max_read_window};
pub use disk_store::DiskStore;
