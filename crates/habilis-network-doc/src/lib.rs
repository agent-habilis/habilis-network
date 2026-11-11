//! The shared-state store backing the `state` and `meta` channels.
//!
//! Each channel holds one signed slice per author key. An author writes only its own slice, and a
//! frame takes effect only as the slice of the key that signed it. The store keeps each slice at
//! its newest version, and it refuses a slice of a key that said goodbye.
//!
//! # Example
//!
//! ```
//! use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
//! use habilis_network_protocol::Channel;
//!
//! let store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
//! assert!(store.view().is_empty());
//! ```

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

pub mod wire;

mod doc_error;

pub use doc_error::DocError;

mod pending_slices;

mod slice_store;

pub use slice_store::{
    LocalDraft, SliceError, SliceIngest, SliceLimits, SliceStore, frame_overhead,
    worst_frame_overhead,
};
