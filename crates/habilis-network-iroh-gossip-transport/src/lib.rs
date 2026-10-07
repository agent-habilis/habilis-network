//! Gossip as an iroh custom transport: QUIC packets carried as frames on the
//! mesh gossip topic.
//!
//! Built in steps. This step is the frame codec and nothing else.

pub mod frame;

pub use frame::{DecodeError, EncodeError, Frame};
