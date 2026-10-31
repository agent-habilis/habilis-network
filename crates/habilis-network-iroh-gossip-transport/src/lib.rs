//! Gossip as an iroh custom transport: QUIC packets carried as frames on the
//! mesh gossip topic.
//!
//! Built in steps. Step 2 is the frame codec. Step 3 is the transport itself,
//! over a sink that the caller attaches after the endpoint exists.

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

mod address;
mod budget;
mod counters;
mod delivery;
pub mod frame;
mod frame_sink;
mod gossip_handle;
mod gossip_ladder;
mod gossip_lookup;
mod gossip_sink;
pub mod hub;
mod receive_loop;
mod recursion;
mod shared;

pub use address::{gossip_addr, parse_gossip_addr};
pub use budget::DEFAULT_BUDGET_BYTES_PER_SEC;
pub use counters::Stats;
pub use delivery::Delivery;
pub use frame::{DecodeError, EncodeError, Frame};
pub use frame_sink::FrameSink;
pub use gossip_handle::GossipHandle;
pub use gossip_sink::GossipSink;
pub use habilis_network_iroh_transport_util::GOSSIP_TRANSPORT_ID;
pub use iroh_gossip;
pub use receive_loop::{ReceiveLoop, spawn_receive_loop};
pub use recursion::{selected_is_gossip, watch_recursion};
