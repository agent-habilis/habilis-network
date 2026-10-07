//! Gossip as an iroh custom transport: QUIC packets carried as frames on the
//! mesh gossip topic.
//!
//! Built in steps. Step 2 is the frame codec. Step 3 is the transport itself,
//! over a sink that the caller attaches after the endpoint exists.

mod addr;
mod counters;
pub mod frame;
pub mod memory;
mod transport;

pub use addr::{gossip_addr, parse_gossip_addr};
pub use counters::Stats;
pub use frame::{DecodeError, EncodeError, Frame};
pub use habilis_network_iroh_transport_util::GOSSIP_TRANSPORT_ID;
pub use transport::{Delivery, FrameSink, GossipHandle};
