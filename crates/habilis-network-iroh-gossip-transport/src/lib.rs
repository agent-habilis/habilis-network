//! Gossip as an iroh custom transport: QUIC packets carried as frames on the
//! mesh gossip topic.
//!
//! Built in steps. Step 2 is the frame codec. Step 3 is the transport itself,
//! over a sink that the caller attaches after the endpoint exists.

mod addr;
mod budget;
mod counters;
pub mod frame;
mod lookup;
pub mod memory;
mod recursion;
mod sink;
mod transport;

pub use addr::{gossip_addr, parse_gossip_addr};
pub use budget::DEFAULT_BUDGET_BYTES_PER_SEC;
pub use counters::Stats;
pub use frame::{DecodeError, EncodeError, Frame};
pub use habilis_network_iroh_transport_util::GOSSIP_TRANSPORT_ID;
pub use recursion::{selected_is_gossip, watch_recursion};
pub use sink::GossipSink;
pub use transport::{Delivery, FrameSink, GossipHandle};
