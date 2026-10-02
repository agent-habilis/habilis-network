//! Byte streams between two peers, addressed by a hash.
//!
//! A producer [`create`](StreamNode::create)s a stream and hands its
//! [`StreamHash`] to one consumer, which [`open`](StreamNode::open)s it. The
//! bytes ride one QUIC stream on a direct path by default — hole-punched UDP,
//! or a WebRTC data channel when a browser is on either end — on the relay
//! only when the stream's `transport` allows it, and never through gossip. QUIC
//! keeps them in order and paces the producer to the consumer.
//!
//! A stream is 1-1: its hash admits exactly one consumer, and a second one is
//! [`Refused::Taken`]. What goes over it is up to the producer.

mod hash;
mod node;
mod produce;
mod read;

pub use hash::{ID_LEN, SECRET_LEN, StreamHash};
pub use node::{StreamNode, StreamOpts};
pub use produce::Producer;
pub use read::{Reader, Refused};

/// The ALPN a stream rides on.
pub const STREAM_ALPN: &[u8] = b"habilis-network/stream/1";

/// Connection close codes. The producer closes with one of these to tell a
/// consumer why it has no stream, and [`Reader::read`] maps them to a
/// [`Refused`].
pub(crate) mod code {
    pub(crate) const DONE: u32 = 0;
    pub(crate) const UNKNOWN: u32 = 1;
    pub(crate) const TAKEN: u32 = 2;
    pub(crate) const RELAY_REFUSED: u32 = 3;
    pub(crate) const ABANDONED: u32 = 4;
}
