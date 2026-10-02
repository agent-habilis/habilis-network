//! What crosses the wire, and the seam it crosses through.
//!
//! The real transport is a habilis-network mesh — that is what this crate is for, and
//! [`crate::habilis_network_transport`] is the implementation consumers actually use.
//! The trait exists for two reasons: the protocol below has to be testable
//! against injected packet loss and reordering without standing up a mesh,
//! and a consumer embedding this somewhere other than habilis-network should not have
//! to fork it.
//!
//! # What the transport must and must not guarantee
//!
//! **Must not:** ordering, deduplication, or delivery. This layer assumes
//! datagram semantics and handles all three itself — sequence numbers on
//! sync, redundant input resends, and idempotent input application.
//!
//! That is not a lowest-common-denominator assumption, it is what habilis-network
//! actually provides: `send_app` opens a fresh unidirectional QUIC stream per
//! frame (`transport/pool.rs`), so frames are individually reliable but
//! **unordered relative to each other**, and `send_if_warm` is
//! fire-and-forget, so they can be lost outright. Anything stronger than
//! datagrams is a bonus this layer will not notice.
//!
//! **Must:** deliver to the addressed peer and nobody else, and report the
//! sender's address on receive. Identity is load-bearing — inputs are filed
//! per player, so a misattributed packet is a desync.

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::frame::Frame;

/// A packet between two peers in a session.
///
/// `magic` scopes a packet to one session between one pair of peers: each
/// side picks a value when the session starts and ignores anything carrying
/// a different one, so a straggler from a previous match cannot be mistaken
/// for live input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message<I> {
    /// The sender's session nonce.
    pub magic: u32,
    /// What the packet is for.
    pub body: Body<I>,
}

/// The packet kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body<I> {
    /// Handshake, outbound: "echo this back". Repeated a few times so both
    /// sides have evidence the path works in both directions before either
    /// starts simulating.
    SyncRequest {
        /// Echoed verbatim in the reply; anything else is a stale packet.
        token: u32,
    },
    /// Handshake, inbound: the token from a [`Body::SyncRequest`].
    SyncReply {
        /// The token being echoed.
        token: u32,
    },
    /// Real inputs, plus a piggybacked ack.
    ///
    /// Carries **every input from `start_frame` onwards that the sender has
    /// not seen acked**, not just the newest. That redundancy is the entire
    /// loss-recovery strategy: a dropped packet costs nothing as long as a
    /// later one still carries the frame, and at these sizes resending a few
    /// frames is far cheaper than detecting the loss and asking again.
    Input(InputPacket<I>),
    /// Standalone ack, for when there is nothing to send but the peer is
    /// waiting to retire inputs.
    InputAck {
        /// Highest frame received contiguously.
        ack_frame: Frame,
    },
    /// How far ahead the sender believes it is, so the pair can converge on
    /// a shared pace instead of one racing.
    QualityReport {
        /// Sender's frame advantage over what it has received.
        frame_advantage: i8,
        /// Sender's clock, echoed back to measure round-trip time.
        ping: u64,
    },
    /// Response to a [`Body::QualityReport`].
    QualityReply {
        /// The `ping` being echoed.
        pong: u64,
    },
    /// A checksum of confirmed state, so divergence is *detected* rather
    /// than silently played out. Nothing else in rollback notices a desync.
    Checksum {
        /// The frame the checksum covers.
        frame: Frame,
        /// The sender's checksum for that frame.
        checksum: u128,
    },
    /// Nothing to say; proves the peer is alive.
    KeepAlive,
}

/// A run of consecutive inputs starting at `start_frame`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputPacket<I> {
    /// The frame `inputs[0]` belongs to; each subsequent entry is one frame
    /// later.
    pub start_frame: Frame,
    /// Highest frame the sender has received from *us*, piggybacked so an
    /// ack costs no extra packet.
    pub ack_frame: Frame,
    /// Consecutive inputs from `start_frame`.
    pub inputs: Vec<I>,
}

/// How a session sends and receives packets.
///
/// Non-blocking by contract: [`Self::receive_all`] returns whatever has
/// arrived and never waits, because it is called from a frame loop that
/// cannot stall.
pub trait Transport<T: Config> {
    /// Send to one peer. Failure is not reported — this layer treats the
    /// transport as lossy regardless, and a caller that cannot act on the
    /// error would only be able to log it.
    fn send_to(&mut self, message: &Message<T::Input>, addr: &T::Address);

    /// Everything received since the last call, oldest first.
    fn receive_all(&mut self) -> Vec<(T::Address, Message<T::Input>)>;
}
