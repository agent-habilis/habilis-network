//! The **gossip subsystem**: the message transport plane. The outbound
//! send plane is [`broadcast`] (broadcast/buffer, presence/`PeerInfo`,
//! the broadcast stdin path); the inbound plane is [`recv`] (the
//! gossip-event pump, neighbor up/down bookkeeping, the per-message
//! router); anti-entropy and the healer are [`antientropy`] / [`heal`].
//! This module holds the shared `json_body` helper, and
//! re-exports the subsystem's public API. Membership/presentation lives
//! in `lifecycle`; this layer never touches the peer roster
//! directly — it calls into `lifecycle::observe` and dispatches by kind.

pub(crate) mod antientropy;
pub(crate) mod app;
pub(crate) mod event;
pub(crate) mod heal;
pub(crate) mod lan;
mod merge_ctx;
mod recv;
pub(crate) mod split;

mod json_body;
mod path_summary;

/// Compile-time tripwire: a serialized message up to `MAX_MESSAGE_SIZE` must
/// fit a single iroh-gossip message, with room for gossip's per-message wire
/// overhead (header + `MessageId` + scope + length prefixes, ~80B; 256 leaves
/// margin). If our cap ever reaches gossip's `DEFAULT_MAX_MESSAGE_SIZE`,
/// oversize messages silently fail to propagate (p2panda #628) — so an
/// iroh-gossip bump that lowers the limit under us fails the build here, not
/// in production.
///
/// It lives in this crate rather than beside `MAX_MESSAGE_SIZE` because
/// `habilis-network-protocol` deliberately does not depend on iroh-gossip and so
/// cannot name the constant being checked against.
const _: () = assert!(
    habilis_network_util::consts::MAX_MESSAGE_SIZE + 256
        <= iroh_gossip::proto::DEFAULT_MAX_MESSAGE_SIZE,
    "MAX_MESSAGE_SIZE leaves too little headroom under iroh-gossip's DEFAULT_MAX_MESSAGE_SIZE"
);

pub(crate) use json_body::json_body;
pub use merge_ctx::{
    MergeCtx, StateMergeParams, app_frame, broadcast_msg, broadcast_state_merge, send_app,
    start_ping_round, unicast_farewell,
};
pub(crate) use merge_ctx::{broadcast_peer_info, send_second_probe};
pub(crate) use path_summary::PathSummary;

pub(crate) use recv::{
    drain_dead_receiver, drain_queued, flush_pending, handle_gossip_event, ingest, requeue_failed,
    retain_own_broadcast,
};
