//! The **gossip subsystem**: the message transport plane. The outbound
//! send plane is [`broadcast`] (broadcast/buffer, presence/`PeerInfo`,
//! the broadcast stdin path); the inbound plane is [`recv`] (the
//! gossip-event pump, neighbor up/down bookkeeping, the per-message
//! router); anti-entropy and the healer are [`antientropy`] / [`heal`].
//! This module itself holds only the shared `conn_path` diagnostic and
//! re-exports the subsystem's public API. Membership/presentation lives
//! in `lifecycle`; this layer never touches the peer roster
//! directly — it calls into `lifecycle::observe` and dispatches by kind.

pub(crate) mod antientropy;
pub(crate) mod app;
mod broadcast;
pub(crate) mod event;
pub(crate) mod heal;
mod recv;
pub(crate) mod split;

use iroh::endpoint::TransportAddrUsage;
use iroh::{Endpoint, EndpointId, RelayUrl, TransportAddr};

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

pub use broadcast::{
    StateMergeParams, broadcast_msg, broadcast_state_merge, send_app, start_ping_round,
    unicast_farewell,
};
pub(crate) use broadcast::{broadcast_peer_info, send_second_probe};

/// Serialize `value` as the JSON body of a control frame, or `None` when it
/// will not fit a [`MessageBody`](crate::protocol::MessageBody).
///
/// Both failure modes are unreachable for the types that use this — a struct of
/// strings and numbers always serializes, and its JSON carries no control
/// characters — but a control broadcast that cannot build its body drops the
/// tick rather than panicking, so every caller was writing the same pair of
/// `let ... else { return; }` guards.
pub(crate) fn json_body<T: serde::Serialize>(value: &T) -> Option<crate::protocol::MessageBody> {
    let json = serde_json::to_string(value).ok()?;
    crate::protocol::MessageBody::new(json).ok()
}
pub(crate) use recv::{
    drain_dead_receiver, flush_pending, handle_gossip_event, ingest, retain_own_broadcast,
};

/// Which transport paths to a peer are active: direct (IP or a custom
/// transport), the relay, both, or none reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSummary {
    Direct,
    Relay,
    Mixed,
    Unknown,
}

impl PathSummary {
    /// The log label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Mixed => "mixed",
            Self::Unknown => "unknown",
        }
    }
}

/// Snapshot the active transport paths to `node_id`, plus the relay URL
/// when one is in use. Point-in-time, not a watcher — iroh starts a fresh
/// link relayed and upgrades to direct after hole-punching, so a reading
/// taken right at `NeighborUp` skews toward `relay`; the periodic census
/// reading is the representative one. Diagnostics only; other iroh apps
/// wanted this too (sendme #67/#112, psyche #586).
pub async fn conn_path(
    endpoint: &Endpoint,
    node_id: EndpointId,
) -> (PathSummary, Option<RelayUrl>) {
    let Some(info) = endpoint.remote_info(node_id).await else {
        return (PathSummary::Unknown, None);
    };
    let mut has_direct = false;
    let mut has_relay = false;
    let mut relay_url = None;
    for addr in info.addrs() {
        if !matches!(addr.usage(), TransportAddrUsage::Active) {
            continue;
        }
        // `TransportAddr` is `#[non_exhaustive]`, so a wildcard is
        // mandatory and the match can't be made exhaustive.
        match addr.addr() {
            TransportAddr::Relay(url) => {
                has_relay = true;
                relay_url = Some(url.clone());
            }
            // A custom transport (`WebRTC`, multihop) is a peer-to-peer path
            // as far as the relay is concerned: nothing on it crosses the
            // relay server.
            TransportAddr::Ip(_) | TransportAddr::Custom(_) => has_direct = true,
            _ => {}
        }
    }
    let summary = match (has_direct, has_relay) {
        (true, true) => PathSummary::Mixed,
        (true, false) => PathSummary::Direct,
        (false, true) => PathSummary::Relay,
        (false, false) => PathSummary::Unknown,
    };
    (summary, relay_url)
}
