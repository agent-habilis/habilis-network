//! Probe, then graft: on a mesh whose relay is lookup only, a peer joins our
//! gossip overlay only once a direct path to it is proven.
//!
//! iroh opens the first connection to a peer behind NAT over the relay and
//! punches a direct path *inside* it; a gossip link opened on that connection
//! would carry every frame relayed until the punch lands — and, for a `WebRTC`
//! peer, for the life of the link, since a custom-transport path is never
//! added to a live connection. So the graft waits: an IP peer is probed with
//! the unicast pool's own connection until iroh selects a non-relay path, a
//! browser peer until its `WebRTC` session is attached. Both bounded — a
//! peer that never proves a direct path stays `RelayOnly`, retried on the
//! alive tick, and is never grafted through the relay.
mod direct_outcome;
mod graft_request;
mod grafts;
mod kinds;
mod lanes;
mod nudge_addrs;
mod pair_to_climb;
mod path_action;
mod path_change;
mod path_kind;
mod regraft;
mod step;
mod watchers;
pub(crate) use direct_outcome::DirectOutcome;
pub(crate) use graft_request::graft_request;
pub(crate) use grafts::{
    ensure_direct, on_outcome, request_graft, retry_direct,
};
pub(crate) use kinds::{
    allow_for, any_not_ip, best_kind, pair_kind, selected_kind,
};
pub(crate) use lanes::{lane_pick, plan_lane_offers, top_up_lane_offers};
pub(crate) use nudge_addrs::NudgeAddrs;
pub(crate) use path_action::path_action;
pub(crate) use path_change::PathChange;
pub(crate) use path_kind::PathKind;
pub(crate) use regraft::{
    refill_isolated, regraft_due,
};
pub(crate) use step::step;
pub(crate) use watchers::{
    ensure_watchers, mark_proven, nudge_climbing_pairs, nudge_known,
    nudge_webrtc_riders, on_path_change, prove_routed_pairs,
};
