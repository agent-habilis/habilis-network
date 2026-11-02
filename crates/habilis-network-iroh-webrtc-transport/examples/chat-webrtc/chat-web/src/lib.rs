//! An iroh endpoint in a browser tab, talking QUIC over a `WebRTC` data
//! channel.
//!
//! # The two-endpoint dance
//!
//! A tab binds **two endpoints on one secret key**, and that is the single
//! least obvious thing in this example:
//!
//! - a *signalling* endpoint, which holds the relay and is used once, to swap
//!   one JSEP envelope each way with the room;
//! - a *chat* endpoint, with `RelayMode::Disabled` and nothing registered but
//!   the `WebRTC` transport, which carries the conversation.
//!
//! Why not one. iroh only fans a connect's Initial out to candidate paths
//! *while the remote has no selected path*, so a live connection cannot be
//! upgraded onto a transport attached after it. The signalling connection has
//! already settled on the relay; a chat dial from that same endpoint would
//! settle there too and stay for the life of the connection. Giving the chat an
//! endpoint with no other path to lose to is what makes `webrtc` the answer
//! rather than a coin flip.
//!
//! Why one key. The room keys its roster, its session registry and its TLS by
//! endpoint id. Two keys would arrive as two strangers, and the session
//! negotiated by the first would not route the second's traffic.
//!
//! Why only the signalling endpoint may hold the relay: two same-key endpoints
//! registering with one relay server fight over the registration, and ICE never
//! completes.

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

mod address;
mod chat_peer;
mod emitter;
mod event;
mod js_error;
mod negotiate;
mod tasks;
mod wire;

pub(crate) use address::{candidate, label_of};
pub(crate) use emitter::Emitter;
pub(crate) use event::{Event, event_of};
pub(crate) use js_error::{describe, err};
pub(crate) use negotiate::negotiate;
pub(crate) use tasks::{spawn_reader, spawn_writer};
pub(crate) use wire::{read_msg, write_msg};
