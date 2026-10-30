//! A habilis-network mesh peer for the browser: [`habilis_network::membership`] behind one
//! wasm-bindgen class.
//!
//! Everything crosses the JS boundary as a JSON string — options in, messages,
//! events, roster and state out — because a `js_sys::Function` is neither
//! `Send` nor `Sync` and could never be held by the engine's sink; the JS
//! side polls [`MeshPeer::next_msg`] / [`MeshPeer::next_event`] instead
//! (the same shape `packages/habilis-network-api` was designed around). One in-flight
//! call per queue: the receivers are behind async mutexes, so a second
//! concurrent `nextMsg()` waits rather than panics.
//!
//! # Example
//!
//! ```js
//! const peer = await MeshPeer.open(JSON.stringify({ name: "demo" }));
//! await peer.stateMerge(JSON.stringify({ hello: "world" }));
//! console.log(peer.id(), await peer.peerCount());
//! ```

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

mod stream_node;

mod mesh_peer;

pub use mesh_peer::MeshPeer;
pub(crate) use mesh_peer::to_js_error;

mod tracing_console;

pub use tracing_console::init_tracing;
