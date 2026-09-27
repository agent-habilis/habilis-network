//! `fofoca-ffi` — the C-ABI boundary over the `fofoca`
//! engine.
//!
//! The **third consumer** of the engine, and the first non-Rust one: it exposes
//! an opaque handle plus blocking text/JSON calls (see `include/fofoca.h`) so a
//! C program can create or join a mesh, exchange broadcast and directed
//! messages, and read/write the shared automerge state document — in-process,
//! with no daemon and no socket.
//!
//! It also exposes byte streams: a producer creates one and hands its hash to
//! one consumer, over a direct QUIC path rather than gossip.
//!
//! [`mesh`] is the blocking handle over `fofoca::membership`, [`stream`] the
//! blocking handles over `fofoca-stream`; [`ffi`] is the thin unsafe shim over
//! both.

pub mod ffi;
pub mod mesh;
pub mod stream;
