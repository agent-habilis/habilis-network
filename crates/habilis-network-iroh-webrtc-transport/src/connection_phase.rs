//! The pure half of the browser hub's peer-connection watchdog.
//!
//! A data channel reports `close` when its own transport goes away, but not
//! when ICE underneath it fails: after a laptop sleep, or a peer that stops
//! answering consent checks, `RTCPeerConnection.connectionState` moves to
//! `disconnected` and then `failed` while the channel still reads `open`. A
//! session judged live only by its channel therefore stays in the registry,
//! keeps counting toward the direct-peer total, and keeps refusing a re-dial.
//!
//! The judgment lives here, free of every `web-sys` type, for the same reason
//! [`crate::registry`] does: the browser backend cannot be unit-tested off
//! wasm32, and this is the part with the hysteresis worth testing.

/// A coarse reading of `RTCPeerConnection.connectionState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionPhase {
    /// `new`, `connecting`, or `connected`: nothing to do.
    Healthy,
    /// `disconnected`: ICE may still recover on its own.
    Disconnected,
    /// `failed` or `closed`: the connection will not come back.
    Dead,
}
