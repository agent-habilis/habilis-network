//! The seams a consumer implements or is handed.
//!
//! Implement [`NodeApp`] to handle application payloads and [`NodeDriver`] to
//! own the session/IPC/HTTP request types; implement [`NodeSink`] to receive the
//! engine's surfacings. Everything else here is a value the engine passes *into*
//! those hooks.

// `NodeDriver` is portable — a browser implements the same seam. `IpcRequest`
// is not: it is the control socket's request envelope, and there is no socket
// off a host.
#[cfg(feature = "host")]
pub use crate::daemon::app::IpcRequest;
pub use crate::daemon::app::NodeDriver;
pub use crate::daemon::ctx::HandlerCtx;
pub use crate::daemon::state::{EventLoopState, PingRound, Reach, RosterEntry, RosterSnapshot};
pub use crate::doc::SelfWriteGate;
pub use crate::gossip::app::{AppClass, InboundApp, NodeApp};
pub use crate::gossip::event::{NodeEvent, NodeSink, SilentSink};
pub use crate::transport::Lane;
