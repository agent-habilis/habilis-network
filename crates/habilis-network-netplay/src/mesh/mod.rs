//! Running a rollback session over a habilis-network mesh.
//!
//! This is the part that makes the crate concrete: everything above it is
//! transport-agnostic rollback machinery, and this is where it meets the
//! engine that actually connects peers.
//!
//! Three pieces, in the order a consumer meets them:
//!
//! 1. [`RollbackDriver`] — the `NodeApp`/`NodeDriver` handed to
//!    `Node::spawn`. It owns the mailboxes and is the only code that calls
//!    `send_app`.
//! 2. [`Lobby`] — peers announce themselves, someone starts, and everyone
//!    derives the same player list and the same handle assignment.
//! 3. [`MeshTransport`] — the [`crate::Transport`] the session drives, backed
//!    by those mailboxes.
//!
//! # Why there are mailboxes at all
//!
//! `habilis_network::ops::send_app` needs `&mut EventLoopState`, which exists only
//! *inside* the engine's event loop. The game's frame loop runs outside it.
//! So sends cannot happen where the session wants to make them.
//!
//! Instead [`MeshTransport::send_to`] enqueues onto the node's session
//! channel (`Node::sender()`), and the driver drains it inside
//! `handle_session` where the engine hands it the state it needs. Inbound
//! goes the other way: `on_app_frame` fires in the event loop and drops
//! decoded packets into a mailbox the frame loop drains. It is the same
//! pattern an app would write by hand, kept here so every consumer does not.
//!
//! # Framing
//!
//! Packets are `serde_json` inside a `MessageBody`. JSON rather than a
//! binary codec because `MessageBody` accepts only UTF-8 without control
//! characters — JSON satisfies that by construction, where a binary encoding
//! would need base64 over the top, costing a dependency, an extra copy and
//! 33% size. Rollback packets are small (a handful of frames of a small
//! input), so the compactness a binary codec would buy is not worth that.

mod driver;
mod lobby;
mod transport;

pub use driver::{LOBBY_TAG, Outbound, ROLLBACK_TAG, RollbackDriver};
pub use lobby::{Lobby, LobbyError, StartedMatch};
pub use transport::MeshTransport;
