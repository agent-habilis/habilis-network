//! Everything that moves bytes for the mesh, on either plane:
//!
//! - [`deliver`] — the single cross-plane send decision: a broadcast rides
//!   gossip, a directed message goes over the **unicast** point-to-point QUIC
//!   channel only (`send`). [`deliver_in_background`] takes the same decision but
//!   never waits on a dial, for callers on the event loop.
//! - The unicast plane machinery: the per-peer connection pool (`pool`) and
//!   the inbound acceptor (`accept`). Distinct from `link` (a gossip
//!   active-view neighbor) and from `Reach::Direct` (a gossip-overlay
//!   concept): a unicast connection is a real client/server QUIC link this
//!   node opens to one peer's endpoint, on its own ALPN, off the
//!   gossip flood.
//! - [`MeshSender`] — the gossip broadcast handle (`sender`).
//! - `ipc` — the unix-socket / named-pipe listener used by the CLI's `msg`
//!   and `poll` subcommands to talk to a running `create` or `join` daemon.
//!   (The MCP stdio server is a separate, consumer-side path.)
//!
//! Inbound unicast frames are funnelled into the *same* validation+dispatch
//! path as gossip (`gossip::ingest`), so signature-verify, the mesh gate, and
//! cross-transport dedup are identical on both planes.

mod accept;
mod admission;
mod direct_gossip;
#[cfg(feature = "host")]
pub(crate) mod ipc;
pub(crate) mod path;
mod pool;
pub(crate) mod probe;
// The JSEP exchange that fills `lookup::TransportHandles::webrtc`. Portable:
// a browser peer negotiates with a CLI peer over the same envelope, and only
// the backend behind it differs.
pub(crate) mod webrtc;

/// Messages flowing from the IPC listener to the event loop, generic over the
/// app's command type `C`: the command, plus the channel the loop sends its raw
/// JSON response back on.
///
/// Deliberately declared out here rather than inside the host-gated [`ipc`]
/// module. It is a plain tuple with nothing host-specific in it, and keeping it
/// portable is what lets the event loop's IPC `select!` arm compile everywhere
/// and simply never fire — a browser binds no socket, so its receiver is always
/// `None`. Only the socket *server* needs `interprocess`.
pub(crate) type IpcMessage<C> = (C, tokio::sync::oneshot::Sender<String>);
mod send;
pub(crate) mod sender;

pub(crate) use accept::UnicastAcceptor;
pub use admission::SignalAdmission;
pub(crate) use direct_gossip::DirectOnlyGossip;
#[cfg(feature = "blob")]
pub(crate) use path::{PROBE_DEADLINE, refuse_relayed};
pub(crate) use path::{RELAY_REFUSED, payload_allowed_on};
pub(crate) use pool::UnicastPool;
pub(crate) use send::HeldForDirect;
pub use send::Lane;
pub(crate) use send::lane_for;
pub(crate) use send::send_best_effort;
pub use send::{deliver, deliver_in_background};
pub use sender::MeshSender;
pub use webrtc::MAX_DIRECT_PEERS;
pub(crate) use webrtc::{IceProfile, MESH_WEBRTC_SIGNAL_ALPN, WebRtcSignalAcceptor};

/// ALPN for the unicast channel — a raw bidirectional QUIC stream with its own
/// protocol identity, distinct from `GOSSIP_ALPN` and the application's own bridge ALPN.
/// Wire-load-bearing: changing it is a protocol break, so it moves only with
/// `message::VERSION` (it last changed when the byte-domains dropped the
/// product's name for the engine's).
pub(crate) const UNICAST_ALPN: &[u8] = b"habilis-mesh/unicast/1";

/// `tracing` target for the unicast plane (matches the module path so
/// `EnvFilter` prefix-matching works, e.g. `RUST_LOG=fofoca::transport=debug`).
pub(crate) const LOG_TARGET: &str = "fofoca::transport";
