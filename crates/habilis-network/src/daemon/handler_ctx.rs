//! `HandlerCtx`, hoisted here so both `gossip` and `lifecycle` share it.

use iroh::{Endpoint, EndpointId};
use tokio::sync::broadcast;

use crate::gossip::event::NodeSink;
use crate::protocol::identity::Identity;
use crate::protocol::messages::Authored;
use crate::protocol::{AuthorKey, MeshId, Nickname};
use crate::transport::MeshSender;

use std::fmt;
/// Immutable loop-level context threaded through every handler.
/// Bundles the refs a handler may need but never mutates itself.
///
/// # Examples
///
/// A handler context is what a handler gets from the node for one event. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::HandlerCtx;
///
/// # fn demo(ctx: &HandlerCtx<'_>) {
/// let _ = ctx;
/// # }
/// ```
#[derive(Clone)]
pub struct HandlerCtx<'node> {
    /// The sender of the topic.
    pub sender: &'node MeshSender,
    /// This node's iroh endpoint.
    pub endpoint: &'node Endpoint,
    /// The id of the mesh this node belongs to.
    pub mesh: &'node MeshId,
    /// This member's nickname, the author of every message it sends.
    pub author: &'node Nickname,
    /// This member's signing identity (Ed25519). Messages we author are
    /// signed with it before broadcast; see [`Identity`].
    pub identity: &'node Identity,
    /// Our own author key — taken once at loop setup so the per-message
    /// self-echo check is a 32-byte compare, not a fresh key derivation on
    /// every inbound message.
    pub our_pubkey: AuthorKey,
    pub(crate) max_peers: usize,
    /// Well-known rendezvous endpoint id. Its co-hosted pseudo-node
    /// shows up as a gossip neighbor on peer endpoints; it is
    /// filtered out of peer accounting everywhere it could leak.
    pub rendezvous_id: EndpointId,
    /// Inbound push channel. `Some` only when the in-process consumer wired one
    /// (`DriverMode::InProcess::msg_tx`); every inbound message that survives
    /// the self-author filter is forwarded here before kind routing. `None` for
    /// the CLI, and for an in-process consumer that drains frames some other way.
    pub(crate) external_msg_tx: Option<&'node broadcast::Sender<Authored>>,
    /// Per-loop generic event sink: the engine emits
    /// [`NodeEvent`](crate::gossip::event::NodeEvent) through it and never names
    /// the app's concrete `Output`. Borrowed for the loop's lifetime; handlers
    /// emit through `ctx.sink`. The app layer reaches its own renderer
    /// separately (it owns the concrete `Output`).
    pub sink: &'node dyn NodeSink,
}

// Manual: `sink` is a `&dyn NodeSink` trait object with no `Debug` bound, so
// the struct can't derive. The identity fields below are what a log reader cares
// about; the borrowed handles are elided.
impl fmt::Debug for HandlerCtx<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("HandlerCtx");
        debug.field("mesh", &self.mesh);
        debug.field("author", &self.author);
        debug.field("rendezvous_id", &self.rendezvous_id);
        debug.finish_non_exhaustive()
    }
}
