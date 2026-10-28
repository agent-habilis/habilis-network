use iroh::{Endpoint, EndpointId};
use tokio::sync::broadcast;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::gossip::event::NodeSink;
use crate::protocol::message::Authored;
use crate::protocol::{AuthorKey, MeshId, Nickname, identity};
use crate::transport::MeshSender;

/// Everything a [`HandlerCtx`] needs except the gossip sender. The loop
/// holds one of these and builds the ctx per-arm (`parts.handler_ctx(&sender)`):
/// a loop-lifetime ctx would borrow `sender` forever, and the
/// resubscribe path must be able to replace it.
pub(in crate::daemon) struct CtxParts<'node> {
    pub(in crate::daemon) endpoint: &'node Endpoint,
    pub(in crate::daemon) mesh: &'node MeshId,
    pub(in crate::daemon) author: &'node Nickname,
    pub(in crate::daemon) identity: &'node identity::Identity,
    pub(in crate::daemon) our_pubkey: AuthorKey,
    pub(in crate::daemon) max_peers: usize,
    pub(in crate::daemon) rendezvous_id: EndpointId,
    pub(in crate::daemon) external_msg_tx: Option<&'node broadcast::Sender<Authored>>,
    pub(in crate::daemon) sink: &'node dyn NodeSink,
}

impl<'node> CtxParts<'node> {
    pub(in crate::daemon) fn handler_ctx<'handler>(
        &'handler self,
        sender: &'handler MeshSender,
    ) -> HandlerCtx<'handler>
    where
        'node: 'handler,
    {
        HandlerCtx {
            sender,
            endpoint: self.endpoint,
            mesh: self.mesh,
            author: self.author,
            identity: self.identity,
            our_pubkey: self.our_pubkey,
            max_peers: self.max_peers,
            rendezvous_id: self.rendezvous_id,
            external_msg_tx: self.external_msg_tx,
            sink: self.sink,
        }
    }
}
