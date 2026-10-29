use crate::beacon;
use crate::daemon::event_loop::ctx_parts::CtxParts;

use iroh_gossip::net;
/// The resubscribe attempt's read-only environment: the gossip frontend to
/// re-subscribe through, the rendezvous params to bootstrap from, the shared
/// ctx-building parts (for its `sink` and to rebuild a [`HandlerCtx`] once the
/// sender is swapped).
pub(in crate::daemon) struct ResubscribeEnv<'node> {
    pub(in crate::daemon) gossip: &'node net::Gossip,
    pub(in crate::daemon) params: &'node beacon::RendezvousParams,
    pub(in crate::daemon) parts: &'node CtxParts<'node>,
}
