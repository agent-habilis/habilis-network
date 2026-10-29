use super::{AppClass, InboundApp};
use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::protocol::Nickname;
use crate::protocol::message::Authored;

/// The seam the engine drives for application-payload handling. The engine
/// owns [`EventLoopState`] and hands the app the frame plus the loop context
/// once it has done parse → signature verify → mesh gate → dedup → shard
/// reassembly → unseal. The app never names an engine transport detail it
/// isn't given here.
#[async_trait::async_trait]
pub trait NodeApp: Send {
    /// Classify one inbound `App` frame by tag/payload — see [`AppClass`](super::AppClass).
    fn classify(&self, message: &Authored) -> AppClass;

    /// Dispatch an inbound `App` frame (addressed to us, or broadcast) after
    /// the engine's generic prefix. Returns `true` when the engine should
    /// proceed to retain/index the frame, `false` when it must stop (plumbing
    /// like an RPC leg, or a directed leg addressed elsewhere).
    async fn on_app_frame(
        &mut self,
        frame: InboundApp<'_>,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool;

    /// Surface a reassembled multipart `App` body through the same path an
    /// unsplit frame of that tag would take (the raw shards were already
    /// retained; this only surfaces the logical view).
    ///
    /// Defaults to a no-op — an app that never splits a body past
    /// [`crate::util::consts::MAX_MESSAGE_SIZE`] (so the engine never reassembles
    /// one for it) has nothing to surface here.
    fn surface_logical(&mut self, logical: &Authored, surfaceable: bool, context: &HandlerCtx<'_>) {
        let _ = (logical, surfaceable, context);
    }

    /// Post-apply hook for a meta-channel event: adopt the author's published
    /// endpoint hint into the dial book, if any.
    ///
    /// Defaults to a no-op — an app that publishes no per-peer endpoint hint
    /// into the meta channel has nothing to adopt.
    fn on_meta_applied(
        &mut self,
        author: &Nickname,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) {
        let _ = (author, state, context);
    }

    /// The node just formed its first real-peer link (became meshed). Lets the
    /// app re-publish anything whose value depends on being meshed — e.g. its
    /// card's dial hint, now that the home relay is homed and the startup
    /// publish's (possibly path-less) hint can be corrected.
    ///
    /// Defaults to a no-op — an app with nothing to re-publish on the mesh edge
    /// leaves it empty.
    async fn on_meshed(&mut self, state: &mut EventLoopState, context: &HandlerCtx<'_>) {
        let _ = (state, context);
    }

    /// A peer broadcast a graceful `Left` and was removed from the roster.
    /// Fired only for a surfaced departure — never for a relayed pre-join
    /// `Left`, and never from the silence-timeout sweep: a quiet peer may
    /// return, so its app-side state must survive a mere timeout.
    ///
    /// Defaults to a no-op — an app holding no per-peer state has nothing to
    /// release.
    async fn on_peer_left(
        &mut self,
        nickname: &Nickname,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) {
        let _ = (nickname, state, context);
    }
}
