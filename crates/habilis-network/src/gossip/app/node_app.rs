use super::{AppClass, InboundApp};
use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::protocol::messages::Authored;
use crate::protocol::{AuthorKey, Nickname};

/// The seam the engine drives for application-payload handling. The engine
/// owns [`EventLoopState`] and hands the app the frame plus the loop context
/// once it has done parse → signature verify → mesh gate → dedup → shard
/// reassembly → unseal. The app never names an engine transport detail it
/// isn't given here.
///
/// # Examples
///
/// A node app handles the application payloads of a node, and it classifies each message. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::{AppClass, NodeApp};
/// use habilis_network::protocol::Authored;
///
/// # fn demo<App: NodeApp>(app: &App, message: &Authored) -> AppClass {
/// app.classify(message)
/// # }
/// ```
#[async_trait::async_trait]
pub trait NodeApp: Send {
    /// Classify one inbound `App` frame by tag/payload — see [`super::AppClass`].
    fn classify(&self, message: &Authored) -> AppClass;

    /// Dispatch an inbound `App` frame after the engine's generic prefix. The frame can be
    /// addressed to us, broadcast, or directed to **another key** that this node relays for
    /// anti-entropy: the engine does not filter by recipient, and a nickname is a label, so the
    /// other key of a shared nickname is another peer. An app that acts on a directed frame must
    /// check that `to` is `context.our_pubkey` itself, and return `false` for a frame that is not
    /// for it. Returns `true` when the engine should retain/index the frame (a relay then holds
    /// it, and gives it only to its addressee in an anti-entropy answer), `false` when it must
    /// stop and not retain it (plumbing like an RPC leg, or a directed leg addressed elsewhere).
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
    /// endpoint hint into the dial book, if any. `author` is the key that signed the
    /// event, and the slot of that key is the one that changed: a nickname is a label that
    /// two keys can share, so it does not name a slot.
    ///
    /// Defaults to a no-op — an app that publishes no per-peer endpoint hint
    /// into the meta channel has nothing to adopt.
    fn on_meta_applied(
        &mut self,
        author: &AuthorKey,
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
    /// Fired once for every key of the roster that says goodbye, whether or not
    /// the arrival of the peer was shown, and whatever the stamp of the goodbye:
    /// the clock of the sender can run slow. Another key that
    /// still holds the nickname does not change that: a nickname is a label,
    /// and the state of the key that left is not valid for its twin. `nickname`
    /// is the one that the roster recorded for `key`; the roster has dropped it
    /// when the hook runs, so `state.nickname_of(key)` gives `None` here. An app
    /// that reads the whole roster (`live_nicknames`) holds state for a peer
    /// that is not shown yet, and must release it. Never fired for the goodbye
    /// of a key that is not in the roster, and never from the silence-timeout
    /// sweep: a quiet peer may return, so its app-side state must survive a
    /// mere timeout.
    ///
    /// Defaults to a no-op — an app holding no per-peer state has nothing to
    /// release.
    async fn on_peer_left(
        &mut self,
        key: &AuthorKey,
        nickname: &Nickname,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) {
        let _ = (key, nickname, state, context);
    }
}
