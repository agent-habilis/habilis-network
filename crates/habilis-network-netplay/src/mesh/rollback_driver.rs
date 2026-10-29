//! The engine-facing half: mailboxes, framing, and the only `send_app` call.

use habilis_network::protocol::message::Authored;
use std::sync::Arc;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver,
};
use habilis_network::protocol::message::Verified;
use habilis_network::protocol::{AppFrameParams, AppTag, MessageBody, Nickname};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::mesh::mailboxes::Mailboxes;
use crate::mesh::outbound::Outbound;
use crate::mesh::pending_transport::PendingTransport;
use crate::transport::Message;

/// App tag for rollback packets.
pub const ROLLBACK_TAG: &str = "rb_input";
/// App tag for lobby packets.
pub const LOBBY_TAG: &str = "rb_lobby";

/// The `NodeApp`/`NodeDriver` a rollback consumer hands to `Node::spawn`.
///
/// Construct one with [`RollbackDriver::new`], keep the returned
/// [`MeshTransport`](super::MeshTransport) handle for the session, and give
/// the driver to the node.
pub struct RollbackDriver<T: Config> {
    // the driver shares the mailboxes with the transports it hands out
    mailboxes: Arc<Mailboxes<T>>,
}

impl<T: Config> std::fmt::Debug for RollbackDriver<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RollbackDriver")
            .finish_non_exhaustive()
    }
}

// the driver takes the mailboxes that its transports share
impl<T: Config> From<Arc<Mailboxes<T>>> for RollbackDriver<T> {
    // the driver takes the mailboxes that its transports share
    fn from(mailboxes: Arc<Mailboxes<T>>) -> Self {
        Self { mailboxes }
    }
}

impl<T: Config> RollbackDriver<T> {
    /// Build a driver and the transport that talks to it.
    ///
    /// Hand the driver to `Node::spawn`, then pass the node's
    /// `sender()` to `PendingTransport::connect` to finish wiring:
    ///
    /// ```ignore
    /// let (driver, pending) = RollbackDriver::<MyGame>::new();
    /// let node = Node::spawn(config, driver, None, SignalHandling::Leave);
    /// let transport = pending.connect(node.sender());
    /// ```
    ///
    /// Split in two because the outbound channel only exists once the node
    /// has been spawned, and the node needs the driver to spawn.
    #[must_use]
    pub fn new() -> (Self, PendingTransport<T>) {
        // the driver and the pending transport share the mailboxes
        let mailboxes = Arc::new(Mailboxes::new());
        (
            Self::from(Arc::clone(&mailboxes)),
            PendingTransport::new(mailboxes),
        )
    }
}

/// Decode a packet body, ignoring anything malformed.
fn decode<Decoder: for<'de> Deserialize<'de>>(body: &str) -> Option<Decoder> {
    serde_json::from_str(body).ok()
}

/// Encode a packet body.
pub(crate) fn encode<S: Serialize>(value: &S) -> Option<String> {
    serde_json::to_string(value).ok()
}

#[habilis_network::async_trait]
impl<T: Config> NodeApp for RollbackDriver<T> {
    /// Every flag off but `valid`.
    ///
    /// `loggable: false` is a correctness requirement, not a preference:
    /// a `true` here would enter every input frame into the engine's message
    /// log and its anti-entropy repair. A frame of this crate is also always
    /// directed, and `send_app` keeps only a broadcast frame of its own.
    /// It lives in the library so a consumer cannot get it wrong.
    fn classify(&self, message: &Authored) -> AppClass {
        let tag = message.kind.app_tag().map(AppTag::as_str);
        let ours = matches!(tag, Some(ROLLBACK_TAG | LOBBY_TAG));
        AppClass::NONE.with_if(AppClass::VALID, ours)
    }

    async fn on_app_frame(
        &mut self,
        frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) -> bool {
        let Some(tag) = frame.message.kind.app_tag().map(AppTag::as_str) else {
            return false;
        };
        let pubkey = frame.message.key();

        // Learn the pubkey -> nickname pairing from any frame. The signed
        // pubkey is the identity; the nickname is only how `send_app`
        // addresses it.
        if let Ok(mut directory) = self.mailboxes.directory.lock() {
            directory.insert(pubkey, frame.message.author.clone());
        }

        match tag {
            ROLLBACK_TAG => {
                if let Some(message) = decode::<Message<T::Input>>(frame.message.body.as_str())
                    && let Ok(mut inbound) = self.mailboxes.inbound.lock()
                {
                    inbound.push_back((pubkey, message));
                }
            }
            LOBBY_TAG => {
                if let Ok(mut lobby) = self.mailboxes.lobby.lock() {
                    lobby.push((pubkey, frame.message.body.as_str().to_owned()));
                }
            }
            _ => {}
        }
        false
    }
}

#[habilis_network::async_trait]
impl<T: Config> NodeDriver for RollbackDriver<T> {
    type Session = Outbound;
    type Http = ();
    type Ipc = serde_json::Value;

    /// Our own public key exists only once the loop is running — nothing
    /// before `Node::spawn` has access to `HandlerCtx` — so this is the
    /// first chance to record it. [`super::MeshTransport::local_pubkey`] surfaces
    /// it to the frame loop, which needs it to build a [`super::Lobby`].
    async fn on_startup(&mut self, _state: &mut EventLoopState, context: &HandlerCtx<'_>) {
        if let Ok(mut slot) = self.mailboxes.local_pubkey.lock() {
            *slot = Some(context.our_pubkey);
        }
    }

    async fn handle_session(
        &mut self,
        request: Outbound,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Outbound::Rollback { to, payload } => {
                // Resolve and release the lock *before* awaiting: holding a
                // `std::sync::Mutex` guard across an await is denied
                // workspace-wide, and rightly so.
                let nickname: Option<Nickname> = {
                    let book = self.mailboxes.directory.lock().ok();
                    book.and_then(|directory| directory.get(&to).cloned())
                };
                let Some(nickname) = nickname else {
                    // We have never heard from this peer, so we cannot
                    // address it. The lobby only admits peers we have heard
                    // from, so this means they left mid-match.
                    tracing::debug!(
                        peer = %to,
                        "dropped a rollback packet for a peer with no known nickname"
                    );
                    return false;
                };
                let Some(frame) = frame_for(context, ROLLBACK_TAG, Some(nickname), &payload) else {
                    return false;
                };
                let class = self.classify(&frame.authored());
                send(state, context, frame, class).await
            }
            Outbound::Lobby { payload } => {
                // Addressed to every roster member individually — never a
                // gossip broadcast. Besides the resend hazard, `send_app`'s
                // broadcast bodies are not mesh-key-sealed, so on a
                // passworded mesh receivers drop them outright.
                let peers: Vec<Nickname> = state
                    .roster_snapshot()
                    .peers
                    .into_iter()
                    .map(|peer| peer.nickname)
                    .collect();
                let mut delivered = false;
                for peer in peers {
                    let Some(frame) = frame_for(context, LOBBY_TAG, Some(peer), &payload) else {
                        continue;
                    };
                    let class = self.classify(&frame.authored());
                    delivered |= send(state, context, frame, class).await;
                }
                delivered
            }
        }
    }
}

/// The frame of one `send_app`, or `None` for a tag or a payload the wire refuses.
fn frame_for(
    context: &HandlerCtx<'_>,
    tag: &str,
    to: Option<Nickname>,
    payload: &str,
) -> Option<Verified> {
    let (Ok(tag), Ok(body)) = (AppTag::try_new(tag), MessageBody::try_new(payload)) else {
        return None;
    };
    Some(habilis_network::ops::app_frame(
        context,
        AppFrameParams::new(tag, to, None, body),
    ))
}

/// One `send_app`, with the failure swallowed.
///
/// Failure is genuinely uninteresting here: this layer assumes a lossy
/// transport and recovers by resending, so a caller could not act on the
/// error even if it had it.
async fn send(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    frame: Verified,
    class: AppClass,
) -> bool {
    habilis_network::ops::send_app(state, context, frame, class)
        .await
        .is_ok()
}
