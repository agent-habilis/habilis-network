//! The engine-facing half: mailboxes, framing, and the only `send_app` call.

use habilis_network::protocol::messages::{Authored, sole_addressee};
use std::sync::Arc;

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver,
};
use habilis_network::protocol::messages::Verified;
use habilis_network::protocol::{AppFrameParams, AppTag, AuthorKey, MessageBody, Nickname};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::mesh::mailboxes::Mailboxes;
use crate::mesh::outbound::Outbound;
use crate::mesh::pending_transport::PendingTransport;
use crate::transport::Message;

use habilis_network::ops;
use std::fmt;
/// App tag for rollback packets.
pub const ROLLBACK_TAG: &str = "rb_input";
/// App tag for lobby packets.
pub const LOBBY_TAG: &str = "rb_lobby";

/// The `NodeApp`/`NodeDriver` a rollback consumer hands to `Node::spawn`.
///
/// Construct one with [`RollbackDriver::new`], keep the returned
/// [`MeshTransport`](super::MeshTransport) handle for the session, and give
/// the driver to the node.
///
/// # Examples
///
/// A driver is made together with the pending transport that its node connects.
///
/// ```
/// use habilis_network_netplay::RollbackDriver;
///
/// use habilis_network_netplay::Config;
///
/// struct Game;
///
/// impl Config for Game {
///     type Input = u8;
///     type State = u32;
///     type Address = u8;
/// }
///
/// let (_driver, _pending) = RollbackDriver::<Game>::new();
/// ```
#[derive(Clone)]
pub struct RollbackDriver<T: Config> {
    // the driver shares the mailboxes with the transports it hands out
    mailboxes: Arc<Mailboxes<T>>,
}

impl<T: Config> fmt::Debug for RollbackDriver<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        AppClass::NONE.plus_if(AppClass::VALID, ours)
    }

    async fn on_app_frame(
        &mut self,
        frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        let Some(tag) = frame.message.kind.app_tag().map(AppTag::as_str) else {
            return false;
        };
        // The engine gives the app a frame that a relay holds for another key. A nickname is a
        // label, so that key can be a twin of ours, and its packet is not ours to act on.
        if sole_addressee(&frame.message.kind).is_some_and(|to| *to != context.our_pubkey) {
            return false;
        }
        let pubkey = frame.message.key();

        // Learn the pubkey -> nickname pairing from any frame. The signed
        // pubkey is the identity; the nickname is a label to show.
        if let Ok(mut directory) = self.mailboxes.directory.lock() {
            directory.insert(pubkey, frame.message.author.clone());
        }

        match tag {
            ROLLBACK_TAG => {
                let decoded: Option<Message<T::Input>> = decode(frame.message.body.as_str());
                if let Some(message) = decoded
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

    /// A key that left the mesh leaves the directory. A peer that restarts brings a new key, so
    /// the directory would otherwise keep one entry for each run of each peer.
    async fn on_peer_left(
        &mut self,
        key: &AuthorKey,
        _nickname: &Nickname,
        _state: &mut EventLoopState,
        _ctx: &HandlerCtx<'_>,
    ) {
        if let Ok(mut directory) = self.mailboxes.directory.lock() {
            directory.remove(key);
        }
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
                // The engine routes by key and answers a key that is not live with an error, which
                // `send` swallows: a peer that left mid-match is a lost packet, as on any other loss.
                let Some(frame) = frame_for(context, ROLLBACK_TAG, Some(to), &payload) else {
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
                // A quiet member has a dead endpoint, so it is not a roster member to address.
                let roster = state.roster_snapshot();
                let peers: Vec<AuthorKey> = roster.addressee_keys().copied().collect();
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
    to: Option<AuthorKey>,
    payload: &str,
) -> Option<Verified> {
    let (Ok(tag), Ok(body)) = (AppTag::try_new(tag), MessageBody::try_new(payload)) else {
        return None;
    };
    Some(ops::app_frame(
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
    ops::send_app(state, context, frame, class).await.is_ok()
}
