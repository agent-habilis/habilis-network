//! The engine-facing half: mailboxes, framing, and the only `send_app` call.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use habilis_network::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver,
};
use habilis_network::protocol::{
    AppFrameParams, AppTag, Message as WireMessage, MessageBody, Nickname,
};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::transport::Message;

/// App tag for rollback packets.
pub const ROLLBACK_TAG: &str = "rb_input";
/// App tag for lobby packets.
pub const LOBBY_TAG: &str = "rb_lobby";

/// What the frame loop asks the event loop to send.
///
/// Pushed through `Node::sender()`; drained by
/// [`RollbackDriver::handle_session`], which is where `&mut EventLoopState`
/// finally exists.
#[derive(Debug)]
pub enum Outbound {
    /// A rollback packet for one peer, addressed by public key.
    Rollback {
        /// The recipient's public key.
        to: String,
        /// Pre-serialized packet.
        payload: String,
    },
    /// A lobby packet for everyone currently in the mesh roster.
    Lobby {
        /// Pre-serialized packet.
        payload: String,
    },
}

/// Everything the frame loop and the event loop share.
///
/// Cloning shares the mailboxes rather than copying them; the driver keeps
/// one handle and each transport another.
pub(crate) struct Mailboxes<T: Config> {
    /// Decoded rollback packets, tagged with the sender's public key.
    pub(crate) inbound: Mutex<VecDeque<(String, Message<T::Input>)>>,
    /// Raw lobby packets, tagged with the sender's public key.
    pub(crate) lobby: Mutex<Vec<(String, String)>>,
    /// This peer's own public key, known only once the event loop starts.
    pub(crate) local_pubkey: Mutex<Option<String>>,
    /// public key -> nickname, learned from inbound frames.
    ///
    /// Needed because `send_app` addresses by `Nickname` while inputs are
    /// filed by public key — the protocol treats nicknames as cosmetic and
    /// explicitly non-unique, so they cannot be the identity.
    pub(crate) directory: Mutex<HashMap<String, Nickname>>,
}

impl<T: Config> std::fmt::Debug for Mailboxes<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Mailboxes").finish_non_exhaustive()
    }
}

impl<T: Config> Mailboxes<T> {
    pub(crate) fn new() -> Self {
        Self {
            inbound: Mutex::new(VecDeque::new()),
            lobby: Mutex::new(Vec::new()),
            local_pubkey: Mutex::new(None),
            directory: Mutex::new(HashMap::new()),
        }
    }
}

/// The `NodeApp`/`NodeDriver` a rollback consumer hands to `Node::spawn`.
///
/// Construct one with [`RollbackDriver::new`], keep the returned
/// [`MeshTransport`](super::MeshTransport) handle for the session, and give
/// the driver to the node.
pub struct RollbackDriver<T: Config> {
    mailboxes: Arc<Mailboxes<T>>,
}

impl<T: Config> std::fmt::Debug for RollbackDriver<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RollbackDriver")
            .finish_non_exhaustive()
    }
}

impl<T: Config> RollbackDriver<T> {
    pub(crate) fn from_mailboxes(mailboxes: Arc<Mailboxes<T>>) -> Self {
        Self { mailboxes }
    }
}

/// Decode a packet body, ignoring anything malformed.
fn decode<D: for<'de> Deserialize<'de>>(body: &str) -> Option<D> {
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
    /// log and its anti-entropy repair, and since `send_app` never logs our
    /// *own* broadcasts, peers would re-send them to us forever with no way
    /// to acknowledge. That runaway is the reason this crate never touches
    /// gossip. It lives in the library so a consumer cannot get it wrong.
    fn classify(&self, message: &WireMessage) -> AppClass {
        let tag = message.kind.app_tag().map(AppTag::as_str);
        let ours = matches!(tag, Some(ROLLBACK_TAG | LOBBY_TAG));
        AppClass {
            loggable: false,
            beat: false,
            // `send_app` never stamps `seq`/`parents`, so a chain would
            // index nothing.
            chained: false,
            sealed: false,
            valid: ours,
        }
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
        let pubkey = frame.message.pubkey.clone();

        // Learn the pubkey -> nickname pairing from any frame. The signed
        // pubkey is the identity; the nickname is only how `send_app`
        // addresses it.
        if let Ok(mut directory) = self.mailboxes.directory.lock() {
            directory.insert(pubkey.clone(), frame.message.author.clone());
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
    async fn on_startup(&mut self, _state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
        if let Ok(mut slot) = self.mailboxes.local_pubkey.lock() {
            *slot = Some(ctx.our_pubkey.to_string());
        }
    }

    async fn handle_session(
        &mut self,
        req: Outbound,
        state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        match req {
            Outbound::Rollback { to, payload } => {
                // Resolve and release the lock *before* awaiting: holding a
                // `std::sync::Mutex` guard across an await is denied
                // workspace-wide, and rightly so.
                let nickname = self
                    .mailboxes
                    .directory
                    .lock()
                    .ok()
                    .and_then(|directory| directory.get(&to).cloned());
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
                send(state, ctx, ROLLBACK_TAG, Some(nickname), payload).await
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
                    delivered |= send(state, ctx, LOBBY_TAG, Some(peer), payload.clone()).await;
                }
                delivered
            }
        }
    }
}

/// One `send_app`, with the failure swallowed.
///
/// Failure is genuinely uninteresting here: this layer assumes a lossy
/// transport and recovers by resending, so a caller could not act on the
/// error even if it had it.
async fn send(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    tag: &str,
    to: Option<Nickname>,
    payload: String,
) -> bool {
    let (Ok(tag), Ok(body)) = (AppTag::new(tag), MessageBody::new(payload)) else {
        return false;
    };
    habilis_network::ops::send_app(
        state,
        ctx,
        AppFrameParams {
            tag,
            to,
            corr: None,
            body,
        },
    )
    .await
    .is_ok()
}
