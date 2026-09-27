//! The membership driver: what a `msg` frame means on the way in, and what a
//! consumer's request means on the way out.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent,
};
use crate::ops::{StateMergeParams, broadcast_state_merge, send_app};
use crate::protocol::{
    AppFrameParams, AppTag, Channel, Message, MessageBody, MessageKind, Nickname,
};
use crate::util::consts::MAX_MESSAGE_SIZE;

/// The one `App`-frame tag a member sends: a whole UTF-8 text, broadcast or
/// directed. Bulk bytes do not ride gossip; they take a stream.
pub const MSG_TAG: &str = "msg";

/// Inbound messages buffered for a consumer that reads on its own schedule.
/// Bounded, because a member that only ever *sends* still receives broadcasts:
/// an unbounded queue would grow for the process's lifetime.
pub const INBOUND_CAP: usize = 256;

/// Wait before leaving, so frames just handed to the event loop go out first.
pub const DEPARTURE_GRACE: Duration = Duration::from_millis(750);

/// What a signed `App` frame costs beyond its body: ids, the pubkey, the
/// signature, the mesh id and the JSON keys. Checked by
/// `the_envelope_fits_its_reserve` against a 32-scalar author and addressee
/// and a mesh id carrying a custom relay ladder.
const ENVELOPE_RESERVE: usize = 1024;

/// The escaped-body budget one frame leaves after [`ENVELOPE_RESERVE`].
const ESCAPED_BUDGET: usize = MAX_MESSAGE_SIZE - ENVELOPE_RESERVE;

/// The longest text in bytes that always fits one frame, whatever it holds.
/// JSON escapes `"`, `\` and the allowed control characters to two bytes and
/// leaves everything else — non-ASCII included — as it is, so the worst case
/// is half the escaped budget. Most text fits well past this; ask
/// [`msg_fits`] for a given one.
pub const MAX_MSG: usize = ESCAPED_BUDGET / 2;

/// Whether `text` fits one `msg` frame. The engine's own check in `send_app` is
/// the final word; this answers early, without building and signing a frame.
#[must_use]
pub fn msg_fits(text: &str) -> bool {
    escaped_len(text) <= ESCAPED_BUDGET
}

/// The body of a `msg` frame.
///
/// # Errors
/// `text` holds a control character other than tab, newline or carriage
/// return, or does not fit one frame (see [`msg_fits`]).
pub fn msg_body(text: &str) -> Result<MessageBody> {
    anyhow::ensure!(
        msg_fits(text),
        "message too large for one frame: send it as a stream instead"
    );
    MessageBody::new(text.to_owned()).map_err(|error| anyhow::anyhow!("{error}"))
}

/// Parse an optional addressee.
///
/// # Errors
/// `to` is not a valid nickname.
pub fn parse_to(to: Option<&str>) -> Result<Option<Nickname>> {
    to.map(|nick| Nickname::new(nick.to_owned()))
        .transpose()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

/// `text` as `serde_json` writes it inside quotes.
fn escaped_len(text: &str) -> usize {
    text.chars()
        .map(|scalar| match scalar {
            '"' | '\\' | '\n' | '\t' | '\r' => 2,
            other => other.len_utf8(),
        })
        .sum()
}

/// One surfaced `msg`, flattened for a consumer outside the engine.
#[derive(Debug)]
pub struct Inbound {
    /// The author's nickname.
    pub nick: String,
    /// The message was addressed to us specifically, not broadcast.
    pub directed: bool,
    pub text: String,
}

/// A request pushed into the event loop from the consumer's side. Every arm
/// carries its own reply channel: a foreign caller needs the outcome of a send
/// as a return code, not a log line.
#[expect(
    missing_debug_implementations,
    reason = "the oneshot reply senders carry no Debug bound worth adding for a value that never reaches a log line"
)]
pub enum Request {
    /// Send one `msg`. Build `body` with [`msg_body`].
    Send {
        to: Option<Nickname>,
        body: MessageBody,
        reply: oneshot::Sender<Result<(), String>>,
    },
    StateMerge {
        merge: serde_json::Value,
        reply: oneshot::Sender<Result<(), String>>,
    },
    StateJson {
        reply: oneshot::Sender<String>,
    },
    Peers {
        reply: oneshot::Sender<String>,
    },
    PeerCount {
        reply: oneshot::Sender<usize>,
    },
}

/// The engine seam. Every inbound `msg` is queued for the consumer instead of
/// being written anywhere: a browser's `js_sys::Function` is neither `Send`
/// nor `Sync`, and [`NodeApp`] is `Send`, so the driver could not keep one even
/// if it wanted to. Consumers drain the queue on their own schedule.
#[derive(Debug)]
pub struct MembershipApp {
    inbound: mpsc::Sender<Inbound>,
    /// Messages dropped since the queue last had room. One error is surfaced
    /// per stall rather than one per drop: the event channel is unbounded,
    /// and a consumer that stopped reading must not grow it without bound.
    dropped: u64,
}

impl MembershipApp {
    /// Messages land on `inbound`, dropped when it is full.
    #[must_use]
    pub fn new(inbound: mpsc::Sender<Inbound>) -> Self {
        Self {
            inbound,
            dropped: 0,
        }
    }

    /// Count one delivery attempt; `true` on the first drop of a stall.
    fn stall_began(&mut self, queued: bool) -> bool {
        if queued {
            self.dropped = 0;
            return false;
        }
        self.dropped += 1;
        self.dropped == 1
    }
}

#[async_trait]
impl NodeApp for MembershipApp {
    fn classify(&self, _message: &Message) -> AppClass {
        // Ephemeral text: never logged, never a task beat, always valid, no
        // per-author hash chain. `sealed: false` is load-bearing — a member
        // publishes no a2a card, so it can neither seal to a peer nor be sealed
        // to, and the addressee must pass a directed plaintext body straight
        // through instead of trying (and failing) to unseal it.
        AppClass {
            loggable: false,
            beat: false,
            valid: true,
            chained: false,
            sealed: false,
        }
    }

    async fn on_app_frame(
        &mut self,
        frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        let InboundApp {
            message,
            surfaceable: _,
        } = frame;
        if message.kind.app_tag().map(AppTag::as_str) != Some(MSG_TAG) {
            return false;
        }
        // The engine only dispatches frames addressed to us or broadcast, so a
        // present `to` is us.
        let inbound = Inbound {
            nick: message.author.to_string(),
            directed: matches!(message.kind, MessageKind::App { to: Some(_), .. }),
            text: message.body.as_str().to_owned(),
        };
        // Full or closed: the caller is not draining. Dropping is the only
        // option that neither blocks the event loop nor grows without bound.
        let queued = self.inbound.try_send(inbound).is_ok();
        if self.stall_began(queued) {
            ctx.sink.emit(NodeEvent::Error(
                "inbound message queue full: messages are being dropped until it is read"
                    .to_owned(),
            ));
        }
        // Never retained or indexed — the frame is fully handled here.
        false
    }
}

#[async_trait]
impl NodeDriver for MembershipApp {
    type Session = Request;
    type Http = ();
    type Ipc = ();

    async fn handle_session(
        &mut self,
        req: Request,
        state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        match req {
            Request::Send { to, body, reply } => {
                let sent = send_app(
                    state,
                    ctx,
                    AppFrameParams {
                        tag: AppTag::from(MSG_TAG),
                        to,
                        corr: None,
                        body,
                    },
                )
                .await;
                let _ = reply.send(sent.map_err(|error| error.to_string()));
                true
            }
            Request::StateMerge { merge, reply } => {
                let merged = broadcast_state_merge(
                    state,
                    StateMergeParams {
                        mesh: ctx.mesh,
                        author: ctx.author,
                        merge,
                        sender: ctx.sender,
                        sink: ctx.sink,
                        channel: Channel::State,
                        surface: true,
                    },
                )
                .await;
                let _ = reply.send(merged.map(|_| ()).map_err(|error| error.to_string()));
                true
            }
            Request::StateJson { reply } => {
                let _ = reply.send(state.doc(Channel::State).to_json().to_string());
                false
            }
            Request::Peers { reply } => {
                let snapshot = state.roster_snapshot();
                let json = serde_json::to_string(&snapshot)
                    .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"));
                let _ = reply.send(json);
                false
            }
            Request::PeerCount { reply } => {
                // `peers.len()`, not the snapshot's `count` — that one includes
                // self, and a caller asking "is anyone else here?" wants zero
                // when it is alone.
                let _ = reply.send(state.roster_snapshot().peers.len());
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Identity, Lookup, MeshConfig, MeshId, RelayLadder};
    use crate::runtime::derive_topic_mesh_config;

    /// The longest nickname there is: 32 four-byte scalars.
    fn widest_nick(seed: char) -> Nickname {
        Nickname::new(std::iter::repeat_n(seed, 32).collect::<String>()).expect("32 scalars")
    }

    /// A mesh id well past the common case: every lookup and a four-rung
    /// custom relay ladder.
    fn long_mesh() -> MeshId {
        let ladder: RelayLadder = (0..4)
            .map(|rung| format!("https://relay-{rung}.a-rather-long-relay-domain.example/"))
            .collect::<Vec<_>>()
            .join(",")
            .parse()
            .expect("ladder");
        let config = MeshConfig::resolve(
            &[Lookup::Mdns, Lookup::Dht, Lookup::Relay],
            Some(ladder),
            &[],
        )
        .expect("config");
        let mesh = derive_topic_mesh_config("standup", config).expect("mesh");
        MeshId::new(mesh.to_string()).expect("id")
    }

    fn signed_len(text: &str) -> usize {
        Message::new_app(
            &long_mesh(),
            &widest_nick('\u{1F980}'),
            AppFrameParams {
                tag: AppTag::from(MSG_TAG),
                to: Some(widest_nick('\u{1F99E}')),
                corr: None,
                body: MessageBody::new(text.to_owned()).expect("body"),
            },
        )
        .signed(&Identity::generate())
        .wire_len()
    }

    #[test]
    fn the_envelope_fits_its_reserve() {
        let envelope = signed_len("");
        assert!(envelope <= ENVELOPE_RESERVE, "envelope is {envelope} bytes");
    }

    /// `msg_fits` must never say yes to a text `send_app` would refuse, at
    /// either end of the escaping range.
    #[test]
    fn a_text_msg_fits_accepts_signs_within_one_frame() {
        for text in [
            "\"".repeat(MAX_MSG),
            "a".repeat(ESCAPED_BUDGET),
            "\u{1F980}".repeat(ESCAPED_BUDGET / 4),
        ] {
            assert!(msg_fits(&text));
            let len = signed_len(&text);
            assert!(len <= MAX_MESSAGE_SIZE, "{len} bytes");
        }
        assert!(!msg_fits(&"\"".repeat(MAX_MSG + 1)));
        assert!(!msg_fits(&"a".repeat(ESCAPED_BUDGET + 1)));
    }

    #[test]
    fn a_body_round_trips_and_refuses_what_it_cannot_carry() {
        let text = "ol\u{e1}, \"mesh\"\n\ttab";
        assert_eq!(msg_body(text).expect("body").as_str(), text);
        assert!(msg_body("bell\u{7}").is_err());
        assert!(msg_body(&"\"".repeat(MAX_MSG + ESCAPED_BUDGET)).is_err());
    }

    #[test]
    fn a_stall_surfaces_once_until_the_queue_drains() {
        let (inbound, _queue) = mpsc::channel(1);
        let mut app = MembershipApp::new(inbound);
        let surfaced: Vec<bool> = [true, false, false, false, true, false]
            .into_iter()
            .map(|queued| app.stall_began(queued))
            .collect();
        assert_eq!(surfaced, [false, true, false, false, false, true]);
    }
}
