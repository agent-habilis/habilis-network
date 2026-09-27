//! The engine's surfacings, in a vocabulary a consumer outside Rust can switch
//! on.

use std::sync::Arc;

use crate::embed::{NodeEvent, NodeSink};
use crate::protocol::{MessageKind, PresenceSubtype};
use serde::Serialize;
use tokio::sync::mpsc;

/// What a consumer is told, as it happens.
///
/// Serialized to JSON and handed across whatever boundary the consumer has — the
/// convention `chat-web` and `light-cycles-web` already use, and cheap here
/// because these are lifecycle events rather than frames. Message payloads
/// deliberately do *not* ride this channel: base64 inside JSON for every frame
/// would inflate every byte on the mesh by a third to hand it to a language that
/// already has a byte array.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MembershipEvent {
    Ready {
        mesh: String,
        name: String,
        nick: String,
    },
    Joined {
        nick: String,
    },
    Left {
        nick: String,
    },
    /// Heartbeat-evicted past `ALIVE_TIMEOUT_SECS`. Deliberately **not** `left`:
    /// the peer is still in the roster with `quiet: true`, and folding the two
    /// together would desync a consumer's mirror from the roster it can read
    /// back.
    Quiet {
        nick: String,
        last_seen_secs_ago: u64,
    },
    Returned {
        nick: String,
    },
    /// A peer's per-author hash chain forked — two signed messages at one `seq`.
    Fork {
        nick: String,
        pubkey: String,
        seq: u64,
    },
    StateChanged {
        channel: String,
        author: String,
        document: serde_json::Value,
        is_self: bool,
    },
    Info {
        text: String,
    },
    Error {
        text: String,
    },
}

/// Map one engine surfacing onto the consumer vocabulary. `None` for a surfacing
/// there is no API for — `PingReport`, since nothing here starts a ping round.
///
/// No `_ =>` arm: `clippy::wildcard_enum_match_arm` is a workspace warn, so a
/// new [`NodeEvent`] variant fails this build instead of vanishing.
fn classify(event: NodeEvent) -> Option<MembershipEvent> {
    match event {
        NodeEvent::Ready {
            mesh,
            name,
            nickname,
        } => Some(MembershipEvent::Ready {
            mesh: mesh.as_str().to_owned(),
            name: name.as_str().to_owned(),
            nick: nickname.to_string(),
        }),
        NodeEvent::Presence { msg } => {
            // The engine emits this for a peer's own `joined` frame, for a
            // `Left`, and — the reliable case — for the *first frame of any
            // kind* from a peer it has not surfaced yet, since a one-shot
            // `joined` broadcast can be lost in the convergence window. See
            // `crates/fofoca/src/lifecycle/mod.rs`. A `matches!` splits them; a
            // `match` would need a wildcard over every `MessageKind`.
            let nick = msg.author.to_string();
            Some(
                if matches!(
                    msg.kind,
                    MessageKind::Presence {
                        subtype: PresenceSubtype::Left
                    }
                ) {
                    MembershipEvent::Left { nick }
                } else {
                    MembershipEvent::Joined { nick }
                },
            )
        }
        NodeEvent::PeerTimeout {
            nickname,
            last_seen_secs_ago,
        } => Some(MembershipEvent::Quiet {
            nick: nickname.to_string(),
            last_seen_secs_ago,
        }),
        NodeEvent::PeerReturn { nickname } => Some(MembershipEvent::Returned {
            nick: nickname.to_string(),
        }),
        NodeEvent::Fork {
            nickname,
            pubkey,
            seq,
        } => Some(MembershipEvent::Fork {
            nick: nickname.to_string(),
            pubkey,
            seq,
        }),
        NodeEvent::StateChanged {
            channel,
            event,
            document,
            is_self,
        } => Some(MembershipEvent::StateChanged {
            channel: channel.label().to_owned(),
            author: event.author.to_string(),
            document,
            is_self,
        }),
        NodeEvent::Info(text) => Some(MembershipEvent::Info { text }),
        NodeEvent::Error(text) => Some(MembershipEvent::Error { text }),
        NodeEvent::PingReport { .. } => None,
    }
}

/// A [`NodeSink`] that serializes each surfacing and pushes it onto a channel.
///
/// The indirection is forced rather than chosen. `NodeSink` is `Send + Sync`
/// with a synchronous `emit`, and a browser's `js_sys::Function` is neither, so
/// a sink destined for one physically cannot hold it. A `String` on a channel
/// *is* `Send`, and the drain lives on the other side, where JS values are
/// legal. Off wasm32 the same type works unchanged, which is why it is here and
/// not in the browser crate.
#[derive(Debug)]
struct JsonSink {
    events: mpsc::UnboundedSender<String>,
}

impl NodeSink for JsonSink {
    fn emit(&self, event: NodeEvent) {
        let Some(event) = classify(event) else {
            return;
        };
        match serde_json::to_string(&event) {
            Ok(json) => {
                // A closed receiver means the consumer went away first. There is
                // nowhere to report that from inside `emit`, and nothing to do
                // about it.
                let _ = self.events.send(json);
            }
            Err(error) => tracing::warn!(
                target: "crate::messages",
                %error,
                "dropping an unserializable node event"
            ),
        }
    }
}

/// A sink plus the queue it fills.
///
/// Unbounded, unlike the frame queue: dropping an app frame costs one
/// message, where dropping a `left` leaves a phantom peer in the consumer's
/// mirror forever. Events are small and rare.
#[must_use]
pub fn json_sink() -> (Arc<dyn NodeSink>, mpsc::UnboundedReceiver<String>) {
    let (events, queue) = mpsc::unbounded_channel();
    (Arc::new(JsonSink { events }), queue)
}
