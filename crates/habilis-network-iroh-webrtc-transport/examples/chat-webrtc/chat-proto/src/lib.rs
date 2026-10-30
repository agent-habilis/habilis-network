//! The chat's wire vocabulary: two ALPNs, two message enums, one frame format,
//! and a ticket.
//!
//! Deliberately sans-io. Neither this crate's host consumer nor its browser
//! consumer can share a stream type — the browser has no tokio and the host has
//! no `web-sys` — but they must agree on every byte. So the bytes live here as
//! plain functions over `&[u8]`, and each side does its own reading.
//!
//! It is also the crate that has to build for `wasm32-unknown-unknown`, which
//! is why it reaches no further than
//! [`habilis_network_iroh_webrtc_transport::iroh_base`]: an endpoint id and a relay URL
//! need no QUIC stack, and pulling `iroh` proper in here would put one in the
//! browser's dependency graph for the sake of two type names.

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

use habilis_network_iroh_webrtc_transport::iroh_base::{EndpointId, RelayUrl};
use serde::{Deserialize, Serialize};

use serde::de;
use std::str;
/// The chat itself: one long-lived bidirectional stream per peer.
///
/// Wire-load-bearing — both ends must agree on the string, so it moves only
/// with a deliberate protocol break.
pub const CHAT_ALPN: &[u8] = b"chat-webrtc/chat/1";

/// The JSEP exchange: one short-lived connection, one
/// [`SignalEnvelope`](habilis_network_iroh_webrtc_transport::SignalEnvelope) each way.
///
/// Separate from [`CHAT_ALPN`] because they are carried differently on purpose.
/// This one rides the relay — it is how two peers that cannot yet reach each
/// other are introduced. The chat rides the data channel that introduction
/// produced.
pub const SIGNAL_ALPN: &[u8] = b"chat-webrtc/signal/1";

/// Ceiling on one frame's JSON body.
///
/// Generous for chat — the point is that a peer reading a length prefix off the
/// wire allocates against a bound rather than against whatever number the other
/// side sent.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Longest nickname the room accepts, in `char`s.
pub const MAX_NICK_CHARS: usize = 24;

/// Longest message the room accepts, in `char`s.
pub const MAX_TEXT_CHARS: usize = 512;

/// Peer to room.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// First frame on the stream, always. The room answers with
    /// [`ServerMsg::Welcome`].
    Join {
        nick: String,
    },
    Say {
        text: String,
    },
}

/// Room to peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Answer to [`ClientMsg::Join`].
    ///
    /// `you` is the nick the room actually assigned, which is not necessarily
    /// the one asked for: the room uniquifies collisions (`bob`, `bob#2`). A
    /// client that echoes its *requested* nick in its own UI would disagree
    /// with everyone else about who it is.
    Welcome {
        you: String,
        roster: Vec<String>,
    },
    Joined {
        nick: String,
    },
    Left {
        nick: String,
    },
    Said {
        nick: String,
        text: String,
    },
}

/// What a chat message, frame or ticket can get wrong. The chat binaries show it to the user.
#[derive(Debug)]
pub enum ProtoError {
    /// A nick or a message is empty once trimmed.
    Empty { what: &'static str },
    /// A nick or a message is longer than its cap, in characters.
    TooLong {
        what: &'static str,
        chars: usize,
        max: usize,
    },
    /// A frame body is larger than the cap.
    FrameTooLarge { bytes: usize, max: usize },
    /// A frame body does not serialize, or does not parse as the message it should be.
    Json(serde_json::Error),
    /// A ticket is not Base58Check, is truncated, or holds an id or a relay URL that does not parse.
    Ticket(&'static str),
    /// A ticket carries another version of the payload.
    TicketVersion { found: u8, expected: u8 },
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty { what } => write!(formatter, "{what} is empty"),
            Self::TooLong { what, chars, max } => {
                write!(formatter, "{what} is {chars} chars, max is {max}")
            }
            Self::FrameTooLarge { bytes, max } => {
                write!(formatter, "frame is {bytes} bytes, max is {max}")
            }
            Self::Json(error) => write!(formatter, "frame body: {error}"),
            Self::Ticket(reason) => write!(formatter, "ticket {reason}"),
            Self::TicketVersion { found, expected } => {
                write!(
                    formatter,
                    "ticket is version {found}, this build speaks {expected}"
                )
            }
        }
    }
}

impl std::error::Error for ProtoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Empty { .. }
            | Self::TooLong { .. }
            | Self::FrameTooLarge { .. }
            | Self::Ticket(_)
            | Self::TicketVersion { .. } => None,
        }
    }
}

impl ClientMsg {
    /// Reject what the room would have to reject anyway, at the edge.
    ///
    /// # Errors
    /// The nick or text is empty, or longer than the cap.
    pub fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::Join { nick } => check_len("nick", nick, MAX_NICK_CHARS),
            Self::Say { text } => check_len("message", text, MAX_TEXT_CHARS),
        }
    }
}

fn check_len(what: &'static str, value: &str, max_chars: usize) -> Result<(), ProtoError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ProtoError::Empty { what });
    }
    // `chars`, not `len`: a cap in bytes would reject a shorter message in a
    // non-Latin script than in English, which is a bug rather than a policy.
    let chars = trimmed.chars().count();
    if chars > max_chars {
        return Err(ProtoError::TooLong {
            what,
            chars,
            max: max_chars,
        });
    }
    Ok(())
}

// ── framing ──────────────────────────────────────────────────────────────────
//
// `u32` little-endian length ‖ JSON body. One frame per message, many frames
// per stream.
//
// Why a length prefix at all, when QUIC already delimits streams: the stream is
// held open for the whole session, so `finish()` cannot mark a boundary the way
// it does in the one-shot JSEP exchange. And why not one stream per message —
// a chat is a conversation, and opening a stream per line would spend a round
// trip on every "hi".

/// Bytes of the fixed-size header every frame starts with.
pub const FRAME_HEADER_LEN: usize = 4;

/// Encode one message as a frame.
///
/// # Errors
/// The message does not serialize, or its body exceeds [`MAX_FRAME_BYTES`].
pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtoError> {
    let body = serde_json::to_vec(message).map_err(ProtoError::Json)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge {
            bytes: body.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| ProtoError::FrameTooLarge {
        bytes: body.len(),
        max: MAX_FRAME_BYTES,
    })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// How many body bytes follow a header.
///
/// Checked against [`MAX_FRAME_BYTES`] *before* the caller allocates, which is
/// the whole reason for a function, not a `u32::from_le_bytes` at the
/// call site.
///
/// # Errors
/// The length exceeds [`MAX_FRAME_BYTES`].
pub fn decode_frame_len(header: [u8; FRAME_HEADER_LEN]) -> Result<usize, ProtoError> {
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge {
            bytes: len,
            max: MAX_FRAME_BYTES,
        });
    }
    Ok(len)
}

/// Decode a frame body.
///
/// # Errors
/// The body is not the expected message.
pub fn decode_body<T: de::DeserializeOwned>(body: &[u8]) -> Result<T, ProtoError> {
    serde_json::from_slice(body).map_err(ProtoError::Json)
}

// ── ticket ───────────────────────────────────────────────────────────────────

/// Everything a peer needs to reach the room: who it is, and one relay to meet
/// it on.
///
/// No IP addresses, unlike a full `EndpointAddr`. A browser cannot dial an IP,
/// and a native peer reaches the room over the relay and lets iroh hole-punch
/// from there — so carrying them would lengthen the ticket to serve nobody.
///
/// The relay is carried rather than resolved because the alternative is a
/// DNS-over-HTTPS lookup from the tab before anything else can happen. The
/// capability to join *is* this string; keeping it self-contained means the
/// demo has no third party in it.
#[derive(Debug, Clone)]
pub struct Ticket {
    pub id: EndpointId,
    pub relay: Option<RelayUrl>,
}

/// Bumped only on a breaking change to the payload below, so an old peer given
/// a new ticket says so instead of misreading it.
const TICKET_VERSION: u8 = 1;

impl Ticket {
    /// `version(1) ‖ id(32) ‖ relay_len(u16 LE) ‖ relay(utf8)`, Base58Check.
    ///
    /// Base58 so the string survives a double-click, a URL fragment and a copy
    /// out of a terminal: no `+`, `/`, `=` or characters that look alike.
    #[must_use]
    pub fn encode(&self) -> String {
        let relay = self
            .relay
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let relay_len = u16::try_from(relay.len()).unwrap_or(u16::MAX);
        let mut payload = Vec::with_capacity(35 + relay.len());
        payload.push(TICKET_VERSION);
        payload.extend_from_slice(self.id.as_bytes());
        payload.extend_from_slice(&relay_len.to_le_bytes());
        payload.extend_from_slice(&relay.as_bytes()[..relay_len as usize]);
        bs58::encode(payload).with_check().into_string()
    }

    /// # Errors
    /// The string is not Base58Check, carries another version, is truncated, or
    /// holds an id or relay URL that does not parse.
    pub fn decode(encoded: &str) -> Result<Self, ProtoError> {
        let decoded = bs58::decode(encoded.trim()).with_check(None);
        let payload = decoded
            .into_vec()
            .map_err(|_| ProtoError::Ticket("is not valid Base58Check"))?;

        let (&version, rest) = payload
            .split_first()
            .ok_or(ProtoError::Ticket("is empty"))?;
        if version != TICKET_VERSION {
            return Err(ProtoError::TicketVersion {
                found: version,
                expected: TICKET_VERSION,
            });
        }

        if rest.len() < 34 {
            return Err(ProtoError::Ticket("is truncated"));
        }
        let (id_bytes, rest) = rest.split_at(32);
        let id: [u8; 32] = id_bytes
            .try_into()
            .map_err(|_| ProtoError::Ticket("holds a malformed id"))?;
        let id = EndpointId::from_bytes(&id)
            .map_err(|_| ProtoError::Ticket("holds an invalid endpoint id"))?;

        let (len_bytes, relay_bytes) = rest.split_at(2);
        let len_bytes: [u8; 2] = len_bytes
            .try_into()
            .map_err(|_| ProtoError::Ticket("holds a malformed length"))?;
        let relay_len = u16::from_le_bytes(len_bytes) as usize;
        if relay_bytes.len() != relay_len {
            return Err(ProtoError::Ticket(
                "says a relay length that the bytes do not match",
            ));
        }
        let relay = if relay_len == 0 {
            None
        } else {
            let text = str::from_utf8(relay_bytes)
                .map_err(|_| ProtoError::Ticket("holds a relay URL that is not utf8"))?;
            let relay: RelayUrl = text
                .parse()
                .map_err(|_| ProtoError::Ticket("holds an invalid relay URL"))?;
            Some(relay)
        };

        Ok(Self { id, relay })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientMsg, EndpointId, FRAME_HEADER_LEN, MAX_NICK_CHARS, ServerMsg, Ticket, decode_body,
        decode_frame_len, encode_frame,
    };

    use habilis_network_iroh_webrtc_transport::iroh_base;
    /// Generated rather than a hardcoded array: an endpoint id is a point on a
    /// curve, and most 32-byte patterns are not one.
    fn sample_id() -> EndpointId {
        iroh_base::SecretKey::generate().public()
    }

    #[test]
    fn a_ticket_round_trips_with_a_relay() {
        let _guard = ::habilis_network_test_tracing::init();
        let ticket = Ticket {
            id: sample_id(),
            relay: Some("https://relay.example/".parse().expect("a valid relay URL")),
        };
        let decoded = Ticket::decode(&ticket.encode()).expect("round trip");
        assert_eq!(
            decoded.id, ticket.id,
            "a ticket round trips its id with a relay"
        );
        assert_eq!(
            decoded.relay, ticket.relay,
            "a ticket round trips its relay"
        );
    }

    #[test]
    fn a_ticket_round_trips_without_a_relay() {
        let _guard = ::habilis_network_test_tracing::init();
        let ticket = Ticket {
            id: sample_id(),
            relay: None,
        };
        let decoded = Ticket::decode(&ticket.encode()).expect("round trip");
        assert_eq!(
            decoded.id, ticket.id,
            "a ticket round trips its id without a relay"
        );
        assert!(
            decoded.relay.is_none(),
            "a ticket without a relay decodes with no relay"
        );
    }

    /// Base58Check's checksum is the point: a ticket loses a character to a
    /// line wrap or a bad paste far more often than it is corrupted in transit,
    /// and the failure should name itself rather than surface as "no such
    /// endpoint" after a 20-second dial.
    #[test]
    fn a_mistyped_ticket_is_rejected_rather_than_dialled() {
        let _guard = ::habilis_network_test_tracing::init();
        let encoded = Ticket {
            id: sample_id(),
            relay: None,
        }
        .encode();
        let mangled: String = encoded
            .chars()
            .enumerate()
            .map(|(index, ch)| {
                if index == 4 {
                    if ch == 'z' { 'y' } else { 'z' }
                } else {
                    ch
                }
            })
            .collect();
        assert!(
            Ticket::decode(&mangled).is_err(),
            "a mistyped ticket is rejected rather than dialled"
        );
    }

    #[test]
    fn a_frame_round_trips() {
        let _guard = ::habilis_network_test_tracing::init();
        let message = ServerMsg::Said {
            nick: "bob".into(),
            text: "hi".into(),
        };
        let frame = encode_frame(&message).expect("encode");
        let header: [u8; FRAME_HEADER_LEN] = frame[..FRAME_HEADER_LEN].try_into().expect("header");
        let len = decode_frame_len(header).expect("length");
        assert_eq!(
            len,
            frame.len() - FRAME_HEADER_LEN,
            "a frame round trips at its body length"
        );
        let decoded: ServerMsg = decode_body(&frame[FRAME_HEADER_LEN..]).expect("body");
        assert!(
            matches!(decoded, ServerMsg::Said { nick, text } if nick == "bob" && text == "hi"),
            "a frame round trips to the same said message"
        );
    }

    /// The bound is checked before the reader allocates, so a peer cannot make
    /// us reserve `4 GiB` by sending four bytes.
    #[test]
    fn an_oversized_length_prefix_is_refused_before_allocating() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            decode_frame_len(u32::MAX.to_le_bytes()).is_err(),
            "an oversized length prefix is refused before allocating"
        );
    }

    #[test]
    fn a_nick_is_measured_in_chars_not_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        // 24 multi-byte chars is 72 bytes; a byte cap would reject it.
        let nick = "ぁ".repeat(MAX_NICK_CHARS);
        assert!(
            ClientMsg::Join { nick }.validate().is_ok(),
            "a nick of the maximum chars is valid"
        );
        let too_long = "ぁ".repeat(MAX_NICK_CHARS + 1);
        assert!(
            ClientMsg::Join { nick: too_long }.validate().is_err(),
            "a nick over the maximum chars is refused"
        );
    }

    #[test]
    fn an_empty_message_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            ClientMsg::Say { text: "   ".into() }.validate().is_err(),
            "an empty message is refused"
        );
    }
}
