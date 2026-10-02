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

use anyhow::{Context as _, Result, bail, ensure};
use habilis_network_iroh_webrtc_transport::iroh_base::{EndpointId, RelayUrl};
use serde::{Deserialize, Serialize};

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

impl ClientMsg {
    /// Reject what the room would have to reject anyway, at the edge.
    ///
    /// # Errors
    /// The nick or text is empty, or longer than the cap.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Join { nick } => check_len("nick", nick, MAX_NICK_CHARS),
            Self::Say { text } => check_len("message", text, MAX_TEXT_CHARS),
        }
    }
}

fn check_len(what: &str, value: &str, max_chars: usize) -> Result<()> {
    let trimmed = value.trim();
    ensure!(!trimmed.is_empty(), "{what} is empty");
    // `chars`, not `len`: a cap in bytes would reject a shorter message in a
    // non-Latin script than in English, which is a bug rather than a policy.
    let chars = trimmed.chars().count();
    ensure!(
        chars <= max_chars,
        "{what} is {chars} chars, max is {max_chars}"
    );
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
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(msg).context("serialize frame")?;
    ensure!(
        body.len() <= MAX_FRAME_BYTES,
        "frame is {} bytes, max is {MAX_FRAME_BYTES}",
        body.len()
    );
    let len = u32::try_from(body.len()).context("frame length does not fit a u32")?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// How many body bytes follow a header.
///
/// Checked against [`MAX_FRAME_BYTES`] *before* the caller allocates, which is
/// the whole reason this is a function and not a `u32::from_le_bytes` at the
/// call site.
///
/// # Errors
/// The length exceeds [`MAX_FRAME_BYTES`].
pub fn decode_frame_len(header: [u8; FRAME_HEADER_LEN]) -> Result<usize> {
    let len = u32::from_le_bytes(header) as usize;
    ensure!(
        len <= MAX_FRAME_BYTES,
        "peer announced a {len}-byte frame, max is {MAX_FRAME_BYTES}"
    );
    Ok(len)
}

/// Decode a frame body.
///
/// # Errors
/// The body is not the expected message.
pub fn decode_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).context("decode frame body")
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
    pub fn decode(encoded: &str) -> Result<Self> {
        let payload = bs58::decode(encoded.trim())
            .with_check(None)
            .into_vec()
            .context("ticket is not valid Base58Check")?;

        let (&version, rest) = payload.split_first().context("ticket is empty")?;
        if version != TICKET_VERSION {
            bail!("ticket is version {version}, this build speaks {TICKET_VERSION}");
        }

        ensure!(rest.len() >= 34, "ticket is truncated");
        let (id_bytes, rest) = rest.split_at(32);
        let id: [u8; 32] = id_bytes.try_into().context("ticket holds a malformed id")?;
        let id = EndpointId::from_bytes(&id).context("ticket holds an invalid endpoint id")?;

        let (len_bytes, relay_bytes) = rest.split_at(2);
        let len_bytes: [u8; 2] = len_bytes
            .try_into()
            .context("ticket holds a malformed length")?;
        let relay_len = u16::from_le_bytes(len_bytes) as usize;
        ensure!(
            relay_bytes.len() == relay_len,
            "ticket says {relay_len} relay bytes but carries {}",
            relay_bytes.len()
        );
        let relay = if relay_len == 0 {
            None
        } else {
            let text = std::str::from_utf8(relay_bytes).context("relay URL is not utf8")?;
            Some(
                text.parse::<RelayUrl>()
                    .context("ticket holds an invalid relay URL")?,
            )
        };

        Ok(Self { id, relay })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generated rather than a hardcoded array: an endpoint id is a point on a
    /// curve, and most 32-byte patterns are not one.
    fn sample_id() -> EndpointId {
        habilis_network_iroh_webrtc_transport::iroh_base::SecretKey::generate().public()
    }

    #[test]
    fn a_ticket_round_trips_with_a_relay() {
        let ticket = Ticket {
            id: sample_id(),
            relay: Some("https://relay.example/".parse().expect("a valid relay URL")),
        };
        let decoded = Ticket::decode(&ticket.encode()).expect("round trip");
        assert_eq!(decoded.id, ticket.id);
        assert_eq!(decoded.relay, ticket.relay);
    }

    #[test]
    fn a_ticket_round_trips_without_a_relay() {
        let ticket = Ticket {
            id: sample_id(),
            relay: None,
        };
        let decoded = Ticket::decode(&ticket.encode()).expect("round trip");
        assert_eq!(decoded.id, ticket.id);
        assert!(decoded.relay.is_none());
    }

    /// Base58Check's checksum is the point: a ticket loses a character to a
    /// line wrap or a bad paste far more often than it is corrupted in transit,
    /// and the failure should name itself rather than surface as "no such
    /// endpoint" after a 20-second dial.
    #[test]
    fn a_mistyped_ticket_is_rejected_rather_than_dialled() {
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
        assert!(Ticket::decode(&mangled).is_err());
    }

    #[test]
    fn a_frame_round_trips() {
        let msg = ServerMsg::Said {
            nick: "bob".into(),
            text: "hi".into(),
        };
        let frame = encode_frame(&msg).expect("encode");
        let header: [u8; FRAME_HEADER_LEN] = frame[..FRAME_HEADER_LEN].try_into().expect("header");
        let len = decode_frame_len(header).expect("length");
        assert_eq!(len, frame.len() - FRAME_HEADER_LEN);
        let decoded: ServerMsg = decode_body(&frame[FRAME_HEADER_LEN..]).expect("body");
        assert!(matches!(decoded, ServerMsg::Said { nick, text } if nick == "bob" && text == "hi"));
    }

    /// The bound is checked before the reader allocates, so a peer cannot make
    /// us reserve `4 GiB` by sending four bytes.
    #[test]
    fn an_oversized_length_prefix_is_refused_before_allocating() {
        assert!(decode_frame_len(u32::MAX.to_le_bytes()).is_err());
    }

    #[test]
    fn a_nick_is_measured_in_chars_not_bytes() {
        // 24 multi-byte chars is 72 bytes; a byte cap would reject it.
        let nick = "ぁ".repeat(MAX_NICK_CHARS);
        assert!(ClientMsg::Join { nick }.validate().is_ok());
        let too_long = "ぁ".repeat(MAX_NICK_CHARS + 1);
        assert!(ClientMsg::Join { nick: too_long }.validate().is_err());
    }

    #[test]
    fn an_empty_message_is_refused() {
        assert!(ClientMsg::Say { text: "   ".into() }.validate().is_err());
    }
}
