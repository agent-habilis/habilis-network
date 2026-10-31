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

mod client_msg;
mod frame;
mod proto_error;
mod ticket;

pub use client_msg::{ClientMsg, ServerMsg};
pub use frame::{FRAME_HEADER_LEN, decode_body, decode_frame_len, encode_frame};
pub use proto_error::ProtoError;
pub use ticket::Ticket;

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

#[cfg(test)]
mod tests {
    use super::{
        ClientMsg, FRAME_HEADER_LEN, MAX_NICK_CHARS, ServerMsg, Ticket, decode_body,
        decode_frame_len, encode_frame,
    };
    use habilis_network_iroh_webrtc_transport::iroh_base::EndpointId;

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

    /// `Base58Check`'s checksum is the point: a ticket loses a character to a
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
