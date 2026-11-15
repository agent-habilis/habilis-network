use habilis_network_iroh_webrtc_transport::iroh_base::{EndpointId, RelayUrl};
use std::str;

use crate::ProtoError;

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
    /// `version(1) ‖ id(32) ‖ relay_len(u16 LE) ‖ relay(utf8)`, `Base58Check`.
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
    /// The string is not `Base58Check`, carries another version, is truncated, or
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
