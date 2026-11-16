//! The body of a signal as it is signed and sealed, and the envelope around it.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::signal::Signal;
use super::signal_kind::SignalKind;

/// The most addresses a signal may carry. A real peer has a few; every one of
/// them lands in each receiver's address book for the sender.
pub(crate) const MAX_ADDRS: usize = 8;

/// Signed together with the body, so no other protocol that signs with the
/// endpoint key can be made to produce a valid signal.
const SIGNATURE_DOMAIN: &[u8] = b"habilis-network/nostr-signal/1";

/// The version of the body: a build refuses one it does not know.
pub(super) const VERSION: u8 = 1;

/// The body as it is signed and sealed. Short wire names: it rides every
/// announce.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body {
    #[serde(rename = "v")]
    pub(super) version: u8,
    #[serde(rename = "t")]
    pub(super) kind: SignalKind,
    pub(super) from: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) to: Option<[u8; 32]>,
    pub(super) ts: u64,
    #[serde(rename = "n")]
    pub(super) nonce: [u8; 16],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) re: Option<[u8; 16]>,
    #[serde(rename = "env", default, skip_serializing_if = "Option::is_none")]
    pub(super) envelope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) addrs: Vec<SocketAddr>,
    #[serde(default)]
    pub(super) webrtc: bool,
}

impl From<&Signal> for Body {
    fn from(signal: &Signal) -> Self {
        let from = *signal.from.as_bytes();
        let to = signal.to.map(|to| *to.as_bytes());
        let envelope = signal.envelope.clone();
        let addrs = signal.addrs.clone();
        Self {
            version: VERSION,
            kind: signal.kind,
            from,
            to,
            ts: signal.ts,
            nonce: signal.nonce,
            re: signal.re,
            envelope,
            addrs,
            webrtc: signal.webrtc,
        }
    }
}

/// The sealed payload: the body's JSON and its signature.
#[derive(Serialize, Deserialize)]
pub(super) struct Envelope {
    #[serde(rename = "b")]
    pub(super) body: String,
    #[serde(rename = "s")]
    pub(super) signature: String,
}

/// The bytes a signal's signature covers: the domain, the room tag and the body.
pub(super) fn signed_message(room_tag: &[u8; 32], body: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + body.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(room_tag);
    message.extend_from_slice(body.as_bytes());
    message
}
