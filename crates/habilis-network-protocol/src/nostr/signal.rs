//! One signal in the clear, and how it is sealed for the mesh.

use std::net::SocketAddr;

use iroh_base::{EndpointId, SecretKey};

use super::body::{Body, Envelope, signed_message};
use super::nostr_keys::NostrKeys;
use super::signal_kind::SignalKind;
use crate::seal_error::seal_symmetric;

/// One signal, in the clear. Only [`seal`] and [`Opener::open`](super::Opener::open)
/// see it on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Signal {
    /// What the signal says.
    pub kind: SignalKind,
    /// The member that sent the signal.
    pub from: EndpointId,
    /// Set on directed signals; a receiver refuses one addressed elsewhere.
    pub to: Option<EndpointId>,
    /// The sender's clock, in seconds since the Unix epoch.
    pub ts: u64,
    /// A random value that tells this signal from every other.
    pub nonce: [u8; 16],
    /// The offer an answer or refusal replies to.
    pub re: Option<[u8; 16]>,
    /// The JSEP envelope (JSON) of an offer or answer.
    pub envelope: Option<String>,
    /// The sender's direct addresses, for a peer that can try IP first.
    pub addrs: Vec<SocketAddr>,
    /// The sender has no IP transport and needs a data channel.
    pub webrtc: bool,
}

impl Signal {
    /// A signal of `kind` from `from`, sent at `now`, with no addressee yet.
    #[must_use]
    pub fn new(kind: SignalKind, from: EndpointId, now: u64) -> Self {
        Self {
            kind,
            from,
            to: None,
            ts: now,
            nonce: rand::random(),
            re: None,
            envelope: None,
            addrs: Vec::new(),
            webrtc: false,
        }
    }
}

/// Seal `signal` for the mesh, signed by `secret`, as the `content` of a Nostr
/// event.
///
/// # Panics
/// If `secret` is not the key of `signal.from`: a caller bug, since the
/// receiver would drop the signal anyway.
#[must_use]
pub fn seal(keys: &NostrKeys, secret: &SecretKey, signal: &Signal) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    assert_eq!(
        secret.public(),
        signal.from,
        "a signal is signed by its sender"
    );
    let body = serde_json::to_string(&Body::from(signal)).expect("a signal body always serializes");
    let signature = secret.sign(&signed_message(&keys.room_tag, &body));
    let envelope = serde_json::to_vec(&Envelope {
        body,
        signature: BASE64.encode(signature.to_bytes()),
    })
    .expect("an envelope always serializes");
    BASE64.encode(seal_symmetric(&keys.seal_key, &envelope))
}
