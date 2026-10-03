//! What a mesh puts on Nostr: the tags it listens on, the relays it ranks, and
//! the sealed, signed signal every event carries.
//!
//! Everything is derived from the gossip topic id, so a peer without the
//! password or the invite (which the topic binds) cannot even find the room.
//! The Nostr key an event is signed with is random and proves nothing; the
//! Ed25519 signature by the sender's iroh endpoint key, inside the seal, is
//! what makes `from` true. Without it anyone holding the mesh id could offer
//! as another member and tear down that member's session.

use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use iroh_base::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::crypto::derive_secret;
use crate::mesh::NostrChoice;
use crate::seal::{open_symmetric, seal_symmetric};
use crate::topic::TopicId;

/// Public relays that forwarded ephemeral events in the probe of 2026-09-24
/// (`cargo run -p habilis-network-nostr --example probe`), fastest first. `relay.damus.io`
/// forwarded too but rate-limits bursts, so it is left out.
pub const PINNED_RELAYS: &[&str] = &[
    "wss://relay-can.zombi.cloudrodion.com",
    "wss://nostr.islandarea.net",
    "wss://bucket.coracle.social",
    "wss://nostr-relay.corb.net",
    "wss://schnorr.me",
    "wss://nostr-01.uid.ovh",
    "wss://top.testrelay.top",
    "wss://basspistol.org",
    "wss://offchain.pub",
    "wss://relay.primal.net",
    "wss://relay.sigit.io",
    "wss://social.amanah.eblessing.co",
    "wss://nos.lol",
    "wss://nostr.sathoarder.com",
    "wss://relay02.lnfi.network",
    "wss://staging.yabu.me",
    "wss://yabu.me/v2",
];

/// A signal older or newer than this, by the sender's clock against ours, is
/// refused. It bounds how long a captured signal can be replayed.
pub const REPLAY_WINDOW_SECS: u64 = 120;

/// The most `(sender, nonce)` pairs the replay cache holds. A real mesh of
/// 16 peers announcing every 5 s fills about 770 in a window.
const MAX_SEEN: usize = 4096;

/// The most addresses a signal may carry. A real peer has a few; every one of
/// them lands in each receiver's address book for the sender.
const MAX_ADDRS: usize = 8;

/// Signed together with the body, so no other protocol that signs with the
/// endpoint key can be made to produce a valid signal.
const SIGNATURE_DOMAIN: &[u8] = b"habilis-network/nostr-signal/1";

/// The Nostr view of one mesh, all derived from its topic id.
#[derive(Clone)]
pub struct NostrKeys {
    room_tag: [u8; 32],
    seal_key: [u8; 32],
    relay_seed: [u8; 32],
}

impl std::fmt::Debug for NostrKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("NostrKeys").finish_non_exhaustive()
    }
}

impl NostrKeys {
    #[must_use]
    pub fn derive(topic: &TopicId) -> Self {
        Self {
            room_tag: derive_secret(topic.as_bytes(), b"nostr-room"),
            seal_key: derive_secret(topic.as_bytes(), b"nostr-seal"),
            relay_seed: derive_secret(topic.as_bytes(), b"nostr-relays"),
        }
    }

    /// The tag every member announces on and listens to.
    #[must_use]
    pub fn room_tag(&self) -> [u8; 32] {
        self.room_tag
    }

    /// The tag directed signals to `member` go to. Unlinkable to the member's
    /// id without the room tag.
    #[must_use]
    pub fn self_tag(&self, member: &EndpointId) -> [u8; 32] {
        derive_secret(&self.room_tag, member.as_bytes())
    }

    /// The relays of `choice`, ranked the same way by every member.
    ///
    /// # Panics
    /// If a pinned URL does not parse; they are constants checked by a test.
    #[must_use]
    pub fn ranked_relays(&self, choice: &NostrChoice) -> Vec<Url> {
        let urls: Vec<Url> = match choice {
            NostrChoice::Disabled => return Vec::new(),
            NostrChoice::Pinned => PINNED_RELAYS
                .iter()
                .map(|url| url.parse().expect("pinned relay URLs are valid"))
                .collect(),
            NostrChoice::Custom(urls) => urls.clone(),
        };
        rank_relays(urls, &self.relay_seed)
    }
}

/// Highest-random-weight order: each relay scores `sha256(seed ‖ url)`, highest
/// first. Adding or removing one relay leaves the order of the others alone,
/// so members on two versions of the pinned list still rank alike. A relay
/// named twice is kept once (it still counted twice against the list's cap).
#[must_use]
pub fn rank_relays(mut urls: Vec<Url>, seed: &[u8; 32]) -> Vec<Url> {
    let score = |url: &Url| -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(url.as_str().as_bytes());
        hasher.finalize().into()
    };
    urls.sort_by_cached_key(|url| std::cmp::Reverse(score(url)));
    urls.dedup();
    urls
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalKind {
    /// "I am here": on the room tag to everyone, or on a member's self tag to
    /// wake it.
    Hello,
    /// A `WebRTC` offer, to the answering member's self tag.
    Offer,
    /// The answer to the offer whose nonce is in `re`.
    Answer,
    /// The answerer is at its session cap; `re` names the refused offer.
    Refuse,
}

/// One signal, in the clear. Only [`seal`] and [`Opener::open`] see it on the
/// wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub kind: SignalKind,
    pub from: EndpointId,
    /// Set on directed signals; a receiver refuses one addressed elsewhere.
    pub to: Option<EndpointId>,
    /// The sender's clock, in seconds since the Unix epoch.
    pub ts: u64,
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

/// The body as it is signed and sealed. Short wire names: it rides every
/// announce.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "t")]
    kind: SignalKind,
    from: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<[u8; 32]>,
    ts: u64,
    #[serde(rename = "n")]
    nonce: [u8; 16],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    re: Option<[u8; 16]>,
    #[serde(rename = "env", default, skip_serializing_if = "Option::is_none")]
    envelope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    addrs: Vec<SocketAddr>,
    #[serde(default)]
    webrtc: bool,
}

/// The sealed payload: the body's JSON and its signature.
#[derive(Serialize, Deserialize)]
struct Envelope {
    #[serde(rename = "b")]
    body: String,
    #[serde(rename = "s")]
    signature: String,
}

const VERSION: u8 = 1;

fn signed_message(room_tag: &[u8; 32], body: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + body.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(room_tag);
    message.extend_from_slice(body.as_bytes());
    message
}

/// Seal `signal` for the mesh, signed by `secret`, as the `content` of a Nostr
/// event.
///
/// # Panics
/// If `secret` is not the key of `signal.from`: a caller bug, since the
/// receiver would drop the signal anyway.
#[must_use]
pub fn seal(keys: &NostrKeys, secret: &SecretKey, signal: &Signal) -> String {
    assert_eq!(
        secret.public(),
        signal.from,
        "a signal is signed by its sender"
    );
    let body = serde_json::to_string(&Body {
        version: VERSION,
        kind: signal.kind,
        from: *signal.from.as_bytes(),
        to: signal.to.map(|to| *to.as_bytes()),
        ts: signal.ts,
        nonce: signal.nonce,
        re: signal.re,
        envelope: signal.envelope.clone(),
        addrs: signal.addrs.clone(),
        webrtc: signal.webrtc,
    })
    .expect("a signal body always serializes");
    let signature = secret.sign(&signed_message(&keys.room_tag, &body));
    let envelope = serde_json::to_vec(&Envelope {
        body,
        signature: BASE64.encode(signature.to_bytes()),
    })
    .expect("an envelope always serializes");
    BASE64.encode(seal_symmetric(&keys.seal_key, &envelope))
}

/// Opens signals addressed to one member and remembers what it has opened, so
/// a signal replayed inside the window is refused.
#[derive(Debug)]
pub struct Opener {
    keys: NostrKeys,
    me: EndpointId,
    /// `(sender, nonce)` of every signal opened in the last two windows, with
    /// its `ts`, for pruning.
    seen: HashMap<(EndpointId, [u8; 16]), u64>,
}

impl Opener {
    #[must_use]
    pub fn new(keys: NostrKeys, me: EndpointId) -> Self {
        Self {
            keys,
            me,
            seen: HashMap::new(),
        }
    }

    /// Open a sealed signal. Checked in this order, so a forger can fill
    /// nothing, not even the replay cache: the seal, the signature against
    /// `from`, the version, the clock window, the addressee, the replay.
    ///
    /// # Errors
    /// Any check fails: wrong mesh, tampered, forged, stale, for another
    /// member, from ourselves, or already seen.
    pub fn open(&mut self, content: &str, now: u64) -> Result<Signal> {
        let sealed = BASE64.decode(content).context("content is not base64")?;
        let plain =
            open_symmetric(&self.keys.seal_key, &sealed).context("not sealed for this mesh")?;
        let envelope: Envelope = serde_json::from_slice(&plain).context("malformed envelope")?;
        let body: Body = serde_json::from_str(&envelope.body).context("malformed signal body")?;
        let from = EndpointId::from_bytes(&body.from).context("sender is not an endpoint id")?;
        let signature: [u8; 64] = BASE64
            .decode(&envelope.signature)
            .context("signature is not base64")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))?;
        from.verify(
            &signed_message(&self.keys.room_tag, &envelope.body),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| anyhow::anyhow!("signature does not match the sender"))?;
        ensure!(
            body.version == VERSION,
            "unknown signal version {}",
            body.version
        );
        ensure!(
            body.ts.abs_diff(now) <= REPLAY_WINDOW_SECS,
            "signal is {} s off our clock",
            body.ts.abs_diff(now)
        );
        ensure!(from != self.me, "our own signal");
        check_shape(&body)?;
        let to = body
            .to
            .map(|to| EndpointId::from_bytes(&to))
            .transpose()
            .context("addressee is not an endpoint id")?;
        if let Some(to) = to
            && to != self.me
        {
            bail!("signal addressed to another member");
        }
        self.seen
            .retain(|_, ts| ts.abs_diff(now) <= 2 * REPLAY_WINDOW_SECS);
        if self.seen.len() >= MAX_SEEN
            && let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(key, _)| *key)
        {
            // A full cache still leaves the clock window, which bounds any
            // replay of the evicted entry to 120 s.
            self.seen.remove(&oldest);
        }
        ensure!(
            self.seen.insert((from, body.nonce), body.ts).is_none(),
            "replayed signal"
        );
        Ok(Signal {
            kind: body.kind,
            from,
            to,
            ts: body.ts,
            nonce: body.nonce,
            re: body.re,
            envelope: body.envelope,
            addrs: body.addrs,
            webrtc: body.webrtc,
        })
    }
}

/// What each kind must and must not carry. Checked at the seal, so no
/// handler downstream meets a directed kind with no addressee (which every
/// member on the room tag would answer) or an answer that names no offer.
fn check_shape(body: &Body) -> Result<()> {
    let (to, envelope, re) = match body.kind {
        SignalKind::Hello => (None, Some(false), Some(false)),
        SignalKind::Offer => (Some(true), Some(true), Some(false)),
        SignalKind::Answer => (Some(true), Some(true), Some(true)),
        SignalKind::Refuse => (Some(true), Some(false), Some(true)),
    };
    let matches = |want: Option<bool>, has: bool| want.is_none_or(|want| want == has);
    ensure!(
        matches(to, body.to.is_some())
            && matches(envelope, body.envelope.is_some())
            && matches(re, body.re.is_some()),
        "malformed {:?}: wrong fields for its kind",
        body.kind
    );
    ensure!(
        body.addrs.len() <= MAX_ADDRS,
        "signal carries {} addresses, the ceiling is {MAX_ADDRS}",
        body.addrs.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn keys() -> NostrKeys {
        NostrKeys::derive(&TopicId::from_bytes([4u8; 32]))
    }

    fn member() -> SecretKey {
        SecretKey::generate()
    }

    fn offer(from: &SecretKey, to: &SecretKey) -> Signal {
        let mut signal = Signal::new(SignalKind::Offer, from.public(), NOW);
        signal.to = Some(to.public());
        signal.envelope = Some(r#"{"type":"offer","v":1,"endpoint_id":"x","sdp":"v=0"}"#.into());
        signal.addrs = vec!["192.0.2.1:4433".parse().unwrap()];
        signal
    }

    #[test]
    fn a_sealed_signal_opens_as_itself() {
        let (alice, bob) = (member(), member());
        let signal = offer(&alice, &bob);
        let mut opener = Opener::new(keys(), bob.public());
        let signal_back = opener
            .open(&seal(&keys(), &alice, &signal), NOW + 3)
            .unwrap();
        assert_eq!(signal_back, signal);
    }

    #[test]
    fn another_mesh_cannot_open_it() {
        let (alice, bob) = (member(), member());
        let sealed = seal(&keys(), &alice, &offer(&alice, &bob));
        let other = NostrKeys::derive(&TopicId::from_bytes([5u8; 32]));
        let error = Opener::new(other, bob.public())
            .open(&sealed, NOW)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not sealed for this mesh"), "{error}");
    }

    /// The forgery the signature exists for: a mesh member (who holds the
    /// seal key) claims to be someone else.
    #[test]
    fn a_member_cannot_sign_as_another() {
        let (alice, bob, mallory) = (member(), member(), member());
        let claimed = offer(&alice, &bob);
        // Mallory builds alice's body and signs it with her own key.
        let body = serde_json::to_string(&Body {
            version: VERSION,
            kind: claimed.kind,
            from: *alice.public().as_bytes(),
            to: Some(*bob.public().as_bytes()),
            ts: NOW,
            nonce: claimed.nonce,
            re: None,
            envelope: claimed.envelope.clone(),
            addrs: Vec::new(),
            webrtc: false,
        })
        .unwrap();
        let signature = mallory.sign(&signed_message(&keys().room_tag, &body));
        let envelope = serde_json::to_vec(&Envelope {
            body,
            signature: BASE64.encode(signature.to_bytes()),
        })
        .unwrap();
        let forged = BASE64.encode(seal_symmetric(&keys().seal_key, &envelope));
        let error = Opener::new(keys(), bob.public())
            .open(&forged, NOW)
            .unwrap_err()
            .to_string();
        assert!(error.contains("signature does not match"), "{error}");
    }

    #[test]
    fn a_tampered_body_is_refused() {
        let (alice, bob) = (member(), member());
        let sealed = seal(&keys(), &alice, &offer(&alice, &bob));
        let mut tampered = BASE64.decode(&sealed).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            Opener::new(keys(), bob.public())
                .open(&BASE64.encode(tampered), NOW)
                .is_err()
        );
    }

    #[test]
    fn a_stale_or_early_signal_is_refused() {
        let (alice, bob) = (member(), member());
        let sealed = seal(&keys(), &alice, &offer(&alice, &bob));
        let mut opener = Opener::new(keys(), bob.public());
        for now in [NOW + REPLAY_WINDOW_SECS + 1, NOW - REPLAY_WINDOW_SECS - 1] {
            let error = opener.open(&sealed, now).unwrap_err().to_string();
            assert!(error.contains("off our clock"), "{error}");
        }
        assert!(opener.open(&sealed, NOW + REPLAY_WINDOW_SECS).is_ok());
    }

    #[test]
    fn a_signal_for_another_member_is_refused() {
        let (alice, bob, carol) = (member(), member(), member());
        let sealed = seal(&keys(), &alice, &offer(&alice, &bob));
        let error = Opener::new(keys(), carol.public())
            .open(&sealed, NOW)
            .unwrap_err()
            .to_string();
        assert!(error.contains("another member"), "{error}");
    }

    #[test]
    fn our_own_signal_is_refused() {
        let alice = member();
        let hello = Signal::new(SignalKind::Hello, alice.public(), NOW);
        let error = Opener::new(keys(), alice.public())
            .open(&seal(&keys(), &alice, &hello), NOW)
            .unwrap_err()
            .to_string();
        assert!(error.contains("own signal"), "{error}");
    }

    /// Every kind goes through the cache, so a replayed refusal cannot put a
    /// willing peer on cooldown.
    #[test]
    fn a_replayed_signal_of_any_kind_is_refused() {
        let (alice, bob) = (member(), member());
        for kind in [
            SignalKind::Hello,
            SignalKind::Offer,
            SignalKind::Answer,
            SignalKind::Refuse,
        ] {
            let mut signal = Signal::new(kind, alice.public(), NOW);
            if kind != SignalKind::Hello {
                signal.to = Some(bob.public());
            }
            if matches!(kind, SignalKind::Answer | SignalKind::Refuse) {
                signal.re = Some([1u8; 16]);
            }
            if matches!(kind, SignalKind::Offer | SignalKind::Answer) {
                signal.envelope = Some("{}".into());
            }
            let sealed = seal(&keys(), &alice, &signal);
            let mut opener = Opener::new(keys(), bob.public());
            opener.open(&sealed, NOW).unwrap();
            let error = opener.open(&sealed, NOW + 1).unwrap_err().to_string();
            assert!(error.contains("replayed"), "{kind:?}: {error}");
        }
    }

    #[test]
    fn the_tags_are_distinct_per_mesh_and_per_member() {
        let (alice, bob) = (member(), member());
        let other = NostrKeys::derive(&TopicId::from_bytes([5u8; 32]));
        assert_ne!(keys().room_tag(), other.room_tag());
        assert_ne!(
            keys().self_tag(&alice.public()),
            keys().self_tag(&bob.public())
        );
        assert_ne!(
            keys().self_tag(&alice.public()),
            other.self_tag(&alice.public())
        );
        assert_ne!(keys().room_tag(), keys().self_tag(&alice.public()));
    }

    #[test]
    fn every_pinned_relay_parses_as_a_websocket_url() {
        let ranked = keys().ranked_relays(&NostrChoice::Pinned);
        assert_eq!(ranked.len(), PINNED_RELAYS.len());
        assert!(ranked.iter().all(|url| url.scheme() == "wss"));
        assert!(keys().ranked_relays(&NostrChoice::Disabled).is_empty());
    }

    /// Two members on lists that differ by one relay still rank the rest
    /// alike, which is what keeps their open relays overlapping.
    #[test]
    fn dropping_one_relay_leaves_the_order_of_the_rest() {
        let urls: Vec<Url> = PINNED_RELAYS
            .iter()
            .map(|url| url.parse().unwrap())
            .collect();
        let seed = [9u8; 32];
        let full = rank_relays(urls.clone(), &seed);
        let dropped = &urls[3];
        let without: Vec<Url> = urls.iter().filter(|url| *url != dropped).cloned().collect();
        let expected: Vec<Url> = full.iter().filter(|url| *url != dropped).cloned().collect();
        assert_eq!(rank_relays(without, &seed), expected);
        // A different mesh ranks differently, so meshes spread over relays.
        assert_ne!(rank_relays(urls, &[8u8; 32]), full);
    }

    /// Each kind carries what its handler needs and nothing else. An offer
    /// with no addressee would be answered by every member on the room tag.
    #[test]
    fn a_kind_without_its_fields_is_refused() {
        let (alice, bob) = (member(), member());
        let mut undirected = offer(&alice, &bob);
        undirected.to = None;
        let mut no_envelope = offer(&alice, &bob);
        no_envelope.envelope = None;
        let mut answer_without_re = Signal::new(SignalKind::Answer, alice.public(), NOW);
        answer_without_re.to = Some(bob.public());
        answer_without_re.envelope = Some("{}".into());
        let mut refuse_with_envelope = Signal::new(SignalKind::Refuse, alice.public(), NOW);
        refuse_with_envelope.to = Some(bob.public());
        refuse_with_envelope.re = Some([2u8; 16]);
        refuse_with_envelope.envelope = Some("{}".into());
        let mut hello_with_re = Signal::new(SignalKind::Hello, alice.public(), NOW);
        hello_with_re.re = Some([2u8; 16]);
        for (name, signal) in [
            ("undirected offer", undirected),
            ("offer without envelope", no_envelope),
            ("answer without re", answer_without_re),
            ("refuse with envelope", refuse_with_envelope),
            ("hello with re", hello_with_re),
        ] {
            let error = Opener::new(keys(), bob.public())
                .open(&seal(&keys(), &alice, &signal), NOW)
                .expect_err(name)
                .to_string();
            assert!(error.contains("malformed"), "{name}: {error}");
        }
    }

    #[test]
    fn a_signal_with_too_many_addresses_is_refused() {
        let (alice, bob) = (member(), member());
        let mut hello = Signal::new(SignalKind::Hello, alice.public(), NOW);
        hello.addrs = (0..100u16)
            .map(|port| SocketAddr::from(([192, 0, 2, 1], 4000 + port)))
            .collect();
        let error = Opener::new(keys(), bob.public())
            .open(&seal(&keys(), &alice, &hello), NOW)
            .unwrap_err()
            .to_string();
        assert!(error.contains("addresses"), "{error}");
    }

    /// A member flooding fresh nonces must not grow the cache without bound.
    #[test]
    fn the_replay_cache_is_bounded() {
        let (alice, bob) = (member(), member());
        let mut opener = Opener::new(keys(), bob.public());
        for _ in 0..(MAX_SEEN + 100) {
            let hello = Signal::new(SignalKind::Hello, alice.public(), NOW);
            opener.open(&seal(&keys(), &alice, &hello), NOW).unwrap();
        }
        assert!(opener.seen.len() <= MAX_SEEN, "{}", opener.seen.len());
    }

    /// A field this build does not know is refused rather than dropped: the
    /// signature covers it, so a newer sender meant it.
    #[test]
    fn an_unknown_body_field_is_refused() {
        let (alice, bob) = (member(), member());
        let hello = Signal::new(SignalKind::Hello, alice.public(), NOW);
        let sealed = seal(&keys(), &alice, &hello);
        let envelope: Envelope = serde_json::from_slice(
            &open_symmetric(&keys().seal_key, &BASE64.decode(&sealed).unwrap()).unwrap(),
        )
        .unwrap();
        let body = envelope.body.replacen('{', r#"{"extra":1,"#, 1);
        let signature = alice.sign(&signed_message(&keys().room_tag, &body));
        let resealed = BASE64.encode(seal_symmetric(
            &keys().seal_key,
            &serde_json::to_vec(&Envelope {
                body,
                signature: BASE64.encode(signature.to_bytes()),
            })
            .unwrap(),
        ));
        let error = Opener::new(keys(), bob.public())
            .open(&resealed, NOW)
            .unwrap_err()
            .to_string();
        assert!(error.contains("malformed signal body"), "{error}");
    }
}
