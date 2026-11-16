//! Opens the signals addressed to one member, and refuses a replay.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use iroh_base::{EndpointId, Signature};

use super::body::{Body, Envelope, MAX_ADDRS, VERSION, signed_message};
use super::nostr_keys::NostrKeys;
use super::signal::Signal;
use super::signal_kind::SignalKind;
use crate::nostr_error::NostrError;
use crate::seal_error;

/// A signal older or newer than this, by the sender's clock against ours, is
/// refused. It bounds how long a captured signal can be replayed.
pub const REPLAY_WINDOW_SECS: u64 = 120;

/// The most `(sender, nonce)` pairs the replay cache holds. A real mesh of
/// 16 peers announcing every 5 s fills about 770 in a window.
const MAX_SEEN: usize = 4096;

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
    /// An opener for the signals of the mesh `keys` name, addressed to `me`.
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
    pub fn open(&mut self, content: &str, now: u64) -> Result<Signal, NostrError> {
        use base64::Engine as _;

        let sealed = BASE64.decode(content).map_err(|_| NostrError::NotBase64)?;
        let plain = seal_error::open_symmetric(&self.keys.seal_key, &sealed)
            .map_err(|_| NostrError::NotSealed)?;
        let envelope: Envelope =
            serde_json::from_slice(&plain).map_err(|_| NostrError::Malformed {
                step: "malformed envelope",
            })?;
        let body: Body =
            serde_json::from_str(&envelope.body).map_err(|_| NostrError::Malformed {
                step: "malformed signal body",
            })?;
        let from = EndpointId::from_bytes(&body.from).map_err(|_| NostrError::Malformed {
            step: "sender is not an endpoint id",
        })?;
        let signature_bytes =
            BASE64
                .decode(&envelope.signature)
                .map_err(|_| NostrError::Malformed {
                    step: "signature is not base64",
                })?;
        let signature: [u8; 64] =
            signature_bytes
                .try_into()
                .map_err(|_| NostrError::Malformed {
                    step: "signature is not 64 bytes",
                })?;
        from.verify(
            &signed_message(&self.keys.room_tag, &envelope.body),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| NostrError::BadSignature)?;
        if body.version != VERSION {
            return Err(NostrError::UnknownVersion(body.version));
        }
        if body.ts.abs_diff(now) > REPLAY_WINDOW_SECS {
            return Err(NostrError::ClockSkew {
                seconds: body.ts.abs_diff(now),
            });
        }
        if from == self.me {
            return Err(NostrError::OwnSignal);
        }
        check_shape(&body)?;
        let to = self.addressee(&body)?;
        self.remember(from, &body, now)?;
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

    /// The addressee of `body`, which must be us if it names one.
    fn addressee(&self, body: &Body) -> Result<Option<EndpointId>, NostrError> {
        let Some(bytes) = body.to else {
            return Ok(None);
        };
        let to = EndpointId::from_bytes(&bytes).map_err(|_| NostrError::Malformed {
            step: "addressee is not an endpoint id",
        })?;
        if to == self.me {
            Ok(Some(to))
        } else {
            Err(NostrError::AddressedElsewhere)
        }
    }

    /// Note the signal as seen, and refuse it if it was seen before. The cache
    /// is bounded: a member that floods fresh nonces cannot grow it.
    fn remember(&mut self, from: EndpointId, body: &Body, now: u64) -> Result<(), NostrError> {
        self.seen
            .retain(|_, ts| ts.abs_diff(now) <= 2 * REPLAY_WINDOW_SECS);
        if self.seen.len() >= MAX_SEEN {
            let oldest = self.seen.iter().min_by_key(|(_, ts)| **ts);
            if let Some((key, _)) = oldest {
                let key = *key;
                // A full cache still leaves the clock window, which bounds any
                // replay of the evicted entry to 120 s.
                self.seen.remove(&key);
            }
        }
        if self.seen.insert((from, body.nonce), body.ts).is_some() {
            return Err(NostrError::Replayed);
        }
        Ok(())
    }
}

/// What each kind must and must not carry. Checked at the seal, so no
/// handler downstream meets a directed kind with no addressee (which every
/// member on the room tag would answer) or an answer that names no offer.
fn check_shape(body: &Body) -> Result<(), NostrError> {
    let (to, envelope, re) = match body.kind {
        SignalKind::Hello => (None, Some(false), Some(false)),
        SignalKind::Offer => (Some(true), Some(true), Some(false)),
        SignalKind::Answer => (Some(true), Some(true), Some(true)),
        SignalKind::Refuse => (Some(true), Some(false), Some(true)),
    };
    let matches = |want: Option<bool>, has: bool| want.is_none_or(|want| want == has);
    if !(matches(to, body.to.is_some())
        && matches(envelope, body.envelope.is_some())
        && matches(re, body.re.is_some()))
    {
        return Err(NostrError::WrongFields { kind: body.kind });
    }
    if body.addrs.len() > MAX_ADDRS {
        return Err(NostrError::TooManyAddresses {
            count: body.addrs.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use iroh_base::SecretKey;

    use super::{MAX_SEEN, Opener, REPLAY_WINDOW_SECS};
    use crate::nostr::body::{Body, Envelope, signed_message};
    use crate::nostr::nostr_keys::NostrKeys;
    use crate::nostr::signal::{Signal, seal};
    use crate::nostr::signal_kind::SignalKind;
    use crate::seal_error;
    use crate::topic::TopicId;

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
        signal.addrs = vec!["192.0.2.1:4433".parse().expect("a valid address")];
        signal
    }

    /// Why `opener` refuses `content` at `now`.
    fn refusal(opener: &mut Opener, content: &str, now: u64) -> String {
        let error = opener
            .open(content, now)
            .expect_err("the signal is refused");
        error.to_string()
    }

    #[test]
    fn a_sealed_signal_opens_as_itself() {
        let (alice, bob) = (member(), member());
        let signal = offer(&alice, &bob);
        let mut opener = Opener::new(keys(), bob.public());
        let signal_back = opener
            .open(&seal(&keys(), &alice, &signal), NOW + 3)
            .expect("a sealed signal opens");
        assert_eq!(signal_back, signal, "the signal comes back unchanged");
    }

    #[test]
    fn another_mesh_cannot_open_it() {
        let (alice, bob) = (member(), member());
        let sealed = seal(&keys(), &alice, &offer(&alice, &bob));
        let other = NostrKeys::derive(&TopicId::from_bytes([5u8; 32]));
        let error = refusal(&mut Opener::new(other, bob.public()), &sealed, NOW);
        assert!(error.contains("not sealed for this mesh"), "{error}");
    }

    /// The forgery the signature exists for: a mesh member (who holds the
    /// seal key) claims to be someone else.
    #[test]
    fn a_member_cannot_sign_as_another() {
        let (alice, bob, mallory) = (member(), member(), member());
        let claimed = offer(&alice, &bob);
        // Mallory builds alice's body and signs it with her own key.
        let alices_body = Body::from(&claimed);
        let body = serde_json::to_string(&alices_body).expect("a body serializes");
        let signature = mallory.sign(&signed_message(&keys().room_tag, &body));
        let envelope = serde_json::to_vec(&Envelope {
            body,
            signature: BASE64.encode(signature.to_bytes()),
        })
        .expect("an envelope serializes");
        let forged = BASE64.encode(seal_error::seal_symmetric(&keys().seal_key, &envelope));
        let error = refusal(&mut Opener::new(keys(), bob.public()), &forged, NOW);
        assert!(error.contains("signature does not match"), "{error}");
    }

    #[test]
    fn a_tampered_body_is_refused() {
        let (alice, bob) = (member(), member());
        let sealed = seal(&keys(), &alice, &offer(&alice, &bob));
        let mut tampered = BASE64.decode(&sealed).expect("the seal is base64");
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let result = Opener::new(keys(), bob.public()).open(&BASE64.encode(tampered), NOW);
        assert!(result.is_err(), "a flipped bit breaks the seal");
    }

    #[test]
    fn a_stale_or_early_signal_is_refused() {
        let (alice, bob) = (member(), member());
        let sealed = seal(&keys(), &alice, &offer(&alice, &bob));
        let mut opener = Opener::new(keys(), bob.public());
        for now in [NOW + REPLAY_WINDOW_SECS + 1, NOW - REPLAY_WINDOW_SECS - 1] {
            let error = refusal(&mut opener, &sealed, now);
            assert!(error.contains("off our clock"), "{error}");
        }
        assert!(
            opener.open(&sealed, NOW + REPLAY_WINDOW_SECS).is_ok(),
            "the edge of the window is still inside it"
        );
    }

    #[test]
    fn a_signal_for_another_member_is_refused() {
        let (alice, bob, carol) = (member(), member(), member());
        let sealed = seal(&keys(), &alice, &offer(&alice, &bob));
        let error = refusal(&mut Opener::new(keys(), carol.public()), &sealed, NOW);
        assert!(error.contains("another member"), "{error}");
    }

    #[test]
    fn our_own_signal_is_refused() {
        let alice = member();
        let hello = Signal::new(SignalKind::Hello, alice.public(), NOW);
        let sealed = seal(&keys(), &alice, &hello);
        let error = refusal(&mut Opener::new(keys(), alice.public()), &sealed, NOW);
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
            opener.open(&sealed, NOW).expect("the first copy opens");
            let error = refusal(&mut opener, &sealed, NOW + 1);
            assert!(error.contains("replayed"), "{kind:?}: {error}");
        }
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
            let sealed = seal(&keys(), &alice, &signal);
            let error = refusal(&mut Opener::new(keys(), bob.public()), &sealed, NOW);
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
        let sealed = seal(&keys(), &alice, &hello);
        let error = refusal(&mut Opener::new(keys(), bob.public()), &sealed, NOW);
        assert!(error.contains("addresses"), "{error}");
    }

    /// A member flooding fresh nonces must not grow the cache without bound.
    #[test]
    fn the_replay_cache_is_bounded() {
        let (alice, bob) = (member(), member());
        let mut opener = Opener::new(keys(), bob.public());
        for _ in 0..(MAX_SEEN + 100) {
            let hello = Signal::new(SignalKind::Hello, alice.public(), NOW);
            opener
                .open(&seal(&keys(), &alice, &hello), NOW)
                .expect("a fresh nonce opens");
        }
        assert!(
            opener.seen.len() <= MAX_SEEN,
            "the cache holds {} pairs",
            opener.seen.len()
        );
    }

    /// A field this build does not know is refused rather than dropped: the
    /// signature covers it, so a newer sender meant it.
    #[test]
    fn an_unknown_body_field_is_refused() {
        let (alice, bob) = (member(), member());
        let hello = Signal::new(SignalKind::Hello, alice.public(), NOW);
        let sealed = seal(&keys(), &alice, &hello);
        let sealed_bytes = BASE64.decode(&sealed).expect("the seal is base64");
        let plain =
            seal_error::open_symmetric(&keys().seal_key, &sealed_bytes).expect("the seal opens");
        let envelope: Envelope = serde_json::from_slice(&plain).expect("an envelope");
        let body = envelope.body.replacen('{', r#"{"extra":1,"#, 1);
        let signature = alice.sign(&signed_message(&keys().room_tag, &body));
        let rebuilt = serde_json::to_vec(&Envelope {
            body,
            signature: BASE64.encode(signature.to_bytes()),
        })
        .expect("an envelope serializes");
        let resealed = BASE64.encode(seal_error::seal_symmetric(&keys().seal_key, &rebuilt));
        let error = refusal(&mut Opener::new(keys(), bob.public()), &resealed, NOW);
        assert!(error.contains("malformed signal body"), "{error}");
    }
}
