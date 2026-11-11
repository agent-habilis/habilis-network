//! The JSON wire envelope of a protocol frame, and its constructors and checks.

#[cfg(any(test, feature = "test-fixtures"))]
use iroh_base::Signature;

use habilis_network_util::unix_secs::UnixSecs;

use crate::identity::{self, Identity};
use crate::meshes::MeshId;
use crate::nickname_error::Nickname;
use crate::{AuthorKey, ContentHash, DedupKey};

use super::{
    AppFrameParams, Channel, MAX_MESSAGE_SIZE, MessageBody, MessageError, MessageId, MessageKind,
    PresenceSubtype, Shard, Signer, VERSION, Verified, Wire, WireIn, default_ext, empty_body,
    split_resend_trailer,
};

/// A protocol frame — serialized as JSON on the wire. The transport
/// envelope beneath the app layer: for an app frame (e.g. chat, `app_msg`),
/// `body` carries a whole serialized app payload opaque to this layer;
/// plumbing kinds (presence, state digests, ping/pong, state/meta) carry their own
/// opaque bodies.
///
/// Wire format (compact JSON, one line):
/// ```json
/// {"v":"17.0","id":"<uuid>","type":"app","tag":"app_msg","mesh":"...","author":"word-word","ts":1234567890,"body":"{\"messageId\":\"<uuid>\",\"role\":\"ROLE_USER\",...}","ext":{}}
/// ```
///
/// `to` (the addressee nickname) is inlined into the JSON for a directed app frame.
/// `ext`: free-form object for experimental/future fields; parsers MUST ignore unknown keys inside it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Message {
    /// The protocol version of the message.
    pub version: String,
    /// The id of the message.
    pub id: MessageId,
    /// What the message carries.
    pub kind: MessageKind,
    /// The mesh that the message belongs to.
    pub mesh: MeshId,
    /// The member that signed the message.
    pub author: Nickname,
    /// Unix timestamp (seconds, UTC).
    pub timestamp: UnixSecs,
    /// The body of the message (sealed for a directed frame on a passworded mesh).
    pub body: MessageBody,
    /// Author's Ed25519 public key and the detached signature over the message's
    /// [canonical bytes](Message::canonical_bytes), always together: a message has both or
    /// neither. `None` is the unsigned message: its key and signature are skipped on the wire,
    /// which is also the **canonical pre-signing form** that [`Message::canonical_bytes`] hashes
    /// (the signature cannot cover itself). Real outbound traffic is always signed on the
    /// broadcast path, and the receive path drops anything that fails verification.
    pub signer: Option<Signer>,
    /// Shard header: present only on a message that is one slice of a body
    /// too large for a single message (see [`Shard`]). `None` on an ordinary
    /// message, so its wire form is unchanged. Signed like every other field.
    pub shard: Option<Shard>,
    /// Extension escape hatch. Add experimental fields here; stable fields get promoted to top-level.
    pub ext: serde_json::Value,
}

impl Message {
    fn new(mesh: &MeshId, author: &Nickname, kind: MessageKind, body: MessageBody) -> Self {
        Message {
            version: VERSION.to_string(),
            id: MessageId::random(),
            kind,
            mesh: mesh.clone(),
            author: author.clone(),
            timestamp: UnixSecs::now(),
            body,
            signer: None,
            shard: None,
            ext: default_ext(),
        }
    }

    /// A frame of an explicit `kind` — the generic constructor the task
    /// send path uses to build the application's directed frames through
    /// one shard-splitting flow.
    #[must_use]
    pub fn new_frame(
        mesh: &MeshId,
        author: &Nickname,
        kind: MessageKind,
        body: MessageBody,
    ) -> Self {
        Self::new(mesh, author, kind, body)
    }

    /// An application-payload frame: `tag` is the app's wire discriminant, `to`
    /// the directed addressee (`None` for a broadcast), `corr` the optional
    /// request/response correlation id, and `body` the opaque payload. The
    /// engine routes on `to`/`corr` and never inspects `body`.
    ///
    /// Reused as-is by `habilis_network::ops::send_app`, whose `App` frame shape is
    /// identical.
    #[must_use]
    pub fn new_app(mesh: &MeshId, author: &Nickname, params: AppFrameParams) -> Self {
        let AppFrameParams {
            tag,
            to,
            corr,
            body,
        } = params;
        Self::new(mesh, author, MessageKind::App { tag, to, corr }, body)
    }

    /// A presence message for `author` joining `mesh`. It has no body.
    #[must_use]
    pub fn new_joined(mesh: &MeshId, author: &Nickname) -> Self {
        // Presence carries no body; peer metadata (model/harness/host) is application
        // data an agent writes into the `meta` channel, not a presence payload.
        Self::new(
            mesh,
            author,
            MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            },
            empty_body(),
        )
    }

    /// A presence message for `author` joining `mesh`, with the identity proof of its session in
    /// the body. An empty body stays valid: a node with no member key sends `new_joined`.
    #[must_use]
    pub fn new_joined_with_proof(
        mesh: &MeshId,
        author: &Nickname,
        proof: &identity::IdentityProof,
    ) -> Self {
        // A proof text is hex digits and separators, so it is always a valid body.
        let body = MessageBody::try_new(&proof.encode()).unwrap_or_else(|_| empty_body());
        Self::new(
            mesh,
            author,
            MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            },
            body,
        )
    }

    /// The identity proof in the body of a `joined` frame. An empty, cut or bad body gives `None`.
    #[must_use]
    pub fn joined_proof(&self) -> Option<identity::IdentityProof> {
        identity::IdentityProof::decode(self.body.as_str())
    }

    /// A presence message for `author` leaving `mesh`. It has no body.
    #[must_use]
    pub fn new_left(mesh: &MeshId, author: &Nickname) -> Self {
        Self::new(
            mesh,
            author,
            MessageKind::Presence {
                subtype: PresenceSubtype::Left,
            },
            empty_body(),
        )
    }

    /// A presence message that `author` is alive on `mesh`. It has no body.
    #[must_use]
    pub fn new_alive(mesh: &MeshId, author: &Nickname) -> Self {
        Self::new(
            mesh,
            author,
            MessageKind::Presence {
                subtype: PresenceSubtype::Alive,
            },
            empty_body(),
        )
    }

    /// A request for the identity proof of the session `to`, sent to that session alone. It has no
    /// body.
    #[must_use]
    pub fn new_proof_request(mesh: &MeshId, author: &Nickname, to: AuthorKey) -> Self {
        Self::new(mesh, author, MessageKind::ProofRequest { to }, empty_body())
    }

    /// A liveness probe (broadcast). Receivers auto-respond with a
    /// `Pong` addressed back to `author`.
    #[must_use]
    pub fn new_ping(mesh: &MeshId, author: &Nickname) -> Self {
        Self::new(mesh, author, MessageKind::Ping, empty_body())
    }

    /// A `Pong` response addressed to the original pinger (`to`), naming the `Ping` (`probe`) that
    /// it answers.
    #[must_use]
    pub fn new_pong(mesh: &MeshId, author: &Nickname, to: AuthorKey, probe: &MessageId) -> Self {
        let probe = probe.clone();
        Self::new(mesh, author, MessageKind::Pong { to, probe }, empty_body())
    }

    /// Create a `PeerInfo` message. The body carries endpoint address data
    /// as a JSON string for mesh peer lookup.
    #[must_use]
    pub fn new_peer_info(mesh: &MeshId, author: &Nickname, addr_data: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::PeerInfo, addr_data)
    }

    /// A multihop link-state advertisement; `vector_json` is a serialized
    /// `habilis_network_iroh_multihop_transport::LinkVector`.
    ///
    /// Portable: it only builds a `Message`, so a browser that mints vectors builds
    /// the advertisement as a native node does.
    #[must_use]
    pub fn new_link_state(mesh: &MeshId, author: &Nickname, vector_json: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::LinkState, vector_json)
    }

    /// A durable state event whose opaque payload is `body`. Routed to the
    /// un-pruned `daemon::state_log`. Harness
    /// constructor; production uses [`new_channel_event`](Self::new_channel_event).
    #[cfg(any(test, feature = "adversarial"))]
    #[must_use]
    pub fn new_state(mesh: &MeshId, author: &Nickname, body: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::State, body)
    }

    /// A durable event on the given channel (`state` / `meta`).
    #[must_use]
    pub fn new_channel_event(
        mesh: &MeshId,
        author: &Nickname,
        body: MessageBody,
        channel: Channel,
    ) -> Self {
        Self::new(mesh, author, channel.event_kind(), body)
    }

    /// An anti-entropy digest for the given channel.
    #[must_use]
    pub fn new_channel_digest(
        mesh: &MeshId,
        author: &Nickname,
        body: MessageBody,
        channel: Channel,
    ) -> Self {
        Self::new(mesh, author, channel.digest_kind(), body)
    }

    /// A state anti-entropy digest whose `body` is the sender's automerge heads.
    /// Test-only; production uses [`new_channel_digest`](Self::new_channel_digest).
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn new_state_digest(mesh: &MeshId, author: &Nickname, body: MessageBody) -> Self {
        Self::new(mesh, author, MessageKind::StateDigest, body)
    }

    /// Serialize to compact JSON bytes for the gossip wire. Outside this crate only a [`Verified`]
    /// serializes, through [`Verified::serialize`]: an unverified or an authored view has no wire form.
    /// # Errors
    /// A [`MessageError::Source`] when the JSON does not encode, or
    /// [`MessageError::Oversize`] when the bytes pass `MAX_MESSAGE_SIZE`.
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, MessageError> {
        let bytes = serde_json::to_vec(&Wire(self))
            .map_err(MessageError::with_step("failed to serialize message"))?;
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::Oversize { bytes: bytes.len() });
        }
        Ok(bytes)
    }

    /// Parse a message from JSON bytes.
    /// # Errors
    /// A [`MessageError::TooLarge`] past `MAX_MESSAGE_SIZE`, a [`MessageError::Source`]
    /// when the JSON does not parse, [`MessageError::UnsupportedVersion`] for another
    /// protocol version, or [`MessageError::Invalid`] for a field the protocol does not allow.
    pub fn parse(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::TooLarge);
        }
        let wire: WireIn = match serde_json::from_slice(data) {
            Ok(wire) => wire,
            Err(error) => {
                // A frame of another version can fail on a field that the version changed. The
                // cause to name is the version, not the field.
                if let Some(version) = envelope_version(data)
                    && version != VERSION
                {
                    return Err(MessageError::UnsupportedVersion(version));
                }
                return Err(MessageError::with_step("failed to parse message JSON")(
                    error,
                ));
            }
        };
        if wire.version != VERSION {
            return Err(MessageError::UnsupportedVersion(wire.version));
        }
        Message::try_from(wire).map_err(MessageError::Invalid)
    }

    /// Parse a gossip payload that may end in the trailer of a resend (see
    /// [`WireFrame::copy_with_resend_nonce`](super::WireFrame::copy_with_resend_nonce)). Returns the message and the nonce, if any. The trailer is
    /// outside the signature: it changes the gossip message id and nothing else.
    ///
    /// # Errors
    /// A [`MessageError`] as for [`Message::parse`].
    pub fn parse_wire(data: &[u8]) -> Result<(Self, Option<u64>), MessageError> {
        let (frame, nonce) = split_resend_trailer(data);
        Ok((Self::parse(frame)?, nonce))
    }

    /// Deterministic, domain-separated, length-prefixed encoding of every
    /// signed field (i.e. all of them **except** `sig`, including
    /// `pubkey` so the key is bound to the message). This — not the JSON —
    /// is what gets signed and hashed, so signature verification does not
    /// depend on JSON formatting. `kind` and `ext` are folded in via their
    /// (deterministic, sorted-key) `serde_json` encodings.
    #[must_use]
    /// # Panics
    /// If a field exceeds `u32::MAX` bytes; the wire cap makes that unreachable.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_with_key(self.author_key().as_ref())
    }

    /// [`Self::canonical_bytes`] as if the author key were `key`. The signature is not in
    /// the signed bytes, so a message under signing has the key and not yet the signature.
    fn canonical_with_key(&self, key: Option<&AuthorKey>) -> Vec<u8> {
        const DOMAIN: &[u8] = b"habilis-mesh/msg";
        let mut buffer = Vec::new();
        let mut field = |bytes: &[u8]| {
            let len: u32 = u32::try_from(bytes.len()).expect("a message field fits in u32");
            buffer.extend_from_slice(&len.to_le_bytes());
            buffer.extend_from_slice(bytes);
        };
        field(DOMAIN);
        field(self.version.as_bytes());
        field(self.id.as_str().as_bytes());
        field(&serde_json::to_vec(&self.kind).unwrap_or_default());
        field(self.mesh.as_str().as_bytes());
        field(self.author.as_str().as_bytes());
        field(&self.timestamp.to_le_bytes());
        field(self.body.as_str().as_bytes());
        // The hex text of the key, not its 32 bytes: the text is what every signature covers.
        match key {
            Some(key) => field(&key.hex()),
            None => field(&[]),
        }
        // The shard header is signed so a shard can't be re-grouped or
        // re-indexed by a relay. `None` (ordinary message) folds as `null`.
        field(&serde_json::to_vec(&self.shard).unwrap_or_default());
        field(&serde_json::to_vec(&self.ext).unwrap_or_default());
        buffer
    }

    /// This message's content hash (SHA-256 of [`Message::canonical_bytes`]) — the id used by
    /// another author's `prev` backlink and by fork detection, and the key of the DAG.
    /// Recomputed locally on receive; never trusted off the wire.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::of(&self.canonical_bytes())
    }

    /// The key that signed this message, or `None` for an unsigned message. Outside this module
    /// a message that is not known to be signed has no proven key: a [`Verified`] or an
    /// `Authored` gives it through `key()`, with no `Option`.
    #[must_use]
    pub(crate) fn author_key(&self) -> Option<AuthorKey> {
        self.signer.map(|signed| signed.key)
    }

    /// The 16-byte dedup key (`SHA-256(pubkey ‖ id)[..16]`).
    /// Dedup keys on this rather
    /// than the sender-chosen id, so a forged message reusing a victim's id
    /// cannot suppress the genuine one. See `identity::dedup_key16`.
    #[must_use]
    pub fn dedup_key(&self) -> DedupKey {
        identity::dedup_key16(self.author_key().as_ref(), &self.id.as_uuid_bytes())
    }

    /// Stamp the [`Shard`] header (which slice of a split body this
    /// message carries) before signing. `None` leaves it an ordinary message.
    #[must_use]
    pub fn shard(mut self, shard: Option<Shard>) -> Self {
        self.shard = shard;
        self
    }

    /// Replace the minted random id before signing. The chat path pins the
    /// frame id to the payload's own logical id so every consumer-visible id
    /// (dedup, poll cursor, echo) *is* the payload's own id; receive validates the two
    /// agree.
    #[must_use]
    pub fn id(mut self, id: MessageId) -> Self {
        self.id = id;
        self
    }

    /// The serialized wire size **without** the `MAX_MESSAGE_SIZE` gate, for
    /// deciding how to split a body. `serialize` is the gated counterpart.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        serde_json::to_vec(&Wire(self)).map_or(usize::MAX, |bytes| bytes.len())
    }

    /// Sign this message with `identity` and return it as a [`Verified`], the proof that its
    /// signature covers these exact bytes. The key is part of the signed bytes, so they are
    /// computed with the key and before the signature exists; consuming-builder style so it composes
    /// in the construction expression (`Message::new_app(..).sign(&id)`).
    #[must_use]
    pub fn sign(mut self, identity: &Identity) -> Verified {
        let key = identity.author_key();
        let signature = identity.sign(&self.canonical_with_key(Some(&key)));
        self.signer = Some(Signer::new(key, signature));
        Verified::new(self, key)
    }

    /// Check the signature of an untrusted message over its canonical bytes. `Ok` is the proof. `Err`
    /// gives the message back unchanged, because it is unsigned or its signature does not verify.
    ///
    /// # Errors
    ///
    /// Returns the message itself, boxed, when [`verify_signature_with`](Self::verify_signature_with) fails.
    pub fn verify(self) -> Result<Verified, Box<Message>> {
        self.verify_canonical().map(|(verified, _)| verified)
    }

    /// [`verify`](Self::verify), and also the canonical bytes that were checked, so the receive path
    /// serializes each inbound frame once. The bytes are computed here from this message, never taken
    /// from the caller, so they are always the bytes the signature covers.
    ///
    /// # Errors
    ///
    /// Returns the message itself when its signature does not verify.
    ///
    /// Outside the crate the canonical bytes cannot be supplied by the caller: `verify_with` is
    /// crate-private, so an edited clone cannot be checked against another message's bytes.
    ///
    /// ```compile_fail,E0624
    /// use habilis_network_protocol::messages::Message;
    ///
    /// const SIGNED: &str = r#"{"v":"17.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"be64c678c6336f65be3817c748ba07478c1723863a070d5a09e62a159e06dc6bc01af49a9a2c3e5a5e25fd90e145b46b87cd803915da07fca9453b7b64b4480a","ext":{}}"#;
    ///
    /// let message = Message::parse(SIGNED.as_bytes()).unwrap();
    /// let canonical = message.canonical_bytes();
    /// let _ = message.verify_with(&canonical);
    /// ```
    pub fn verify_canonical(self) -> Result<(Verified, Vec<u8>), Box<Message>> {
        let canonical = self.canonical_bytes();
        match self.verify_with(&canonical) {
            Ok(verified) => Ok((verified, canonical)),
            Err(message) => Err(message),
        }
    }

    /// The check behind [`verify_canonical`](Self::verify_canonical), against canonical bytes that
    /// the caller computed. Crate-private: outside the crate the bytes must come from the message.
    pub(crate) fn verify_with(self, canonical: &[u8]) -> Result<Verified, Box<Message>> {
        let Some(signed) = self.signer else {
            return Err(Box::new(self));
        };
        if !self.verify_signature_with(canonical) {
            return Err(Box::new(self));
        }
        Ok(Verified::new(self, signed.key()))
    }

    /// Verify the detached signature against the embedded key over the
    /// canonical bytes. `false` if the message is unsigned, the key is not a
    /// point of the curve, or the signature does not match — never panics.
    /// (Whether the key is the *expected* identity for this `author` is the
    /// receiver's TOFU check, separate from this cryptographic check.)
    /// Convenience wrapper that computes the canonical bytes itself. The hot
    /// receive path uses [`verify_signature_with`](Self::verify_signature_with)
    /// to share one `canonical_bytes()` with the content hash; this form is
    /// only the ergonomic one used by tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn verify_signature(&self) -> bool {
        self.verify_signature_with(&self.canonical_bytes())
    }

    /// Like `verify_signature` but against
    /// **precomputed** canonical bytes. The hot receive path computes
    /// `canonical_bytes()` once and reuses it for both this check and the
    /// content hash, instead of re-serializing the message twice per `Msg`.
    /// `canonical` MUST be `self.canonical_bytes()` for the result to be
    /// meaningful.
    #[must_use]
    pub fn verify_signature_with(&self, canonical: &[u8]) -> bool {
        let Some(signed) = &self.signer else {
            return false;
        };
        let Some(public) = signed.key.public_key() else {
            return false;
        };
        identity::verify(&public, canonical, &signed.signature)
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Message {
    /// This message claiming `key` as its author, with a signature that does not verify: for a
    /// test that needs a message with an author key and never checks the signature.
    #[must_use]
    pub fn unverified_key(mut self, key: AuthorKey) -> Self {
        self.signer = Some(Signer::new(key, Signature::from_bytes(&[0u8; 64])));
        self
    }

    /// A fixed test message of `kind` with `body`, from `alice-bot` on mesh `test`.
    #[must_use]
    pub fn fixture(kind: MessageKind, body: &str) -> Self {
        Message {
            version: VERSION.to_string(),
            id: "00000000-0000-0000-0000-000000000001".into(),
            kind,
            mesh: MeshId::from("test"),
            author: "alice-bot".into(),
            timestamp: UnixSecs::from(1_700_000_000),
            body: body.into(),
            signer: None,
            shard: None,
            ext: serde_json::json!({}),
        }
    }
}

/// The `v` of a JSON envelope, for a frame that does not parse as a whole.
fn envelope_version(data: &[u8]) -> Option<String> {
    let envelope: serde_json::Value = serde_json::from_slice(data).ok()?;
    let version = envelope.get("v")?;
    version.as_str().map(str::to_owned)
}
