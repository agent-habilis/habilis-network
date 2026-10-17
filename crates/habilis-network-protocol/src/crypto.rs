//! Seed-derived identities and the gossip topic.
//!
//! Concept split: this module owns the seed-derived **identity** (the
//! rendezvous keypair/ports + the gossip topic id, all computed
//! locally by every joiner). The *role* of actually binding and
//! serving the rendezvous — the **beacon** — lives in
//! `habilis-network`'s beacon.
//!
//! The mesh id token carries a random 32-byte `seed` (see
//! [`crate::mesh`]). Every value the mesh needs is derived
//! from it in memory — no stored address, no file:
//!
//! - the gossip topic (`derive_topic_id`),
//! - a well-known **rendezvous endpoint** keypair: every joiner can
//!   compute `rendezvous_id` locally and bootstrap from it without
//!   ever contacting the creator,
//! - (private meshes only) a deterministic loopback port ladder, since
//!   `presets::Minimal` has no pkarr/DNS lookup to resolve
//!   `rendezvous_id` into an address.
//!
//! All derivations are domain-separated SHA-256 so the topic seed, the
//! rendezvous secret key, and the port can never collide for one
//! `seed`.

use crate::topic::TopicId;
use iroh_base::{EndpointId, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::mesh::MeshName;
use habilis_network_util::consts::{
    PASSWORD_KDF_M_COST_KIB, PASSWORD_KDF_P_COST, PASSWORD_KDF_T_COST,
};

/// Domain-separation prefix mixed into every seed derivation. Bumping
/// this is a wire-incompatible change (peers derive a different
/// topic/identity and never meet).
const DOMAIN: &[u8] = b"habilis-mesh/v2";

/// Domain-separation prefix for the topic-string → seed derivation
/// ([`topic_seed`]). Distinct from [`DOMAIN`] so an arbitrary user string can
/// never reproduce a [`derive_secret`] output. Versioned independently:
/// bumping it makes every string derive a fresh mesh.
const TOPIC_DOMAIN: &[u8] = b"habilis-mesh/topic-seed/v1";

/// Deterministically derive a mesh `seed` from an arbitrary string:
/// `SHA256(TOPIC_DOMAIN ‖ topic.trim())`. Two callers passing the same string
/// (byte-for-byte after trimming surrounding whitespace) land on the same seed
/// — and thus, with the same name + config, the same mesh.
///
/// Trim-only by design: the string is *not* lowercased or URL-normalized. URL
/// paths are case-sensitive and Unicode case-folding is platform-dependent, so
/// either would silently break convergence across machines.
#[must_use]
pub(crate) fn topic_seed(topic: &str) -> Seed {
    let mut hasher = Sha256::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(topic.trim().as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Seed::from_bytes(out)
}

/// Derive an independent 32-byte secret for `label` from the mesh
/// `seed`: `SHA256(DOMAIN ‖ [label_len] ‖ label ‖ seed)`. Each label
/// (`"rendezvous"`, `"port"`, `"topic"`, …) yields a distinct value, so
/// one seed safely feeds every derived identity.
///
/// `label` is length-prefixed so distinct labels can never produce the
/// same byte stream (e.g. `("rd","vseed")` vs `("rdv","seed")`).
///
/// # Panics
/// If `label` exceeds 255 bytes; labels are short internal constants.
#[must_use]
pub(crate) fn derive_secret(seed: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update([
        u8::try_from(label.len()).expect("derive_secret labels are short ASCII constants")
    ]);
    hasher.update(label);
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    out
}

/// The random 32 bytes that a mesh id carries, and the salts of the key
/// derivations. Whoever holds it can join an open mesh, so `Debug` prints no
/// byte; unlike [`SymmetricKey`] it is `Copy` and comparable, because it is
/// public material of the id and not a key. It is not wiped on drop: the id
/// carries these bytes in plain text, so a wipe would protect nothing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seed([u8; 32]);

impl Seed {
    /// Wrap 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive an independent [`SymmetricKey`] for `label`: the hash of the
    /// seed under a domain and the label, held in a wiped buffer.
    ///
    /// # Panics
    /// If `label` exceeds 255 bytes; labels are short internal constants.
    #[must_use]
    pub fn derive(&self, label: &[u8]) -> SymmetricKey {
        SymmetricKey::from_zeroizing(derive_secret(&self.0, label))
    }
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Seed(***)")
    }
}

/// A 32-byte key that encrypts, wraps or derives: the stretched password key,
/// the invite root, and each key derived from them. Its bytes are wiped on
/// drop, `Debug` prints no byte, and the type has no `PartialEq`: compare two
/// with [`ct_eq`] on [`Self::as_bytes`].
#[derive(Clone)]
pub struct SymmetricKey(Zeroizing<[u8; 32]>);

impl SymmetricKey {
    /// Wrap 32 raw bytes. The array passed in is a copy that the caller still
    /// holds: keep it in a [`Zeroizing`] when it is a secret.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Take a buffer that is already wiped on drop, whole, so that no plain
    /// copy of the secret exists on the way in. This is the constructor for a
    /// secret that is already in a [`Zeroizing`] (a derivation, a stretch, bytes
    /// read off a stream). [`Self::from_bytes`] stays for raw input at an edge.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive an independent [`SymmetricKey`] for `label`: the hash of the
    /// key under a domain and the label, held in a wiped buffer.
    ///
    /// # Panics
    /// If `label` exceeds 255 bytes; labels are short internal constants.
    #[must_use]
    pub fn derive(&self, label: &[u8]) -> Self {
        Self::from_zeroizing(derive_secret(&self.0, label))
    }
}

// The only field is a `Zeroizing`.
impl zeroize::ZeroizeOnDrop for SymmetricKey {}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SymmetricKey(***)")
    }
}

/// What every derivation of a mesh keys on: the wire [`Seed`] of an open
/// mesh, or the [`SymmetricKey`] that a password or an invite put in its
/// place. Two types feed one derivation because a mesh has one or the other,
/// never both, and the derivations are the same hash over either.
#[derive(Clone, Copy)]
pub(crate) enum Keying<'a> {
    Wire(&'a Seed),
    Secret(&'a SymmetricKey),
}

impl Keying<'_> {
    fn bytes(&self) -> &[u8; 32] {
        match self {
            Self::Wire(seed) => seed.as_bytes(),
            Self::Secret(key) => key.as_bytes(),
        }
    }
}

/// The shared rendezvous endpoint secret key. Every member that
/// co-hosts the rendezvous binds an iroh endpoint to this key, so the
/// node id is stable and joiner-computable. `SecretKey::from_bytes` is
/// infallible — any 32 bytes is a valid Ed25519 secret.
#[must_use]
pub(crate) fn rendezvous_secret(source: Keying<'_>) -> SecretKey {
    SecretKey::from_bytes(&derive_secret(source.bytes(), b"rendezvous"))
}

/// The well-known rendezvous `EndpointId` (public key of
/// [`rendezvous_secret`]). Bootstrap target for every joiner.
#[must_use]
pub(crate) fn rendezvous_id(source: Keying<'_>) -> EndpointId {
    rendezvous_secret(source).public()
}

/// Number of deterministic loopback ports derived per mesh. A single
/// 2-byte-derived port collides across independent private meshes on
/// one host often enough to matter; a ladder lets the beacon skip a
/// foreign-squatted rung instead of hanging. Claim/probe semantics:
/// see `crate::beacon` module docs. A full collision needs all
/// `RENDEZVOUS_LADDER` rungs simultaneously foreign-held — negligible.
pub(crate) const RENDEZVOUS_LADDER: usize = 8;

/// The deterministic loopback port ladder for a private mesh, in
/// preference order. Mapped into the unprivileged range
/// `1024..=65535`. Derived from one `derive_secret` digest (2 bytes per
/// rung); rungs are near-certainly distinct, and a rare in-ladder dup
/// merely wastes a rung (harmless).
///
/// # Panics
/// Never in practice: the derived port stays within `u16` by construction.
#[must_use]
pub(crate) fn rendezvous_ports(source: Keying<'_>) -> [u16; RENDEZVOUS_LADDER] {
    const LOW: u32 = 1024;
    const SPAN: u32 = 65535 - LOW + 1; // 64512
    let digest = derive_secret(source.bytes(), b"port");
    std::array::from_fn(|index| {
        let raw = u32::from(u16::from_le_bytes([
            digest[2 * index],
            digest[2 * index + 1],
        ]));
        u16::try_from(LOW + (raw % SPAN)).expect("LOW + (_ % SPAN) <= 65535")
    })
}

/// An operator-supplied password. A newtype so a stray `{:?}` in a
/// `tracing` call can never leak the value into a log file that is
/// otherwise safe to share. Its bytes are wiped on drop (best-effort: any
/// `String` reallocation or the CLI prompt buffer it was built from is not
/// tracked), so a retained password does not linger in freed memory.
///
/// Two passwords do not compare with `==`: an equality that stops at the first
/// byte that differs is a timing oracle, and no caller needs one.
///
/// ```compile_fail,E0369
/// use habilis_network_protocol::Password;
///
/// let left = Password::new("hunter2".to_owned());
/// let right = Password::new("hunter2".to_owned());
/// let _ = left == right;
/// ```
#[derive(Clone)]
pub struct Password(String);

impl Password {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("***")
    }
}

impl std::fmt::Display for Password {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("***")
    }
}

/// Argon2id-stretch a password into 32 bytes of keying material. The salt is
/// `derive_secret(salt_seed, label)` — keyed by the mesh's random seed and
/// domain-separated by `label`, so the stretch shares no salt with any other
/// `derive_secret` use and no rainbow table carries over. Cost params are a
/// wire contract (`util::consts`); ~50-100ms by design, paid once at
/// create/join.
fn stretch_password(
    password: &Password,
    salt_seed: &[u8; 32],
    label: &[u8],
) -> Zeroizing<[u8; 32]> {
    let params = argon2::Params::new(
        PASSWORD_KDF_M_COST_KIB,
        PASSWORD_KDF_T_COST,
        PASSWORD_KDF_P_COST,
        Some(32),
    )
    .expect("compile-time KDF params are valid");
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = derive_secret(salt_seed, label);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_str().as_bytes(), &*salt, &mut *out)
        .expect("32-byte salt and output are valid argon2 lengths");
    out
}

/// The stretched key for a passworded mesh: every derivation (topic,
/// rendezvous, port ladder) switches from the wire seed onto this value, so
/// holding the mesh id without the password computes nothing reachable.
#[must_use]
pub(crate) fn stretch_mesh_password(password: &Password, seed: &Seed) -> SymmetricKey {
    SymmetricKey::from_zeroizing(stretch_password(password, seed.as_bytes(), b"password"))
}

/// The 32-byte key that wraps an invite ticket's root secret when the mesh's
/// creator minted it with a password. Argon2id-stretched from the password,
/// salted by the mesh's public identity salt (the wire seed of an invite-only
/// mesh — public, in the hash, so both minter and redeemer derive the same key
/// without already holding the root). Domain-separated from the mesh-password
/// and ticket labels so no stretch is shared. The wrapped root is
/// `seal_symmetric`ed under this key, so a redeemer without the password can't
/// recover it — bullet: a leaked invite still needs the password.
#[must_use]
pub(crate) fn invite_wrap_key(password: &Password, salt: &Seed) -> SymmetricKey {
    SymmetricKey::from_zeroizing(stretch_password(
        password,
        salt.as_bytes(),
        b"invite-ticket",
    ))
}

/// Length of the password verifier carried in a passworded mesh hash.
/// 16 bytes: only guess-checking matters (collisions are irrelevant), and
/// every extra byte grows the shared id string.
pub(crate) const PASSWORD_VERIFIER_LEN: usize = 16;

/// The one-way check value a passworded mesh hash carries so `join` can
/// verify a candidate password locally. Derived from the *stretched* key
/// through a second one-way step, so the verifier reveals neither the
/// password nor the effective seed.
#[must_use]
pub(crate) fn password_verifier(key: &SymmetricKey) -> [u8; PASSWORD_VERIFIER_LEN] {
    let digest = derive_secret(key.as_bytes(), b"password-verify");
    let mut out = [0u8; PASSWORD_VERIFIER_LEN];
    out.copy_from_slice(&digest[..PASSWORD_VERIFIER_LEN]);
    out
}

/// The 32-byte bearer secret of a ticket. Whoever holds it can redeem the
/// ticket, so `Debug` prints no byte, and the type has no `PartialEq`: compare
/// two with [`ct_eq`] on [`Self::as_bytes`], which does not stop at the first
/// byte that differs. Its bytes are wiped on drop (best-effort: a copy that
/// a caller made from [`Self::as_bytes`] is not tracked).
///
/// A raw array is not a secret, so a swap with another 32-byte value does not
/// compile:
///
/// ```compile_fail,E0308
/// use habilis_network_protocol::TicketAuth;
///
/// let raw = [0u8; 32];
/// let _ = TicketAuth::blob(&raw, None);
/// ```
#[derive(Clone)]
pub struct TicketSecret(Zeroizing<[u8; 32]>);

impl TicketSecret {
    /// Wrap 32 raw bytes. The array passed in is a copy that the caller still
    /// holds: keep it in a [`Zeroizing`] when it is a secret.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Take a buffer that is already wiped on drop, whole, so that no plain
    /// copy of the secret exists on the way in. This is the constructor for a
    /// secret that is already in a [`Zeroizing`] (a stretch, a salt or a token
    /// read off a stream). [`Self::from_bytes`] stays for raw input at an edge.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// The only field is a `Zeroizing`.
impl zeroize::ZeroizeOnDrop for TicketSecret {}

impl std::fmt::Debug for TicketSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TicketSecret(***)")
    }
}

/// The 32 bytes a bridge consumer presents on connect and a producer
/// expects: the raw ticket secret (no password), or its Argon2id stretch
/// salted by the secret (passworded) — same wire size either way, so a
/// directory ad (which carries the secret) is not enough to redeem a
/// passworded ticket.
#[derive(Clone)]
pub struct TicketAuth {
    pub token: TicketSecret,
    pub password_protected: bool,
}

impl TicketAuth {
    /// The token for a **blob** ticket. `label` is what keeps ticket kinds apart:
    /// two kinds sharing a secret must never derive the same passworded token, so
    /// an application minting its own ticket kind passes its own label through
    /// [`Self::derive`] rather than reusing this one.
    #[must_use]
    pub fn blob(secret: &TicketSecret, password: Option<&Password>) -> Self {
        Self::derive(secret, password, b"blob-ticket")
    }

    /// Derive a ticket token under a caller-chosen `label`.
    ///
    /// The label is a **byte-domain**: it is stretched into the token, so it
    /// reaches the wire and is fixed for the life of that ticket kind. Pick one
    /// distinct per kind; reusing another kind's label collapses the separation
    /// [`Self::blob`] documents.
    #[must_use]
    pub fn derive(secret: &TicketSecret, password: Option<&Password>, label: &[u8]) -> Self {
        match password {
            Some(password) => Self {
                token: TicketSecret::from_zeroizing(stretch_password(
                    password,
                    secret.as_bytes(),
                    label,
                )),
                password_protected: true,
            },
            None => Self {
                token: secret.clone(),
                password_protected: false,
            },
        }
    }
}

impl std::fmt::Debug for TicketAuth {
    // The token is the live credential — redact it, keep the flag.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TicketAuth")
            .field("token", &"***")
            .field("password_protected", &self.password_protected)
            .finish()
    }
}

/// Constant-time equality for 32-byte auth tokens: XOR-fold the full pair so
/// the cost never depends on where the first mismatch lies (a short-circuit
/// `==` is a timing oracle on the secret).
#[must_use]
pub fn ct_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (lhs, rhs)| acc | (lhs ^ rhs))
        == 0
}

/// Derive the gossip `TopicId` from the mesh `seed` + name + config. The
/// seed is the random 32 bytes carried in the mesh id, so the topic
/// is **creator-independent**: it never depends on any node's ephemeral
/// key and survives the creator's death. The name and the canonical
/// config bytes are each length-prefixed before hashing so distinct
/// fields can never collide across the boundary.
///
/// The seed is first run through the domain-separated [`derive_secret`]
/// so a `seed` can never produce the same 32 bytes for the topic and for
/// the rendezvous key. Binding the name *and* the config means a forged
/// token (same seed, swapped name or tampered lookups)
/// hashes to a different topic and the joiner finds no peers — so every
/// member of a mesh provably shares the same config.
///
/// # Panics
/// If `config_bytes` exceeds 65535 bytes; a mesh config encodes well within that.
#[must_use]
pub(crate) fn derive_topic_id(source: Keying<'_>, name: &MeshName, config_bytes: &[u8]) -> TopicId {
    let mut hasher = Sha256::new();
    hasher.update(derive_secret(source.bytes(), b"topic"));
    hasher.update([name.len_u8()]);
    hasher.update(name.as_bytes());
    let config_len =
        u16::try_from(config_bytes.len()).expect("mesh config encodes well within a u16 length");
    hasher.update(config_len.to_le_bytes());
    hasher.update(config_bytes);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    TopicId::from_bytes(bytes)
}

#[cfg(test)]
mod derive_secret_tests {
    use super::{
        Keying, RENDEZVOUS_LADDER, Seed, derive_secret, rendezvous_id, rendezvous_ports,
        rendezvous_secret, topic_seed,
    };
    use habilis_network_test_tracing::test;

    const SEED_A: [u8; 32] = [7u8; 32];
    const SEED_B: [u8; 32] = [9u8; 32];

    #[test]
    fn derive_secret_is_deterministic() {
        assert_eq!(
            derive_secret(&SEED_A, b"rendezvous"),
            derive_secret(&SEED_A, b"rendezvous")
        );
    }

    #[test]
    fn derive_hashes_the_same_bytes_as_derive_secret() {
        use super::{Seed, SymmetricKey};
        let seed = Seed::from_bytes(SEED_A);
        assert_eq!(
            seed.derive(b"state-doc").as_bytes(),
            &*derive_secret(&SEED_A, b"state-doc")
        );
        // A key derives from the same bytes the way a seed does.
        let key = SymmetricKey::from_bytes(SEED_A);
        assert_eq!(
            key.derive(b"broadcast").as_bytes(),
            seed.derive(b"broadcast").as_bytes()
        );
    }

    #[test]
    fn a_seed_and_a_symmetric_key_print_no_byte() {
        use super::{Seed, SymmetricKey};
        assert_eq!(format!("{:?}", Seed::from_bytes(SEED_A)), "Seed(***)");
        assert_eq!(
            format!("{:?}", SymmetricKey::from_bytes(SEED_A)),
            "SymmetricKey(***)"
        );
    }

    #[test]
    fn derive_secret_domain_separates_by_label() {
        assert_ne!(
            derive_secret(&SEED_A, b"rendezvous"),
            derive_secret(&SEED_A, b"port")
        );
    }

    #[test]
    fn derive_secret_domain_separates_by_seed() {
        assert_ne!(
            derive_secret(&SEED_A, b"rendezvous"),
            derive_secret(&SEED_B, b"rendezvous")
        );
    }

    #[test]
    fn label_length_prefix_prevents_collision() {
        // Without the length prefix ("rd"+"vx") and ("rdv"+"x") would
        // hash the same stream. The prefix must keep them distinct.
        assert_ne!(
            derive_secret(&SEED_A, b"rdvx"),
            derive_secret(&SEED_A, b"rdv")
        );
    }

    #[test]
    fn rendezvous_id_is_stable_for_a_seed() {
        assert_eq!(
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_A))),
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_A)))
        );
        assert_ne!(
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_A))),
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_B)))
        );
    }

    #[test]
    fn rendezvous_id_matches_secret_public() {
        assert_eq!(
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_A))),
            rendezvous_secret(Keying::Wire(&Seed::from_bytes(SEED_A))).public()
        );
    }

    #[test]
    fn rendezvous_ports_are_in_range_stable_and_seed_specific() {
        let ladder = rendezvous_ports(Keying::Wire(&Seed::from_bytes(SEED_A)));
        assert_eq!(ladder.len(), RENDEZVOUS_LADDER);
        assert!(ladder.iter().all(|&port| port >= 1024));
        assert_eq!(
            ladder,
            rendezvous_ports(Keying::Wire(&Seed::from_bytes(SEED_A))),
            "stable for a seed"
        );
        assert_ne!(
            rendezvous_ports(Keying::Wire(&Seed::from_bytes(SEED_A))),
            rendezvous_ports(Keying::Wire(&Seed::from_bytes(SEED_B))),
            "different seeds get different ladders"
        );
    }

    #[test]
    fn topic_seed_is_deterministic() {
        assert_eq!(topic_seed("agent-habilis"), topic_seed("agent-habilis"));
    }

    #[test]
    fn topic_seed_differs_by_string() {
        assert_ne!(topic_seed("alpha"), topic_seed("beta"));
    }

    #[test]
    fn topic_seed_trims_surrounding_whitespace() {
        assert_eq!(topic_seed("  x\n"), topic_seed("x"));
    }

    #[test]
    fn topic_seed_is_case_sensitive() {
        assert_ne!(topic_seed("Repo"), topic_seed("repo"));
    }

    #[test]
    fn topic_seed_domain_separated_from_derive_secret() {
        // A topic seed lives under TOPIC_DOMAIN; it must not coincide with a
        // labelled derivation off some other seed for any plausible collision.
        assert_ne!(
            topic_seed("rendezvous").as_bytes(),
            &*derive_secret(&SEED_A, b"rendezvous")
        );
    }

    #[test]
    fn rendezvous_ports_rungs_are_near_certainly_distinct() {
        let ladder = rendezvous_ports(Keying::Wire(&Seed::from_bytes(SEED_A)));
        let unique: std::collections::HashSet<_> = ladder.iter().collect();
        // A rare in-ladder dup is harmless, but the fixed test seed
        // must not regress into a degenerate all-same ladder.
        assert!(unique.len() >= RENDEZVOUS_LADDER - 1);
    }
}

#[cfg(test)]
mod password_tests {
    use super::{Password, Seed, derive_secret, password_verifier, stretch_mesh_password};
    use habilis_network_test_tracing::test;

    const SEED_A: [u8; 32] = [7u8; 32];
    const SEED_B: [u8; 32] = [9u8; 32];

    fn pw(text: &str) -> Password {
        Password::new(text.to_owned())
    }

    #[test]
    fn stretch_is_deterministic_and_separates_by_password_and_seed() {
        let seed_a = Seed::from_bytes(SEED_A);
        let seed_b = Seed::from_bytes(SEED_B);
        let key = stretch_mesh_password(&pw("hunter2"), &seed_a);
        let same = stretch_mesh_password(&pw("hunter2"), &seed_a);
        assert_eq!(key.as_bytes(), same.as_bytes());
        let other_password = stretch_mesh_password(&pw("hunter3"), &seed_a);
        assert_ne!(key.as_bytes(), other_password.as_bytes());
        let other_seed = stretch_mesh_password(&pw("hunter2"), &seed_b);
        assert_ne!(key.as_bytes(), other_seed.as_bytes());
    }

    #[test]
    fn verifier_is_not_the_key_and_not_a_topic_or_rendezvous_input() {
        let key = stretch_mesh_password(&pw("hunter2"), &Seed::from_bytes(SEED_A));
        let verifier = password_verifier(&key);
        assert_ne!(
            &key.as_bytes()[..16],
            &verifier[..],
            "verifier must be one-way"
        );
        assert_ne!(
            &derive_secret(key.as_bytes(), b"topic")[..16],
            &verifier[..],
            "verifier must not collide with a derivation label"
        );
    }

    #[test]
    fn password_never_leaks_through_debug_or_display() {
        let secret = pw("hunter2");
        assert_eq!(format!("{secret:?}"), "***");
        assert_eq!(format!("{secret}"), "***");
    }

    #[test]
    fn channel_keys_are_domain_separated() {
        // The state/meta/broadcast content keys are all derived from the same
        // stretched mesh key but must never collide.
        let mesh_key = stretch_mesh_password(&pw("hunter2"), &Seed::from_bytes(SEED_A));
        let state = derive_secret(mesh_key.as_bytes(), b"state-doc");
        let meta = derive_secret(mesh_key.as_bytes(), b"meta-doc");
        let broadcast = derive_secret(mesh_key.as_bytes(), b"broadcast");
        assert_ne!(state, meta);
        assert_ne!(state, broadcast);
        assert_ne!(meta, broadcast);
    }

    /// The stretched token for a fixed secret, password and label. A change
    /// here breaks each passworded ticket that exists outside the code.
    #[test]
    fn derive_token_matches_the_golden_bytes() {
        use super::{TicketAuth, TicketSecret};
        let secret = TicketSecret::from_bytes([3u8; 32]);
        let auth = TicketAuth::derive(&secret, Some(&pw("hunter2")), b"blob-ticket");
        assert!(auth.password_protected);
        assert_eq!(
            hex(auth.token.as_bytes()),
            "824798ec30b0b968447a543d55adf59dd4a8a8a2218a9833409ce313edd258cf"
        );
    }

    /// The stretched password key is secret material, so the stretch hands it on in
    /// a wiped buffer and each secret type takes that buffer whole: no plain
    /// `[u8; 32]` copy of it exists on the way. A wipe cannot be observed at run
    /// time (`unsafe_code` is denied), so the types carry the test: it does not
    /// compile if `stretch_password` returns a bare array, or if a secret type has
    /// no constructor for a wiped buffer.
    #[test]
    fn the_stretched_key_moves_from_its_wiped_buffer_into_a_secret_type() {
        use super::{SymmetricKey, TicketSecret, stretch_password};
        use zeroize::Zeroizing;

        let stretched: Zeroizing<[u8; 32]> = stretch_password(&pw("hunter2"), &SEED_A, b"password");
        assert_ne!(*stretched, [0u8; 32], "the stretch fills the buffer");
        let key = SymmetricKey::from_zeroizing(stretched.clone());
        let secret = TicketSecret::from_zeroizing(stretched.clone());
        assert_eq!(key.as_bytes(), &*stretched);
        assert_eq!(secret.as_bytes(), &*stretched);
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn ticket_secret_debug_never_prints_a_byte() {
        use super::TicketSecret;
        let secret = TicketSecret::from_bytes([9u8; 32]);
        assert_eq!(format!("{secret:?}"), "TicketSecret(***)");
        assert_eq!(secret.as_bytes(), &[9u8; 32]);
    }

    // `unsafe_code` is denied, so a test cannot read the freed bytes: the types
    // carry the test. The `ZeroizeOnDrop` marker on a secret type is a promise
    // and proves nothing by itself, so the test pins the field: it holds its
    // bytes in a `Zeroizing`, which wipes them on drop. This does not compile if
    // a field becomes a bare array.
    #[test]
    fn the_secret_types_hold_their_bytes_in_a_zeroizing_buffer() {
        use zeroize::Zeroizing;

        let _: &Zeroizing<[u8; 32]> = &super::TicketSecret::from_bytes([0; 32]).0;
        let _: &Zeroizing<[u8; 32]> = &super::SymmetricKey::from_bytes([0; 32]).0;
    }

    #[test]
    fn ticket_tokens_are_domain_separated_by_label() {
        use super::{TicketAuth, TicketSecret};
        let secret = TicketSecret::from_bytes([3u8; 32]);
        let password = pw("hunter2");
        let blob = TicketAuth::blob(&secret, Some(&password)).token;
        // Stands in for any application-minted kind (the application's bridge passes
        // its own label); only the label differs.
        let other = TicketAuth::derive(&secret, Some(&password), b"other-ticket").token;
        assert_ne!(
            blob.as_bytes(),
            other.as_bytes(),
            "the same password+secret must yield different tokens per ticket kind"
        );
        // Without a password both are the raw secret (no stretch, no label).
        assert_eq!(TicketAuth::blob(&secret, None).token.as_bytes(), &[3u8; 32]);
        assert_eq!(
            TicketAuth::derive(&secret, None, b"other-ticket")
                .token
                .as_bytes(),
            &[3u8; 32]
        );
    }
}

#[cfg(test)]
mod topic_tests {
    use super::{Keying, MeshName, Seed, derive_topic_id};
    use habilis_network_test_tracing::test;

    fn name(text: &str) -> MeshName {
        MeshName::new(text).unwrap()
    }

    const CFG_A: &[u8] = &[60, 0, 0]; // rate 60, lookups loopback
    const CFG_B: &[u8] = &[0, 0, 0b0111]; // rate 0, mdns+dht+pinned relay

    #[test]
    fn deterministic_for_same_input() {
        let seed = [42u8; 32];
        let first = derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("team"), CFG_A);
        let second = derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("team"), CFG_A);
        assert_eq!(first, second);
    }

    #[test]
    fn different_seeds_produce_different_topics() {
        let seed_a = [1u8; 32];
        let seed_b = [42u8; 32];
        assert_ne!(
            derive_topic_id(
                Keying::Wire(&Seed::from_bytes(seed_a)),
                &name("team"),
                CFG_A
            ),
            derive_topic_id(
                Keying::Wire(&Seed::from_bytes(seed_b)),
                &name("team"),
                CFG_A
            )
        );
    }

    #[test]
    fn different_names_produce_different_topics() {
        let seed = [1u8; 32];
        assert_ne!(
            derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("alpha"), CFG_A),
            derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("beta"), CFG_A)
        );
    }

    #[test]
    fn different_config_produces_different_topics() {
        let seed = [1u8; 32];
        assert_ne!(
            derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("team"), CFG_A),
            derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("team"), CFG_B),
            "config is mixed into the topic, so it cannot diverge across members"
        );
    }
}

/// Golden outputs of the mesh derivations, for fixed inputs. They equal what
/// the code before the newtype refactor (795c4f88) gives, so they prove that
/// the refactor moved no derived byte. Change a value only on purpose, as a
/// named wire decision.
#[cfg(test)]
mod golden_tests {
    use super::{
        Keying, Password, Seed, SymmetricKey, derive_topic_id, invite_wrap_key, password_verifier,
        rendezvous_id, rendezvous_ports, stretch_mesh_password,
    };
    use crate::mesh::MeshName;
    use habilis_network_test_tracing::test;

    const SEED: [u8; 32] = [7u8; 32];
    const ROOT: [u8; 32] = [5u8; 32];

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn golden_rendezvous_of_a_wire_seed() {
        let seed = Seed::from_bytes(SEED);
        assert_eq!(
            rendezvous_id(Keying::Wire(&seed)).to_string(),
            "f7172ec3cf80783eb9972177ba2ac384d4b30612c0892ec0fa8d4ee552190469"
        );
        assert_eq!(
            rendezvous_ports(Keying::Wire(&seed)),
            [5931, 48242, 42909, 64096, 38056, 45299, 54555, 32776]
        );
    }

    #[test]
    fn golden_password_stretch_and_verifier() {
        let seed = Seed::from_bytes(SEED);
        let password = Password::new("hunter2".to_owned());
        let key = stretch_mesh_password(&password, &seed);
        assert_eq!(
            hex(key.as_bytes()),
            "2ac1fef982a96d1f5051cbe48638f57d8484c22d159fff7c6e5459a8d6de94ba"
        );
        assert_eq!(
            hex(&password_verifier(&key)),
            "58756a1b4f3ce544517606c0abccdf8e"
        );
        assert_eq!(
            hex(invite_wrap_key(&password, &seed).as_bytes()),
            "541efc2dd477ce08854291e7da56e3297d537044170c90f78373e84960ad58ab"
        );
    }

    #[test]
    fn golden_derivations_keyed_by_a_secret() {
        let root = SymmetricKey::from_bytes(ROOT);
        let name = MeshName::new("test").unwrap();
        assert_eq!(
            format!(
                "{:?}",
                derive_topic_id(Keying::Secret(&root), &name, b"fixed-config-bytes")
            ),
            "TopicId(d4137216ab43c3277fa07d4a2abb128fd8b69a4dbfac3ddd1fecf27f8ea18107)"
        );
        assert_eq!(
            rendezvous_id(Keying::Secret(&root)).to_string(),
            "6996293bba871f0c8b7adacb92463b5924a26c6555bcb0ebbf87f605be01bf50"
        );
        assert_eq!(
            rendezvous_ports(Keying::Secret(&root)),
            [64619, 51235, 41400, 1621, 17345, 37799, 35331, 60865]
        );
    }
}
