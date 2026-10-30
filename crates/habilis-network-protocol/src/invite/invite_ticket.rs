//! Wire: bare `Base58Check`(`version ‖ kind ‖ payload`) with a `SHA256d`
//! checksum. The `kind` byte tells invite tickets apart from blob / bridge
//! tickets; mesh ids share the bare-base58 shape but have a different payload,
//! so they fail invite decode on the kind/structure check.
//!
//! Payload: `expiry(8, LE i64) ‖ flags(1) ‖ sig(64) ‖ hash_len(2, LE u16) ‖
//! mesh_hash(UTF-8) ‖ root_field`. Bit 0 of `flags` marks a password-protected
//! invite (the root is `seal_symmetric`-wrapped under a password-derived key);
//! otherwise `root_field` is the 32-byte root in the clear. The issuer signs the
//! *plaintext* root, so a redeemer decrypts first, then verifies.

use std::fmt;
use std::time::Duration;

use iroh_base::{PublicKey, Signature};

use super::InviteError;
use crate::base58check::{self, take_array};
use crate::crypto::{self, Password, SymmetricKey};
use crate::meshes::{LockedMesh, Mesh};
use crate::{identity, seal_error};
use habilis_network_util::unix_secs::UnixSecs;
use zeroize::Zeroizing;

use std::str;
/// Framing version. Bumped only on a breaking framing change.
const VERSION: u8 = 2;

/// Ticket-kind discriminant. Distinct from the application's bridge ticket (`2`) and the
/// blob ticket (`1`) so a wrong-kind token is rejected on decode.
const KIND: u8 = 3;

/// Bit 0 of the flags byte: the password flag.
const PASSWORD_BIT: u8 = 0b0000_0001;

/// Domain-separation prefix on the issuer-signed bytes, so an invite signature
/// can never be replayed as any other Ed25519 signature in the system.
const SIG_DOMAIN: &[u8] = b"habilis-mesh/invite/v1";

/// A decoded invite ticket. Parsing (`decode`) is structural only — verifying
/// the issuer signature, checking expiry, and unwrapping the root all happen in
/// [`Self::redeem`], which needs the password for a protected invite.
///
/// # Examples
///
/// Text that is not an invite ticket does not decode.
///
/// ```
/// use habilis_network_protocol::invite::InviteTicket;
///
/// let result = InviteTicket::decode("not a ticket");
/// assert!(result.is_err());
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct InviteTicket {
    mesh_hash: String,
    /// The point after which the invite is refused, or [`UnixSecs::ZERO`] for no expiry.
    expiry: UnixSecs,
    password: bool,
    signature: [u8; 64],
    /// The 32-byte root in the clear, or its `seal_symmetric` blob when
    /// password-protected.
    root_field: Vec<u8>,
}

impl fmt::Debug for InviteTicket {
    // Redact the root — for a passwordless invite it is the mesh's join key in
    // the clear, so a stray `{:?}` must never leak it.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("InviteTicket");
        debug
            .field("mesh_hash", &self.mesh_hash)
            .field("expiry", &self.expiry)
            .field("password", &self.password)
            .field("root_field", &"***");
        debug.finish_non_exhaustive()
    }
}

/// The exact bytes the issuer signs / a redeemer verifies: a domain tag, the
/// published mesh hash, the plaintext root, and the expiry.
fn signing_bytes(mesh_hash: &str, root: &SymmetricKey, expiry: UnixSecs) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIG_DOMAIN.len() + mesh_hash.len() + 32 + 8);
    bytes.extend_from_slice(SIG_DOMAIN);
    bytes.extend_from_slice(mesh_hash.as_bytes());
    bytes.extend_from_slice(root.as_bytes());
    bytes.extend_from_slice(&expiry.to_le_bytes());
    bytes
}

/// Mint an invite for `mesh`. `ttl` `None`/`Some(Duration::ZERO)` ⇒ no expiry,
/// else the invite expires `ttl` from now. The expiry is a whole second, so a ttl that
/// has a part of a second rounds up: the invite never lives shorter than asked, and a
/// ttl of one millisecond is not already spent. `password` (the mesh's, if it
/// has one) wraps the root so a scraped invite still needs it.
///
/// # Errors
/// # Errors
/// [`InviteError::Refused`] when this session is not the creator (holds no issuer
/// key), or when `mesh` is not invite-only.
///
/// # Examples
///
/// A mesh that is not invite-only refuses to mint an invite.
///
/// ```
/// use habilis_network_protocol::invite::{InviteError, mint};
///
/// use habilis_network_protocol::{Mesh, MeshConfig, MeshName, Seed};
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
/// let mesh = Mesh::try_new(Seed::new([4u8; 32]), MeshName::try_new("chat").expect("a name"), config)
///     .expect("a mesh");
///
/// let error = mint(&mesh, None, None).unwrap_err();
/// assert!(matches!(error, InviteError::Refused(_)));
/// ```
pub fn mint(
    mesh: &Mesh,
    ttl: Option<Duration>,
    password: Option<&Password>,
) -> Result<String, InviteError> {
    let issuer_secret = mesh.issuer_secret().ok_or(InviteError::Refused(
        "only the creator can mint invites (this session holds no issuer key)",
    ))?;
    let root = mesh
        .invite_key()
        .ok_or(InviteError::Refused("not an invite-only mesh"))?;
    let mesh_hash = mesh.to_string();
    let expiry: UnixSecs = match ttl {
        None => UnixSecs::ZERO,
        Some(ttl) if ttl.is_zero() => UnixSecs::ZERO,
        Some(ttl) => {
            let whole_seconds = ttl
                .as_secs()
                .saturating_add(u64::from(ttl.subsec_nanos() > 0));
            UnixSecs::now() + Duration::from_secs(whole_seconds)
        }
    };
    let signature = issuer_secret.sign(&signing_bytes(&mesh_hash, root, expiry));
    let root_field = match password {
        Some(password) => {
            let wrap_key = crypto::invite_wrap_key(password, mesh.wrap_salt());
            seal_error::seal_symmetric(&wrap_key, root.as_bytes())
        }
        None => root.as_bytes().to_vec(),
    };
    let ticket = InviteTicket {
        mesh_hash,
        expiry,
        password: password.is_some(),
        signature: signature.to_bytes(),
        root_field,
    };
    Ok(ticket.encode())
}

impl InviteTicket {
    /// Whether this invite is password-protected (the redeemer must supply the
    /// mesh password to unwrap the root).
    #[must_use]
    pub fn requires_password(&self) -> bool {
        self.password
    }

    fn encode(&self) -> String {
        let hash_bytes = self.mesh_hash.as_bytes();
        let hash_len = u16::try_from(hash_bytes.len()).expect("mesh hash fits in a u16 length");
        let mut payload =
            Vec::with_capacity(8 + 1 + 64 + 2 + hash_bytes.len() + self.root_field.len());
        payload.extend_from_slice(&self.expiry.to_le_bytes());
        payload.push(if self.password { PASSWORD_BIT } else { 0 });
        payload.extend_from_slice(&self.signature);
        payload.extend_from_slice(&hash_len.to_le_bytes());
        payload.extend_from_slice(hash_bytes);
        payload.extend_from_slice(&self.root_field);
        let mut framed = Vec::with_capacity(2 + payload.len());
        framed.push(VERSION);
        framed.push(KIND);
        framed.extend_from_slice(&payload);
        base58check::encode(&framed)
    }

    /// Decode a bare base58 invite ticket — structural parse only.
    ///
    /// # Errors
    /// # Errors
    /// [`InviteError::Base58`] for a bad Base58 text or checksum, [`InviteError::Truncated`]
    /// when the ticket ends early, [`InviteError::UnsupportedVersion`] for another
    /// version, [`InviteError::Refused`] for the wrong kind, and [`InviteError::Source`]
    /// for a field that does not decode.
    pub fn decode(token: &str) -> Result<Self, InviteError> {
        let framed =
            base58check::decode(token.trim(), "invite ticket").map_err(InviteError::Base58)?;
        let version = *framed
            .first()
            .ok_or(InviteError::Truncated("ticket too short"))?;
        if version != VERSION {
            return Err(InviteError::UnsupportedVersion(format!(
                "unsupported invite ticket version {version}, this build reads version {VERSION}: \
                 upgrade, then ask for a new invite (a ticket names a mesh id, and mesh ids changed)"
            )));
        }
        let kind = *framed
            .get(1)
            .ok_or(InviteError::Truncated("ticket too short"))?;
        if kind != KIND {
            return Err(InviteError::Refused(
                "not an invite ticket: wrong ticket kind",
            ));
        }
        let payload = &framed[2..];
        let mut position = 0;
        let expiry = UnixSecs::from(
            take_array::<8>(payload, &mut position)
                .ok_or(InviteError::Truncated("missing expiry"))?,
        );
        let flags = *payload
            .get(position)
            .ok_or(InviteError::Truncated("missing flags"))?;
        position += 1;
        let password = flags & PASSWORD_BIT != 0;
        let signature = take_array::<64>(payload, &mut position)
            .ok_or(InviteError::Truncated("missing signature"))?;
        let hash_len = usize::from(u16::from_le_bytes(
            take_array::<2>(payload, &mut position)
                .ok_or(InviteError::Truncated("missing hash length"))?,
        ));
        let hash_end = position
            .checked_add(hash_len)
            .ok_or(InviteError::Truncated("hash length overflow"))?;
        let hash_bytes = payload
            .get(position..hash_end)
            .ok_or(InviteError::Truncated("truncated mesh hash"))?;
        position = hash_end;
        let mesh_hash = str::from_utf8(hash_bytes)
            .map_err(InviteError::with_step("invalid mesh hash utf-8"))?
            .to_owned();
        let root_field = payload
            .get(position..)
            .ok_or(InviteError::Truncated("missing root"))?
            .to_vec();
        Ok(Self {
            mesh_hash,
            expiry,
            password,
            signature,
            root_field,
        })
    }

    /// Redeem the invite: reconstruct the mesh, unwrap the root (needs the
    /// password iff protected), verify the creator's signature, and reject an
    /// expired invite. Returns a mesh ready to join.
    ///
    /// # Errors
    /// # Errors
    /// [`InviteError::Source`] for a malformed embedded hash or a bad issuer key,
    /// [`InviteError::Refused`] for a missing or unexpected password, an invalid issuer
    /// signature (not creator-minted or tampered), or an expired invite.
    pub fn redeem(&self, password: Option<&Password>) -> Result<Mesh, InviteError> {
        let locked: LockedMesh = self
            .mesh_hash
            .parse()
            .map_err(InviteError::with_step("invite carries an invalid mesh id"))?;
        let issuer_pubkey = *locked
            .issuer_pubkey()
            .ok_or(InviteError::Refused("invite is for a non-invite-only mesh"))?;
        let root = self.unwrap_root(&locked, password)?;
        let pubkey = PublicKey::from_bytes(&issuer_pubkey)
            .map_err(InviteError::with_step("invalid issuer public key"))?;
        let signature = Signature::from_bytes(&self.signature);
        if !identity::verify(
            &pubkey,
            &signing_bytes(&self.mesh_hash, &root, self.expiry),
            &signature,
        ) {
            return Err(InviteError::Refused(
                "invalid invite signature — not creator-minted, or tampered",
            ));
        }
        if self.expiry != UnixSecs::ZERO && UnixSecs::now() >= self.expiry {
            return Err(InviteError::Refused("this invite has expired"));
        }
        Ok(locked.redeem_with(root))
    }

    fn unwrap_root(
        &self,
        mesh: &LockedMesh,
        password: Option<&Password>,
    ) -> Result<SymmetricKey, InviteError> {
        let raw = match (self.password, password) {
            (true, Some(password)) => {
                let wrap_key = crypto::invite_wrap_key(password, mesh.wrap_salt());
                seal_error::open_symmetric(&wrap_key, &self.root_field)
                    .map_err(InviteError::with_step("wrong password or corrupt invite"))?
            }
            (true, None) => {
                return Err(InviteError::Refused(
                    "this invite is password-protected — pass --password",
                ));
            }
            (false, Some(_)) => {
                return Err(InviteError::Refused(
                    "this invite has no password — drop --password",
                ));
            }
            (false, None) => self.root_field.clone(),
        };
        let raw = Zeroizing::new(raw);
        let mut bytes = Zeroizing::new([0u8; 32]);
        if raw.len() != bytes.len() {
            return Err(InviteError::Refused("invite root is not 32 bytes"));
        }
        bytes.copy_from_slice(&raw);
        Ok(SymmetricKey::from(bytes))
    }
}

/// Read `N` bytes at `*pos` into a fixed array, advancing `*pos`. `None` if the
/// slice is too short.
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{InviteTicket, mint, signing_bytes};
    use crate::crypto::{Password, Seed};
    use crate::meshes::{Mesh, MeshConfig, MeshName};
    use habilis_network_util::unix_secs::UnixSecs;
    use iroh_base::SecretKey;

    use crate::base58check;
    fn pw(text: &str) -> Password {
        Password::new(text.to_owned())
    }

    // A ticket names a mesh id, and mesh ids changed with version 2 of the id: an
    // old ticket must tell the member to upgrade, not fail as a malformed token.
    #[test]
    fn a_ticket_of_version_1_fails_with_the_upgrade_text() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        let mut framed = base58check::decode(&minted(&mesh, None, None).encode(), "invite ticket")
            .expect("a minted ticket decodes");
        framed[0] = 1;
        let old = base58check::encode(&framed);
        let error = InviteTicket::decode(&old).expect_err("a version 1 ticket is refused");
        assert!(error.to_string().contains("upgrade"), "{error}");
    }

    /// A fresh invite-only mesh on the creator (holds the issuer key + root).
    fn creator() -> Mesh {
        let mut mesh = Mesh::try_new(
            Seed::new([1u8; 32]),
            MeshName::try_new("t").expect("`MeshName::try_new(\"t\")` yields a value in this test's fixture"),
            MeshConfig::loopback(),
        )
        .expect("`Mesh::try_new( Seed::new([1u8; 32]), MeshName::try_new(\"t\").expect(\"`MeshName::try_new(\\\"t\\\")` yields a value in this test's fixture\"), MeshConfig::loopback(), )` yields a value in this test's fixture");
        mesh.set_invite();
        assert!(
            mesh.issuer_secret().is_some(),
            "the creator holds the issuer key"
        );
        mesh
    }

    fn minted(mesh: &Mesh, ttl: Option<Duration>, password: Option<&Password>) -> InviteTicket {
        InviteTicket::decode(
            &mint(mesh, ttl, password)
                .expect("`mint(mesh, ttl, password)` yields a value in this test's fixture"),
        )
        .expect("decode")
    }

    /// A ticket with fixed fields: the signature and root are bytes, not the
    /// output of a mint, so the encoding needs no key and no clock.
    fn fixed_ticket() -> InviteTicket {
        InviteTicket {
            mesh_hash: "fixed-mesh-hash".to_owned(),
            expiry: UnixSecs::from(1_700_000_000),
            password: true,
            signature: [5u8; 64],
            root_field: vec![6u8; 32],
        }
    }

    /// The encoding of `fixed_ticket()`, a ticket built by hand from fixed fields, not minted.
    /// A change here is a wire change: tokens of this shape exist outside the code.
    const GOLDEN: &str = "CwX3aUAD9kjLm3ckGQZRSWa7jgHDTkggEgknyFUdHA9jDSm9M2YETdX3eachwWSHUkki6oZu2rStxtuJy3ZQM51fCh8Le1a7Suh3cuhtAYt67jN72d11tJPQ72hSp1mvLAwaSUkKQpL8eYxewU9y6ANjDBqTn6gHv7XwMWcJSSgM6s";

    #[test]
    fn encode_matches_the_golden_string() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            fixed_ticket().encode(),
            GOLDEN,
            "the invite encodes to the golden string"
        );
    }

    #[test]
    fn decode_of_the_golden_string_gives_the_same_fields() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            InviteTicket::decode(GOLDEN).expect("decode"),
            fixed_ticket(),
            "the golden string decodes to the same fields"
        );
    }

    // ── happy path ────────────────────────────────────────────────────────

    #[test]
    fn minted_invite_is_bare_base58() {
        let _guard = ::habilis_network_test_tracing::init();
        let token = mint(&creator(), Some(Duration::from_hours(1)), None).expect("`mint(&creator(), Some(Duration::from_hours(1)), None)` yields a value in this test's fixture");
        assert!(token.is_ascii(), "a minted invite is ascii");
        assert!(
            !token.contains("://"),
            "a minted invite carries no url scheme"
        );
    }

    #[test]
    fn redeemed_invite_derives_the_creators_topic() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        let redeemed = minted(&mesh, Some(Duration::from_hours(1)), None)
            .redeem(None)
            .expect("`minted(&mesh, Some(Duration::from_hours(1)), None) .redeem(None)` yields a value in this test's fixture");
        assert!(
            redeemed.requires_invite(),
            "a redeemed invite requires an invite"
        );
        // The gate works: same root ⇒ same topic ⇒ they actually meet.
        assert_eq!(
            redeemed.topic_id(),
            mesh.topic_id(),
            "a redeemed invite derives the creator's topic id"
        );
    }

    #[test]
    fn no_expiry_invite_round_trips() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        for ttl in [None, Some(Duration::ZERO)] {
            let ticket = minted(&mesh, ttl, None);
            assert!(ticket.redeem(None).is_ok(), "0/none ttl never expires");
        }
    }

    /// A ttl that does not fit the range saturates the expiry at the last point: the invite is
    /// valid, and its signed bytes carry that point.
    #[test]
    fn a_ttl_past_the_range_saturates_the_expiry() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        let ticket = minted(&mesh, Some(Duration::from_secs(u64::MAX)), None);
        assert_eq!(
            ticket.expiry,
            UnixSecs::MAX,
            "a ttl past the range saturates the expiry at the maximum"
        );
        assert!(
            ticket.redeem(None).is_ok(),
            "a saturated invite still redeems"
        );
    }

    /// The expiry is a whole second. A ttl with a part of a second rounds up, so that a ttl
    /// of one millisecond is no invite that is spent at once (`redeem` refuses `now >= expiry`).
    #[test]
    fn a_sub_second_ttl_rounds_up_to_a_whole_second() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        for (ttl, secs) in [
            (Duration::from_millis(1), 1),
            (Duration::from_millis(999), 1),
            (Duration::from_secs(1), 1),
            (Duration::from_millis(1_500), 2),
            (Duration::from_mins(1) + Duration::from_nanos(1), 61),
        ] {
            let before = UnixSecs::now();
            let ticket = minted(&mesh, Some(ttl), None);
            let after = UnixSecs::now();
            assert!(
                before + Duration::from_secs(secs) <= ticket.expiry
                    && ticket.expiry <= after + Duration::from_secs(secs),
                "ttl {ttl:?} must expire {secs} s from now, got {} (now {before}..{after})",
                ticket.expiry
            );
            assert!(
                ticket.redeem(None).is_ok(),
                "ttl {ttl:?} is not spent at once"
            );
        }
    }

    // ── "only the creator can mint" ───────────────────────────────────────

    #[test]
    fn a_redeemer_holds_the_root_but_cannot_mint() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        let redeemed = minted(&mesh, Some(Duration::from_hours(1)), None)
            .redeem(None)
            .expect("`minted(&mesh, Some(Duration::from_hours(1)), None) .redeem(None)` yields a value in this test's fixture");
        // The redeemer has the join root (it derived the topic) but no issuer
        // key, so it can neither mint nor sign a forgery.
        assert!(
            redeemed.issuer_secret().is_none(),
            "a redeemer holds the root but cannot mint"
        );
        assert!(
            mint(&redeemed, Some(Duration::from_hours(1)), None).is_err(),
            "a non-creator must not be able to mint a valid invite"
        );
    }

    #[test]
    fn mint_refuses_a_non_invite_only_mesh() {
        let _guard = ::habilis_network_test_tracing::init();
        let plain = Mesh::try_new(
            Seed::new([2u8; 32]),
            MeshName::try_new("t").expect("`MeshName::try_new(\"t\")` yields a value in this test's fixture"),
            MeshConfig::loopback(),
        )
        .expect("`Mesh::try_new( Seed::new([2u8; 32]), MeshName::try_new(\"t\").expect(\"`MeshName::try_new(\\\"t\\\")` yields a value in this test's fixture\"), MeshConfig::loopback(), )` yields a value in this test's fixture");
        assert!(
            mint(&plain, Some(Duration::from_hours(1)), None).is_err(),
            "minting refuses a mesh that is not invite-only"
        );
    }

    // ── adversarial: forged / tampered signatures ─────────────────────────

    #[test]
    fn rejects_a_zeroed_or_garbage_signature() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        let mut ticket = minted(&mesh, Some(Duration::from_hours(1)), None);
        ticket.signature = [0u8; 64];
        assert!(ticket.redeem(None).is_err(), "a blank sig must be refused");
    }

    #[test]
    fn rejects_an_invite_signed_by_a_non_issuer_key() {
        let _guard = ::habilis_network_test_tracing::init();
        // An attacker who knows the mesh hash + root (a member) signs an
        // otherwise-valid invite with their OWN key. It must fail against the
        // issuer pubkey baked into the hash — this is what makes minting
        // creator-only rather than any-member.
        let mesh = creator();
        let hash = mesh.to_string();
        let root = mesh
            .invite_key()
            .expect("`mesh.invite_key()` yields a value in this test's fixture")
            .clone();
        let expiry = UnixSecs::now() + Duration::from_hours(1);
        let attacker = SecretKey::from_bytes(&[9u8; 32]);
        let signature = attacker
            .sign(&signing_bytes(&hash, &root, expiry))
            .to_bytes();
        let forged: InviteTicket = InviteTicket {
            mesh_hash: hash,
            expiry,
            password: false,
            signature,
            root_field: root.as_bytes().to_vec(),
        };
        assert!(
            forged.redeem(None).is_err(),
            "an invite signed by a non-issuer must be refused"
        );
    }

    #[test]
    fn rejects_a_tampered_expiry() {
        let _guard = ::habilis_network_test_tracing::init();
        // Extending the window by editing `expiry` invalidates the signature,
        // which covers it — so a bearer can't lengthen their own invite.
        let mesh = creator();
        let mut ticket = minted(&mesh, Some(Duration::from_hours(1)), None);
        ticket.expiry = UnixSecs::MAX;
        assert!(
            ticket.redeem(None).is_err(),
            "a tampered expiry is refused on redeem"
        );
    }

    #[test]
    fn rejects_a_tampered_root() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        let mut ticket = minted(&mesh, Some(Duration::from_hours(1)), None);
        ticket.root_field[0] ^= 0xff;
        assert!(
            ticket.redeem(None).is_err(),
            "a swapped root breaks the signature over the plaintext root"
        );
    }

    // ── adversarial: expiry ───────────────────────────────────────────────

    #[test]
    fn rejects_an_expired_invite_even_with_a_valid_signature() {
        let _guard = ::habilis_network_test_tracing::init();
        // A genuinely creator-signed invite whose window has passed: the
        // signature is valid, but the local-clock check still refuses it.
        let mesh = creator();
        let hash = mesh.to_string();
        let root = mesh
            .invite_key()
            .expect("`mesh.invite_key()` yields a value in this test's fixture")
            .clone();
        let past = UnixSecs::now() - Duration::from_secs(100);
        let issuer = mesh
            .issuer_secret()
            .expect("`mesh.issuer_secret()` yields a value in this test's fixture")
            .clone();
        let signature = issuer.sign(&signing_bytes(&hash, &root, past)).to_bytes();
        let expired: InviteTicket = InviteTicket {
            mesh_hash: hash,
            expiry: past,
            password: false,
            signature,
            root_field: root.as_bytes().to_vec(),
        };
        let error = expired
            .redeem(None)
            .expect_err("`expired.redeem(None)` fails in this test's fixture")
            .to_string();
        assert!(error.contains("expired"), "got: {error}");
    }

    // ── adversarial: password wrap ────────────────────────────────────────

    #[test]
    fn a_password_wrapped_invite_needs_the_right_password() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        let ticket = minted(&mesh, Some(Duration::from_hours(1)), Some(&pw("hunter2")));
        assert!(
            ticket.requires_password(),
            "a password-wrapped invite requires its password"
        );
        assert!(ticket.redeem(None).is_err(), "missing password");
        assert!(
            ticket.redeem(Some(&pw("wrong"))).is_err(),
            "a wrong password must not unwrap the root (AEAD self-verifies)"
        );
        let ok = ticket.redeem(Some(&pw("hunter2"))).expect(
            "`ticket.redeem(Some(&pw(\"hunter2\")))` yields a value in this test's fixture",
        );
        assert_eq!(
            ok.topic_id(),
            mesh.topic_id(),
            "the password-wrapped invite derives the creator's topic id"
        );
    }

    #[test]
    fn a_plain_invite_rejects_a_stray_password() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = creator();
        assert!(
            minted(&mesh, Some(Duration::from_hours(1)), None)
                .redeem(Some(&pw("x")))
                .is_err(),
            "a plain invite refuses a stray password"
        );
    }

    // ── adversarial: cross-token confusion ────────────────────────────────

    #[test]
    fn a_mesh_id_is_not_an_invite() {
        let _guard = ::habilis_network_test_tracing::init();
        // A bare mesh id is not an invite ticket (different framing).
        let plain = Mesh::try_new(
            Seed::new([3u8; 32]),
            MeshName::try_new("t").expect("`MeshName::try_new(\"t\")` yields a value in this test's fixture"),
            MeshConfig::loopback(),
        )
        .expect("`Mesh::try_new( Seed::new([3u8; 32]), MeshName::try_new(\"t\").expect(\"`MeshName::try_new(\\\"t\\\")` yields a value in this test's fixture\"), MeshConfig::loopback(), )` yields a value in this test's fixture");
        assert!(
            InviteTicket::decode(&plain.to_string()).is_err(),
            "a mesh id is not an invite"
        );
    }

    #[test]
    fn rejects_a_bad_checksum() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut token = mint(&creator(), Some(Duration::from_hours(1)), None).expect("`mint(&creator(), Some(Duration::from_hours(1)), None)` yields a value in this test's fixture");
        let last = token
            .pop()
            .expect("`token.pop()` yields a value in this test's fixture");
        token.push(if last == '1' { '2' } else { '1' });
        assert!(
            InviteTicket::decode(&token).is_err(),
            "a bad checksum is refused as an invite"
        );
    }

    #[test]
    fn mints_bare_ascii_base58() {
        let _guard = ::habilis_network_test_tracing::init();
        // No glyph, no variation selector, no `://`: an invite pastes into a
        // URL or a shell word untouched.
        let token = mint(&creator(), Some(Duration::from_hours(1)), None).expect("`mint(&creator(), Some(Duration::from_hours(1)), None)` yields a value in this test's fixture");
        assert!(
            token.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "invite must be ASCII Base58: {token}"
        );
    }
}
