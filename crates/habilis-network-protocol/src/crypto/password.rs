//! An operator password, and the keys stretched from it.

use super::{Seed, SymmetricKey};
use habilis_network_util::consts::{
    PASSWORD_KDF_M_COST_KIB, PASSWORD_KDF_P_COST, PASSWORD_KDF_T_COST,
};
use zeroize::Zeroizing;

use super::derive;

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
    /// Wraps an operator password. Its `Debug` output is `***`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The password in plain text. `Debug` hides it; this does not.
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
/// `derive::derive_secret(salt_seed, label)` — keyed by the mesh's random seed and
/// domain-separated by `label`, so the stretch shares no salt with any other
/// `derive_secret` use and no rainbow table carries over. Cost params are a
/// wire contract (`util::consts`); ~50-100ms by design, paid once at
/// create/join.
pub(super) fn stretch_password(
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
    let salt = derive::derive_secret(salt_seed, label);
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
    SymmetricKey::from(stretch_password(password, seed.as_bytes(), b"password"))
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
    SymmetricKey::from(stretch_password(
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
    let digest = derive::derive_secret(key.as_bytes(), b"password-verify");
    let mut out = [0u8; PASSWORD_VERIFIER_LEN];
    out.copy_from_slice(&digest[..PASSWORD_VERIFIER_LEN]);
    out
}

#[cfg(test)]
mod password_tests {
    use super::derive;

    use crate::crypto::{Password, Seed, password_verifier, stretch_mesh_password};

    const SEED_A: [u8; 32] = [7u8; 32];
    const SEED_B: [u8; 32] = [9u8; 32];

    fn pw(text: &str) -> Password {
        Password::new(text.to_owned())
    }

    #[test]
    fn stretch_is_deterministic_and_separates_by_password_and_seed() {
        let _guard = ::habilis_network_test_tracing::init();
        let seed_a = Seed::new(SEED_A);
        let seed_b = Seed::new(SEED_B);
        let key = stretch_mesh_password(&pw("hunter2"), &seed_a);
        let same = stretch_mesh_password(&pw("hunter2"), &seed_a);
        assert_eq!(
            key.as_bytes(),
            same.as_bytes(),
            "the stretch of the same password and seed is the same key"
        );
        let other_password = stretch_mesh_password(&pw("hunter3"), &seed_a);
        assert_ne!(
            key.as_bytes(),
            other_password.as_bytes(),
            "a different password gives a different key"
        );
        let other_seed = stretch_mesh_password(&pw("hunter2"), &seed_b);
        assert_ne!(
            key.as_bytes(),
            other_seed.as_bytes(),
            "a different seed gives a different key"
        );
    }

    #[test]
    fn verifier_is_not_the_key_and_not_a_topic_or_rendezvous_input() {
        let _guard = ::habilis_network_test_tracing::init();
        let key = stretch_mesh_password(&pw("hunter2"), &Seed::new(SEED_A));
        let verifier = password_verifier(&key);
        assert_ne!(
            &key.as_bytes()[..16],
            &verifier[..],
            "verifier must be one-way"
        );
        assert_ne!(
            &derive::derive_secret(key.as_bytes(), b"topic")[..16],
            &verifier[..],
            "verifier must not collide with a derivation label"
        );
    }

    #[test]
    fn password_never_leaks_through_debug_or_display() {
        let _guard = ::habilis_network_test_tracing::init();
        let secret = pw("hunter2");
        assert_eq!(
            format!("{secret:?}"),
            "***",
            "a password debug prints no byte"
        );
        assert_eq!(
            format!("{secret}"),
            "***",
            "a password display prints no byte"
        );
    }

    #[test]
    fn channel_keys_are_domain_separated() {
        let _guard = ::habilis_network_test_tracing::init();
        // The state/meta/broadcast content keys are all derived from the same
        // stretched mesh key but must never collide.
        let mesh_key = stretch_mesh_password(&pw("hunter2"), &Seed::new(SEED_A));
        let state = derive::derive_secret(mesh_key.as_bytes(), b"state-doc");
        let meta = derive::derive_secret(mesh_key.as_bytes(), b"meta-doc");
        let broadcast = derive::derive_secret(mesh_key.as_bytes(), b"broadcast");
        assert_ne!(state, meta, "the state and meta channel keys are separate");
        assert_ne!(
            state, broadcast,
            "the state and broadcast keys are separate"
        );
        assert_ne!(meta, broadcast, "the meta and broadcast keys are separate");
    }

    /// The stretched token for a fixed secret, password and label. A change
    /// here breaks each passworded ticket that exists outside the code.
    #[test]
    fn derive_token_matches_the_golden_bytes() {
        use crate::crypto::{TicketAuth, TicketSecret};
        let _guard = ::habilis_network_test_tracing::init();
        let secret = TicketSecret::from([3u8; 32]);
        let auth = TicketAuth::derive(&secret, Some(&pw("hunter2")), b"blob-ticket");
        assert!(
            auth.password_protected,
            "a password-protected ticket is marked protected"
        );
        assert_eq!(
            hex(auth.token.as_bytes()),
            "824798ec30b0b968447a543d55adf59dd4a8a8a2218a9833409ce313edd258cf",
            "the derived token matches the golden bytes"
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
        use crate::crypto::{SymmetricKey, TicketSecret};
        use zeroize::Zeroizing;

        let _guard = ::habilis_network_test_tracing::init();
        let stretched: Zeroizing<[u8; 32]> =
            super::stretch_password(&pw("hunter2"), &SEED_A, b"password");
        assert_ne!(*stretched, [0u8; 32], "the stretch fills the buffer");
        let key = SymmetricKey::from(stretched.clone());
        let secret = TicketSecret::from(stretched.clone());
        assert_eq!(
            key.as_bytes(),
            &*stretched,
            "the stretched key keeps its bytes when moved into its type"
        );
        assert_eq!(
            secret.as_bytes(),
            &*stretched,
            "the moved secret keeps the stretched bytes"
        );
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
        use crate::crypto::TicketSecret;
        let _guard = ::habilis_network_test_tracing::init();
        let secret = TicketSecret::from([9u8; 32]);
        assert_eq!(
            format!("{secret:?}"),
            "TicketSecret(***)",
            "a ticket secret debug prints no byte"
        );
        assert_eq!(
            secret.as_bytes(),
            &[9u8; 32],
            "the ticket secret keeps its bytes"
        );
    }

    // `unsafe_code` is denied, so a test cannot read the freed bytes: the types
    // carry the test. The `ZeroizeOnDrop` marker on a secret type is a promise
    // and proves nothing by itself, so the test pins the field: it holds its
    // bytes in a `Zeroizing`, which wipes them on drop. This does not compile if
    // a field becomes a bare array.
    #[test]
    fn the_secret_types_hold_their_bytes_in_a_zeroizing_buffer() {
        use zeroize::Zeroizing;

        let _guard = ::habilis_network_test_tracing::init();
        let _: &Zeroizing<[u8; 32]> = &crate::crypto::TicketSecret::from([0; 32]).0;
        let _: &Zeroizing<[u8; 32]> = &crate::crypto::SymmetricKey::from([0; 32]).0;
    }

    #[test]
    fn ticket_tokens_are_domain_separated_by_label() {
        use crate::crypto::{TicketAuth, TicketSecret};
        let _guard = ::habilis_network_test_tracing::init();
        let secret = TicketSecret::from([3u8; 32]);
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
        assert_eq!(
            TicketAuth::blob(&secret, None).token.as_bytes(),
            &[3u8; 32],
            "the blob token is the derived bytes for its label"
        );
        assert_eq!(
            TicketAuth::derive(&secret, None, b"other-ticket")
                .token
                .as_bytes(),
            &[3u8; 32],
            "a different label gives a different token"
        );
    }
}
