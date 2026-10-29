//! The random 32-byte seed of a mesh id.

use super::SymmetricKey;

use super::derive;

use std::fmt;
/// The random 32 bytes that a mesh id carries, and the salts of the key
/// derivations. Whoever holds it can join an open mesh, so `Debug` prints no
/// byte; unlike [`SymmetricKey`] it is `Copy` and comparable, because it is
/// public material of the id and not a key. It is not wiped on drop: the id
/// carries these bytes in plain text, so a wipe would protect nothing.
///
/// # Examples
///
/// A seed holds 32 bytes, and each label derives its own key from it.
///
/// ```
/// use habilis_network_protocol::Seed;
///
/// let seed = Seed::new([3u8; 32]);
/// assert_eq!(seed.as_bytes(), &[3u8; 32]);
///
/// let key = seed.derive(b"state");
/// assert_ne!(key.as_bytes(), seed.as_bytes());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seed([u8; 32]);

impl Seed {
    /// Wrap 32 raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, borrowed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive an independent [`SymmetricKey`] for `label`: the hash of the
    /// seed under a domain and the label, held in a wiped buffer.
    ///
    /// # Panics
    /// If `label` exceeds 255 bytes; labels are short internal constants.
    #[must_use]
    pub fn derive(&self, label: &[u8]) -> SymmetricKey {
        SymmetricKey::from(derive::derive_secret(&self.0, label))
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Seed(***)")
    }
}

/// Golden outputs of the mesh derivations, for fixed inputs. They equal what
/// the code before the newtype refactor (795c4f88) gives, so they prove that
/// the refactor moved no derived byte. Change a value only on purpose, as a
/// named wire decision.
#[cfg(test)]
mod golden_tests {
    use crate::crypto::{
        Keying, Password, Seed, SymmetricKey, derive_topic_id, invite_wrap_key, password_verifier,
        rendezvous_id, rendezvous_ports, stretch_mesh_password,
    };
    use crate::mesh::MeshName;

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
        let _guard = ::habilis_network_test_tracing::init();
        let seed = Seed::new(SEED);
        assert_eq!(
            rendezvous_id(Keying::Wire(&seed)).to_string(),
            "f7172ec3cf80783eb9972177ba2ac384d4b30612c0892ec0fa8d4ee552190469",
            "the golden wire seed gives the golden rendezvous id"
        );
        assert_eq!(
            rendezvous_ports(Keying::Wire(&seed)),
            [5931, 16498, 11165, 32352, 6312, 13555, 22811, 1032],
            "the golden wire seed gives the golden rendezvous ports"
        );
    }

    #[test]
    fn golden_password_stretch_and_verifier() {
        let _guard = ::habilis_network_test_tracing::init();
        let seed = Seed::new(SEED);
        let password = Password::new("hunter2".to_owned());
        let key = stretch_mesh_password(&password, &seed);
        assert_eq!(
            hex(key.as_bytes()),
            "2ac1fef982a96d1f5051cbe48638f57d8484c22d159fff7c6e5459a8d6de94ba",
            "the golden password stretch is pinned"
        );
        assert_eq!(
            hex(&password_verifier(&key)),
            "58756a1b4f3ce544517606c0abccdf8e",
            "the golden password verifier is pinned"
        );
        assert_eq!(
            hex(invite_wrap_key(&password, &seed).as_bytes()),
            "541efc2dd477ce08854291e7da56e3297d537044170c90f78373e84960ad58ab",
            "the golden invite wrap key is pinned"
        );
    }

    #[test]
    fn golden_derivations_keyed_by_a_secret() {
        let _guard = ::habilis_network_test_tracing::init();
        let root = SymmetricKey::from(ROOT);
        let name = MeshName::try_new("test").unwrap();
        assert_eq!(
            format!(
                "{:?}",
                derive_topic_id(Keying::Secret(&root), &name, b"fixed-config-bytes")
            ),
            "TopicId(d4137216ab43c3277fa07d4a2abb128fd8b69a4dbfac3ddd1fecf27f8ea18107)",
            "the golden secret-keyed topic id is pinned"
        );
        assert_eq!(
            rendezvous_id(Keying::Secret(&root)).to_string(),
            "6996293bba871f0c8b7adacb92463b5924a26c6555bcb0ebbf87f605be01bf50",
            "the golden secret-keyed rendezvous id is pinned"
        );
        assert_eq!(
            rendezvous_ports(Keying::Secret(&root)),
            [1131, 19491, 9656, 2645, 17345, 6055, 3587, 29121],
            "the golden secret-keyed rendezvous ports are pinned"
        );
    }

    #[test]
    fn the_ladders_of_the_old_range_are_no_longer_derived() {
        let _guard = ::habilis_network_test_tracing::init();
        let old_wire = [5931, 48242, 42909, 64096, 38056, 45299, 54555, 32776];
        let old_secret = [64619, 51235, 41400, 1621, 17345, 37799, 35331, 60865];
        let wire = rendezvous_ports(Keying::Wire(&Seed::new(SEED)));
        let secret = rendezvous_ports(Keying::Secret(&SymmetricKey::from(ROOT)));
        assert_ne!(wire, old_wire, "the old wire ladder is no longer derived");
        assert_ne!(
            secret, old_secret,
            "the old secret ladder is no longer derived"
        );
        assert!(
            old_wire.iter().chain(&old_secret).any(|&port| port > 32767),
            "no old port is in the new ladders"
        );
    }
}
