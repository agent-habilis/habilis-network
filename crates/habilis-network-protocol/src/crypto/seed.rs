//! The random 32-byte seed of a mesh id.

use super::SymmetricKey;

use super::derive;

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
        SymmetricKey::from_zeroizing(derive::derive_secret(&self.0, label))
    }
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            [5931, 16498, 11165, 32352, 6312, 13555, 22811, 1032]
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
        let name = MeshName::try_new("test").unwrap();
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
            [1131, 19491, 9656, 2645, 17345, 6055, 3587, 29121]
        );
    }

    #[test]
    fn the_ladders_of_the_old_range_are_no_longer_derived() {
        let old_wire = [5931, 48242, 42909, 64096, 38056, 45299, 54555, 32776];
        let old_secret = [64619, 51235, 41400, 1621, 17345, 37799, 35331, 60865];
        let wire = rendezvous_ports(Keying::Wire(&Seed::from_bytes(SEED)));
        let secret = rendezvous_ports(Keying::Secret(&SymmetricKey::from_bytes(ROOT)));
        assert_ne!(wire, old_wire);
        assert_ne!(secret, old_secret);
        assert!(old_wire.iter().chain(&old_secret).any(|&port| port > 32767));
    }
}
