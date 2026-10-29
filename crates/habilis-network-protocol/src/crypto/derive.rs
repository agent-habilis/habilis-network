//! The derivations of a mesh: its topic seed, its labelled secrets, and its topic id.

use super::{Keying, Seed};
use crate::mesh::MeshName;
use crate::topic::TopicId;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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
    use crate::crypto::{
        Keying, RENDEZVOUS_LADDER, Seed, derive_secret, rendezvous_id, rendezvous_ports,
        rendezvous_secret, topic_seed,
    };
    use habilis_network_test_tracing::test;
    use std::collections::HashSet;

    const SEED_A: [u8; 32] = [7u8; 32];
    const SEED_B: [u8; 32] = [9u8; 32];

    #[test]
    fn derive_secret_is_deterministic() {
        assert_eq!(
            derive_secret(&SEED_A, b"rendezvous"),
            derive_secret(&SEED_A, b"rendezvous"),
            "derive_secret is deterministic for the same label"
        );
    }

    #[test]
    fn derive_hashes_the_same_bytes_as_derive_secret() {
        use crate::crypto::{Seed, SymmetricKey};
        let seed = Seed::from_bytes(SEED_A);
        assert_eq!(
            seed.derive(b"state-doc").as_bytes(),
            &*derive_secret(&SEED_A, b"state-doc"),
            "derive hashes the same bytes as derive_secret for a seed"
        );
        // A key derives from the same bytes the way a seed does.
        let key = SymmetricKey::from(SEED_A);
        assert_eq!(
            key.derive(b"broadcast").as_bytes(),
            seed.derive(b"broadcast").as_bytes(),
            "the key and the seed derive the same broadcast bytes"
        );
    }

    #[test]
    fn a_seed_and_a_symmetric_key_print_no_byte() {
        use crate::crypto::{Seed, SymmetricKey};
        assert_eq!(
            format!("{:?}", Seed::from_bytes(SEED_A)),
            "Seed(***)",
            "a seed prints no byte"
        );
        assert_eq!(
            format!("{:?}", SymmetricKey::from(SEED_A)),
            "SymmetricKey(***)",
            "a symmetric key prints no byte"
        );
    }

    #[test]
    fn derive_secret_domain_separates_by_label() {
        assert_ne!(
            derive_secret(&SEED_A, b"rendezvous"),
            derive_secret(&SEED_A, b"port"),
            "different labels derive different secrets"
        );
    }

    #[test]
    fn derive_secret_domain_separates_by_seed() {
        assert_ne!(
            derive_secret(&SEED_A, b"rendezvous"),
            derive_secret(&SEED_B, b"rendezvous"),
            "different seeds derive different secrets"
        );
    }

    #[test]
    fn label_length_prefix_prevents_collision() {
        // Without the length prefix ("rd"+"vx") and ("rdv"+"x") would
        // hash the same stream. The prefix must keep them distinct.
        assert_ne!(
            derive_secret(&SEED_A, b"rdvx"),
            derive_secret(&SEED_A, b"rdv"),
            "the label length prefix prevents a collision"
        );
    }

    #[test]
    fn rendezvous_id_is_stable_for_a_seed() {
        assert_eq!(
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_A))),
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_A))),
            "the rendezvous id is stable for a seed"
        );
        assert_ne!(
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_A))),
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_B))),
            "a different seed gives a different rendezvous id"
        );
    }

    #[test]
    fn rendezvous_id_matches_secret_public() {
        assert_eq!(
            rendezvous_id(Keying::Wire(&Seed::from_bytes(SEED_A))),
            rendezvous_secret(Keying::Wire(&Seed::from_bytes(SEED_A))).public(),
            "the rendezvous id matches the secret public key"
        );
    }

    #[test]
    fn rendezvous_ports_are_in_range_stable_and_seed_specific() {
        let ladder = rendezvous_ports(Keying::Wire(&Seed::from_bytes(SEED_A)));
        assert_eq!(
            ladder.len(),
            RENDEZVOUS_LADDER,
            "the rendezvous ladder has the expected length"
        );
        assert!(
            ladder.iter().all(|&port| port >= 1024),
            "every rendezvous port is at least 1024"
        );
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
    fn rendezvous_ports_stay_below_every_ephemeral_range() {
        for seed in 0..2000_u32 {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&seed.to_le_bytes());
            let ladder = rendezvous_ports(Keying::Wire(&Seed::from_bytes(bytes)));
            assert!(
                ladder.iter().all(|port| (1024..32768).contains(port)),
                "seed {seed} gave {ladder:?}"
            );
        }
    }

    #[test]
    fn topic_seed_is_deterministic() {
        assert_eq!(
            topic_seed("agent-habilis"),
            topic_seed("agent-habilis"),
            "the topic seed is deterministic"
        );
    }

    #[test]
    fn topic_seed_differs_by_string() {
        assert_ne!(
            topic_seed("alpha"),
            topic_seed("beta"),
            "different strings give different topic seeds"
        );
    }

    #[test]
    fn topic_seed_trims_surrounding_whitespace() {
        assert_eq!(
            topic_seed("  x\n"),
            topic_seed("x"),
            "the topic seed trims surrounding whitespace"
        );
    }

    #[test]
    fn topic_seed_is_case_sensitive() {
        assert_ne!(
            topic_seed("Repo"),
            topic_seed("repo"),
            "the topic seed is case sensitive"
        );
    }

    #[test]
    fn topic_seed_domain_separated_from_derive_secret() {
        // A topic seed lives under TOPIC_DOMAIN; it must not coincide with a
        // labelled derivation off some other seed for any plausible collision.
        assert_ne!(
            topic_seed("rendezvous").as_bytes(),
            &*derive_secret(&SEED_A, b"rendezvous"),
            "the topic seed is domain separated from derive_secret"
        );
    }

    #[test]
    fn rendezvous_ports_rungs_are_near_certainly_distinct() {
        let ladder = rendezvous_ports(Keying::Wire(&Seed::from_bytes(SEED_A)));
        let unique: HashSet<_> = ladder.iter().collect();
        // A rare in-ladder dup is harmless, but the fixed test seed
        // must not regress into a degenerate all-same ladder.
        assert!(
            unique.len() >= RENDEZVOUS_LADDER - 1,
            "the rendezvous rungs are almost surely distinct"
        );
    }
}

#[cfg(test)]
mod topic_tests {
    use crate::crypto::{Keying, Seed, derive_topic_id};
    use crate::mesh::MeshName;
    use habilis_network_test_tracing::test;

    fn name(text: &str) -> MeshName {
        MeshName::try_new(text).unwrap()
    }

    const CFG_A: &[u8] = &[60, 0, 0]; // rate 60, lookups loopback
    const CFG_B: &[u8] = &[0, 0, 0b0111]; // rate 0, mdns+dht+pinned relay

    #[test]
    fn deterministic_for_same_input() {
        let seed = [42u8; 32];
        let first = derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("team"), CFG_A);
        let second = derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("team"), CFG_A);
        assert_eq!(first, second, "the same input derives the same topic id");
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
            ),
            "different seeds derive different topic ids"
        );
    }

    #[test]
    fn different_names_produce_different_topics() {
        let seed = [1u8; 32];
        assert_ne!(
            derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("alpha"), CFG_A),
            derive_topic_id(Keying::Wire(&Seed::from_bytes(seed)), &name("beta"), CFG_A),
            "different names derive different topic ids"
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
