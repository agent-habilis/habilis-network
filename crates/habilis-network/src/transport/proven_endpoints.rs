//! Which endpoint a signing key owns, proven rather than claimed.
//!
//! A frame proves its signing key and nothing else: its nickname is a label
//! any signer can put on it, and a `PeerInfo`'s endpoint id is a claim. So a
//! `PeerInfo` also carries a proof, a signature by the endpoint's own key over
//! the mesh and the frame's signing key. Only the holder of both keys can make
//! it, so a point-to-point answer to a digest goes to the endpoint proven for
//! the digest's signer, and a signer that proved none is answered on gossip.

use std::collections::{HashMap, HashSet, VecDeque};

use iroh::{EndpointId, SecretKey, Signature};

use crate::protocol::identity::{decode_hex, encode_hex};
use crate::protocol::{AuthorKey, MeshId, UnixSecs};

const DOMAIN: &[u8] = b"habilis-network/peerinfo-endpoint-proof/1";

/// The bytes a proof signs: the domain, the mesh, then the 32-byte signing
/// key. The domain has a fixed length and the key is always the last 32
/// bytes, so the layout has one reading.
fn proof_bytes(mesh: &MeshId, signer: &AuthorKey) -> Vec<u8> {
    [DOMAIN, mesh.as_str().as_bytes(), signer.as_bytes()].concat()
}

/// The proof this endpoint's key gives for `signer` on `mesh`, as hex.
pub(crate) fn sign(endpoint_key: &SecretKey, mesh: &MeshId, signer: &AuthorKey) -> String {
    encode_hex(&endpoint_key.sign(&proof_bytes(mesh, signer)).to_bytes())
}

/// Whether `proof` is `endpoint`'s signature over `signer` on `mesh`.
pub(crate) fn verifies(
    endpoint: EndpointId,
    mesh: &MeshId,
    signer: &AuthorKey,
    proof: &str,
) -> bool {
    let Some(bytes) = decode_hex(proof).and_then(|raw| <[u8; 64]>::try_from(raw).ok()) else {
        return false;
    };
    endpoint
        .verify(&proof_bytes(mesh, signer), &Signature::from_bytes(&bytes))
        .is_ok()
}

/// The endpoint each signing key proved, bounded: a signer owns as many key
/// and endpoint pairs as it cares to make. An endpoint keeps one signer, its
/// latest, so the pairs with a linked endpoint are at most the links, and a
/// new session on the same endpoint replaces the old one. At the cap the
/// oldest pair whose endpoint is not linked goes, since only a linked
/// endpoint is ever a target; with every pair linked a new one is not kept.
/// "Latest" holds because an endpoint key is new each run by default: an
/// endpoint that keeps its key across runs lets an old `PeerInfo` be replayed
/// to put back the old signer, and that peer is answered on gossip until its
/// next `PeerInfo`.
#[derive(Debug, Clone)]
pub(crate) struct ProvenEndpoints {
    by_signer: HashMap<AuthorKey, EndpointId>,
    order: VecDeque<AuthorKey>,
    cap: usize,
    /// The endpoint of each roster key whose proof was checked, for the trust in a link vector.
    /// It has no cap and no order: the roster bounds it, and the sweep drops a key that left.
    trusted: HashMap<AuthorKey, EndpointId>,
    /// The stamp of the newest `PeerInfo` that proved each endpoint of `by_signer`.
    stamps: HashMap<EndpointId, UnixSecs>,
}

impl ProvenEndpoints {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            by_signer: HashMap::new(),
            order: VecDeque::new(),
            cap,
            trusted: HashMap::new(),
            stamps: HashMap::new(),
        }
    }

    /// The endpoint that `signer`, a key of the roster, proved.
    pub(crate) fn trusted(&self, signer: &AuthorKey) -> Option<EndpointId> {
        self.trusted.get(signer).copied()
    }

    /// Keep the trust in `signer` at `endpoint`. The caller admits roster keys only.
    pub(crate) fn trust(&mut self, signer: AuthorKey, endpoint: EndpointId) {
        self.trusted.insert(signer, endpoint);
    }

    /// Drop the trust in each key that `keep` refuses.
    pub(crate) fn retain_trusted(&mut self, keep: impl Fn(&AuthorKey) -> bool) {
        self.trusted.retain(|signer, _| keep(signer));
    }

    /// Drop the trust in `signer`.
    pub(crate) fn forget_trust(&mut self, signer: &AuthorKey) {
        self.trusted.remove(signer);
    }

    pub(crate) fn get(&self, signer: &AuthorKey) -> Option<EndpointId> {
        self.by_signer.get(signer).copied()
    }

    /// Record that `signer` proved `endpoint` in a `PeerInfo` stamped `stamp`. Another signer
    /// takes an endpoint over only with a newer stamp: a restart keeps the key of the endpoint
    /// and makes a new signing key, and a replay of the old `PeerInfo` must not put it back.
    pub(crate) fn insert(
        &mut self,
        signer: AuthorKey,
        endpoint: EndpointId,
        stamp: UnixSecs,
        linked: &HashSet<EndpointId>,
    ) {
        let held = self.stamps.get(&endpoint).copied();
        if self.by_signer.get(&signer) != Some(&endpoint) && held.is_some_and(|held| stamp <= held)
        {
            return;
        }
        self.place(signer, endpoint, linked);
        if self.by_signer.get(&signer) == Some(&endpoint) {
            self.stamps
                .insert(endpoint, stamp.max(held.unwrap_or(stamp)));
        }
        let live: HashSet<EndpointId> = self.by_signer.values().copied().collect();
        self.stamps.retain(|eid, _| live.contains(eid));
    }

    fn place(&mut self, signer: AuthorKey, endpoint: EndpointId, linked: &HashSet<EndpointId>) {
        self.by_signer
            .retain(|other, eid| *other == signer || *eid != endpoint);
        let by_signer = &self.by_signer;
        self.order.retain(|kept| by_signer.contains_key(kept));
        if self.by_signer.insert(signer, endpoint).is_some() {
            return;
        }
        if self.order.len() >= self.cap {
            let evictable: Option<usize> = self.order.iter().position(|old| {
                self.by_signer
                    .get(old)
                    .is_none_or(|eid| !linked.contains(eid))
            });
            let Some(index) = evictable else {
                self.by_signer.remove(&signer);
                return;
            };
            if let Some(old) = self.order.remove(index) {
                self.by_signer.remove(&old);
            }
        }
        self.order.push_back(signer);
    }

    /// Drop every pair for `endpoint`, as its peer leaves. The caller finds the
    /// endpoint by nickname, which a signer can take over; a pair missed that
    /// way is no longer linked, so the cap evicts it later.
    pub(crate) fn forget_endpoint(&mut self, endpoint: EndpointId) {
        self.trusted.retain(|_, eid| *eid != endpoint);
        self.by_signer.retain(|_, eid| *eid != endpoint);
        let by_signer = &self.by_signer;
        self.order.retain(|signer| by_signer.contains_key(signer));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_signer.len()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iroh::SecretKey;

    use super::{ProvenEndpoints, sign, verifies};
    use crate::protocol::{AuthorKey, MeshId, UnixSecs};

    fn key(byte: u8) -> AuthorKey {
        AuthorKey::from([byte; 32])
    }

    #[test]
    fn a_proof_holds_only_for_its_signer_and_mesh() {
        let _guard = ::habilis_network_test_tracing::init();
        let endpoint_key = SecretKey::generate();
        let endpoint = endpoint_key.public();
        let mesh = MeshId::from("mesh-a");
        let (signer, other) = (key(1), key(2));
        let proof = sign(&endpoint_key, &mesh, &signer);

        assert!(
            verifies(endpoint, &mesh, &signer, &proof),
            "a proof holds only for its signer and mesh"
        );
        assert!(!verifies(endpoint, &mesh, &other, &proof), "another signer");
        assert!(
            !verifies(endpoint, &MeshId::from("mesh-b"), &signer, &proof),
            "another mesh"
        );
        assert!(
            !verifies(SecretKey::generate().public(), &mesh, &signer, &proof),
            "another endpoint"
        );
        assert!(!verifies(endpoint, &mesh, &signer, "not hex"), "garbage");
    }

    #[test]
    fn the_map_is_bounded_and_keeps_a_linked_endpoint() {
        let _guard = ::habilis_network_test_tracing::init();
        let cap = 4;
        let mut proven = ProvenEndpoints::new(cap);
        let linked_one = SecretKey::generate().public();
        let linked: HashSet<_> = [linked_one].into_iter().collect();
        proven.insert(key(0), linked_one, UnixSecs::from(1), &linked);
        for byte in 1..=u8::try_from(cap * 2).expect("small") {
            proven.insert(
                key(byte),
                SecretKey::generate().public(),
                UnixSecs::from(1),
                &linked,
            );
        }
        assert_eq!(
            proven.len(),
            cap,
            "the proven map stays at its cap and keeps a linked endpoint"
        );
        assert_eq!(
            proven.get(&key(0)),
            Some(linked_one),
            "the linked pair stays"
        );
        assert_eq!(proven.get(&key(1)), None, "the oldest unlinked pair went");

        proven.forget_endpoint(linked_one);
        assert_eq!(proven.get(&key(0)), None, "gone with its peer");
    }
}

#[cfg(test)]
mod one_signer_tests {
    use std::collections::HashSet;

    use iroh::SecretKey;

    use super::ProvenEndpoints;
    use crate::protocol::{AuthorKey, UnixSecs};

    /// Many signers can prove one endpoint, since whoever holds that endpoint's
    /// key makes as many signing keys as it likes. Kept as separate pairs, a
    /// linked peer would fill the map with pairs the cap may not evict, and no
    /// other peer would get a binding.
    #[test]
    fn one_endpoint_keeps_one_signer() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut proven = ProvenEndpoints::new(4);
        let attacker = SecretKey::generate().public();
        let linked: HashSet<_> = [attacker].into_iter().collect();
        for byte in 1..=5u8 {
            let stamp = UnixSecs::from(i64::from(byte));
            proven.insert(AuthorKey::from([byte; 32]), attacker, stamp, &linked);
        }
        let honest = SecretKey::generate().public();
        proven.insert(AuthorKey::from([9; 32]), honest, UnixSecs::from(1), &linked);

        assert_eq!(
            proven.get(&AuthorKey::from([9; 32])),
            Some(honest),
            "the honest pair is kept"
        );
        assert_eq!(proven.len(), 2, "the linked endpoint has one signer");
        assert_eq!(
            proven.get(&AuthorKey::from([5; 32])),
            Some(attacker),
            "its latest signer"
        );

        proven.insert(
            AuthorKey::from([6; 32]),
            attacker,
            UnixSecs::from(5),
            &linked,
        );
        assert_eq!(
            proven.get(&AuthorKey::from([5; 32])),
            Some(attacker),
            "a signer with an equal stamp does not take the endpoint over"
        );
        assert_eq!(
            proven.get(&AuthorKey::from([6; 32])),
            None,
            "the signer with the equal stamp holds nothing"
        );
    }
}
