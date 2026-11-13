//! Which endpoint a signing key owns, proven rather than claimed.
//!
//! A frame proves its signing key and nothing else: its nickname is a label
//! any signer can put on it, and a `PeerInfo`'s endpoint id is a claim. So a
//! `PeerInfo` also carries a proof, a signature by the endpoint's own key over
//! the mesh and the frame's signing key. Only the holder of both keys can make
//! it, so a point-to-point backfill goes to the endpoint proven for
//! the key of its receiver. A key that proved none is owed the frame: the backfill tick sends
//! again, and the entry expires after the alive timeout.

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
/// next `PeerInfo`. The peers of a mesh are cooperative: a holder that is not live keeps
/// its endpoint against no replay guard.
#[derive(Debug, Clone)]
pub(crate) struct ProvenEndpoints {
    by_signer: HashMap<AuthorKey, EndpointId>,
    order: VecDeque<AuthorKey>,
    cap: usize,
    /// The endpoint of each roster key whose proof was checked, for the trust in a link vector.
    /// It has no cap and no order: the roster bounds it, and the sweep drops a key that left.
    trusted: HashMap<AuthorKey, EndpointId>,
    /// The roster key that each endpoint of `trusted` is trusted for: `trusted` read the other way,
    /// so that the question "who holds this endpoint" is a lookup and not a scan of every key.
    trusted_by_endpoint: HashMap<EndpointId, AuthorKey>,
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
            trusted_by_endpoint: HashMap::new(),
            stamps: HashMap::new(),
        }
    }

    /// The endpoint that `signer`, a key of the roster, proved.
    pub(crate) fn trusted(&self, signer: &AuthorKey) -> Option<EndpointId> {
        self.trusted.get(signer).copied()
    }

    /// The roster key that `endpoint` is trusted for, if one is.
    pub(crate) fn trusted_signer(&self, endpoint: EndpointId) -> Option<AuthorKey> {
        self.trusted_by_endpoint.get(&endpoint).copied()
    }

    /// Keep the trust in `signer` at `endpoint`, in place of the trust in any other signer of that
    /// endpoint: an endpoint has one signer. The caller admits roster keys only.
    pub(crate) fn trust(&mut self, signer: AuthorKey, endpoint: EndpointId) {
        if let Some(displaced) = self.trusted_by_endpoint.insert(endpoint, signer)
            && displaced != signer
        {
            self.trusted.remove(&displaced);
        }
        if let Some(previous) = self.trusted.insert(signer, endpoint)
            && previous != endpoint
        {
            self.trusted_by_endpoint.remove(&previous);
        }
    }

    /// Drop the trust in each key that `keep` refuses.
    pub(crate) fn retain_trusted(&mut self, keep: impl Fn(&AuthorKey) -> bool) {
        self.trusted.retain(|signer, _| keep(signer));
        self.trusted_by_endpoint.retain(|_, signer| keep(signer));
    }

    /// Drop the trust in `signer`.
    pub(crate) fn forget_trust(&mut self, signer: &AuthorKey) {
        if let Some(endpoint) = self.trusted.remove(signer) {
            self.trusted_by_endpoint.remove(&endpoint);
        }
    }

    pub(crate) fn get(&self, signer: &AuthorKey) -> Option<EndpointId> {
        self.by_signer.get(signer).copied()
    }

    /// The signers that hold `endpoint`: the signer of its pair and the signer that the roster
    /// trusts for it. They are two keys when a newer `PeerInfo` of a key that is not in the roster
    /// yet took the pair and the roster still trusts the old key.
    fn holders_of(&self, endpoint: EndpointId) -> Vec<AuthorKey> {
        let paired = self.by_signer.iter().find(|(_, eid)| **eid == endpoint);
        let paired = paired.map(|(signer, _)| *signer);
        let mut holders: Vec<AuthorKey> = paired.into_iter().collect();
        holders.extend(
            self.trusted_signer(endpoint)
                .filter(|key| Some(*key) != paired),
        );
        holders
    }

    /// Record that `signer` proved `endpoint` in a `PeerInfo` stamped `stamp`. Another signer
    /// takes an endpoint over from a holder that is live only with a newer stamp. A restart keeps
    /// the key of the endpoint and makes a new signing key, and the old key stays live until it is
    /// silent for the alive timeout. A holder that is not live (`holder_is_live` says no) holds
    /// the endpoint against nothing: a restart whose clock is behind the old key has an older
    /// stamp and must take the endpoint all the same. The stored stamp is then the stamp of the
    /// new signer, so the next restart is judged against it and not against the old holder.
    ///
    /// The peers of a mesh are cooperative. A replay of an old `PeerInfo` can take an endpoint
    /// from a holder that is not live, and no guard stops it.
    pub(crate) fn insert(
        &mut self,
        signer: AuthorKey,
        endpoint: EndpointId,
        stamp: UnixSecs,
        linked: &HashSet<EndpointId>,
        holder_is_live: impl Fn(&AuthorKey) -> bool,
    ) {
        let held = self.stamps.get(&endpoint).copied();
        let mut other_holders = self.holders_of(endpoint);
        other_holders.retain(|holder| *holder != signer);
        let outranked = held.is_some_and(|held| stamp <= held);
        if outranked && other_holders.iter().any(holder_is_live) {
            return;
        }
        self.place(signer, endpoint, linked);
        if self.by_signer.get(&signer) == Some(&endpoint) {
            let kept = if other_holders.is_empty() {
                stamp.max(held.unwrap_or(stamp))
            } else {
                stamp
            };
            self.stamps.insert(endpoint, kept);
        }
        // A trusted endpoint keeps its stamp when the cap takes its pair out: the stamp is what
        // refuses an older `PeerInfo` that would move the trust to another signer.
        let mut live: HashSet<EndpointId> = self.by_signer.values().copied().collect();
        live.extend(self.trusted.values().copied());
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
        if let Some(signer) = self.trusted_by_endpoint.remove(&endpoint) {
            self.trusted.remove(&signer);
        }
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

    /// Every holder is live: the rule for a live holder, which these tests pin.
    fn every_key(_holder: &AuthorKey) -> bool {
        true
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
        proven.insert(key(0), linked_one, UnixSecs::from(1), &linked, every_key);
        for byte in 1..=u8::try_from(cap * 2).expect("small") {
            proven.insert(
                key(byte),
                SecretKey::generate().public(),
                UnixSecs::from(1),
                &linked,
                every_key,
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

    /// Every holder is live: the rule for a live holder, which these tests pin.
    fn every_key(_holder: &AuthorKey) -> bool {
        true
    }

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
            proven.insert(
                AuthorKey::from([byte; 32]),
                attacker,
                stamp,
                &linked,
                every_key,
            );
        }
        let honest = SecretKey::generate().public();
        proven.insert(
            AuthorKey::from([9; 32]),
            honest,
            UnixSecs::from(1),
            &linked,
            every_key,
        );

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
            every_key,
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

    /// An endpoint has one trusted signer and a signer one trusted endpoint. The two directions of
    /// the table agree after a takeover, a move, a forget and a retain.
    #[test]
    fn the_trust_of_an_endpoint_and_the_trust_of_a_signer_agree_in_both_directions() {
        let _guard = ::habilis_network_test_tracing::init();
        let (first, second) = (
            AuthorKey::from_bytes([1; 32]),
            AuthorKey::from_bytes([2; 32]),
        );
        let one = SecretKey::from_bytes(&[11; 32]).public();
        let two = SecretKey::from_bytes(&[12; 32]).public();
        let mut proven = ProvenEndpoints::new(8);

        proven.trust(first, one);
        proven.trust(second, one);
        assert_eq!(
            proven.trusted_signer(one),
            Some(second),
            "the endpoint has one signer"
        );
        assert_eq!(
            proven.trusted(&first),
            None,
            "the displaced signer lost its trust"
        );

        proven.trust(second, two);
        assert_eq!(
            proven.trusted_signer(one),
            None,
            "the endpoint that the signer left"
        );
        assert_eq!(
            proven.trusted_signer(two),
            Some(second),
            "the endpoint that it took"
        );

        proven.forget_trust(&second);
        assert_eq!(
            proven.trusted_signer(two),
            None,
            "a forgotten signer holds no endpoint"
        );

        proven.trust(first, one);
        proven.trust(second, two);
        proven.retain_trusted(|signer| *signer == first);
        assert_eq!(
            proven.trusted_signer(one),
            Some(first),
            "the kept signer holds its endpoint"
        );
        assert_eq!(
            proven.trusted_signer(two),
            None,
            "the refused signer holds none"
        );

        proven.forget_endpoint(one);
        assert_eq!(
            proven.trusted(&first),
            None,
            "a forgotten endpoint has no signer"
        );
    }

    /// The pair of an endpoint and the trust in it can name two signers: a newer `PeerInfo` of a
    /// key that is not in the roster yet takes the pair, and the roster still trusts the old key.
    /// The old key is live, so a `PeerInfo` that is not newer than the stamp held must not take
    /// the endpoint from it, whoever holds the pair.
    #[test]
    fn a_live_trusted_key_keeps_its_endpoint_when_the_pair_names_a_key_that_is_not_live() {
        let _guard = ::habilis_network_test_tracing::init();
        let (trusted, newcomer, claimant) = (
            AuthorKey::from([1; 32]),
            AuthorKey::from([2; 32]),
            AuthorKey::from([3; 32]),
        );
        let endpoint = SecretKey::generate().public();
        let none = HashSet::new();
        let only_trusted_is_live = |holder: &AuthorKey| *holder == trusted;
        let mut proven = ProvenEndpoints::new(4);
        proven.insert(trusted, endpoint, UnixSecs::from(10), &none, every_key);
        proven.trust(trusted, endpoint);
        proven.insert(newcomer, endpoint, UnixSecs::from(20), &none, every_key);

        proven.insert(
            claimant,
            endpoint,
            UnixSecs::from(20),
            &none,
            only_trusted_is_live,
        );

        assert_eq!(
            proven.get(&claimant),
            None,
            "a stamp that is not newer took the endpoint from the live trusted key"
        );
    }

    /// The cap can take a pair out of `by_signer` while the endpoint is still trusted. The stamp
    /// of that endpoint must stay: without it an older `PeerInfo` of another signer reclaims the
    /// endpoint, and the trust moves from the current signer to the replayed one.
    #[test]
    fn the_replay_stamp_of_a_trusted_endpoint_outlives_its_pair() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut proven = ProvenEndpoints::new(1);
        let current = AuthorKey::from([1; 32]);
        let held = SecretKey::generate().public();
        let none = HashSet::new();
        proven.insert(current, held, UnixSecs::from(10), &none, every_key);
        proven.trust(current, held);

        let other = SecretKey::generate().public();
        proven.insert(
            AuthorKey::from([2; 32]),
            other,
            UnixSecs::from(1),
            &none,
            every_key,
        );
        assert_eq!(
            proven.get(&current),
            None,
            "the cap took the pair of the current signer out"
        );

        let replayed = AuthorKey::from([3; 32]);
        proven.insert(replayed, held, UnixSecs::from(5), &none, every_key);
        assert_eq!(
            proven.get(&replayed),
            None,
            "a PeerInfo older than the proof of the trusted signer does not reclaim the endpoint"
        );
        assert_eq!(
            proven.trusted(&current),
            Some(held),
            "the current signer stays trusted"
        );
    }
}
