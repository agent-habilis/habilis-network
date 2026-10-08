//! Link-state dissemination: a peer's advertised **link-vector** (the links it
//! measures itself, plus its own underlay dial address) and the assembly of many
//! peers' vectors into the routing [`Graph`] and concrete source [`Route`]s.
//!
//! Each origin advertises only its *own* outbound links and its own underlay
//! address, carrying a monotonic `seq` so a newer vector supersedes an older one
//! (last-writer-wins per origin). Every node folds the freshest vector from each
//! origin into one metric-weighted graph and runs Dijkstra locally.

use std::collections::HashMap;

use iroh::{EndpointAddr, EndpointId, SecretKey};
use iroh_base::Signature;
use n0_future::time::{Duration, Instant, SystemTime};
use serde::{Deserialize, Serialize};

use crate::addr::{Route, RouteHop};
use crate::graph::Graph;
use crate::metric::LinkMetric;

/// How long a vector stays without a newer one, unless the handle says otherwise.
pub(crate) const DEFAULT_VECTOR_MAX_AGE: Duration = Duration::from_secs(45);

/// Milliseconds since the Unix epoch: what a vector's `seq` counts.
pub(crate) fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// What a link-vector signature covers, so a signature made for anything else
/// with the same key can never be replayed as one.
const LINK_VECTOR_DOMAIN: &[u8] = b"habilis-network-iroh-multihop-transport link-vector v1\0";

/// One peer's advertised view of its **own** outbound links plus how to dial its
/// multihop underlay — the gossiped payload. `seq` orders successive vectors
/// from the same `origin`; it is the origin's wall-clock time in milliseconds,
/// so a restart does not start again at 1 and lose to the vectors it sent
/// before, and a vector older than the max age is refused.
///
/// Signed by the origin's own key. The `origin` field is the verifying key, so
/// the proof needs nothing else: a node cannot advertise an underlay address, or
/// a link, in another peer's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkVector {
    pub(crate) origin: EndpointId,
    pub(crate) seq: u64,
    /// How to reach this origin's multihop **underlay** endpoint. A hop with no
    /// advertised underlay address cannot be dialed, so any route through it is
    /// dropped.
    pub(crate) underlay: EndpointAddr,
    pub(crate) links: Vec<(EndpointId, LinkMetric)>,
    /// The origin's signature over every field above.
    pub(crate) sig: Signature,
}

fn signing_bytes(
    origin: &EndpointId,
    seq: u64,
    underlay: &EndpointAddr,
    links: &[(EndpointId, LinkMetric)],
) -> Vec<u8> {
    let mut bytes = LINK_VECTOR_DOMAIN.to_vec();
    bytes.extend(
        postcard::to_allocvec(&(origin, seq, underlay, links)).expect("a link vector serializes"),
    );
    bytes
}

impl LinkVector {
    /// Build a vector from this node's direct neighbours and their measured
    /// costs, signed with `secret`, whose public key becomes the origin.
    /// `underlay` is our own underlay [`EndpointAddr`], advertised so peers can
    /// route through us.
    #[must_use]
    pub fn signed(
        secret: &SecretKey,
        seq: u64,
        underlay: EndpointAddr,
        links: Vec<(EndpointId, u32)>,
    ) -> Self {
        let origin = secret.public();
        let links: Vec<(EndpointId, LinkMetric)> = links
            .into_iter()
            .map(|(id, cost)| (id, LinkMetric(cost)))
            .collect();
        let sig = secret.sign(&signing_bytes(&origin, seq, &underlay, &links));
        Self {
            origin,
            seq,
            underlay,
            links,
            sig,
        }
    }

    /// The endpoint id that made this vector and signed it.
    #[must_use]
    pub fn origin(&self) -> EndpointId {
        self.origin
    }

    /// Whether the origin signed exactly these fields.
    fn is_signed_by_origin(&self) -> bool {
        let bytes = signing_bytes(&self.origin, self.seq, &self.underlay, &self.links);
        self.origin.verify(&bytes, &self.sig).is_ok()
    }
}

/// The received link-vectors, kept freshest-per-origin — the routing table's raw
/// material. [`route_to`](Topology::route_to) folds them into the graph on demand.
#[derive(Debug)]
pub struct Topology {
    vectors: HashMap<EndpointId, Held>,
    /// Origins removed or expired, with the highest `seq` held for each. A vector
    /// at or below it is refused for one max age, so the last vector of a peer
    /// that left cannot come back as if new (a late joiner gets it again through
    /// anti-entropy).
    tombstones: HashMap<EndpointId, Tombstone>,
    max_age: Duration,
    /// When a vector last refused for its age was reported in the log.
    last_skew_report: Option<Instant>,
}

impl Default for Topology {
    fn default() -> Self {
        Self::with_max_age(DEFAULT_VECTOR_MAX_AGE)
    }
}

/// A removed origin's highest `seq`, and when it was removed.
#[derive(Debug)]
struct Tombstone {
    seq: u64,
    at: Instant,
}

/// A held vector and when a newer one last arrived for its origin.
#[derive(Debug)]
struct Held {
    vector: LinkVector,
    received: Instant,
}

impl Topology {
    /// An empty table whose vectors live for `max_age` without a newer one.
    ///
    /// The age is also how old a vector may be when it arrives, and how long a
    /// removed origin is remembered. It trades two things: a short age drops a
    /// peer that only missed a tick or two under load, and a long one keeps the
    /// routes of a crashed peer. A peer's clock more than `max_age` behind ours
    /// has its vectors refused.
    #[must_use]
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            vectors: HashMap::new(),
            tombstones: HashMap::new(),
            max_age,
            last_skew_report: None,
        }
    }

    /// Whether to report a vector refused for its age now: once per max age. A
    /// peer with a wrong clock sends a vector every 15 s, so without this limit
    /// it is one line each time, and the limit is global so that a flood of keys
    /// cannot grow it.
    fn should_report_skew(&mut self, now: Instant) -> bool {
        if self
            .last_skew_report
            .is_some_and(|at| now.duration_since(at) < self.max_age)
        {
            return false;
        }
        self.last_skew_report = Some(now);
        true
    }

    /// Ingest a received vector, keeping it only if its origin signed it, it is
    /// not older than the max age, it is above what we removed for that origin,
    /// and it is newer (`seq`) than what we hold. Returns whether the store
    /// changed.
    pub fn ingest(&mut self, vector: LinkVector) -> bool {
        self.ingest_at(vector, Instant::now(), wall_clock_ms())
    }

    /// [`ingest`](Self::ingest) at a given time, for the age-out. Only a newer
    /// vector is fresh: a peer that has gone cannot be kept alive by a copy of
    /// its last vector turning up again.
    pub fn ingest_at(&mut self, vector: LinkVector, now: Instant, wall_ms: u64) -> bool {
        if !vector.is_signed_by_origin() {
            return false;
        }
        let behind_ms = wall_ms.saturating_sub(vector.seq);
        if u128::from(behind_ms) > self.max_age.as_millis() {
            if self.should_report_skew(now) {
                tracing::warn!(
                    origin = %vector.origin.fmt_short(),
                    skew_secs = behind_ms / 1000,
                    max_age_secs = self.max_age.as_secs(),
                    "link-state refused: the sender's clock is behind ours by more than \
                     the max age (or ours is ahead), so it is no hop and no destination \
                     until the clocks agree"
                );
            }
            return false;
        }
        if self
            .tombstones
            .get(&vector.origin)
            .is_some_and(|gone| vector.seq <= gone.seq)
        {
            return false;
        }
        match self.vectors.get(&vector.origin) {
            Some(existing) if existing.vector.seq >= vector.seq => false,
            _ => {
                self.tombstones.remove(&vector.origin);
                self.vectors.insert(
                    vector.origin,
                    Held {
                        vector,
                        received: now,
                    },
                );
                true
            }
        }
    }

    /// Drop an origin's advertised links (e.g. when the peer leaves the mesh) and
    /// remember its highest `seq`. Returns whether anything was removed.
    pub fn remove(&mut self, origin: EndpointId) -> bool {
        self.remove_at(origin, Instant::now())
    }

    fn remove_at(&mut self, origin: EndpointId, now: Instant) -> bool {
        let Some(held) = self.vectors.remove(&origin) else {
            return false;
        };
        self.tombstones.insert(
            origin,
            Tombstone {
                seq: held.vector.seq,
                at: now,
            },
        );
        true
    }

    /// Drop every vector whose newest version arrived more than the max age
    /// before `now`: the peer crashed, or left without a word, and its edges must
    /// not stay in the graph. Also forgets tombstones older than the max age.
    /// Returns how many vectors were dropped.
    pub fn expire_older_than(&mut self, now: Instant) -> usize {
        let max_age = self.max_age;
        let expired: Vec<EndpointId> = self
            .vectors
            .iter()
            .filter(|(_, held)| now.saturating_duration_since(held.received) > max_age)
            .map(|(origin, _)| *origin)
            .collect();
        for origin in &expired {
            self.remove_at(*origin, now);
        }
        self.tombstones
            .retain(|_, gone| now.saturating_duration_since(gone.at) <= max_age);
        expired.len()
    }

    /// The underlay address an origin advertised, for dialing a hop through it.
    pub(crate) fn underlay_of(&self, origin: EndpointId) -> Option<EndpointAddr> {
        self.vectors
            .get(&origin)
            .map(|held| held.vector.underlay.clone())
    }

    /// The application id of the origin whose advertised underlay endpoint is
    /// `underlay_id`, if we hold a vector from it.
    #[must_use]
    pub fn app_id_of(&self, underlay_id: EndpointId) -> Option<EndpointId> {
        self.vectors
            .iter()
            .find(|(_, held)| held.vector.underlay.id == underlay_id)
            .map(|(origin, _)| *origin)
    }

    /// Up to `max_paths` **node-disjoint** source [`Route`]s from `src` to `dst`,
    /// shortest first — the primary plus failover candidates. A route is dropped
    /// if any hop hasn't advertised its underlay address yet (we can't dial a hop
    /// we can't reach), so the returned list may be shorter than `max_paths` or
    /// empty.
    #[must_use]
    pub fn route_to(&self, src: EndpointId, dst: EndpointId, max_paths: usize) -> Vec<Route> {
        self.graph()
            .disjoint_paths(src, dst, max_paths)
            .iter()
            .filter_map(|path| self.route_of(path))
            .collect()
    }

    /// The shortest [`Route`] from `src` to `dst` that does not start with a hop in
    /// `refused`, with the same filter on underlay addresses as [`Self::route_to`].
    /// The destination can be a refused first hop: a direct link is skipped too.
    #[must_use]
    pub(crate) fn route_to_avoiding_first_hops(
        &self,
        src: EndpointId,
        dst: EndpointId,
        refused: &std::collections::HashSet<EndpointId>,
    ) -> Option<Route> {
        let path = self
            .graph()
            .shortest_path_avoiding_first_hops(src, dst, refused)?;
        self.route_of(&path)
    }

    /// `path` as a dialable [`Route`], or `None` if a hop has not advertised its
    /// underlay address yet (we can't dial a hop we can't reach).
    fn route_of(&self, path: &crate::graph::Path) -> Option<Route> {
        let hops = path
            .hops
            .iter()
            .map(|hop| {
                self.underlay_of(*hop).map(|underlay| RouteHop {
                    app_id: *hop,
                    underlay,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Route::new(hops)
    }

    /// A JSON-serializable snapshot of the routing graph from `self_id`'s point
    /// of view — every metric-labelled edge assembled from the held vectors, plus
    /// which node is "us". Backs the `topology` IPC query.
    #[must_use]
    pub fn view(&self, self_id: EndpointId) -> TopologyView {
        let edges = self
            .vectors
            .values()
            .map(|held| &held.vector)
            .flat_map(|vector| {
                vector.links.iter().map(move |(to, metric)| TopologyEdge {
                    from: vector.origin.to_string(),
                    to: to.to_string(),
                    metric: metric.0,
                })
            })
            .collect();
        TopologyView {
            self_id: self_id.to_string(),
            edges,
        }
    }

    /// The directed, metric-weighted graph assembled from every held vector.
    fn graph(&self) -> Graph {
        let mut graph = Graph::default();
        for held in self.vectors.values() {
            let vector = &held.vector;
            for (neighbor, metric) in &vector.links {
                graph.insert_link(vector.origin, *neighbor, *metric);
            }
        }
        graph
    }
}

/// A node's-eye view of the routing graph, ready to serialize to JSON for the
/// `topology` IPC query.
#[derive(Debug, serde::Serialize)]
pub struct TopologyView {
    /// This node's own endpoint id (hex) — the graph's "you".
    pub self_id: String,
    pub edges: Vec<TopologyEdge>,
}

/// One directed, metric-labelled edge in a [`TopologyView`].
#[derive(Debug, serde::Serialize)]
pub struct TopologyEdge {
    pub from: String,
    pub to: String,
    pub metric: u32,
}

#[cfg(test)]
mod tests {
    use n0_future::time::{Duration, Instant};

    use super::{LinkVector, Topology};
    use iroh::{EndpointAddr, EndpointId, SecretKey};

    fn eid(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// The key behind an id the tests made with `eid`.
    fn secret_of(origin: EndpointId) -> SecretKey {
        (0..=u8::MAX)
            .map(|seed| SecretKey::from_bytes(&[seed; 32]))
            .find(|secret| secret.public() == origin)
            .expect("the id was made by `eid`")
    }

    fn vector(origin: EndpointId, seq: u64, links: &[(EndpointId, u32)]) -> LinkVector {
        LinkVector::signed(
            &secret_of(origin),
            seq,
            EndpointAddr::new(origin),
            links.iter().map(|(to, cost)| (*to, *cost)).collect(),
        )
    }

    /// Ingest a vector as if it arrived when its own clock said it was made.
    fn ingest(store: &mut Topology, vector: LinkVector) -> bool {
        let wall = vector.seq;
        store.ingest_at(vector, Instant::now(), wall)
    }

    fn secs(count: u64) -> Duration {
        Duration::from_secs(count)
    }

    #[test]
    fn a_vector_that_claims_another_origin_is_refused() {
        // Mallory broadcasts a vector as the victim and points the victim's
        // underlay at her own address: every route through the victim would
        // then go to her.
        let (victim, mallory, other) = (eid(1), eid(9), eid(2));
        let mut store = Topology::default();
        let mut forged = vector(mallory, 1, &[(other, 1)]);
        forged.origin = victim;
        forged.underlay = EndpointAddr::new(mallory);
        assert!(
            !ingest(&mut store, forged),
            "a vector the origin did not sign is refused"
        );
        assert!(store.view(other).edges.is_empty());
    }

    #[test]
    fn a_vector_changed_after_signing_is_refused() {
        let (na, nb, nc) = (eid(1), eid(2), eid(3));
        let mut store = Topology::default();
        let mut tampered = vector(na, 1, &[(nb, 10)]);
        tampered.links.push((nc, crate::metric::LinkMetric(1)));
        assert!(!ingest(&mut store, tampered));
        let mut moved = vector(na, 1, &[(nb, 10)]);
        moved.underlay = EndpointAddr::new(nc);
        assert!(
            !ingest(&mut store, moved),
            "the underlay address is signed too"
        );
        assert!(ingest(&mut store, vector(na, 1, &[(nb, 10)])));
    }

    #[test]
    fn a_vector_refused_for_its_age_is_reported_once_per_max_age() {
        let mut store = Topology::default();
        let start = Instant::now();
        assert!(store.should_report_skew(start), "the first is reported");
        assert!(
            !store.should_report_skew(start + secs(15)),
            "the same peer every 15 s is one line"
        );
        assert!(
            store.should_report_skew(start + secs(46)),
            "reported again after the max age"
        );
        // The refusal itself does not depend on the report.
        let (na, nb) = (eid(1), eid(2));
        assert!(
            !store.ingest_at(vector(na, 1_000, &[(nb, 1)]), start, 1_000 + 46_000),
            "a vector 46 s behind our clock is refused"
        );
    }

    #[test]
    fn a_stale_vector_ages_out() {
        let (na, nb) = (eid(1), eid(2));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(store.ingest_at(vector(na, 1_000, &[(nb, 1)]), start, 1_000));
        assert!(store.ingest_at(vector(nb, 1_000, &[(na, 1)]), start, 1_000));
        // `na` speaks again, `nb` has crashed and says nothing.
        let later = start + secs(46);
        assert!(store.ingest_at(vector(na, 41_000, &[(nb, 1)]), start + secs(40), 41_000));
        assert_eq!(store.expire_older_than(later), 1);
        assert!(
            store
                .view(na)
                .edges
                .iter()
                .all(|edge| edge.from == na.to_string()),
            "no edge of the crashed peer is left"
        );
        assert!(
            store.route_to(na, nb, 1).is_empty(),
            "its underlay is gone too"
        );
    }

    #[test]
    fn a_copy_of_an_old_vector_does_not_keep_a_gone_peer_alive() {
        let (na, nb) = (eid(1), eid(2));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(store.ingest_at(vector(na, 7_000, &[(nb, 1)]), start, 7_000));
        assert!(
            !store.ingest_at(vector(na, 7_000, &[(nb, 1)]), start + secs(46), 7_000),
            "same seq is not fresh"
        );
        assert_eq!(store.expire_older_than(start + secs(46)), 1);
    }

    #[test]
    fn a_vector_that_was_expired_does_not_come_back() {
        // The peer's last vector arrives again after the age-out, through
        // anti-entropy: it must not read as new.
        let (na, nb) = (eid(1), eid(2));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(store.ingest_at(vector(nb, 7_000, &[(na, 1)]), start, 7_000));
        assert_eq!(store.expire_older_than(start + secs(46)), 1);
        assert!(
            !store.ingest_at(vector(nb, 7_000, &[(na, 1)]), start + secs(46), 30_000),
            "the same vector again is refused"
        );
        // Tombstones are kept for one max age, then forgotten.
        assert_eq!(store.expire_older_than(start + secs(92)), 0);
    }

    #[test]
    fn a_vector_of_a_peer_that_left_does_not_come_back() {
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        assert!(ingest(&mut store, vector(nb, 7_000, &[(na, 1)])));
        assert!(store.remove(nb), "Left removes the vector");
        assert!(
            !ingest(&mut store, vector(nb, 7_000, &[(na, 1)])),
            "refused after Left"
        );
        assert!(
            ingest(&mut store, vector(nb, 8_000, &[(na, 1)])),
            "a newer vector from the same peer is accepted"
        );
    }

    #[test]
    fn a_node_whose_vector_expired_returns_with_its_next_one() {
        // A node that missed ticks under load is expired by every peer. Its
        // next vector must bring it back, not be held off by the tombstone.
        let (na, nb) = (eid(1), eid(2));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(store.ingest_at(vector(nb, 1_000, &[(na, 1)]), start, 1_000));
        assert_eq!(store.expire_older_than(start + secs(46)), 1);
        assert!(store.ingest_at(vector(nb, 47_000, &[(na, 1)]), start + secs(47), 47_000));
        assert_eq!(store.view(na).edges.len(), 1);
    }

    #[test]
    fn a_vector_older_than_the_max_age_is_refused() {
        // The replay a member with old vectors can try after a restart, or
        // against a late joiner.
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        assert!(!store.ingest_at(
            vector(nb, 1_000, &[(na, 1)]),
            Instant::now(),
            1_000 + 45_001
        ));
        assert!(store.ingest_at(
            vector(nb, 1_000, &[(na, 1)]),
            Instant::now(),
            1_000 + 45_000
        ));
    }

    #[test]
    fn after_a_restart_the_first_new_vector_wins() {
        // seq is wall-clock milliseconds, so a node that restarts with the same
        // key does not start again at 1 and lose to what it sent before.
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        assert!(ingest(&mut store, vector(nb, 100_000, &[(na, 1)])));
        assert!(
            ingest(&mut store, vector(nb, 100_050, &[(na, 5)])),
            "the first vector after the restart is above the last one before it"
        );
        assert_eq!(store.view(na).edges[0].metric, 5);
    }

    #[test]
    fn newer_vector_supersedes_older() {
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        assert!(ingest(&mut store, vector(na, 2_000, &[(nb, 10)])));
        assert!(!ingest(&mut store, vector(na, 1_000, &[(nb, 1)])));
        assert!(ingest(&mut store, vector(na, 3_000, &[(nb, 1)])));
    }

    #[test]
    fn route_traces_the_chain_and_carries_underlay_addrs() {
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nb, 1)]));
        ingest(&mut store, vector(nb, 1, &[(nc, 1)]));
        ingest(&mut store, vector(nc, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nd, 1, &[]));
        let routes = store.route_to(na, nd, 3);
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0]
                .hops()
                .iter()
                .map(|hop| hop.app_id)
                .collect::<Vec<_>>(),
            vec![nb, nc, nd]
        );
        // Every hop carries a dialable underlay addr for that node.
        assert_eq!(routes[0].hops()[0].underlay, EndpointAddr::new(nb));
    }

    #[test]
    fn a_known_underlay_maps_to_its_app_id() {
        let (alice, bob) = (eid(1), eid(2));
        let (alice_underlay, bob_underlay) = (eid(101), eid(102));
        let mut store = Topology::default();
        for (origin, underlay) in [(alice, alice_underlay), (bob, bob_underlay)] {
            let signed = LinkVector::signed(
                &secret_of(origin),
                1,
                EndpointAddr::new(underlay),
                Vec::new(),
            );
            ingest(&mut store, signed);
        }
        assert_eq!(store.app_id_of(bob_underlay), Some(bob));
        assert_eq!(store.app_id_of(alice_underlay), Some(alice));
        assert_eq!(store.app_id_of(eid(103)), None, "an unknown underlay");
        assert_eq!(
            store.app_id_of(bob),
            None,
            "an app id is not an underlay id"
        );
    }

    #[test]
    fn a_hop_without_an_underlay_addr_drops_the_route() {
        let (na, nb, nc) = (eid(1), eid(2), eid(3));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nb, 1)]));
        ingest(&mut store, vector(nb, 1, &[(nc, 1)]));
        // nc never advertised its own vector, so its underlay addr is unknown.
        assert!(
            store.route_to(na, nc, 3).is_empty(),
            "missing hop underlay ⇒ no usable route"
        );
    }

    #[test]
    fn prefers_the_cheaper_direct_over_the_chain() {
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nb, 1), (nd, 1)]));
        ingest(&mut store, vector(nb, 1, &[(nc, 1)]));
        ingest(&mut store, vector(nc, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nd, 1, &[]));
        let routes = store.route_to(na, nd, 3);
        assert_eq!(
            routes.len(),
            1,
            "the interior-less direct route ends the search"
        );
        assert_eq!(
            routes[0]
                .hops()
                .iter()
                .map(|hop| hop.app_id)
                .collect::<Vec<_>>(),
            vec![nd]
        );
    }

    #[test]
    fn returns_disjoint_alternates() {
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nb, 1), (nc, 1)]));
        ingest(&mut store, vector(nb, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nc, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nd, 1, &[]));
        let routes = store.route_to(na, nd, 3);
        assert_eq!(routes.len(), 2, "both diamond arms");
        assert_ne!(routes[0].hops()[0].app_id, routes[1].hops()[0].app_id);
    }
}
