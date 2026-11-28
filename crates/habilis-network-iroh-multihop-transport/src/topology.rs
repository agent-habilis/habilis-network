//! Link-state dissemination: a peer's advertised **link-vector** (the links it
//! measures itself, plus its own underlay dial address) and the assembly of many
//! peers' vectors into the routing [`Graph`] that each node reads its next hops from.
//!
//! Each origin advertises only its *own* outbound links and its own underlay
//! address, carrying a monotonic `seq` so a newer vector supersedes an older one
//! (last-writer-wins per origin). Every node folds the freshest vector from each
//! origin into one metric-weighted graph and runs Dijkstra locally.

use std::collections::{HashMap, HashSet};

use iroh::{EndpointAddr, SecretKey};
use iroh_base::Signature;
use n0_future::time::{Duration, Instant, SystemTime};
use serde::{Deserialize, Serialize};

use crate::app_id::{AppId, UnderlayId};
use crate::graph::{Graph, Link};
use crate::link_metric::LinkMetric;
use crate::next_hop;
use crate::next_hop::NextHop;
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
///
/// # Examples
///
/// A link vector is signed by its origin, and its origin is the key that signed it.
///
/// ```
/// use habilis_network_iroh_multihop_transport::{AppId, LinkVector};
/// use iroh_base::{EndpointAddr, SecretKey};
///
/// let secret = SecretKey::from_bytes(&[1u8; 32]);
/// let vector = LinkVector::signed(&secret, 1, EndpointAddr::new(secret.public()), Vec::new());
/// assert_eq!(vector.origin(), AppId::new(secret.public()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkVector {
    pub(crate) origin: AppId,
    pub(crate) seq: u64,
    /// How to reach this origin's multihop **underlay** endpoint. A hop with no
    /// advertised underlay address cannot be dialed, so any route through it is
    /// dropped.
    pub(crate) underlay: EndpointAddr,
    pub(crate) links: Vec<(AppId, LinkMetric)>,
    /// The origin's signature over every field above.
    #[serde(rename = "sig")]
    pub(crate) signature: Signature,
}

fn signing_bytes(
    origin: &AppId,
    seq: u64,
    underlay: &EndpointAddr,
    links: &[(AppId, LinkMetric)],
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
        links: Vec<(AppId, u32)>,
    ) -> Self {
        let origin = AppId::new(secret.public());
        let links: Vec<(AppId, LinkMetric)> = links
            .into_iter()
            .map(|(id, cost)| (id, LinkMetric::new(cost)))
            .collect();
        let signature = secret.sign(&signing_bytes(&origin, seq, &underlay, &links));
        Self {
            origin,
            seq,
            underlay,
            links,
            signature,
        }
    }

    /// The endpoint id that made this vector and signed it.
    #[must_use]
    pub fn origin(&self) -> AppId {
        self.origin
    }

    /// Whether the origin signed exactly these fields.
    fn is_signed_by_origin(&self) -> bool {
        let bytes = signing_bytes(&self.origin, self.seq, &self.underlay, &self.links);
        self.origin.get().verify(&bytes, &self.signature).is_ok()
    }
}

/// The received link-vectors, kept freshest-per-origin — the routing table's raw
/// material. The next hop of a cell is read from them: they are folded into a graph on demand.
///
/// # Examples
///
/// A topology accepts a signed link vector from a member.
///
/// ```
/// use std::time::Duration;
///
/// use habilis_network_iroh_multihop_transport::{LinkVector, Topology};
/// use iroh_base::{EndpointAddr, SecretKey};
///
/// let secret = SecretKey::from_bytes(&[1u8; 32]);
/// let vector = LinkVector::signed(&secret, 1, EndpointAddr::new(secret.public()), Vec::new());
/// let mut topology = Topology::with_max_age(Duration::from_secs(60));
/// assert!(topology.ingest_at(vector, tokio::time::Instant::now(), 1));
/// ```
#[derive(Debug)]
pub struct Topology {
    vectors: HashMap<AppId, Held>,
    /// Origins removed or expired, with the highest `seq` held for each. A vector
    /// at or below it is refused for one max age, so the last vector of a peer
    /// that left cannot come back as if new (a late joiner gets it again at its
    /// next advertisement).
    tombstones: HashMap<AppId, Tombstone>,
    max_age: Duration,
    /// When a vector last refused for its age was reported in the log.
    last_skew_report: Option<Instant>,
    /// Raised each time the held vectors change, so a value that was computed from the graph can tell that it is
    /// stale without reading the graph.
    generation: u64,
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
            generation: 0,
        }
    }

    /// The number of changes that the held vectors have had: it rises when a vector is taken in or removed, and
    /// never when a vector is refused or only renewed in place.
    #[must_use]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
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
                self.generation += 1;
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
    pub fn remove(&mut self, origin: AppId) -> bool {
        self.remove_at(origin, Instant::now())
    }

    fn remove_at(&mut self, origin: AppId, now: Instant) -> bool {
        let Some(held) = self.vectors.remove(&origin) else {
            return false;
        };
        self.generation += 1;
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
        let stale = self
            .vectors
            .iter()
            .filter(|(_, held)| now.saturating_duration_since(held.received) > max_age);
        let expired: Vec<AppId> = stale.map(|(origin, _)| *origin).collect();
        for origin in &expired {
            self.remove_at(*origin, now);
        }
        self.tombstones
            .retain(|_, gone| now.saturating_duration_since(gone.at) <= max_age);
        expired.len()
    }

    /// Whether a vector of `origin` was held and removed inside the last max age: the peer
    /// left, or its vector expired.
    #[must_use]
    pub fn is_gone(&self, origin: AppId) -> bool {
        self.tombstones.contains_key(&origin)
    }

    /// The underlay address an origin advertised, for dialing a hop through it.
    pub(crate) fn underlay_of(&self, origin: AppId) -> Option<EndpointAddr> {
        self.vectors
            .get(&origin)
            .map(|held| held.vector.underlay.clone())
    }

    /// The application id of the origin whose advertised underlay endpoint is
    /// `underlay_id`, if we hold a vector from it.
    #[must_use]
    pub fn app_id_of(&self, underlay_id: UnderlayId) -> Option<AppId> {
        self.vectors
            .iter()
            .find(|(_, held)| UnderlayId::new(held.vector.underlay.id) == underlay_id)
            .map(|(origin, _)| *origin)
    }

    /// The next hop of a cell at `node` for `dst`, from the vectors that we hold, with the hops that are stuck
    /// removed and the hops in wait behind the others: see [`next_hop::next_hop`]. No cell came from anywhere
    /// here (`from` is applied by the caller).
    pub(crate) fn next_hop(
        &self,
        node: AppId,
        dst: AppId,
        stuck: &HashSet<AppId>,
        waiting: &HashSet<AppId>,
    ) -> NextHop {
        let graph = self.graph();
        // A neighbor with no vector has no underlay address: this node cannot dial it, so it is no candidate
        // until its vector is here.
        let links = graph.links_of(node).iter();
        let known = links.filter(|(neighbor, _)| self.vectors.contains_key(neighbor));
        let dialable: Vec<(AppId, LinkMetric)> = known.copied().collect();
        next_hop::next_hop(
            &dialable,
            &graph.distances_to(dst),
            next_hop::GateView { waiting, stuck },
            None,
        )
    }

    /// A JSON-serializable snapshot of the routing graph from `self_id`'s point
    /// of view — every metric-labelled edge assembled from the held vectors, plus
    /// which node is "us". Backs the `topology` IPC query.
    #[must_use]
    pub fn view(&self, self_id: AppId) -> TopologyView {
        let edges: Vec<TopologyEdge> = self
            .vectors
            .values()
            .map(|held| &held.vector)
            .flat_map(|vector| {
                vector.links.iter().map(move |(to, metric)| TopologyEdge {
                    from: vector.origin.to_string(),
                    to: to.to_string(),
                    metric: metric.get(),
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
                graph.insert_link(Link {
                    from: vector.origin,
                    to: *neighbor,
                    cost: *metric,
                });
            }
        }
        graph
    }
}

/// A node's-eye view of the routing graph, ready to serialize to JSON for the
/// `topology` IPC query.
///
/// # Examples
///
/// A view of the topology serializes for a caller that prints it.
///
/// ```
/// use std::time::Duration;
///
/// use habilis_network_iroh_multihop_transport::{AppId, Topology};
/// use iroh_base::SecretKey;
///
/// let topology = Topology::with_max_age(Duration::from_secs(60));
/// let view = topology.view(AppId::new(SecretKey::from_bytes(&[1u8; 32]).public()));
/// fn assert_serialize<T: serde::Serialize>(_: &T) {}
/// assert_serialize(&view);
/// ```
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct TopologyView {
    /// This node's own endpoint id (hex) — the graph's "you".
    pub self_id: String,
    /// The links of the graph, one per edge.
    pub edges: Vec<TopologyEdge>,
}

/// One directed, metric-labelled edge in a [`TopologyView`].
///
/// # Examples
///
/// The topology view builds an edge, and a caller outside the crate has no other way to make one, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_multihop_transport::TopologyEdge;
///
/// # fn demo(edge: &TopologyEdge) -> TopologyEdge {
/// edge.clone()
/// # }
/// ```
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct TopologyEdge {
    /// The endpoint id at one end, in hex.
    pub from: String,
    /// The endpoint id at the other end, in hex.
    pub to: String,
    /// The routing cost of the link.
    pub metric: u32,
}

#[cfg(test)]
mod tests {
    use n0_future::time::{Duration, Instant};

    use std::collections::HashSet;

    use super::{LinkVector, Topology};
    use crate::app_id::{AppId, UnderlayId};
    use crate::next_hop::NextHop;
    use iroh::{EndpointAddr, SecretKey};

    use crate::link_metric;
    fn eid(seed: u8) -> AppId {
        AppId::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    /// The key behind an id the tests made with `eid`.
    fn secret_of(origin: AppId) -> SecretKey {
        (0..=u8::MAX)
            .map(|seed| SecretKey::from_bytes(&[seed; 32]))
            .find(|secret| secret.public() == origin.get())
            .expect("the id was made by `eid`")
    }

    fn vector(origin: AppId, seq: u64, links: &[(AppId, u32)]) -> LinkVector {
        LinkVector::signed(
            &secret_of(origin),
            seq,
            EndpointAddr::new(origin.get()),
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

    /// The generation rises when a vector is taken in, and not when a vector is refused: a value computed from the
    /// graph is stale exactly when the generation moved.
    #[test]
    fn the_generation_rises_when_a_vector_is_taken_in_and_not_when_it_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        let start = store.generation();

        assert!(
            ingest(&mut store, vector(na, 7_000, &[(nb, 1)])),
            "the first vector is taken in"
        );
        let after_first = store.generation();
        assert!(
            !ingest(&mut store, vector(na, 7_000, &[(nb, 1)])),
            "the same seq"
        );
        assert!(
            !ingest(&mut store, vector(na, 6_000, &[(nb, 1)])),
            "an older seq"
        );
        let after_refused = store.generation();
        assert!(
            ingest(&mut store, vector(na, 8_000, &[])),
            "a newer vector is taken in"
        );
        let after_newer = store.generation();

        assert!(after_first > start, "a vector that was taken in");
        assert_eq!(after_refused, after_first, "refused vectors change nothing");
        assert!(
            after_newer > after_refused,
            "a newer vector replaces the old"
        );
    }

    /// A removal and an expiry both change the graph, so both raise the generation: a next hop that was cached
    /// from the vector of a hop that left is not used again.
    #[test]
    fn the_generation_rises_when_a_vector_is_removed_or_expires() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc) = (eid(1), eid(2), eid(3));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(
            store.ingest_at(vector(na, 7_000, &[(nc, 1)]), start, 7_000),
            "the vector of na is taken in"
        );
        assert!(
            store.ingest_at(vector(nb, 7_000, &[(nc, 1)]), start, 7_000),
            "the vector of nb is taken in"
        );

        let before_remove = store.generation();
        assert!(store.remove(na), "the vector of na was held");
        let after_remove = store.generation();
        assert!(!store.remove(na), "nothing left to remove");
        let after_second_remove = store.generation();
        assert_eq!(
            store.expire_older_than(start + secs(46)),
            1,
            "the vector of nb expires"
        );
        let after_expiry = store.generation();

        assert!(after_remove > before_remove, "a removal");
        assert_eq!(
            after_second_remove, after_remove,
            "a removal of nothing changes nothing"
        );
        assert!(after_expiry > after_second_remove, "an expiry");
    }

    #[test]
    fn a_vector_that_claims_another_origin_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        // Mallory broadcasts a vector as the victim and points the victim's
        // underlay at her own address: every route through the victim would
        // then go to her.
        let (victim, mallory, other) = (eid(1), eid(9), eid(2));
        let mut store = Topology::default();
        let mut forged = vector(mallory, 1, &[(other, 1)]);
        forged.origin = victim;
        forged.underlay = EndpointAddr::new(mallory.get());
        assert!(
            !ingest(&mut store, forged),
            "a vector the origin did not sign is refused"
        );
        assert!(
            store.view(other).edges.is_empty(),
            "a vector that claims another origin leaves the view empty"
        );
    }

    #[test]
    fn a_vector_changed_after_signing_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc) = (eid(1), eid(2), eid(3));
        let mut store = Topology::default();
        let mut tampered = vector(na, 1, &[(nb, 10)]);
        tampered.links.push((nc, link_metric::LinkMetric::new(1)));
        assert!(
            !ingest(&mut store, tampered),
            "a tampered vector is refused"
        );
        let mut moved = vector(na, 1, &[(nb, 10)]);
        moved.underlay = EndpointAddr::new(nc.get());
        assert!(
            !ingest(&mut store, moved),
            "the underlay address is signed too"
        );
        assert!(
            ingest(&mut store, vector(na, 1, &[(nb, 10)])),
            "the untampered vector is accepted"
        );
    }

    #[test]
    fn a_vector_refused_for_its_age_is_reported_once_per_max_age() {
        let _guard = ::habilis_network_test_tracing::init();
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
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb) = (eid(1), eid(2));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(
            store.ingest_at(vector(na, 1_000, &[(nb, 1)]), start, 1_000),
            "a stale vector is accepted at its time"
        );
        assert!(
            store.ingest_at(vector(nb, 1_000, &[(na, 1)]), start, 1_000),
            "the second stale vector is accepted at its time"
        );
        // `na` speaks again, `nb` has crashed and says nothing.
        let later = start + secs(46);
        assert!(
            store.ingest_at(vector(na, 41_000, &[(nb, 1)]), start + secs(40), 41_000),
            "a newer vector is accepted after the stale ones"
        );
        assert_eq!(store.expire_older_than(later), 1, "one old vector expires");
        assert!(
            store
                .view(na)
                .edges
                .iter()
                .all(|edge| edge.from == na.to_string()),
            "no edge of the crashed peer is left"
        );
        assert_eq!(
            store.next_hop(na, nb, &HashSet::new(), &HashSet::new()),
            NextHop::Unreachable,
            "its underlay is gone too, so it is no next hop"
        );
    }

    #[test]
    fn a_copy_of_an_old_vector_does_not_keep_a_gone_peer_alive() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb) = (eid(1), eid(2));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(
            store.ingest_at(vector(na, 7_000, &[(nb, 1)]), start, 7_000),
            "a copy of an old vector is accepted"
        );
        assert!(
            !store.ingest_at(vector(na, 7_000, &[(nb, 1)]), start + secs(46), 7_000),
            "same seq is not fresh"
        );
        assert_eq!(
            store.expire_older_than(start + secs(46)),
            1,
            "a copy of an old vector expires nothing new"
        );
    }

    #[test]
    fn a_vector_that_was_expired_does_not_come_back() {
        let _guard = ::habilis_network_test_tracing::init();
        // The peer's last vector arrives again after the age-out, through
        // a replay of an old frame: it must not read as new.
        let (na, nb) = (eid(1), eid(2));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(
            store.ingest_at(vector(nb, 7_000, &[(na, 1)]), start, 7_000),
            "an expired vector is accepted again when it returns"
        );
        assert_eq!(
            store.expire_older_than(start + secs(46)),
            1,
            "the returned vector expires nothing at the first window"
        );
        assert!(
            !store.ingest_at(vector(nb, 7_000, &[(na, 1)]), start + secs(46), 30_000),
            "the same vector again is refused"
        );
        // Tombstones are kept for one max age, then forgotten.
        assert_eq!(
            store.expire_older_than(start + secs(92)),
            0,
            "the returned vector expires at the second window"
        );
    }

    #[test]
    fn a_vector_of_a_peer_that_left_does_not_come_back() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        assert!(
            ingest(&mut store, vector(nb, 7_000, &[(na, 1)])),
            "a vector of a peer that left is accepted again"
        );
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
        let _guard = ::habilis_network_test_tracing::init();
        // A node that missed ticks under load is expired by every peer. Its
        // next vector must bring it back, not be held off by the tombstone.
        let (na, nb) = (eid(1), eid(2));
        let start = Instant::now();
        let mut store = Topology::default();
        assert!(
            store.ingest_at(vector(nb, 1_000, &[(na, 1)]), start, 1_000),
            "a node whose vector expired is accepted with its next vector"
        );
        assert_eq!(
            store.expire_older_than(start + secs(46)),
            1,
            "the expired vector is counted once"
        );
        assert!(
            store.ingest_at(vector(nb, 47_000, &[(na, 1)]), start + secs(47), 47_000),
            "the next vector from the node is accepted"
        );
        assert_eq!(
            store.view(na).edges.len(),
            1,
            "the node has one edge after its next vector"
        );
    }

    #[test]
    fn a_vector_older_than_the_max_age_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network_iroh_multihop_transport::topology",
            "link-state refused: the sender's clock is behind ours",
        );
        // The replay a member with old vectors can try after a restart, or
        // against a late joiner.
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        assert!(
            !store.ingest_at(
                vector(nb, 1_000, &[(na, 1)]),
                Instant::now(),
                1_000 + 45_001
            ),
            "a vector older than the max age is refused"
        );
        assert!(
            store.ingest_at(
                vector(nb, 1_000, &[(na, 1)]),
                Instant::now(),
                1_000 + 45_000
            ),
            "a vector older than the max age is refused at its time"
        );
    }

    #[test]
    fn after_a_restart_the_first_new_vector_wins() {
        let _guard = ::habilis_network_test_tracing::init();
        // seq is wall-clock milliseconds, so a node that restarts with the same
        // key does not start again at 1 and lose to what it sent before.
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        assert!(
            ingest(&mut store, vector(nb, 100_000, &[(na, 1)])),
            "after a restart the first new vector wins"
        );
        assert!(
            ingest(&mut store, vector(nb, 100_050, &[(na, 5)])),
            "the first vector after the restart is above the last one before it"
        );
        assert_eq!(
            store.view(na).edges[0].metric,
            5,
            "after a restart the edge keeps the new metric"
        );
    }

    #[test]
    fn newer_vector_supersedes_older() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb) = (eid(1), eid(2));
        let mut store = Topology::default();
        assert!(
            ingest(&mut store, vector(na, 2_000, &[(nb, 10)])),
            "a newer vector supersedes the older one"
        );
        assert!(
            !ingest(&mut store, vector(na, 1_000, &[(nb, 1)])),
            "an older vector is refused once a newer one is held"
        );
        assert!(
            ingest(&mut store, vector(na, 3_000, &[(nb, 1)])),
            "a newer-still vector supersedes the held one"
        );
    }

    /// Each node of a chain picks the next node of the chain as its next hop, from its own table.
    #[test]
    fn each_node_of_a_chain_picks_the_next_node_as_its_next_hop() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nb, 1)]));
        ingest(&mut store, vector(nb, 1, &[(nc, 1)]));
        ingest(&mut store, vector(nc, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nd, 1, &[]));
        let none = HashSet::new();
        assert_eq!(
            store.next_hop(na, nd, &none, &HashSet::new()),
            NextHop::Forward(nb),
            "na reaches nd through nb"
        );
        assert_eq!(
            store.next_hop(nb, nd, &none, &HashSet::new()),
            NextHop::Forward(nc),
            "nb reaches nd through nc"
        );
        assert_eq!(
            store.next_hop(nc, nd, &none, &HashSet::new()),
            NextHop::Forward(nd),
            "nc is next to nd"
        );
    }

    #[test]
    fn a_known_underlay_maps_to_its_app_id() {
        let _guard = ::habilis_network_test_tracing::init();
        let (alice, bob) = (eid(1), eid(2));
        let (alice_underlay, bob_underlay) = (eid(101), eid(102));
        let mut store = Topology::default();
        for (origin, underlay) in [(alice, alice_underlay), (bob, bob_underlay)] {
            let signed = LinkVector::signed(
                &secret_of(origin),
                1,
                EndpointAddr::new(underlay.get()),
                Vec::new(),
            );
            ingest(&mut store, signed);
        }
        let underlay = |id: AppId| UnderlayId::new(id.get());
        assert_eq!(
            store.app_id_of(underlay(bob_underlay)),
            Some(bob),
            "a known underlay maps to bob's app id"
        );
        assert_eq!(
            store.app_id_of(underlay(alice_underlay)),
            Some(alice),
            "a known underlay maps to alice's app id"
        );
        assert_eq!(
            store.app_id_of(underlay(eid(103))),
            None,
            "an unknown underlay"
        );
        assert_eq!(
            store.app_id_of(underlay(bob)),
            None,
            "the key of an app endpoint is not an underlay id"
        );
    }

    /// The origin of a cell needs no vector of the destination: the next hop is a neighbor, and only a neighbor
    /// has to be dialable. A neighbor that has no vector is no next hop.
    #[test]
    fn the_destination_needs_no_vector_and_a_neighbor_without_one_is_no_next_hop() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc) = (eid(1), eid(2), eid(3));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nb, 1)]));
        ingest(&mut store, vector(nb, 1, &[(nc, 1)]));
        // nc never advertised its own vector, so its underlay addr is unknown.
        assert_eq!(
            store.next_hop(na, nc, &HashSet::new(), &HashSet::new()),
            NextHop::Forward(nb),
            "the destination needs no vector: nb is a neighbor with one"
        );
        let mut alone = Topology::default();
        ingest(&mut alone, vector(na, 1, &[(nb, 1)]));
        assert_eq!(
            alone.next_hop(na, nb, &HashSet::new(), &HashSet::new()),
            NextHop::Unreachable,
            "a neighbor with no vector cannot be dialed, so it is no next hop"
        );
    }

    #[test]
    fn prefers_the_cheaper_direct_over_the_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nb, 1), (nd, 1)]));
        ingest(&mut store, vector(nb, 1, &[(nc, 1)]));
        ingest(&mut store, vector(nc, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nd, 1, &[]));
        assert_eq!(
            store.next_hop(na, nd, &HashSet::new(), &HashSet::new()),
            NextHop::Forward(nd),
            "the cheaper direct hop wins over the chain"
        );
    }

    /// The refused set removes only the neighbors of this node from the choice. A neighbor that this node refuses
    /// still counts as a node on the way of another neighbor: A refuses X, and A > H > X > D is still a way.
    #[test]
    fn a_refused_neighbor_is_still_a_node_on_the_way_of_another_neighbor() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nx, nh, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nx, 1), (nh, 1)]));
        ingest(&mut store, vector(nh, 1, &[(nx, 1)]));
        ingest(&mut store, vector(nx, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nd, 1, &[]));

        assert_eq!(
            store.next_hop(na, nd, &HashSet::new(), &HashSet::new()),
            NextHop::Forward(nx),
            "control: with nothing refused the direct neighbor is the best"
        );
        assert_eq!(
            store.next_hop(na, nd, &HashSet::from([nx]), &HashSet::new()),
            NextHop::Forward(nh),
            "a refused x is no next hop of a, and it is still on the way of h"
        );
        let distances = store.graph().distances_to(nd);
        assert_eq!(
            distances.get(&nh).map(|cost| cost.get()),
            Some(2),
            "the distance of h reads the table, which the refused set does not change"
        );
    }

    /// A refused neighbor is removed before the choice: the other arm of a diamond takes over at once.
    #[test]
    fn a_refused_arm_of_a_diamond_gives_way_to_the_other() {
        let _guard = ::habilis_network_test_tracing::init();
        let (na, nb, nc, nd) = (eid(1), eid(2), eid(3), eid(4));
        let mut store = Topology::default();
        ingest(&mut store, vector(na, 1, &[(nb, 1), (nc, 1)]));
        ingest(&mut store, vector(nb, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nc, 1, &[(nd, 1)]));
        ingest(&mut store, vector(nd, 1, &[]));
        let first = store.next_hop(na, nd, &HashSet::new(), &HashSet::new());
        let NextHop::Forward(arm) = first else {
            panic!("a way exists: {first:?}");
        };
        let other = if arm == nb { nc } else { nb };
        assert_eq!(
            store.next_hop(na, nd, &HashSet::from([arm]), &HashSet::new()),
            NextHop::Forward(other),
            "the other arm of the diamond takes over"
        );
    }

    /// What a link costs to a native node, and what a browser advertises for its own links
    /// (decision D5: a route avoids a browser as a hop). They are the values of
    /// `HandleConfig::default()` and `HandleConfig::for_browser()`, and the guard in `lib.rs`
    /// pins the relation between them. The cost is data in the signed vector: nothing in the
    /// route search knows what a browser is.
    const NATIVE_COST: u32 = crate::DEFAULT_LINK_COST;
    const BROWSER_COST: u32 = crate::DEFAULT_LINK_COST * crate::BROWSER_HOP_FACTOR;

    /// The neighbor that `src` picks as the next hop of a cell for `dst`, with no neighbor refused.
    fn first_hop(store: &Topology, src: AppId, dst: AppId) -> Option<AppId> {
        match store.next_hop(src, dst, &HashSet::new(), &HashSet::new()) {
            NextHop::Forward(neighbor) => Some(neighbor),
            NextHop::TurnedBack | NextHop::Unreachable => None,
        }
    }

    /// The cost of the cheapest path from `src` to `dst`.
    fn best_cost(store: &Topology, src: AppId, dst: AppId) -> Option<u32> {
        let distances = store.graph().distances_to(dst);
        distances.get(&src).map(|cost| cost.get())
    }

    /// `src` reaches `dst` by three native hops (`n1`, `n2`, `dst`), or by one browser hop (`tab`)
    /// whose own links cost `tab_cost`.
    fn native_and_browser_routes(tab_cost: u32) -> (Topology, [AppId; 5]) {
        let [src, n1, n2, dst, tab] = [1, 2, 3, 4, 5].map(eid);
        let mut store = Topology::default();
        for (origin, links) in [
            (src, vec![(n1, NATIVE_COST), (tab, NATIVE_COST)]),
            (n1, vec![(n2, NATIVE_COST)]),
            (n2, vec![(dst, NATIVE_COST)]),
            (tab, vec![(dst, tab_cost)]),
            (dst, vec![]),
        ] {
            assert!(
                ingest(&mut store, vector(origin, 1, &links)),
                "a native and a browser vector are accepted together"
            );
        }
        (store, [src, n1, n2, dst, tab])
    }

    #[test]
    fn a_three_hop_native_path_beats_a_one_hop_browser_path() {
        let _guard = ::habilis_network_test_tracing::init();
        let (store, [src, n1, n2, dst, tab]) = native_and_browser_routes(BROWSER_COST);
        assert_eq!(
            first_hop(&store, src, dst),
            Some(n1),
            "a three-hop native path beats a one-hop browser path"
        );
        assert_eq!(
            best_cost(&store, src, dst),
            Some(3 * NATIVE_COST),
            "the best cost is the native path's cost"
        );
        assert_eq!(
            store.next_hop(src, dst, &HashSet::from([n1]), &HashSet::new()),
            NextHop::Forward(tab),
            "the browser way is still a way: it takes over when the native neighbor is refused"
        );
        let _ = n2;

        // The cost is what decides: a tab that advertises the native cost wins by its length.
        let (cheap_tab, [from, _, _, to, cheap]) = native_and_browser_routes(NATIVE_COST);
        assert_eq!(
            first_hop(&cheap_tab, from, to),
            Some(cheap),
            "the cheap tab is the best next hop"
        );
    }

    #[test]
    fn without_the_native_route_the_route_goes_through_the_browser() {
        let _guard = ::habilis_network_test_tracing::init();
        let [alice, bob, carol, tab] = [1, 2, 3, 4].map(eid);
        let mut store = Topology::default();
        for (origin, links) in [
            (alice, vec![(carol, NATIVE_COST), (tab, NATIVE_COST)]),
            (carol, vec![(bob, NATIVE_COST)]),
            (tab, vec![(bob, BROWSER_COST)]),
            (bob, vec![]),
        ] {
            assert!(
                ingest(&mut store, vector(origin, 1, &links)),
                "without the native route the route goes through the browser"
            );
        }
        assert_eq!(
            first_hop(&store, alice, bob),
            Some(carol),
            "the way from alice to the browser is found"
        );

        assert!(store.remove(carol), "carol leaves: her vector is gone");
        assert_eq!(
            first_hop(&store, alice, bob),
            Some(tab),
            "the way through the browser has the browser's hop"
        );
        assert_eq!(
            best_cost(&store, alice, bob),
            Some(NATIVE_COST + BROWSER_COST),
            "the browser hop costs its in-edge and its out-edge"
        );
    }

    #[test]
    fn a_browser_pays_nothing_as_a_destination() {
        let _guard = ::habilis_network_test_tracing::init();
        let [src, dst] = [1, 2].map(eid);
        // The last edge into it is advertised by its predecessor.
        for (name, last_cost) in [("native", NATIVE_COST), ("browser", BROWSER_COST)] {
            let mut store = Topology::default();
            for (origin, links) in [
                (src, vec![(dst, NATIVE_COST)]),
                (dst, vec![(src, last_cost)]),
            ] {
                assert!(
                    ingest(&mut store, vector(origin, 1, &links)),
                    "a browser pays nothing as a destination"
                );
            }
            assert_eq!(
                best_cost(&store, src, dst),
                Some(NATIVE_COST),
                "{name} destination"
            );
        }
    }

    #[test]
    fn the_cost_of_a_source_changes_no_choice() {
        let _guard = ::habilis_network_test_tracing::init();
        let [src, hop, dst, other] = [1, 2, 3, 4].map(eid);
        // Every route starts with one of the edges of the source, so the choice is the same
        // whatever those edges cost.
        for (name, cost) in [("native", NATIVE_COST), ("browser", BROWSER_COST)] {
            let mut store = Topology::default();
            for (origin, links) in [
                (src, vec![(hop, cost), (other, cost)]),
                (hop, vec![(dst, NATIVE_COST)]),
                (other, vec![(hop, NATIVE_COST), (dst, 3 * NATIVE_COST)]),
                (dst, vec![]),
            ] {
                assert!(
                    ingest(&mut store, vector(origin, 1, &links)),
                    "the cost of a source changes no choice"
                );
            }
            assert_eq!(first_hop(&store, src, dst), Some(hop), "{name} source");
        }
    }

    /// The cost of a browser's links is inside its signature: another node cannot make a browser
    /// look native, nor a native look like a browser.
    #[test]
    fn a_changed_cost_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let [tab, dst] = [1, 2].map(eid);
        let mut store = Topology::default();
        let mut cheaper = vector(tab, 1, &[(dst, BROWSER_COST)]);
        cheaper.links[0].1 = link_metric::LinkMetric::new(NATIVE_COST);
        assert!(!ingest(&mut store, cheaper), "a lowered cost");
        let mut dearer = vector(tab, 1, &[(dst, NATIVE_COST)]);
        dearer.links[0].1 = link_metric::LinkMetric::new(BROWSER_COST);
        assert!(!ingest(&mut store, dearer), "a raised cost");
        assert!(
            ingest(&mut store, vector(tab, 1, &[(dst, BROWSER_COST)])),
            "a changed browser cost is refused"
        );
    }
}
