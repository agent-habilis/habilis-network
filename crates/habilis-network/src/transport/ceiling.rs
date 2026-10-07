//! The ceiling of direct connections: one count for plain QUIC connections and `WebRTC`
//! sessions together, and the rule that keeps it.
//!
//! A direct connection is a cache. Below the ceiling `C` nothing closes for idleness (the one
//! backstop of `DIRECT_IDLE_BACKSTOP_SECS` apart). At `C` the node always accepts a new peer and
//! evicts the least recently used one.
//!
//! The count is per peer: a peer that holds a session and a QUIC connection over it is one unit.
//! A peer counts while it holds a unicast QUIC connection, or a session and is not a gossip
//! neighbor: the gossip links are bound by G, outside `C`, and are never evicted.
//!
//! **An eviction is triggered only by an admission.** [`Ceiling::admit`] is the only call that
//! returns victims; touching, closing or marking a peer never evicts.
//!
//! The rule for the victims of an admission:
//! 1. The ceiling holds at every instant: an admission evicts at least what it needs.
//! 2. A busy unit (a send or a stream is in flight on it) is never evicted. If every candidate is
//!    busy, the newcomer is admitted and the count is over the ceiling by the busy units, which
//!    [`Ceiling::over_ceiling`] reports; it shrinks as the sends finish.
//! 3. Peers idle for [`PREFER_IDLE`] or more go first, least recently used first, then the others.
//!    A peer younger than [`MIN_AGE`] goes last, and only if nothing else can: the ceiling wins.
//! 4. Beyond what is needed, a batch evicts down to 90 percent of the ceiling (rounded up, so that a
//!    ceiling of 2 evicts one peer for one newcomer), so that the next
//!    admissions do not each evict. Batches are rate limited to one per [`BATCH_EVERY`], and
//!    take only peers that rule 3 puts first.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use iroh::EndpointId;

use crate::util::clock::Instant;

/// A peer idle at least this long is evicted before any other.
pub(crate) const PREFER_IDLE: Duration = Duration::from_secs(30);

/// A peer younger than this is evicted only when nothing else can be.
pub(crate) const MIN_AGE: Duration = Duration::from_mins(1);

/// The batch down to 90 percent of the ceiling runs at most this often.
pub(crate) const BATCH_EVERY: Duration = Duration::from_secs(5);

/// How long a peer that evicted us is left alone by proactive dials, before the jitter.
pub(crate) const EVICTED_BACKOFF: Duration = Duration::from_mins(1);

/// The jitter on [`EVICTED_BACKOFF`], as a fraction either way, so that the peers one node
/// evicted at once do not come back at once.
pub(crate) const EVICTED_JITTER: f64 = 0.2;

/// The peers that evicted us, each until when proactive dials to it wait. A send is never
/// held by this: a node that has something to say dials at once.
#[derive(Debug, Default)]
pub(crate) struct EvictionBackoff {
    until: HashMap<EndpointId, Instant>,
}

impl EvictionBackoff {
    /// `peer` evicted us at `now`. `spread` is in `-1.0..=1.0` and scales the jitter.
    pub(crate) fn note(&mut self, peer: EndpointId, now: Instant, spread: f64) {
        self.until.retain(|_, until| now < *until);
        let wait = EVICTED_BACKOFF.mul_f64(1.0 + EVICTED_JITTER * spread.clamp(-1.0, 1.0));
        self.until.insert(peer, now + wait);
    }

    pub(crate) fn holds(&self, peer: &EndpointId, now: Instant) -> bool {
        self.until.get(peer).is_some_and(|until| now < *until)
    }
}

#[derive(Debug, Clone, Default)]
struct Entry {
    opened_at: Option<Instant>,
    last_use: Option<Instant>,
    quic: bool,
    session: bool,
    neighbor: bool,
    busy: u32,
}

impl Entry {
    /// Whether the peer is one unit of the ceiling.
    fn counted(&self) -> bool {
        self.quic || (self.session && !self.neighbor)
    }
}

/// A peer that an admission may evict, in the order of rule 3.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Candidate {
    /// 0: old enough and idle; 1: old enough; 2: younger than [`MIN_AGE`].
    class: u8,
    used: Instant,
    peer: EndpointId,
}

/// What an admission did to the ceiling.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Admission {
    /// The peers to evict now: close their connections and detach their sessions.
    pub(crate) evict: Vec<EndpointId>,
    /// How many units the count is over the ceiling after the evictions, because every other
    /// candidate is busy.
    pub(crate) over_ceiling: usize,
}

/// The ledger of the direct connections of a node, and the ceiling `C`.
#[derive(Debug)]
pub(crate) struct Ceiling {
    cap: usize,
    entries: HashMap<EndpointId, Entry>,
    neighbors: HashSet<EndpointId>,
    last_batch: Option<Instant>,
}

impl Ceiling {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            entries: HashMap::new(),
            neighbors: HashSet::new(),
            last_batch: None,
        }
    }

    /// When `peer` was last used, for a test.
    #[cfg(test)]
    pub(crate) fn last_use(&self, peer: EndpointId) -> Option<Instant> {
        self.entries.get(&peer).and_then(|entry| entry.last_use)
    }

    /// The units that count against the ceiling now.
    pub(crate) fn units(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.counted())
            .count()
    }

    /// How many units the count is over the ceiling now.
    pub(crate) fn over_ceiling(&self) -> usize {
        self.units().saturating_sub(self.cap)
    }

    fn entry(&mut self, peer: EndpointId, now: Instant) -> &mut Entry {
        let neighbor = self.neighbors.contains(&peer);
        let entry = self.entries.entry(peer).or_insert_with(|| Entry {
            neighbor,
            ..Entry::default()
        });
        entry.opened_at.get_or_insert(now);
        entry.last_use.get_or_insert(now);
        entry
    }

    /// A unicast QUIC connection to `peer` is open. Returns the admission of a peer that
    /// was not a unit before.
    pub(crate) fn register_quic(&mut self, peer: EndpointId, now: Instant) -> Admission {
        self.register(peer, now, |entry| entry.quic = true)
    }

    /// A session to `peer` is open.
    pub(crate) fn register_session(&mut self, peer: EndpointId, now: Instant) -> Admission {
        self.register(peer, now, |entry| entry.session = true)
    }

    fn register(
        &mut self,
        peer: EndpointId,
        now: Instant,
        set: impl FnOnce(&mut Entry),
    ) -> Admission {
        let was_counted = self.entries.get(&peer).is_some_and(Entry::counted);
        set(self.entry(peer, now));
        if was_counted || !self.entries[&peer].counted() {
            return Admission::default();
        }
        self.admit(peer, now)
    }

    pub(crate) fn unregister_quic(&mut self, peer: EndpointId) {
        self.unregister(peer, |entry| entry.quic = false);
    }

    pub(crate) fn unregister_session(&mut self, peer: EndpointId) {
        self.unregister(peer, |entry| entry.session = false);
    }

    fn unregister(&mut self, peer: EndpointId, clear: impl FnOnce(&mut Entry)) {
        if let Some(entry) = self.entries.get_mut(&peer) {
            clear(entry);
            if !entry.quic && !entry.session {
                self.entries.remove(&peer);
            }
        }
    }

    /// `peer` carried a frame, or a stream, at `now`.
    pub(crate) fn touch(&mut self, peer: EndpointId, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&peer) {
            entry.last_use = Some(now);
        }
    }

    /// A send or a stream is in flight on the connection of `peer`.
    pub(crate) fn busy_begin(&mut self, peer: EndpointId) {
        if let Some(entry) = self.entries.get_mut(&peer) {
            entry.busy += 1;
        }
    }

    /// The send or stream that [`Self::busy_begin`] marked ended, at `now`.
    pub(crate) fn busy_end(&mut self, peer: EndpointId, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&peer) {
            entry.busy = entry.busy.saturating_sub(1);
            entry.last_use = Some(now);
        }
    }

    /// The set of gossip neighbors changed: a session counts only while its peer is not one.
    pub(crate) fn set_neighbors(
        &mut self,
        neighbors: &HashSet<EndpointId>,
        now: Instant,
    ) -> Admission {
        self.neighbors.clone_from(neighbors);
        let mut newly_counted = Vec::new();
        for (peer, entry) in &mut self.entries {
            let was_counted = entry.counted();
            entry.neighbor = neighbors.contains(peer);
            if !was_counted && entry.counted() {
                newly_counted.push(*peer);
            }
        }
        let mut admission = Admission::default();
        for peer in newly_counted {
            let one = self.admit(peer, now);
            admission.evict.extend(one.evict);
            admission.over_ceiling = admission.over_ceiling.max(one.over_ceiling);
        }
        admission
    }

    /// `peer` became a unit at `now`: the victims that keep the ceiling.
    fn admit(&mut self, peer: EndpointId, now: Instant) -> Admission {
        let units = self.units();
        let need = units.saturating_sub(self.cap);
        if need == 0 {
            return Admission::default();
        }
        // Rule 3: the order of the candidates. A busy unit and the newcomer are not candidates.
        let mut candidates: Vec<Candidate> = self
            .entries
            .iter()
            .filter(|(id, entry)| **id != peer && entry.counted() && entry.busy == 0)
            .map(|(id, entry)| {
                let opened = entry.opened_at.unwrap_or(now);
                let used = entry.last_use.unwrap_or(opened);
                let old_enough = now.duration_since(opened) >= MIN_AGE;
                let idle = now.duration_since(used) >= PREFER_IDLE;
                let class = match (old_enough, idle) {
                    (true, true) => 0,
                    (true, false) => 1,
                    (false, _) => 2,
                };
                Candidate {
                    class,
                    used,
                    peer: *id,
                }
            })
            .collect();
        candidates.sort();

        // Rule 1: what the ceiling needs.
        let mut evict: Vec<EndpointId> = candidates
            .iter()
            .take(need)
            .map(|candidate| candidate.peer)
            .collect();
        // Rule 4: the batch, down to 90 percent, at most once per `BATCH_EVERY`, from the first class only.
        let batch_due = self
            .last_batch
            .is_none_or(|at| now.duration_since(at) >= BATCH_EVERY);
        if batch_due {
            let target = (self.cap * 9).div_ceil(10);
            let extra = units.saturating_sub(evict.len()).saturating_sub(target);
            evict.extend(
                candidates
                    .iter()
                    .skip(evict.len())
                    .take_while(|candidate| candidate.class == 0)
                    .take(extra)
                    .map(|candidate| candidate.peer),
            );
            self.last_batch = Some(now);
        }
        // The victims leave the count: a registered peer is still registered until the caller
        // closes it, so the ledger drops the unit at once and the close follows.
        if evict.len() < need {
            tracing::debug!(target: super::LOG_TARGET, units, cap = self.cap, "every other peer is busy: over the ceiling");
        }
        if let Some(young) = candidates
            .iter()
            .filter(|candidate| candidate.class == 2 && evict.contains(&candidate.peer))
            .map(|candidate| candidate.peer)
            .next()
        {
            tracing::info!(target: super::LOG_TARGET, peer = %young.fmt_short(), "evicting a peer younger than the minimum age: the ceiling holds");
        }
        Admission {
            over_ceiling: units.saturating_sub(evict.len()).saturating_sub(self.cap),
            evict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::endpoint_id;

    #[test]
    fn an_eviction_holds_proactive_dials_for_a_minute_within_the_jitter() {
        let start = Instant::now();
        let peer = endpoint_id(1);
        for (spread, secs) in [(-1.0, 48), (0.0, 60), (1.0, 72)] {
            let mut backoff = EvictionBackoff::default();
            assert!(
                !backoff.holds(&peer, start),
                "nothing is held before an eviction"
            );
            backoff.note(peer, start, spread);
            assert!(backoff.holds(&peer, at(start, secs - 1)));
            assert!(!backoff.holds(&peer, at(start, secs + 1)));
            assert!(
                !backoff.holds(&endpoint_id(2), start),
                "only that peer is held"
            );
        }
    }

    #[test]
    fn a_noted_eviction_forgets_the_expired_ones() {
        let start = Instant::now();
        let mut backoff = EvictionBackoff::default();
        backoff.note(endpoint_id(1), start, 0.0);
        backoff.note(endpoint_id(2), at(start, 100), 0.0);
        assert_eq!(backoff.until.len(), 1);
    }

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    /// `count` peers, each opened at `start` and last used `idle` seconds apart.
    fn full(cap: usize, start: Instant) -> Ceiling {
        let mut ceiling = Ceiling::new(cap);
        for index in 0..cap {
            let peer = endpoint_id(u8::try_from(index).unwrap());
            assert!(ceiling.register_quic(peer, start).evict.is_empty());
            // The lower the index, the older the last use.
            ceiling.touch(peer, at(start, 10 + u64::try_from(index).unwrap()));
        }
        ceiling
    }

    fn apply(ceiling: &mut Ceiling, admission: &Admission) {
        for peer in &admission.evict {
            ceiling.unregister_quic(*peer);
        }
    }

    #[test]
    fn the_newcomer_past_the_ceiling_evicts_the_least_recently_used_idle_peer() {
        let start = Instant::now();
        let mut ceiling = full(4, start);
        let now = at(start, 200);
        let admission = ceiling.register_quic(endpoint_id(100), now);
        assert_eq!(
            admission.evict.first(),
            Some(&endpoint_id(0)),
            "the LRU goes first"
        );
        apply(&mut ceiling, &admission);
        assert!(ceiling.units() <= 4);
        assert_eq!(admission.over_ceiling, 0);
    }

    #[test]
    fn a_peer_under_the_ceiling_evicts_nobody() {
        let start = Instant::now();
        let mut ceiling = Ceiling::new(4);
        for index in 0..4u8 {
            assert!(
                ceiling
                    .register_quic(endpoint_id(index), start)
                    .evict
                    .is_empty()
            );
        }
        assert_eq!(ceiling.units(), 4);
    }

    #[test]
    fn a_peer_younger_than_a_minute_is_kept_while_an_older_one_can_go() {
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let (old, young) = (endpoint_id(1), endpoint_id(2));
        ceiling.register_quic(old, start);
        ceiling.register_quic(young, at(start, 95));
        ceiling.touch(old, at(start, 99));
        ceiling.touch(young, at(start, 96));
        let admission = ceiling.register_quic(endpoint_id(3), at(start, 100));
        assert_eq!(
            admission.evict.first(),
            Some(&old),
            "the older peer goes, though it is not the LRU"
        );
    }

    #[test]
    fn when_every_peer_is_young_the_least_recently_used_goes_anyway() {
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(endpoint_id(1), start);
        ceiling.register_quic(endpoint_id(2), at(start, 1));
        ceiling.touch(endpoint_id(2), at(start, 5));
        let admission = ceiling.register_quic(endpoint_id(3), at(start, 10));
        assert_eq!(admission.evict.first(), Some(&endpoint_id(1)));
        assert_eq!(admission.over_ceiling, 0, "the ceiling holds");
    }

    #[test]
    fn a_busy_peer_is_never_evicted_and_a_ceiling_of_busy_peers_is_overrun_by_the_newcomer() {
        let start = Instant::now();
        let mut ceiling = full(2, start);
        ceiling.busy_begin(endpoint_id(0));
        ceiling.busy_begin(endpoint_id(1));
        let admission = ceiling.register_quic(endpoint_id(9), at(start, 200));
        assert!(admission.evict.is_empty(), "nobody is idle");
        assert_eq!(admission.over_ceiling, 1);
        assert_eq!(ceiling.over_ceiling(), 1);
        // The sends end: the next admission evicts down.
        ceiling.busy_end(endpoint_id(0), at(start, 201));
        ceiling.busy_end(endpoint_id(1), at(start, 201));
        let later = ceiling.register_quic(endpoint_id(10), at(start, 400));
        assert!(!later.evict.is_empty());
    }

    #[test]
    fn a_batch_evicts_down_to_ninety_percent_once_per_five_seconds() {
        let start = Instant::now();
        let mut ceiling = full(10, start);
        let first = ceiling.register_quic(endpoint_id(100), at(start, 200));
        // 10 + 1 - 9 = 2 victims: one that is needed, one for the batch.
        assert_eq!(first.evict.len(), 2);
        apply(&mut ceiling, &first);
        assert_eq!(ceiling.units(), 9);
        // Two seconds later: only what is needed.
        let second = ceiling.register_quic(endpoint_id(101), at(start, 202));
        assert!(second.evict.is_empty(), "9 + 1 fits");
        let third = ceiling.register_quic(endpoint_id(102), at(start, 203));
        assert_eq!(
            third.evict.len(),
            1,
            "no batch inside five seconds: only what is needed"
        );
        apply(&mut ceiling, &third);
        // Five seconds after the first batch: a batch again.
        let fourth = ceiling.register_quic(endpoint_id(103), at(start, 206));
        assert_eq!(fourth.evict.len(), 2);
    }

    #[test]
    fn the_count_never_exceeds_the_ceiling_over_a_long_run_of_admissions() {
        let start = Instant::now();
        let mut ceiling = Ceiling::new(8);
        let mut state = 12345_u64;
        for step in 0..2000_u64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let peer = endpoint_id(u8::try_from(state >> 56).unwrap());
            let now = at(start, step * 3);
            let admission = ceiling.register_quic(peer, now);
            apply(&mut ceiling, &admission);
            ceiling.touch(peer, now);
            assert!(
                ceiling.units() <= 8,
                "step {step}: {} units",
                ceiling.units()
            );
        }
    }

    #[test]
    fn a_session_to_a_neighbor_does_not_count_until_the_peer_stops_being_one() {
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let neighbor = endpoint_id(1);
        ceiling.set_neighbors(&HashSet::from([neighbor]), start);
        ceiling.register_session(neighbor, start);
        assert_eq!(ceiling.units(), 0, "a gossip link is outside the ceiling");
        ceiling.register_quic(endpoint_id(2), start);
        ceiling.register_quic(endpoint_id(3), start);
        assert_eq!(ceiling.units(), 2);
        // It stops being a neighbor: its session counts from now on, and the ceiling holds.
        let admission = ceiling.set_neighbors(&HashSet::new(), at(start, 200));
        assert_eq!(admission.evict.len(), 1, "one for the ceiling");
        assert!(
            !admission.evict.contains(&neighbor),
            "the newcomer is not a victim"
        );
    }

    #[test]
    fn two_peers_at_a_ceiling_of_two_and_a_newcomer_evict_exactly_one_then_nothing() {
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(endpoint_id(1), start);
        ceiling.register_quic(endpoint_id(2), start);
        let admission = ceiling.register_quic(endpoint_id(3), at(start, 100));
        assert_eq!(admission.evict.len(), 1);
        apply(&mut ceiling, &admission);
        // Touching, a second look at a held peer, a close: no eviction.
        ceiling.touch(endpoint_id(3), at(start, 101));
        assert!(
            ceiling
                .register_quic(endpoint_id(3), at(start, 102))
                .evict
                .is_empty()
        );
        let survivor = if admission.evict[0] == endpoint_id(1) {
            endpoint_id(2)
        } else {
            endpoint_id(1)
        };
        ceiling.unregister_quic(survivor);
        assert_eq!(ceiling.units(), 1);
    }

    #[test]
    fn a_session_and_its_connection_are_one_unit() {
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        ceiling.register_session(endpoint_id(1), start);
        ceiling.register_quic(endpoint_id(1), at(start, 1));
        assert_eq!(ceiling.units(), 1);
        ceiling.unregister_session(endpoint_id(1));
        assert_eq!(ceiling.units(), 1, "the connection still counts");
        ceiling.unregister_quic(endpoint_id(1));
        assert_eq!(ceiling.units(), 0);
    }
}
