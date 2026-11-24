//! The ceiling of direct connections: one count for plain QUIC connections and `WebRTC`
//! sessions together, and the rule that keeps it.
//!
//! A direct connection is a cache. Below the ceiling `C` nothing closes for idleness (the one
//! backstop of `DIRECT_IDLE_BACKSTOP` apart). At `C` the node always accepts a new peer and
//! evicts the least recently used one.
//!
//! The count is per peer: a peer that holds a gossip link, a session and a QUIC connection is
//! one unit. A peer counts while it holds a unicast QUIC connection, a session, or a gossip link
//! (it is a gossip neighbor). A gossip neighbor counts but is never evicted: an eviction takes
//! only peers that are not neighbors, so a ceiling full of neighbors is overrun by a newcomer.
//!
//! A second limit, `2C`, holds all the QUIC connections: the direct units, the pinned
//! connections, and the inbound connections above `C`. A dial at `C` that has a multihop route
//! pins its peer and takes no unit (see [`Ceiling::plan_dial`]). An inbound connection above `C`
//! is accepted and takes no unit. A connection or a session that finds no free unit and no peer
//! that can go (each is a gossip neighbor or busy) takes no unit either. These are the extras: they
//! count toward `2C` and close after [`EXTRA_IDLE`] with no use. Above `2C` the least recently used
//! extra goes.
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

/// How long an extra (a pinned connection, or a connection or a session that took no unit) stays
/// open with no use. It is shorter than the idle timeout of a direct connection: the node holds it
/// above its ceiling, and a pinned one costs the members that forward for it.
pub(crate) const EXTRA_IDLE: Duration = Duration::from_mins(1);

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
#[derive(Debug, Default, Clone)]
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

/// The unicast QUIC connection of a peer.
#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
enum Quic {
    #[default]
    Absent,
    /// A direct unit of the ceiling.
    Unit,
    /// No direct unit: the peer connected to us above the ceiling, or no unit was free and no peer
    /// could go.
    Extra,
    /// No direct unit: the connection was dialed through multihop alone, and the peer is pinned to
    /// it. It ends with the connection, or when the peer becomes a gossip neighbor.
    Pinned,
}

/// The `WebRTC` session of a peer.
#[derive(Debug, Clone, Default, Copy, PartialEq, Eq)]
enum Session {
    #[default]
    Absent,
    /// A direct unit of the ceiling.
    Unit,
    /// No direct unit: no unit was free and no peer could go. It counts toward `2C` only.
    Extra,
}

#[derive(Debug, Clone, Default, Copy)]
struct Entry {
    opened_at: Option<Instant>,
    last_use: Option<Instant>,
    quic: Quic,
    session: Session,
    neighbor: bool,
    /// The peer is the rendezvous of the mesh: whatever it holds takes no unit.
    rendezvous: bool,
    busy: u32,
}

impl Entry {
    /// Whether the peer is one direct unit of the ceiling. The rendezvous never is.
    fn counted(&self) -> bool {
        !self.rendezvous
            && (self.quic == Quic::Unit || self.session == Session::Unit || self.neighbor)
    }

    /// Whether the peer holds a connection or a session that took no unit.
    fn extra(&self) -> bool {
        (self.rendezvous && self.held())
            || self.quic == Quic::Extra
            || self.quic == Quic::Pinned
            || self.session == Session::Extra
    }

    /// The extra connection and the extra session of the peer take a unit.
    fn promote(&mut self) {
        if self.quic == Quic::Extra {
            self.quic = Quic::Unit;
        }
        if self.session == Session::Extra {
            self.session = Session::Unit;
        }
    }

    /// The connection and the session of the peer give up their unit: they count toward `2C` only.
    fn demote(&mut self) {
        if self.quic == Quic::Unit {
            self.quic = Quic::Extra;
        }
        if self.session == Session::Unit {
            self.session = Session::Extra;
        }
    }

    /// Whether the peer holds a connection of any kind, which counts toward twice the ceiling.
    fn held(&self) -> bool {
        self.quic != Quic::Absent || self.session != Session::Absent || self.neighbor
    }
}

/// A peer that an admission may evict, in the order of rule 3.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct Candidate {
    /// 0: old enough and idle; 1: old enough; 2: younger than [`MIN_AGE`].
    class: u8,
    used: Instant,
    peer: EndpointId,
}

/// What a new dial to a peer does to the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialPlan {
    /// A direct connection: it takes one unit, and at the ceiling it evicts the least recently used.
    Direct,
    /// A connection that rides multihop: the peer is pinned, and it takes no unit.
    Multihop,
}

/// What an admission did to the ceiling.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub(crate) struct Admission {
    /// The peers to evict now: close their connections and detach their sessions.
    pub(crate) evict: Vec<EndpointId>,
    /// How many units the count is over the ceiling after the evictions, because every other
    /// candidate is busy.
    pub(crate) over_ceiling: usize,
    /// The peers whose admission this is: the connection, the session or the gossip neighbors that
    /// took the units. A victim is never among them.
    pub(crate) newcomers: Vec<EndpointId>,
}

/// The ledger of the direct connections of a node, and the ceiling `C`.
#[derive(Debug, Clone)]
pub(crate) struct Ceiling {
    cap: usize,
    /// Whether an admission above the cap evicts the least recently used peer. The cache of the
    /// application evicts; the sessions of the underlay are route edges, which are not evicted: its
    /// table refuses a newcomer at the cap instead (see `SignalAdmission::new_route_table`).
    evicts: bool,
    entries: HashMap<EndpointId, Entry>,
    neighbors: HashSet<EndpointId>,
    /// The peers whose direct dial holds a unit that no connection holds yet.
    reserved: HashSet<EndpointId>,
    /// The rendezvous of the mesh. A member at its ceiling may still return to it and hold it: the
    /// link takes no unit, and no admission evicts it.
    rendezvous: Option<EndpointId>,
    /// The peers that a dial reaches through multihop, from the plan of the dial to the opening of
    /// its connection: the pin before it has a connection. When the connection opens, the entry of
    /// the peer is [`Quic::Pinned`] and the peer leaves this set. An inbound connection of such a
    /// peer that closes does not take the pin, because the dial still needs it.
    awaiting: HashSet<EndpointId>,
    last_batch: Option<Instant>,
}

impl Ceiling {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            evicts: true,
            entries: HashMap::new(),
            neighbors: HashSet::new(),
            reserved: HashSet::new(),
            rendezvous: None,
            awaiting: HashSet::new(),
            last_batch: None,
        }
    }

    /// A ceiling that evicts nothing: the table that owns it refuses at the cap.
    pub(crate) fn refusing(cap: usize) -> Self {
        Self {
            evicts: false,
            ..Self::new(cap)
        }
    }

    /// Whether the table refuses a newcomer at the cap, and evicts nobody.
    pub(crate) fn refuses(&self) -> bool {
        !self.evicts
    }

    /// `peer` is the rendezvous of the mesh: it takes no unit, whatever it holds, and no admission
    /// evicts it.
    pub(crate) fn set_rendezvous(&mut self, peer: EndpointId) {
        if let Some(entry) = self.entries.get_mut(&peer) {
            entry.rendezvous = true;
        }
        if let Some(previous) = self.rendezvous.replace(peer).filter(|old| *old != peer)
            && let Some(entry) = self.entries.get_mut(&previous)
        {
            entry.rendezvous = false;
        }
        self.promote_extras();
    }

    /// Whether `peer` already counts against the ceiling.
    pub(crate) fn holds(&self, peer: EndpointId) -> bool {
        self.entries.get(&peer).is_some_and(Entry::counted)
    }

    /// When `peer` was last used, for a test.
    #[cfg(test)]
    pub(crate) fn last_use(&self, peer: EndpointId) -> Option<Instant> {
        self.entries.get(&peer).and_then(|entry| entry.last_use)
    }

    /// How long ago `peer` was last used, at `now`. `None` when the ledger does not know the peer,
    /// or when a send or a stream is in flight on it: a busy peer is not idle.
    pub(crate) fn unused_for(&self, peer: EndpointId, now: Instant) -> Option<Duration> {
        let entry = self.entries.get(&peer).filter(|entry| entry.busy == 0)?;
        Some(now.saturating_duration_since(entry.last_use?))
    }

    /// The peers that hold a unicast connection, in no order.
    pub(crate) fn quic_peers(&self) -> Vec<EndpointId> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.quic != Quic::Absent)
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// The peers that hold a session, in no order.
    pub(crate) fn session_peers(&self) -> Vec<EndpointId> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.session != Session::Absent)
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Whether `peer` holds an extra: a connection or a session that took no unit.
    pub(crate) fn is_extra(&self, peer: EndpointId) -> bool {
        self.entries.get(&peer).is_some_and(Entry::extra)
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
        let rendezvous = self.rendezvous == Some(peer);
        let entry = self.entries.entry(peer).or_insert_with(|| Entry {
            neighbor,
            rendezvous,
            ..Entry::default()
        });
        entry.opened_at.get_or_insert(now);
        entry.last_use.get_or_insert(now);
        entry
    }

    /// A unicast QUIC connection to `peer` is open. Returns the admission of a peer that
    /// was not a unit before.
    pub(crate) fn register_quic(&mut self, peer: EndpointId, now: Instant) -> Admission {
        if !self.awaiting.remove(&peer) {
            return self.register_quic_as(peer, now, Quic::Unit);
        }
        // The connection of our dial rides multihop alone and the sends of the node use it, so it
        // decides the entry, whatever the peer opened before: the unit of an inbound connection
        // goes back, and an extra can take it.
        let admission = self.register_with(peer, now, |entry| entry.quic = Quic::Pinned);
        self.promote_extras();
        admission
    }

    /// A session to `peer` is open.
    pub(crate) fn register_session(&mut self, peer: EndpointId, now: Instant) -> Admission {
        self.register_with(peer, now, |entry| {
            if entry.session == Session::Absent {
                entry.session = Session::Unit;
            }
        })
    }

    /// What a new dial to `peer` does to the ledger, decided under one lock so that parallel dials
    /// cannot all take the last unit. A dial that finds a free unit reserves it, and
    /// [`Self::register_quic`] or [`Self::release_dial`] gives the reservation back. At the ceiling,
    /// a dial that has a multihop route (`route`) pins the peer and takes no unit. At the ceiling,
    /// with no route, the dial is direct and evicts when its connection registers.
    ///
    /// A peer whose pinned connection is open is not planned again: the open connection is the
    /// dial, and the plan leaves the pin and the units as they are, whatever `route` says. The
    /// watcher closes a pinned connection that has no route, and it reads the pin.
    pub(crate) fn plan_dial(&mut self, peer: EndpointId, route: bool) -> DialPlan {
        if self
            .entries
            .get(&peer)
            .is_some_and(|entry| entry.quic == Quic::Pinned)
        {
            return DialPlan::Multihop;
        }
        self.awaiting.remove(&peer);
        self.reserved.remove(&peer);
        if self.holds(peer) || !self.evicts || self.rendezvous == Some(peer) {
            return DialPlan::Direct;
        }
        if self.units() + self.reserved.len() < self.cap {
            self.reserved.insert(peer);
            return DialPlan::Direct;
        }
        if route {
            self.awaiting.insert(peer);
            return DialPlan::Multihop;
        }
        DialPlan::Direct
    }

    /// Whether a dial that no send asked for (a probe, a courtesy reply) may take a unit now: the
    /// peer holds a unit already, or a unit is free. A node at its ceiling dials nobody for itself:
    /// a send reaches the peer through multihop when it needs to, and no connection is evicted for
    /// a dial that nobody waits on.
    pub(crate) fn has_room(&self, peer: EndpointId) -> bool {
        self.holds(peer)
            || !self.evicts
            || self.rendezvous == Some(peer)
            || self.units() + self.reserved.len() < self.cap
    }

    /// [`Self::has_room`], and a free unit is reserved for the dial, under the same lock, so that
    /// parallel proactive dials cannot take the last unit together. [`Self::register_quic`] or
    /// [`Self::release_dial`] gives the reservation back.
    pub(crate) fn reserve_proactive(&mut self, peer: EndpointId) -> bool {
        if !self.has_room(peer) {
            return false;
        }
        if !self.holds(peer) && self.evicts && self.rendezvous != Some(peer) {
            self.reserved.insert(peer);
        }
        true
    }

    /// The dial that [`Self::plan_dial`] planned ended without a connection.
    pub(crate) fn release_dial(&mut self, peer: EndpointId) {
        self.reserved.remove(&peer);
        self.awaiting.remove(&peer);
    }

    /// Every pinned peer, planned or connected, in no order.
    pub(crate) fn pins(&self) -> Vec<EndpointId> {
        let open = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.quic == Quic::Pinned)
            .map(|(peer, _)| *peer);
        self.awaiting.iter().copied().chain(open).collect()
    }

    /// Forget every pin: the table closed.
    pub(crate) fn clear_pins(&mut self) {
        self.awaiting.clear();
        for entry in self.entries.values_mut() {
            if entry.quic == Quic::Pinned {
                entry.quic = Quic::Extra;
            }
        }
    }

    /// Whether `peer` is pinned to multihop: its dial is in flight, or the connection of that dial
    /// is open.
    pub(crate) fn pinned(&self, peer: EndpointId) -> bool {
        self.awaiting.contains(&peer)
            || self
                .entries
                .get(&peer)
                .is_some_and(|entry| entry.quic == Quic::Pinned)
    }

    /// A unicast connection that `peer` opened to us. Below the ceiling it is a unit. At the
    /// ceiling it is accepted and takes no unit, and nobody is evicted for it before `2C`.
    pub(crate) fn register_inbound(&mut self, peer: EndpointId, now: Instant) -> Admission {
        let already = self.entries.get(&peer).is_some_and(Entry::held);
        let reserved_by_others: usize =
            self.reserved.iter().filter(|other| **other != peer).count();
        let full = self.units() + reserved_by_others >= self.cap;
        let quic = if !already && full && self.evicts {
            Quic::Extra
        } else {
            Quic::Unit
        };
        self.register_quic_as(peer, now, quic)
    }

    /// The pinned peers that hold their connection now, in no order.
    pub(crate) fn pinned_connected(&self) -> Vec<EndpointId> {
        let pinned = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.quic == Quic::Pinned);
        pinned.map(|(peer, _)| *peer).collect()
    }

    /// The limit `2C` on all the connections of the node: direct, pinned, and inbound above `C`.
    pub(crate) fn total_cap(&self) -> usize {
        self.cap * 2
    }

    /// Every peer that holds a connection of any kind.
    pub(crate) fn connections(&self) -> usize {
        self.entries.values().filter(|entry| entry.held()).count()
    }

    /// The least recently used extra connections (pinned, or inbound above `C`) beyond `2C`. A direct
    /// unit is bound by `C`, and a gossip neighbor, a busy peer, the newcomer, and a peer that
    /// `evicted` names already never go.
    fn trim_total(
        &self,
        newcomer: EndpointId,
        evicted: &[EndpointId],
        now: Instant,
    ) -> Vec<EndpointId> {
        if !self.evicts {
            return Vec::new();
        }
        let held = self.connections().saturating_sub(evicted.len());
        let need = held.saturating_sub(self.total_cap());
        let mut candidates = self.candidates(now, newcomer, Entry::extra);
        candidates.retain(|candidate| !evicted.contains(&candidate.peer));
        candidates
            .iter()
            .take(need)
            .map(|candidate| candidate.peer)
            .collect()
    }

    /// A unicast connection of `peer`, as a unit or as an extra.
    fn register_quic_as(&mut self, peer: EndpointId, now: Instant, quic: Quic) -> Admission {
        self.register_with(peer, now, |entry| {
            if entry.quic == Quic::Absent {
                entry.quic = quic;
            }
        })
    }

    /// Record a connection, and return the victims of the two limits.
    fn register_with(
        &mut self,
        peer: EndpointId,
        now: Instant,
        set: impl FnOnce(&mut Entry),
    ) -> Admission {
        let was_counted = self.entries.get(&peer).is_some_and(Entry::counted);
        set(self.entry(peer, now));
        self.reserved.remove(&peer);
        if !was_counted && self.entries[&peer].counted() {
            self.demote_without_room(peer, now);
        }
        let mut admission = if was_counted || !self.entries[&peer].counted() {
            Admission::default()
        } else {
            self.admit(peer, now)
        };
        let beyond = self.trim_total(peer, &admission.evict, now);
        admission.evict.extend(beyond);
        admission
    }

    /// A connection or a session of `peer` just took a unit. If the count is over the ceiling and no
    /// peer can go to make room (each is a gossip neighbor, busy, or the newcomer), the connection
    /// or session takes no unit: it is an extra, and it counts toward `2C` only.
    fn demote_without_room(&mut self, peer: EndpointId, now: Instant) {
        if !self.evicts || self.entries[&peer].neighbor {
            return;
        }
        let need = self.units().saturating_sub(self.cap);
        let room = self.candidates(now, peer, Entry::counted).len();
        if room >= need {
            return;
        }
        self.entry(peer, now).demote();
    }

    pub(crate) fn unregister_quic(&mut self, peer: EndpointId) {
        self.unregister(peer, |entry| entry.quic = Quic::Absent);
    }

    pub(crate) fn unregister_session(&mut self, peer: EndpointId) {
        self.unregister(peer, |entry| {
            entry.session = Session::Absent;
        });
    }

    fn unregister(&mut self, peer: EndpointId, clear: impl FnOnce(&mut Entry)) {
        if let Some(entry) = self.entries.get_mut(&peer) {
            clear(entry);
            if !entry.held() {
                self.entries.remove(&peer);
            }
        }
        self.promote_extras();
    }

    /// While a unit is free, the most recently used extra takes it. A pinned peer rides multihop
    /// only, so it never becomes a unit.
    fn promote_extras(&mut self) {
        if !self.evicts {
            return;
        }
        while self.units() + self.reserved.len() < self.cap {
            let awaiting = &self.awaiting;
            let entries = self.entries.iter();
            let extras = entries.filter(|(peer, entry)| {
                entry.extra()
                    && !entry.rendezvous
                    && entry.quic != Quic::Pinned
                    && !awaiting.contains(*peer)
            });
            let hottest: Option<(&EndpointId, &Entry)> =
                extras.max_by_key(|(_, entry)| entry.last_use);
            let Some((peer, _)) = hottest else {
                return;
            };
            let peer = *peer;
            if let Some(entry) = self.entries.get_mut(&peer) {
                entry.promote();
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

    /// The set of gossip neighbors changed: each neighbor is one unit, and an eviction never
    /// takes it. A peer that stops being a neighbor and holds nothing else leaves the count.
    pub(crate) fn set_neighbors(
        &mut self,
        neighbors: &HashSet<EndpointId>,
        now: Instant,
    ) -> Admission {
        self.neighbors.clone_from(neighbors);
        let mut newly_counted = Vec::new();
        for peer in neighbors {
            let was_counted = self.entries.get(peer).is_some_and(Entry::counted);
            let entry = self.entry(*peer, now);
            entry.neighbor = true;
            if !was_counted && entry.counted() {
                newly_counted.push(*peer);
            }
        }
        self.entries.retain(|peer, entry| {
            entry.neighbor = neighbors.contains(peer);
            entry.held()
        });
        self.promote_extras();
        for peer in neighbors {
            self.awaiting.remove(peer);
            if let Some(entry) = self.entries.get_mut(peer)
                && entry.quic == Quic::Pinned
            {
                entry.quic = Quic::Extra;
            }
        }
        // One admission for all the new neighbors: the neighbors are no candidates, and one pass names
        // each victim once.
        let mut admission = match newly_counted.first() {
            Some(first) => self.admit(*first, now),
            None => Admission::default(),
        };
        admission.newcomers.clone_from(&newly_counted);
        self.demote_over_ceiling(&admission.evict);
        admission.over_ceiling = self
            .units()
            .saturating_sub(admission.evict.len())
            .saturating_sub(self.cap);
        admission
    }

    /// The neighbors took units that busy peers held. A busy peer is never evicted, so each
    /// connection or session that no neighbor holds, least recently used first, becomes an extra
    /// until the count fits the ceiling. `evicted` already go, and `units` still counts them.
    fn demote_over_ceiling(&mut self, evicted: &[EndpointId]) {
        if !self.evicts {
            return;
        }
        let staying: usize = self.units().saturating_sub(evicted.len());
        let over: usize = staying.saturating_sub(self.cap);
        let units = self.entries.iter();
        let holding = units
            .filter(|(peer, entry)| entry.counted() && !entry.neighbor && !evicted.contains(peer));
        let mut holders: Vec<(Instant, EndpointId)> = Vec::new();
        for (peer, entry) in holding {
            holders.push((
                entry
                    .last_use
                    .or(entry.opened_at)
                    .unwrap_or_else(Instant::now),
                *peer,
            ));
        }
        holders.sort_unstable();
        let demoted = holders.into_iter().take(over);
        for (_, peer) in demoted {
            if let Some(entry) = self.entries.get_mut(&peer) {
                entry.demote();
            }
        }
    }

    /// The peers that `pool` accepts, in the order of rule 3, without a busy peer, a gossip
    /// neighbor or `newcomer`.
    fn candidates(
        &self,
        now: Instant,
        newcomer: EndpointId,
        pool: impl Fn(&Entry) -> bool,
    ) -> Vec<Candidate> {
        let mut candidates: Vec<Candidate> = self
            .entries
            .iter()
            .filter(|(id, entry)| {
                **id != newcomer && pool(entry) && !entry.neighbor && entry.busy == 0
            })
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
        candidates
    }

    /// `peer` became a unit at `now`: the victims that keep the ceiling.
    fn admit(&mut self, peer: EndpointId, now: Instant) -> Admission {
        if !self.evicts {
            return Admission::default();
        }
        let units = self.units();
        let need = units.saturating_sub(self.cap);
        if need == 0 {
            return Admission::default();
        }
        // Rule 3: the order of the candidates. A busy unit, a gossip neighbor and the newcomer are
        // not candidates.
        let candidates = self.candidates(now, peer, Entry::counted);

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
            let already = evict.len();
            let remaining = candidates.iter().skip(already);
            let victims = remaining
                .take_while(|candidate| candidate.class == 0)
                .take(extra);
            evict.extend(victims.map(|candidate| candidate.peer));
            self.last_batch = Some(now);
        }
        // The victims leave the count: a registered peer is still registered until the caller
        // closes it, so the ledger drops the unit at once and the close follows.
        if evict.len() < need {
            tracing::debug!(target: super::LOG_TARGET, units, cap = self.cap, "every other peer is busy: over the ceiling");
        }
        let young_candidates = candidates
            .iter()
            .filter(|candidate| candidate.class == 2 && evict.contains(&candidate.peer));
        if let Some(young) = young_candidates.map(|candidate| candidate.peer).next() {
            tracing::info!(target: super::LOG_TARGET, victim = %young.fmt_short(), newcomer = %peer.fmt_short(), "evicting a peer younger than the minimum age: the ceiling holds");
        }
        Admission {
            over_ceiling: units.saturating_sub(evict.len()).saturating_sub(self.cap),
            evict,
            newcomers: vec![peer],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Admission, Ceiling, DialPlan, Duration, EndpointId, EvictionBackoff, HashSet, Instant,
    };
    use crate::testing;

    #[test]
    fn an_eviction_holds_proactive_dials_for_a_minute_within_the_jitter() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let peer = testing::endpoint_id(1);
        for (spread, secs) in [(-1.0, 48), (0.0, 60), (1.0, 72)] {
            let mut backoff = EvictionBackoff::default();
            assert!(
                !backoff.holds(&peer, start),
                "nothing is held before an eviction"
            );
            backoff.note(peer, start, spread);
            assert!(
                backoff.holds(&peer, at(start, secs - 1)),
                "an eviction holds proactive dials for a minute within the jitter"
            );
            assert!(
                !backoff.holds(&peer, at(start, secs + 1)),
                "the eviction hold ends after the jitter window"
            );
            assert!(
                !backoff.holds(&testing::endpoint_id(2), start),
                "only that peer is held"
            );
        }
    }

    #[test]
    fn a_noted_eviction_forgets_the_expired_ones() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut backoff = EvictionBackoff::default();
        backoff.note(testing::endpoint_id(1), start, 0.0);
        backoff.note(testing::endpoint_id(2), at(start, 100), 0.0);
        assert_eq!(
            backoff.until.len(),
            1,
            "a noted eviction forgets the expired ones and keeps one"
        );
    }

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    /// `count` peers, each opened at `start` and last used `idle` seconds apart.
    fn full(cap: usize, start: Instant) -> Ceiling {
        let mut ceiling = Ceiling::new(cap);
        for index in 0..cap {
            let peer = testing::endpoint_id(
                u8::try_from(index).expect("the test caps are at most 10, so the index fits a u8"),
            );
            assert!(
                ceiling.register_quic(peer, start).evict.is_empty(),
                "a full ceiling evicts nobody for the first quic peer"
            );
            // The lower the index, the older the last use.
            ceiling.touch(
                peer,
                at(
                    start,
                    10 + u64::try_from(index).expect("an index fits a u64"),
                ),
            );
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
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = full(4, start);
        let now = at(start, 200);
        let admission = ceiling.register_quic(testing::endpoint_id(100), now);
        assert_eq!(
            admission.evict.first(),
            Some(&testing::endpoint_id(0)),
            "the LRU goes first"
        );
        apply(&mut ceiling, &admission);
        assert!(
            ceiling.units() <= 4,
            "the ceiling holds at most four units after the newcomer"
        );
        assert_eq!(
            admission.over_ceiling, 0,
            "no unit is over the ceiling after the eviction"
        );
    }

    #[test]
    fn a_peer_under_the_ceiling_evicts_nobody() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(4);
        for index in 0..4u8 {
            assert!(
                ceiling
                    .register_quic(testing::endpoint_id(index), start)
                    .evict
                    .is_empty(),
                "a peer under the ceiling evicts nobody"
            );
        }
        assert_eq!(
            ceiling.units(),
            4,
            "the ceiling holds four units when no one is evicted"
        );
    }

    #[test]
    fn a_peer_younger_than_a_minute_is_kept_while_an_older_one_can_go() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let (old, young) = (testing::endpoint_id(1), testing::endpoint_id(2));
        ceiling.register_quic(old, start);
        ceiling.register_quic(young, at(start, 95));
        ceiling.touch(old, at(start, 99));
        ceiling.touch(young, at(start, 96));
        let admission = ceiling.register_quic(testing::endpoint_id(3), at(start, 100));
        assert_eq!(
            admission.evict.first(),
            Some(&old),
            "the older peer goes, though it is not the LRU"
        );
    }

    #[test]
    fn when_every_peer_is_young_the_least_recently_used_goes_anyway() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(testing::endpoint_id(1), start);
        ceiling.register_quic(testing::endpoint_id(2), at(start, 1));
        ceiling.touch(testing::endpoint_id(2), at(start, 5));
        let admission = ceiling.register_quic(testing::endpoint_id(3), at(start, 10));
        assert_eq!(
            admission.evict.first(),
            Some(&testing::endpoint_id(1)),
            "the least recently used young peer is the one evicted"
        );
        assert_eq!(admission.over_ceiling, 0, "the ceiling holds");
    }

    #[test]
    fn a_busy_peer_is_never_evicted_and_a_ceiling_of_busy_peers_makes_the_newcomer_an_extra() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = full(2, start);
        ceiling.busy_begin(testing::endpoint_id(0));
        ceiling.busy_begin(testing::endpoint_id(1));
        let newcomer = testing::endpoint_id(9);
        let admission = ceiling.register_quic(newcomer, at(start, 200));
        assert!(admission.evict.is_empty(), "nobody is idle");
        assert_eq!(admission.over_ceiling, 0, "a busy peer is never evicted");
        assert_eq!(ceiling.units(), 2, "the newcomer takes no unit");
        assert!(
            ceiling.is_extra(newcomer),
            "the newcomer of a ceiling of busy peers is an extra"
        );
        // The sends end: the next admission evicts one idle peer, and the extra stays.
        ceiling.busy_end(testing::endpoint_id(0), at(start, 201));
        ceiling.busy_end(testing::endpoint_id(1), at(start, 201));
        let later = ceiling.register_quic(testing::endpoint_id(10), at(start, 400));
        assert_eq!(
            later.evict.len(),
            1,
            "the later newcomer evicts one idle peer"
        );
        assert!(
            !later.evict.contains(&newcomer),
            "an extra is not a candidate of the units"
        );
    }

    #[test]
    fn a_batch_evicts_down_to_ninety_percent_once_per_five_seconds() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = full(10, start);
        let first = ceiling.register_quic(testing::endpoint_id(100), at(start, 200));
        // 10 + 1 - 9 = 2 victims: one that is needed, one for the batch.
        assert_eq!(
            first.evict.len(),
            2,
            "the first batch evicts two peers down to ninety percent"
        );
        apply(&mut ceiling, &first);
        assert_eq!(ceiling.units(), 9, "nine units remain after the batch");
        // Two seconds later: only what is needed.
        let second = ceiling.register_quic(testing::endpoint_id(101), at(start, 202));
        assert!(second.evict.is_empty(), "9 + 1 fits");
        let third = ceiling.register_quic(testing::endpoint_id(102), at(start, 203));
        assert_eq!(
            third.evict.len(),
            1,
            "no batch inside five seconds: only what is needed"
        );
        apply(&mut ceiling, &third);
        // Five seconds after the first batch: a batch again.
        let fourth = ceiling.register_quic(testing::endpoint_id(103), at(start, 206));
        assert_eq!(
            fourth.evict.len(),
            2,
            "the next batch waits out its five seconds and evicts two more"
        );
    }

    #[test]
    fn the_count_never_exceeds_the_ceiling_over_a_long_run_of_admissions() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(8);
        let mut state = 12345_u64;
        for step in 0..2000_u64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let peer = testing::endpoint_id(
                u8::try_from(state >> 56).expect("a u64 shifted right by 56 fits a u8"),
            );
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
    fn a_refusing_ceiling_evicts_nobody_above_its_cap() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::refusing(2);
        for byte in 1..=4 {
            let admission = ceiling.register_session(testing::endpoint_id(byte), start);
            assert!(
                admission.evict.is_empty(),
                "peer {byte}: nothing is evicted"
            );
        }
        assert_eq!(ceiling.units(), 4, "the count passes the cap, no victim");
        assert!(
            ceiling.refuses(),
            "a refusing ceiling refuses newcomers above its cap"
        );
        assert!(
            ceiling.holds(testing::endpoint_id(1)),
            "peer 1 is still held by the refusing ceiling"
        );
        assert!(
            !ceiling.holds(testing::endpoint_id(9)),
            "peer 9 is not held by the refusing ceiling"
        );
        let mut cache = Ceiling::new(2);
        cache.register_session(testing::endpoint_id(1), start);
        cache.register_session(testing::endpoint_id(2), start);
        let admission = cache.register_session(testing::endpoint_id(3), start);
        assert_eq!(admission.evict.len(), 1, "the cache evicts, as before");
    }

    #[test]
    fn a_gossip_neighbor_is_one_unit_with_no_other_connection() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(4);
        let neighbor = testing::endpoint_id(1);
        ceiling.set_neighbors(&HashSet::from([neighbor]), start);
        assert_eq!(
            ceiling.units(),
            1,
            "a gossip link is one unit of the ceiling"
        );
        assert!(ceiling.holds(neighbor), "the ceiling holds the neighbor");
        ceiling.set_neighbors(&HashSet::new(), at(start, 1));
        assert_eq!(
            ceiling.units(),
            0,
            "a peer that stops being a neighbor and holds nothing else leaves the count"
        );
    }

    #[test]
    fn a_neighbor_with_a_session_and_a_connection_is_still_one_unit() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(4);
        let neighbor = testing::endpoint_id(1);
        ceiling.set_neighbors(&HashSet::from([neighbor]), start);
        ceiling.register_session(neighbor, start);
        ceiling.register_quic(neighbor, start);
        assert_eq!(
            ceiling.units(),
            1,
            "a gossip link, a session and a connection to one peer are one unit"
        );
        ceiling.unregister_quic(neighbor);
        ceiling.unregister_session(neighbor);
        assert_eq!(
            ceiling.units(),
            1,
            "the gossip link alone keeps the unit after the session and the connection close"
        );
    }

    #[test]
    fn an_admission_never_evicts_a_gossip_neighbor() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let neighbor = testing::endpoint_id(1);
        let cached = testing::endpoint_id(2);
        // The neighbor is the oldest and the least recently used, so it would go first.
        ceiling.set_neighbors(&HashSet::from([neighbor]), start);
        ceiling.register_quic(cached, at(start, 10));
        let admission = ceiling.register_quic(testing::endpoint_id(3), at(start, 200));
        assert_eq!(
            admission.evict,
            vec![cached],
            "the cached peer goes and the neighbor stays"
        );
    }

    #[test]
    fn a_connection_that_no_peer_can_make_room_for_is_an_extra_and_takes_no_unit() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.set_neighbors(
            &HashSet::from([testing::endpoint_id(1), testing::endpoint_id(2)]),
            start,
        );
        let newcomer = testing::endpoint_id(3);
        let admission = ceiling.register_quic(newcomer, at(start, 200));
        assert!(
            admission.evict.is_empty(),
            "no peer that a ceiling may evict is left"
        );
        assert_eq!(ceiling.units(), 2, "the newcomer takes no unit");
        assert_eq!(admission.over_ceiling, 0, "the count stays at the ceiling");
        assert!(ceiling.is_extra(newcomer), "the newcomer is an extra");
        assert_eq!(ceiling.connections(), 3, "an extra counts toward 2C");
    }

    #[test]
    fn a_session_that_no_peer_can_make_room_for_is_an_extra_and_takes_no_unit() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.set_neighbors(
            &HashSet::from([testing::endpoint_id(1), testing::endpoint_id(2)]),
            start,
        );
        let newcomer = testing::endpoint_id(3);
        let admission = ceiling.register_session(newcomer, at(start, 200));
        assert!(admission.evict.is_empty(), "nobody can go");
        assert_eq!(ceiling.units(), 2, "the session takes no unit");
        assert!(ceiling.is_extra(newcomer), "the session is an extra");
        ceiling.unregister_session(newcomer);
        assert!(
            !ceiling.is_extra(newcomer),
            "the extra ends with its session"
        );
    }

    #[test]
    fn a_busy_peer_that_new_neighbors_push_over_the_ceiling_becomes_an_extra() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let cached = testing::endpoint_id(3);
        ceiling.register_quic(cached, start);
        ceiling.busy_begin(cached);
        let admission = ceiling.set_neighbors(
            &HashSet::from([testing::endpoint_id(1), testing::endpoint_id(2)]),
            at(start, 200),
        );
        assert!(admission.evict.is_empty(), "a busy peer is not evicted");
        assert_eq!(ceiling.units(), 2, "the two neighbors hold the two units");
        assert_eq!(admission.over_ceiling, 0, "nothing is over the ceiling");
        assert!(
            ceiling.is_extra(cached),
            "the busy connection that no unit holds is an extra"
        );
    }

    #[test]
    fn an_inbound_close_does_not_take_the_pin_of_a_dial_in_flight() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        ceiling.register_quic(testing::endpoint_id(1), start);
        let peer = testing::endpoint_id(2);
        assert_eq!(
            ceiling.plan_dial(peer, true),
            DialPlan::Multihop,
            "the dial is planned through multihop"
        );
        ceiling.register_inbound(peer, at(start, 1));
        ceiling.unregister_quic(peer);
        assert!(
            ceiling.pinned(peer),
            "the dial in flight still needs its pin when the inbound connection closes"
        );
        ceiling.register_quic(peer, at(start, 2));
        ceiling.unregister_quic(peer);
        assert!(
            !ceiling.pinned(peer),
            "the pin ends with the connection that the dial opened"
        );
    }

    #[test]
    fn an_extra_becomes_a_unit_when_a_unit_frees_up_and_a_pinned_one_does_not() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        let unit = testing::endpoint_id(1);
        ceiling.register_quic(unit, start);
        ceiling.busy_begin(unit);
        let extra = testing::endpoint_id(2);
        ceiling.register_quic(extra, at(start, 10));
        let pinned = testing::endpoint_id(3);
        assert_eq!(
            ceiling.plan_dial(pinned, true),
            DialPlan::Multihop,
            "the dial is planned through multihop"
        );
        ceiling.register_quic(pinned, at(start, 11));
        assert!(ceiling.is_extra(extra), "the second connection is an extra");
        ceiling.unregister_quic(unit);
        assert!(
            !ceiling.is_extra(extra),
            "the extra becomes the unit that freed up"
        );
        assert_eq!(ceiling.units(), 1, "one unit again, and no more");
        assert!(
            ceiling.is_extra(pinned) && ceiling.pinned(pinned),
            "a pinned connection stays on multihop and never becomes a unit"
        );
    }

    #[test]
    fn an_inbound_connection_does_not_take_the_unit_that_a_dial_reserved() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(testing::endpoint_id(1), start);
        assert_eq!(
            ceiling.plan_dial(testing::endpoint_id(2), false),
            DialPlan::Direct,
            "a free unit is reserved for the dial"
        );
        let inbound = testing::endpoint_id(3);
        let admission = ceiling.register_inbound(inbound, at(start, 1));
        assert!(admission.evict.is_empty(), "nobody is evicted for it");
        assert!(
            ceiling.is_extra(inbound),
            "the last unit belongs to the dial in flight"
        );
        let dialed = ceiling.register_quic(testing::endpoint_id(2), at(start, 2));
        assert!(
            dialed.evict.is_empty() && ceiling.units() == 2,
            "the dial takes the unit that it reserved"
        );
    }

    #[test]
    fn a_pinned_peer_that_becomes_a_gossip_neighbor_is_unpinned() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        ceiling.register_quic(testing::endpoint_id(1), start);
        let peer = testing::endpoint_id(2);
        assert_eq!(
            ceiling.plan_dial(peer, true),
            DialPlan::Multihop,
            "the dial is planned through multihop"
        );
        ceiling.register_quic(peer, at(start, 1));
        ceiling.set_neighbors(&HashSet::from([peer]), at(start, 2));
        assert!(
            !ceiling.pinned(peer),
            "a gossip neighbor is a direct peer, and no pin holds it on multihop"
        );
    }

    /// A node at its ceiling holds a connection that it dialed through multihop. A unit frees up, and
    /// a send finds the connection unusable for a moment, so the dial of the peer is planned again
    /// with a route. The connection is open and it is the pin: the plan changes nothing. Before the
    /// fix the plan dropped the pin, reserved the free unit and went direct, and the open
    /// connection stayed with a pool that said pinned and a ledger that said not.
    #[test]
    fn a_replan_with_a_route_keeps_the_pin_of_a_peer_whose_pinned_connection_is_open() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let first = testing::endpoint_id(1);
        ceiling.register_quic(first, start);
        ceiling.register_quic(testing::endpoint_id(2), at(start, 1));
        let peer = testing::endpoint_id(3);
        assert_eq!(
            ceiling.plan_dial(peer, true),
            DialPlan::Multihop,
            "the node is at its ceiling, so the dial rides multihop"
        );
        ceiling.register_quic(peer, at(start, 2));
        ceiling.unregister_quic(first);
        assert_eq!(ceiling.units(), 1, "a unit is free");

        let plan = ceiling.plan_dial(peer, true);

        assert_eq!(
            plan,
            DialPlan::Multihop,
            "the pinned connection is open: the peer stays on multihop"
        );
        assert!(ceiling.pinned(peer), "the pin stays");
        assert!(ceiling.is_extra(peer), "the connection takes no unit");
        assert!(
            !ceiling.reserved.contains(&peer),
            "no unit is reserved for the peer"
        );
    }

    /// The same replan with no route. The connection is still the pin: the watcher closes a pinned
    /// connection that has no route (`close_pinned_without_route`, which reads
    /// `pinned_connected`), and it cannot if the plan has dropped the pin.
    #[test]
    fn a_replan_with_no_route_leaves_the_pinned_connection_for_the_watcher_to_close() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let first = testing::endpoint_id(1);
        ceiling.register_quic(first, start);
        ceiling.register_quic(testing::endpoint_id(2), at(start, 1));
        let peer = testing::endpoint_id(3);
        assert_eq!(
            ceiling.plan_dial(peer, true),
            DialPlan::Multihop,
            "the node is at its ceiling, so the dial rides multihop"
        );
        ceiling.register_quic(peer, at(start, 2));
        ceiling.unregister_quic(first);

        let plan = ceiling.plan_dial(peer, false);

        assert_eq!(
            plan,
            DialPlan::Multihop,
            "the open connection is reused: the plan does not go direct"
        );
        assert_eq!(
            ceiling.pinned_connected(),
            vec![peer],
            "the watcher still finds the pinned connection, and closes it if no route comes back"
        );
        assert!(
            !ceiling.reserved.contains(&peer),
            "no unit is reserved for the peer"
        );
    }

    /// The loss of the pin does not depend on how many units are free at the replan.
    #[test]
    fn a_replan_keeps_the_pin_of_an_open_pinned_connection_whatever_the_free_units() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let holders = [testing::endpoint_id(1), testing::endpoint_id(2)];
        let peer = testing::endpoint_id(3);
        for free in 0..=holders.len() {
            let mut ceiling = Ceiling::new(2);
            for holder in holders {
                ceiling.register_quic(holder, start);
            }
            assert_eq!(
                ceiling.plan_dial(peer, true),
                DialPlan::Multihop,
                "the node is at its ceiling, so the dial rides multihop"
            );
            ceiling.register_quic(peer, at(start, 5));
            let freed = holders.iter().take(free);
            for holder in freed {
                ceiling.unregister_quic(*holder);
            }
            assert_eq!(
                ceiling.units(),
                holders.len() - free,
                "{free} units are free"
            );

            let plan = ceiling.plan_dial(peer, true);

            assert_eq!(
                plan,
                DialPlan::Multihop,
                "{free} free units: the open pinned connection stays on multihop"
            );
            assert!(
                ceiling.pinned(peer) && ceiling.is_extra(peer),
                "{free} free units: the pin and the extra stay"
            );
        }
    }

    /// A peer opens a connection to a node at its ceiling while the pinned dial of the node to that
    /// peer is in flight. The connection of the peer is an extra, and the pin waits for the dial.
    /// When the dial opens its own connection, the one entry of the peer is the pinned one. The
    /// ledger keeps one entry for all the unicast connections of a peer, and the table calls
    /// `unregister_quic` only when none is open (`Inner::drop_quic_without_connection`), so the
    /// pin ends with the last connection of the peer.
    #[test]
    fn an_inbound_extra_of_a_peer_becomes_the_pinned_connection_when_the_dial_opens() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        ceiling.register_quic(testing::endpoint_id(1), start);
        let peer = testing::endpoint_id(2);
        assert_eq!(
            ceiling.plan_dial(peer, true),
            DialPlan::Multihop,
            "the node is at its ceiling, so the dial rides multihop"
        );

        ceiling.register_inbound(peer, at(start, 1));
        assert!(
            ceiling.is_extra(peer) && ceiling.pinned(peer),
            "the inbound connection is an extra, and the dial in flight holds the pin"
        );
        assert!(
            ceiling.pinned_connected().is_empty(),
            "no pinned connection is open yet"
        );

        ceiling.register_quic(peer, at(start, 2));
        assert_eq!(
            ceiling.pinned_connected(),
            vec![peer],
            "the dial opened: the entry of the peer is the pinned connection"
        );

        ceiling.unregister_quic(peer);
        assert!(
            !ceiling.pinned(peer) && !ceiling.is_extra(peer),
            "the last connection of the peer closed: the pin and the entry end"
        );
    }

    /// The peer opens a connection to the node while the pinned dial of the node is in flight, and
    /// a unit is free, so the connection of the peer takes it. Then the dial opens its own
    /// connection. The sends of the node use that one, and it rides multihop alone: it decides the
    /// entry. The peer is pinned, and the unit of the inbound connection goes back. Before, the
    /// entry stayed a unit and the pin ended, so a connection dialed on a route alone had no pin.
    #[test]
    fn the_connection_of_a_pinned_dial_decides_the_entry_when_an_inbound_unit_was_open() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let first = testing::endpoint_id(1);
        ceiling.register_quic(first, start);
        ceiling.register_quic(testing::endpoint_id(2), at(start, 1));
        let peer = testing::endpoint_id(3);
        assert_eq!(
            ceiling.plan_dial(peer, true),
            DialPlan::Multihop,
            "the node is at its ceiling, so the dial rides multihop"
        );
        ceiling.unregister_quic(first);
        ceiling.register_inbound(peer, at(start, 2));
        assert_eq!(
            ceiling.units(),
            2,
            "the inbound connection took the free unit"
        );

        ceiling.register_quic(peer, at(start, 3));

        assert!(
            ceiling.pinned(peer),
            "the dial opened its connection: the peer is pinned"
        );
        assert_eq!(
            ceiling.pinned_connected(),
            vec![peer],
            "the entry of the peer is the pinned connection"
        );
        assert_eq!(
            ceiling.units(),
            1,
            "the unit of the inbound connection is back"
        );
    }

    /// The dial of a pinned peer ends with no connection, while an extra that the peer opened
    /// is open. The pin was for the dial: it ends with the dial, and the inbound extra stays what
    /// it was, an extra that a unit can promote. Before, the pin outlived the dial because an
    /// unrelated extra was open.
    #[test]
    fn a_pinned_dial_that_ends_takes_its_pin_with_it_when_an_inbound_extra_is_open() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        ceiling.register_quic(testing::endpoint_id(1), start);
        let peer = testing::endpoint_id(2);
        assert_eq!(
            ceiling.plan_dial(peer, true),
            DialPlan::Multihop,
            "the node is at its ceiling, so the dial rides multihop"
        );
        ceiling.register_inbound(peer, at(start, 1));

        ceiling.release_dial(peer);

        assert!(
            !ceiling.pinned(peer),
            "the dial ended: no pin holds the peer"
        );
        assert!(
            ceiling.is_extra(peer),
            "the inbound extra of the peer is what it was"
        );
    }

    #[test]
    fn several_new_neighbors_name_each_victim_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(3);
        for byte in 1..=3 {
            ceiling.register_quic(testing::endpoint_id(byte), start);
        }
        let admission = ceiling.set_neighbors(
            &HashSet::from([testing::endpoint_id(10), testing::endpoint_id(11)]),
            at(start, 200),
        );
        let mut victims = admission.evict.clone();
        victims.sort_unstable();
        victims.dedup();
        assert_eq!(
            victims.len(),
            admission.evict.len(),
            "no victim is named twice: {:?}",
            admission.evict
        );
        assert_eq!(
            admission.evict.len(),
            2,
            "two new neighbors take the units of two cached peers"
        );
    }

    #[test]
    fn an_extra_takes_the_unit_of_a_neighbor_that_leaves() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        let neighbor = testing::endpoint_id(1);
        ceiling.set_neighbors(&HashSet::from([neighbor]), start);
        let extra = testing::endpoint_id(2);
        ceiling.register_quic(extra, at(start, 10));
        assert!(
            ceiling.is_extra(extra),
            "no unit was free for the connection"
        );
        ceiling.set_neighbors(&HashSet::new(), at(start, 20));
        assert!(
            !ceiling.is_extra(extra) && ceiling.units() == 1,
            "the unit of the neighbor that left goes to the extra"
        );
    }

    #[test]
    fn an_admission_names_the_newcomers_that_took_the_units() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let (first, second) = (testing::endpoint_id(1), testing::endpoint_id(2));
        ceiling.register_quic(first, start);
        ceiling.register_quic(second, start);
        let newcomer = testing::endpoint_id(3);
        let admission = ceiling.register_quic(newcomer, at(start, 100));
        assert_eq!(
            admission.newcomers,
            vec![newcomer],
            "a connection that evicts names itself as the newcomer"
        );
        assert!(
            !admission
                .newcomers
                .iter()
                .any(|peer| admission.evict.contains(peer)),
            "the newcomer is never its own victim"
        );
        let neighbors = HashSet::from([testing::endpoint_id(10), testing::endpoint_id(11)]);
        let joined = ceiling.set_neighbors(&neighbors, at(start, 200));
        assert!(
            joined
                .newcomers
                .iter()
                .all(|peer| !joined.evict.contains(peer)),
            "a gossip neighbor is never the victim of its own admission"
        );
        let mut named = joined.newcomers;
        named.sort_unstable();
        let mut expected: Vec<EndpointId> = neighbors.into_iter().collect();
        expected.sort_unstable();
        assert_eq!(named, expected, "the new neighbors are the newcomers");
    }

    #[test]
    fn the_rendezvous_takes_no_unit_at_the_ceiling_and_evicts_nobody() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let rendezvous = testing::endpoint_id(9);
        ceiling.set_rendezvous(rendezvous);
        ceiling.set_neighbors(
            &HashSet::from([testing::endpoint_id(1), testing::endpoint_id(2)]),
            start,
        );
        assert!(
            ceiling.has_room(rendezvous) && !ceiling.has_room(testing::endpoint_id(3)),
            "a full ceiling has room for the rendezvous and for nobody else"
        );
        assert!(
            ceiling.reserve_proactive(rendezvous),
            "a visit to the rendezvous is allowed at the ceiling"
        );
        assert_eq!(
            ceiling.plan_dial(rendezvous, false),
            DialPlan::Direct,
            "a dial to the rendezvous plans no eviction and reserves no unit"
        );
        let admission = ceiling.register_session(rendezvous, at(start, 100));
        assert!(
            admission.evict.is_empty(),
            "the rendezvous session evicts nobody"
        );
        assert_eq!(ceiling.units(), 2, "the rendezvous takes no unit");
        assert!(
            ceiling.is_extra(rendezvous),
            "the rendezvous session is an extra"
        );
        assert_eq!(
            ceiling.connections(),
            3,
            "the rendezvous counts toward twice the ceiling"
        );
    }

    #[test]
    fn the_rendezvous_is_never_the_victim_of_an_admission() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let (rendezvous, cached) = (testing::endpoint_id(9), testing::endpoint_id(2));
        ceiling.set_rendezvous(rendezvous);
        ceiling.register_session(rendezvous, start);
        ceiling.set_neighbors(&HashSet::from([testing::endpoint_id(1)]), start);
        ceiling.register_quic(cached, at(start, 10));
        let admission = ceiling.set_neighbors(
            &HashSet::from([testing::endpoint_id(1), testing::endpoint_id(3)]),
            at(start, 200),
        );
        assert_eq!(
            admission.evict,
            vec![cached],
            "the cached peer goes, and the rendezvous stays: it holds no unit to take"
        );
        assert!(
            ceiling.is_extra(rendezvous),
            "the rendezvous session is still held"
        );
    }

    #[test]
    fn a_rendezvous_that_became_known_after_its_entry_holds_no_unit() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        let rendezvous = testing::endpoint_id(9);
        ceiling.register_quic(rendezvous, start);
        assert_eq!(ceiling.units(), 1, "before it is known it is a unit");
        ceiling.set_rendezvous(rendezvous);
        assert_eq!(ceiling.units(), 0, "once known it takes no unit");
        assert!(ceiling.is_extra(rendezvous), "it is an extra");
    }

    #[test]
    fn a_session_evicts_a_cached_peer_when_one_can_go() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let cached = testing::endpoint_id(2);
        ceiling.set_neighbors(&HashSet::from([testing::endpoint_id(1)]), start);
        ceiling.register_quic(cached, at(start, 10));
        let newcomer = testing::endpoint_id(3);
        let admission = ceiling.register_session(newcomer, at(start, 200));
        assert_eq!(admission.evict, vec![cached], "the cached peer goes");
        assert!(
            !ceiling.is_extra(newcomer),
            "the session takes the unit that the eviction frees"
        );
    }

    #[test]
    fn the_extras_are_the_first_to_go_above_twice_the_ceiling() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        ceiling.set_neighbors(&HashSet::from([testing::endpoint_id(1)]), start);
        let session = testing::endpoint_id(2);
        assert!(
            ceiling
                .register_session(session, at(start, 100))
                .evict
                .is_empty(),
            "the first extra fits in 2C"
        );
        let admission = ceiling.register_quic(testing::endpoint_id(3), at(start, 200));
        assert_eq!(
            admission.evict,
            vec![session],
            "above 2C the least recently used extra goes, and the neighbor stays"
        );
    }

    #[test]
    fn a_new_neighbor_past_the_ceiling_evicts_a_cached_peer_not_a_neighbor() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let (old_neighbor, cached) = (testing::endpoint_id(1), testing::endpoint_id(2));
        ceiling.set_neighbors(&HashSet::from([old_neighbor]), start);
        ceiling.register_quic(cached, at(start, 10));
        let admission = ceiling.set_neighbors(
            &HashSet::from([old_neighbor, testing::endpoint_id(3)]),
            at(start, 200),
        );
        assert_eq!(
            admission.evict,
            vec![cached],
            "a new neighbor takes the unit of a cached peer"
        );
    }

    #[test]
    fn two_peers_at_a_ceiling_of_two_and_a_newcomer_evict_exactly_one_then_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(testing::endpoint_id(1), start);
        ceiling.register_quic(testing::endpoint_id(2), start);
        let admission = ceiling.register_quic(testing::endpoint_id(3), at(start, 100));
        assert_eq!(
            admission.evict.len(),
            1,
            "the newcomer evicts exactly one peer at a ceiling of two"
        );
        apply(&mut ceiling, &admission);
        // Touching, a second look at a held peer, a close: no eviction.
        ceiling.touch(testing::endpoint_id(3), at(start, 101));
        assert!(
            ceiling
                .register_quic(testing::endpoint_id(3), at(start, 102))
                .evict
                .is_empty(),
            "the next newcomer evicts nobody after the eviction"
        );
        let survivor = if admission.evict[0] == testing::endpoint_id(1) {
            testing::endpoint_id(2)
        } else {
            testing::endpoint_id(1)
        };
        ceiling.unregister_quic(survivor);
        assert_eq!(
            ceiling.units(),
            1,
            "one unit remains after the second eviction"
        );
    }

    #[test]
    fn a_session_and_its_connection_are_one_unit() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        ceiling.register_session(testing::endpoint_id(1), start);
        ceiling.register_quic(testing::endpoint_id(1), at(start, 1));
        assert_eq!(
            ceiling.units(),
            1,
            "a session and its connection count as one unit"
        );
        ceiling.unregister_session(testing::endpoint_id(1));
        assert_eq!(ceiling.units(), 1, "the connection still counts");
        ceiling.unregister_quic(testing::endpoint_id(1));
        assert_eq!(
            ceiling.units(),
            0,
            "no unit remains after the session and its connection close"
        );
    }

    #[test]
    fn at_the_ceiling_a_dial_with_a_route_plans_multihop_and_one_without_evicts() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(testing::endpoint_id(1), start);
        ceiling.register_quic(testing::endpoint_id(2), start);
        assert_eq!(
            ceiling.plan_dial(testing::endpoint_id(3), true),
            DialPlan::Multihop,
            "a full ceiling and a route: the dial rides multihop"
        );
        assert!(
            ceiling.pinned(testing::endpoint_id(3)),
            "the peer is pinned"
        );
        assert_eq!(
            ceiling.plan_dial(testing::endpoint_id(4), false),
            DialPlan::Direct,
            "a full ceiling and no route: evict and dial, as before"
        );
        assert!(
            !ceiling.pinned(testing::endpoint_id(4)),
            "the peer is not pinned"
        );
    }

    #[test]
    fn parallel_dials_below_the_ceiling_do_not_all_take_the_last_unit() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(3);
        ceiling.register_quic(testing::endpoint_id(1), start);
        ceiling.register_quic(testing::endpoint_id(2), start);
        assert_eq!(
            ceiling.plan_dial(testing::endpoint_id(3), true),
            DialPlan::Direct,
            "one unit is free: the first dial takes it"
        );
        assert_eq!(
            ceiling.plan_dial(testing::endpoint_id(4), true),
            DialPlan::Multihop,
            "the unit is reserved: the second dial rides multihop"
        );
        ceiling.release_dial(testing::endpoint_id(3));
        assert_eq!(
            ceiling.plan_dial(testing::endpoint_id(5), true),
            DialPlan::Direct,
            "a dial that failed gives its reservation back"
        );
    }

    #[test]
    fn a_pinned_connection_is_no_direct_unit_and_evicts_nobody() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(testing::endpoint_id(1), start);
        ceiling.register_quic(testing::endpoint_id(2), start);
        let pinned = testing::endpoint_id(3);
        assert_eq!(
            ceiling.plan_dial(pinned, true),
            DialPlan::Multihop,
            "planned"
        );
        let admission = ceiling.register_quic(pinned, at(start, 100));
        assert!(
            admission.evict.is_empty(),
            "a pinned connection evicts nobody"
        );
        assert_eq!(ceiling.units(), 2, "a pinned connection is no direct unit");
        assert_eq!(
            ceiling.connections(),
            3,
            "a pinned connection is a connection"
        );
        assert!(
            !ceiling.holds(pinned),
            "the ceiling holds no unit for the pinned peer"
        );
        ceiling.unregister_quic(pinned);
        assert_eq!(ceiling.connections(), 2, "the close ends the connection");
        assert!(!ceiling.pinned(pinned), "the close releases the pin");
    }

    #[test]
    fn above_twice_the_ceiling_the_least_recently_used_pinned_connection_goes() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        let neighbor = testing::endpoint_id(1);
        ceiling.set_neighbors(&HashSet::from([neighbor]), start);
        ceiling.register_quic(testing::endpoint_id(2), start);
        let mut pinned = Vec::new();
        for seed in 10..13_u8 {
            let peer = testing::endpoint_id(seed);
            assert_eq!(ceiling.plan_dial(peer, true), DialPlan::Multihop, "planned");
            let when = at(start, 100 + u64::from(seed));
            let admission = ceiling.register_quic(peer, when);
            pinned.push((peer, admission));
        }
        assert!(
            pinned[0].1.evict.is_empty() && pinned[1].1.evict.is_empty(),
            "up to twice the ceiling nobody goes"
        );
        assert_eq!(
            pinned[2].1.evict,
            vec![pinned[0].0],
            "the fifth connection evicts the least recently used pinned one, and no neighbor"
        );
    }

    #[test]
    fn an_inbound_connection_above_the_ceiling_is_accepted_up_to_twice_the_ceiling() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(testing::endpoint_id(1), start);
        ceiling.register_quic(testing::endpoint_id(2), start);
        for seed in 3..5_u8 {
            let admission = ceiling
                .register_inbound(testing::endpoint_id(seed), at(start, 100 + u64::from(seed)));
            assert!(
                admission.evict.is_empty(),
                "an inbound connection evicts nobody up to 2N"
            );
        }
        assert_eq!(
            ceiling.units(),
            2,
            "the inbound connections above N are no direct unit"
        );
        assert_eq!(
            ceiling.connections(),
            4,
            "they count toward twice the ceiling"
        );
        let admission = ceiling.register_inbound(testing::endpoint_id(5), at(start, 200));
        assert_eq!(admission.evict.len(), 1, "above 2N one connection goes");
    }

    #[test]
    fn the_pinned_peers_that_hold_a_connection_are_listed() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        ceiling.register_quic(testing::endpoint_id(1), start);
        let pinned = testing::endpoint_id(2);
        let planned_only = testing::endpoint_id(3);
        assert_eq!(
            ceiling.plan_dial(pinned, true),
            DialPlan::Multihop,
            "planned"
        );
        assert_eq!(
            ceiling.plan_dial(planned_only, true),
            DialPlan::Multihop,
            "planned"
        );
        assert!(
            ceiling.pinned_connected().is_empty(),
            "a plan without a connection lists nobody"
        );
        ceiling.register_quic(pinned, start);
        assert_eq!(
            ceiling.pinned_connected(),
            vec![pinned],
            "a pinned peer with its connection is listed, a direct unit is not"
        );
    }

    #[test]
    fn a_dial_that_no_send_asked_for_takes_a_free_unit_and_never_the_last_at_the_ceiling() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(2);
        ceiling.register_quic(testing::endpoint_id(1), start);
        assert!(
            ceiling.has_room(testing::endpoint_id(2)),
            "one unit is free"
        );
        assert!(
            ceiling.reserve_proactive(testing::endpoint_id(2)),
            "the first proactive dial takes it"
        );
        assert!(
            !ceiling.has_room(testing::endpoint_id(3)),
            "the unit is reserved, so no room is left"
        );
        assert!(
            !ceiling.reserve_proactive(testing::endpoint_id(3)),
            "a second proactive dial finds the ceiling full and takes nothing"
        );
        assert_eq!(ceiling.units(), 1, "the refusal changed no unit");
        ceiling.release_dial(testing::endpoint_id(2));
        assert!(
            ceiling.reserve_proactive(testing::endpoint_id(3)),
            "a dial that failed gives its unit back"
        );
    }

    #[test]
    fn a_proactive_dial_to_a_peer_that_holds_a_unit_is_allowed_at_the_ceiling() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut ceiling = Ceiling::new(1);
        let neighbor = testing::endpoint_id(1);
        ceiling.set_neighbors(&HashSet::from([neighbor]), start);
        assert!(
            ceiling.has_room(neighbor) && ceiling.reserve_proactive(neighbor),
            "a peer that holds a unit costs no new unit"
        );
        assert!(
            !ceiling.has_room(testing::endpoint_id(2)),
            "another peer finds the ceiling full"
        );
    }
}
