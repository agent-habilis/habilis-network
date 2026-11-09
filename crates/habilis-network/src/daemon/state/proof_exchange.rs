use std::collections::HashMap;
use std::mem;
use std::time::Duration;

use super::proof_book::ProofBook;
use crate::protocol::identity::{IdentityProof, verify_proof};
use crate::protocol::{AuthorKey, MeshId, Nickname};
use crate::util::bounded_fifo_set::BoundedFifoSet;
use crate::util::clock::Instant;
use iroh::{EndpointId, PublicKey};

/// The first retry waits 30 s, and each next one waits twice as long: 30 s, 60 s, 120 s.
const FIRST_RETRY_WAIT: Duration = Duration::from_secs(30);
const RETRIES: u8 = 3;
/// After the fast retries a session is asked once per 10 minutes, for as long as its entry lives: while the session
/// stays visible and has no proof. The entry goes with the session, and the rate is bounded by the budgets.
const SLOW_RETRY_WAIT: Duration = Duration::from_secs(600);
/// The asks of sessions that are not in the roster and claim one bound nickname: 4 open at most. A
/// session that claims a bound nickname is asked for its proof, and a flood of forged keys under
/// that nickname must replace its own asks and nobody else's.
const OPEN_ASKS_PER_NICKNAME: usize = 4;
/// The asks that were skipped for lack of a warm path and wait for one: 64 at most. When the map is full a
/// new one takes the place of the oldest, whose session falls back to the ask at its next alive frame.
const DEFERRED_ASKS_MAX: usize = 64;
/// The proofs that are valid but INACTIVE: the proof of a sender that is not live (an old copy of a frame, a quiet
/// session), kept for the day that its session proves presence. A pending proof binds no nickname, replaces no
/// session and evicts none; it only admits its own session. Two classes, so that a flood of one cannot push out the
/// other: the proofs of a member that already holds the nickname (the sender can only be a restart of that member;
/// the attacker cannot sign them), and all the others (free nicknames: anyone can sign a proof of its own and put it
/// in an old frame). Each class holds 32 at most, the oldest dropped when it is full.
const PENDING_PROOFS_CLASS_MAX: usize = 32;
/// The most pending proofs that one member has in the class of the holders: a member signs as many valid proofs as it
/// likes for its own nickname, and one member must not push out the restart proof of another.
const PENDING_PER_MEMBER: usize = 4;
/// The proof requests that one endpoint gets, for each `ASK_BUDGET_WINDOW`. A peer that makes fresh session keys
/// (they are free) sets off one ask for each key to its own endpoint: each ask is a signature and a task that
/// holds a frame. The budget is checked before the request is signed.
const ASKS_PER_ENDPOINT: usize = 8;
/// The proof requests that this node sends, for each `ASK_BUDGET_WINDOW`, in all: the asks after the first of an
/// endpoint need room in it. The first ask of each endpoint is guaranteed (it counts in it, and it needs none),
/// up to `FIRST_ASKS_IN_ALL` of them, so a window holds at most that many first asks plus the asks after them.
const ASKS_IN_ALL: usize = 64;
/// The guaranteed first asks that this node sends, for each `ASK_BUDGET_WINDOW`, in all. Without it, the map of
/// counts (it drops its oldest endpoint) lets an endpoint whose count was dropped be first again, and the asks
/// follow the rate of an attacker that has many endpoints with a path. A window holds at most this number of
/// first asks, and `ASKS_IN_ALL` asks after them.
const FIRST_ASKS_IN_ALL: usize = 256;
/// The first asks for sessions that claim a bound nickname (a restart of the member that holds the name, or an
/// intruder), for each window, outside the shared `FIRST_ASKS_IN_ALL`: an attacker that keeps many endpoints with a
/// path asking cannot starve the restart of a member that holds a name. The asks of the reserve count in the work in
/// all. At most `ASKS_PER_BOUND_NICKNAME` for each nickname, and at most `ASKS_PER_ENDPOINT` for each endpoint: an
/// attacker that claims 16 bound nicknames with 4 fresh sessions each uses the whole reserve, and the restart of
/// another bound nickname waits one window.
const FIRST_ASKS_BOUND: usize = 64;
const ASKS_PER_BOUND_NICKNAME: usize = 4;
/// The window of the budget of the proof requests.
const ASK_BUDGET_WINDOW: Duration = Duration::from_secs(10);
/// The endpoints that have a count in the budget: 256 at most. A count outside its window is dropped first, the
/// oldest one; a count inside its window is never dropped, and an endpoint that the full map does not track waits
/// in the deferred map until a window has moved.
const ASK_BUDGET_ENDPOINTS_MAX: usize = 256;
/// How long a skipped ask waits for a warm path before the alive cycle takes over.
const DEFERRED_ASK_TTL: Duration = Duration::from_secs(30);
/// The least time between two tries of one deferred ask, so a flood of frames from one endpoint makes at most one
/// signature for each session and gap.
const DEFERRED_ASK_GAP: Duration = Duration::from_secs(1);

/// The wait after the ask number `tries` (0 for the first): 30 s, 60 s, 120 s, then 10 minutes.
fn retry_wait(tries: u8) -> Duration {
    if tries < RETRIES {
        FIRST_RETRY_WAIT * 2u32.pow(u32::from(tries))
    } else {
        SLOW_RETRY_WAIT
    }
}

/// A skipped ask: when it was first skipped, and when it was tried again last (none: not yet).
#[derive(Debug, Clone)]
struct DeferredAsk {
    /// The nickname that the session claims. A session that the roster refused is not in the roster, so
    /// the roster has no name for it; the retry reads the name here.
    nickname: Nickname,
    since: Instant,
    tried: Option<Instant>,
}

/// How many times a session was asked, and when the next request may go.
#[derive(Debug, Clone)]
struct Retry {
    tries: u8,
    next_at: Instant,
    // the bound nickname that a session outside the roster claimed, when it was asked
    claimed: Option<Nickname>,
}

/// The proofs this node holds, and the sessions it already asked for one. A proof comes in the
/// `joined` frame of a session. A receiver that missed that frame asks the session once, by a
/// unicast request, so a calm mesh carries no proof bytes beyond the `joined` frames.
///
/// Between two proofs for one session, the one with the higher run wins. On a tie the first stays.
///
/// A nickname is bound to the member key that proved it, for as long as a session of that member
/// is held in the roster. A session that claims a bound nickname with no proof of that member is
/// not admitted ([`Self::admits`]), and a proof of another member for it is not held. A nickname
/// that no held session binds is free: a session with no proof is admitted and binds nothing.
/// The reserve of the asks of the claims of bound nicknames, in one window. Each map holds at most
/// `FIRST_ASKS_BOUND` entries, as many as the asks that one window allows.
#[derive(Debug)]
struct BoundReserve {
    /// When the window started.
    start: Instant,
    /// The asks that the reserve gave in it.
    total: usize,
    /// How many of them went for each nickname.
    by_nickname: HashMap<Nickname, usize>,
    /// How many of them went to each endpoint.
    by_endpoint: HashMap<EndpointId, usize>,
}

#[derive(Debug)]
pub(crate) struct ProofExchange {
    // the proofs, as many as the cap at most; the binding of a nickname is derived from them, so
    // the bindings are bounded by the same cap
    book: ProofBook<AuthorKey, (Nickname, IdentityProof)>,
    // the requests per session, as many as the book holds at most: when full, the oldest goes
    asked: ProofBook<AuthorKey, Retry>,
    // the sessions told that their nickname is bound to another member: the oldest goes at the cap
    told: BoundedFifoSet<AuthorKey>,
    // the sessions that a newer run of their member dropped, until the caller takes them: at most as
    // many as the book holds, and `roster_gate` takes them on each frame, so it holds a few at most
    // between two frames
    replaced: Vec<AuthorKey>,
    // the sessions of another member that a proof just bound the nickname away from, until the caller
    // takes them: the roster size at most (live and quiet), and `roster_gate` takes them on each frame
    evicted: Vec<AuthorKey>,
    // the asks that waited for a warm path: `DEFERRED_ASKS_MAX` at most, the oldest dropped when full
    deferred: ProofBook<AuthorKey, DeferredAsk>,
    // the valid but inactive proofs of senders that are not live, of a member that holds the nickname already:
    // `PENDING_PROOFS_CLASS_MAX` at most, the oldest dropped when full; not in `book`, so nothing that reads the
    // book sees them
    pending_held: ProofBook<AuthorKey, (Nickname, IdentityProof)>,
    // the same for all the other pending proofs
    pending_other: ProofBook<AuthorKey, (Nickname, IdentityProof)>,
    // the proof requests sent to each endpoint in the window: when it started, and how many;
    // `ASK_BUDGET_ENDPOINTS_MAX` endpoints at most, the oldest dropped when full
    ask_budget: ProofBook<EndpointId, (Instant, usize)>,
    ask_budget_bound: Option<BoundReserve>,
    // the proof requests sent in all in the window: when it started, how many, and how many of them were the
    // guaranteed first ask of an endpoint
    ask_budget_all: Option<(Instant, usize, usize)>,
    ties_refused: u64,
    bound_refused: u64,
    gate_refused: u64,
}

impl ProofExchange {
    pub(crate) fn with_cap(cap: usize) -> Self {
        Self {
            book: ProofBook::with_cap(cap),
            asked: ProofBook::with_cap(cap),
            told: BoundedFifoSet::new(cap),
            replaced: Vec::new(),
            evicted: Vec::new(),
            deferred: ProofBook::with_cap(DEFERRED_ASKS_MAX),
            pending_held: ProofBook::with_cap(PENDING_PROOFS_CLASS_MAX),
            pending_other: ProofBook::with_cap(PENDING_PROOFS_CLASS_MAX),
            ask_budget: ProofBook::with_cap(ASK_BUDGET_ENDPOINTS_MAX),
            ask_budget_all: None,
            ask_budget_bound: None,
            ties_refused: 0,
            bound_refused: 0,
            gate_refused: 0,
        }
    }

    /// The member key that holds `nickname` now: the proof of a session that `is_held` says is in
    /// the roster, live or quiet, names the nickname.
    fn bound_to(
        &self,
        nickname: &Nickname,
        is_held: impl Fn(&AuthorKey) -> bool,
    ) -> Option<PublicKey> {
        let mut holders = self.book.iter();
        let holder = holders.find(|(session, (named, _))| named == nickname && is_held(session));
        holder.map(|(_, (_, proof))| proof.identity)
    }

    /// Whether some held session of the roster binds `nickname`.
    pub(crate) fn is_bound(
        &self,
        nickname: &Nickname,
        is_held: impl Fn(&AuthorKey) -> bool,
    ) -> bool {
        self.bound_to(nickname, is_held).is_some()
    }

    /// Whether the frames of `session` that claim `nickname` reach the roster. They do when the
    /// session proved the nickname for the member that holds the binding, or when no held session binds it. A bound nickname with no
    /// proof of its member is the join error of the claimant; the refusal is counted. A session that was
    /// admitted while no proof bound the nickname does not keep it: the proof that binds the name ends it
    /// ([`ProofExchange::evict`]).
    pub(crate) fn admits(
        &mut self,
        session: &AuthorKey,
        nickname: &Nickname,
        is_held: impl Fn(&AuthorKey) -> bool,
    ) -> bool {
        // A cached proof counts only while it agrees with the binding now: a proof that was cached while
        // its session was not in the roster must not pass once another member holds the nickname.
        // A pending proof (valid, inactive) counts for the admission of its own session only: the nickname is
        // bound to its member, or free, and the session then enters the roster, where the proof is activated.
        let in_book = self.book.get(session);
        let kept = in_book.or_else(|| self.pending_entry(session));
        let proof_of = kept
            .filter(|(named, _)| named == nickname)
            .map(|(_, proof)| proof.identity);
        let bound = self.bound_to(nickname, is_held);
        let admitted = match (proof_of, bound) {
            (Some(member), Some(held)) => member == held,
            (Some(_) | None, None) => true,
            (None, Some(_)) => false,
        };
        if !admitted {
            self.gate_refused += 1;
        }
        admitted
    }

    /// Forget the proof of `session`, which said goodbye, and the requests for it.
    pub(crate) fn forget(&mut self, session: &AuthorKey) {
        self.drop_pending(session);
        self.book.remove(session);
        self.asked.remove(session);
        self.deferred.remove(session);
    }

    /// The ask for `session` was skipped for lack of a warm path: it waits for one. A session that waits
    /// already keeps its first time, so the wait ends after `DEFERRED_ASK_TTL` whatever comes.
    pub(crate) fn defer_ask(&mut self, session: AuthorKey, nickname: &Nickname, now: Instant) {
        if self.deferred.get(&session).is_some() {
            return;
        }
        // every entry reads as dead, so a full map drops the oldest one
        self.deferred.insert_evicting(
            session,
            DeferredAsk {
                nickname: nickname.clone(),
                since: now,
                tried: None,
            },
            |_, _| false,
        );
    }

    /// The ask for `session` no longer waits: it went out, or the session holds a proof or is gone.
    pub(crate) fn undefer(&mut self, session: &AuthorKey) {
        self.deferred.remove(session);
    }

    /// Whether no ask waits. The caller asks it first, so a node with nothing deferred pays one comparison.
    pub(crate) fn deferred_is_empty(&self) -> bool {
        self.deferred.len() == 0
    }

    /// The sessions whose ask waits and may be tried at `now`: the oldest first. The first try of a session
    /// is free, so the ask goes as soon as a path is up; after it, none that was tried less than
    /// `DEFERRED_ASK_GAP` ago. It marks nothing: the caller marks the ones that it tries.
    pub(crate) fn deferred_due(&self, now: Instant) -> Vec<(AuthorKey, Nickname)> {
        let due = self.deferred.keys_where(|waiting| {
            waiting
                .tried
                .is_none_or(|tried| now.saturating_duration_since(tried) >= DEFERRED_ASK_GAP)
        });
        let mut named = Vec::with_capacity(due.len());
        for session in due {
            if let Some(waiting) = self.deferred.get(&session) {
                named.push((session, waiting.nickname.clone()));
            }
        }
        named
    }

    /// The deferred ask of `session` is tried now.
    pub(crate) fn mark_deferred_tried(&mut self, session: &AuthorKey, now: Instant) {
        if let Some(waiting) = self.deferred.get_mut(session) {
            waiting.tried = Some(now);
        }
    }

    /// Drop the asks that waited `DEFERRED_ASK_TTL` and more: the alive cycle takes those sessions over.
    pub(crate) fn expire_deferred(&mut self, now: Instant) {
        let old = self
            .deferred
            .keys_where(|waiting| now.saturating_duration_since(waiting.since) >= DEFERRED_ASK_TTL);
        for session in old {
            self.deferred.remove(&session);
        }
    }

    /// How many asks wait.
    #[cfg(test)]
    pub(crate) fn deferred_len(&self) -> usize {
        self.deferred.len()
    }

    /// The sessions that a newer run of their member dropped since the last call. The caller ends
    /// them in the roster.
    pub(crate) fn take_replaced(&mut self) -> Vec<AuthorKey> {
        mem::take(&mut self.replaced)
    }

    /// Mark `sessions` for the end: a proof bound their nickname to another member.
    pub(crate) fn evict(&mut self, sessions: impl IntoIterator<Item = AuthorKey>) {
        self.evicted.extend(sessions);
    }

    /// Whether one more proof request may go to `endpoint` at `now`, and the request is counted when it may.
    /// The caller asks BEFORE it signs the request. An ask that may not go waits in the map of the deferred
    /// asks, and goes when the window has moved.
    #[cfg(test)]
    pub(crate) fn may_ask(&mut self, endpoint: EndpointId, now: Instant) -> bool {
        self.may_ask_for(endpoint, None, now)
    }

    /// `may_ask` for a session that CLAIMS A BOUND NICKNAME (`claim`: a restart of the member that holds the
    /// name, or an intruder). The asks of such a session have a reserve of their own, outside the shared budgets, while
    /// its endpoint is under its cap of 8, and they are not refused because the map of counts is full of live counts
    /// (the ask goes out untracked, no live count is dropped, and the reserve keeps the cap of that endpoint itself):
    /// an attacker that keeps many endpoints asking cannot starve the restart of a member that holds a name. The
    /// reserve is `FIRST_ASKS_BOUND` for each window and `ASKS_PER_BOUND_NICKNAME` for each nickname, and the asks
    /// that it allows count in the work in all.
    pub(crate) fn may_ask_for(
        &mut self,
        endpoint: EndpointId,
        claim: Option<&Nickname>,
        now: Instant,
    ) -> bool {
        let in_window = |start: Instant| now.saturating_duration_since(start) < ASK_BUDGET_WINDOW;
        let (all_start, all_count, all_first) = match self.ask_budget_all {
            Some((start, count, first)) if in_window(start) => (start, count, first),
            _ => (now, 0, 0),
        };
        let (start, count) = match self.ask_budget.get(&endpoint) {
            Some((start, count)) if in_window(*start) => (*start, *count),
            _ => (now, 0),
        };
        // A count that is inside its window is never dropped to make room: an endpoint that used its asks would
        // get a second budget. A full map of live counts defers an endpoint that it does not track.
        let tracked = self.ask_budget.get(&endpoint).is_some();
        let has_room = self.ask_budget.len() < ASK_BUDGET_ENDPOINTS_MAX
            || self
                .ask_budget
                .iter()
                .any(|(_, (counted_at, _))| !in_window(*counted_at));
        // The reserve is for the SESSION that claims a bound nickname: any ask of it, while its endpoint is under its
        // own cap (an embedder keeps one endpoint across starts, so a restart can come on an endpoint with a count).
        // A full map of live counts leaves the ask untracked: it counts in the reserve and in the work in all.
        if count < ASKS_PER_ENDPOINT
            && let Some(nickname) = claim
            && self.take_bound_reserve(endpoint, nickname, now)
        {
            self.ask_budget_all = Some((all_start, all_count + 1, all_first));
            if tracked || has_room {
                self.ask_budget.insert_evicting(
                    endpoint,
                    (start, count + 1),
                    |_, (counted_at, _)| in_window(*counted_at),
                );
            }
            return true;
        }
        if !tracked && !has_room {
            return false;
        }
        // The first ask of an endpoint in the window is guaranteed: it needs no room in the budget in all (it counts
        // in it). The budget in all would otherwise be the vector of a starvation: one peer with a few endpoints
        // that have a path to us uses all of it, and every honest endpoint is deferred. Only the asks after the
        // first need both budgets.
        // The first asks have a budget in all of their own.
        let first = count == 0;
        let over_all = if first {
            all_first >= FIRST_ASKS_IN_ALL
        } else {
            all_count >= ASKS_IN_ALL
        };
        if over_all || count >= ASKS_PER_ENDPOINT {
            self.ask_budget_all = Some((all_start, all_count, all_first));
            return false;
        }
        self.ask_budget_all = Some((all_start, all_count + 1, all_first + usize::from(first)));
        // a full map drops its oldest count that is outside its window (there is one: `has_room`)
        self.ask_budget
            .insert_evicting(endpoint, (start, count + 1), |_, (counted_at, _)| {
                in_window(*counted_at)
            });
        true
    }

    /// Take one ask out of the reserve of the claims of bound nicknames, if there is room for `nickname` and for
    /// `endpoint`. The reserve has its own window; its map of nicknames and its map of endpoints hold at most
    /// `FIRST_ASKS_BOUND` entries each, as many as the asks that it allows in a window.
    ///
    /// The count of the endpoint is kept here as well as in `ask_budget`, because a full map of live counts leaves
    /// the ask untracked there: an endpoint that claims several bound nicknames would otherwise get
    /// `ASKS_PER_BOUND_NICKNAME` asks for each of them, over the cap that every endpoint has.
    fn take_bound_reserve(
        &mut self,
        endpoint: EndpointId,
        nickname: &Nickname,
        now: Instant,
    ) -> bool {
        let mut reserve = match self.ask_budget_bound.take() {
            Some(reserve) if now.saturating_duration_since(reserve.start) < ASK_BUDGET_WINDOW => {
                reserve
            }
            _ => BoundReserve {
                start: now,
                total: 0,
                by_nickname: HashMap::new(),
                by_endpoint: HashMap::new(),
            },
        };
        let used = reserve.by_nickname.get(nickname).copied().unwrap_or(0);
        let from_endpoint = reserve.by_endpoint.get(&endpoint).copied().unwrap_or(0);
        let allowed = reserve.total < FIRST_ASKS_BOUND
            && used < ASKS_PER_BOUND_NICKNAME
            && from_endpoint < ASKS_PER_ENDPOINT;
        if allowed {
            reserve.total += 1;
            reserve.by_nickname.insert(nickname.clone(), used + 1);
            reserve.by_endpoint.insert(endpoint, from_endpoint + 1);
        }
        self.ask_budget_bound = Some(reserve);
        allowed
    }

    /// How many endpoints have a count in the budget of the proof requests.
    #[cfg(test)]
    pub(crate) fn ask_budget_endpoints(&self) -> usize {
        self.ask_budget.len()
    }

    /// Keep the proof of a sender that is not live as a PENDING proof: valid (its signature was checked), and
    /// inactive. `member_holds_name` says that the member of the proof holds the nickname in the book already AND
    /// that the run is above every run of that member in the book (a past run, which anyone who logged its frame can
    /// replay, is not a restart): the proof goes in its own class, which the other proofs cannot push out. The
    /// higher run of a session wins.
    fn hold_pending(
        &mut self,
        session: AuthorKey,
        nickname: &Nickname,
        proof: IdentityProof,
        member_holds_name: bool,
    ) {
        if self
            .pending_entry(&session)
            .is_some_and(|(_, held)| held.run >= proof.run)
        {
            return;
        }
        self.drop_pending(&session);
        if !member_holds_name {
            // every entry reads as dead, so a full class drops its oldest one
            self.pending_other
                .insert_evicting(session, (nickname.clone(), proof), |_, _| false);
            return;
        }
        // The class of the holder is kept for the RESTARTS of the members that hold a name, and a member signs as many
        // valid proofs as it likes for its own name. So each member has a cap in it, `PENDING_PER_MEMBER`, and keeps
        // its HIGHEST runs (only the member signs its runs, so a replay is always below its real newest one): a
        // member over its cap replaces its own lowest run, or is refused if the run is not above it. A full class
        // drops the lowest run of the member that has the most entries, so a member that holds several entries never
        // pushes out the one entry of another. With a full class of members that hold one entry each the choice is
        // between members: the proof of one of them goes, and its session is admitted at its next ask (30 s, 60 s,
        // 120 s). The class holds `PENDING_PROOFS_CLASS_MAX` members, as many as a mesh of that size has.
        let member = proof.identity;
        let own: Vec<(AuthorKey, u64)> = self
            .pending_held
            .iter()
            .filter(|(_, (_, kept))| kept.identity == member)
            .map(|(held, (_, kept))| (*held, kept.run))
            .collect();
        let own_lowest: Option<(AuthorKey, u64)> = own.iter().min_by_key(|(_, run)| *run).copied();
        if let Some((lowest, run)) = own_lowest
            && own.len() >= PENDING_PER_MEMBER
        {
            if proof.run <= run {
                return;
            }
            self.pending_held.remove(&lowest);
        } else if self.pending_held.len() >= PENDING_PROOFS_CLASS_MAX {
            let mut by_member: HashMap<PublicKey, usize> = HashMap::new();
            for (_, (_, kept)) in self.pending_held.iter() {
                *by_member.entry(kept.identity).or_default() += 1;
            }
            let fullest: Option<PublicKey> = by_member
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(fullest, _)| fullest);
            let victim: Option<AuthorKey> = self
                .pending_held
                .iter()
                .filter(|(_, (_, kept))| Some(kept.identity) == fullest)
                .min_by_key(|(_, (_, kept))| kept.run)
                .map(|(held, _)| *held);
            if let Some(victim) = victim {
                self.pending_held.remove(&victim);
            }
        }
        self.pending_held.insert(session, (nickname.clone(), proof));
    }

    /// The highest run of `member` among the sessions that the book holds, or 0.
    fn highest_run_of(&self, member: PublicKey) -> u64 {
        let runs = self
            .book
            .iter()
            .filter(|(_, (_, held))| held.identity == member)
            .map(|(_, (_, held))| held.run);
        runs.max().unwrap_or(0)
    }

    fn pending_entry(&self, session: &AuthorKey) -> Option<&(Nickname, IdentityProof)> {
        let held = self.pending_held.get(session);
        held.or_else(|| self.pending_other.get(session))
    }

    fn drop_pending(&mut self, session: &AuthorKey) {
        self.pending_held.remove(session);
        self.pending_other.remove(session);
    }

    /// Whether a pending proof is kept for `session`.
    pub(crate) fn has_pending(&self, session: &AuthorKey) -> bool {
        self.pending_entry(session).is_some()
    }

    /// Take the pending proof of `session` out, if it is for `nickname`. A frame of the session under another
    /// nickname leaves it where it is.
    pub(crate) fn take_pending(
        &mut self,
        session: &AuthorKey,
        nickname: &Nickname,
    ) -> Option<IdentityProof> {
        let taken = self
            .pending_entry(session)
            .filter(|(named, _)| named == nickname)
            .map(|(_, proof)| *proof);
        if taken.is_some() {
            self.drop_pending(session);
        }
        taken
    }

    /// How many pending proofs are kept.
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending_held.len() + self.pending_other.len()
    }

    /// The sessions that a proof bound the nickname away from since the last call. The caller ends them in
    /// the roster. They said no goodbye: a session that was shown ends with a `left` line, and one that was never
    /// shown ends with none.
    pub(crate) fn take_evicted(&mut self) -> Vec<AuthorKey> {
        mem::take(&mut self.evicted)
    }

    /// A frame was refused the roster because it claims the nickname of this node.
    pub(crate) fn note_gate_refused(&mut self) {
        self.gate_refused += 1;
    }

    /// Whether `session` is told now that its nickname is bound to another member: once for each
    /// session, so a resent `joined` frame makes one error line and not a stream.
    pub(crate) fn tell_once(&mut self, session: &AuthorKey) -> bool {
        self.told.insert(*session)
    }

    /// An alive frame came from `session`. True means: send the session a proof request now. A
    /// request that got no answer is sent again, with a doubling back-off (3 fast retries, then one every 10
    /// minutes for as long as the entry lives). The caller tells [`Self::note_asked`] when the request went out.
    pub(crate) fn wants_proof(&self, session: &AuthorKey, now: Instant) -> bool {
        if self.book.get(session).is_some() {
            return false;
        }
        self.asked
            .get(session)
            .is_none_or(|retry| now >= retry.next_at)
    }

    /// The request for `session` went out at `now`: the retry clock of the session starts. `claimed`
    /// is the bound nickname of a session that is not in the roster. At most 4 asks stay open for
    /// each such nickname, and the oldest of that nickname goes for a new one. `is_held` says whether
    /// a session is in the roster. The book holds 1024 records: when it is full, the record of the
    /// oldest session that is not in the roster goes, so the retry clock of a session that is in it
    /// is not reset. Only when all 1024 are in the roster does the oldest record go, and that
    /// session can be asked again at once: the limit of a mesh of more than 1024 sessions that send
    /// no proof.
    pub(crate) fn note_asked(
        &mut self,
        session: &AuthorKey,
        now: Instant,
        claimed: Option<&Nickname>,
        is_held: impl Fn(&AuthorKey) -> bool,
    ) {
        // the request went out: the ask no longer waits for a path
        self.deferred.remove(session);
        let tries = self.asked.get(session).map_or(0, |retry| retry.tries);
        if let Some(nickname) = claimed {
            let same = |retry: &Retry| retry.claimed.as_ref() == Some(nickname);
            let open: Vec<AuthorKey> = self
                .asked
                .keys_where(same)
                .into_iter()
                .filter(|asked| asked != session)
                .collect();
            let excess = (open.len() + 1).saturating_sub(OPEN_ASKS_PER_NICKNAME);
            let oldest_ones = &open[..excess.min(open.len())];
            for oldest in oldest_ones {
                self.asked.remove(oldest);
            }
        }
        let retry = Retry {
            tries: tries.saturating_add(1),
            next_at: now + retry_wait(tries),
            claimed: claimed.cloned(),
        };
        self.asked
            .insert_evicting(*session, retry.clone(), |asked, _| is_held(asked));
        if self.asked.get(session).is_none() {
            // Every record is of a session in the roster: the oldest goes, as it always did.
            if let Some(oldest) = self.asked.keys_where(|_| true).first() {
                self.asked.remove(oldest);
            }
            self.asked.insert(*session, retry);
        }
    }

    /// A proof came for `session`. It is held if it verifies for this nickname and mesh, if it does
    /// not lower the run of a proof already held, and if no held session binds the nickname to
    /// another member. `is_held` says whether a held session is in the roster: at the cap the
    /// oldest session that is not goes first, and a book of sessions in the roster refuses.
    #[cfg(test)]
    pub(crate) fn accept(
        &mut self,
        session: &AuthorKey,
        nickname: &Nickname,
        mesh: &MeshId,
        proof: IdentityProof,
        is_held: impl Fn(&AuthorKey) -> bool,
    ) -> bool {
        self.accept_live(session, nickname, mesh, proof, true, is_held)
    }

    /// `accept` (a test helper that passes a live sender) for a frame whose sender may not be live. `claimant_live` says that the sender is in the
    /// roster (live) after the frame. A proof of a sender that is not live does not replace a live session of its
    /// member: a historical `joined` frame with a higher run (the member restored a lower counter) would end the
    /// live session, with the frames that wait for it, for a member that is not there. Such a proof is kept
    /// inactive (pending), and it activates when its session proves presence.
    pub(crate) fn accept_live(
        &mut self,
        session: &AuthorKey,
        nickname: &Nickname,
        mesh: &MeshId,
        proof: IdentityProof,
        claimant_live: bool,
        is_held: impl Fn(&AuthorKey) -> bool,
    ) -> bool {
        // A copy of the pending proof of a sender that is still not live costs a lookup, as a copy of a held one.
        if !claimant_live
            && self
                .pending_entry(session)
                .is_some_and(|(_, kept)| kept.run >= proof.run)
        {
            return false;
        }
        // The run is compared first: a copy of the held proof, which comes with each resent or
        // re-announced `joined` frame, costs no signature check.
        if let Some((_, held)) = self.book.get(session)
            && held.run >= proof.run
        {
            let copy = held.run == proof.run
                && held.identity == proof.identity
                && held.signature == proof.signature;
            if !copy {
                self.ties_refused += 1;
            }
            return false;
        }
        // The binding is checked before the signature of the proof: a copy of a refused proof (a replay,
        // or the one answer of a member, which every asker gets) costs a lookup, not a signature check.
        let bound = self.bound_to(nickname, &is_held);
        if bound.is_some_and(|member| member != proof.identity) {
            self.bound_refused += 1;
            return false;
        }
        if !verify_proof(&proof, session, nickname.as_ref(), mesh.as_ref()) {
            return false;
        }
        // The proof is valid (its signature was checked: a forged one is never kept). If its sender is not live
        // (an old copy of a frame, a quiet session) it is kept INACTIVE: it binds no nickname, replaces no
        // session and evicts none, so a replay of an old signed frame changes nothing in the roster. It admits its
        // own session, and it is activated when that session proves presence.
        if !claimant_live {
            // `bound` is the member that holds the nickname, and it is the member of this proof or none
            let restart = bound.is_some() && proof.run > self.highest_run_of(proof.identity);
            self.hold_pending(*session, nickname, proof, restart);
            return false;
        }
        // A member holds one session, the newest: a restart makes a new session with a higher run,
        // and the sessions of its older runs go. A proof of a run that is not higher than the run
        // of a session in the roster is a late copy of an older frame, and it does not replace the
        // newer session. A session that is not in the roster is dead: it never blocks, whatever its
        // run, so a member that restores an old run file is still held.
        let others = |held: &AuthorKey, (_, other): &(Nickname, IdentityProof)| {
            held != session && other.identity == proof.identity
        };
        let runs: Vec<(AuthorKey, u64, bool)> = self
            .book
            .iter()
            .filter(|(held, entry)| others(held, entry))
            .map(|(held, (_, other))| (*held, other.run, is_held(held)))
            .collect();
        if runs.iter().any(|(_, run, live)| *live && *run >= proof.run) {
            self.ties_refused += 1;
            return false;
        }
        for (older, _, live) in runs {
            self.book.remove(&older);
            if live {
                self.replaced.push(older);
            }
        }
        self.book
            .insert_evicting(*session, (nickname.clone(), proof), |held, _| is_held(held));
        let held = self.book.get(session).is_some();
        if held {
            self.deferred.remove(session);
            self.drop_pending(session);
        }
        held
    }

    /// Whether one more answer to `asker` may go out at `now`: one per asker and window, and the per-minute cap of the node.
    pub(crate) fn may_answer(&mut self, asker: &AuthorKey, now: Instant, cap: usize) -> bool {
        self.book.allow_answer_to(asker, now, cap)
    }

    /// How many proofs this node refused because their run did not beat the held run. A proof is
    /// counted before its signature is checked, so a bad proof of a held session counts too; only
    /// the holder of the session key can send one. A copy of the held proof is not counted.
    pub(crate) fn ties_refused(&self) -> u64 {
        self.ties_refused
    }

    /// How many proofs were refused because another member holds the nickname.
    pub(crate) fn bound_refused(&self) -> u64 {
        self.bound_refused
    }

    /// How many frames were refused the roster because they claim a bound nickname with no proof.
    pub(crate) fn gate_refused(&self) -> u64 {
        self.gate_refused
    }

    /// How many proofs the full book refused because every held session was in the roster.
    pub(crate) fn refused(&self) -> u64 {
        self.book.refused()
    }

    /// How many answers the per-asker limit and the node-wide cap refused.
    pub(crate) fn answers_refused(&self) -> u64 {
        self.book.answers_refused()
    }

    pub(crate) fn len(&self) -> usize {
        self.book.len()
    }

    pub(crate) fn proof_of(&self, session: &AuthorKey) -> Option<&IdentityProof> {
        self.book.get(session).map(|(_, proof)| proof)
    }

    /// The proof of `session` for `nickname`: none when the session proved another nickname. A proof signs
    /// its nickname, so it says nothing about a frame that claims a different one.
    pub(crate) fn proof_for(
        &self,
        session: &AuthorKey,
        nickname: &Nickname,
    ) -> Option<&IdentityProof> {
        self.book
            .get(session)
            .filter(|(named, _)| named == nickname)
            .map(|(_, proof)| proof)
    }

    /// [`Self::proof_for`], and then the pending proof of the session: for the ADMISSION of a session only. A
    /// pending proof (valid, inactive) is the proof that its session shows, as in [`Self::admits`]; it binds
    /// nothing and is no active proof.
    pub(crate) fn proof_for_admission(
        &self,
        session: &AuthorKey,
        nickname: &Nickname,
    ) -> Option<&IdentityProof> {
        let kept = self
            .book
            .get(session)
            .or_else(|| self.pending_entry(session));
        kept.filter(|(named, _)| named == nickname)
            .map(|(_, proof)| proof)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ASK_BUDGET_ENDPOINTS_MAX, ASK_BUDGET_WINDOW, ASKS_IN_ALL, ASKS_PER_BOUND_NICKNAME,
        ASKS_PER_ENDPOINT, DEFERRED_ASK_GAP, DEFERRED_ASK_TTL, DEFERRED_ASKS_MAX, EndpointId,
        FIRST_ASKS_IN_ALL, PENDING_PER_MEMBER, PENDING_PROOFS_CLASS_MAX, ProofExchange,
        verify_proof,
    };
    use crate::protocol::identity::Identity;
    use crate::protocol::{AuthorKey, MeshId, Nickname};
    use crate::util::clock::Instant;
    use crate::util::tuning::QUIET_CAP;
    use iroh::SecretKey;
    use std::time::Duration;

    /// The endpoint id of `index`: as many distinct ids as a test needs.
    fn endpoint_of(index: u32) -> EndpointId {
        let mut bytes = [1u8; 32];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        SecretKey::from_bytes(&bytes).public()
    }

    /// A proof of a nickname that another member holds is refused at the binding, before its signature is
    /// read: a replayed copy of a refused frame costs a lookup. A proof whose signature is not valid
    /// shows it: it is counted as refused for the binding, which is the first check that it meets.
    #[test]
    fn a_proof_for_a_held_nickname_is_refused_before_its_signature_is_read() {
        let mesh = MeshId::from("💬test");
        let nickname = Nickname::from("alice");
        let (holder, other) = (Identity::generate(), Identity::generate());
        let (holder_session, other_session) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let held = holder.prove(&holder_session, nickname.as_ref(), mesh.as_ref(), 1);
        assert!(
            book.accept(&holder_session, &nickname, &mesh, held, |_| true),
            "the holder binds the nickname"
        );
        let mut forged = other.prove(&other_session, nickname.as_ref(), mesh.as_ref(), 1);
        forged.run += 1;

        let accepted = book.accept(&other_session, &nickname, &mesh, forged, |_| true);

        assert!(!accepted, "the proof is refused");
        assert_eq!(
            book.bound_refused(),
            1,
            "it was refused at the binding, before its signature was checked"
        );
    }

    /// The asks that wait for a path are 64 at most: fed 10 times the cap, the map holds the cap, and the
    /// oldest ones are the ones that went.
    #[test]
    fn the_deferred_asks_stay_inside_their_cap_when_they_are_fed_10_times_the_cap() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let now = Instant::now();
        let sessions: Vec<AuthorKey> = (0..640)
            .map(|_| Identity::generate().author_key())
            .collect();

        for session in &sessions {
            book.defer_ask(
                *session,
                &Nickname::try_new("alice").expect("a nickname"),
                now,
            );
        }

        assert_eq!(book.deferred_len(), DEFERRED_ASKS_MAX, "the cap holds");
        let waiting: Vec<AuthorKey> = book
            .deferred_due(now + DEFERRED_ASK_GAP)
            .into_iter()
            .map(|(session, _)| session)
            .collect();
        assert!(
            waiting.contains(&sessions[639]) && !waiting.contains(&sessions[0]),
            "the newest waits and the oldest was dropped"
        );
    }

    /// The pending proofs (valid, inactive: the proofs of senders that are not live) are bounded, each class by its own
    /// cap: fed 10 times the cap, a class holds the cap, and the other class keeps its entries. In the class of the
    /// holders no member has more than `PENDING_PER_MEMBER`, and each keeps its newest. They are not in the book, so
    /// nothing that reads the book sees them. A taken one is gone.
    #[test]
    fn the_pending_proofs_stay_inside_their_cap_when_they_are_fed_10_times_the_cap() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let mesh = MeshId::from("test");
        let member = Identity::generate();
        let alice = Nickname::try_new("alice").expect("a nickname");

        // no session of the member holds the name: the proofs go in the other class, oldest first
        let others: Vec<AuthorKey> = (0..10 * PENDING_PROOFS_CLASS_MAX)
            .map(|_| Identity::generate().author_key())
            .collect();
        for (run, session) in (1u64..).zip(&others) {
            let proof = member.prove(session, "alice", mesh.as_ref(), run);
            assert!(
                !book.accept_live(session, &alice, &mesh, proof, false, |_| true),
                "the proof of a sender that is not live was held active"
            );
        }
        assert_eq!(
            book.pending_len(),
            PENDING_PROOFS_CLASS_MAX,
            "the cap holds"
        );

        // 10 members hold a name each (run 2); each is fed 10 times the cap of proofs above its run
        let mut fed: Vec<Vec<AuthorKey>> = Vec::new();
        for index in 0..10 {
            let (holder, name) = (Identity::generate(), format!("holder{index}"));
            let nickname = Nickname::try_new(&name).expect("a nickname");
            let live = Identity::generate().author_key();
            let held = holder.prove(&live, &name, mesh.as_ref(), 2);
            assert!(
                book.accept_live(&live, &nickname, &mesh, held, true, |_| true),
                "the live session of {name} did not hold its proof"
            );
            let sessions: Vec<AuthorKey> = (0..10 * PENDING_PROOFS_CLASS_MAX)
                .map(|_| Identity::generate().author_key())
                .collect();
            for (run, session) in (3u64..).zip(&sessions) {
                let proof = holder.prove(session, &name, mesh.as_ref(), run);
                assert!(
                    !book.accept_live(session, &nickname, &mesh, proof, false, |_| true),
                    "the proof of a sender that is not live was held active"
                );
            }
            fed.push(sessions);
        }

        assert_eq!(
            book.pending_len(),
            2 * PENDING_PROOFS_CLASS_MAX,
            "each class holds its own cap, and the other class kept its entries"
        );
        let (oldest, newest) = (&others[0], &others[others.len() - 1]);
        assert!(
            !book.has_pending(oldest) && book.has_pending(newest),
            "the oldest of the other class was dropped and the newest is kept"
        );
        for sessions in &fed {
            let kept: usize = sessions
                .iter()
                .filter(|session| book.has_pending(session))
                .count();
            assert!(
                kept <= PENDING_PER_MEMBER && book.has_pending(&sessions[sessions.len() - 1]),
                "a member holds {kept} pending proofs, and its newest is kept"
            );
        }
        let holder_newest = &fed[0][fed[0].len() - 1];
        assert!(
            book.proof_of(holder_newest).is_none(),
            "a pending proof is not in the book"
        );
        let first_holder = Nickname::try_new("holder0").expect("a nickname");
        assert!(
            book.take_pending(holder_newest, &first_holder).is_some()
                && !book.has_pending(holder_newest),
            "a taken pending proof is gone"
        );
    }

    /// A pending proof is never stored for a forged proof (its signature is checked first), and it binds no
    /// nickname, replaces no session and evicts none before it is activated: an attacker cannot use the pending map
    /// to bind a nickname or to end a live session.
    #[test]
    fn a_pending_proof_binds_replaces_and_evicts_nothing_and_a_forged_one_is_never_kept() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let mesh = MeshId::from("test");
        let (member, other) = (Identity::generate(), Identity::generate());
        let alice = Nickname::try_new("alice").expect("a nickname");
        let (live, pending, forged) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let held = member.prove(&live, "alice", mesh.as_ref(), 3);
        assert!(
            book.accept_live(&live, &alice, &mesh, held, true, |_| true),
            "the live session of the member holds its proof"
        );

        let newer = member.prove(&pending, "alice", mesh.as_ref(), 9);
        assert!(
            !book.accept_live(&pending, &alice, &mesh, newer, false, |_| true),
            "the proof of a sender that is not live was held active"
        );
        let mut bad = other.prove(&forged, "alice", mesh.as_ref(), 1);
        bad.run += 1;
        assert!(
            !book.accept_live(&forged, &alice, &mesh, bad, false, |_| true),
            "a forged proof was accepted"
        );

        assert!(
            book.has_pending(&pending) && !book.has_pending(&forged),
            "the valid proof is pending and the forged one is never kept"
        );
        assert!(
            book.proof_of(&live).is_some(),
            "the pending proof replaced the live session of its member"
        );
        assert!(
            book.take_replaced().is_empty() && book.take_evicted().is_empty(),
            "a pending proof replaced or evicted a session"
        );
        assert!(
            book.admits(&pending, &alice, |_| true),
            "a pending proof of the member that holds the nickname admits its own session"
        );
    }

    /// The proof requests are budgeted before they are signed: 8 for each endpoint and 64 in all, for each window
    /// of 10 s. An endpoint that uses its budget does not starve another one, and a window that has moved starts
    /// the counts again.
    #[test]
    fn the_proof_requests_have_a_budget_for_each_endpoint_and_in_all() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let (first, second) = (endpoint_of(1), endpoint_of(2));

        let allowed_first = (0..20).filter(|_| book.may_ask(first, start)).count();
        let allowed_second = (0..3).filter(|_| book.may_ask(second, start)).count();

        assert_eq!(
            allowed_first, ASKS_PER_ENDPOINT,
            "the budget of one endpoint"
        );
        assert_eq!(
            allowed_second, 3,
            "another endpoint is not starved by the first"
        );
        assert!(
            book.may_ask(first, start + ASK_BUDGET_WINDOW),
            "a window that has moved starts the count again"
        );
    }

    /// Past runs of the member were gossiped, so anyone who logged them can replay them: each is a valid pending proof
    /// of the member that holds the name. A past run (not above the highest run of the member in the book) goes to the
    /// other class, so replays of 40 of them do not push out the real newer run of the HELD class.
    #[test]
    fn the_replays_of_past_runs_of_the_member_do_not_push_out_its_real_newer_run() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let mesh = MeshId::from("test");
        let member = Identity::generate();
        let alice = Nickname::try_new("alice").expect("a nickname");
        let live = Identity::generate().author_key();
        let held = member.prove(&live, "alice", mesh.as_ref(), 41);
        assert!(
            book.accept_live(&live, &alice, &mesh, held, true, |_| true),
            "the live session of the member did not hold its proof"
        );
        let real = Identity::generate().author_key();
        let newer = member.prove(&real, "alice", mesh.as_ref(), 42);
        assert!(
            !book.accept_live(&real, &alice, &mesh, newer, false, |_| true),
            "the proof of a sender that is not live was held active"
        );

        for run in 1..=40u64 {
            let past = Identity::generate().author_key();
            let proof = member.prove(&past, "alice", mesh.as_ref(), run);
            book.accept_live(&past, &alice, &mesh, proof, false, |_| true);
        }

        assert!(
            book.has_pending(&real),
            "the replays of 40 past runs pushed out the real newer run of the member"
        );
        assert!(
            book.admits(&real, &alice, |_| true),
            "the session of the real newer run is not admitted"
        );
    }

    /// A member that holds a nickname signs valid pending proofs for its own nickname with fresh session keys and
    /// runs above its book run, and so can fill the class of the holders. One member must not push out the pending
    /// proof of ANOTHER member: the class has a cap for each member.
    #[test]
    fn one_member_cannot_fill_the_class_of_the_holders_and_push_out_the_restart_of_another() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let mesh = MeshId::from("test");
        let (victim, insider) = (Identity::generate(), Identity::generate());
        let (alice, mallory) = (
            Nickname::try_new("alice").expect("a nickname"),
            Nickname::try_new("mallory").expect("a nickname"),
        );
        for (member, nickname, name, run) in [
            (&victim, &alice, "alice", 3u64),
            (&insider, &mallory, "mallory", 5),
        ] {
            let live = Identity::generate().author_key();
            let held = member.prove(&live, name, mesh.as_ref(), run);
            assert!(
                book.accept_live(&live, nickname, &mesh, held, true, |_| true),
                "the live session of {name} did not hold its proof"
            );
        }
        let restart = Identity::generate().author_key();
        let answer = victim.prove(&restart, "alice", mesh.as_ref(), 9);
        assert!(
            !book.accept_live(&restart, &alice, &mesh, answer, false, |_| true),
            "the proof of a sender that is not live was held active"
        );

        for run in 6..66u64 {
            let own = Identity::generate().author_key();
            let proof = insider.prove(&own, "mallory", mesh.as_ref(), run);
            book.accept_live(&own, &mallory, &mesh, proof, false, |_| true);
        }

        assert!(
            book.has_pending(&restart),
            "60 pending proofs of another member pushed out the restart of the victim"
        );
        assert!(
            book.admits(&restart, &alice, |_| true),
            "the session of the restart is not admitted"
        );
    }

    /// Inside the class of the holder, the HIGHEST runs of a member are kept: the member alone signs its runs, so a
    /// replay of a logged run is always below the real newest one, and a member over its cap drops its lowest run, not
    /// its oldest entry.
    #[test]
    fn a_full_class_of_the_holder_keeps_the_highest_runs() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let mesh = MeshId::from("test");
        let member = Identity::generate();
        let alice = Nickname::try_new("alice").expect("a nickname");
        let live = Identity::generate().author_key();
        let held = member.prove(&live, "alice", mesh.as_ref(), 3);
        assert!(
            book.accept_live(&live, &alice, &mesh, held, true, |_| true),
            "the live session of the member did not hold its proof"
        );
        let real = Identity::generate().author_key();
        let newest = member.prove(&real, "alice", mesh.as_ref(), 100);
        assert!(
            !book.accept_live(&real, &alice, &mesh, newest, false, |_| true),
            "the proof of a sender that is not live was held active"
        );

        // 60 runs above the live one, all logged by an attacker: they all go to the class of the holder
        for run in 4..64u64 {
            let logged = Identity::generate().author_key();
            let proof = member.prove(&logged, "alice", mesh.as_ref(), run);
            book.accept_live(&logged, &alice, &mesh, proof, false, |_| true);
        }

        assert!(
            book.has_pending(&real),
            "60 logged runs pushed out the highest run of the member"
        );
        assert_eq!(
            book.pending_len(),
            PENDING_PER_MEMBER,
            "one member holds its cap in the class of the holders, and keeps its highest runs"
        );
    }

    /// A full class of the holders, with one entry for each member: the class keeps its cap, the new proof is kept,
    /// and the entry of one earlier member goes. Every entry is the restart proof of a member that holds a name, so
    /// the class cannot grow and one of them must go. The member whose proof went is admitted at its next ask.
    #[test]
    fn a_full_class_of_one_entry_for_each_member_keeps_its_cap_and_takes_the_new_proof() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let mesh = MeshId::from("test");
        let members = PENDING_PROOFS_CLASS_MAX + 1;
        let restarts: Vec<AuthorKey> = (0..members)
            .map(|index| {
                let member = Identity::generate();
                let name = format!("member{index:02}");
                let nickname = Nickname::try_new(&name).expect("a nickname");
                let live = Identity::generate().author_key();
                let held = member.prove(&live, &name, mesh.as_ref(), 3);
                assert!(
                    book.accept_live(&live, &nickname, &mesh, held, true, |_| true),
                    "the live session of a member did not hold its proof"
                );
                let restart = Identity::generate().author_key();
                let newest = member.prove(&restart, &name, mesh.as_ref(), 100);
                book.accept_live(&restart, &nickname, &mesh, newest, false, |_| true);
                restart
            })
            .collect();

        let kept: usize = restarts
            .iter()
            .filter(|restart| book.has_pending(restart))
            .count();

        assert_eq!(
            book.pending_len(),
            PENDING_PROOFS_CLASS_MAX,
            "a class of one entry for each member grew past the cap that bounds it"
        );
        assert!(
            book.has_pending(restarts.last().expect("the last restart")),
            "the newest restart proof was refused by a full class, so a member that restarts last never gets in"
        );
        assert_eq!(
            kept, PENDING_PROOFS_CLASS_MAX,
            "the new proof did not take the place of exactly one earlier member"
        );
    }

    /// The pending proof of a session whose member already holds the nickname (it can only be a restart of that
    /// member) is not pushed out by a flood of pending proofs of other keys: the attacker signs fresh proofs of its
    /// own, under nicknames that are free, inside old frames, and each one is a valid pending proof.
    #[test]
    fn a_flood_of_pending_proofs_of_other_members_does_not_push_out_the_proof_of_a_restart() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let mesh = MeshId::from("test");
        let (member, attacker) = (Identity::generate(), Identity::generate());
        let alice = Nickname::try_new("alice").expect("a nickname");
        let (live, restart) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let held = member.prove(&live, "alice", mesh.as_ref(), 3);
        assert!(
            book.accept_live(&live, &alice, &mesh, held, true, |_| true),
            "the live session of the member did not hold its proof"
        );
        let answer = member.prove(&restart, "alice", mesh.as_ref(), 9);
        assert!(
            !book.accept_live(&restart, &alice, &mesh, answer, false, |_| true),
            "the proof of a sender that is not live was held active"
        );

        for index in 0..200 {
            let session = Identity::generate().author_key();
            let name = format!("flood{index}");
            let nickname = Nickname::try_new(&name).expect("a nickname");
            let proof = attacker.prove(&session, &name, mesh.as_ref(), 1);
            book.accept_live(&session, &nickname, &mesh, proof, false, |_| true);
        }

        assert!(
            book.has_pending(&restart),
            "a flood of pending proofs of another member pushed out the proof of the restart of the member that holds the name"
        );
        assert!(
            book.admits(&restart, &alice, |_| true),
            "the session of the restart is not admitted"
        );
    }

    /// A count that is still inside its window is not dropped to make room: an endpoint that used its 8 asks is
    /// still at 8 when 256 other endpoints came after it. A full map of live counts defers an untracked endpoint.
    #[test]
    fn an_endpoint_that_used_its_asks_does_not_get_a_second_budget_when_the_map_of_counts_is_full()
    {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        // X opens the window of the budget in all, and A uses its 8 asks 5 s later
        assert!(book.may_ask(endpoint_of(0), at(0)), "the first ask of X");
        let used: usize = (0..ASKS_PER_ENDPOINT)
            .filter(|_| book.may_ask(endpoint_of(1), at(5)))
            .count();
        assert_eq!(used, ASKS_PER_ENDPOINT, "A uses its asks");
        // 254 more endpoints fill the map of 256 counts, 9 s into the window
        for index in 2..256u32 {
            assert!(book.may_ask(endpoint_of(index), at(9)), "a first ask");
        }
        // the window in all has moved: two new endpoints need room in the map
        assert!(
            book.may_ask(endpoint_of(1000), at(11)),
            "a new endpoint after X expired"
        );
        let _ = book.may_ask(endpoint_of(1001), at(11));

        assert!(
            !book.may_ask(endpoint_of(1), at(12)),
            "A, whose count is still inside its window, got a second budget after the map dropped its count"
        );
    }

    /// An ask for a session that CLAIMS A BOUND NICKNAME (a restart of the member, or an intruder) has a reserve of its
    /// own, outside the shared budget of the first asks, so an attacker that keeps many endpoints asking cannot starve
    /// the restart of a member that holds a name: the shared 256 are used up, the map of counts is full of live
    /// counts, and the ask of the claim still goes.
    #[test]
    fn a_claim_of_a_bound_nickname_is_asked_when_the_shared_first_asks_are_used_up() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let alice = Nickname::try_new("alice").expect("a nickname");
        let used: usize = (0..300u32)
            .filter(|index| book.may_ask_for(endpoint_of(*index), None, start))
            .count();
        assert_eq!(used, FIRST_ASKS_IN_ALL, "the shared first asks are used up");

        assert!(
            book.may_ask_for(endpoint_of(1000), Some(&alice), start),
            "the ask for a claim of a bound nickname was refused although the shared first asks were used up"
        );
        assert!(
            !book.may_ask_for(endpoint_of(1001), None, start),
            "an ask for a free nickname got into the reserve of the claims"
        );
    }

    /// The reserve is for a SESSION that claims a bound nickname, not for the first ask of an endpoint: a restart that
    /// comes on an endpoint that has a count in the window (an embedder keeps one endpoint across starts) is asked from
    /// the reserve although the budget in all is used up.
    #[test]
    fn a_claim_from_an_endpoint_that_has_a_count_is_asked_from_the_reserve() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let alice = Nickname::try_new("alice").expect("a nickname");
        assert!(
            book.may_ask_for(endpoint_of(0), None, start),
            "the first ask of the endpoint"
        );
        for index in 1..300u32 {
            let _ = book.may_ask_for(endpoint_of(index), None, start);
        }

        assert!(
            book.may_ask_for(endpoint_of(0), Some(&alice), start),
            "a claim from an endpoint that has a count was deferred although the reserve was unused"
        );
    }

    /// The reserve does not drop a count that is inside its window: with the map full of live counts the ask of a claim
    /// goes out untracked, and an endpoint that used its 8 asks cannot get 8 more by a claim after the map dropped it.
    #[test]
    fn the_reserve_keeps_the_live_counts_of_the_endpoints() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let (alice, bob) = (
            Nickname::try_new("alice").expect("a nickname"),
            Nickname::try_new("bob").expect("a nickname"),
        );
        // A uses its 8 asks first, so it is the oldest count; 255 other endpoints fill the map with live counts
        let used: usize = (0..ASKS_PER_ENDPOINT)
            .filter(|_| book.may_ask_for(endpoint_of(0), None, start))
            .count();
        assert_eq!(used, ASKS_PER_ENDPOINT, "A uses its asks");
        for index in 1..256u32 {
            assert!(
                book.may_ask_for(endpoint_of(index), None, start),
                "a first ask"
            );
        }

        assert!(
            book.may_ask_for(endpoint_of(1000), Some(&alice), start),
            "a claim from a new endpoint was refused although the reserve was unused"
        );
        assert!(
            !book.may_ask_for(endpoint_of(0), Some(&bob), start),
            "A got more asks by a claim after the reserve dropped its live count"
        );
    }

    /// An untracked ask of the reserve keeps the cap of its endpoint. With the map full of live counts the count of a
    /// new endpoint is not kept, so its asks all read as the first one: an endpoint that claims several bound
    /// nicknames would get 4 asks for each of them, and each ask is a signature and a task that holds a frame.
    #[test]
    fn an_untracked_claim_keeps_the_cap_of_its_endpoint() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let claims: Vec<Nickname> = ["alice", "bob", "carol"]
            .iter()
            .map(|name| Nickname::try_new(name).expect("a nickname"))
            .collect();
        // 256 endpoints fill the map with live counts, so the count of the endpoint below is not kept
        for index in 0..256u32 {
            assert!(
                book.may_ask_for(endpoint_of(index), None, start),
                "a first ask"
            );
        }

        let every_claim_to_its_cap = claims
            .iter()
            .flat_map(|claim| (0..ASKS_PER_BOUND_NICKNAME).map(move |_| claim));
        let asked: usize = every_claim_to_its_cap
            .filter(|claim| book.may_ask_for(endpoint_of(1000), Some(claim), start))
            .count();

        assert!(
            asked <= ASKS_PER_ENDPOINT,
            "one endpoint got {asked} asks of the reserve in a window, over the cap of {ASKS_PER_ENDPOINT} that every endpoint has"
        );
    }

    /// The reserve is 64 asks for each window and 4 for each nickname: an attacker that claims 16 bound nicknames with
    /// 4 fresh sessions each uses the whole reserve, and the restart of ANOTHER bound nickname waits for the next
    /// window (no nickname is lost). One nickname cannot eat the reserve alone.
    #[test]
    fn the_reserve_of_the_claims_has_64_asks_for_each_window_and_4_for_each_nickname() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let name = |index: u32| Nickname::try_new(&format!("claim{index}")).expect("a nickname");
        // the shared first asks are used up by endpoints that claim nothing
        for index in 0..300u32 {
            let _ = book.may_ask_for(endpoint_of(index), None, start);
        }

        // one nickname: 4 asks from the reserve, no more
        let eaten: usize = (0..10u32)
            .filter(|index| book.may_ask_for(endpoint_of(1000 + index), Some(&name(0)), start))
            .count();
        assert_eq!(eaten, 4, "one nickname got other than 4 asks in a window");

        // 15 other nicknames with 4 each: 16 x 4 = 64, the whole reserve
        let mut index = 2000u32;
        for nickname in 1..16u32 {
            for _ in 0..4 {
                assert!(
                    book.may_ask_for(endpoint_of(index), Some(&name(nickname)), start),
                    "claim {nickname} was refused inside the reserve"
                );
                index += 1;
            }
        }

        // the restart of another bound nickname waits for the next window, and then it is asked
        let restart = name(99);
        assert!(
            !book.may_ask_for(endpoint_of(5000), Some(&restart), start),
            "the reserve gave more than 64 asks in a window"
        );
        assert!(
            book.may_ask_for(endpoint_of(5000), Some(&restart), start + ASK_BUDGET_WINDOW),
            "the restart was not asked in the next window"
        );
    }

    /// The guaranteed first asks are bounded in all too: 600 endpoints with a path, each asking once in one window,
    /// get 256 signed asks and no more. Else the map of the counts (256 endpoints, the oldest dropped) lets an endpoint
    /// whose count was dropped be first again, and the asks follow the rate of the attacker.
    #[test]
    fn the_first_asks_of_600_endpoints_in_one_window_are_bounded_in_all() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();

        let allowed: usize = (0..600u32)
            .filter(|index| book.may_ask(endpoint_of(*index), start))
            .count();

        assert!(
            allowed <= 256,
            "the first asks of 600 endpoints were not bounded in all: {allowed} allowed"
        );
    }

    /// The first ask of each endpoint in a window is guaranteed: it needs no room in the budget in all (it counts in
    /// it). Fed 10 times its cap of endpoints, each asking once, all are allowed, and the map of the endpoints
    /// holds its cap at most. An endpoint that asks again, when the budget in all is full, is refused.
    #[test]
    fn the_first_ask_of_each_endpoint_is_guaranteed_and_the_map_stays_inside_its_cap_at_10_times_the_cap()
     {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let endpoints = u32::try_from(10 * ASK_BUDGET_ENDPOINTS_MAX).expect("a small number");

        let allowed: usize = (0..endpoints)
            .filter(|index| book.may_ask(endpoint_of(*index), start))
            .count();

        assert_eq!(
            allowed, FIRST_ASKS_IN_ALL,
            "the first ask of each endpoint is guaranteed, whatever the budget in all, up to the budget of the first asks"
        );
        assert!(
            book.ask_budget_endpoints() <= ASK_BUDGET_ENDPOINTS_MAX,
            "the map of the endpoints holds more than its cap"
        );
        assert!(
            !book.may_ask(endpoint_of(0), start),
            "a second ask of an endpoint was allowed while the budget in all was full"
        );
    }

    /// The budget in all (64 for each window) is for the asks after the first of an endpoint: 8 endpoints with their
    /// own budget of 8 use it up, and the 9th endpoint still gets its first ask.
    #[test]
    fn the_budget_in_all_is_used_up_by_the_asks_after_the_first_and_the_next_endpoint_still_asks() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();

        let from_eight: usize = (0..8)
            .map(|index| {
                (0..ASKS_PER_ENDPOINT)
                    .filter(|_| book.may_ask(endpoint_of(index), start))
                    .count()
            })
            .sum();

        assert_eq!(from_eight, ASKS_IN_ALL, "8 endpoints use the budget in all");
        assert!(
            book.may_ask(endpoint_of(8), start),
            "the ninth endpoint did not get its first ask"
        );
        assert!(
            !book.may_ask(endpoint_of(8), start),
            "the ninth endpoint got a second ask from a full budget"
        );
    }

    /// A deferred ask is tried once for each gap, and it is dropped after its time, so a flood of frames from
    /// one endpoint makes one try for each session and gap, and a session that never gets a path falls back
    /// to the alive cycle.
    #[test]
    fn a_deferred_ask_is_tried_once_for_each_gap_and_expires() {
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let session = Identity::generate().author_key();
        let start = Instant::now();
        let alice = Nickname::try_new("alice").expect("a nickname");
        book.defer_ask(session, &alice, start);

        assert_eq!(
            book.deferred_due(start),
            vec![(session, alice.clone())],
            "the first try is free: the ask goes as soon as a path is up"
        );
        book.mark_deferred_tried(&session, start);
        assert!(
            book.deferred_due(start).is_empty(),
            "but not twice in one gap"
        );
        assert_eq!(
            book.deferred_due(start + DEFERRED_ASK_GAP),
            vec![(session, alice)],
            "after the gap it is tried again"
        );
        book.expire_deferred(start + DEFERRED_ASK_TTL);
        assert!(book.deferred_is_empty(), "after its time it is dropped");
    }

    /// A joiner that missed the `joined` frame of a member gets the proof by one request.
    #[test]
    fn a_joiner_that_missed_the_joined_frame_gets_the_proof_by_request() {
        let mesh = MeshId::from("💬test");
        let nickname = Nickname::from("alice");
        let member = Identity::generate();
        let session = Identity::generate().author_key();
        let proof = member.prove(&session, nickname.as_ref(), mesh.as_ref(), 1);
        let mut joiner = ProofExchange::with_cap(QUIET_CAP);

        let now = Instant::now();
        assert!(
            joiner.wants_proof(&session, now),
            "an alive frame of a session with no proof asks for it"
        );
        joiner.note_asked(&session, now, None, |_| true);
        assert!(
            !joiner.wants_proof(&session, Instant::now()),
            "the session is asked once, not at each alive frame"
        );
        assert!(
            joiner.accept(&session, &nickname, &mesh, proof, |_| true),
            "the answer verifies and is held"
        );
        let held = joiner.proof_of(&session).expect("the proof is held");
        assert!(
            verify_proof(held, &session, nickname.as_ref(), mesh.as_ref()),
            "the held proof verifies"
        );
    }

    /// A proof that was cached while its session was not in the roster does not outlive the nickname: once
    /// another member holds the binding, the cached proof of the first member admits nothing under it.
    #[test]
    fn a_cached_proof_does_not_admit_a_session_to_a_nickname_that_another_member_binds() {
        let mesh = MeshId::from("💬test");
        let nickname = Nickname::from("alice");
        let (first, second) = (Identity::generate(), Identity::generate());
        let (first_session, second_session) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let first_proof = first.prove(&first_session, nickname.as_ref(), mesh.as_ref(), 1);
        assert!(
            book.accept(&first_session, &nickname, &mesh, first_proof, |_| false),
            "the proof of the first member is held while no session of it is in the roster"
        );
        let second_proof = second.prove(&second_session, nickname.as_ref(), mesh.as_ref(), 1);
        assert!(
            book.accept(&second_session, &nickname, &mesh, second_proof, |key| {
                *key == second_session
            }),
            "the second member binds the nickname: no held session binds it yet"
        );

        let admitted = book.admits(&first_session, &nickname, |key| *key == second_session);

        assert!(
            !admitted,
            "a fresh frame of the first member passed the binding of the second member"
        );
    }

    /// A request that was not sent, for lack of a warm path, does not start the retry clock: the
    /// session is asked at its next alive frame.
    #[test]
    fn a_request_that_was_not_sent_is_not_counted() {
        let session = Identity::generate().author_key();
        let mut joiner = ProofExchange::with_cap(QUIET_CAP);
        let now = Instant::now();
        assert!(
            joiner.wants_proof(&session, now),
            "the session needs a request"
        );
        assert!(
            joiner.wants_proof(&session, now),
            "no send, so the session still needs one"
        );
        joiner.note_asked(&session, now, None, |_| true);
        assert!(
            !joiner.wants_proof(&session, now),
            "after a send the retry clock runs"
        );
    }

    /// A request that got no answer is sent again 3 times, after 30 s, 60 s and 120 s, and then at a
    /// slow pace (see the next test).
    #[test]
    fn an_unanswered_request_is_retried_three_times_with_a_back_off() {
        let session = Identity::generate().author_key();
        let mut joiner = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        assert!(
            joiner.wants_proof(&session, at(0)),
            "the first request goes at once"
        );
        joiner.note_asked(&session, at(0), None, |_| true);
        assert!(
            !joiner.wants_proof(&session, at(29)),
            "no retry before 30 s"
        );
        assert!(joiner.wants_proof(&session, at(30)), "retry 1 after 30 s");
        joiner.note_asked(&session, at(30), None, |_| true);
        assert!(
            !joiner.wants_proof(&session, at(89)),
            "no retry before 60 s more"
        );
        assert!(
            joiner.wants_proof(&session, at(90)),
            "retry 2 after 60 s more"
        );
        joiner.note_asked(&session, at(90), None, |_| true);
        assert!(
            !joiner.wants_proof(&session, at(209)),
            "no retry before 120 s more"
        );
        assert!(
            joiner.wants_proof(&session, at(210)),
            "retry 3 after 120 s more"
        );
        joiner.note_asked(&session, at(210), None, |_| true);
        assert!(
            !joiner.wants_proof(&session, at(809)),
            "no fourth fast retry: the next ask waits 10 minutes"
        );
    }

    /// After the 3 fast retries a session is asked once per 10 minutes for as long as its entry lives (while the
    /// session stays visible and has no proof), so a long time with no warm path does not lose the proof for good.
    /// The ask is never sooner than 10 minutes after the one before.
    #[test]
    fn a_slow_retry_follows_the_fast_ones_every_10_minutes_while_the_session_is_visible() {
        let session = Identity::generate().author_key();
        let mut joiner = ProofExchange::with_cap(QUIET_CAP);
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        for secs in [0, 30, 90, 210] {
            assert!(
                joiner.wants_proof(&session, at(secs)),
                "a fast ask at {secs} s"
            );
            joiner.note_asked(&session, at(secs), None, |_| true);
        }
        assert!(
            !joiner.wants_proof(&session, at(809)),
            "no slow retry before 10 minutes"
        );
        let mut last = 210;
        for round in 1..=30 {
            last += 600;
            assert!(
                !joiner.wants_proof(&session, at(last - 1)),
                "slow retry {round} came before 10 minutes"
            );
            assert!(
                joiner.wants_proof(&session, at(last)),
                "slow retry {round} did not come: the asks stopped"
            );
            joiner.note_asked(&session, at(last), None, |_| true);
        }
    }

    /// The same proof comes again with each resent or re-announced `joined` frame. A copy of the
    /// proof held is a duplicate: it is not a refusal and the census does not count it.
    #[test]
    fn a_repeated_proof_is_a_duplicate_and_not_a_tie() {
        let mesh = MeshId::from("💬test");
        let nickname = Nickname::from("alice");
        let member = Identity::generate();
        let session = Identity::generate().author_key();
        let mut receiver = ProofExchange::with_cap(QUIET_CAP);
        let proof = member.prove(&session, nickname.as_ref(), mesh.as_ref(), 3);
        assert!(
            receiver.accept(&session, &nickname, &mesh, proof, |_| true),
            "the first copy is held"
        );
        assert!(
            !receiver.accept(&session, &nickname, &mesh, proof, |_| true),
            "a second copy adds nothing"
        );
        assert_eq!(receiver.ties_refused(), 0, "a copy is not a tie");
    }

    /// In a calm mesh every receiver holds the proof of each session, so no alive frame asks for
    /// one: 0 bytes of proof traffic besides the `joined` frames.
    #[test]
    fn a_calm_mesh_asks_for_no_proof() {
        let mesh = MeshId::from("💬test");
        let nickname = Nickname::from("alice");
        let member = Identity::generate();
        let session = Identity::generate().author_key();
        let proof = member.prove(&session, nickname.as_ref(), mesh.as_ref(), 1);
        let mut receiver = ProofExchange::with_cap(QUIET_CAP);
        assert!(
            receiver.accept(&session, &nickname, &mesh, proof, |_| true),
            "the joined frame proof is held"
        );
        let requests = (0..1000)
            .filter(|_| receiver.wants_proof(&session, Instant::now()))
            .count();
        assert_eq!(
            requests, 0,
            "1000 alive frames of a held session ask 0 times"
        );
    }

    /// A proof that the member key signed for another nickname does not verify here.
    #[test]
    fn a_proof_for_another_nickname_is_refused() {
        let mesh = MeshId::from("💬test");
        let member = Identity::generate();
        let session = Identity::generate().author_key();
        let proof = member.prove(&session, "mallory", mesh.as_ref(), 1);
        let mut receiver = ProofExchange::with_cap(QUIET_CAP);
        assert!(
            !receiver.accept(&session, &Nickname::from("alice"), &mesh, proof, |_| true),
            "a proof of another nickname is refused"
        );
        assert!(receiver.proof_of(&session).is_none(), "nothing is held");
    }

    /// Of two proofs for one session, the higher run wins, and on a tie the first stays.
    #[test]
    fn the_higher_run_wins_and_a_tie_keeps_the_first() {
        let mesh = MeshId::from("💬test");
        let nickname = Nickname::from("alice");
        let member = Identity::generate();
        let session = Identity::generate().author_key();
        let mut receiver = ProofExchange::with_cap(QUIET_CAP);
        let at = |run| member.prove(&session, nickname.as_ref(), mesh.as_ref(), run);
        assert!(
            receiver.accept(&session, &nickname, &mesh, at(5), |_| true),
            "run 5 is held"
        );
        assert!(
            !receiver.accept(&session, &nickname, &mesh, at(5), |_| true),
            "a copy of the held proof is not held again"
        );
        let rival = Identity::generate().prove(&session, nickname.as_ref(), mesh.as_ref(), 5);
        assert!(
            !receiver.accept(&session, &nickname, &mesh, rival, |_| true),
            "a tie from another member key is not held"
        );
        assert!(
            !receiver.accept(&session, &nickname, &mesh, at(4), |_| true),
            "a lower run is not held"
        );
        assert!(
            receiver.accept(&session, &nickname, &mesh, at(6), |_| true),
            "a higher run is held"
        );
        let held = receiver.proof_of(&session).expect("a proof is held");
        assert_eq!(held.run, 6, "the held proof is the highest run");
        assert_eq!(
            receiver.ties_refused(),
            2,
            "a rival tie and a lower run are counted, the copy is not"
        );
    }

    /// A nickname can have a dead session of a member that left and a live session of the member
    /// that took it after. The book must tell them apart: the dead session goes first when the book
    /// is full, so the proof of a new member still lands. A nickname alone cannot tell them apart,
    /// because the live session keeps it live.
    #[test]
    fn the_dead_session_of_a_restarted_member_does_not_block_a_full_book() {
        let mesh = MeshId::from("💬test");
        let alice = Nickname::from("alice");
        let (old, new) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let mut book = ProofExchange::with_cap(4);
        // The first member left: its session is not held, so the nickname is free for the second.
        for session in [old, new] {
            let proof = Identity::generate().prove(&session, alice.as_ref(), mesh.as_ref(), 1);
            assert!(
                book.accept(&session, &alice, &mesh, proof, |held| *held != old),
                "the book has room"
            );
        }
        for name in ["bob", "carol"] {
            let (nickname, session) = (Nickname::from(name), Identity::generate().author_key());
            let proof = Identity::generate().prove(&session, nickname.as_ref(), mesh.as_ref(), 1);
            assert!(
                book.accept(&session, &nickname, &mesh, proof, |_| true),
                "the book has room"
            );
        }
        assert_eq!(book.len(), 4, "the book is full");

        let (dave, session) = (Nickname::from("dave"), Identity::generate().author_key());
        let proof = Identity::generate().prove(&session, dave.as_ref(), mesh.as_ref(), 1);
        // The roster has a live session under each nickname, and the old session of alice is dead.
        let held = book.accept(&session, &dave, &mesh, proof, |held| *held != old);

        assert!(
            held,
            "the dead old session of alice goes, and the proof of dave lands"
        );
        assert!(
            book.proof_of(&old).is_none() && book.proof_of(&new).is_some(),
            "the dead session is gone and the live session stays"
        );
    }

    /// A restart makes a new session with a higher run. The proof of the new session replaces the
    /// proof of the old one, so a member holds one proof, the newest.
    #[test]
    fn a_newer_run_of_a_member_drops_its_older_session() {
        let mesh = MeshId::from("💬test");
        let alice = Nickname::from("alice");
        let member = Identity::generate();
        let (old, new) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let first = member.prove(&old, alice.as_ref(), mesh.as_ref(), 1);
        let second = member.prove(&new, alice.as_ref(), mesh.as_ref(), 2);

        assert!(
            book.accept(&old, &alice, &mesh, first, |_| true),
            "run 1 is held"
        );
        assert!(
            book.accept(&new, &alice, &mesh, second, |_| true),
            "run 2 is held"
        );

        assert!(
            book.proof_of(&old).is_none(),
            "the older session is dropped"
        );
        assert!(book.proof_of(&new).is_some(), "the newer session is held");
        assert_eq!(
            book.take_replaced(),
            [old],
            "the caller hears of the dropped session"
        );
        assert!(book.take_replaced().is_empty(), "and hears of it once");
    }

    /// An old `joined` frame that a relay delivers late must not replace the newer session.
    #[test]
    fn a_proof_of_an_older_run_of_the_same_member_is_not_held() {
        let mesh = MeshId::from("💬test");
        let alice = Nickname::from("alice");
        let member = Identity::generate();
        let (old, new) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let newer = member.prove(&new, alice.as_ref(), mesh.as_ref(), 5);
        let older = member.prove(&old, alice.as_ref(), mesh.as_ref(), 4);

        assert!(
            book.accept(&new, &alice, &mesh, newer, |_| true),
            "run 5 is held"
        );
        assert!(
            !book.accept(&old, &alice, &mesh, older, |_| true),
            "a late proof of run 4 is not held"
        );

        assert!(book.proof_of(&new).is_some(), "the newer session stays");
        assert!(book.take_replaced().is_empty(), "nothing was dropped");
    }

    /// A member that restarts 1100 times, with all its old sessions still in the roster (no goodbye,
    /// no timeout yet), holds one proof, the newest. The book never fills with its sessions, so the
    /// proof of the newest session is never refused.
    #[test]
    fn a_member_that_restarts_1100_times_holds_its_newest_session() {
        let mesh = MeshId::from("💬test");
        let alice = Nickname::from("alice");
        let member = Identity::generate();
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let mut newest = None;
        for run in 1..=1100u64 {
            let session = Identity::generate().author_key();
            let proof = member.prove(&session, alice.as_ref(), mesh.as_ref(), run);
            assert!(
                book.accept(&session, &alice, &mesh, proof, |_| true),
                "the proof of run {run} is held"
            );
            let _ = book.take_replaced();
            newest = Some(session);
        }

        let newest = newest.expect("1100 restarts");
        assert!(
            book.proof_of(&newest).is_some(),
            "the newest session is held"
        );
        assert_eq!(book.len(), 1, "the sessions of the older runs are gone");
        assert_eq!(book.refused(), 0, "no proof was refused for want of room");
    }

    /// A session that is not in the roster is dead. Its proof, with whatever run, does not block the
    /// proof of the same member: a member that restores an old run file, or moves its state to
    /// another host, starts with a run that is lower than the dead session's, and must still be held.
    #[test]
    fn a_dead_session_with_a_higher_run_does_not_block_the_proof_of_its_member() {
        let mesh = MeshId::from("💬test");
        let alice = Nickname::from("alice");
        let member = Identity::generate();
        let (dead, new) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        let high = member.prove(&dead, alice.as_ref(), mesh.as_ref(), 100);
        assert!(
            book.accept(&dead, &alice, &mesh, high, |_| true),
            "run 100 is held"
        );
        let low = member.prove(&new, alice.as_ref(), mesh.as_ref(), 1);

        let held = book.accept(&new, &alice, &mesh, low, |session| *session != dead);

        assert!(
            held,
            "the proof of run 1 is held: the session of run 100 is dead"
        );
        assert!(book.proof_of(&dead).is_none(), "the dead session is gone");
        assert!(
            book.take_replaced().is_empty(),
            "a dead session needs no end in the roster"
        );
    }

    /// A session that said goodbye is forgotten: its proof goes with it.
    #[test]
    fn a_forgotten_session_loses_its_proof() {
        let mesh = MeshId::from("💬test");
        let alice = Nickname::from("alice");
        let session = Identity::generate().author_key();
        let proof = Identity::generate().prove(&session, alice.as_ref(), mesh.as_ref(), 1);
        let mut book = ProofExchange::with_cap(QUIET_CAP);
        assert!(
            book.accept(&session, &alice, &mesh, proof, |_| true),
            "the proof is held"
        );

        book.forget(&session);

        assert!(book.proof_of(&session).is_none(), "the proof is gone");
    }

    /// Keys that are not members can claim a bound nickname by the thousand, and each one with an
    /// address is asked for a proof. The asks of such sessions are limited for each nickname, so the
    /// flood replaces its own asks and pushes no other ask, and no retry clock, out of the book.
    #[test]
    fn a_flood_of_forged_keys_under_one_nickname_keeps_the_asks_of_the_members() {
        let member = Identity::generate().author_key();
        let claimed = Nickname::from("alice");
        let mut joiner = ProofExchange::with_cap(QUIET_CAP);
        let now = Instant::now();
        joiner.note_asked(&member, now, None, |_| true);
        assert!(
            !joiner.wants_proof(&member, now),
            "the member waits for its answer"
        );

        for _ in 0..2_000 {
            let forged = Identity::generate().author_key();
            joiner.note_asked(&forged, now, Some(&claimed), |_| true);
        }

        assert!(
            !joiner.wants_proof(&member, now),
            "the ask of the member is still there, and its retry clock was not reset"
        );
    }

    /// The book of asks is full, and the oldest record belongs to a session that is still waiting. The
    /// record of a session that left goes first, so the retry clock of a session in the roster is not
    /// reset: a session that was asked 9 times is not asked 9 more.
    #[test]
    fn a_full_book_of_asks_drops_a_session_that_left_before_one_that_waits() {
        let sessions: Vec<AuthorKey> = (0..5).map(|_| Identity::generate().author_key()).collect();
        let [waiting, gone, second, third, newest] = [0, 1, 2, 3, 4].map(|index| sessions[index]);
        let mut book = ProofExchange::with_cap(4);
        let now = Instant::now();
        for session in [waiting, gone, second, third, newest] {
            book.note_asked(&session, now, None, |held| *held != gone);
        }

        assert!(
            !book.wants_proof(&waiting, now),
            "the oldest record is of a session that waits, and it is still there"
        );
    }
}
