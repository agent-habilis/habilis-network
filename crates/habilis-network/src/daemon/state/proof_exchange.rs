use std::mem;
use std::time::Duration;

use super::proof_book::ProofBook;
use crate::protocol::identity::{IdentityProof, verify_proof};
use crate::protocol::{AuthorKey, MeshId, Nickname};
use crate::util::bounded_fifo_set::BoundedFifoSet;
use crate::util::clock::Instant;
use iroh::PublicKey;

/// The first retry waits 30 s, and each next one waits twice as long: 30 s, 60 s, 120 s.
const FIRST_RETRY_WAIT: Duration = Duration::from_secs(30);
const RETRIES: u8 = 3;
/// After the fast retries a session is asked once per 10 minutes, 6 times at most.
const SLOW_RETRY_WAIT: Duration = Duration::from_secs(600);
const SLOW_RETRIES: u8 = 6;
/// The asks of sessions that are not in the roster and claim one bound nickname: 4 open at most. A
/// session that claims a bound nickname is asked for its proof, and a flood of forged keys under
/// that nickname must replace its own asks and nobody else's.
const OPEN_ASKS_PER_NICKNAME: usize = 4;
/// The asks that were skipped for lack of a warm path and wait for one: 64 at most. When the map is full a
/// new one takes the place of the oldest, whose session falls back to the ask at its next alive frame.
const DEFERRED_ASKS_MAX: usize = 64;
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
        let proof_of = self
            .book
            .get(session)
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
        self.book.remove(session);
        self.asked.remove(session);
        self.deferred.remove(session);
    }

    /// The ask for `session` was skipped for lack of a warm path: it waits for one. A session that waits
    /// already keeps its first time, so the wait ends after `DEFERRED_ASK_TTL` whatever comes.
    pub(crate) fn defer_ask(&mut self, session: AuthorKey, now: Instant) {
        if self.deferred.get(&session).is_some() {
            return;
        }
        // every entry reads as dead, so a full map drops the oldest one
        self.deferred.insert_evicting(
            session,
            DeferredAsk {
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
    /// `DEFERRED_ASK_GAP` ago. Each one is marked as tried now.
    pub(crate) fn take_deferred_to_try(&mut self, now: Instant) -> Vec<AuthorKey> {
        let due = self.deferred.keys_where(|waiting| {
            waiting
                .tried
                .is_none_or(|tried| now.saturating_duration_since(tried) >= DEFERRED_ASK_GAP)
        });
        for session in &due {
            if let Some(waiting) = self.deferred.get_mut(session) {
                waiting.tried = Some(now);
            }
        }
        due
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

    /// The sessions that a proof bound the nickname away from since the last call. The caller ends them in
    /// the roster, with no `left` line, because the nickname stays held by the member that proved it.
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
    /// request that got no answer is sent again, with a doubling back-off (3 fast retries, then 6
    /// slow ones). The caller tells [`Self::note_asked`] when the request went out.
    pub(crate) fn wants_proof(&self, session: &AuthorKey, now: Instant) -> bool {
        if self.book.get(session).is_some() {
            return false;
        }
        self.asked
            .get(session)
            .is_none_or(|retry| retry.tries <= RETRIES + SLOW_RETRIES && now >= retry.next_at)
    }

    /// The request for `session` went out at `now`: the retry clock of the session starts. `claimed`
    /// is the bound nickname of a session that is not in the roster. At most 4 asks stay open for
    /// each such nickname, and the oldest of that nickname goes for a new one. `is_held` says whether
    /// a session is in the roster. The book holds 1024 records: when it is full, the record of the
    /// oldest session that is not in the roster goes, so the retry clock of a session that is in it
    /// is not reset. Only when all 1024 are in the roster does the oldest record go, and that
    /// session can be asked again, up to 9 more times: the limit of a mesh of more than 1024
    /// sessions that send no proof.
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
    pub(crate) fn accept(
        &mut self,
        session: &AuthorKey,
        nickname: &Nickname,
        mesh: &MeshId,
        proof: IdentityProof,
        is_held: impl Fn(&AuthorKey) -> bool,
    ) -> bool {
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
}

#[cfg(test)]
mod tests {
    use super::{
        DEFERRED_ASK_GAP, DEFERRED_ASK_TTL, DEFERRED_ASKS_MAX, ProofExchange, verify_proof,
    };
    use crate::protocol::identity::Identity;
    use crate::protocol::{AuthorKey, MeshId, Nickname};
    use crate::util::clock::Instant;
    use crate::util::tuning::QUIET_CAP;
    use std::time::Duration;

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
            book.defer_ask(*session, now);
        }

        assert_eq!(book.deferred_len(), DEFERRED_ASKS_MAX, "the cap holds");
        let waiting = book.take_deferred_to_try(now + DEFERRED_ASK_GAP);
        assert!(
            waiting.contains(&sessions[639]) && !waiting.contains(&sessions[0]),
            "the newest waits and the oldest was dropped"
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
        book.defer_ask(session, start);

        assert_eq!(
            book.take_deferred_to_try(start),
            vec![session],
            "the first try is free: the ask goes as soon as a path is up"
        );
        assert!(
            book.take_deferred_to_try(start).is_empty(),
            "but not twice in one gap"
        );
        assert_eq!(
            book.take_deferred_to_try(start + DEFERRED_ASK_GAP),
            vec![session],
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

    /// After the 3 fast retries a session is asked once per 10 minutes, 6 more times at most, so a
    /// long time with no warm path does not lose the proof for good.
    #[test]
    fn a_slow_retry_follows_the_fast_ones_and_stops_after_six() {
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
        for round in 1..=6 {
            last += 600;
            assert!(joiner.wants_proof(&session, at(last)), "slow retry {round}");
            joiner.note_asked(&session, at(last), None, |_| true);
        }
        assert!(
            !joiner.wants_proof(&session, at(last + 100_000)),
            "no seventh slow retry"
        );
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
