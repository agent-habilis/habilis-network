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

/// The wait after the ask number `tries` (0 for the first): 30 s, 60 s, 120 s, then 10 minutes.
fn retry_wait(tries: u8) -> Duration {
    if tries < RETRIES {
        FIRST_RETRY_WAIT * 2u32.pow(u32::from(tries))
    } else {
        SLOW_RETRY_WAIT
    }
}

/// How many times a session was asked, and when the next request may go.
#[derive(Debug, Clone, Copy)]
struct Retry {
    tries: u8,
    next_at: Instant,
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
    /// session proved the nickname, or when no held session binds it. A bound nickname with no
    /// proof of its member is the join error of the claimant; the refusal is counted.
    pub(crate) fn admits(
        &mut self,
        session: &AuthorKey,
        nickname: &Nickname,
        is_held: impl Fn(&AuthorKey) -> bool,
    ) -> bool {
        let proved = self
            .book
            .get(session)
            .is_some_and(|(named, _)| named == nickname);
        let admitted = proved || self.bound_to(nickname, is_held).is_none();
        if !admitted {
            self.gate_refused += 1;
        }
        admitted
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
    /// request that got no answer is sent again, 3 times at most, with a doubling back-off. The
    /// caller tells [`Self::note_asked`] when the request went out.
    pub(crate) fn wants_proof(&self, session: &AuthorKey, now: Instant) -> bool {
        if self.book.get(session).is_some() {
            return false;
        }
        self.asked
            .get(session)
            .is_none_or(|retry| retry.tries <= RETRIES + SLOW_RETRIES && now >= retry.next_at)
    }

    /// The request for `session` went out at `now`: the retry clock of the session starts.
    pub(crate) fn note_asked(&mut self, session: &AuthorKey, now: Instant) {
        let tries = self.asked.get(session).map_or(0, |retry| retry.tries);
        let retry = Retry {
            tries: tries.saturating_add(1),
            next_at: now + retry_wait(tries),
        };
        self.asked.insert_evicting(*session, retry, |_, _| false);
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
        if !verify_proof(&proof, session, nickname.as_ref(), mesh.as_ref()) {
            return false;
        }
        let bound = self.bound_to(nickname, &is_held);
        if bound.is_some_and(|member| member != proof.identity) {
            self.bound_refused += 1;
            return false;
        }
        self.book
            .insert_evicting(*session, (nickname.clone(), proof), |held, _| is_held(held));
        self.book.get(session).is_some()
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
    use super::{ProofExchange, verify_proof};
    use crate::protocol::identity::Identity;
    use crate::protocol::{MeshId, Nickname};
    use crate::util::clock::Instant;
    use crate::util::tuning::QUIET_CAP;
    use std::time::Duration;

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
        joiner.note_asked(&session, now);
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
        joiner.note_asked(&session, now);
        assert!(
            !joiner.wants_proof(&session, now),
            "after a send the retry clock runs"
        );
    }

    /// A request that got no answer is sent again, 3 times at most, after 30 s, 60 s and 120 s.
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
        joiner.note_asked(&session, at(0));
        assert!(
            !joiner.wants_proof(&session, at(29)),
            "no retry before 30 s"
        );
        assert!(joiner.wants_proof(&session, at(30)), "retry 1 after 30 s");
        joiner.note_asked(&session, at(30));
        assert!(
            !joiner.wants_proof(&session, at(89)),
            "no retry before 60 s more"
        );
        assert!(
            joiner.wants_proof(&session, at(90)),
            "retry 2 after 60 s more"
        );
        joiner.note_asked(&session, at(90));
        assert!(
            !joiner.wants_proof(&session, at(209)),
            "no retry before 120 s more"
        );
        assert!(
            joiner.wants_proof(&session, at(210)),
            "retry 3 after 120 s more"
        );
        joiner.note_asked(&session, at(210));
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
            joiner.note_asked(&session, at(secs));
        }
        assert!(
            !joiner.wants_proof(&session, at(809)),
            "no slow retry before 10 minutes"
        );
        let mut last = 210;
        for round in 1..=6 {
            last += 600;
            assert!(joiner.wants_proof(&session, at(last)), "slow retry {round}");
            joiner.note_asked(&session, at(last));
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

    /// A restarted member has a dead session and a live one under one nickname. The book must tell
    /// them apart: the dead session goes first when the book is full, so the proof of a new member
    /// still lands. A nickname alone cannot tell them apart, because the live session keeps it live.
    #[test]
    fn the_dead_session_of_a_restarted_member_does_not_block_a_full_book() {
        let mesh = MeshId::from("💬test");
        let alice = Nickname::from("alice");
        let member = Identity::generate();
        let (old, new) = (
            Identity::generate().author_key(),
            Identity::generate().author_key(),
        );
        let mut book = ProofExchange::with_cap(4);
        for (session, run) in [(old, 1), (new, 2)] {
            let proof = member.prove(&session, alice.as_ref(), mesh.as_ref(), run);
            assert!(
                book.accept(&session, &alice, &mesh, proof, |_| true),
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
}
