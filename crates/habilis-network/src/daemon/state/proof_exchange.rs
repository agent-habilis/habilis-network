#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the event loop state holds the exchange in the next commit"
    )
)]

use super::proof_book::ProofBook;
use crate::protocol::identity::{IdentityProof, verify_proof};
use crate::protocol::{AuthorKey, MeshId, Nickname};
use crate::util::clock::Instant;
use habilis_network_util::bounded_fifo_set::BoundedFifoSet;

/// The proofs this node holds, and the sessions it already asked for one. A proof comes in the
/// `joined` frame of a session. A receiver that missed that frame asks the session once, by a
/// unicast request, so a calm mesh carries no proof bytes beyond the `joined` frames.
///
/// Between two proofs for one session, the one with the higher run wins. On a tie the first stays.
#[derive(Debug)]
pub(crate) struct ProofExchange {
    book: ProofBook<AuthorKey, (Nickname, IdentityProof)>,
    // one request per session: a bound like the book, so a flood of new sessions cannot grow it
    asked: BoundedFifoSet<AuthorKey>,
    ties_refused: u64,
}

impl ProofExchange {
    pub(crate) fn with_cap(cap: usize) -> Self {
        Self {
            book: ProofBook::with_cap(cap),
            asked: BoundedFifoSet::new(cap),
            ties_refused: 0,
        }
    }

    /// An alive frame came from `session`. True means: send the session one proof request now.
    pub(crate) fn wants_proof(&mut self, session: &AuthorKey, _now: Instant) -> bool {
        self.book.get(session).is_none() && self.asked.insert(*session)
    }

    /// A proof came for `session`. It is held if it verifies for this nickname and mesh, and if it
    /// does not lower the run of a proof already held.
    pub(crate) fn accept(
        &mut self,
        session: &AuthorKey,
        nickname: &Nickname,
        mesh: &MeshId,
        proof: IdentityProof,
        is_live: impl Fn(&Nickname) -> bool,
    ) -> bool {
        if !verify_proof(&proof, session, nickname.as_ref(), mesh.as_ref()) {
            return false;
        }
        if self
            .book
            .get(session)
            .is_some_and(|(_, held)| held.run >= proof.run)
        {
            self.ties_refused += 1;
            return false;
        }
        self.book
            .insert_evicting(*session, (nickname.clone(), proof), |_, (held, _)| {
                is_live(held)
            });
        self.book.get(session).is_some()
    }

    /// Whether one more answer to `asker` may go out at `now`: one per asker and window, and the per-minute cap of the node.
    pub(crate) fn may_answer(&mut self, asker: &AuthorKey, now: Instant) -> bool {
        self.book.allow_answer_to(asker, now)
    }

    /// How many proofs this node refused because their run did not beat the held run.
    pub(crate) fn ties_refused(&self) -> u64 {
        self.ties_refused
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

        assert!(
            joiner.wants_proof(&session, Instant::now()),
            "an alive frame of a session with no proof asks for it"
        );
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
        assert!(
            !joiner.wants_proof(&session, at(29)),
            "no retry before 30 s"
        );
        assert!(joiner.wants_proof(&session, at(30)), "retry 1 after 30 s");
        assert!(
            !joiner.wants_proof(&session, at(89)),
            "no retry before 60 s more"
        );
        assert!(
            joiner.wants_proof(&session, at(90)),
            "retry 2 after 60 s more"
        );
        assert!(
            !joiner.wants_proof(&session, at(209)),
            "no retry before 120 s more"
        );
        assert!(
            joiner.wants_proof(&session, at(210)),
            "retry 3 after 120 s more"
        );
        assert!(
            !joiner.wants_proof(&session, at(100_000)),
            "no fourth retry"
        );
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
            "a tie is not held"
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
            "a tie and a lower run are counted"
        );
    }
}
