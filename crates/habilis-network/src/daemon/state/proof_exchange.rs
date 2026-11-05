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
use crate::util::tuning::QUIET_CAP;
use habilis_network_util::bounded_fifo_set::BoundedFifoSet;

/// The proofs this node holds, and the sessions it already asked for one. A proof comes in the
/// `joined` frame of a session. A receiver that missed that frame asks the session once, by a
/// unicast request, so a calm mesh carries no proof bytes beyond the `joined` frames.
///
/// Between two proofs for one session, the one with the higher run wins. On a tie the first stays.
pub(crate) struct ProofExchange {
    book: ProofBook<AuthorKey, IdentityProof>,
    // one request per session: a bound like the book, so a flood of new sessions cannot grow it
    asked: BoundedFifoSet<AuthorKey>,
}

impl ProofExchange {
    pub(crate) fn with_cap(cap: usize) -> Self {
        Self {
            book: ProofBook::with_cap(cap),
            asked: BoundedFifoSet::new(cap),
        }
    }

    /// An alive frame came from `session`. True means: send the session one proof request now.
    pub(crate) fn wants_proof(&mut self, session: &AuthorKey) -> bool {
        let _ = (&self.asked, session);
        false
    }

    /// A proof came for `session`. It is held if it verifies for this nickname and mesh.
    pub(crate) fn accept(
        &mut self,
        _session: &AuthorKey,
        _nickname: &Nickname,
        _mesh: &MeshId,
        _proof: IdentityProof,
        _is_live: impl Fn(&AuthorKey) -> bool,
    ) -> bool {
        false
    }

    pub(crate) fn proof_of(&self, session: &AuthorKey) -> Option<&IdentityProof> {
        self.book.get(session)
    }
}

#[cfg(test)]
mod tests {
    use super::{ProofExchange, QUIET_CAP, verify_proof};
    use crate::protocol::identity::Identity;
    use crate::protocol::{MeshId, Nickname};

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
            joiner.wants_proof(&session),
            "an alive frame of a session with no proof asks for it"
        );
        assert!(
            !joiner.wants_proof(&session),
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
        let requests = (0..1000).filter(|_| receiver.wants_proof(&session)).count();
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
}
