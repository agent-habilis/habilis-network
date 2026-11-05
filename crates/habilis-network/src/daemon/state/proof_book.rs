#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the event loop state holds the book in the next commit"
    )
)]

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::Duration;

use crate::util::clock::Instant;

/// The answers this node sends per minute. A request is cheap to send; an answer is one proof, so
/// a flood of requests must not turn this node into a sender of proofs.
pub(crate) const ANSWERS_PER_MINUTE: usize = 30;
const ANSWER_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub(crate) struct ProofBook<K, V> {
    cap: usize,
    held: HashMap<K, V>,
    // the sessions in the order their proofs came, oldest first; as long as `held`, so bounded by the cap
    order: VecDeque<K>,
    refused: u64,
    answers: Vec<Instant>,
    // the askers answered in the last window, as many as the cap at most; as long as `answers` is bounded by the rate
    askers: HashMap<K, Instant>,
    answers_refused: u64,
}

impl<K: Eq + Hash + Clone, V> ProofBook<K, V> {
    pub(crate) fn with_cap(cap: usize) -> Self {
        Self {
            cap,
            held: HashMap::new(),
            order: VecDeque::new(),
            refused: 0,
            answers: Vec::new(),
            askers: HashMap::new(),
            answers_refused: 0,
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V) {
        if self.held.contains_key(&key) || self.held.len() < self.cap {
            if self.held.insert(key.clone(), value).is_none() {
                self.order.push_back(key);
            }
        } else {
            self.refused += 1;
        }
    }

    /// Hold the proof of a session. At the cap, the oldest session that `is_live` denies goes first.
    /// If every held session is live, the proof is refused and counted.
    pub(crate) fn insert_evicting(&mut self, key: K, value: V, is_live: impl Fn(&K, &V) -> bool) {
        let full = !self.held.contains_key(&key) && self.held.len() >= self.cap;
        let held = &self.held;
        let is_dead = |session: &&K| {
            held.get(*session)
                .is_some_and(|proof| !is_live(session, proof))
        };
        let mut dead_ones = self.order.iter().filter(is_dead);
        if full && let Some(oldest_dead) = dead_ones.next().cloned() {
            self.remove(&oldest_dead);
        }
        self.insert(key, value);
    }

    /// Forget the proof of a session that left or that a newer run replaced.
    pub(crate) fn remove(&mut self, key: &K) {
        if self.held.remove(key).is_some() {
            self.order.retain(|held| held != key);
        }
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.held.get(key)
    }

    pub(crate) fn len(&self) -> usize {
        self.held.len()
    }

    pub(crate) fn refused(&self) -> u64 {
        self.refused
    }

    /// Whether an answer may go out at `now`, within the per-minute cap. A refused answer is counted.
    pub(crate) fn allow_answer(&mut self, now: Instant) -> bool {
        self.answers
            .retain(|sent| now.saturating_duration_since(*sent) < ANSWER_WINDOW);
        if self.answers.len() < ANSWERS_PER_MINUTE {
            self.answers.push(now);
            true
        } else {
            self.answers_refused += 1;
            false
        }
    }

    /// Whether an answer to `asker` may go out at `now`: one answer per asker in each window, and
    /// the node-wide cap as the outer bound. A refused answer is counted.
    pub(crate) fn allow_answer_to(&mut self, asker: &K, now: Instant) -> bool {
        self.askers
            .retain(|_, sent| now.saturating_duration_since(*sent) < ANSWER_WINDOW);
        if self.askers.contains_key(asker) || self.askers.len() >= self.cap {
            self.answers_refused += 1;
            return false;
        }
        if !self.allow_answer(now) {
            return false;
        }
        self.askers.insert(asker.clone(), now);
        true
    }

    pub(crate) fn answers_refused(&self) -> u64 {
        self.answers_refused
    }
}

#[cfg(test)]
mod tests {
    use super::ProofBook;
    use crate::util::clock::Instant;
    use std::time::Duration;

    /// The book holds at most its cap of proofs: a proof past the cap is refused and counted, and a
    /// proof already held is never evicted.
    #[test]
    fn the_proof_book_refuses_past_its_cap_and_counts_it() {
        let mut book: ProofBook<u8, u8> = ProofBook::with_cap(4);
        for index in 0..40u8 {
            book.insert(index, index);
        }
        assert_eq!(book.len(), 4, "the book holds its cap");
        assert_eq!(book.refused(), 36, "every proof past the cap is counted");
        assert_eq!(book.get(&0), Some(&0), "a held proof is never evicted");
    }

    /// Each run of a peer is a new session. A session that a newer run replaced is removed, so the
    /// book keeps the newest session however many runs went by.
    #[test]
    fn a_replaced_session_is_removed_and_the_newest_always_verifies() {
        let mut book: ProofBook<u8, u8> = ProofBook::with_cap(4);
        for run in 0..40u8 {
            if let Some(older) = run.checked_sub(1) {
                book.remove(&older);
            }
            book.insert(run, run);
        }
        assert_eq!(book.get(&39), Some(&39), "the newest session verifies");
        assert_eq!(book.len(), 1, "only the newest session stays");
        assert_eq!(book.refused(), 0, "no proof was refused");
    }

    /// 40 members that each come once and never return must not fill the book: the oldest dead
    /// session goes, so the newest always verifies.
    #[test]
    fn dead_sessions_go_first_when_the_book_is_full() {
        let mut book: ProofBook<u8, u8> = ProofBook::with_cap(4);
        for member in 0..40u8 {
            book.insert_evicting(member, member, |_, _| false);
        }
        assert_eq!(book.get(&39), Some(&39), "the newest session verifies");
        assert_eq!(book.len(), 4, "the book holds its cap");
        assert_eq!(book.refused(), 0, "no proof was refused");
    }

    /// A live session is never evicted: if all are live and the book is full, the new proof is
    /// refused and counted.
    #[test]
    fn a_live_session_is_never_evicted() {
        let mut book: ProofBook<u8, u8> = ProofBook::with_cap(4);
        for member in 0..40u8 {
            book.insert_evicting(member, member, |_, _| true);
        }
        assert_eq!(book.get(&0), Some(&0), "the oldest live session stays");
        assert_eq!(book.len(), 4, "the book holds its cap");
        assert_eq!(book.refused(), 36, "every proof past the cap is counted");
    }

    /// One asker gets one answer per window, so a single asker cannot take the node-wide cap and
    /// starve the others.
    #[test]
    fn one_asker_gets_one_answer_per_window() {
        let mut book: ProofBook<u8, u8> = ProofBook::with_cap(4);
        let now = Instant::now();
        assert!(
            book.allow_answer_to(&1, now),
            "the first request of an asker is answered"
        );
        assert!(
            !book.allow_answer_to(&1, now),
            "its second request in the window is not"
        );
        assert!(
            book.allow_answer_to(&2, now),
            "another asker is still answered"
        );
        let later = now + Duration::from_secs(61);
        assert!(
            book.allow_answer_to(&1, later),
            "the next window answers the asker again"
        );
    }

    /// Answers to requests are capped per minute; the answers past the cap are refused and counted.
    #[test]
    fn answers_are_capped_per_window() {
        let mut book: ProofBook<u8, u8> = ProofBook::with_cap(4);
        let now = Instant::now();
        let allowed = (0..100).filter(|_| book.allow_answer(now)).count();
        assert_eq!(
            allowed,
            super::ANSWERS_PER_MINUTE,
            "answers stop at the cap"
        );
        assert_eq!(
            book.answers_refused(),
            100 - super::ANSWERS_PER_MINUTE as u64,
            "every answer past the cap is counted"
        );
    }
}
