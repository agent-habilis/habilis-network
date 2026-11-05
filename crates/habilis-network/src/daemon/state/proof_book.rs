//! The proofs of sessions this node has verified, and the answers it sends for the ones it is asked.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the event loop state holds the book in the next commit"
    )
)]

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// The answers this node sends per minute. A request is cheap to send; an answer is one proof, so
/// a flood of requests must not turn this node into a sender of proofs.
pub(crate) const ANSWERS_PER_MINUTE: usize = 30;
const ANSWER_WINDOW: Duration = Duration::from_secs(60);

pub(crate) struct ProofBook<K, V> {
    cap: usize,
    held: HashMap<K, V>,
    refused: u64,
    answers: Vec<Instant>,
    answers_refused: u64,
}

impl<K: Eq + Hash, V> ProofBook<K, V> {
    pub(crate) fn with_cap(cap: usize) -> Self {
        Self {
            cap,
            held: HashMap::new(),
            refused: 0,
            answers: Vec::new(),
            answers_refused: 0,
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V) {
        if self.held.contains_key(&key) || self.held.len() < self.cap {
            self.held.insert(key, value);
        } else {
            self.refused += 1;
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

    pub(crate) fn answers_refused(&self) -> u64 {
        self.answers_refused
    }
}

#[cfg(test)]
mod tests {
    use super::ProofBook;
    use std::time::Instant;

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
