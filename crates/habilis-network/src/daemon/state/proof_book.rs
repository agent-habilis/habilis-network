//! The proofs of sessions this node has verified, and the requests it has sent for the ones it lacks.

#[cfg(test)]
mod tests {
    use super::ProofBook;

    /// The book holds at most its cap of proofs: a proof past the cap is refused and counted, and a
    /// proof already held is never evicted.
    #[test]
    fn the_proof_book_refuses_past_its_cap_and_counts_it() {
        let mut book = ProofBook::with_cap(4);
        for index in 0..40u8 {
            book.insert(index.into(), index);
        }
        assert_eq!(book.len(), 4, "the book holds its cap");
        assert_eq!(book.refused(), 36, "every proof past the cap is counted");
        assert_eq!(book.get(&0u8.into()), Some(&0), "a held proof is never evicted");
    }

    /// Answers to requests are capped per minute; the answers past the cap are refused and counted.
    #[test]
    fn answers_are_capped_per_window() {
        let mut book = ProofBook::with_cap(4);
        let now = std::time::Instant::now();
        let allowed = (0..100).filter(|_| book.allow_answer(now)).count();
        assert_eq!(allowed, super::ANSWERS_PER_MINUTE, "answers stop at the cap");
        assert_eq!(book.answers_refused(), 100 - super::ANSWERS_PER_MINUTE);
    }
}
