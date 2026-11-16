//! What a relay's refusal means for us.

/// What a refusal's machine-readable prefix (NIP-01) tells us to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Slow down: back off before the next publish or REQ.
    RateLimited,
    /// This relay will never serve us: stop using it for good.
    Retire,
    /// Harmless: the relay already has it.
    Duplicate,
    /// The relay refused the event as outside its time window. Its window can
    /// be shorter than our replay window (strfry refuses an ephemeral event
    /// older than 60 s, ours is ±120 s), so this one is worth a warning.
    Stale,
    /// Anything else: log it and carry on.
    Other,
}

/// Words a relay uses to say an event is outside its time window.
const STALE_WORDS: [&str; 3] = ["expired", "too early", "too old"];

pub(crate) fn classify(reason: &str) -> Verdict {
    let prefix = reason.split(':').next().unwrap_or_default();
    match prefix {
        "rate-limited" => Verdict::RateLimited,
        "blocked" | "restricted" | "auth-required" | "pow" => Verdict::Retire,
        "duplicate" => Verdict::Duplicate,
        _ => {
            let lowercase = reason.to_lowercase();
            if STALE_WORDS.iter().any(|word| lowercase.contains(word)) {
                Verdict::Stale
            } else {
                Verdict::Other
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Verdict, classify};

    #[test]
    fn refusal_prefixes_map_to_what_trystero_does() {
        assert_eq!(
            classify("rate-limited: slow down"),
            Verdict::RateLimited,
            "a rate limit means slow down"
        );
        for terminal in [
            "blocked: you are banned",
            "restricted: members only",
            "auth-required: NIP-42",
            "pow: difficulty 20",
        ] {
            assert_eq!(
                classify(terminal),
                Verdict::Retire,
                "a refusal for good retires the relay: {terminal}"
            );
        }
        assert_eq!(
            classify("duplicate: have it"),
            Verdict::Duplicate,
            "a duplicate is harmless"
        );
        assert_eq!(
            classify("error: disk full"),
            Verdict::Other,
            "an error with no known words is logged and ignored"
        );
        assert_eq!(classify(""), Verdict::Other, "no reason is Other");
    }

    /// A relay's time window can be shorter than our replay window, and the
    /// refusal then names it in free text.
    #[test]
    fn a_refusal_that_names_a_time_window_is_stale() {
        for stale in [
            "invalid: event expired",
            "error: created_at too early",
            "invalid: Event is too old",
            "EXPIRED",
        ] {
            assert_eq!(
                classify(stale),
                Verdict::Stale,
                "the words name a time window: {stale}"
            );
        }
        // The words count only when no prefix we act on is present.
        for (reason, verdict) in [
            ("rate-limited: too old a client", Verdict::RateLimited),
            ("blocked: your key expired", Verdict::Retire),
            ("restricted: too early for members", Verdict::Retire),
            ("duplicate: too old to matter", Verdict::Duplicate),
        ] {
            assert_eq!(
                classify(reason),
                verdict,
                "a prefix we act on wins over the words: {reason}"
            );
        }
    }
}
