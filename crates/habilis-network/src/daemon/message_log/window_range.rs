use super::Bound;

/// Inclusive `[lo, hi]` bounds to filter by — the shape shared by a
/// `DigestWindow` and a wire-decoded digest window entry (the anti-entropy
/// caller's own type), grouped so `MessageLog::missing_in_window` doesn't
/// need either concrete type by name.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WindowRange {
    pub lo: Bound,
    pub hi: Bound,
}
