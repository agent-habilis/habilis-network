//! Which browser a tab runs in.

/// Which browser a tab runs in.
#[derive(Clone, Copy)]
pub(crate) enum Engine {
    Chrome,
    Safari,
}
