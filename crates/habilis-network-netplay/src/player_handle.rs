//! Player handles.

/// A player's place in the roster, counting from `0`.
///
/// Positional: every peer of a match builds the same roster in the same order,
/// so one handle names the same player on every peer. The handle of a roster
/// slot and the length of the roster are both `usize`, which is why a handle
/// is not a bare `usize`: a frame count, a delay or a queue length can sit
/// beside it in one signature.
///
/// # Examples
///
/// A handle names one roster slot, by its index.
///
/// ```
/// use habilis_network_netplay::PlayerHandle;
///
/// let handle = PlayerHandle::new(1);
/// assert_eq!(handle.index(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlayerHandle(usize);

impl PlayerHandle {
    /// The handle of roster slot `index`.
    #[must_use]
    pub fn new(index: usize) -> Self {
        Self(index)
    }

    /// The roster slot this handle names.
    #[must_use]
    pub fn index(self) -> usize {
        self.0
    }
}

impl std::fmt::Display for PlayerHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}
