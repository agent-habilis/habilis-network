//! Whether a session is still handshaking or playing.

/// Whether the session is still handshaking or actually playing.
///
/// # Examples
///
/// A session that waits for its peers is not yet running.
///
/// ```
/// use habilis_network_netplay::SessionState;
///
/// assert_ne!(SessionState::Synchronizing, SessionState::Running);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionState {
    /// At least one peer has not completed its handshake. **Do not advance
    /// frames yet** — this is what makes every peer start together, without
    /// needing a shared wall clock.
    Synchronizing,
    /// Every peer is connected; the match is live.
    Running,
}
