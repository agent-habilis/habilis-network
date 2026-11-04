//! What the window of the end of the session reports.

use super::SessionEnd;

/// What the window of [`watch_session_end`](super::watch_session_end) reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// `WM_ENDSESSION` with `TRUE`: the session ends, and Windows ends the
    /// process when the window procedure returns.
    End(SessionEnd),
    /// `WM_CLOSE`: a request to close, with no deadline.
    Close,
}
