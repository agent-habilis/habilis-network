//! Why the Windows session ends.

use windows_sys::Win32::Foundation::LPARAM;
use windows_sys::Win32::UI::WindowsAndMessaging::{ENDSESSION_CLOSEAPP, ENDSESSION_LOGOFF};

/// Why the session ends, from the bits of the `lParam` of `WM_ENDSESSION`.
///
/// A forced end (`ENDSESSION_CRITICAL`) is one of these too: the bit only says
/// that the process cannot refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEnd {
    /// The user logs off (`ENDSESSION_LOGOFF`).
    Logoff,
    /// The system shuts down or restarts (no bit).
    Shutdown,
    /// The Restart Manager closes the process (`ENDSESSION_CLOSEAPP`), for
    /// example an installer that replaces its file.
    CloseApp,
}

impl SessionEnd {
    pub(super) fn parse_lparam(lparam: LPARAM) -> Self {
        let bits = lparam.cast_unsigned();
        if bits & ENDSESSION_CLOSEAPP as usize != 0 {
            Self::CloseApp
        } else if bits & ENDSESSION_LOGOFF as usize != 0 {
            Self::Logoff
        } else {
            Self::Shutdown
        }
    }
}
