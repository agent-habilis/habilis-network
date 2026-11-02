//! The console events that a process can raise.

/// The console events that a process can raise.
///
/// `GenerateConsoleCtrlEvent` raises only these two. Closing the console, a
/// logoff and a shutdown come from the system alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsoleEvent {
    /// Ctrl+C, to every process of the console of the target.
    CtrlC,
    /// Ctrl+Break, to the process group of the target only. The target must be
    /// the root of its own group ([`CREATE_NEW_PROCESS_GROUP`](super::CREATE_NEW_PROCESS_GROUP)), so the id of
    /// the group is its pid.
    CtrlBreak,
}
