/// Whether the daemon that a record names runs.
///
/// A process is the daemon of a record when it has the recorded pid and the recorded start, so a later
/// process that reuses the pid is not taken for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DaemonState {
    /// A process has the recorded pid and the recorded start.
    Live,
    /// No process has the pid, or the process of the pid started at another time.
    Gone,
    /// The system could not say: the read of the start failed. The daemon can run.
    Unknown,
}
