use std::io;

/// What the system says about the start of a process.
///
/// A failed read is not the same as a process that is gone. A caller that treats a failed read as
/// "gone" ends the work of a live owner after one failed system call (a full file table, no memory).
///
/// # Examples
///
/// A running process has a start time.
///
/// ```
/// use habilis_network_util::process::start_of;
/// use habilis_network_util::process_start::ProcessStart;
///
/// assert!(matches!(start_of(std::process::id()), ProcessStart::Live(_)));
/// ```
#[derive(Debug)]
#[expect(
    clippy::exhaustive_enums,
    reason = "a caller matches every state, so a new state breaks the build of the caller and never passes in a wildcard arm"
)]
pub enum ProcessStart {
    /// The process runs. The unit of the value differs by system (microseconds since the epoch on
    /// macOS, clock ticks since boot on Linux), so compare two values from one host only.
    Live(u64),
    /// No process has the pid, or the process ended and its parent has not reaped it yet (a zombie).
    Gone,
    /// The read failed, so the system says nothing about the process.
    Unknown(io::Error),
}
