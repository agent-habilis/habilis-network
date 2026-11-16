#[cfg(feature = "host")]
use std::error;
#[cfg(feature = "host")]
use std::fmt;
/// Why a pid cannot be the owner of a detached daemon.
///
/// # Examples
///
/// A reserved pid returns this error with the pid.
///
/// ```
/// use habilis_network::runtime::{OwnerPidError, validate_owner_pid};
///
/// assert!(matches!(validate_owner_pid(0), Err(OwnerPidError::Reserved(0))));
/// ```
#[cfg(feature = "host")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum OwnerPidError {
    /// The pid is `0` or `1`: init, or no process at all.
    Reserved(u32),
    /// The pid is the calling process's own.
    OwnSelf(u32),
    /// No live process has the pid.
    NotRunning(u32),
}

#[cfg(feature = "host")]
impl fmt::Display for OwnerPidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reserved(pid) => write!(
                formatter,
                "owner pid {pid} is init or invalid. Give a live process id greater than 1"
            ),
            Self::OwnSelf(pid) => write!(formatter, "owner pid {pid} is this process itself"),
            Self::NotRunning(pid) => write!(formatter, "owner pid {pid} is not running"),
        }
    }
}

#[cfg(feature = "host")]
impl error::Error for OwnerPidError {}
