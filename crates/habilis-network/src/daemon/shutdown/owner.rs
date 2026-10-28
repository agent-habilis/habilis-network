#[cfg(feature = "host")]
use crate::util::process;

use super::OwnerPidError;

/// The process a detached daemon lives for, in place of its parent. The pid
/// alone cannot tell the owner from a later process that reuses the pid, so
/// the start time captured at startup is what identifies it.
#[cfg(feature = "host")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Owner {
    pub(super) pid: u32,
    pub(super) start: u64,
}

#[cfg(feature = "host")]
impl Owner {
    /// # Errors
    /// See [`validate_owner_pid`].
    pub(crate) fn try_new(pid: u32) -> Result<Self, OwnerPidError> {
        Ok(Self {
            pid,
            start: super::owner_start(pid)?,
        })
    }

    pub(crate) fn pid(self) -> u32 {
        self.pid
    }

    pub(super) fn lost(self) -> bool {
        process::live_start_time(self.pid) != Some(self.start)
    }
}
