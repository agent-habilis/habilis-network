#[cfg(feature = "host")]
use crate::util::process;
#[cfg(feature = "host")]
use crate::util::process_start::ProcessStart;

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
    /// See `validate_owner_pid`.
    pub(crate) fn try_new(pid: u32) -> Result<Self, OwnerPidError> {
        Ok(Self {
            pid,
            start: super::owner_start(pid)?,
        })
    }

    pub(crate) fn pid(self) -> u32 {
        self.pid
    }

    /// The start time that the run recorded for its owner.
    pub(crate) fn start(self) -> u64 {
        self.start
    }

    pub(super) fn lost(self) -> bool {
        self.lost_given(&process::start_of(self.pid))
    }

    /// The owner is lost when its pid has no process, or has a process that started at another time. A
    /// failed read of the start says nothing, so it does not lose the owner.
    fn lost_given(self, now: &ProcessStart) -> bool {
        if let ProcessStart::Live(start) = now {
            return *start != self.start;
        }
        !matches!(now, ProcessStart::Unknown(_))
    }
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use std::io;

    use super::{Owner, ProcessStart};

    /// A failed read of the start time says nothing about the owner. A daemon that reads a failure
    /// (a full file table, no memory) as "the owner is gone" ends while its owner lives.
    #[test]
    fn a_failed_read_of_the_start_of_the_owner_does_not_end_the_daemon() {
        let _guard = ::habilis_network_test_tracing::init();
        let owner = Owner {
            pid: 4242,
            start: 7,
        };

        assert!(
            !owner.lost_given(&ProcessStart::Unknown(io::Error::other("the read failed"))),
            "an unknown start is not a lost owner"
        );
        assert!(!owner.lost_given(&ProcessStart::Live(7)), "the same start");
        assert!(owner.lost_given(&ProcessStart::Live(8)), "another start");
        assert!(owner.lost_given(&ProcessStart::Gone), "no process");
    }
}
