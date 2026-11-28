use std::fs::File;

/// The lock of a registry file, held by a caller that waited for the daemon of the member to end. While the guard
/// lives, no daemon can start for that member, so drop it at once. The lock goes when the guard drops.
#[derive(Debug)]
#[must_use = "the lock goes when the guard drops"]
pub struct FreeGuard {
    // The lock belongs to the open file, so the file is held and never read.
    _file: File,
}

impl FreeGuard {
    pub(super) fn new(file: File) -> Self {
        Self { _file: file }
    }
}
