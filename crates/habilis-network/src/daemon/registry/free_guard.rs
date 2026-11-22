use std::fs::File;

/// The lock of a registry file, held by a caller that found no daemon for the member. While the guard
/// lives, no daemon can start for that member. The lock goes when the guard drops.
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
