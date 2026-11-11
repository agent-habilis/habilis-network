use std::io;

/// What [`check_runtime_base`](crate::check_runtime_base) found at the base.
#[derive(Debug)]
#[non_exhaustive]
pub enum RuntimeBaseCheck {
    /// A directory that this user owns, with no group or other bits.
    Private,
    /// Nothing is at the base, so no daemon of this user runs there.
    Absent,
    /// Something is at the base, and it is not a private directory of this
    /// user: a link, a file, a directory of another user, or a directory that
    /// other users can open. The error says which.
    Refused(io::Error),
}
