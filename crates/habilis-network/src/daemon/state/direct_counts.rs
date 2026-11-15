/// Link counts by [`DirectState`](super::DirectState), for the census line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectCounts {
    pub(crate) direct: usize,
    pub(crate) relay_only: usize,
    pub(crate) pending: usize,
}
