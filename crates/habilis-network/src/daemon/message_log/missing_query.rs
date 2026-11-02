use std::collections::HashSet;

use crate::protocol::{DedupKey, Nickname};

use super::WindowRange;

/// One gap query against the log: the window to search, the ids the requester
/// already advertised, the resend budget left for this round, and **who** is
/// asking — the last because entitlement is per-peer, not global (see
/// `resendable_to`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct MissingQuery<'query> {
    pub range: WindowRange,
    pub have: &'query HashSet<DedupKey>,
    pub max: usize,
    pub requester: &'query Nickname,
}
