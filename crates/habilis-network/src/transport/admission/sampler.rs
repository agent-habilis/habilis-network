//! The sampler of the gossip view and the spawn of its task.

use crate::transport::probe;
use std::sync::{Mutex, Weak};
use std::time::Duration;



use super::Inner;

/// Pure: what the table tells the gossip transport about a peer whose live connections read as
/// `kinds`: whether it is established (any live connection, on any protocol) and whether frames
/// may go to it (no higher rung carries the pair: see
/// [`allow_for`](probe::allow_for), read on the best of the connections). A peer with no
/// connection is not established and is allowed.
///
/// Two ends of one pair may disagree for one sweep, and a multihop path that is dead stays
/// selected until noq abandons it (15 s), so gossip is blocked for that long.
pub(crate) fn gossip_view(kinds: &[probe::PathKind]) -> (bool, bool) {
    let best = probe::best_kind(kinds.iter().copied());
    (!kinds.is_empty(), best.is_none_or(probe::allow_for))
}

/// One timer for the whole table, ending with it.
pub(crate) fn spawn_sampler(table: Weak<Mutex<Inner>>, period: Duration) {
    n0_future::task::spawn(async move {
        loop {
            n0_future::time::sleep(period).await;
            let Some(table) = table.upgrade() else {
                return;
            };
            let mut inner = table.lock().expect("signal admission poisoned");
            if inner.closed {
                return;
            }
            inner.sample();
        }
    });
}
