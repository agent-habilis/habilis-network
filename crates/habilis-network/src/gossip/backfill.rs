//! Backfill of a newcomer: each member sends its own slice of each channel to it, as one signed frame per
//! channel.
//!
//! A frame is the author's original signed frame, so the newcomer checks the author's signature on it.
//! A newcomer is owed the frames until one of them goes out. A send that finds no path keeps the newcomer
//! owed. The tick sends again, and the entry expires after `ALIVE_TIMEOUT`. A proof answer to the newcomer
//! sends at once, because that exchange opens the path.

use crate::daemon::state::EventLoopState;
use crate::protocol::{AuthorKey, Channel};
use crate::transport;
use crate::util::clock::Instant;
use crate::util::tuning;
use iroh::EndpointId;

/// Records that `newcomer` is owed the backfill of this node, when it is not owed already.
pub(crate) fn owe(state: &mut EventLoopState, newcomer: AuthorKey, now: Instant) {
    state.owed_backfill.entry(newcomer).or_insert(now);
}

/// Sends the own frames to `eid`, and says whether every one of them went out. `dial_back` is true when
/// `eid` has just sent this node an authenticated unicast frame, so a dial back is allowed.
pub(crate) async fn send_to(state: &EventLoopState, eid: EndpointId, dial_back: bool) -> bool {
    let own = state.identity.author_key();
    let mut all_sent = true;
    for channel in [Channel::State, Channel::Meta] {
        let Some(frame) = state.docs.own_frame(channel, &own) else {
            continue;
        };
        all_sent &= if dial_back {
            transport::send_dialing_back(eid, frame, state).await
        } else {
            transport::send_best_effort(eid, frame, state).await
        };
    }
    all_sent
}

/// Sends the own frames to each owed newcomer that has a path, and drops the entries that lasted
/// `ALIVE_TIMEOUT`.
pub(crate) async fn settle(state: &mut EventLoopState, now: Instant) {
    let lifetime = tuning::alive_timeout();
    state
        .owed_backfill
        .retain(|_, owed_at| now.saturating_duration_since(*owed_at) < lifetime);
    let owed: Vec<AuthorKey> = state.owed_backfill.keys().copied().collect();
    for newcomer in owed {
        let Some(eid) = state.address_of(&newcomer).map(|address| address.id) else {
            continue;
        };
        if send_to(state, eid, false).await {
            state.owed_backfill.remove(&newcomer);
        }
    }
}
