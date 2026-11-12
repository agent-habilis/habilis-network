//! The digest round: on each backfill tick a node sends its digests to its linked neighbours. A holder whose
//! digest differs from ours waits the settle delay, then this node asks for its pages, and pulls the slices
//! that it wants and keeps.

use std::collections::HashMap;
use std::time::Duration;

use habilis_network_protocol::digest::{DigestPage, DigestRoot};
use habilis_network_protocol::{AuthorKey, Channel, Message, MessageBody, MessageKind};
use habilis_network_util::clock::Instant;
use habilis_network_util::tuning::{DIGEST_SETTLE, DIGEST_SETTLE_JITTER};
use iroh::EndpointId;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::transport;

/// A digest of a holder that differs from ours: when the settle delay ends, the pages that are asked for, and
/// how many pages the digest has.
#[derive(Debug, Clone, Copy)]
struct Waiting {
    due: Instant,
    total: usize,
    requested: bool,
}

/// The digests that differ from ours, by holder and channel.
#[derive(Debug, Default)]
pub(crate) struct DigestRound {
    waiting: HashMap<(AuthorKey, Channel), Waiting>,
}

impl DigestRound {
    /// Notes that the digest of `holder` on `channel` differs from ours, with `total` pages. The pages are asked
    /// for after the settle delay and `jitter`. A difference that is already noted keeps its first due time.
    pub(crate) fn note_difference(
        &mut self,
        holder: AuthorKey,
        channel: Channel,
        total: usize,
        now: Instant,
        jitter: Duration,
    ) {
        self.waiting.entry((holder, channel)).or_insert(Waiting {
            due: now + DIGEST_SETTLE + jitter,
            total,
            requested: false,
        });
    }

    /// The differences whose settle delay has ended at `now` and whose first page is not asked for yet. Each
    /// one is marked as asked, so the first page is asked once.
    pub(crate) fn ready(&mut self, now: Instant) -> Vec<(AuthorKey, Channel)> {
        let mut ready = Vec::new();
        for (&(holder, channel), waiting) in &mut self.waiting {
            if !waiting.requested && waiting.due <= now {
                waiting.requested = true;
                ready.push((holder, channel));
            }
        }
        ready
    }

    /// Notes that the page `index` of the digest was read. Returns the next page to ask for, or `None` when
    /// it was the last page, and the difference is then settled.
    pub(crate) fn page_read(
        &mut self,
        holder: AuthorKey,
        channel: Channel,
        index: usize,
    ) -> Option<usize> {
        let next = index + 1;
        let waiting = self.waiting.get_mut(&(holder, channel))?;
        if next < waiting.total {
            return Some(next);
        }
        self.waiting.remove(&(holder, channel));
        None
    }
}

impl DigestRound {
    /// The keys of `page` that this node wants and keeps, in pulls of at most `rows` keys each. A key that is
    /// not in the roster is not pulled: the store would hold its slice only as a pending one.
    pub(crate) fn pull_plan(
        state: &EventLoopState,
        channel: Channel,
        page: &DigestPage,
        rows: usize,
    ) -> Vec<Vec<AuthorKey>> {
        let listed: Vec<AuthorKey> = state.docs.wanted(channel, page);
        let wanted: Vec<AuthorKey> = listed
            .into_iter()
            .filter(|key| state.keeps_slice(key))
            .collect();
        wanted
            .chunks(rows.max(1))
            .map(<[AuthorKey]>::to_vec)
            .collect()
    }
}

/// The settle jitter of one mismatch: uniform from zero to `DIGEST_SETTLE_JITTER`, so the peers that see the same
/// difference do not all ask at once.
pub(crate) fn settle_jitter() -> Duration {
    let millis = rand::Rng::random_range(&mut rand::rng(), 0..=DIGEST_SETTLE_JITTER.as_millis());
    Duration::from_millis(u64::try_from(millis).unwrap_or(0))
}

/// The linked neighbours of this node: the roster keys whose endpoint is in the linked set, with that endpoint.
fn neighbours(state: &EventLoopState) -> Vec<(AuthorKey, EndpointId)> {
    state
        .peers
        .iter()
        .filter_map(|key| {
            let eid = state.address_of(key)?.id;
            state.linked_endpoints.contains(&eid).then_some((*key, eid))
        })
        .collect()
}

/// Sends `kind` to `eid` as a signed frame of this node.
async fn send_kind(
    state: &EventLoopState,
    context: &HandlerCtx<'_>,
    eid: EndpointId,
    kind: MessageKind,
) {
    let Ok(body) = MessageBody::try_new("{}") else {
        return;
    };
    let frame = Message::new_frame(context.mesh, context.author, kind, body).sign(&state.identity);
    let Ok(bytes) = frame.serialize() else {
        tracing::debug!(target: "habilis_network::gossip", "a digest frame did not serialize, so it is not sent");
        return;
    };
    transport::send_best_effort(eid, bytes, state).await;
}

/// The digest round tick: each linked neighbour gets this node's digests, and each difference whose settle
/// delay has ended gets its first page asked for.
pub(crate) async fn tick(state: &mut EventLoopState, context: &HandlerCtx<'_>, now: Instant) {
    for (key, eid) in neighbours(state) {
        let root = MessageKind::SliceRoot {
            to: key,
            state: state.docs.digest(Channel::State),
            meta: state.docs.digest(Channel::Meta),
        };
        send_kind(state, context, eid, root).await;
    }
    for (holder, channel) in state.digest_round.ready(now) {
        request_page(state, context, holder, channel, 0).await;
    }
}

/// Asks `holder` for page `index` of its digest on `channel`, when the holder has an address.
async fn request_page(
    state: &EventLoopState,
    context: &HandlerCtx<'_>,
    holder: AuthorKey,
    channel: Channel,
    index: usize,
) {
    let Some(address) = state.address_of(&holder) else {
        return;
    };
    let request = MessageKind::SlicePageRequest {
        to: holder,
        channel,
        index,
    };
    send_kind(state, context, address.id, request).await;
}

/// A holder's root arrived. Each channel whose root differs from ours is noted, to be asked after the settle.
pub(crate) fn on_root(
    state: &mut EventLoopState,
    holder: AuthorKey,
    roots: [(Channel, &DigestRoot); 2],
    now: Instant,
    jitter: Duration,
) {
    if !state.in_roster(&holder) {
        return;
    }
    for (channel, root) in roots {
        if !state.docs.matches(channel, &root.root()) {
            state
                .digest_round
                .note_difference(holder, channel, root.total(), now, jitter);
        }
    }
}

/// A page of a holder's digest arrived. This node pulls the keys of the page that it wants, in pulls of the
/// store's row count, and asks for the next page.
pub(crate) async fn on_page(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    holder: AuthorKey,
    channel: Channel,
    page: &DigestPage,
    now: Instant,
) {
    let rows = state.docs.pull_rows(channel);
    let Some(address) = state.address_of(&holder).map(|address| address.id) else {
        return;
    };
    for keys in DigestRound::pull_plan(state, channel, page, rows) {
        for key in &keys {
            state
                .outstanding_pulls
                .register(address, channel, *key, now);
        }
        let pull = MessageKind::SlicePull {
            to: holder,
            channel,
            keys,
        };
        send_kind(state, context, address, pull).await;
    }
    if let Some(next) = state.digest_round.page_read(holder, channel, page.index()) {
        request_page(state, context, holder, channel, next).await;
    }
}

#[cfg(test)]
mod tests {
    use super::DigestRound;
    use crate::testing;
    use habilis_network_protocol::digest::{DigestEntry, DigestPage};
    use habilis_network_protocol::{AuthorKey, Channel, ContentHash, Identity};
    use habilis_network_util::clock::Instant;
    use habilis_network_util::tuning::DIGEST_SETTLE;
    use std::time::Duration;

    fn entry(seed: u8) -> DigestEntry {
        DigestEntry::new(AuthorKey::from([seed; 32]), 1, ContentHash::of(&[seed]))
    }

    /// A difference waits the settle delay before its first page is asked for.
    #[test]
    fn a_mismatch_waits_the_settle_before_it_asks() {
        let now = Instant::now();
        let holder = Identity::generate().author_key();
        let mut round = DigestRound::default();
        round.note_difference(holder, Channel::State, 1, now, Duration::ZERO);
        assert!(
            round.ready(now).is_empty(),
            "a difference is not asked for before the settle delay ends"
        );
        assert_eq!(
            round.ready(now + DIGEST_SETTLE),
            vec![(holder, Channel::State)],
            "the first page is asked for once the settle delay has ended"
        );
    }

    /// A page lists a key that is not in the roster. The pull plan keeps the roster key only.
    #[test]
    fn a_key_outside_the_roster_is_not_pulled() {
        let mut state = testing::fresh_state();
        let member = AuthorKey::from([1; 32]);
        let stranger = AuthorKey::from([2; 32]);
        state.peers.insert(member);
        let page =
            DigestPage::build(&[entry(1), entry(2)], 2, 0, 1).expect("a page of two sorted rows");
        let planned: Vec<AuthorKey> = DigestRound::pull_plan(&state, Channel::State, &page, 18)
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(planned, vec![member], "only the roster key is pulled");
        assert!(!planned.contains(&stranger), "a stranger is not pulled");
    }
}
