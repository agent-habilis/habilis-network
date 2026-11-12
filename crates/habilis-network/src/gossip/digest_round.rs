//! The digest round. Each backfill tick a node sends its digests to its linked neighbours. A holder whose digest
//! differs from ours waits the settle delay, then compares again. If it still differs, this node reads the
//! holder's digest one page at a time, on one channel at a time, and pulls the slices that it wants and keeps.
//!
//! The round takes only what arrived by unicast from a roster peer. A page is taken only when this node asked
//! for it, from the same connection, within a deadline.

use std::collections::HashMap;
use std::mem;
use std::time::Duration;

use habilis_network_protocol::digest::{DigestPage, DigestRoot};
use habilis_network_protocol::{
    AuthorKey, Channel, ContentHash, Message, MessageBody, MessageKind,
};
use habilis_network_util::clock::Instant;
use habilis_network_util::tuning::{
    DIGEST_PULL_TTL, DIGEST_SERVE_WINDOW, DIGEST_SERVES_PER_WINDOW, DIGEST_SETTLE,
    DIGEST_SETTLE_JITTER,
};
use iroh::EndpointId;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::transport;

/// A holder's digest that differs from ours, while its settle delay runs.
#[derive(Debug, Clone, Copy)]
struct Difference {
    endpoint: EndpointId,
    root: ContentHash,
    total: usize,
    due: Instant,
}

/// A holder's digest that this node reads on one channel: the page that is asked for next, when that page was
/// asked for, and when it may be asked for.
#[derive(Debug, Clone, Copy)]
struct Reading {
    holder: AuthorKey,
    endpoint: EndpointId,
    total: usize,
    index: usize,
    asked: Option<Instant>,
    next_at: Instant,
}

/// A page request that the round sends this tick.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Request {
    holder: AuthorKey,
    endpoint: EndpointId,
    channel: Channel,
    index: usize,
}

/// The digests that differ from ours, and the holder read on each channel.
#[derive(Debug, Default)]
pub(crate) struct DigestRound {
    differences: HashMap<(AuthorKey, Channel), Difference>,
    reading: HashMap<Channel, Reading>,
}

impl DigestRound {
    /// Notes the root of `holder` on `channel`, which came from `endpoint`. A root that agrees with ours cancels
    /// a difference that is noted. A root that differs is noted with its settle due time, and a later root of the
    /// same holder replaces the root that was noted.
    pub(crate) fn note_root(
        &mut self,
        holder: AuthorKey,
        endpoint: EndpointId,
        channel: Channel,
        root: &DigestRoot,
        matches: bool,
        due: Instant,
    ) {
        if matches {
            self.differences.remove(&(holder, channel));
            return;
        }
        self.differences
            .entry((holder, channel))
            .and_modify(|difference| {
                difference.endpoint = endpoint;
                difference.root = root.root();
                difference.total = root.total();
            })
            .or_insert(Difference {
                endpoint,
                root: root.root(),
                total: root.total(),
                due,
            });
    }

    /// Advances the round to `now`. A holder that left the roster is dropped, and so is a reading whose page
    /// request got no answer within [`DIGEST_PULL_TTL`]: a new difference of that holder is then noted again. A
    /// difference whose settle delay has ended is compared again: if it agrees, it is cancelled; if it still
    /// differs, and no holder is read on its channel, it is read. Returns the page requests that are due.
    pub(crate) fn advance(
        &mut self,
        now: Instant,
        in_roster: impl Fn(&AuthorKey) -> bool,
        matches: impl Fn(Channel, &ContentHash) -> bool,
    ) -> Vec<Request> {
        self.reading.retain(|_, reading| {
            let answered_late = reading
                .asked
                .is_some_and(|asked| now.duration_since(asked) >= DIGEST_PULL_TTL);
            in_roster(&reading.holder) && !answered_late
        });
        self.differences.retain(|(holder, _), _| in_roster(holder));
        let due: Vec<(AuthorKey, Channel)> = self
            .differences
            .iter()
            .filter(|(_, difference)| difference.due <= now)
            .map(|(&key, _)| key)
            .collect();
        for (holder, channel) in due {
            let Some(difference) = self.differences.get(&(holder, channel)).copied() else {
                continue;
            };
            if matches(channel, &difference.root) {
                self.differences.remove(&(holder, channel));
                continue;
            }
            if self.reading.contains_key(&channel) {
                continue;
            }
            self.differences.remove(&(holder, channel));
            self.reading.insert(
                channel,
                Reading {
                    holder,
                    endpoint: difference.endpoint,
                    total: difference.total,
                    index: 0,
                    asked: None,
                    next_at: now,
                },
            );
        }
        let mut requests = Vec::new();
        for (&channel, reading) in &mut self.reading {
            if reading.asked.is_none() && reading.next_at <= now {
                reading.asked = Some(now);
                requests.push(Request {
                    holder: reading.holder,
                    endpoint: reading.endpoint,
                    channel,
                    index: reading.index,
                });
            }
        }
        requests
    }

    /// Whether a page is one that this node asked for: the holder, the connection, the channel and the index
    /// match the request in flight, and the request is within its deadline.
    pub(crate) fn accepts(
        &self,
        holder: AuthorKey,
        endpoint: EndpointId,
        channel: Channel,
        index: usize,
        now: Instant,
    ) -> bool {
        self.reading.get(&channel).is_some_and(|reading| {
            reading.holder == holder
                && reading.endpoint == endpoint
                && reading.index == index
                && reading
                    .asked
                    .is_some_and(|asked| now.duration_since(asked) < DIGEST_PULL_TTL)
        })
    }

    /// Notes that the page of `channel` that was asked for has been read. The next page may be asked for after
    /// [`DIGEST_SERVE_WINDOW`], so the holder's serve budget refills between pages. After the last page the
    /// reading ends.
    pub(crate) fn page_read(&mut self, channel: Channel, now: Instant) {
        let Some(reading) = self.reading.get_mut(&channel) else {
            return;
        };
        let next = reading.index + 1;
        if next >= reading.total {
            self.reading.remove(&channel);
            return;
        }
        reading.index = next;
        reading.asked = None;
        reading.next_at = now + DIGEST_SERVE_WINDOW;
    }

    /// The number of channels that a holder is read on, for the tests.
    #[cfg(test)]
    pub(crate) fn reading_count(&self) -> usize {
        self.reading.len()
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

/// The backfill tick: this node sends its two digests to each linked neighbour. Each digest is computed once.
pub(crate) async fn send_roots(state: &EventLoopState, context: &HandlerCtx<'_>) {
    let own_state = state.docs.digest(Channel::State);
    let own_meta = state.docs.digest(Channel::Meta);
    for (key, eid) in neighbours(state) {
        let root = MessageKind::SliceRoot {
            to: key,
            state: own_state.clone(),
            meta: own_meta.clone(),
        };
        send_kind(state, context, eid, root).await;
    }
}

/// The round tick: each difference whose settle has ended is compared again, and each page request that is due is
/// sent on the holder's connection.
pub(crate) async fn advance(state: &mut EventLoopState, context: &HandlerCtx<'_>, now: Instant) {
    let mut round = mem::take(&mut state.digest_round);
    let requests = round.advance(
        now,
        |key| state.in_roster(key),
        |channel, root| state.docs.matches(channel, root),
    );
    state.digest_round = round;
    for request in requests {
        let page = MessageKind::SlicePageRequest {
            to: request.holder,
            channel: request.channel,
            index: request.index,
        };
        send_kind(state, context, request.endpoint, page).await;
    }
}

/// A holder's roots arrived by unicast from `endpoint`. Each channel whose root differs from ours is noted for the
/// round. A root of a key that is not in the roster is not noted.
pub(crate) fn on_root(
    state: &mut EventLoopState,
    holder: AuthorKey,
    endpoint: EndpointId,
    roots: [(Channel, &DigestRoot); 2],
    now: Instant,
    jitter: Duration,
) {
    if !state.in_roster(&holder) {
        return;
    }
    let due = now + DIGEST_SETTLE + jitter;
    for (channel, root) in roots {
        let matches = state.docs.matches(channel, &root.root());
        state
            .digest_round
            .note_root(holder, endpoint, channel, root, matches, due);
    }
}

/// A page of a holder's digest arrived by unicast from `endpoint`. It is taken only when this node asked for it.
/// This node then pulls the keys of the page that it wants, in pulls of the store's row count. The next page is
/// asked for by the round tick, after the serve window.
pub(crate) async fn on_page(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    holder: AuthorKey,
    endpoint: EndpointId,
    channel: Channel,
    page: &DigestPage,
    now: Instant,
) {
    if !state
        .digest_round
        .accepts(holder, endpoint, channel, page.index(), now)
    {
        return;
    }
    let rows = state.docs.pull_rows(channel);
    let cap = DIGEST_SERVES_PER_WINDOW * rows;
    for keys in DigestRound::pull_plan(state, channel, page, rows) {
        let mut accepted = Vec::new();
        for key in keys {
            if state
                .outstanding_pulls
                .register(endpoint, channel, key, now, cap)
            {
                accepted.push(key);
            }
        }
        if accepted.is_empty() {
            continue;
        }
        let pull = MessageKind::SlicePull {
            to: holder,
            channel,
            keys: accepted,
        };
        send_kind(state, context, endpoint, pull).await;
    }
    state.digest_round.page_read(channel, now);
}

#[cfg(test)]
mod tests {
    use super::DigestRound;
    use crate::testing;
    use habilis_network_protocol::digest::{DigestEntry, DigestPage, DigestRoot};
    use habilis_network_protocol::{AuthorKey, Channel, ContentHash};
    use habilis_network_util::clock::Instant;
    use habilis_network_util::tuning::{DIGEST_PULL_TTL, DIGEST_SERVE_WINDOW, DIGEST_SETTLE};

    fn entry(seed: u8) -> DigestEntry {
        DigestEntry::new(AuthorKey::from([seed; 32]), 1, ContentHash::of(&[seed]))
    }

    fn root(text: &[u8], total: usize) -> DigestRoot {
        DigestRoot::new(ContentHash::of(text), total).expect("a root of at least one page")
    }

    fn holder(seed: u8) -> AuthorKey {
        AuthorKey::from([seed; 32])
    }

    /// Notes a differing root of `holder` on `channel`, due after the settle delay from `now`.
    fn note(
        round: &mut DigestRound,
        holder: AuthorKey,
        seed: u8,
        channel: Channel,
        now: Instant,
        total: usize,
    ) {
        let endpoint = testing::endpoint_id(seed);
        let digest = root(&[seed], total);
        round.note_root(
            holder,
            endpoint,
            channel,
            &digest,
            false,
            now + DIGEST_SETTLE,
        );
    }

    /// A differing root is read only after the settle delay.
    #[test]
    fn a_mismatch_waits_the_settle_before_it_asks() {
        let now = Instant::now();
        let mut round = DigestRound::default();
        note(&mut round, holder(1), 81, Channel::State, now, 1);
        let early = round.advance(now, |_| true, |_, _| false);
        assert!(
            early.is_empty(),
            "a difference is not asked for before the settle delay ends"
        );
        let due = round.advance(now + DIGEST_SETTLE, |_| true, |_, _| false);
        assert_eq!(
            due.len(),
            1,
            "the first page is asked for once the settle delay has ended"
        );
    }

    /// A root that agrees with ours during the settle cancels the difference: no page is asked for.
    #[test]
    fn a_root_that_agrees_during_the_settle_cancels_the_request() {
        let now = Instant::now();
        let mut round = DigestRound::default();
        note(&mut round, holder(1), 81, Channel::State, now, 1);
        round.note_root(
            holder(1),
            testing::endpoint_id(81),
            Channel::State,
            &root(&[81], 1),
            true,
            now,
        );
        let due = round.advance(now + DIGEST_SETTLE, |_| true, |_, _| false);
        assert!(due.is_empty(), "an agreeing root cancels the difference");
    }

    /// A page request that gets no answer does not block the holder: its deadline ends the reading, and a new
    /// difference of the holder is read again.
    #[test]
    fn an_unanswered_request_does_not_block_the_next_difference() {
        let now = Instant::now();
        let mut round = DigestRound::default();
        note(&mut round, holder(1), 81, Channel::State, now, 1);
        let asked = round.advance(now + DIGEST_SETTLE, |_| true, |_, _| false);
        assert_eq!(asked.len(), 1, "the first page is asked for");
        let late = now + DIGEST_SETTLE + DIGEST_PULL_TTL;
        round.advance(late, |_| true, |_, _| false);
        assert_eq!(
            round.reading_count(),
            0,
            "a request past its deadline ends the reading"
        );
        note(&mut round, holder(1), 82, Channel::State, late, 1);
        let retry = round.advance(late + DIGEST_SETTLE, |_| true, |_, _| false);
        assert_eq!(retry.len(), 1, "a new difference is read again");
    }

    /// One holder is read on a channel at a time: the other holders wait for it.
    #[test]
    fn one_holder_per_channel_at_a_time() {
        let now = Instant::now();
        let mut round = DigestRound::default();
        for seed in [1, 2, 3] {
            note(&mut round, holder(seed), 80 + seed, Channel::State, now, 1);
        }
        let asked = round.advance(now + DIGEST_SETTLE, |_| true, |_, _| false);
        assert_eq!(
            asked.len(),
            1,
            "one holder is read on the channel at a time"
        );
    }

    /// A page is taken only when it was asked for, from the same connection, for the same index.
    #[test]
    fn a_page_is_taken_only_when_it_was_asked_for() {
        let now = Instant::now();
        let mut round = DigestRound::default();
        note(&mut round, holder(1), 81, Channel::State, now, 3);
        assert!(
            !round.accepts(holder(1), testing::endpoint_id(81), Channel::State, 0, now),
            "nothing was asked for yet"
        );
        let asked_at = now + DIGEST_SETTLE;
        round.advance(asked_at, |_| true, |_, _| false);
        assert!(
            round.accepts(
                holder(1),
                testing::endpoint_id(81),
                Channel::State,
                0,
                asked_at
            ),
            "the page that was asked for is accepted"
        );
        assert!(
            !round.accepts(
                holder(1),
                testing::endpoint_id(82),
                Channel::State,
                0,
                asked_at
            ),
            "another connection"
        );
        assert!(
            !round.accepts(
                holder(1),
                testing::endpoint_id(81),
                Channel::State,
                1,
                asked_at
            ),
            "another index"
        );
    }

    /// After a page, the next one waits one serve window, so the holder's serve budget refills between pages.
    #[test]
    fn the_next_page_is_paced_to_the_serve_window() {
        let now = Instant::now();
        let mut round = DigestRound::default();
        note(&mut round, holder(1), 81, Channel::State, now, 6);
        round.advance(now + DIGEST_SETTLE, |_| true, |_, _| false);
        round.page_read(Channel::State, now + DIGEST_SETTLE);
        let soon = round.advance(
            now + DIGEST_SETTLE + DIGEST_SERVE_WINDOW / 2,
            |_| true,
            |_, _| false,
        );
        assert!(soon.is_empty(), "the next page waits");
        let due = round.advance(
            now + DIGEST_SETTLE + DIGEST_SERVE_WINDOW,
            |_| true,
            |_, _| false,
        );
        assert_eq!(due.len(), 1, "the next page is asked after the window");
        assert_eq!(due[0].index, 1, "and it is page 1");
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
