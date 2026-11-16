//! A pool: one subscriber's view of the relays. It holds the healthiest
//! `width` relays in rank order, publishes to them, and merges what they
//! deliver into one deduplicated stream.
//!
//! Every member of a mesh ranks the same list the same way, so pools of
//! different widths still overlap: a member at width 1 listens on the first
//! healthy relay, which a joiner at width 3 also holds.
//!
//! "Healthy" includes "forwards": a relay can accept every event and deliver
//! none. Our own event coming back on a tag we subscribe to is the proof, so
//! a relay that owes us an echo for too long stops counting toward the width.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use n0_future::time::Instant;
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::data_queue::Outgoing;
use crate::event::{Event, Keys, kind_for};
use crate::hub::{Hub, Lease};
use crate::lane::Lane;
use crate::wire::{self, Filter};

use crate::hub::Health;
use n0_future::{task, time};
use std::{future, mem};
/// Choosing again on a timer is what notices an echo that is overdue.
const RECHOOSE_EVERY: Duration = Duration::from_secs(5);
/// A relay that has not echoed our event this long after we sent it is taken
/// to swallow events. Public relays echo in about a second. It must stay above
/// the connect timeout (10 s in `hub`), or a relay still dialing when we
/// first publish could be flagged before it had a chance to echo.
const ECHO_DEADLINE: Duration = if cfg!(test) {
    Duration::from_secs(1)
} else {
    Duration::from_secs(10)
};
/// A relay swallowing this much longer gets its socket dropped and dialed
/// again: a half-open TCP connection (a NAT rebinding, a sleeping laptop)
/// otherwise stays "up" until the kernel's retransmission timeout, around
/// 15 minutes.
const SWALLOW_RECONNECT: Duration = if cfg!(test) {
    Duration::from_secs(1)
} else {
    Duration::from_mins(1)
};
const SEEN_CAPACITY: usize = 4096;
/// How many ids of the events this pool sent it remembers, to tell an echo of
/// its own event from a forged event that carries its public key. At the
/// announce cadence this reaches back well past the echo deadline.
const SENT_CAPACITY: usize = 256;

enum Command {
    Width(usize),
    Publish {
        tag: [u8; 32],
        id: String,
        frame: String,
    },
    Datagram(Outgoing),
}

/// A subscription to a set of tags on a ranked relay list.
#[derive(Debug)]
pub struct Pool {
    lane: Lane,
    // Shared with every datagram the pool queues on a socket task: one key signs them all.
    keys: Arc<Keys>,
    commands: mpsc::UnboundedSender<Command>,
    connected: watch::Receiver<Vec<Url>>,
    sendable: watch::Receiver<bool>,
    _task: task::AbortOnDropHandle<()>,
}

impl Pool {
    /// Subscribe to `tags` on `lane`, on the first `width` healthy relays of `ranking`.
    /// Events arrive on the returned receiver, each once, whichever relays
    /// carried it. The pool shares its sockets with the other pools of the lane,
    /// not with those of the other lane.
    #[must_use]
    pub fn open(
        lane: Lane,
        ranking: Vec<Url>,
        width: usize,
        tags: &[[u8; 32]],
    ) -> (Self, mpsc::UnboundedReceiver<Event>) {
        let distinct_kinds: HashSet<u32> = tags.iter().map(|tag| kind_for(lane, tag)).collect();
        let hex_tags: Vec<String> = tags.iter().map(hex::encode).collect();
        let filter = Filter {
            kinds: distinct_kinds.into_iter().collect(),
            tags: hex_tags,
        };
        let subscription_bytes: [u8; 16] = rand::random();
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (connected_tx, connected) = watch::channel(Vec::new());
        let (sendable_tx, sendable) = watch::channel(false);
        if ranking.is_empty() {
            tracing::warn!(target: "habilis_network::lookup", "a pool with no relays reaches no one");
        }
        let chooser = Chooser {
            hub: Hub::of(lane),
            ranking,
            width,
            sub_id: hex::encode(subscription_bytes),
            filter,
            subscribed: tags.iter().copied().collect(),
            leases: Vec::new(),
            owed_echo: HashMap::new(),
            redialed: HashMap::new(),
            sent: SentIds::default(),
        };
        // The pool signs with this key, and so does every datagram it queues on a socket.
        let keys = Arc::new(Keys::generate());
        let own = keys.pubkey().to_owned();
        let task = task::spawn(run(
            chooser,
            own,
            command_rx,
            out_tx,
            Watches {
                connected: connected_tx,
                sendable: sendable_tx,
            },
        ));
        let pool = Self {
            lane,
            keys,
            commands,
            connected,
            sendable,
            _task: task::AbortOnDropHandle::new(task),
        };
        (pool, out_rx)
    }

    /// Sign `content` under `tag` and send it to every usable relay held.
    pub fn publish(&self, tag: &[u8; 32], content: String) {
        let event = Event::sign(self.lane, &self.keys, crate::unix_now(), tag, content);
        let _ = self.commands.send(Command::Publish {
            tag: *tag,
            id: event.id.clone(),
            frame: wire::event(&event),
        });
    }

    /// Queue `datagram` for the destination whose tag is `tag`, on the first relay that takes it.
    /// `from` is written in the header of the batch, for the receiver. Nothing blocks: a datagram
    /// the socket cannot take is dropped. Meant for a pool of [`Lane::Data`].
    pub fn send_datagram(&self, tag: &[u8; 32], from: &[u8; 32], datagram: Vec<u8>) {
        let _ = self.commands.send(Command::Datagram(Outgoing {
            keys: Arc::clone(&self.keys),
            tag: *tag,
            from: *from,
            bytes: datagram,
        }));
    }

    /// The key this pool signs with. Events from it never reach its own
    /// receiver.
    #[must_use]
    pub fn pubkey(&self) -> &str {
        self.keys.pubkey()
    }

    /// How many healthy relays to hold. The pool opens or closes sockets to
    /// match, keeping the best-ranked ones.
    pub fn set_width(&self, width: usize) {
        let _ = self.commands.send(Command::Width(width));
    }

    /// The relays currently held and connected, in rank order.
    pub fn connected(&self) -> impl Iterator<Item = Url> + use<> {
        let snapshot: Vec<Url> = self.connected.borrow().clone();
        snapshot.into_iter()
    }

    /// Whether a datagram sent now has a relay that takes it: one is `Up`, or one is limited
    /// and its wait is over, so the datagram is its probe. A read of a flag, not of the list.
    #[must_use]
    pub fn sendable(&self) -> bool {
        *self.sendable.borrow()
    }

    /// Wait until the connected set changes.
    pub async fn changed(&mut self) {
        let _ = self.connected.changed().await;
    }
}

struct Chooser {
    hub: &'static Hub,
    ranking: Vec<Url>,
    width: usize,
    sub_id: String,
    filter: Filter,
    subscribed: HashSet<[u8; 32]>,
    leases: Vec<(Url, Lease)>,
    /// When each relay was first sent an event it has not yet echoed.
    owed_echo: HashMap<Url, Instant>,
    /// When each relay was last dialed again for swallowing. It times the next
    /// redial and says nothing about forwarding: only an echo clears `owed_echo`.
    redialed: HashMap<Url, Instant>,
    /// The ids of the events this pool sent lately.
    sent: SentIds,
}

/// The ids of the last [`SENT_CAPACITY`] events a pool sent. An echo is an
/// event whose id is here: the public key alone proves nothing, because the
/// receiver checks only the id of an event, so anyone can forge one that
/// carries our key.
#[derive(Debug, Default)]
struct SentIds {
    order: VecDeque<String>,
    ids: HashSet<String>,
}

impl SentIds {
    fn insert(&mut self, id: String) {
        if self.ids.insert(id.clone()) {
            self.order.push_back(id);
            if self.order.len() > SENT_CAPACITY
                && let Some(oldest) = self.order.pop_front()
            {
                self.ids.remove(&oldest);
            }
        }
    }

    /// What `event` is to the pool whose key is `own`.
    fn receipt(&self, own: &str, event: &Event) -> Receipt {
        if self.ids.contains(&event.id) {
            Receipt::Echo
        } else if event.pubkey == own {
            Receipt::Forged
        } else {
            Receipt::Foreign
        }
    }
}

/// What a received event is to a pool.
#[derive(Debug, PartialEq, Eq)]
enum Receipt {
    /// An event this pool sent, come back: the proof its relay forwards.
    Echo,
    /// An event that carries this pool's key but that it did not send.
    Forged,
    /// Another member's event.
    Foreign,
}

impl Chooser {
    /// Walk the ranking and hold relays until `width` of them are usable.
    /// Unusable relays met on the way stay held, so they keep reconnecting
    /// and win their rank back when they recover. Retired relays are skipped,
    /// and a lease whose connection died is replaced.
    fn choose(&mut self, events: &mpsc::UnboundedSender<(Url, Event)>) {
        let mut old = mem::take(&mut self.leases);
        let mut usable = 0;
        for url in &self.ranking {
            if usable >= self.width {
                break;
            }
            let slot = old
                .iter()
                .position(|(held, lease)| held == url && !lease.is_dead());
            let held = slot.map(|index| old.swap_remove(index).1);
            let Some(lease) = held.or_else(|| {
                self.hub.lease(
                    url,
                    self.sub_id.clone(),
                    self.filter.clone(),
                    events.clone(),
                )
            }) else {
                continue;
            };
            if lease.health().usable() && !self.swallows(url) {
                usable += 1;
            }
            self.leases.push((url.clone(), lease));
        }
        // `old` now holds the relays we no longer want; dropping it releases them.
        for (url, lease) in &self.leases {
            let Some(&since) = self.owed_echo.get(url) else {
                continue;
            };
            let last = self.redialed.get(url).copied().unwrap_or(since);
            if last.elapsed() >= ECHO_DEADLINE + SWALLOW_RECONNECT {
                lease.reconnect();
                // Timed from here, so a relay that goes on swallowing is dialed
                // again once a round, not on every choose.
                self.redialed.insert(url.clone(), Instant::now());
            }
        }
        let held = |url: &Url| self.leases.iter().any(|(held, _)| held == url);
        self.owed_echo.retain(|url, _| held(url));
        self.redialed.retain(|url, _| held(url));
    }

    fn swallows(&self, url: &Url) -> bool {
        self.owed_echo
            .get(url)
            .is_some_and(|since| since.elapsed() >= ECHO_DEADLINE)
    }

    /// Send to every held relay whose socket takes it. A relay that swallows
    /// gets it too: its echo is how it earns its place back.
    fn publish(&mut self, tag: &[u8; 32], frame: &str) {
        let expect_echo = self.subscribed.contains(tag);
        let now = Instant::now();
        for (url, lease) in &self.leases {
            if lease.health().sendable(self.hub.lane()) {
                lease.publish(frame.to_owned());
                if expect_echo {
                    self.owed_echo.entry(url.clone()).or_insert(now);
                }
            }
        }
    }

    /// Our own event came back through `url`. `true` if that relay had been
    /// passed over and should be counted again.
    fn echoed(&mut self, url: &Url) -> bool {
        let was_swallowing = self.swallows(url);
        self.owed_echo.remove(url);
        self.redialed.remove(url);
        was_swallowing
    }

    /// Hand a datagram to the first held relay whose socket takes it, in rank order. A data pool
    /// listens on every relay of its list, so the receiver hears the datagram on whichever relay
    /// the sender's view of health picks; a relay that is down or limited is passed over.
    fn datagram(&self, outgoing: Outgoing) {
        let lane = self.hub.lane();
        if let Some((_, lease)) = self
            .leases
            .iter()
            .find(|(_, lease)| lease.health().sendable(lane))
        {
            lease.datagram(outgoing);
        }
    }

    /// Some held relay takes a datagram now: it is `Up`, or limited with its wait over.
    fn sendable(&self) -> bool {
        let lane = self.hub.lane();
        self.leases
            .iter()
            .any(|(url, lease)| lease.health().sendable(lane) && !self.swallows(url))
    }

    /// When the first wait of a limited relay ends, so the pool tells its owner then.
    fn next_limit_end(&self) -> Option<Instant> {
        let now = Instant::now();
        self.leases
            .iter()
            .filter_map(|(_, lease)| {
                if let Health::Limited(until) = lease.health()
                    && until > now
                {
                    Some(until)
                } else {
                    None
                }
            })
            .min()
    }

    fn connected(&self) -> Vec<Url> {
        let mut urls = Vec::new();
        for (url, lease) in &self.leases {
            if lease.health() == Health::Up && !self.swallows(url) {
                urls.push(url.clone());
            }
        }
        urls
    }
}

/// What a pool tells its owner about its relays.
struct Watches {
    connected: watch::Sender<Vec<Url>>,
    sendable: watch::Sender<bool>,
}

async fn run(
    mut chooser: Chooser,
    own: String,
    mut commands: mpsc::UnboundedReceiver<Command>,
    out: mpsc::UnboundedSender<Event>,
    watches: Watches,
) {
    let (events_tx, mut events) = mpsc::unbounded_channel();
    let mut changes = chooser.hub.changes();
    let mut seen = Seen::default();
    let mut rechoose = time::interval(RECHOOSE_EVERY);
    chooser.choose(&events_tx);
    loop {
        let limit_end = chooser.next_limit_end();
        let wait_limit = async move {
            match limit_end {
                Some(at) => time::sleep_until(at).await,
                None => future::pending().await,
            }
        };
        tokio::select! {
            () = wait_limit => {}
            command = commands.recv() => match command {
                None => return,
                Some(Command::Width(width)) => {
                    chooser.width = width;
                    chooser.choose(&events_tx);
                }
                Some(Command::Publish { tag, id, frame }) => {
                    chooser.sent.insert(id);
                    chooser.publish(&tag, &frame);
                }
                Some(Command::Datagram(outgoing)) => chooser.datagram(outgoing),
            },
            delivery = events.recv() => {
                let Some((relay, event)) = delivery else { return };
                // Only the id is checked, and before anything else: a relay can
                // forward a copy with the content changed and the id kept, and
                // marking that id seen would drop the good copies other relays
                // carry. The Schnorr signature is not checked on receipt: the
                // Nostr key is random and proves nothing, and the content
                // authenticates itself (the seal, and the endpoint signature
                // inside it). Signing stays on send, since relays require it.
                if let Err(error) = event.verify_id() {
                    tracing::debug!(target: "habilis_network::lookup", %relay, %error, "dropped an invalid event");
                    continue;
                }
                // Our own events come back on the tags we publish to; each is
                // proof that relay forwards. It is recognized by its id, one we
                // sent: the public key alone proves nothing, since only the id
                // is checked and anyone can put our key on an event.
                match chooser.sent.receipt(&own, &event) {
                    Receipt::Echo => {
                        if chooser.echoed(&relay) {
                            chooser.choose(&events_tx);
                        }
                    }
                    Receipt::Forged => {
                        tracing::debug!(target: "habilis_network::lookup", %relay, "dropped an event that carries our key but that we did not send");
                    }
                    Receipt::Foreign => {
                        if seen.insert(&event.id) && out.send(event).is_err() {
                            return;
                        }
                    }
                }
            }
            health = changes.changed() => {
                if health.is_err() {
                    return;
                }
                chooser.choose(&events_tx);
            }
            _ = rechoose.tick() => chooser.choose(&events_tx),
        }
        watches.connected.send_if_modified(|current| {
            let now = chooser.connected();
            if *current == now {
                false
            } else {
                *current = now;
                true
            }
        });
        watches.sendable.send_replace(chooser.sendable());
    }
}

/// The ids delivered recently, so an event carried by two relays reaches the
/// subscriber once.
#[derive(Default)]
struct Seen {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl Seen {
    fn insert(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }
        if self.order.len() == SEEN_CAPACITY
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        self.order.push_back(id.to_owned());
        self.set.insert(id.to_owned());
        true
    }
}

#[cfg(all(test, feature = "test-relay"))]
mod tests {
    use std::time::Duration;

    use tokio::time;
    use url::Url;

    use std::collections::{HashMap, HashSet};

    use n0_future::time::Instant;
    use tokio::sync::mpsc;

    use super::{
        Chooser, ECHO_DEADLINE, Event, Filter, Hub, Keys, Lane, Pool, Receipt, SENT_CAPACITY,
        SWALLOW_RECONNECT, SentIds,
    };
    use crate::test_relay::TestRelay;

    const TAG: [u8; 32] = [3u8; 32];

    /// The relays the pool holds now, in rank order.
    fn connected_set(pool: &Pool) -> Vec<Url> {
        let held: Vec<Url> = pool.connected().collect();
        held
    }

    async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
        for _ in 0..300 {
            if check() {
                return;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
        assert!(check(), "timed out waiting for: {what}");
    }

    /// Only the id of an event is checked on receipt, so anyone can forge an
    /// event that carries our public key. It must not count as the echo that
    /// proves a relay forwards: only an event whose id we sent does.
    #[test]
    fn only_an_event_we_sent_is_an_echo() {
        let ours = Keys::generate();
        let theirs = Keys::generate();
        let own = ours.pubkey();
        let mut sent = SentIds::default();

        let ours_sent = Event::sign(
            Lane::Signal,
            &ours,
            crate::unix_now(),
            &TAG,
            "ours".to_owned(),
        );
        sent.insert(ours_sent.id.clone());
        assert_eq!(
            sent.receipt(own, &ours_sent),
            Receipt::Echo,
            "an event we sent comes back as an echo"
        );

        let forged = Event::forged_as(own, crate::unix_now(), &TAG, "forged".to_owned());
        forged
            .verify_id()
            .expect("the id of a forged event is valid");
        assert_eq!(
            sent.receipt(own, &forged),
            Receipt::Forged,
            "a valid id with our key, that we did not send, is not an echo"
        );

        let foreign = Event::sign(
            Lane::Signal,
            &theirs,
            crate::unix_now(),
            &TAG,
            "theirs".to_owned(),
        );
        assert_eq!(
            sent.receipt(own, &foreign),
            Receipt::Foreign,
            "an event of another key is not ours"
        );
    }

    #[test]
    fn the_sent_ids_are_bounded() {
        let mut sent = SentIds::default();
        for index in 0..=SENT_CAPACITY {
            sent.insert(format!("id{index}"));
        }
        assert_eq!(sent.ids.len(), SENT_CAPACITY, "the set stops growing");
        assert!(
            !sent.ids.contains("id0"),
            "the oldest id is forgotten first"
        );
        assert!(
            sent.ids.contains(&format!("id{SENT_CAPACITY}")),
            "the newest id is kept"
        );
    }

    /// A rate-limited relay is out of the count, but past its wait it gets our
    /// publishes as probes, and the one it accepts brings it back, on the same
    /// socket. (The unit-test build shortens the first wait to a second.)
    #[tokio::test]
    async fn a_rate_limited_relay_comes_back_without_a_new_socket() {
        let first = TestRelay::spawn().await.expect("spawn test relay");
        let second = TestRelay::spawn().await.expect("spawn test relay");
        first.refuse_events(Some("rate-limited: slow down"));
        let (pool, _rx) = Pool::open(Lane::Signal, vec![first.url(), second.url()], 1, &[TAG]);
        eventually("connected to the first", || {
            connected_set(&pool) == vec![first.url()]
        })
        .await;

        pool.publish(&TAG, "limited".to_owned());
        eventually("refilled to the second", || {
            connected_set(&pool) == vec![second.url()]
        })
        .await;

        first.refuse_events(None);
        let dials = first.accepted();
        for _ in 0..40 {
            pool.publish(&TAG, "probe".to_owned());
            if connected_set(&pool) == vec![first.url()] {
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(
            connected_set(&pool),
            vec![first.url()],
            "the first relay is back"
        );
        assert_eq!(first.accepted(), dials, "on the same socket");
    }

    /// Dialing a swallowing relay again says nothing about whether it forwards:
    /// only an echo does. The redial must not start the relay's count over.
    #[tokio::test]
    async fn a_redial_does_not_forgive_a_relay_that_swallows() {
        let relay = TestRelay::spawn().await.expect("spawn test relay");
        let url = relay.url();
        let (events, _events_rx) = mpsc::unbounded_channel();
        let mut chooser = Chooser {
            hub: Hub::global(),
            ranking: vec![url.clone()],
            width: 1,
            sub_id: "redial".to_owned(),
            filter: Filter {
                kinds: vec![20_001],
                tags: vec!["ab".to_owned()],
            },
            subscribed: HashSet::new(),
            leases: Vec::new(),
            owed_echo: HashMap::new(),
            redialed: HashMap::new(),
            sent: SentIds::default(),
        };
        chooser.choose(&events);
        let overdue = ECHO_DEADLINE + SWALLOW_RECONNECT;
        let since = Instant::now()
            .checked_sub(overdue)
            .expect("a clock that has run for two seconds");
        chooser.owed_echo.insert(url.clone(), since);
        assert!(chooser.swallows(&url), "the relay owes an overdue echo");

        chooser.choose(&events);
        assert!(
            chooser.swallows(&url),
            "the redial it was sent is not an echo, so it still swallows"
        );
    }

    /// A socket that stays up while nothing comes back (a half-open TCP
    /// connection after a NAT rebinding looks exactly like this) is dropped
    /// and dialed again, rather than left for the kernel's retransmission
    /// timeout. (The unit-test build shortens both deadlines.)
    #[tokio::test]
    async fn a_relay_that_keeps_swallowing_is_dialed_again() {
        let relay = TestRelay::spawn().await.expect("spawn test relay");
        relay.swallow_events(true);
        let (pool, _rx) = Pool::open(Lane::Signal, vec![relay.url()], 1, &[TAG]);
        eventually("connected", || connected_set(&pool) == vec![relay.url()]).await;
        let dials = relay.accepted();
        for _ in 0..60 {
            pool.publish(&TAG, "anyone there?".to_owned());
            if relay.accepted() > dials {
                return;
            }
            time::sleep(Duration::from_millis(200)).await;
        }
        panic!("the swallowing relay was never dialed again");
    }
}
