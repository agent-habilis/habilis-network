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
use std::time::Duration;

use n0_future::time::Instant;
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::conn::{Hub, Lease};
use crate::event::{Event, Keys, kind_for};
use crate::unix_now;
use crate::wire::{self, Filter};

use crate::conn::Health;
use n0_future::{task, time};
use std::mem;
/// Choosing again on a timer is what notices an echo that is overdue.
const RECHOOSE_EVERY: Duration = Duration::from_secs(5);
/// A relay that has not echoed our event this long after we sent it is taken
/// to swallow events. Public relays echo in about a second. It must stay above
/// the connect timeout (10 s in `conn`), or a relay still dialing when we
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
}

/// A subscription to a set of tags on a ranked relay list.
#[derive(Debug)]
pub struct Pool {
    keys: Keys,
    commands: mpsc::UnboundedSender<Command>,
    connected: watch::Receiver<Vec<Url>>,
    _task: task::AbortOnDropHandle<()>,
}

impl Pool {
    /// Subscribe to `tags` on the first `width` healthy relays of `ranking`.
    /// Events arrive on the returned receiver, each once, whichever relays
    /// carried it.
    #[must_use]
    pub fn open(
        ranking: Vec<Url>,
        width: usize,
        tags: &[[u8; 32]],
    ) -> (Self, mpsc::UnboundedReceiver<Event>) {
        let filter = Filter {
            kinds: tags
                .iter()
                .map(kind_for)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            tags: tags.iter().map(hex::encode).collect(),
        };
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (connected_tx, connected) = watch::channel(Vec::new());
        if ranking.is_empty() {
            tracing::warn!(target: "habilis_network::lookup", "a pool with no relays reaches no one");
        }
        let chooser = Chooser {
            hub: Hub::global(),
            ranking,
            width,
            sub_id: hex::encode(rand::random::<[u8; 16]>()),
            filter,
            subscribed: tags.iter().copied().collect(),
            leases: Vec::new(),
            owed_echo: HashMap::new(),
            sent: SentIds::default(),
        };
        let keys = Keys::generate();
        let own = keys.pubkey().to_owned();
        let task = task::spawn(run(chooser, own, command_rx, out_tx, connected_tx));
        let pool = Self {
            keys,
            commands,
            connected,
            _task: task::AbortOnDropHandle::new(task),
        };
        (pool, out_rx)
    }

    /// Sign `content` under `tag` and send it to every usable relay held.
    pub fn publish(&self, tag: &[u8; 32], content: String) {
        let event = Event::sign(&self.keys, unix_now(), tag, content);
        let _ = self.commands.send(Command::Publish {
            tag: *tag,
            id: event.id.clone(),
            frame: wire::event(&event),
        });
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
    #[must_use]
    pub fn connected(&self) -> Vec<Url> {
        self.connected.borrow().clone()
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
            let held = old
                .iter()
                .position(|(held, lease)| held == url && !lease.is_dead())
                .map(|index| old.swap_remove(index).1);
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
            if self
                .owed_echo
                .get(url)
                .is_some_and(|since| since.elapsed() >= ECHO_DEADLINE + SWALLOW_RECONNECT)
            {
                lease.reconnect();
                // Re-armed, so a relay that goes on swallowing is dialed again
                // once a round, not on every choose.
                self.owed_echo.insert(url.clone(), Instant::now());
            }
        }
        self.owed_echo
            .retain(|url, _| self.leases.iter().any(|(held, _)| held == url));
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
            if lease.health().sendable() {
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
        was_swallowing
    }

    fn connected(&self) -> Vec<Url> {
        self.leases
            .iter()
            .filter(|(url, lease)| lease.health() == Health::Up && !self.swallows(url))
            .map(|(url, _)| url.clone())
            .collect()
    }
}

async fn run(
    mut chooser: Chooser,
    own: String,
    mut commands: mpsc::UnboundedReceiver<Command>,
    out: mpsc::UnboundedSender<Event>,
    connected: watch::Sender<Vec<Url>>,
) {
    let (events_tx, mut events) = mpsc::unbounded_channel();
    let mut changes = chooser.hub.changes();
    let mut seen = Seen::default();
    let mut rechoose = time::interval(RECHOOSE_EVERY);
    chooser.choose(&events_tx);
    loop {
        tokio::select! {
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
        connected.send_if_modified(|current| {
            let now = chooser.connected();
            if *current == now {
                false
            } else {
                *current = now;
                true
            }
        });
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
    use super::*;
    use crate::test_relay::TestRelay;

    use tokio::time;
    const TAG: [u8; 32] = [3u8; 32];

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

        let ours_sent = Event::sign(&ours, unix_now(), &TAG, "ours".to_owned());
        sent.insert(ours_sent.id.clone());
        assert_eq!(sent.receipt(own, &ours_sent), Receipt::Echo);

        let forged = Event::forged_as(own, unix_now(), &TAG, "forged".to_owned());
        forged
            .verify_id()
            .expect("the id of a forged event is valid");
        assert_eq!(
            sent.receipt(own, &forged),
            Receipt::Forged,
            "a valid id with our key, that we did not send, is not an echo"
        );

        let foreign = Event::sign(&theirs, unix_now(), &TAG, "theirs".to_owned());
        assert_eq!(sent.receipt(own, &foreign), Receipt::Foreign);
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
        assert!(sent.ids.contains(&format!("id{SENT_CAPACITY}")));
    }

    /// A rate-limited relay is out of the count, but past its wait it gets our
    /// publishes as probes, and the one it accepts brings it back, on the same
    /// socket. (The unit-test build shortens the first wait to a second.)
    #[tokio::test]
    async fn a_rate_limited_relay_comes_back_without_a_new_socket() {
        let first = TestRelay::spawn().await.expect("spawn test relay");
        let second = TestRelay::spawn().await.expect("spawn test relay");
        first.refuse_events(Some("rate-limited: slow down"));
        let (pool, _rx) = Pool::open(vec![first.url(), second.url()], 1, &[TAG]);
        eventually("connected to the first", || {
            pool.connected() == vec![first.url()]
        })
        .await;

        pool.publish(&TAG, "limited".to_owned());
        eventually("refilled to the second", || {
            pool.connected() == vec![second.url()]
        })
        .await;

        first.refuse_events(None);
        let dials = first.accepted();
        for _ in 0..40 {
            pool.publish(&TAG, "probe".to_owned());
            if pool.connected() == vec![first.url()] {
                break;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(
            pool.connected(),
            vec![first.url()],
            "the first relay is back"
        );
        assert_eq!(first.accepted(), dials, "on the same socket");
    }

    /// A socket that stays up while nothing comes back (a half-open TCP
    /// connection after a NAT rebinding looks exactly like this) is dropped
    /// and dialed again, rather than left for the kernel's retransmission
    /// timeout. (The unit-test build shortens both deadlines.)
    #[tokio::test]
    async fn a_relay_that_keeps_swallowing_is_dialed_again() {
        let relay = TestRelay::spawn().await.expect("spawn test relay");
        relay.swallow_events(true);
        let (pool, _rx) = Pool::open(vec![relay.url()], 1, &[TAG]);
        eventually("connected", || pool.connected() == vec![relay.url()]).await;
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
