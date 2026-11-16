//! One socket per relay URL per process, shared by every pool that wants that
//! relay. A connection lives as long as some pool holds a lease on it,
//! reconnects on its own, and keeps its subscriptions across reconnects.
//!
//! Sharing is total: a relay's refusal of one pool's event limits or retires
//! the socket for every pool on it. That is how the relay sees us anyway, since
//! its limits are per connection or per IP.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use n0_future::time::{Instant, sleep, timeout};
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::event::Event;
use crate::wire::{self, Filter, FromRelay, Verdict};
use crate::{unix_now, ws};

use n0_future::{task, time};
use std::{future, mem};
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Reconnects wait 1 s, doubling up to a minute. A socket must serve this long
/// before the next drop counts as a fresh start: a relay that accepts and
/// hangs up at once would otherwise be dialed every second until it bans us.
const RECONNECT: Backoff = Backoff::new(Duration::from_secs(1), Duration::from_mins(1));
const SERVE_TO_TRUST: Duration = Duration::from_secs(30);
/// Each reconnect delay is scaled by a random factor in this range, so clients
/// that lost one relay together do not all redial it at the same instants. The
/// factor never goes below 1: a relay is never dialed sooner than its backoff.
const RECONNECT_JITTER: Range<f64> = 1.0..1.5;
/// A relay that refuses us for good (`blocked`, `restricted`, `auth-required`,
/// `pow`) is left alone this long. Relay policy changes, so after it one retry
/// is allowed; if the relay refuses again the wait doubles, up to the cap.
const RETIRE_FIRST: Duration = Duration::from_hours(6);
const RETIRE_MAX: Duration = Duration::from_hours(7 * 24);
/// Trystero's numbers: a first rate limit waits a minute, and each repeat
/// doubles it up to 15 minutes. The wait resets only after this long with no
/// limit, so a relay that accepts one event a minute cannot keep it at 1 min.
const RATE_LIMIT: Backoff = Backoff::new(
    if cfg!(test) {
        Duration::from_secs(1)
    } else {
        Duration::from_mins(1)
    },
    Duration::from_mins(15),
);
const RATE_LIMIT_CALM: Duration = Duration::from_mins(5);
/// A REQ the relay closed for no stated reason is sent again after 5 s,
/// doubling up to 5 min.
const RESUBSCRIBE: Backoff = Backoff::new(Duration::from_secs(5), Duration::from_mins(5));

/// Where a relay stands, as pools see it when they choose relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Health {
    /// Dialing for the first time. Counted as usable, so a pool does not open
    /// spare relays while its first ones are still handshaking.
    Connecting,
    /// Connected, and every subscription known at connect time is on the wire.
    Up,
    /// The last connect failed or the socket dropped; a reconnect is pending.
    Down,
    /// Rate-limited until the instant, and unusable until the relay accepts an
    /// event again. After the instant the socket sends publishes as probes.
    Limited(Instant),
    /// Refused for good (`blocked`, `auth-required`, ...). Not dialed again
    /// for hours, then once more (see [`RETIRE_FIRST`]).
    Retired,
}

impl Health {
    /// Counts toward a pool's width.
    pub(crate) fn usable(self) -> bool {
        matches!(self, Self::Connecting | Self::Up)
    }

    /// May be sent a publish. A limited relay past its wait takes one as a
    /// probe: the `OK true` it earns is its only way back to `Up`.
    pub(crate) fn sendable(self) -> bool {
        match self {
            Self::Connecting | Self::Up => true,
            Self::Limited(until) => Instant::now() >= until,
            Self::Down | Self::Retired => false,
        }
    }
}

/// A doubling delay with a cap.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    first: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    const fn new(first: Duration, max: Duration) -> Self {
        Self {
            first,
            max,
            next: first,
        }
    }

    /// The delay to wait now; the one after it is twice as long, up to the cap.
    fn step(&mut self) -> Duration {
        let delay = self.next;
        self.next = (delay * 2).min(self.max);
        delay
    }

    /// [`step`](Self::step), scaled by a random factor in [`RECONNECT_JITTER`].
    fn step_jittered(&mut self) -> Duration {
        self.step().mul_f64(rand::random_range(RECONNECT_JITTER))
    }

    fn reset(&mut self) {
        self.next = self.first;
    }
}

/// The relays that refused us for good, and until when each is left alone.
#[derive(Debug)]
struct Retirements {
    relays: HashMap<String, Retirement>,
    first: Duration,
    max: Duration,
}

impl Default for Retirements {
    fn default() -> Self {
        Self::new(RETIRE_FIRST, RETIRE_MAX)
    }
}

#[derive(Debug, Clone, Copy)]
struct Retirement {
    until: Instant,
    wait: Duration,
}

impl Retirements {
    fn new(first: Duration, max: Duration) -> Self {
        Self {
            relays: HashMap::new(),
            first,
            max,
        }
    }

    /// Whether `url` is still left alone at `now`.
    fn blocks(&self, url: &str, now: Instant) -> bool {
        self.relays
            .get(url)
            .is_some_and(|retirement| now < retirement.until)
    }

    /// The relay refused us for good at `now`: leave it alone for the first
    /// wait, or twice the last one when it refused us again after a retry.
    fn retire(&mut self, url: &str, now: Instant) {
        let wait = self
            .relays
            .get(url)
            .map_or(self.first, |retirement| (retirement.wait * 2).min(self.max));
        self.relays.insert(
            url.to_owned(),
            Retirement {
                until: now + wait,
                wait,
            },
        );
    }

    /// The relay served us again (it accepted an event or finished a REQ), so
    /// its next refusal starts from the first wait. Reaching `Up` is not
    /// that: a relay that refuses every REQ is `Up` between the dial and the
    /// refusal.
    fn clear(&mut self, url: &str) {
        self.relays.remove(url);
    }
}

enum Command {
    Subscribe {
        sub_id: String,
        filter: Filter,
        events: mpsc::UnboundedSender<(Url, Event)>,
    },
    Unsubscribe {
        sub_id: String,
    },
    Publish(String),
    /// Drop the socket and dial again.
    Reconnect,
}

/// A pool's hold on a relay. Dropping the last lease closes the socket.
#[must_use]
#[derive(Debug)]
pub(crate) struct Lease {
    // Shared with the other leases of this relay, and with the table of connections.
    connection: Arc<Conn>,
    sub_id: String,
}

impl Lease {
    pub(crate) fn health(&self) -> Health {
        if self.is_dead() {
            return Health::Down;
        }
        *self.connection.health.borrow()
    }

    /// The connection task is gone, for instance because the runtime that
    /// spawned it shut down. A dead lease is replaced, never reused.
    pub(crate) fn is_dead(&self) -> bool {
        self.connection.commands.is_closed()
    }

    pub(crate) fn publish(&self, frame: String) {
        let _ = self.connection.commands.send(Command::Publish(frame));
    }

    /// Drop the socket and dial again. It is shared, so every pool on it
    /// reconnects: fine, since the socket is the suspect.
    pub(crate) fn reconnect(&self) {
        let _ = self.connection.commands.send(Command::Reconnect);
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.connection.commands.send(Command::Unsubscribe {
            sub_id: mem::take(&mut self.sub_id),
        });
    }
}

#[derive(Debug)]
struct Conn {
    commands: mpsc::UnboundedSender<Command>,
    health: watch::Receiver<Health>,
}

/// The process-wide table of relay connections.
#[derive(Debug, Default)]
pub(crate) struct Hub {
    conns: Mutex<HashMap<String, Weak<Conn>>>,
    retired: Mutex<Retirements>,
    /// Bumped on any relay's health change, so pools choose again.
    changed: OnceLock<watch::Sender<u64>>,
}

impl Hub {
    pub(crate) fn global() -> &'static Hub {
        static HUB: OnceLock<Hub> = OnceLock::new();
        HUB.get_or_init(Hub::default)
    }

    /// A hub whose first retirement wait and cap are these, so a test can see a
    /// whole retire, retry and refuse cycle in milliseconds.
    #[cfg(all(test, feature = "test-relay"))]
    fn with_retirement(first: Duration, max: Duration) -> Self {
        Self {
            retired: Mutex::new(Retirements::new(first, max)),
            ..Self::default()
        }
    }

    /// The relay served us: forgive it, so its next refusal starts over.
    fn forgive(&self, url: &Url) {
        self.retired
            .lock()
            .expect("hub mutex poisoned")
            .clear(url.as_str());
    }

    pub(crate) fn changes(&self) -> watch::Receiver<u64> {
        self.change_sender().subscribe()
    }

    fn change_sender(&self) -> &watch::Sender<u64> {
        self.changed.get_or_init(|| watch::channel(0).0)
    }

    fn bump(&self) {
        self.change_sender()
            .send_modify(|generation| *generation += 1);
    }

    /// Hold `url` for a subscription, dialing it if no live connection exists.
    /// `None` for a relay that is retired for now.
    pub(crate) fn lease(
        &'static self,
        url: &Url,
        sub_id: String,
        filter: Filter,
        events: mpsc::UnboundedSender<(Url, Event)>,
    ) -> Option<Lease> {
        if self
            .retired
            .lock()
            .expect("hub mutex poisoned")
            .blocks(url.as_str(), Instant::now())
        {
            return None;
        }
        let connection = {
            let mut conns = self.conns.lock().expect("hub mutex poisoned");
            let tracked = conns.get(url.as_str()).and_then(Weak::upgrade);
            let live = tracked.filter(|candidate| !candidate.commands.is_closed());
            if let Some(connection) = live {
                connection
            } else {
                let connection = self.spawn(url.clone());
                conns.insert(url.as_str().to_owned(), Arc::downgrade(&connection));
                connection
            }
        };
        let _ = connection.commands.send(Command::Subscribe {
            sub_id: sub_id.clone(),
            filter,
            events,
        });
        Some(Lease { connection, sub_id })
    }

    // Shared by every lease of the relay, and by the table that finds it again.
    fn spawn(&'static self, url: Url) -> Arc<Conn> {
        let (commands, receiver) = mpsc::unbounded_channel();
        let (health_tx, health) = watch::channel(Health::Connecting);
        task::spawn(run(self, url, receiver, health_tx));
        // Shared by every lease of the relay, and by the table that finds it again.
        Arc::new(Conn { commands, health })
    }

    fn set_health(&self, url: &Url, health_tx: &watch::Sender<Health>, health: Health) {
        if health == Health::Retired {
            self.retired
                .lock()
                .expect("hub mutex poisoned")
                .retire(url.as_str(), Instant::now());
        }
        health_tx.send_replace(health);
        self.bump();
    }
}

struct Subscription {
    filter: Filter,
    events: mpsc::UnboundedSender<(Url, Event)>,
}

/// The connection task's state across reconnects. It owns the command
/// receiver, so dropping the task, even by cancellation, closes the channel
/// and every lease sees the connection as dead.
struct Task {
    hub: &'static Hub,
    url: Url,
    commands: mpsc::UnboundedReceiver<Command>,
    health: watch::Sender<Health>,
    subs: HashMap<String, Subscription>,
    rate_limit: Backoff,
    last_limited: Option<Instant>,
    resubscribe: Backoff,
    resubscribe_at: Option<Instant>,
    closed_subs: HashSet<String>,
    /// The socket has shown the relay serves us (see [`Task::note_served`]).
    served: bool,
    /// When the stale-event warning last went out for this relay.
    stale_warned: Option<Instant>,
}

impl Drop for Task {
    fn drop(&mut self) {
        self.commands.close();
        // Pools holding this connection choose again, and find it dead.
        self.hub.bump();
    }
}

/// The connection task: dial, subscribe, pump frames, reconnect. It ends when
/// every lease is dropped (the command channel closes) or the relay retires us.
async fn run(
    hub: &'static Hub,
    url: Url,
    commands: mpsc::UnboundedReceiver<Command>,
    health: watch::Sender<Health>,
) {
    let mut task = Task {
        hub,
        url,
        commands,
        health,
        subs: HashMap::new(),
        rate_limit: RATE_LIMIT,
        last_limited: None,
        resubscribe: RESUBSCRIBE,
        resubscribe_at: None,
        closed_subs: HashSet::new(),
        served: false,
        stale_warned: None,
    };
    let mut reconnect = RECONNECT;
    loop {
        let started = Instant::now();
        let outcome = match timeout(CONNECT_TIMEOUT, ws::connect(&task.url)).await {
            Ok(Ok((sender, receiver))) => task.serve(sender, receiver).await,
            Ok(Err(error)) => {
                tracing::debug!(target: "habilis_network::lookup", url = %task.url, %error, "relay connect failed");
                Outcome::Dropped
            }
            Err(_) => {
                tracing::debug!(target: "habilis_network::lookup", url = %task.url, "relay connect timed out");
                Outcome::Dropped
            }
        };
        match outcome {
            Outcome::Idle => return,
            Outcome::Retired => {
                task.set_health(Health::Retired);
                return;
            }
            Outcome::Dropped => {
                if started.elapsed() >= SERVE_TO_TRUST {
                    reconnect.reset();
                }
                task.set_health(Health::Down);
                if !task.wait_absorbing(reconnect.step_jittered()).await {
                    return;
                }
            }
        }
    }
}

impl Task {
    fn set_health(&self, health: Health) {
        self.hub.set_health(&self.url, &self.health, health);
    }

    /// One socket's life: subscribe, then pump commands and frames until the
    /// socket dies, the relay retires us, or every lease is gone.
    async fn serve(&mut self, mut sender: ws::Sender, mut receiver: ws::Receiver) -> Outcome {
        self.resubscribe.reset();
        self.resubscribe_at = None;
        self.closed_subs.clear();
        self.served = false;
        if self.subscribe_all(&mut sender).await.is_err() {
            return Outcome::Dropped;
        }
        // Take what queued while we dialed, so `Up` means every pool known now
        // is subscribed. Publishes among them are sent: they are a node's
        // first announces, and they queued before the health said anything.
        while let Ok(command) = self.commands.try_recv() {
            if let Err(outcome) = self.on_command(command, &mut sender, true).await {
                return outcome;
            }
        }
        self.set_health(Health::Up);
        let outcome = loop {
            let resubscribe_at = self.resubscribe_at;
            let resubscribe = async move {
                match resubscribe_at {
                    Some(at) => time::sleep_until(at).await,
                    None => future::pending().await,
                }
            };
            let step = tokio::select! {
                command = self.commands.recv() => match command {
                    None => Err(Outcome::Idle),
                    Some(command) => self.on_command(command, &mut sender, false).await,
                },
                () = resubscribe => {
                    self.resubscribe_at = None;
                    self.subscribe_closed(&mut sender).await
                }
                frame = receiver.next() => match frame {
                    None => Err(Outcome::Dropped),
                    Some(frame) => self.on_frame(&frame),
                },
            };
            if let Err(outcome) = step {
                break outcome;
            }
        };
        if !matches!(outcome, Outcome::Dropped) {
            sender.close().await;
        }
        outcome
    }

    async fn subscribe_all(&self, sender: &mut ws::Sender) -> Result<(), ()> {
        for (sub_id, sub) in &self.subs {
            sender
                .send(wire::request(sub_id, &sub.filter, unix_now()))
                .await
                .map_err(|_| ())?;
        }
        Ok(())
    }

    /// Send again only the REQs the relay closed.
    async fn subscribe_closed(&mut self, sender: &mut ws::Sender) -> Result<(), Outcome> {
        for sub_id in mem::take(&mut self.closed_subs) {
            if let Some(sub) = self.subs.get(&sub_id) {
                sender
                    .send(wire::request(&sub_id, &sub.filter, unix_now()))
                    .await
                    .map_err(|_| Outcome::Dropped)?;
            }
        }
        Ok(())
    }

    /// `queued` is a command that waited while the socket dialed.
    async fn on_command(
        &mut self,
        command: Command,
        sender: &mut ws::Sender,
        queued: bool,
    ) -> Result<(), Outcome> {
        let frame = match command {
            Command::Subscribe {
                sub_id,
                filter,
                events,
            } => {
                let frame = wire::request(&sub_id, &filter, unix_now());
                self.subs.insert(sub_id, Subscription { filter, events });
                frame
            }
            Command::Unsubscribe { sub_id } => {
                self.closed_subs.remove(&sub_id);
                if self.subs.remove(&sub_id).is_none() {
                    return Ok(());
                }
                wire::close(&sub_id)
            }
            Command::Publish(frame) => {
                if !queued && !self.health.borrow().sendable() {
                    return Ok(());
                }
                frame
            }
            Command::Reconnect => return Err(Outcome::Dropped),
        };
        sender.send(frame).await.map_err(|_| Outcome::Dropped)
    }

    fn on_frame(&mut self, frame: &str) -> Result<(), Outcome> {
        match wire::parse(frame) {
            FromRelay::Event { sub_id, event } => {
                if let Some(sub) = self.subs.get(&sub_id) {
                    let _ = sub.events.send((self.url.clone(), event));
                }
            }
            FromRelay::Eose => self.note_served(),
            FromRelay::Ok { accepted: true, .. } => {
                self.note_served();
                if self
                    .last_limited
                    .is_none_or(|at| at.elapsed() >= RATE_LIMIT_CALM)
                {
                    self.rate_limit.reset();
                }
                if matches!(*self.health.borrow(), Health::Limited(_)) {
                    self.set_health(Health::Up);
                }
            }
            FromRelay::Ok {
                accepted: false,
                reason,
            } => match refusal(&self.url, &reason, &mut self.stale_warned) {
                Refusal::Retire => return Err(Outcome::Retired),
                Refusal::Limit => {
                    self.limit();
                }
                Refusal::Ignore => {}
            },
            FromRelay::Closed { sub_id, reason } => {
                if !self.subs.contains_key(&sub_id) {
                    return Ok(());
                }
                let at = match refusal(&self.url, &reason, &mut self.stale_warned) {
                    Refusal::Retire => return Err(Outcome::Retired),
                    Refusal::Limit => self.limit(),
                    Refusal::Ignore => Instant::now() + self.resubscribe.step(),
                };
                self.closed_subs.insert(sub_id);
                self.resubscribe_at =
                    Some(self.resubscribe_at.map_or(at, |current| current.max(at)));
            }
            FromRelay::Other => {}
        }
        Ok(())
    }

    /// The relay accepted an event or finished a REQ: it serves us. Once per
    /// socket, an earlier retirement is forgiven, so a relay that refuses us
    /// again later starts from the first wait. Reaching `Up` proves nothing: a
    /// relay that refuses every REQ is `Up` between the dial and the refusal.
    fn note_served(&mut self) {
        if !self.served {
            self.served = true;
            self.hub.forgive(&self.url);
        }
    }

    /// Back off: mark the relay limited and double the next wait.
    fn limit(&mut self) -> Instant {
        let now = Instant::now();
        let until = now + self.rate_limit.step();
        self.last_limited = Some(now);
        self.set_health(Health::Limited(until));
        until
    }

    /// Wait out a reconnect delay while still taking commands, so a subscribe
    /// that arrives now goes out on the next socket. `false` when every lease
    /// is gone and the task should end.
    async fn wait_absorbing(&mut self, delay: Duration) -> bool {
        let wait = sleep(delay);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                () = &mut wait => return true,
                command = self.commands.recv() => match command {
                    None => return false,
                    Some(Command::Subscribe { sub_id, filter, events }) => {
                        self.subs.insert(sub_id, Subscription { filter, events });
                    }
                    Some(Command::Unsubscribe { sub_id }) => {
                        self.subs.remove(&sub_id);
                    }
                    // Nowhere to send it, or already reconnecting.
                    Some(Command::Publish(_) | Command::Reconnect) => {}
                },
            }
        }
    }
}

enum Outcome {
    /// Every lease is gone.
    Idle,
    /// The relay refused us for good.
    Retired,
    /// The socket died; reconnect.
    Dropped,
}

enum Refusal {
    Retire,
    Limit,
    Ignore,
}

/// The warning about a stale event goes out at most this often per relay.
const STALE_WARN_EVERY: Duration = Duration::from_mins(10);

/// What to do about a refusal. `stale_warned` is when the stale-event warning
/// last went out for this relay.
fn refusal(url: &Url, reason: &str, stale_warned: &mut Option<Instant>) -> Refusal {
    match wire::classify(reason) {
        Verdict::Retire => {
            tracing::info!(target: "habilis_network::lookup", %url, reason, "relay refused us for good; retiring it");
            Refusal::Retire
        }
        Verdict::RateLimited => {
            tracing::debug!(target: "habilis_network::lookup", %url, reason, "relay rate-limited us");
            Refusal::Limit
        }
        Verdict::Duplicate => Refusal::Ignore,
        Verdict::Stale => {
            if stale_warned.is_none_or(|at| at.elapsed() >= STALE_WARN_EVERY) {
                *stale_warned = Some(Instant::now());
                tracing::warn!(target: "habilis_network::lookup", %url, reason, "relay refused an event as outside its time window; the usual cause is this machine's clock being wrong (a relay window can also be shorter than our 120 s replay window)");
            }
            Refusal::Ignore
        }
        Verdict::Other => {
            tracing::debug!(target: "habilis_network::lookup", %url, reason, "relay refusal");
            Refusal::Ignore
        }
    }
}

#[cfg(all(test, feature = "test-relay"))]
mod flow_tests {
    use std::time::Duration;

    use n0_future::time::{Instant, sleep};
    use tokio::sync::mpsc;
    use url::Url;

    use super::{Hub, Lease};
    use crate::test_relay::TestRelay;
    use crate::wire::Filter;

    /// The first retirement wait of the hubs below: short enough to see a whole
    /// retire, retry and refuse-again cycle in a second or two.
    const FIRST: Duration = Duration::from_millis(400);

    fn hub() -> &'static Hub {
        Box::leak(Box::new(Hub::with_retirement(
            FIRST,
            Duration::from_secs(60),
        )))
    }

    fn filter() -> Filter {
        Filter {
            kinds: vec![20_001],
            tags: vec!["ab".into()],
        }
    }

    fn blocked(hub: &Hub, url: &Url) -> bool {
        hub.retired
            .lock()
            .expect("hub mutex poisoned")
            .blocks(url.as_str(), Instant::now())
    }

    fn remembered(hub: &Hub, url: &Url) -> bool {
        hub.retired
            .lock()
            .expect("hub mutex poisoned")
            .relays
            .contains_key(url.as_str())
    }

    async fn until(what: &str, mut check: impl FnMut() -> bool) {
        for _ in 0..300 {
            if check() {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert!(check(), "timed out waiting for: {what}");
    }

    /// The real flow: a relay that refuses every REQ is `Up` between the dial
    /// and the refusal, and that must not forgive it. Its second refusal, after
    /// the retry, doubles the wait.
    #[tokio::test]
    async fn a_relay_that_refuses_again_after_a_retry_waits_twice_as_long() {
        let hub = hub();
        let relay = TestRelay::spawn().await.expect("spawn test relay");
        relay.refuse_subs(Some("blocked: no"));
        let url = relay.url();
        let (events, _events_rx) = mpsc::unbounded_channel();

        let first: Lease = hub
            .lease(&url, "one".into(), filter(), events.clone())
            .expect("a first lease");
        until("the first refusal retires the relay", || blocked(hub, &url)).await;
        drop(first);
        until("the first wait ends", || !blocked(hub, &url)).await;

        let _retry = hub
            .lease(&url, "two".into(), filter(), events)
            .expect("one retry is allowed after the wait");
        until("the second refusal retires the relay", || {
            blocked(hub, &url)
        })
        .await;
        // The first wait was 400 ms and the second is 800: still blocked at 600.
        sleep(Duration::from_millis(600)).await;
        assert!(
            blocked(hub, &url),
            "the second refusal waits twice as long as the first"
        );
        until("the doubled wait ends", || !blocked(hub, &url)).await;
    }

    /// A relay that serves us after a retry (it finishes the REQ) is forgiven:
    /// its next refusal starts again from the first wait.
    #[tokio::test]
    async fn a_relay_that_serves_after_a_retry_is_forgiven() {
        let hub = hub();
        let relay = TestRelay::spawn().await.expect("spawn test relay");
        relay.refuse_subs(Some("blocked: no"));
        let url = relay.url();
        let (events, _events_rx) = mpsc::unbounded_channel();

        let first: Lease = hub
            .lease(&url, "one".into(), filter(), events.clone())
            .expect("a first lease");
        until("the first refusal retires the relay", || blocked(hub, &url)).await;
        drop(first);
        relay.refuse_subs(None);
        until("the first wait ends", || !blocked(hub, &url)).await;
        assert!(remembered(hub, &url), "the retirement is still remembered");

        let _retry = hub
            .lease(&url, "two".into(), filter(), events)
            .expect("one retry is allowed after the wait");
        until("the relay finishes the REQ and is forgiven", || {
            !remembered(hub, &url)
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use n0_future::time::Instant;
    use url::Url;

    use super::{
        Backoff, Health, RETIRE_FIRST, RETIRE_MAX, Refusal, Retirements, STALE_WARN_EVERY, refusal,
    };

    /// A relay with a shorter window refuses every announce, so the warning
    /// goes out once per relay per ten minutes, not once per refusal.
    #[test]
    fn the_stale_warning_is_rate_limited_per_relay() {
        let url: Url = "wss://relay.example/".parse().expect("a valid URL");
        let reason = "invalid: event too old";
        let mut warned = None;

        let outcome = refusal(&url, reason, &mut warned);
        assert!(
            matches!(outcome, Refusal::Ignore),
            "a stale refusal is not a retirement"
        );
        let first = warned.expect("the first refusal warns");
        let again = refusal(&url, reason, &mut warned);
        assert!(
            matches!(again, Refusal::Ignore),
            "the second one is not either"
        );
        assert_eq!(warned, Some(first), "the second refusal stays quiet");

        if let Some(long_ago) = Instant::now().checked_sub(STALE_WARN_EVERY) {
            warned = Some(long_ago);
            let _ = refusal(&url, reason, &mut warned);
            assert!(
                warned.is_some_and(|at| at > long_ago),
                "after ten minutes the warning goes out again"
            );
        }
    }

    #[test]
    fn a_backoff_doubles_up_to_its_cap_and_resets() {
        let mut backoff = Backoff::new(Duration::from_mins(1), Duration::from_mins(15));
        let steps: Vec<u64> = (0..7).map(|_| backoff.step().as_secs() / 60).collect();
        assert_eq!(steps, [1, 2, 4, 8, 15, 15, 15], "minutes");
        backoff.reset();
        assert_eq!(
            backoff.step(),
            Duration::from_mins(1),
            "a reset starts from the first step"
        );
    }

    /// Clients that lost a relay together must not redial it at the same marks,
    /// and none may redial it sooner than its backoff.
    #[test]
    fn a_reconnect_delay_is_spread_and_never_shorter_than_its_backoff() {
        let mut waits = Vec::new();
        for _ in 0..200 {
            let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_mins(1));
            let wait = backoff.step_jittered();
            assert!(
                wait >= Duration::from_secs(1) && wait < Duration::from_millis(1500),
                "the first delay scales by a factor in 1.0..1.5: {wait:?}"
            );
            let second = backoff.step_jittered();
            assert!(
                second >= Duration::from_secs(2) && second < Duration::from_secs(3),
                "the doubled delay scales the same way: {second:?}"
            );
            waits.push(wait);
        }
        waits.sort();
        let (shortest, longest) = (waits[0], waits[waits.len() - 1]);
        assert!(
            longest.saturating_sub(shortest) > Duration::from_millis(100),
            "200 draws spread over the range: {shortest:?} to {longest:?}"
        );
    }

    #[test]
    fn a_retired_relay_gets_one_retry_after_six_hours_and_a_longer_wait_after_that() {
        let mut retired = Retirements::default();
        let url = "wss://relay.example/";
        let start = Instant::now();
        assert!(
            !retired.blocks(url, start),
            "an unknown relay is not blocked"
        );

        retired.retire(url, start);
        assert!(retired.blocks(url, start), "blocked at once");
        assert!(
            retired.blocks(
                url,
                start + Duration::from_hours(6) - Duration::from_secs(1)
            ),
            "still blocked just before 6 h"
        );
        let retry = start + Duration::from_hours(6);
        assert!(!retired.blocks(url, retry), "one retry is allowed at 6 h");

        // The retry is refused again: the wait doubles.
        retired.retire(url, retry);
        assert!(
            retired.blocks(
                url,
                retry + Duration::from_hours(12) - Duration::from_secs(1)
            ),
            "blocked for 12 h after the second refusal"
        );
        assert!(
            !retired.blocks(url, retry + Duration::from_hours(12)),
            "allowed again at 12 h"
        );
    }

    #[test]
    fn a_retirement_wait_stops_doubling_at_its_cap_and_resets_when_the_relay_serves() {
        let mut retired = Retirements::default();
        let url = "wss://relay.example/";
        let mut now = Instant::now();
        for _ in 0..20 {
            retired.retire(url, now);
            now += RETIRE_MAX;
        }
        assert!(
            retired.blocks(url, now - RETIRE_MAX + Duration::from_hours(1)),
            "the wait is the cap, not more"
        );
        assert!(!retired.blocks(url, now), "and the cap is the longest wait");

        retired.clear(url);
        retired.retire(url, now);
        assert!(
            !retired.blocks(url, now + RETIRE_FIRST),
            "after a clear the next refusal starts from the first wait"
        );
    }

    #[test]
    fn a_limited_relay_is_not_usable_even_past_its_wait() {
        let past = Instant::now();
        assert!(!Health::Limited(past).usable(), "a limited relay waits");
        assert!(Health::Up.usable(), "an up relay is usable");
        assert!(Health::Connecting.usable(), "a dialing relay counts");
        assert!(!Health::Down.usable(), "a down relay is not");
        assert!(!Health::Retired.usable(), "a retired relay is not");
    }
}
