//! One socket per relay URL per process, shared by every pool that wants that
//! relay. A connection lives as long as some pool holds a lease on it,
//! reconnects on its own, and keeps its subscriptions across reconnects.
//!
//! Sharing is total: a relay's refusal of one pool's event limits or retires
//! the socket for every pool on it. That is how the relay sees us anyway, since
//! its limits are per connection or per IP.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use n0_future::time::{Instant, sleep, timeout};
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::event::Event;
use crate::wire::{self, Filter, FromRelay, Verdict};
use crate::{unix_now, ws};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Reconnects wait 1 s, doubling up to a minute. A socket must serve this long
/// before the next drop counts as a fresh start: a relay that accepts and
/// hangs up at once would otherwise be dialed every second until it bans us.
const RECONNECT: Backoff = Backoff::new(Duration::from_secs(1), Duration::from_mins(1));
const SERVE_TO_TRUST: Duration = Duration::from_secs(30);
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
    /// Refused for good (`blocked`, `auth-required`, ...). Never dialed again.
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

    fn reset(&mut self) {
        self.next = self.first;
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
#[derive(Debug)]
pub(crate) struct Lease {
    conn: Arc<Conn>,
    sub_id: String,
}

impl Lease {
    pub(crate) fn health(&self) -> Health {
        if self.is_dead() {
            return Health::Down;
        }
        *self.conn.health.borrow()
    }

    /// The connection task is gone, for instance because the runtime that
    /// spawned it shut down. A dead lease is replaced, never reused.
    pub(crate) fn is_dead(&self) -> bool {
        self.conn.commands.is_closed()
    }

    pub(crate) fn publish(&self, frame: String) {
        let _ = self.conn.commands.send(Command::Publish(frame));
    }

    /// Drop the socket and dial again. It is shared, so every pool on it
    /// reconnects: fine, since the socket is the suspect.
    pub(crate) fn reconnect(&self) {
        let _ = self.conn.commands.send(Command::Reconnect);
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.conn.commands.send(Command::Unsubscribe {
            sub_id: std::mem::take(&mut self.sub_id),
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
    retired: Mutex<HashSet<String>>,
    /// Bumped on any relay's health change, so pools choose again.
    changed: OnceLock<watch::Sender<u64>>,
}

impl Hub {
    pub(crate) fn global() -> &'static Hub {
        static HUB: OnceLock<Hub> = OnceLock::new();
        HUB.get_or_init(Hub::default)
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
    /// `None` for a retired relay.
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
            .contains(url.as_str())
        {
            return None;
        }
        let conn = {
            let mut conns = self.conns.lock().expect("hub mutex poisoned");
            let live = conns
                .get(url.as_str())
                .and_then(Weak::upgrade)
                .filter(|conn| !conn.commands.is_closed());
            if let Some(conn) = live {
                conn
            } else {
                let conn = self.spawn(url.clone());
                conns.insert(url.as_str().to_owned(), Arc::downgrade(&conn));
                conn
            }
        };
        let _ = conn.commands.send(Command::Subscribe {
            sub_id: sub_id.clone(),
            filter,
            events,
        });
        Some(Lease { conn, sub_id })
    }

    fn spawn(&'static self, url: Url) -> Arc<Conn> {
        let (commands, receiver) = mpsc::unbounded_channel();
        let (health_tx, health) = watch::channel(Health::Connecting);
        n0_future::task::spawn(run(self, url, receiver, health_tx));
        Arc::new(Conn { commands, health })
    }

    fn set_health(&self, url: &Url, health_tx: &watch::Sender<Health>, health: Health) {
        if health == Health::Retired {
            self.retired
                .lock()
                .expect("hub mutex poisoned")
                .insert(url.as_str().to_owned());
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
    };
    let mut reconnect = RECONNECT;
    loop {
        let started = Instant::now();
        let outcome = match timeout(CONNECT_TIMEOUT, ws::connect(&task.url)).await {
            Ok(Ok((sender, receiver))) => task.serve(sender, receiver).await,
            Ok(Err(error)) => {
                tracing::debug!(target: "habilis_network::nostr", url = %task.url, %error, "relay connect failed");
                Outcome::Dropped
            }
            Err(_) => {
                tracing::debug!(target: "habilis_network::nostr", url = %task.url, "relay connect timed out");
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
                if !task.wait_absorbing(reconnect.step()).await {
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
                    Some(at) => n0_future::time::sleep_until(at).await,
                    None => std::future::pending().await,
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
                .send(wire::req(sub_id, &sub.filter, unix_now()))
                .await
                .map_err(|_| ())?;
        }
        Ok(())
    }

    /// Send again only the REQs the relay closed.
    async fn subscribe_closed(&mut self, sender: &mut ws::Sender) -> Result<(), Outcome> {
        for sub_id in std::mem::take(&mut self.closed_subs) {
            if let Some(sub) = self.subs.get(&sub_id) {
                sender
                    .send(wire::req(&sub_id, &sub.filter, unix_now()))
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
                let frame = wire::req(&sub_id, &filter, unix_now());
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
            FromRelay::Ok { accepted: true, .. } => {
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
            } => match refusal(&self.url, &reason) {
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
                let at = match refusal(&self.url, &reason) {
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

fn refusal(url: &Url, reason: &str) -> Refusal {
    match wire::classify(reason) {
        Verdict::Retire => {
            tracing::info!(target: "habilis_network::nostr", %url, reason, "relay refused us for good; retiring it");
            Refusal::Retire
        }
        Verdict::RateLimited => {
            tracing::debug!(target: "habilis_network::nostr", %url, reason, "relay rate-limited us");
            Refusal::Limit
        }
        Verdict::Duplicate => Refusal::Ignore,
        Verdict::Other => {
            tracing::debug!(target: "habilis_network::nostr", %url, reason, "relay refusal");
            Refusal::Ignore
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backoff_doubles_up_to_its_cap_and_resets() {
        let mut backoff = Backoff::new(Duration::from_mins(1), Duration::from_mins(15));
        let steps: Vec<u64> = (0..7).map(|_| backoff.step().as_secs() / 60).collect();
        assert_eq!(steps, [1, 2, 4, 8, 15, 15, 15], "minutes");
        backoff.reset();
        assert_eq!(backoff.step(), Duration::from_mins(1));
    }

    #[test]
    fn a_limited_relay_is_not_usable_even_past_its_wait() {
        let past = Instant::now();
        assert!(!Health::Limited(past).usable());
        assert!(Health::Up.usable());
        assert!(Health::Connecting.usable());
        assert!(!Health::Down.usable());
        assert!(!Health::Retired.usable());
    }
}
