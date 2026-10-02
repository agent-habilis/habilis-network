//! The room: a roster and a fan-out, with no notion of how anyone is connected.
//!
//! Nothing here mentions iroh, WebRTC or a stream. That is deliberate — the
//! host's own terminal is a member on exactly the same terms as a browser tab,
//! so "the native peer" in the demo is not a special case bolted on beside the
//! real ones. It joins, it says things, it leaves.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chat_proto::ServerMsg;
use tokio::sync::broadcast;

/// How many messages a slow member may fall behind before it is told it lagged.
///
/// A member that lags is skipped forward rather than disconnected: dropping a
/// tab because its event loop stalled behind a breakpoint would make the demo
/// fragile in exactly the situation someone is most likely to be debugging it.
const FANOUT_CAPACITY: usize = 256;

/// Identifies one *membership*, not one peer.
///
/// Deliberately not an `EndpointId`. A tab that reloads arrives as a new
/// endpoint id, but more to the point the host itself is a member and has no
/// remote id at all. A counter sidesteps both, and makes "skip the message I
/// sent" a comparison that cannot accidentally match somebody else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberId(u64);

/// One message, tagged with who caused it.
#[derive(Debug, Clone)]
pub struct Fanout {
    from: MemberId,
    pub msg: ServerMsg,
}

#[derive(Debug)]
struct Inner {
    members: Mutex<HashMap<MemberId, String>>,
    next_id: AtomicU64,
    tx: broadcast::Sender<Fanout>,
}

/// A handle to the room. Cheap to clone; every clone is the same room.
#[derive(Debug, Clone)]
pub struct Room {
    inner: Arc<Inner>,
}

impl Room {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(FANOUT_CAPACITY);
        Self {
            inner: Arc::new(Inner {
                members: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(0),
                tx,
            }),
        }
    }

    /// Admit a member under `requested`, or the nearest free variant of it.
    ///
    /// The returned [`Membership`] is the member's whole existence in the room:
    /// dropping it removes them from the roster and announces the departure, so
    /// a handler that panics or a connection that dies cannot leave a ghost in
    /// the roster. There is no `leave` to forget to call.
    pub fn join(&self, requested: &str) -> Membership {
        let id = MemberId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        // Subscribe *before* announcing, so the announcement cannot slip past
        // between the insert and the subscribe and leave the new member with a
        // roster that disagrees with everyone else's.
        let rx = self.inner.tx.subscribe();

        let (nick, roster) = {
            let mut members = self.inner.members.lock().expect("roster mutex poisoned");
            let nick = unique_nick(requested, &members);
            members.insert(id, nick.clone());
            let mut roster: Vec<String> = members.values().cloned().collect();
            roster.sort();
            (nick, roster)
        };

        // Ignored: `send` fails only when nobody is subscribed, and the first
        // member joining an empty room is the ordinary case, not an error.
        let _ = self.inner.tx.send(Fanout {
            from: id,
            msg: ServerMsg::Joined { nick: nick.clone() },
        });

        Membership {
            id,
            nick,
            roster,
            rx,
            inner: Arc::clone(&self.inner),
        }
    }

    /// Broadcast a line from `from` to everyone else.
    pub fn say(&self, from: MemberId, text: String) {
        let Some(nick) = self
            .inner
            .members
            .lock()
            .expect("roster mutex poisoned")
            .get(&from)
            .cloned()
        else {
            // The member left between saying this and us handling it.
            return;
        };
        let _ = self.inner.tx.send(Fanout {
            from,
            msg: ServerMsg::Said { nick, text },
        });
    }

    /// How many members are in the room, the host included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .members
            .lock()
            .expect("roster mutex poisoned")
            .len()
    }
}

impl Default for Room {
    fn default() -> Self {
        Self::new()
    }
}

/// Append `#2`, `#3`, … until the nick is free.
///
/// Two people called `bob` is not an error worth refusing a join over, but two
/// *indistinguishable* people is a chat that lies to its readers. The room
/// decides the name and tells the member what it settled on
/// ([`ServerMsg::Welcome`]'s `you`), so nobody renders a nick the others do not
/// see.
fn unique_nick(requested: &str, members: &HashMap<MemberId, String>) -> String {
    let base = requested.trim();
    let taken = |candidate: &str| members.values().any(|nick| nick == candidate);
    if !taken(base) {
        return base.to_owned();
    }
    // Bounded in practice by the roster's size, which is bounded by memory: the
    // loop cannot outrun a `u32` of distinct names that all fit in a `HashMap`.
    let mut suffix = 2u32;
    loop {
        let candidate = format!("{base}#{suffix}");
        if !taken(&candidate) {
            return candidate;
        }
        suffix = suffix.saturating_add(1);
    }
}

/// A member's presence in the room. Leaving is what dropping this does.
#[derive(Debug)]
pub struct Membership {
    pub id: MemberId,
    /// What the room actually called them — not necessarily what they asked for.
    pub nick: String,
    /// The roster at the moment they joined, themselves included.
    pub roster: Vec<String>,
    rx: broadcast::Receiver<Fanout>,
    inner: Arc<Inner>,
}

impl Membership {
    /// The next message this member should be shown.
    ///
    /// Their own messages are filtered out here rather than at each call site:
    /// a client renders what it said the moment it says it, and a room that
    /// echoed would double every line. Returns `None` once the room is gone.
    ///
    /// Cancel-safe, and it has to be — this is the one thing in the connection
    /// handler that shares a `select!` with an inbound-message channel.
    pub async fn next_broadcast(&mut self) -> Option<Fanout> {
        loop {
            match self.rx.recv().await {
                // Their own message: swallowed, and the loop goes round again.
                Ok(fanout) if fanout.from == self.id => {}
                Ok(fanout) => return Some(fanout),
                // Skipped forward rather than disconnected; see FANOUT_CAPACITY.
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!(%missed, nick = %self.nick, "member lagged the fan-out");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl Drop for Membership {
    fn drop(&mut self) {
        let removed = self
            .inner
            .members
            .lock()
            .expect("roster mutex poisoned")
            .remove(&self.id);
        if let Some(nick) = removed {
            let _ = self.inner.tx.send(Fanout {
                from: self.id,
                msg: ServerMsg::Left { nick },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_second_bob_is_renamed_and_told_so() {
        let room = Room::new();
        let first = room.join("bob");
        let second = room.join("bob");
        assert_eq!(first.nick, "bob");
        assert_eq!(second.nick, "bob#2");
        assert_eq!(room.len(), 2);
    }

    /// The regression this guards: a client that renders its own line locally
    /// *and* receives it back prints everything twice.
    #[tokio::test]
    async fn a_member_does_not_hear_its_own_message() {
        let room = Room::new();
        let mut alice = room.join("alice");
        let mut bob = room.join("bob");

        // alice's own Joined is filtered; bob's is not.
        let seen = alice.next_broadcast().await.expect("bob joined");
        assert!(matches!(seen.msg, ServerMsg::Joined { ref nick } if nick == "bob"));

        room.say(alice.id, "hi".to_owned());
        let heard = bob.next_broadcast().await.expect("bob hears alice");
        assert!(
            matches!(heard.msg, ServerMsg::Said { ref nick, ref text } if nick == "alice" && text == "hi")
        );

        // And alice hears nothing further of her own.
        room.say(bob.id, "hello".to_owned());
        let next = alice.next_broadcast().await.expect("alice hears bob");
        assert!(matches!(next.msg, ServerMsg::Said { ref nick, .. } if nick == "bob"));
    }

    /// Leaving is a `Drop`, so a handler that unwinds still cleans up. If this
    /// regresses, a tab that closes mid-frame leaves a name in the roster
    /// forever.
    #[tokio::test]
    async fn dropping_a_membership_announces_the_departure() {
        let room = Room::new();
        let mut alice = room.join("alice");
        let bob = room.join("bob");
        let _ = alice.next_broadcast().await; // bob joined
        assert_eq!(room.len(), 2);

        drop(bob);
        let seen = alice.next_broadcast().await.expect("bob left");
        assert!(matches!(seen.msg, ServerMsg::Left { ref nick } if nick == "bob"));
        assert_eq!(room.len(), 1);
    }

    /// And the name comes free again, so a reconnecting tab is `bob`, not
    /// `bob#2` climbing forever.
    #[tokio::test]
    async fn a_departed_nick_is_reusable() {
        let room = Room::new();
        let _alice = room.join("alice");
        drop(room.join("bob"));
        assert_eq!(room.join("bob").nick, "bob");
    }
}
