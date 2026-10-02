//! Agreeing who is playing, before anyone starts.
//!
//! A rollback session needs the player list fixed up front and **identical
//! on every peer**, because handles are positional — if two peers order the
//! roster differently they file each other's inputs against the wrong
//! player, which is a desync with no symptom until the game diverges.
//!
//! The engine has no barrier primitive to build that on (checked: `ready`
//! and `NodeEvent::Ready` are local daemon readiness, unrelated to peers),
//! so this is it. It is deliberately small, because it is not a consensus
//! problem: somebody presses start.
//!
//! 1. Every peer periodically broadcasts [`LobbyMessage::Present`].
//! 2. One peer broadcasts [`LobbyMessage::Start`] with the player list.
//! 3. Everyone in that list — including the proposer — builds a session with
//!    handles assigned by position in the list, which is sorted by public
//!    key so it is the same everywhere.
//!
//! Proposals are ranked by `(epoch, then lower session id)`. The epoch
//! counts matches, so a rematch retires the one before it and a straggler
//! from that older match can never resurrect it. The id breaks a tie
//! between two peers pressing start at once, without a round trip: every
//! peer applies the same rule to the same pair of proposals, so they
//! converge on the same one.
//!
//! What this does *not* do is agree on a moment in time — there is no shared
//! wall clock on a habilis-network mesh to agree with. It agrees on *who* and on a
//! logical frame 0; the session's own handshake
//! ([`SessionState::Synchronizing`](crate::SessionState)) aligns the rest.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// A lobby packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LobbyMessage {
    /// "I am here, and this is what to call me."
    Present {
        /// The sender's display name. Cosmetic, but it has to be unique
        /// within a match — see [`LobbyError::DuplicateNickname`].
        nick: String,
    },
    /// "Start now, with exactly these players."
    Start {
        /// Which match this is, counting from 1. Monotonic, so a rematch
        /// always supersedes the match before it and a straggler from
        /// that older match never resurrects it.
        epoch: u64,
        /// Tie-breaker between two proposals for the *same* epoch; lower
        /// wins.
        session_id: u64,
        /// Every player's public key, sorted. Position is the handle.
        players: Vec<String>,
    },
}

/// Why a match could not be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LobbyError {
    /// Fewer than two players are present.
    NotEnoughPlayers,
    /// Two peers are using the same nickname.
    ///
    /// Fatal rather than cosmetic: `send_app` addresses peers by nickname,
    /// so two players sharing one are not separately reachable and one would
    /// silently never receive input.
    DuplicateNickname(String),
}

impl std::fmt::Display for LobbyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnoughPlayers => write!(formatter, "need at least two players to start"),
            Self::DuplicateNickname(nick) => write!(
                formatter,
                "two peers are both called {nick:?}; unicast addressing is by nickname, so they \
                 are not separately reachable"
            ),
        }
    }
}

impl std::error::Error for LobbyError {}

/// The agreed shape of a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedMatch {
    /// Which match this is, counting from 1. Every peer agrees on it, so
    /// it doubles as a match number to show a player.
    pub epoch: u64,
    /// Distinguishes this match's packets from a previous one's.
    pub session_id: u64,
    /// Public keys in handle order. Identical on every peer.
    pub players: Vec<String>,
    /// This peer's own handle.
    pub local_handle: usize,
}

/// One peer we have heard from.
#[derive(Debug, Clone)]
struct Presence {
    nick: String,
    /// When we last heard from them, in the caller's tick units.
    last_seen: u64,
}

/// Tracks who is present and whether a match has started.
#[derive(Debug)]
pub struct Lobby {
    my_pubkey: String,
    my_nick: String,
    /// Public key -> presence, in sorted order so the roster is canonical.
    present: BTreeMap<String, Presence>,
    started: Option<StartedMatch>,
    /// The highest epoch adopted so far; `0` before the first match.
    epoch: u64,
}

impl Lobby {
    /// A lobby for this peer. `my_pubkey` is the signed identity from
    /// `HandlerCtx::our_pubkey`.
    #[must_use]
    pub fn new(my_pubkey: String, my_nick: String) -> Self {
        let mut present = BTreeMap::new();
        present.insert(
            my_pubkey.clone(),
            Presence {
                nick: my_nick.clone(),
                last_seen: 0,
            },
        );
        Self {
            my_pubkey,
            my_nick,
            present,
            started: None,
            epoch: 0,
        }
    }

    /// The packet to broadcast periodically while waiting.
    #[must_use]
    pub fn presence(&self) -> LobbyMessage {
        LobbyMessage::Present {
            nick: self.my_nick.clone(),
        }
    }

    /// Everyone currently present, as `(public key, nickname)`, in handle
    /// order.
    #[must_use]
    pub fn present(&self) -> Vec<(String, String)> {
        self.present
            .iter()
            .map(|(pubkey, seen)| (pubkey.clone(), seen.nick.clone()))
            .collect()
    }

    /// Why a match cannot start, when the reason is not simply "nobody
    /// else is here yet".
    ///
    /// The same rule [`Self::propose`] enforces, asked without proposing.
    /// Only one peer proposes — the lobby picks one so a room does not
    /// fill with competing proposals — so without this the other peer has
    /// no idea why nothing is happening, and its screen cheerfully reports
    /// that the match is about to start.
    #[must_use]
    pub fn blocker(&self) -> Option<LobbyError> {
        if self.present.len() < 2 {
            return None;
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for presence in self.present.values() {
            if !seen.insert(presence.nick.as_str()) {
                return Some(LobbyError::DuplicateNickname(presence.nick.clone()));
            }
        }
        None
    }

    /// Drop peers we have not heard from within `ttl` of `now`, both in
    /// whatever tick unit the caller counts in.
    ///
    /// Without this the roster only ever grows, and a peer that restarts
    /// is not the peer that left: every launch mints a fresh public key,
    /// so the departed one lingers forever. The next proposal then builds
    /// a match that includes a player who cannot answer, and the session
    /// waits in `Synchronizing` for them — so restarting one side, the
    /// obvious thing to try when a match will not start, wedges the pair
    /// instead of fixing it.
    ///
    /// Never drops us: we are present by definition, and we do not send
    /// ourselves presence to refresh the stamp with.
    ///
    /// A match already agreed is untouched. Its roster was fixed when it
    /// started ([`StartedMatch::players`]) precisely so it cannot shift
    /// under a running session; this only governs who the *next* proposal
    /// will include.
    pub fn expire(&mut self, now: u64, ttl: u64) {
        let mine = self.my_pubkey.clone();
        self.present
            .retain(|pubkey, seen| *pubkey == mine || now.saturating_sub(seen.last_seen) <= ttl);
    }

    /// The agreed match, once one has started.
    #[must_use]
    pub fn started(&self) -> Option<&StartedMatch> {
        self.started.as_ref()
    }

    /// The current match as a packet to re-announce, if there is one.
    ///
    /// Broadcast this on the same cadence as [`Self::presence`]. Sending
    /// [`LobbyMessage::Start`] once is not enough: it crosses the same
    /// fire-and-forget path as everything else here, and a peer that
    /// misses the single copy waits forever for a match the others are
    /// already playing — with no symptom beyond a lobby that never starts.
    ///
    /// Repeating it is free. [`Self::on_message`] ignores any proposal
    /// that does not outrank what the receiver already holds, so a peer
    /// re-announcing a match it merely adopted just helps it spread.
    #[must_use]
    pub fn announcement(&self) -> Option<LobbyMessage> {
        self.started.as_ref().map(|current| LobbyMessage::Start {
            epoch: current.epoch,
            session_id: current.session_id,
            players: current.players.clone(),
        })
    }

    /// Fold in a packet from `pubkey`, seen at `now` (the caller's tick
    /// unit — see [`Self::expire`], which measures staleness against it).
    ///
    /// Unparseable packets are ignored rather than reported: a peer running
    /// a different version is not something this peer can act on.
    pub fn on_message(&mut self, pubkey: &str, raw: &str, now: u64) {
        let Ok(message) = serde_json::from_str::<LobbyMessage>(raw) else {
            return;
        };
        match message {
            LobbyMessage::Present { nick } => {
                self.present.insert(
                    pubkey.to_owned(),
                    Presence {
                        nick,
                        last_seen: now,
                    },
                );
            }
            LobbyMessage::Start {
                epoch,
                session_id,
                players,
            } => self.adopt(epoch, session_id, players),
        }
    }

    /// Accept a proposal, unless an existing one already outranks it.
    ///
    /// Rank is `(epoch, then lower session id)`. The epoch half retires
    /// the previous match outright, so a rematch is adopted even though
    /// its id may be higher; the id half breaks a tie between two peers
    /// proposing the same epoch at once. Every peer applies both rules to
    /// the same proposals, so they converge without a round trip.
    fn adopt(&mut self, epoch: u64, session_id: u64, players: Vec<String>) {
        if !players.contains(&self.my_pubkey) {
            // A match between other people.
            return;
        }
        if epoch < self.epoch {
            return;
        }
        if let Some(current) = &self.started
            && epoch == self.epoch
            && current.session_id <= session_id
        {
            return;
        }
        let Some(local_handle) = players.iter().position(|key| *key == self.my_pubkey) else {
            return;
        };
        // A replacement at the *same* epoch is the tie-break resolving a
        // proposal race, and it is the one transition a consumer can miss:
        // it changes the agreed session id without changing the epoch, so a
        // consumer that only re-arms on a new epoch keeps the old match.
        tracing::debug!(
            epoch,
            session_id,
            local_handle,
            players = players.len(),
            replaced = self
                .started
                .as_ref()
                .is_some_and(|current| current.epoch == epoch),
            "adopted a match"
        );
        self.epoch = epoch;
        self.started = Some(StartedMatch {
            epoch,
            session_id,
            players,
            local_handle,
        });
    }

    /// Propose the *next* match with everyone currently present.
    ///
    /// Returns the packet to broadcast. The proposer has already joined its
    /// own match by the time this returns — [`Self::started`] is populated —
    /// so there is no need to feed the packet back in.
    ///
    /// Calling this again proposes a further match, superseding the current
    /// one. That is how a rematch is started; there is no separate call,
    /// and nothing stops a peer proposing one mid-match, which is the same
    /// thing as abandoning it.
    ///
    /// # Errors
    /// [`LobbyError::NotEnoughPlayers`] below two players;
    /// [`LobbyError::DuplicateNickname`] if two peers share a nickname.
    pub fn propose(&mut self) -> Result<LobbyMessage, LobbyError> {
        if self.present.len() < 2 {
            return Err(LobbyError::NotEnoughPlayers);
        }
        if let Some(blocker) = self.blocker() {
            return Err(blocker);
        }
        // `BTreeMap` iterates sorted, so every peer proposing the same set
        // produces the same order and therefore the same handles.
        let players: Vec<String> = self.present.keys().cloned().collect();
        let epoch = self.epoch + 1;
        let session_id = session_id_for(&players, &self.my_pubkey, epoch);
        self.adopt(epoch, session_id, players.clone());
        Ok(LobbyMessage::Start {
            epoch,
            session_id,
            players,
        })
    }
}

/// A match id that is a pure function of the roster, the proposer and the
/// epoch.
///
/// The three inputs each rule out a collision that would matter: the epoch
/// so a rematch is never confused with the match before it, the roster so
/// two different player sets are never confused, and the proposer so two
/// peers proposing the same epoch and roster at once still produce
/// different ids for the tie-break to order.
///
/// Hand-rolled FNV-1a rather than `std`'s hasher, which is randomly seeded
/// per process and would give every peer a different answer — the same
/// portability constraint the determinism contract puts on consumers.
fn session_id_for(players: &[String], proposer: &str, epoch: u64) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
    };
    for player in players {
        eat(player.as_bytes());
        eat(b":");
    }
    eat(b"@");
    eat(proposer.as_bytes());
    eat(b"#");
    eat(&epoch.to_le_bytes());
    hash
}

#[cfg(test)]
mod tests {
    use super::{Lobby, LobbyError, LobbyMessage};

    fn raw(message: &LobbyMessage) -> String {
        serde_json::to_string(message).expect("a lobby message serializes")
    }

    #[test]
    fn a_peer_is_present_in_its_own_lobby() {
        let lobby = Lobby::new("aaa".into(), "alice".into());
        assert_eq!(
            lobby.present(),
            vec![("aaa".to_owned(), "alice".to_owned())]
        );
    }

    #[test]
    fn presence_from_a_peer_is_recorded() {
        let mut lobby = Lobby::new("aaa".into(), "alice".into());
        lobby.on_message(
            "bbb",
            &raw(&LobbyMessage::Present { nick: "bob".into() }),
            0,
        );
        assert_eq!(lobby.present().len(), 2);
    }

    #[test]
    fn starting_alone_is_refused() {
        let mut lobby = Lobby::new("aaa".into(), "alice".into());
        assert_eq!(lobby.propose(), Err(LobbyError::NotEnoughPlayers));
    }

    #[test]
    fn two_peers_sharing_a_nickname_is_refused() {
        let mut lobby = Lobby::new("aaa".into(), "alice".into());
        lobby.on_message(
            "bbb",
            &raw(&LobbyMessage::Present {
                nick: "alice".into(),
            }),
            0,
        );
        assert_eq!(
            lobby.propose(),
            Err(LobbyError::DuplicateNickname("alice".to_owned())),
            "unicast is addressed by nickname, so a duplicate is unreachable"
        );
    }

    /// The property the whole module exists for.
    #[test]
    fn both_peers_derive_the_same_handles() {
        let mut alice = Lobby::new("aaa".into(), "alice".into());
        let mut bob = Lobby::new("bbb".into(), "bob".into());
        alice.on_message(
            "bbb",
            &raw(&LobbyMessage::Present { nick: "bob".into() }),
            0,
        );
        bob.on_message(
            "aaa",
            &raw(&LobbyMessage::Present {
                nick: "alice".into(),
            }),
            0,
        );

        let start = alice.propose().expect("two distinct players");
        bob.on_message("aaa", &raw(&start), 0);

        let alice_match = alice.started().expect("proposer joins its own match");
        let bob_match = bob.started().expect("bob adopted it");
        assert_eq!(alice_match.players, bob_match.players);
        assert_eq!(alice_match.session_id, bob_match.session_id);
        assert_eq!(alice_match.local_handle, 0, "aaa sorts first");
        assert_eq!(bob_match.local_handle, 1);
    }

    #[test]
    fn simultaneous_proposals_converge_on_the_lower_id() {
        let mut alice = Lobby::new("aaa".into(), "alice".into());
        let mut bob = Lobby::new("bbb".into(), "bob".into());
        alice.on_message(
            "bbb",
            &raw(&LobbyMessage::Present { nick: "bob".into() }),
            0,
        );
        bob.on_message(
            "aaa",
            &raw(&LobbyMessage::Present {
                nick: "alice".into(),
            }),
            0,
        );

        // Both press start before hearing the other.
        let from_alice = alice.propose().expect("valid");
        let from_bob = bob.propose().expect("valid");
        alice.on_message("bbb", &raw(&from_bob), 0);
        bob.on_message("aaa", &raw(&from_alice), 0);

        let alice_match = alice.started().expect("started");
        let bob_match = bob.started().expect("started");
        assert_eq!(
            alice_match.session_id, bob_match.session_id,
            "both must land on the same match, or they play different games"
        );
        assert_eq!(alice_match.players, bob_match.players);
    }

    /// The single `Start` packet crosses a lossy path, so the lobby has to
    /// be able to say it again.
    #[test]
    fn a_started_match_can_be_announced_again_and_a_peer_that_missed_it_catches_up() {
        let mut alice = Lobby::new("aaa".into(), "alice".into());
        let mut bob = Lobby::new("bbb".into(), "bob".into());
        alice.on_message(
            "bbb",
            &raw(&LobbyMessage::Present { nick: "bob".into() }),
            0,
        );
        bob.on_message(
            "aaa",
            &raw(&LobbyMessage::Present {
                nick: "alice".into(),
            }),
            0,
        );

        // Alice starts, and the packet is dropped on the way to Bob.
        alice.propose().expect("two distinct players");
        assert!(bob.started().is_none());

        let again = alice.announcement().expect("alice is in a match");
        bob.on_message("aaa", &raw(&again), 0);
        assert_eq!(
            bob.started().map(|current| current.session_id),
            alice.started().map(|current| current.session_id),
        );
    }

    #[test]
    fn a_lobby_with_no_match_has_nothing_to_announce() {
        let lobby = Lobby::new("aaa".into(), "alice".into());
        assert_eq!(lobby.announcement(), None);
    }

    /// Regression for a pair that could only be unwedged by restarting
    /// both sides: presence was insert-only, and a relaunched peer arrives
    /// under a brand-new public key, so the departed one lingered and the
    /// next match was proposed with a player who could never answer.
    /// Both peers must be able to say why, not just whichever one the
    /// lobby elected to propose.
    #[test]
    fn a_duplicate_nickname_is_reported_without_proposing() {
        let mut lobby = Lobby::new("aaa".into(), "alice".into());
        assert_eq!(lobby.blocker(), None, "alone is not blocked, just empty");

        lobby.on_message(
            "bbb",
            &raw(&LobbyMessage::Present {
                nick: "alice".into(),
            }),
            0,
        );
        assert_eq!(
            lobby.blocker(),
            Some(LobbyError::DuplicateNickname("alice".to_owned()))
        );
    }

    #[test]
    fn a_peer_that_stops_announcing_is_dropped() {
        let mut lobby = Lobby::new("aaa".into(), "alice".into());
        lobby.on_message(
            "bbb",
            &raw(&LobbyMessage::Present { nick: "bob".into() }),
            100,
        );
        assert_eq!(lobby.present().len(), 2);

        lobby.expire(160, 50);
        assert_eq!(
            lobby.present(),
            vec![("aaa".to_owned(), "alice".to_owned())],
            "bob went quiet for longer than the ttl and must not be proposed into a match"
        );
    }

    #[test]
    fn a_peer_that_keeps_announcing_is_kept_and_we_never_expire_ourselves() {
        let mut lobby = Lobby::new("aaa".into(), "alice".into());
        for now in [100, 150, 200] {
            lobby.on_message(
                "bbb",
                &raw(&LobbyMessage::Present { nick: "bob".into() }),
                now,
            );
            lobby.expire(now, 50);
        }
        assert_eq!(lobby.present().len(), 2);

        // We never receive our own presence, so our stamp stays at 0 —
        // expiring on that would delete the one peer that is certainly here.
        lobby.expire(10_000, 50);
        assert_eq!(
            lobby.present(),
            vec![("aaa".to_owned(), "alice".to_owned())]
        );
    }

    #[test]
    fn expiry_does_not_disturb_a_match_already_agreed() {
        let mut lobby = Lobby::new("aaa".into(), "alice".into());
        lobby.on_message(
            "bbb",
            &raw(&LobbyMessage::Present { nick: "bob".into() }),
            10,
        );
        let started = lobby.propose().expect("two distinct players");
        let before = lobby.started().cloned();

        lobby.expire(10_000, 50);
        assert_eq!(
            lobby.started().cloned(),
            before,
            "a running match's roster is fixed at start; only the next proposal narrows"
        );
        let _ = started;
    }

    #[test]
    fn a_match_between_other_people_is_ignored() {
        let mut lobby = Lobby::new("aaa".into(), "alice".into());
        lobby.on_message(
            "bbb",
            &raw(&LobbyMessage::Start {
                epoch: 1,
                session_id: 1,
                players: vec!["bbb".into(), "ccc".into()],
            }),
            0,
        );
        assert!(lobby.started().is_none());
    }

    /// Rematch. The point of the epoch: the second match's id may well be
    /// *higher* than the first's, which the tie-break alone would refuse.
    #[test]
    fn a_second_proposal_supersedes_the_first_on_both_peers() {
        let mut alice = Lobby::new("aaa".into(), "alice".into());
        let mut bob = Lobby::new("bbb".into(), "bob".into());
        alice.on_message(
            "bbb",
            &raw(&LobbyMessage::Present { nick: "bob".into() }),
            0,
        );
        bob.on_message(
            "aaa",
            &raw(&LobbyMessage::Present {
                nick: "alice".into(),
            }),
            0,
        );

        let first = alice.propose().expect("two distinct players");
        bob.on_message("aaa", &raw(&first), 0);
        let first_id = alice.started().expect("started").session_id;

        let second = bob.propose().expect("still two players");
        alice.on_message("bbb", &raw(&second), 0);

        for lobby in [&alice, &bob] {
            let current = lobby.started().expect("started");
            assert_eq!(current.epoch, 2);
            assert_ne!(
                current.session_id, first_id,
                "a rematch must not reuse the previous match's id, or its \
                 stragglers would pass for live input"
            );
        }
        assert_eq!(
            alice.started().expect("started").session_id,
            bob.started().expect("started").session_id
        );
    }

    #[test]
    fn a_straggler_from_the_previous_match_never_resurrects_it() {
        let mut alice = Lobby::new("aaa".into(), "alice".into());
        alice.on_message(
            "bbb",
            &raw(&LobbyMessage::Present { nick: "bob".into() }),
            0,
        );
        let stale = alice.propose().expect("two distinct players");
        alice.propose().expect("rematch");
        let current = alice.started().expect("started").clone();

        alice.on_message("bbb", &raw(&stale), 0);
        assert_eq!(
            alice.started(),
            Some(&current),
            "an epoch-1 packet arriving after epoch 2 must be ignored"
        );
    }
}
