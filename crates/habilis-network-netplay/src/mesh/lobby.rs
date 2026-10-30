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

use habilis_network::protocol::{AuthorKey, Nickname};
use serde::{Deserialize, Serialize};

use crate::player_handle::PlayerHandle;

use std::{error, fmt};
/// Which match this is, counting from 1; `0` before the first.
///
/// Monotonic, so a rematch always supersedes the match before it and a
/// straggler from that older match never resurrects it.
///
/// # Examples
///
/// An epoch counts matches, and the next epoch is one more than the last.
///
/// ```
/// use habilis_network_netplay::Epoch;
///
/// assert_eq!(Epoch::ZERO.next().get(), 1);
/// assert_eq!(Epoch::new(4).get(), 4);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Epoch(u64);

impl Epoch {
    /// Before the first match.
    pub const ZERO: Self = Self(0);

    /// The match with number `number`.
    #[must_use]
    pub fn new(number: u64) -> Self {
        Self(number)
    }

    /// The match number.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    /// The match after this one.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for Epoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The id of one proposal for a match: the tie-breaker between two proposals
/// for the same [`Epoch`], where the lower one wins, and the scope of one
/// match's packets.
///
/// # Examples
///
/// A session id keeps the number it was made with.
///
/// ```
/// use habilis_network_netplay::SessionId;
///
/// assert_eq!(SessionId::new(9).get(), 9);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(u64);

impl SessionId {
    /// The id with value `value`.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// The id as a number.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A point in time, in the caller's own tick unit. The lobby reads no clock:
/// the caller says what "now" is each time it hands a packet in.
///
/// # Examples
///
/// A tick is a point on the lobby clock, and the span since an earlier tick is their difference.
///
/// ```
/// use habilis_network_netplay::{Tick, TickSpan};
///
/// assert_eq!(Tick::new(10).since(Tick::new(4)), TickSpan::new(6));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tick(u64);

impl Tick {
    /// The tick with number `number`.
    #[must_use]
    pub fn new(number: u64) -> Self {
        Self(number)
    }

    /// How long ago `earlier` was, `0` when it is not earlier.
    #[must_use]
    pub fn since(self, earlier: Self) -> TickSpan {
        TickSpan(self.0.saturating_sub(earlier.0))
    }
}

/// A length of time, in the same tick unit as [`Tick`].
///
/// # Examples
///
/// A span of ticks is the distance between two points on the lobby clock.
///
/// ```
/// use habilis_network_netplay::{Tick, TickSpan};
///
/// assert_eq!(TickSpan::new(6), Tick::new(10).since(Tick::new(4)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TickSpan(u64);

impl TickSpan {
    /// A span of `ticks` ticks.
    #[must_use]
    pub fn new(ticks: u64) -> Self {
        Self(ticks)
    }
}

/// A lobby packet.
///
/// # Examples
///
/// A lobby announces the presence of its member with a presence message. `LobbyMessage` is in the private lobby module, so this is not compiled.
///
/// ```ignore
/// use habilis_network_netplay::LobbyMessage;
///
/// use habilis_network::protocol::Nickname;
/// use habilis_network_netplay::Lobby;
/// use habilis_network::protocol::identity::Identity;
///
/// let key = Identity::generate().author_key();
/// let nick = Nickname::try_new("alice").expect("a nickname");
/// let mut lobby = Lobby::new(key, nick);
///
/// let message = lobby.presence();
/// assert!(matches!(message, LobbyMessage::Present { .. }));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LobbyMessage {
    /// "I am here, and this is what to call me."
    Present {
        /// The sender's display name. Cosmetic, but it has to be unique
        /// within a match — see [`LobbyError::DuplicateNickname`].
        nick: Nickname,
    },
    /// "Start now, with exactly these players."
    Start {
        /// Which match this is, counting from 1.
        epoch: Epoch,
        /// Tie-breaker between two proposals for the *same* epoch; lower
        /// wins.
        session_id: SessionId,
        /// Every player's public key, sorted. Position is the handle. On
        /// the wire a key is its lowercase hex text.
        #[serde(with = "key_list")]
        players: Vec<AuthorKey>,
    },
}

/// A list of keys as a JSON array of their hex text, the form the lobby has
/// always written. A text that is not a lowercase 64-character hex key
/// refuses the whole message.
mod key_list {
    use habilis_network::protocol::AuthorKey;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        keys: &[AuthorKey],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(keys.iter().map(ToString::to_string))
    }

    pub(super) fn deserialize<'de, Decoder: Deserializer<'de>>(
        deserializer: Decoder,
    ) -> Result<Vec<AuthorKey>, Decoder::Error> {
        let texts: Vec<String> = Vec::deserialize(deserializer)?;
        texts
            .iter()
            .map(|text| {
                AuthorKey::decode_hex(text).ok_or_else(|| {
                    Decoder::Error::custom(format!("{text:?} is not a lowercase hex key"))
                })
            })
            .collect()
    }
}

/// Why a match could not be started.
///
/// # Examples
///
/// A match cannot be proposed while the lobby holds one player.
///
/// ```
/// use habilis_network_netplay::{LobbyError};
///
/// use habilis_network::protocol::Nickname;
/// use habilis_network_netplay::Lobby;
/// use habilis_network::protocol::identity::Identity;
///
/// let key = Identity::generate().author_key();
/// let nick = Nickname::try_new("alice").expect("a nickname");
/// let mut lobby = Lobby::new(key, nick);
///
/// let error = lobby.propose().unwrap_err();
/// assert!(matches!(error, LobbyError::NotEnoughPlayers));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum LobbyError {
    /// Fewer than two players are present.
    NotEnoughPlayers,
    /// Two peers are using the same nickname.
    ///
    /// Fatal rather than cosmetic: `send_app` addresses peers by nickname,
    /// so two players sharing one are not separately reachable and one would
    /// silently never receive input.
    DuplicateNickname(Nickname),
}

impl fmt::Display for LobbyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl error::Error for LobbyError {}

/// The agreed shape of a match.
///
/// # Examples
///
/// No match has started until the members agree on one.
///
/// ```
/// use habilis_network::protocol::Nickname;
/// use habilis_network_netplay::Lobby;
/// use habilis_network::protocol::identity::Identity;
///
/// let key = Identity::generate().author_key();
/// let nick = Nickname::try_new("alice").expect("a nickname");
/// let mut lobby = Lobby::new(key, nick);
///
/// assert!(lobby.started().is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StartedMatch {
    /// Which match this is, counting from 1. Every peer agrees on it, so
    /// it doubles as a match number to show a player.
    pub epoch: Epoch,
    /// Distinguishes this match's packets from a previous one's.
    pub session_id: SessionId,
    /// Public keys in handle order. Identical on every peer.
    pub players: Vec<AuthorKey>,
    /// This peer's own handle.
    pub local_handle: PlayerHandle,
}

/// One peer we have heard from.
#[derive(Debug, Clone)]
struct Presence {
    nick: Nickname,
    /// When we last heard from them.
    last_seen: Tick,
}

/// Tracks who is present and whether a match has started.
///
/// # Examples
///
/// A lobby tracks the members it has seen and the match, once one starts.
///
/// ```
/// use habilis_network::protocol::Nickname;
/// use habilis_network_netplay::Lobby;
/// use habilis_network::protocol::identity::Identity;
///
/// let key = Identity::generate().author_key();
/// let nick = Nickname::try_new("alice").expect("a nickname");
/// let mut lobby = Lobby::new(key, nick);
///
/// assert_eq!(lobby.present().count(), 1);
/// assert!(lobby.started().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct Lobby {
    my_pubkey: AuthorKey,
    my_nick: Nickname,
    /// Public key -> presence, in sorted order so the roster is canonical.
    present: BTreeMap<AuthorKey, Presence>,
    started: Option<StartedMatch>,
    /// The highest epoch adopted so far; [`Epoch::ZERO`] before the first match.
    epoch: Epoch,
}

impl Lobby {
    /// A lobby for this peer. `my_pubkey` is the signed identity from
    /// `HandlerCtx::our_pubkey`.
    #[must_use]
    pub fn new(my_pubkey: AuthorKey, my_nick: Nickname) -> Self {
        let mut present = BTreeMap::new();
        present.insert(
            my_pubkey,
            Presence {
                nick: my_nick.clone(),
                last_seen: Tick::new(0),
            },
        );
        Self {
            my_pubkey,
            my_nick,
            present,
            started: None,
            epoch: Epoch::ZERO,
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
    pub fn present(&self) -> impl Iterator<Item = (AuthorKey, Nickname)> + '_ {
        self.present
            .iter()
            .map(|(pubkey, seen)| (*pubkey, seen.nick.clone()))
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

    /// Drop peers we have not heard from within `ttl` of `now`.
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
    pub fn expire(&mut self, now: Tick, ttl: TickSpan) {
        let mine = self.my_pubkey;
        self.present
            .retain(|pubkey, seen| *pubkey == mine || now.since(seen.last_seen) <= ttl);
    }

    /// The agreed match, once one has started.
    #[must_use]
    pub fn started(&self) -> Option<&StartedMatch> {
        self.started.as_ref()
    }

    /// The current match as a packet to re-announce, if there is one.
    ///
    /// Broadcast this on the same cadence as [`Self::presence`]. Sending
    /// `LobbyMessage::Start` once is not enough: it crosses the same
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

    /// Fold in a packet from `pubkey`, seen at `now` (see [`Self::expire`],
    /// which measures staleness against it).
    ///
    /// Unparseable packets are ignored rather than reported: a peer running
    /// a different version is not something this peer can act on.
    pub fn on_message(&mut self, pubkey: &AuthorKey, raw: &str, now: Tick) {
        let Ok(message): Result<LobbyMessage, serde_json::Error> = serde_json::from_str(raw) else {
            return;
        };
        match message {
            LobbyMessage::Present { nick } => {
                self.present.insert(
                    *pubkey,
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
    fn adopt(&mut self, epoch: Epoch, session_id: SessionId, players: Vec<AuthorKey>) {
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
        let Some(local_handle) = players
            .iter()
            .position(|key| *key == self.my_pubkey)
            .map(PlayerHandle::new)
        else {
            return;
        };
        // A replacement at the *same* epoch is the tie-break resolving a
        // proposal race, and it is the one transition a consumer can miss:
        // it changes the agreed session id without changing the epoch, so a
        // consumer that only re-arms on a new epoch keeps the old match.
        let replaced = self
            .started
            .as_ref()
            .is_some_and(|current| current.epoch == epoch);
        tracing::debug!(
            epoch = epoch.get(),
            session_id = session_id.get(),
            local_handle = local_handle.index(),
            players = players.len(),
            replaced,
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
        let players: Vec<AuthorKey> = self.present.keys().copied().collect();
        let epoch = self.epoch.next();
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
fn session_id_for(players: &[AuthorKey], proposer: &AuthorKey, epoch: Epoch) -> SessionId {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    // The hex text of each key, not its raw bytes: the id is a wire value.
    for player in players {
        eat(&player.hex());
        eat(b":");
    }
    eat(b"@");
    eat(&proposer.hex());
    eat(b"#");
    eat(&epoch.get().to_le_bytes());
    SessionId(hash)
}

#[cfg(test)]
mod tests {
    use super::{
        Epoch, Lobby, LobbyError, LobbyMessage, PlayerHandle, SessionId, Tick, TickSpan,
        session_id_for,
    };
    use habilis_network::protocol::{AuthorKey, Nickname};

    fn key(byte: u8) -> AuthorKey {
        AuthorKey::from([byte; 32])
    }

    fn nick(text: &str) -> Nickname {
        Nickname::try_new(text).expect("a valid nickname")
    }

    fn raw(message: &LobbyMessage) -> String {
        serde_json::to_string(message).expect("a lobby message serializes")
    }

    #[test]
    fn start_message_json_matches_the_golden() {
        let _guard = ::habilis_network_test_tracing::init();
        let message = LobbyMessage::Start {
            epoch: Epoch::new(2),
            session_id: SessionId::new(12_345),
            players: vec![key(0xaa), key(0xbb)],
        };
        assert_eq!(
            raw(&message),
            concat!(
                r#"{"Start":{"epoch":2,"session_id":12345,"players":["#,
                r#""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
                r#""bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}}"#,
            ),
            "the start message keeps its golden json"
        );
    }

    #[test]
    fn session_id_matches_the_golden_for_fixed_players_and_proposer() {
        let _guard = ::habilis_network_test_tracing::init();
        let players = vec![key(0xaa), key(0xbb)];
        assert_eq!(
            session_id_for(&players, &key(0xaa), Epoch::new(2)),
            SessionId::new(8_136_736_511_243_102_950),
            "the session id is pinned for fixed players and proposer"
        );
    }

    /// The roster order is the handle order, and it was the order of the hex
    /// text. Byte order of a key is the same order, so no handle moves.
    #[test]
    fn the_order_of_the_keys_is_the_order_of_their_hex_text() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut keys = [0xff, 0x0a, 0xa0, 0x9f, 0x10].map(key);
        keys.sort();
        let by_text = {
            let mut texts: Vec<String> = keys.iter().map(ToString::to_string).collect();
            texts.sort();
            texts
        };
        let sorted_text: Vec<String> = keys.iter().map(ToString::to_string).collect();
        assert_eq!(
            sorted_text, by_text,
            "the key order is the order of their hex text"
        );
    }

    #[test]
    fn a_start_with_a_key_that_is_not_lowercase_hex_is_ignored() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        let upper = "AA".repeat(32);
        let raw = format!(
            r#"{{"Start":{{"epoch":1,"session_id":1,"players":["{upper}","{}"]}}}}"#,
            key(0xbb)
        );
        lobby.on_message(&key(0xbb), &raw, Tick::new(0));
        assert!(
            lobby.started().is_none(),
            "a start with a key that is not lowercase hex is ignored"
        );
    }

    /// The literal that the lobby wrote before its players were keys. A new peer refuses
    /// it, and the lobby does not adopt a match from it.
    #[test]
    fn the_old_start_literal_with_text_players_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let old = r#"{"Start":{"epoch":2,"session_id":12345,"players":["aaa","bbb"]}}"#;
        let parsed: Result<LobbyMessage, serde_json::Error> = serde_json::from_str(old);
        let error = parsed.expect_err("players that are not keys");
        assert!(
            error.to_string().contains("is not a lowercase hex key"),
            "{error}"
        );
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        lobby.on_message(&key(0xbb), old, Tick::new(0));
        assert!(
            lobby.started().is_none(),
            "the old start literal with text players is refused"
        );
    }

    /// A nickname that `Nickname::try_new` refuses is not a presence.
    #[test]
    fn a_presence_with_a_nickname_the_wire_refuses_is_dropped() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        lobby.on_message(&key(0xbb), r#"{"Present":{"nick":""}}"#, Tick::new(0));
        let present: Vec<_> = lobby.present().collect();
        assert_eq!(
            present,
            vec![(key(0xaa), nick("alice"))],
            "a presence with a nickname the wire refuses is dropped"
        );
    }

    #[test]
    fn a_peer_is_present_in_its_own_lobby() {
        let _guard = ::habilis_network_test_tracing::init();
        let lobby = Lobby::new(key(0xaa), nick("alice"));
        let present: Vec<_> = lobby.present().collect();
        assert_eq!(
            present,
            vec![(key(0xaa), nick("alice"))],
            "a peer is present in its own lobby"
        );
    }

    #[test]
    fn presence_from_a_peer_is_recorded() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        lobby.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present { nick: nick("bob") }),
            Tick::new(0),
        );
        assert_eq!(
            lobby.present().count(),
            2,
            "a presence from a peer is recorded"
        );
    }

    #[test]
    fn starting_alone_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        assert_eq!(
            lobby.propose(),
            Err(LobbyError::NotEnoughPlayers),
            "starting alone is refused with not enough players"
        );
    }

    #[test]
    fn two_peers_sharing_a_nickname_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        lobby.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present {
                nick: nick("alice"),
            }),
            Tick::new(0),
        );
        assert_eq!(
            lobby.propose(),
            Err(LobbyError::DuplicateNickname(nick("alice"))),
            "unicast is addressed by nickname, so a duplicate is unreachable"
        );
    }

    /// The property the whole module exists for.
    #[test]
    fn both_peers_derive_the_same_handles() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut alice = Lobby::new(key(0xaa), nick("alice"));
        let mut bob = Lobby::new(key(0xbb), nick("bob"));
        alice.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present { nick: nick("bob") }),
            Tick::new(0),
        );
        bob.on_message(
            &key(0xaa),
            &raw(&LobbyMessage::Present {
                nick: nick("alice"),
            }),
            Tick::new(0),
        );

        let start = alice.propose().expect("two distinct players");
        bob.on_message(&key(0xaa), &raw(&start), Tick::new(0));

        let alice_match = alice.started().expect("proposer joins its own match");
        let bob_match = bob.started().expect("bob adopted it");
        assert_eq!(
            alice_match.players, bob_match.players,
            "both peers derive the same players"
        );
        assert_eq!(
            alice_match.session_id, bob_match.session_id,
            "both peers derive the same session id"
        );
        assert_eq!(
            alice_match.local_handle,
            PlayerHandle::new(0),
            "aaa sorts first"
        );
        assert_eq!(
            bob_match.local_handle,
            PlayerHandle::new(1),
            "bob's local handle is player one"
        );
    }

    #[test]
    fn simultaneous_proposals_converge_on_the_lower_id() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut alice = Lobby::new(key(0xaa), nick("alice"));
        let mut bob = Lobby::new(key(0xbb), nick("bob"));
        alice.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present { nick: nick("bob") }),
            Tick::new(0),
        );
        bob.on_message(
            &key(0xaa),
            &raw(&LobbyMessage::Present {
                nick: nick("alice"),
            }),
            Tick::new(0),
        );

        // Both press start before hearing the other.
        let from_alice = alice.propose().expect("valid");
        let from_bob = bob.propose().expect("valid");
        alice.on_message(&key(0xbb), &raw(&from_bob), Tick::new(0));
        bob.on_message(&key(0xaa), &raw(&from_alice), Tick::new(0));

        let alice_match = alice.started().expect("started");
        let bob_match = bob.started().expect("started");
        assert_eq!(
            alice_match.session_id, bob_match.session_id,
            "both must land on the same match, or they play different games"
        );
        assert_eq!(
            alice_match.players, bob_match.players,
            "simultaneous proposals converge on the same players"
        );
    }

    /// The single `Start` packet crosses a lossy path, so the lobby has to
    /// be able to say it again.
    #[test]
    fn a_started_match_can_be_announced_again_and_a_peer_that_missed_it_catches_up() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut alice = Lobby::new(key(0xaa), nick("alice"));
        let mut bob = Lobby::new(key(0xbb), nick("bob"));
        alice.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present { nick: nick("bob") }),
            Tick::new(0),
        );
        bob.on_message(
            &key(0xaa),
            &raw(&LobbyMessage::Present {
                nick: nick("alice"),
            }),
            Tick::new(0),
        );

        // Alice starts, and the packet is dropped on the way to Bob.
        alice.propose().expect("two distinct players");
        assert!(
            bob.started().is_none(),
            "bob has no match before the announcement"
        );

        let again = alice.announcement().expect("alice is in a match");
        bob.on_message(&key(0xaa), &raw(&again), Tick::new(0));
        assert_eq!(
            bob.started().map(|current| current.session_id),
            alice.started().map(|current| current.session_id),
            "a peer that missed the start catches up on the announcement",
        );
    }

    #[test]
    fn a_lobby_with_no_match_has_nothing_to_announce() {
        let _guard = ::habilis_network_test_tracing::init();
        let lobby = Lobby::new(key(0xaa), nick("alice"));
        assert_eq!(
            lobby.announcement(),
            None,
            "a lobby with no match has nothing to announce"
        );
    }

    /// Regression for a pair that could only be unwedged by restarting
    /// both sides: presence was insert-only, and a relaunched peer arrives
    /// under a brand-new public key, so the departed one lingered and the
    /// next match was proposed with a player who could never answer.
    /// Both peers must be able to say why, not just whichever one the
    /// lobby elected to propose.
    #[test]
    fn a_duplicate_nickname_is_reported_without_proposing() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        assert_eq!(lobby.blocker(), None, "alone is not blocked, just empty");

        lobby.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present {
                nick: nick("alice"),
            }),
            Tick::new(0),
        );
        assert_eq!(
            lobby.blocker(),
            Some(LobbyError::DuplicateNickname(nick("alice"))),
            "a duplicate nickname is reported as the blocker without a proposal"
        );
    }

    #[test]
    fn a_peer_that_stops_announcing_is_dropped() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        lobby.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present { nick: nick("bob") }),
            Tick::new(100),
        );
        assert_eq!(
            lobby.present().count(),
            2,
            "a peer that stops announcing is dropped"
        );

        lobby.expire(Tick::new(160), TickSpan::new(50));
        let present: Vec<_> = lobby.present().collect();
        assert_eq!(
            present,
            vec![(key(0xaa), nick("alice"))],
            "bob went quiet for longer than the ttl and must not be proposed into a match"
        );
    }

    #[test]
    fn a_peer_that_keeps_announcing_is_kept_and_we_never_expire_ourselves() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        for now in [Tick::new(100), Tick::new(150), Tick::new(200)] {
            lobby.on_message(
                &key(0xbb),
                &raw(&LobbyMessage::Present { nick: nick("bob") }),
                now,
            );
            lobby.expire(now, TickSpan::new(50));
        }
        assert_eq!(
            lobby.present().count(),
            2,
            "a peer that keeps announcing is kept"
        );

        // We never receive our own presence, so our stamp stays at 0 —
        // expiring on that would delete the one peer that is certainly here.
        lobby.expire(Tick::new(10_000), TickSpan::new(50));
        let present: Vec<_> = lobby.present().collect();
        assert_eq!(
            present,
            vec![(key(0xaa), nick("alice"))],
            "the peer that keeps announcing stays present"
        );
    }

    #[test]
    fn expiry_does_not_disturb_a_match_already_agreed() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        lobby.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present { nick: nick("bob") }),
            Tick::new(10),
        );
        let started = lobby.propose().expect("two distinct players");
        let before = lobby.started().cloned();

        lobby.expire(Tick::new(10_000), TickSpan::new(50));
        assert_eq!(
            lobby.started().cloned(),
            before,
            "a running match's roster is fixed at start; only the next proposal narrows"
        );
        let _ = started;
    }

    #[test]
    fn a_match_between_other_people_is_ignored() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut lobby = Lobby::new(key(0xaa), nick("alice"));
        lobby.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Start {
                epoch: Epoch::new(1),
                session_id: SessionId::new(1),
                players: vec![key(0xbb), key(0xcc)],
            }),
            Tick::new(0),
        );
        assert!(
            lobby.started().is_none(),
            "a match between other people is ignored"
        );
    }

    /// Rematch. The point of the epoch: the second match's id may well be
    /// *higher* than the first's, which the tie-break alone would refuse.
    #[test]
    fn a_second_proposal_supersedes_the_first_on_both_peers() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut alice = Lobby::new(key(0xaa), nick("alice"));
        let mut bob = Lobby::new(key(0xbb), nick("bob"));
        alice.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present { nick: nick("bob") }),
            Tick::new(0),
        );
        bob.on_message(
            &key(0xaa),
            &raw(&LobbyMessage::Present {
                nick: nick("alice"),
            }),
            Tick::new(0),
        );

        let first = alice.propose().expect("two distinct players");
        bob.on_message(&key(0xaa), &raw(&first), Tick::new(0));
        let first_id = alice.started().expect("started").session_id;

        let second = bob.propose().expect("still two players");
        alice.on_message(&key(0xbb), &raw(&second), Tick::new(0));

        for lobby in [&alice, &bob] {
            let current = lobby.started().expect("started");
            assert_eq!(
                current.epoch,
                Epoch::new(2),
                "a second proposal supersedes the first with the newer epoch"
            );
            assert_ne!(
                current.session_id, first_id,
                "a rematch must not reuse the previous match's id, or its \
                 stragglers would pass for live input"
            );
        }
        assert_eq!(
            alice.started().expect("started").session_id,
            bob.started().expect("started").session_id,
            "both peers hold the session of the second proposal"
        );
    }

    #[test]
    fn a_straggler_from_the_previous_match_never_resurrects_it() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut alice = Lobby::new(key(0xaa), nick("alice"));
        alice.on_message(
            &key(0xbb),
            &raw(&LobbyMessage::Present { nick: nick("bob") }),
            Tick::new(0),
        );
        let stale = alice.propose().expect("two distinct players");
        alice.propose().expect("rematch");
        let current = alice.started().expect("started").clone();

        alice.on_message(&key(0xbb), &raw(&stale), Tick::new(0));
        assert_eq!(
            alice.started(),
            Some(&current),
            "an epoch-1 packet arriving after epoch 2 must be ignored"
        );
    }
}
