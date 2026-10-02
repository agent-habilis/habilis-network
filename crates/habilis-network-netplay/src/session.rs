//! The session a game actually drives.
//!
//! Owns the rollback engine and one [`PeerProtocol`] per remote player, and
//! is the only place that touches the [`Transport`].
//!
//! The frame loop is:
//!
//! ```ignore
//! session.poll_remote_peers();              // drain the transport
//! for event in session.drain_events() { ... }
//! if session.state() != SessionState::Running { continue; }
//! session.add_local_input(my_input())?;
//! match session.advance_frame() {
//!     Ok(requests) => for request in requests { fulfil(request) },
//!     // Not a failure — the peer is behind. Render again and retry.
//!     Err(RollbackError::PredictionLimit) => {}
//!     Err(other) => return Err(other),
//! }
//! ```

use crate::config::Config;
use crate::error::RollbackError;
use crate::frame::{Frame, NULL_FRAME};
use crate::protocol::{PeerEvent, PeerProtocol, PeerState};
use crate::request::Request;
use crate::sync::Sync;
use crate::transport::{Message, Transport};

/// Whether the session is still handshaking or actually playing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// At least one peer has not completed its handshake. **Do not advance
    /// frames yet** — this is what makes every peer start together, without
    /// needing a shared wall clock.
    Synchronizing,
    /// Every peer is connected; the match is live.
    Running,
}

/// Something the application should know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<A> {
    /// A peer finished its handshake.
    Synchronized {
        /// Who.
        addr: A,
    },
    /// Every peer has synchronized; the match starts now.
    Running,
    /// A peer went silent past the timeout.
    Disconnected {
        /// Who.
        addr: A,
    },
    /// A peer's checksum disagrees with ours: the two are no longer
    /// simulating the same game. Unrecoverable — see
    /// [`RollbackError::Desync`].
    Desync {
        /// The frame that disagreed.
        frame: Frame,
        /// Our checksum.
        local: u128,
        /// Theirs.
        remote: u128,
    },
}

/// A peer-to-peer rollback session.
pub struct P2PSession<T: Config, X: Transport<T>> {
    sync: Sync<T>,
    peers: Vec<PeerProtocol<T>>,
    transport: X,
    local_handle: usize,
    state: SessionState,
    events: Vec<Event<T::Address>>,
    /// Frames to skip so peers can catch up, from [`TimeSync`].
    skip_frames: u32,
    /// Last frame we told peers a checksum for.
    last_checksum_frame: Frame,
    /// This frame's local input, held until the frame actually advances.
    ///
    /// Buffered rather than filed on receipt because `advance_frame` can
    /// legitimately decline to advance — the prediction window is full, or
    /// we are yielding pace to a peer — and the caller will then supply
    /// input for the *same* frame again next tick. Filing on receipt would
    /// add that frame twice.
    local_input: Option<T::Input>,
    /// Packets received for an address this match has no peer for. A session
    /// that never leaves `Synchronizing` while the transport is busy is
    /// either this or a nonce mismatch, and the two look identical from
    /// outside. Diagnostic only — nothing reads it but the log.
    unaddressed_drops: u64,
}

impl<T: Config, X: Transport<T>> std::fmt::Debug for P2PSession<T, X> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("P2PSession")
            .field("state", &self.state)
            .field("local_handle", &self.local_handle)
            .field("peers", &self.peers)
            .field("sync", &self.sync)
            .finish_non_exhaustive()
    }
}

impl<T: Config, X: Transport<T>> P2PSession<T, X> {
    /// Build a session.
    ///
    /// `players` is every participant's address **in handle order**, and
    /// every peer in the match must construct it with the identical list —
    /// handles are positional, so a disagreement files inputs against the
    /// wrong player. Sorting the roster by address is the usual way to get
    /// that for free.
    ///
    /// `magic` scopes this session's packets; peers that pick different
    /// values is fine and expected, but reusing one across matches is not
    /// (see [`Message::magic`]).
    ///
    /// # Errors
    /// [`RollbackError::InvalidPlayer`] if `local_handle` is not a valid
    /// index into `players`.
    pub fn new(
        players: Vec<T::Address>,
        local_handle: usize,
        transport: X,
        max_prediction: usize,
        input_delay: usize,
        magic: u32,
    ) -> Result<Self, RollbackError> {
        if local_handle >= players.len() {
            return Err(RollbackError::InvalidPlayer(local_handle));
        }
        let num_players = players.len();
        tracing::debug!(
            local_handle,
            num_players,
            magic,
            input_delay,
            max_prediction,
            "session built, synchronizing"
        );
        let peers = players
            .into_iter()
            .enumerate()
            .filter(|(handle, _)| *handle != local_handle)
            .map(|(handle, addr)| PeerProtocol::new(addr, handle, magic))
            .collect();
        Ok(Self {
            sync: Sync::new(num_players, max_prediction, input_delay, local_handle),
            peers,
            transport,
            local_handle,
            state: SessionState::Synchronizing,
            events: Vec::new(),
            skip_frames: 0,
            last_checksum_frame: NULL_FRAME,
            local_input: None,
            unaddressed_drops: 0,
        })
    }

    /// Whether the match has started. Frames must not be advanced until this
    /// is [`SessionState::Running`].
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// The frame the simulation is at.
    #[must_use]
    pub fn current_frame(&self) -> Frame {
        self.sync.current_frame()
    }

    /// Take everything that has happened since the last call.
    pub fn drain_events(&mut self) -> Vec<Event<T::Address>> {
        std::mem::take(&mut self.events)
    }

    /// Drain the transport, apply what arrived, and send what is due.
    ///
    /// Call once per frame, before advancing. Cheap when nothing has
    /// arrived.
    pub fn poll_remote_peers(&mut self) {
        let current = self.sync.current_frame();
        let mut replies: Vec<(T::Address, Message<T::Input>)> = Vec::new();

        let mut unaddressed = 0u32;
        for (addr, message) in self.transport.receive_all() {
            let Some(peer) = self.peers.iter_mut().find(|peer| peer.addr == addr) else {
                // Not a participant in this match. Counted rather than
                // ignored: if the roster's addresses and the transport's
                // disagree, *every* packet lands here and the session sits in
                // `Synchronizing` while traffic flows both ways.
                unaddressed = unaddressed.saturating_add(1);
                continue;
            };
            let handle = peer.handle;
            let mut peer_replies = Vec::new();
            let (inputs, events) = peer.on_message(&message, &mut peer_replies);
            replies.extend(peer_replies.into_iter().map(|reply| (addr.clone(), reply)));

            for (frame, input) in inputs {
                // An out-of-range handle is impossible here — handles come
                // from our own construction — so this cannot fail.
                let _ = self.sync.add_remote_input(handle, frame, input);
            }
            self.record_events(&addr, events);
        }

        if unaddressed > 0 {
            self.unaddressed_drops = self
                .unaddressed_drops
                .saturating_add(u64::from(unaddressed));
            // Powers of two: one poll's worth says little, a climbing total
            // while the state stays `Synchronizing` says everything.
            if self.unaddressed_drops.is_power_of_two() {
                tracing::debug!(
                    dropped = self.unaddressed_drops,
                    state = ?self.state,
                    "packets arrived for an address in no peer of this match"
                );
            }
        }

        for (addr, message) in &replies {
            self.transport.send_to(message, addr);
        }

        let mut outgoing: Vec<(T::Address, Message<T::Input>)> = Vec::new();
        let mut skip = 0;
        // Events are collected rather than recorded inline: `record_events`
        // takes `&mut self`, which cannot coexist with the `&mut self.peers`
        // this loop holds.
        let mut peer_events: Vec<(T::Address, Vec<PeerEvent>)> = Vec::new();
        for peer in &mut self.peers {
            let (messages, events) = peer.tick(current);
            let addr = peer.addr.clone();
            outgoing.extend(messages.into_iter().map(|message| (addr.clone(), message)));
            skip = skip.max(peer.recommend_skip());
            peer_events.push((addr, events));
        }
        for (addr, events) in peer_events {
            self.record_events(&addr, events);
        }
        self.skip_frames = skip;
        for (addr, message) in &outgoing {
            self.transport.send_to(message, addr);
        }

        self.refresh_state();
        self.refresh_confirmed_frame();
    }

    fn record_events(&mut self, addr: &T::Address, events: Vec<PeerEvent>) {
        for event in events {
            self.events.push(match event {
                PeerEvent::Synchronized => Event::Synchronized { addr: addr.clone() },
                PeerEvent::Disconnected => Event::Disconnected { addr: addr.clone() },
                PeerEvent::Desync {
                    frame,
                    local,
                    remote,
                } => Event::Desync {
                    frame,
                    local,
                    remote,
                },
            });
        }
    }

    /// Promote to `Running` once every peer has handshaken.
    fn refresh_state(&mut self) {
        if self.state == SessionState::Running {
            return;
        }
        let all_ready = self
            .peers
            .iter()
            .all(|peer| peer.state() == PeerState::Running);
        if all_ready {
            tracing::debug!(peers = self.peers.len(), "every peer synchronized, running");
            self.state = SessionState::Running;
            self.events.push(Event::Running);
        }
    }

    /// The highest frame every player has a real input for.
    fn refresh_confirmed_frame(&mut self) {
        let Some(confirmed) = self
            .peers
            .iter()
            .filter(|peer| peer.state() != PeerState::Disconnected)
            .map(PeerProtocol::last_received_frame)
            .min()
        else {
            // No live peers: everything we have simulated is confirmed.
            self.sync.confirm_through(self.sync.current_frame());
            return;
        };
        if confirmed != NULL_FRAME {
            self.sync.confirm_through(confirmed);
        }
    }

    /// Supply this peer's input for the current frame.
    ///
    /// Safe to call repeatedly for the same frame — the latest value wins,
    /// which is what makes retrying after a declined `advance_frame`
    /// straightforward.
    ///
    /// # Errors
    /// Never currently; the signature returns `Result` so that a future
    /// version can reject input while not `Running` without a breaking
    /// change.
    pub fn add_local_input(&mut self, input: T::Input) -> Result<(), RollbackError> {
        self.local_input = Some(input);
        Ok(())
    }

    /// Advance one frame, rolling back first if a prediction turned out
    /// wrong. Fulfil the returned requests in order.
    ///
    /// # Errors
    /// [`RollbackError::PredictionLimit`] if the session is too far ahead of
    /// confirmation, or is deliberately yielding so a peer can catch up. Not
    /// a failure: render the same frame again and retry next tick.
    pub fn advance_frame(&mut self) -> Result<Vec<Request<T>>, RollbackError> {
        if self.state != SessionState::Running {
            return Err(RollbackError::PredictionLimit);
        }
        if self.skip_frames > 0 {
            self.skip_frames -= 1;
            return Err(RollbackError::PredictionLimit);
        }

        let Some(input) = self.local_input else {
            return Err(RollbackError::MissingLocalInput);
        };
        // File it only now that the frame is definitely advancing, and only
        // if the prediction window allows — on `Err` the buffered input is
        // left in place for the retry.
        let frame = self.sync.add_local_input(self.local_handle, input)?;
        self.local_input = None;
        if frame != NULL_FRAME {
            for peer in &mut self.peers {
                peer.send_input(frame, input);
            }
        }

        let mut requests = Vec::new();
        // Undo any frame a late input has invalidated before adding more.
        self.sync.check_simulation(&mut requests);
        requests.push(self.sync.save_current_state());
        requests.push(Request::AdvanceFrame {
            inputs: self.sync.synchronize_inputs(),
        });
        self.sync.advance_frame();
        Ok(requests)
    }

    /// Publish the checksum of a confirmed frame so peers can compare.
    ///
    /// Call after fulfilling requests, with the last confirmed frame. Purely
    /// optional, and purely diagnostic — but it is the *only* thing that
    /// turns a silent divergence into a reported one.
    pub fn publish_checksum(&mut self) {
        let frame = self.sync.last_confirmed_frame();
        if frame == NULL_FRAME || frame == self.last_checksum_frame {
            return;
        }
        let Some(cell) = self.sync.saved_state(frame) else {
            return;
        };
        let Some(checksum) = cell.checksum() else {
            return;
        };
        self.last_checksum_frame = frame;

        let mut outgoing = Vec::new();
        for peer in &mut self.peers {
            outgoing.push((peer.addr.clone(), peer.checksum_message(frame, checksum)));
        }
        for (addr, message) in &outgoing {
            self.transport.send_to(message, addr);
        }
    }
}
