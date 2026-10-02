//! One remote peer: handshake, input exchange, liveness.
//!
//! A session owns one of these per remote player. It is a pure state
//! machine — it never touches the transport itself, it produces outgoing
//! [`Message`]s for the session to send and consumes incoming ones. That
//! keeps it testable without a socket and keeps all the I/O in one place.
//!
//! Lifecycle: [`PeerState::Syncing`] until a handshake completes in both
//! directions, then [`PeerState::Running`] for the match, then
//! [`PeerState::Disconnected`] if the peer goes quiet past the timeout.

use crate::config::Config;
use crate::frame::{Frame, NULL_FRAME};
use crate::time_sync::{TimeSync, frame_advantage};
use crate::transport::{Body, InputPacket, Message};

/// Handshake round-trips before a peer is considered reachable. More than
/// one because a single reply only proves the path worked once.
const SYNC_ROUNDTRIPS: u32 = 5;

/// Ticks between resends of an unanswered sync request.
///
/// A request used to go out on every tick until it was answered, which is a
/// feedback loop: the peer echoes each one, only the reply matching the
/// current token advances the handshake, and the rest are discarded. When the
/// loop ticks faster than the transport drains — a slow machine, a busy
/// runner — the queue grows faster than the useful reply can reach the front,
/// and the handshake stops converging at all. Measured on a two-peer
/// loopback match: 4 discarded replies per peer on a developer laptop, 256 on
/// a shared CI runner, and two runs that never finished inside 60s.
///
/// Eight ticks bounds the outstanding requests without slowing the handshake
/// noticeably: a round trip that completes is answered immediately, because
/// [`PeerProtocol::on_message`] clears the counter when the token rotates.
const SYNC_RESEND_EVERY_TICKS: u32 = 8;

/// Ticks without hearing anything before a peer is declared gone.
///
/// Generous on purpose: a browser tab that is backgrounded has its
/// `requestAnimationFrame` suspended entirely, so a peer can legitimately go
/// silent for a long time and come back. Dropping them eagerly would end
/// matches that were merely paused.
const DISCONNECT_TIMEOUT_TICKS: u32 = 600;

/// Ticks between quality reports.
const QUALITY_REPORT_INTERVAL: u32 = 60;

/// Where a peer is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Handshaking. No inputs are exchanged yet.
    Syncing,
    /// Handshake done; exchanging inputs.
    Running,
    /// Silent past the timeout.
    Disconnected,
}

/// Something worth telling the application about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerEvent {
    /// The handshake completed and this peer is now exchanging inputs.
    Synchronized,
    /// The peer went silent past the timeout.
    Disconnected,
    /// The peer's checksum for a frame disagrees with ours.
    Desync {
        /// The frame that disagreed.
        frame: Frame,
        /// Our checksum.
        local: u128,
        /// Theirs.
        remote: u128,
    },
}

/// One remote peer's connection.
pub(crate) struct PeerProtocol<T: Config> {
    pub(crate) addr: T::Address,
    /// Which player handle this peer drives.
    pub(crate) handle: usize,
    state: PeerState,
    /// Our session nonce, stamped on everything we send.
    magic: u32,
    /// Theirs, learned from the first reply to one of our own sync requests;
    /// anything else is stale.
    remote_magic: Option<u32>,
    /// Handshake round-trips still owed.
    roundtrips_left: u32,
    /// Token echoed in the current outstanding sync request.
    sync_token: u32,
    /// Ticks since the outstanding sync request went out, so it is resent on
    /// a cadence rather than every tick. `0` means "send one now".
    since_sync_request: u32,
    /// Highest frame we have a real input from this peer for.
    last_received_frame: Frame,
    /// Highest frame *they* have acked from us — everything past this is
    /// resent for redundancy.
    last_acked_frame: Frame,
    /// Our own inputs not yet known to have arrived, oldest first.
    pending: Vec<(Frame, T::Input)>,
    /// Ticks since we last heard anything.
    silent_ticks: u32,
    /// Ticks since the last quality report went out.
    since_quality_report: u32,
    /// Their self-reported frame advantage.
    remote_advantage: i32,
    time_sync: TimeSync,
    /// Checksums we have advertised, so a mismatch can be attributed.
    local_checksums: Vec<(Frame, u128)>,
    /// Packets discarded for carrying a foreign session nonce, sync replies
    /// discarded for echoing a spent token, and other packets discarded
    /// before the peer's nonce is latched. All are silent drops that leave a
    /// session stuck in `Synchronizing` with traffic flowing both ways, which
    /// is indistinguishable from a dead peer without a count. Diagnostic
    /// only — nothing reads them but the log.
    foreign_magic_drops: u32,
    stale_token_drops: u32,
    unlatched_drops: u32,
}

impl<T: Config> std::fmt::Debug for PeerProtocol<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerProtocol")
            .field("addr", &self.addr)
            .field("handle", &self.handle)
            .field("state", &self.state)
            .field("last_received_frame", &self.last_received_frame)
            .field("last_acked_frame", &self.last_acked_frame)
            .finish_non_exhaustive()
    }
}

impl<T: Config> PeerProtocol<T> {
    pub(crate) fn new(addr: T::Address, handle: usize, magic: u32) -> Self {
        Self {
            addr,
            handle,
            state: PeerState::Syncing,
            magic,
            remote_magic: None,
            roundtrips_left: SYNC_ROUNDTRIPS,
            // Derived from our own nonce so the first request is answerable
            // without any shared randomness.
            sync_token: magic ^ 0x5bf0_3635,
            since_sync_request: 0,
            last_received_frame: NULL_FRAME,
            last_acked_frame: NULL_FRAME,
            pending: Vec::new(),
            silent_ticks: 0,
            since_quality_report: 0,
            remote_advantage: 0,
            time_sync: TimeSync::default(),
            local_checksums: Vec::new(),
            foreign_magic_drops: 0,
            stale_token_drops: 0,
            unlatched_drops: 0,
        }
    }

    pub(crate) fn state(&self) -> PeerState {
        self.state
    }

    pub(crate) fn last_received_frame(&self) -> Frame {
        self.last_received_frame
    }

    /// How many frames to skip so this peer can catch up; `0` to keep going.
    pub(crate) fn recommend_skip(&self) -> u32 {
        if self.state == PeerState::Running {
            self.time_sync.recommend_skip()
        } else {
            0
        }
    }

    /// Queue one of our own inputs for delivery.
    pub(crate) fn send_input(&mut self, frame: Frame, input: T::Input) {
        self.pending.push((frame, input));
    }

    /// Record a confirmed-state checksum and build the packet advertising
    /// it, so the peer can compare against its own.
    ///
    /// Records as well as sends: the comparison happens on whichever side
    /// receives the *other's* value, so both need their own on file.
    pub(crate) fn checksum_message(&mut self, frame: Frame, checksum: u128) -> Message<T::Input> {
        self.local_checksums.push((frame, checksum));
        // Only recent frames can still be contested.
        if self.local_checksums.len() > 64 {
            self.local_checksums.remove(0);
        }
        self.wrap(Body::Checksum { frame, checksum })
    }

    /// Everything to send this tick, and any events for the application.
    pub(crate) fn tick(
        &mut self,
        current_frame: Frame,
    ) -> (Vec<Message<T::Input>>, Vec<PeerEvent>) {
        let mut out = Vec::new();
        let mut events = Vec::new();

        self.silent_ticks = self.silent_ticks.saturating_add(1);
        if self.state != PeerState::Disconnected && self.silent_ticks > DISCONNECT_TIMEOUT_TICKS {
            tracing::debug!(
                handle = self.handle,
                silent_ticks = self.silent_ticks,
                was = ?self.state,
                "peer went silent past the disconnect timeout"
            );
            self.state = PeerState::Disconnected;
            events.push(PeerEvent::Disconnected);
            return (out, events);
        }

        match self.state {
            PeerState::Syncing => {
                // Only when one is due: see `SYNC_RESEND_EVERY_TICKS` for why
                // sending on every tick stops the handshake converging.
                if self.since_sync_request == 0 {
                    out.push(self.wrap(Body::SyncRequest {
                        token: self.sync_token,
                    }));
                }
                self.since_sync_request = (self.since_sync_request + 1) % SYNC_RESEND_EVERY_TICKS;
            }
            PeerState::Running => {
                out.extend(self.input_message());
                self.since_quality_report = self.since_quality_report.saturating_add(1);
                if self.since_quality_report >= QUALITY_REPORT_INTERVAL {
                    self.since_quality_report = 0;
                    let advantage = frame_advantage(current_frame, self.last_received_frame)
                        .clamp(i32::from(i8::MIN), i32::from(i8::MAX));
                    out.push(self.wrap(Body::QualityReport {
                        // Clamped to i8's range immediately above, so this
                        // conversion cannot fail.
                        frame_advantage: i8::try_from(advantage).unwrap_or(0),
                        ping: u64::from(self.silent_ticks),
                    }));
                }
                self.time_sync.advance(
                    frame_advantage(current_frame, self.last_received_frame),
                    self.remote_advantage,
                );
            }
            PeerState::Disconnected => {}
        }
        (out, events)
    }

    /// The input packet for this tick, if there is anything unacked.
    fn input_message(&mut self) -> Option<Message<T::Input>> {
        // Drop what the peer has confirmed; resend everything else.
        self.pending
            .retain(|(frame, _)| *frame > self.last_acked_frame);
        let start_frame = self.pending.first().map(|(frame, _)| *frame)?;
        let inputs: Vec<T::Input> = self.pending.iter().map(|(_, input)| *input).collect();
        Some(self.wrap(Body::Input(InputPacket {
            start_frame,
            ack_frame: self.last_received_frame,
            inputs,
        })))
    }

    fn wrap(&self, body: Body<T::Input>) -> Message<T::Input> {
        Message {
            magic: self.magic,
            body,
        }
    }

    /// Count a sync reply that echoes a spent token. Every request is resent
    /// until it is answered, so a few are normal. A count that keeps
    /// climbing while `roundtrips_left` does not is the handshake failing to
    /// converge.
    fn note_stale_reply(&mut self, token: u32) {
        self.stale_token_drops = self.stale_token_drops.saturating_add(1);
        if self.stale_token_drops.is_power_of_two() {
            tracing::debug!(
                handle = self.handle,
                expected = self.sync_token,
                received = token,
                roundtrips_left = self.roundtrips_left,
                drops = self.stale_token_drops,
                "dropped a sync reply echoing a spent token"
            );
        }
    }

    /// Whether `message` belongs to the peer's current session. The peer's
    /// nonce is latched only on a reply to this session's own request: the
    /// first packet to arrive can be a leftover from the peer's previous
    /// match, and latching that would drop every packet of its current
    /// session as foreign. Until then, requests are still answered while this
    /// session is syncing, so the peer's handshake is not held up by ours.
    ///
    /// Nothing before the latch resets the silence timer, not even an
    /// answered request. A peer whose replies never reach us is therefore
    /// declared disconnected after [`DISCONNECT_TIMEOUT_TICKS`], instead of
    /// staying alive in a handshake that cannot finish.
    fn admit(&mut self, message: &Message<T::Input>, replies: &mut Vec<Message<T::Input>>) -> bool {
        match self.remote_magic {
            Some(known) if known != message.magic => {
                self.foreign_magic_drops = self.foreign_magic_drops.saturating_add(1);
                // Powers of two: the drop that matters is the first one, and a
                // wedged handshake produces thousands a second.
                if self.foreign_magic_drops.is_power_of_two() {
                    tracing::debug!(
                        handle = self.handle,
                        expected = known,
                        received = message.magic,
                        drops = self.foreign_magic_drops,
                        "dropped a packet from a foreign session"
                    );
                }
                false
            }
            Some(_) => true,
            None => match &message.body {
                Body::SyncReply { token }
                    if self.state == PeerState::Syncing && *token == self.sync_token =>
                {
                    tracing::debug!(
                        handle = self.handle,
                        remote_magic = message.magic,
                        "latched the peer's session nonce"
                    );
                    self.remote_magic = Some(message.magic);
                    true
                }
                Body::SyncRequest { token } => {
                    // A disconnected session can never latch, so an answer
                    // would only start a handshake it cannot finish.
                    if self.state == PeerState::Syncing {
                        replies.push(self.wrap(Body::SyncReply { token: *token }));
                    }
                    false
                }
                Body::SyncReply { token } => {
                    self.note_stale_reply(*token);
                    false
                }
                Body::Input(_)
                | Body::InputAck { .. }
                | Body::QualityReport { .. }
                | Body::QualityReply { .. }
                | Body::KeepAlive
                | Body::Checksum { .. } => {
                    self.unlatched_drops = self.unlatched_drops.saturating_add(1);
                    if self.unlatched_drops.is_power_of_two() {
                        tracing::debug!(
                            handle = self.handle,
                            received = message.magic,
                            drops = self.unlatched_drops,
                            "dropped a packet before the peer answered this session's handshake"
                        );
                    }
                    false
                }
            },
        }
    }

    /// Handle a packet from this peer.
    ///
    /// Returns any inputs to feed the rollback engine, as
    /// `(frame, input)` pairs, plus events for the application. Stale
    /// packets — wrong nonce — are dropped silently.
    pub(crate) fn on_message(
        &mut self,
        message: &Message<T::Input>,
        replies: &mut Vec<Message<T::Input>>,
    ) -> (Vec<(Frame, T::Input)>, Vec<PeerEvent>) {
        let mut inputs = Vec::new();
        let mut events = Vec::new();

        if !self.admit(message, replies) {
            return (inputs, events);
        }
        self.silent_ticks = 0;

        match &message.body {
            Body::SyncRequest { token } => {
                replies.push(self.wrap(Body::SyncReply { token: *token }));
            }
            Body::SyncReply { token } => {
                if self.state == PeerState::Syncing && *token == self.sync_token {
                    self.roundtrips_left = self.roundtrips_left.saturating_sub(1);
                    // Fresh token each round so a duplicated reply cannot
                    // advance the handshake twice.
                    self.sync_token = self.sync_token.wrapping_mul(1_664_525).wrapping_add(1);
                    // The next round's request is due now, not in a cadence's
                    // time: this reply is the proof the last one arrived.
                    self.since_sync_request = 0;
                    tracing::debug!(
                        handle = self.handle,
                        roundtrips_left = self.roundtrips_left,
                        "sync round trip"
                    );
                    if self.roundtrips_left == 0 {
                        self.state = PeerState::Running;
                        events.push(PeerEvent::Synchronized);
                    }
                } else if self.state == PeerState::Syncing {
                    self.note_stale_reply(*token);
                }
            }
            Body::Input(packet) => {
                self.last_acked_frame = self.last_acked_frame.max(packet.ack_frame);
                // A run that starts past the next frame we need would leave a
                // hole, and the rollback engine requires contiguity. Drop it
                // and wait — the sender resends everything unacked, so the
                // missing frames are already on their way.
                //
                // The *first* packet is exempt. A sender with input delay
                // files its first real input at frame `delay`, having filled
                // the frames below it with the default input, so its first
                // packet legitimately starts above zero. That is not a hole:
                // our own queue fills the same frames the same way through
                // the same code path, so both sides agree on them.
                if self.last_received_frame != NULL_FRAME
                    && packet.start_frame > self.last_received_frame + 1
                {
                    tracing::trace!(
                        handle = self.handle,
                        start_frame = packet.start_frame,
                        last_received_frame = self.last_received_frame,
                        "dropped an input packet that would leave a hole"
                    );
                    return (inputs, events);
                }
                for (offset, input) in packet.inputs.iter().enumerate() {
                    let frame = packet.start_frame + Frame::try_from(offset).unwrap_or(Frame::MAX);
                    // Only what we have not already filed — resends are the
                    // norm, not an anomaly.
                    if frame > self.last_received_frame {
                        inputs.push((frame, *input));
                    }
                }
                if let Some((frame, _)) = inputs.last() {
                    self.last_received_frame = *frame;
                }
                replies.push(self.wrap(Body::InputAck {
                    ack_frame: self.last_received_frame,
                }));
            }
            Body::InputAck { ack_frame } => {
                self.last_acked_frame = self.last_acked_frame.max(*ack_frame);
            }
            Body::QualityReport {
                frame_advantage,
                ping,
            } => {
                self.remote_advantage = i32::from(*frame_advantage);
                replies.push(self.wrap(Body::QualityReply { pong: *ping }));
            }
            Body::QualityReply { .. } | Body::KeepAlive => {}
            Body::Checksum { frame, checksum } => {
                if let Some((_, ours)) = self.local_checksums.iter().find(|(seen, _)| seen == frame)
                    && ours != checksum
                {
                    events.push(PeerEvent::Desync {
                        frame: *frame,
                        local: *ours,
                        remote: *checksum,
                    });
                }
            }
        }
        (inputs, events)
    }
}

#[cfg(test)]
mod tests {
    use super::{Body, PeerProtocol, PeerState, SYNC_RESEND_EVERY_TICKS};
    use crate::frame::NULL_FRAME;
    use crate::testutil::TestGame;
    use crate::transport::Message;

    fn syncing_peer() -> PeerProtocol<TestGame> {
        PeerProtocol::<TestGame>::new("peer".to_owned(), 1, 0xabcd_1234)
    }

    /// How many sync requests one tick produced.
    fn requests(peer: &mut PeerProtocol<TestGame>) -> usize {
        let (out, _) = peer.tick(NULL_FRAME);
        out.iter()
            .filter(|message| matches!(message.body, Body::SyncRequest { .. }))
            .count()
    }

    /// A request on every tick is a feedback loop: the peer echoes each one,
    /// every reply but the newest is discarded, and on a machine that ticks
    /// faster than the transport drains the handshake stops converging. See
    /// [`SYNC_RESEND_EVERY_TICKS`].
    #[test]
    fn a_syncing_peer_resends_on_a_cadence_not_every_tick() {
        let mut peer = syncing_peer();
        assert_eq!(requests(&mut peer), 1, "the first request goes out at once");
        for tick in 1..SYNC_RESEND_EVERY_TICKS {
            assert_eq!(
                requests(&mut peer),
                0,
                "tick {tick} resent while one was still outstanding"
            );
        }
        assert_eq!(requests(&mut peer), 1, "the unanswered request is resent");
    }

    /// The cadence is a ceiling on *unanswered* requests, not a floor on the
    /// handshake: an answered round trip is proof the path works, so the next
    /// request is due immediately rather than a cadence later.
    #[test]
    fn an_answered_round_trip_releases_the_next_request_at_once() {
        let mut peer = syncing_peer();
        let (out, _) = peer.tick(NULL_FRAME);
        let Some(Body::SyncRequest { token }) = out.first().map(|message| message.body.clone())
        else {
            panic!("a syncing peer opens with a request")
        };

        // Silent while the request is outstanding.
        assert_eq!(requests(&mut peer), 0);

        let mut replies = Vec::new();
        peer.on_message(
            &Message {
                magic: peer.magic,
                body: Body::SyncReply { token },
            },
            &mut replies,
        );
        assert_eq!(
            requests(&mut peer),
            1,
            "the next round trip must not wait out the resend cadence"
        );
        assert_eq!(peer.state(), PeerState::Syncing, "one trip of several");
    }

    /// A rematch builds a fresh session while the peer may still be sending
    /// for the previous match. A leftover packet that happens to arrive
    /// first must not become the session this one pairs with: it would drop
    /// every packet of the peer's new session as foreign, forever.
    #[test]
    fn a_leftover_packet_from_the_previous_match_does_not_block_the_handshake() {
        let mut peer = syncing_peer();
        let previous_match = peer.magic.wrapping_add(1);
        let mut replies = Vec::new();
        peer.on_message(
            &Message {
                magic: previous_match,
                body: Body::Input(crate::transport::InputPacket {
                    start_frame: 40,
                    ack_frame: 39,
                    inputs: vec![crate::testutil::TestInput(7)],
                }),
            },
            &mut replies,
        );

        for _ in 0..super::SYNC_ROUNDTRIPS {
            let (out, _) = peer.tick(NULL_FRAME);
            // An answered trip releases the next request at once, so a
            // missing one means the last reply was dropped.
            let Some(Body::SyncRequest { token }) = out.first().map(|message| message.body.clone())
            else {
                break;
            };
            peer.on_message(
                &Message {
                    // The library lets each peer pick its own nonce.
                    magic: peer.magic ^ 0xffff,
                    body: Body::SyncReply { token },
                },
                &mut replies,
            );
        }

        assert_eq!(
            peer.state(),
            PeerState::Running,
            "the handshake with the peer's current session never completed"
        );
    }

    /// A session that gave up on its peer must not keep answering sync
    /// requests: it can never latch any more, so an answer only invites a
    /// handshake it cannot finish.
    #[test]
    fn a_disconnected_peer_that_never_latched_stops_answering_requests() {
        let mut peer = syncing_peer();
        for _ in 0..=super::DISCONNECT_TIMEOUT_TICKS {
            peer.tick(NULL_FRAME);
        }
        assert_eq!(peer.state(), PeerState::Disconnected);

        let mut replies = Vec::new();
        peer.on_message(
            &Message {
                magic: peer.magic,
                body: Body::SyncRequest { token: 1 },
            },
            &mut replies,
        );

        assert!(replies.is_empty(), "answered a request after giving up");
    }

    /// Before the latch, a reply that echoes a spent token is the same sign
    /// of a wedged handshake as after it, and is counted the same way.
    #[test]
    fn a_stale_reply_before_the_latch_is_counted() {
        let mut peer = syncing_peer();
        let mut replies = Vec::new();
        peer.on_message(
            &Message {
                magic: peer.magic,
                body: Body::SyncReply {
                    token: peer.sync_token.wrapping_add(1),
                },
            },
            &mut replies,
        );

        assert_eq!(peer.stale_token_drops, 1);
    }
}
