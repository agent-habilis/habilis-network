use std::collections::HashMap;
use std::time::Duration;

use n0_future::time::Instant as TokioInstant;

use crate::protocol::{Message, MessageId, Nickname};

use tokio::sync::oneshot;

/// An in-flight RTT round. [`start_ping_round`](crate::ops::start_ping_round), which a driver
/// calls, arms it and sends the first probe at `t1`; the event loop sends the second, a fresh
/// ping, at the middle of the window, so that a probe lost on the way (the peer was not linked
/// yet, a dropped frame) is made up for. A pong names the probe it answers, so its RTT is read
/// from that probe's send, and a pong that names no probe of this round is dropped. A peer's
/// first pong is the one kept. The price is one more broadcast per round and one more pong per
/// peer. The round is emitted and cleared at `deadline`.
#[derive(Debug)]
pub(crate) struct PingRound {
    pub(crate) t1: TokioInstant,
    pub(crate) deadline: TokioInstant,
    /// The probes of the round, by message id, with the instant each left.
    pub(crate) probes: HashMap<MessageId, TokioInstant>,
    /// The RTT of the first pong of each peer.
    pub(crate) pongs: HashMap<Nickname, Duration>,
    /// When set (the in-process `ping` request), the finalized RTT rows are
    /// delivered here instead of only emitted as a `ping_report` event — the
    /// in-process driver has no event stream to read the report from. `None`
    /// for the CLI/IPC path, which consumes the event.
    pub(crate) response: Option<oneshot::Sender<Vec<(Nickname, u64)>>>,
}

impl PingRound {
    /// A round whose first probe is `first`, sent at `t1`.
    pub(crate) fn new(
        first: &Message,
        t1: TokioInstant,
        deadline: TokioInstant,
        response: Option<oneshot::Sender<Vec<(Nickname, u64)>>>,
    ) -> Self {
        Self {
            t1,
            deadline,
            probes: HashMap::from([(first.id.clone(), t1)]),
            pongs: HashMap::new(),
            response,
        }
    }

    /// When the second probe is due: the middle of the window, once.
    pub(crate) fn second_probe_at(&self) -> Option<TokioInstant> {
        (self.probes.len() < 2).then(|| self.t1 + self.deadline.duration_since(self.t1) / 2)
    }

    /// Record the pong of `peer` that answers `probe`, arriving at `arrival`: the RTT is read from
    /// that probe's send, and the first pong of a peer is kept. `false` when `probe` is no probe
    /// of this round.
    pub(crate) fn record_pong(
        &mut self,
        peer: Nickname,
        probe: &MessageId,
        arrival: TokioInstant,
    ) -> bool {
        let Some(sent) = self.probes.get(probe) else {
            return false;
        };
        let rtt = arrival.duration_since(*sent);
        self.pongs.entry(peer).or_insert(rtt);
        true
    }
}
