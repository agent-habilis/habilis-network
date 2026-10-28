/// The answerer's pre-attach buffer — see the buffering handler in [`answer`](super::answer).
///
/// Bounded at [`IN_QUEUE`](crate::IN_QUEUE), the inbound queue's
/// own capacity: at handoff the whole buffer is `try_send`-delivered into a
/// queue of exactly that many slots, so anything held past it could never be
/// delivered — an unbounded buffer only grew browser memory for as long as
/// the signal round dawdled, and the excess was dropped at attach anyway.
/// When full, new datagrams are refused rather than old ones evicted: the
/// QUIC Initial and handshake flights arrive first, and losing those costs
/// the connection where losing a later datagram costs a retransmit.
pub(crate) struct PreAttachBacklog {
    datagrams: Vec<Vec<u8>>,
    dropped: usize,
}

impl PreAttachBacklog {
    pub(crate) fn new() -> Self {
        Self {
            datagrams: Vec::new(),
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, bytes: Vec<u8>) {
        if self.datagrams.len() >= crate::IN_QUEUE {
            self.dropped += 1;
            return;
        }
        self.datagrams.push(bytes);
    }

    /// Take everything held, plus how many datagrams were refused over the
    /// cap. The buffer is empty afterwards, so it cannot deliver twice.
    pub(crate) fn take(&mut self) -> (Vec<Vec<u8>>, usize) {
        (
            std::mem::take(&mut self.datagrams),
            std::mem::take(&mut self.dropped),
        )
    }
}
