/// Wakeup attribution for the idle-cost work: one counter per `select!` arm,
/// reported as a delta on each `mesh census` line and reset there.
///
/// Plain `u64`, not atomics — the event loop owns `&mut EventLoopState`, so a
/// bump is an increment with no synchronization. That matters more than it
/// looks: the arms being measured fire up to 150×/min, and the cheapest thing
/// that could observe them (a `debug!` per tick) costs a write per wakeup and
/// would price its own instrumentation into the measurement.
///
/// Counting arms rather than timers is deliberate. It splits timer work from
/// inbound traffic, which is the split that says whether an idle daemon is
/// paying for its own housekeeping or for the peers talking to it.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct IdleCounters {
    /// Every loop iteration, whichever arm won. The denominator for the rest.
    pub wakeups: u64,
    pub prune: u64,
    pub alive: u64,
    pub sweep: u64,
    pub heal: u64,
    pub reclaim: u64,
    pub antientropy: u64,
    pub state_refresh: u64,
    pub linkstate: u64,
    /// Arms driven by something other than a maintenance timer — inbound
    /// gossip/unicast, IPC, HTTP, deadlines. Summed rather than split per arm:
    /// on an idle daemon this should read 0, and a non-zero value means the
    /// run was not idle, which is the only bit worth reporting.
    pub external: u64,
    /// Signed frames put on the wire by a maintenance tick. The direct cost
    /// driver behind `user` CPU: each one is an Ed25519 signature plus a
    /// serialization.
    pub broadcasts: u64,
    /// Messages a digest answer put in the resend outbox.
    pub resent: u64,
    /// Messages a digest answer could not put there because it was full: the
    /// next digest asks for them again.
    pub resend_dropped: u64,
}

impl IdleCounters {
    /// Read the counters and zero them, so each census line carries the
    /// interval's own work rather than a running total a reader has to
    /// difference (and that a rotated log would corrupt).
    pub(crate) fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}
