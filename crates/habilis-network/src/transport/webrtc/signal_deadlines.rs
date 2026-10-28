//! The deadlines of one signalling exchange.

use super::consts::{SIGNAL_EXCHANGE_DEADLINE, SIGNAL_ROUND_DEADLINE};

/// The deadlines one round runs under.
///
/// Injectable so tests need not wait 45 real seconds. A `util::tuning` knob
/// would not do: that is a process-wide `OnceLock`, and these tests run in
/// parallel in one process.
///
/// [`JSEP_DEADLINE`] is deliberately *not* in here. It is consumed inside the
/// backends' `complete()`, which the browser backend does not even accept a
/// deadline for, so threading it would buy an injectability only half the
/// targets could honour. [`Self::round`] bounds it from the outside on both.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignalDeadlines {
    /// Bound on each wait for the peer's envelope.
    pub(crate) exchange: std::time::Duration,
    /// Bound on the whole round, both roles.
    pub(crate) round: std::time::Duration,
}

impl SignalDeadlines {
    pub(crate) const DEFAULT: Self = Self {
        exchange: SIGNAL_EXCHANGE_DEADLINE,
        round: SIGNAL_ROUND_DEADLINE,
    };
}
