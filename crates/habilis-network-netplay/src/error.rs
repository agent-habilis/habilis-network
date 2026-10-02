//! What can go wrong.

use crate::frame::Frame;

/// Errors a rollback session can return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackError {
    /// We have simulated `max_prediction` frames past the last confirmed one
    /// and cannot guess further — there would be no saved state left to roll
    /// back to.
    ///
    /// **Not a failure.** It is the session telling the caller to skip this
    /// frame and let remote inputs catch up; a real match hits it whenever
    /// the network hiccups. Render the same frame again and retry.
    PredictionLimit,

    /// A player handle that does not exist in this session.
    InvalidPlayer(usize),

    /// `advance_frame` was called without a local input for this frame.
    /// Supply one with `add_local_input` first.
    MissingLocalInput,

    /// Two peers' state checksums disagree for the same frame: they are no
    /// longer simulating the same game.
    ///
    /// This is unrecoverable by design — rollback assumes determinism, and
    /// once it is broken there is nothing to reconcile against. It means the
    /// simulation violated the determinism contract on
    /// [`crate::Config`]. Run [`crate::SyncTestSession`] to find where.
    Desync {
        /// The frame that disagreed.
        frame: Frame,
        /// What we computed.
        local: u128,
        /// What the peer computed.
        remote: u128,
    },
}

impl std::fmt::Display for RollbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PredictionLimit => write!(
                formatter,
                "prediction limit reached; skip this frame and let remote inputs arrive"
            ),
            Self::InvalidPlayer(handle) => write!(formatter, "no such player handle: {handle}"),
            Self::MissingLocalInput => write!(
                formatter,
                "no local input for this frame; call add_local_input before advance_frame"
            ),
            Self::Desync {
                frame,
                local,
                remote,
            } => write!(
                formatter,
                "desync at frame {frame}: local checksum {local:#x} != remote {remote:#x}; \
                 the simulation is not deterministic (see the Config determinism contract)"
            ),
        }
    }
}

impl std::error::Error for RollbackError {}
