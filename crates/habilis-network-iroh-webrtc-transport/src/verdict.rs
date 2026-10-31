//! What the watchdog does with a session after one reading of its connection.

use crate::connection_phase::ConnectionPhase;

/// What to do with the session after one reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Keep,
    /// Disconnected, but not for long enough to give up on ICE.
    Wait,
    Remove,
}

/// How long a `disconnected` connection is given to recover before the
/// session is evicted. ICE consent (RFC 7675) takes up to ~30 s to declare
/// failure outright; this is the earlier cut for a peer that is plainly gone,
/// matched to the mount watchdog agent-share ran before the hub did this.
pub(crate) const DISCONNECT_GRACE_MS: f64 = 10_000.0;

/// Judge one reading of the connection state.
///
/// `disconnected_for_ms` is how long the connection has been `disconnected`
/// at the time of the reading; `None` means it just happened.
pub(crate) fn judge_state(phase: ConnectionPhase, disconnected_for_ms: Option<f64>) -> Verdict {
    match phase {
        ConnectionPhase::Healthy => Verdict::Keep,
        ConnectionPhase::Dead => Verdict::Remove,
        ConnectionPhase::Disconnected => match disconnected_for_ms {
            Some(elapsed) if elapsed >= DISCONNECT_GRACE_MS => Verdict::Remove,
            _ => Verdict::Wait,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{DISCONNECT_GRACE_MS, Verdict, judge_state};
    use crate::connection_phase::ConnectionPhase;

    #[test]
    fn a_dead_connection_is_removed_at_once() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            judge_state(ConnectionPhase::Dead, None),
            Verdict::Remove,
            "a dead connection is removed at once"
        );
        assert_eq!(
            judge_state(ConnectionPhase::Dead, Some(0.0)),
            Verdict::Remove,
            "a dead connection is removed even with a zero rtt"
        );
    }

    #[test]
    fn a_healthy_connection_is_kept_whatever_its_history() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            judge_state(ConnectionPhase::Healthy, None),
            Verdict::Keep,
            "a healthy connection is kept"
        );
        // Recovered inside the grace window: the elapsed figure is stale and
        // must not count against it.
        assert_eq!(
            judge_state(ConnectionPhase::Healthy, Some(DISCONNECT_GRACE_MS * 2.0)),
            Verdict::Keep,
            "a healthy connection is kept with a bad history"
        );
    }

    #[test]
    fn a_fresh_disconnect_waits_for_the_grace_window() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            judge_state(ConnectionPhase::Disconnected, None),
            Verdict::Wait,
            "a fresh disconnect waits for the grace window"
        );
        assert_eq!(
            judge_state(
                ConnectionPhase::Disconnected,
                Some(DISCONNECT_GRACE_MS / 2.0)
            ),
            Verdict::Wait,
            "a fresh disconnect with a sample still waits"
        );
    }

    #[test]
    fn a_disconnect_that_outlives_the_grace_window_is_removed() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            judge_state(ConnectionPhase::Disconnected, Some(DISCONNECT_GRACE_MS)),
            Verdict::Remove,
            "a disconnect past the grace window is removed"
        );
        assert_eq!(
            judge_state(
                ConnectionPhase::Disconnected,
                Some(DISCONNECT_GRACE_MS + 1.0)
            ),
            Verdict::Remove,
            "a disconnect past the grace window with a sample is removed"
        );
    }
}
