//! The pure half of the browser hub's peer-connection watchdog.
//!
//! A data channel reports `close` when its own transport goes away, but not
//! when ICE underneath it fails: after a laptop sleep, or a peer that stops
//! answering consent checks, `RTCPeerConnection.connectionState` moves to
//! `disconnected` and then `failed` while the channel still reads `open`. A
//! session judged live only by its channel therefore stays in the registry,
//! keeps counting toward the direct-peer total, and keeps refusing a re-dial.
//!
//! The judgment lives here, free of every `web-sys` type, for the same reason
//! [`crate::registry`] does: the browser backend cannot be unit-tested off
//! wasm32, and this is the part with the hysteresis worth testing.

/// A coarse reading of `RTCPeerConnection.connectionState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionPhase {
    /// `new`, `connecting`, or `connected`: nothing to do.
    Healthy,
    /// `disconnected`: ICE may still recover on its own.
    Disconnected,
    /// `failed` or `closed`: the connection will not come back.
    Dead,
}

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
    use super::{ConnectionPhase, DISCONNECT_GRACE_MS, Verdict, judge_state};

    #[test]
    fn a_dead_connection_is_removed_at_once() {
        assert_eq!(judge_state(ConnectionPhase::Dead, None), Verdict::Remove);
        assert_eq!(
            judge_state(ConnectionPhase::Dead, Some(0.0)),
            Verdict::Remove
        );
    }

    #[test]
    fn a_healthy_connection_is_kept_whatever_its_history() {
        assert_eq!(judge_state(ConnectionPhase::Healthy, None), Verdict::Keep);
        // Recovered inside the grace window: the elapsed figure is stale and
        // must not count against it.
        assert_eq!(
            judge_state(ConnectionPhase::Healthy, Some(DISCONNECT_GRACE_MS * 2.0)),
            Verdict::Keep
        );
    }

    #[test]
    fn a_fresh_disconnect_waits_for_the_grace_window() {
        assert_eq!(
            judge_state(ConnectionPhase::Disconnected, None),
            Verdict::Wait
        );
        assert_eq!(
            judge_state(
                ConnectionPhase::Disconnected,
                Some(DISCONNECT_GRACE_MS / 2.0)
            ),
            Verdict::Wait
        );
    }

    #[test]
    fn a_disconnect_that_outlives_the_grace_window_is_removed() {
        assert_eq!(
            judge_state(ConnectionPhase::Disconnected, Some(DISCONNECT_GRACE_MS)),
            Verdict::Remove
        );
        assert_eq!(
            judge_state(
                ConnectionPhase::Disconnected,
                Some(DISCONNECT_GRACE_MS + 1.0)
            ),
            Verdict::Remove
        );
    }
}
