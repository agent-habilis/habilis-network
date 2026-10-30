use web_sys::RtcPeerConnection;

use std::{fmt, ops};
/// An `RTCPeerConnection` that closes itself unless it is released.
///
/// Every early return on the way to a session used to drop an open peer
/// connection without closing it, leaving a live ICE agent — and, when the
/// public TURN fallback is in play, a live TURN allocation — for as long as the
/// tab lives. Failures here are routine by design (ICE fails, a peer vanishes
/// mid-handshake, the offerer never opens its channel), so "routine" was
/// leaking.
///
/// The newtype goes on the *field* rather than the outer struct because `Drop`
/// and destructuring `let Self { .. } = self` cannot coexist.
#[derive(Clone)]
pub(super) struct OpenPeerConnection {
    inner: RtcPeerConnection,
    armed: bool,
}

impl OpenPeerConnection {
    pub(super) fn new(inner: RtcPeerConnection) -> Self {
        Self { inner, armed: true }
    }

    /// Hand the connection to whoever owns its lifetime from here — in
    /// practice the hub, whose session keepalive closes it on drop.
    pub(super) fn release(mut self) -> RtcPeerConnection {
        self.armed = false;
        self.inner.clone()
    }
}

impl ops::Deref for OpenPeerConnection {
    type Target = RtcPeerConnection;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for OpenPeerConnection {
    fn drop(&mut self) {
        if self.armed {
            self.inner.close();
        }
    }
}

impl fmt::Debug for OpenPeerConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenPeerConnection")
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}
