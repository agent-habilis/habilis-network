use super::SessionHandle;

use iroh::EndpointId;

/// A session that is attached but not yet proven to carry traffic.
///
/// Attaching happens *before* the data channel opens — deliberately, because
/// the browser has no inbound buffer and a QUIC Initial that lands before
/// `onmessage` is installed is lost. This guard is what makes that early attach
/// safe: dropping it without [`Self::commit`] removes the session and closes
/// the peer connection, so a negotiation that never gets its channel open
/// leaves nothing behind.
///
/// # Examples
///
/// It guards a browser session, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_webrtc_transport::BrowserSessionGuard;
///
/// # fn demo(guard: BrowserSessionGuard) {
/// drop(guard);
/// # }
/// ```
#[derive(Debug)]
#[must_use = "an uncommitted session guard tears the session down when dropped"]
pub struct BrowserSessionGuard(pub(super) crate::registry::SessionGuard<SessionHandle>);

impl BrowserSessionGuard {
    /// The peer this session is for.
    #[must_use]
    pub fn remote(&self) -> EndpointId {
        self.0.remote()
    }

    /// The channel is open and carrying traffic: keep the session.
    pub fn commit(self) {
        self.0.commit();
    }
}
