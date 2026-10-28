use iroh::endpoint::transports;

use crate::{AttachError, selector};
#[cfg(all(feature = "web", not(feature = "native")))]
use crate::{BrowserHubTransport, BrowserSessionGuard, DataChannelCounters, SessionCounts};
#[cfg(feature = "native")]
use crate::{NegotiatedSession, WebRtcTransport};

/// A registered `WebRTC` transport, ready to hand to an iroh endpoint builder.
///
/// The same name on both targets so a consumer's wiring code is written once:
/// which backend it wraps is decided by the feature, not by the caller. Cheap
/// to clone — it is a handle, and every clone shares one session registry.
#[cfg(any(feature = "native", feature = "web"))]
#[derive(Debug, Clone)]
pub struct WebRtcHandle {
    #[cfg(feature = "native")]
    inner: std::sync::Arc<WebRtcTransport>,
    #[cfg(all(feature = "web", not(feature = "native")))]
    inner: std::sync::Arc<BrowserHubTransport>,
}

#[cfg(feature = "native")]
impl WebRtcHandle {
    /// Wrap a host transport.
    #[must_use]
    pub fn new(transport: std::sync::Arc<WebRtcTransport>) -> Self {
        Self { inner: transport }
    }

    /// The transport to register with `Builder::add_custom_transport`.
    ///
    /// Registration is deliberately additive rather than a `Preset`: a preset
    /// would make `WebRTC` the endpoint's *only* transport, which is right for a
    /// browser and wrong for a native peer that should still prefer iroh's own
    /// hole-punched paths.
    #[must_use]
    pub fn transport(&self) -> std::sync::Arc<WebRtcTransport> {
        std::sync::Arc::clone(&self.inner)
    }

    /// The path selector that keeps the relay a rendezvous, for
    /// `Builder::path_selector`. Install it wherever [`Self::transport`] is
    /// registered — see `crate::selector` for why registering the transport
    /// alone is not enough.
    #[must_use]
    pub fn path_selector(&self) -> std::sync::Arc<dyn transports::PathSelector> {
        std::sync::Arc::new(selector::WebRtcPreferred::new(self.inner.local_id()))
    }

    /// Attach a negotiated session for `remote`.
    ///
    /// # Errors
    /// # Errors
    /// [`AttachError::AlreadyAttached`] when the registry already holds a live session
    /// for `remote`, or [`AttachError::Retired`] when it ends before it is recorded.
    pub fn attach(
        &self,
        remote: iroh_base::EndpointId,
        session: NegotiatedSession,
    ) -> Result<(), AttachError> {
        self.inner.attach(remote, session)
    }

    /// Whether a usable session for `remote` exists.
    #[must_use]
    pub fn has_session(&self, remote: &iroh_base::EndpointId) -> bool {
        self.inner.has_session(remote)
    }

    /// How many usable sessions this handle's registry holds.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.inner.session_count()
    }

    /// The remote ids of every live session.
    pub fn live_peer_ids(&self) -> impl Iterator<Item = iroh_base::EndpointId> {
        self.inner.live_peer_ids()
    }

    /// Tear down the session for `remote`, if any.
    #[must_use]
    pub fn detach(&self, remote: &iroh_base::EndpointId) -> bool {
        self.inner.detach(remote)
    }

    /// Tests only: abort every session without a close. See
    /// `WebRtcTransport::abort_sessions`.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn abort_sessions(&self) -> usize {
        self.inner.abort_sessions()
    }
}

#[cfg(all(feature = "web", not(feature = "native")))]
impl WebRtcHandle {
    /// Wrap a browser hub transport (consumer or producer).
    #[must_use]
    pub fn new(transport: std::sync::Arc<BrowserHubTransport>) -> Self {
        Self { inner: transport }
    }

    /// Empty hub for `local`, ready to register and later [`Self::attach`].
    #[must_use]
    pub fn hub(local: iroh_base::EndpointId) -> Self {
        Self::new(BrowserHubTransport::new(local))
    }

    /// The transport to register with `Builder::add_custom_transport`.
    #[must_use]
    pub fn transport(&self) -> std::sync::Arc<BrowserHubTransport> {
        std::sync::Arc::clone(&self.inner)
    }

    /// The path selector that keeps the relay a rendezvous, for
    /// `Builder::path_selector`. Install it wherever [`Self::transport`] is
    /// registered — see [`crate::selector`] for why registering the transport
    /// alone is not enough.
    #[must_use]
    pub fn path_selector(&self) -> std::sync::Arc<dyn transports::PathSelector> {
        std::sync::Arc::new(selector::WebRtcPreferred::new(self.inner.local_id()))
    }

    /// Attach a negotiated browser session for `remote`.
    ///
    /// Prefer calling [`crate::BrowserPendingOffer::complete`] /
    /// [`crate::BrowserPendingAnswer::complete`], which attach themselves; this is
    /// the escape hatch when the session pieces are already in hand.
    ///
    /// # Errors
    /// The peer's slot is already claimed. The handles passed in are closed
    /// before returning.
    pub fn attach_parts(
        &self,
        remote: iroh_base::EndpointId,
        peer_connection: web_sys::RtcPeerConnection,
        data_channel: web_sys::RtcDataChannel,
        callbacks: Vec<wasm_bindgen::JsValue>,
    ) -> Result<BrowserSessionGuard, AttachError> {
        self.inner
            .attach(remote, peer_connection, data_channel, callbacks)
    }

    /// Whether a usable session for `remote` exists.
    #[must_use]
    pub fn has_session(&self, remote: &iroh_base::EndpointId) -> bool {
        self.inner.has_session(remote)
    }

    /// How many usable sessions this handle's registry holds.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.inner.session_count()
    }

    /// Endpoint ids of every live session.
    pub fn live_peer_ids(&self) -> impl Iterator<Item = iroh_base::EndpointId> {
        self.inner.live_peer_ids()
    }

    /// `RTCPeerConnection.connectionState` of a live session, if any.
    #[must_use]
    pub fn session_state(
        &self,
        remote: &iroh_base::EndpointId,
    ) -> Option<web_sys::RtcPeerConnectionState> {
        self.inner.session_state(remote)
    }

    /// The peer connection behind a live session, if any.
    #[must_use]
    pub fn peer_connection(
        &self,
        remote: &iroh_base::EndpointId,
    ) -> Option<web_sys::RtcPeerConnection> {
        self.inner.peer_connection(remote)
    }

    /// Selected ICE remote candidate for a live session, if any.
    pub async fn selected_remote_candidate(
        &self,
        remote: &iroh_base::EndpointId,
    ) -> Option<(String, String)> {
        self.inner.selected_remote_candidate(remote).await
    }

    /// Bytes and messages this session's data channel has carried.
    ///
    /// The measure to use when the question is "did our traffic move?" — see
    /// [`BrowserHubTransport::data_channel_bytes`] for why the ICE candidate
    /// pair is not a dependable stand-in for it.
    pub async fn data_channel_bytes(
        &self,
        remote: &iroh_base::EndpointId,
    ) -> Option<DataChannelCounters> {
        self.inner.data_channel_bytes(remote).await
    }

    /// What this session's outbound lane did with the datagrams QUIC handed it
    /// — sent, and dropped by each of the three routes that can drop one.
    ///
    /// The lane is lossy by design and silent by consequence: `poll_send`
    /// cannot park without stalling every transport, so it discards and
    /// reports success. A consumer diagnosing a stalled transfer — or deciding
    /// whether to demote a peer to the relay — otherwise has nothing to go on
    /// but the transfer not finishing. See [`crate::SessionCounters`].
    #[must_use]
    pub fn session_counters(&self, remote: &iroh_base::EndpointId) -> Option<SessionCounts> {
        self.inner.session_counters(remote)
    }

    /// Tear down the session for `remote`, if any.
    #[must_use]
    pub fn detach(&self, remote: &iroh_base::EndpointId) -> bool {
        self.inner.detach(remote)
    }
}
