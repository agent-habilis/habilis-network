use wasm_bindgen::prelude::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{RtcDataChannel, RtcSdpType, RtcSessionDescriptionInit};

use super::browser_session::BrowserSession;
use super::jsep::{any_err, js_err, wait_channel_open};
use super::open_peer_connection::OpenPeerConnection;
use super::transport::BrowserHubTransport;
use crate::SignalEnvelope;

/// Offerer state between producing the offer and applying the answer.
pub struct PendingOffer {
    pub(super) peer_connection: OpenPeerConnection,
    pub(super) data_channel: RtcDataChannel,
    pub(super) callbacks: Vec<JsValue>,
}

impl std::fmt::Debug for PendingOffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingOffer")
            .finish_non_exhaustive()
    }
}

impl PendingOffer {
    /// Apply the remote answer, wait for the channel, attach into `hub`.
    ///
    /// # Errors
    /// A non-answer envelope, a bad SDP, the channel never opening, or attach.
    pub async fn complete(
        self,
        hub: &BrowserHubTransport,
        answer: &SignalEnvelope,
    ) -> Result<BrowserSession, JsValue> {
        let Self {
            peer_connection,
            data_channel,
            callbacks,
        } = self;

        let remote = answer
            .claimed_endpoint()
            .map_err(|error| any_err("answer endpoint id", error))?;
        let SignalEnvelope::Answer { sdp, .. } = answer else {
            return Err(JsValue::from_str("expected an answer envelope"));
        };

        let answer_init = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        answer_init.set_sdp(sdp);
        JsFuture::from(peer_connection.set_remote_description(&answer_init))
            .await
            .map_err(|error| js_err("setRemoteDescription", &error))?;

        // Attach before Open so inbound QUIC Initials are not lost between
        // the channel opening and the onmessage handler being installed.
        //
        // The guard is what makes that early attach safe. If the channel never
        // opens — ICE failed, or the deadline passed while it was still
        // Connecting — dropping the guard on the way out removes the session
        // and closes the handles. Without it the entry stayed forever, because
        // a channel that never opened never fires `onclose` either: it counted
        // toward the direct-peer total, answered `has_session` so the pair was
        // never retried, and told QUIC it was a valid send address.
        let pc = peer_connection.release();
        let guard = hub
            .attach(remote, pc.clone(), data_channel.clone(), callbacks)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        wait_channel_open(&data_channel, &pc).await?;
        guard.commit();
        Ok(BrowserSession { remote })
    }
}
