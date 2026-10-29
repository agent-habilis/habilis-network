use futures::channel::oneshot;
use iroh_base::EndpointId;
use wasm_bindgen::prelude::JsValue;
use web_sys::RtcDataChannel;

use super::browser_session::BrowserSession;
use super::jsep::{CHANNEL_OPEN_DEADLINE_MS_I32, sleep_ms, wait_channel_open};
use super::open_peer_connection::OpenPeerConnection;
use super::pre_attach_backlog::PreAttachBacklog;
use super::transport::BrowserHubTransport;

/// Answerer state between sending the answer and the channel opening.
pub struct PendingAnswer {
    pub(super) peer_connection: OpenPeerConnection,
    /// Filled by `ondatachannel` when the remote opens the channel.
    pub(super) channel_rx: oneshot::Receiver<RtcDataChannel>,
    /// Datagrams that arrived before the hub's handler was installed, in
    /// arrival order — see the buffering handler in [`answer`](super::answer).
    pub(super) backlog: std::rc::Rc<std::cell::RefCell<PreAttachBacklog>>,
    pub(super) callbacks: Vec<JsValue>,
}

impl std::fmt::Debug for PendingAnswer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingAnswer")
            .finish_non_exhaustive()
    }
}

impl PendingAnswer {
    /// Wait for the offerer's data channel, then attach into `hub`.
    ///
    /// `remote` is the authenticated peer id (prefer `connection.remote_id()`
    /// over the envelope claim).
    ///
    /// # Errors
    /// The channel never arrives or attach fails.
    pub async fn complete(
        self,
        hub: &BrowserHubTransport,
        remote: EndpointId,
    ) -> Result<BrowserSession, JsValue> {
        let Self {
            peer_connection,
            channel_rx,
            backlog,
            callbacks,
        } = self;

        let data_channel = match futures::future::select(
            channel_rx,
            Box::pin(async {
                sleep_ms(CHANNEL_OPEN_DEADLINE_MS_I32).await;
            }),
        )
        .await
        {
            futures::future::Either::Left((Ok(channel), _)) => channel,
            futures::future::Either::Left((Err(_), _)) => {
                return Err(JsValue::from_str("data channel sender dropped"));
            }
            futures::future::Either::Right(((), _)) => {
                return Err(JsValue::from_str("timed out waiting for ondatachannel"));
            }
        };

        // Attach before Open — same race as the offerer path: the peer may
        // dial the mount ALPN the instant its channel is open. Same guard, for
        // the same reason; see `PendingOffer::complete`. `attach` installs the
        // hub's own `onmessage`, replacing the buffering one.
        let pc = peer_connection.release();
        let attached = hub.attach(remote, pc.clone(), data_channel.clone(), callbacks);
        let guard: super::transport::BrowserSessionGuard =
            attached.map_err(|error| JsValue::from_str(&error.to_string()))?;
        // Hand over what arrived before that handler existed, in arrival order
        // and before anything the hub receives itself — the channel is
        // unordered, so this is not a sequencing promise, only a refusal to
        // reorder what we already hold. Taken (not cloned) so the buffer cannot
        // be delivered twice if this is ever called again.
        let (early, over_cap) = backlog.borrow_mut().take();
        if over_cap > 0 {
            web_sys::console::warn_1(&JsValue::from_str(&format!(
                "[habilis-network webrtc] pre-attach backlog refused {over_cap} datagram(s) over its cap for {remote}"
            )));
        }
        if !early.is_empty() {
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "[habilis-network webrtc] delivered {} datagram(s) buffered before attach for {remote}",
                early.len()
            )));
            hub.inject_inbound(remote, early);
        }
        wait_channel_open(&data_channel, &pc).await?;
        guard.commit();
        Ok(BrowserSession { remote })
    }
}
