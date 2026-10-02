use anyhow::Context as _;
use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use iroh::EndpointId;
use iroh::endpoint::Builder;
use iroh::endpoint::presets::{Minimal, Preset};
use iroh::endpoint::transports::{CustomEndpoint, CustomTransport};
use iroh_base::CustomAddr;
use n0_watcher::Watchable;
use tokio::sync::mpsc;

use super::driver::{NegotiatedSession, drive_session};
use super::endpoint::WebRtcEndpoint;
use super::session::{InboundPacket, SessionHandle, SessionRegistry};
use crate::custom_addr;
use crate::{IN_QUEUE, OUT_QUEUE};

/// Factory for the `WebRTC` datagram lane of one iroh endpoint.
///
/// Sessions (one data channel per remote peer) are negotiated out of band
/// via [`crate::offer`]/[`crate::answer`] and adopted with [`Self::attach`];
/// iroh then sees the remote as reachable at its `WebRTC` [`CustomAddr`] and
/// runs QUIC over the channel like over any other path.
pub struct WebRtcTransport {
    local_id: EndpointId,
    registry: Arc<SessionRegistry>,
    inbound_tx: mpsc::Sender<InboundPacket>,
    inbound_rx: Mutex<Option<mpsc::Receiver<InboundPacket>>>,
    local_addrs: Watchable<Vec<CustomAddr>>,
}

impl WebRtcTransport {
    #[must_use]
    pub fn new(local_id: EndpointId) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(IN_QUEUE);
        Arc::new(Self {
            local_id,
            registry: SessionRegistry::new(),
            inbound_tx,
            inbound_rx: Mutex::new(Some(inbound_rx)),
            local_addrs: Watchable::new(vec![custom_addr(local_id)]),
        })
    }

    #[must_use]
    pub fn local_id(&self) -> EndpointId {
        self.local_id
    }

    /// Adopts a negotiated session for `remote` and starts its driver.
    ///
    /// # Errors
    ///
    /// Fails if a live session for `remote` already exists (detach first,
    /// or let the old driver notice the dead channel and clean up).
    pub fn attach(&self, remote: EndpointId, session: NegotiatedSession) -> anyhow::Result<()> {
        let (out_tx, out_rx) = mpsc::channel(OUT_QUEUE);
        let dropped_tx = Arc::new(AtomicU64::new(0));
        // Claim the slot *before* spawning. The driver retires its own
        // generation when it ends, and a session that fails immediately does
        // that while this call is still returning — against an empty registry,
        // that removal is lost and the record below becomes permanent.
        let reservation = self
            .registry
            .reserve(remote)
            .with_context(|| format!("a live WebRTC session for {remote} already exists"))?;
        let generation = reservation.generation();
        let task = tokio::spawn(drive_session(
            session,
            remote,
            generation,
            self.registry.clone(),
            out_rx,
            self.inbound_tx.clone(),
            dropped_tx.clone(),
        ));
        // `None` means the driver already failed and retired its own
        // generation while this spawn was returning. The handle drops, which
        // aborts the task rather than recording a session nothing pumps.
        let guard = reservation
            .fulfil(SessionHandle::new(out_tx, dropped_tx, task))
            .with_context(|| {
                format!("the session for {remote} was retired before it was recorded")
            })?;
        guard.commit();
        tracing::debug!(%remote, "webrtc session attached");
        Ok(())
    }

    /// Tears down the session for `remote`, if any. Returns whether one
    /// existed. A later [`Self::attach`] may replace it.
    pub fn detach(&self, remote: &EndpointId) -> bool {
        self.registry.remove(remote)
    }

    #[must_use]
    pub fn has_session(&self, remote: &EndpointId) -> bool {
        self.registry.is_live(remote)
    }

    #[must_use]
    pub fn session_count(&self) -> usize {
        self.registry.live_len()
    }

    /// A builder preset that makes this the endpoint's *only* transport
    /// (no IP, no relay) — for tests and single-purpose peers like a browser
    /// tab. A consumer that wants `WebRTC` to stay additive calls
    /// `Builder::add_custom_transport` directly instead.
    pub fn preset(self: &Arc<Self>) -> impl Preset {
        ExclusivePreset {
            factory: self.clone(),
        }
    }
}

impl std::fmt::Debug for WebRtcTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebRtcTransport")
            .field("local_id", &self.local_id)
            .field("sessions", &self.registry.live_len())
            .finish_non_exhaustive()
    }
}

impl CustomTransport for WebRtcTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let receiver = self
            .inbound_rx
            .lock()
            .expect("inbound receiver mutex poisoned")
            .take()
            .ok_or_else(|| io::Error::other("WebRtcTransport is already bound to an endpoint"))?;
        Ok(Box::new(WebRtcEndpoint::new(
            custom_addr(self.local_id),
            self.local_addrs.clone(),
            receiver,
            self.registry.clone(),
        )))
    }
}

struct ExclusivePreset {
    factory: Arc<WebRtcTransport>,
}

impl Preset for ExclusivePreset {
    fn apply(self, builder: Builder) -> Builder {
        // `Minimal` supplies the mandatory TLS crypto provider.
        Minimal
            .apply(builder)
            .clear_ip_transports()
            .clear_relay_transports()
            .clear_address_lookup()
            .add_custom_transport(self.factory)
    }
}
