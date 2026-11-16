//! The Nostr transport of one endpoint.

use std::sync::{Arc, OnceLock};

use habilis_network_iroh_gossip_transport::{
    DEFAULT_BUDGET_BYTES_PER_SEC, GossipHandle, NOSTR_TRANSPORT_ID,
};
use habilis_network_iroh_nostr_address_lookup::DataPool;
use habilis_network_protocol::nostr::NostrKeys;
use iroh::EndpointId;
use n0_future::task;
use url::Url;

use crate::data_sink::DataSink;

/// Nostr as a custom transport of one endpoint. Register `handle().custom_transport()` on the
/// endpoint builder. The receive task stops when the last clone is dropped, so the owner of the endpoint keeps one.
///
/// # Examples
///
/// A transport reports the endpoint it serves. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_nostr_transport::NostrTransport;
/// use habilis_network_protocol::TopicId;
/// use habilis_network_protocol::nostr::NostrKeys;
/// use iroh::SecretKey;
///
/// # fn demo() {
/// let keys = NostrKeys::derive(&TopicId::from_bytes([9u8; 32]));
/// let id = SecretKey::from_bytes(&[1u8; 32]).public();
/// let transport = NostrTransport::open(id, keys, Vec::new());
/// assert_eq!(transport.handle().app_id(), id);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct NostrTransport {
    handle: GossipHandle,
    // the clones of the transport share one receive task, which stops with the last of them
    receive: Arc<OnceLock<task::AbortOnDropHandle<()>>>,
}

impl NostrTransport {
    /// A transport that is not active yet: it has no relay and no tag, so its path is not valid.
    /// A mesh that creates its endpoint before it knows its topic registers this one, and calls
    /// [`activate`](Self::activate) once the keys exist. The byte budget of the node is the
    /// default of the transport core.
    #[must_use]
    pub fn new(app_id: EndpointId) -> Self {
        let handle = GossipHandle::with_transport_id(app_id, NOSTR_TRANSPORT_ID);
        handle.set_budget(Some(DEFAULT_BUDGET_BYTES_PER_SEC));
        // The last rung: no frame and no address of it leaves for a peer until the engine allows
        // the pair, or a frame of that peer arrives and shows that it chose this path.
        handle.set_default_allow(false);
        Self {
            handle,
            // the clones of the transport share one receive task
            receive: Arc::new(OnceLock::new()),
        }
    }

    /// Open the data lane on the relays of `ranking`, the custom list in the order every member
    /// computes, and listen on the tag of the endpoint. The caller passes no relay it does not
    /// trust with payload. It does nothing when the transport is active already, and returns
    /// whether it opened the lane. Call it inside a runtime.
    #[must_use]
    pub fn activate(&self, keys: NostrKeys, ranking: Vec<Url>) -> bool {
        let app_id = self.handle.app_id();
        let mut opened = false;
        self.receive.get_or_init(|| {
            opened = true;
            let tag = keys.self_tag(&app_id);
            let (pool, mut datagrams) = DataPool::open(ranking, *app_id.as_bytes(), tag);
            // the handle keeps the sink to send frames, and the sink owns the pool
            self.handle.attach(Arc::new(DataSink::new(pool, keys)));
            let receiving = self.handle.clone();
            task::AbortOnDropHandle::new(task::spawn(async move {
                while let Some(datagram) = datagrams.recv().await {
                    if let Ok(sender) = EndpointId::from_bytes(&datagram.from) {
                        receiving.allow(sender, true);
                    }
                    let _ = receiving.deliver(&datagram.bytes);
                }
            }))
        });
        opened
    }

    /// [`new`](Self::new) and [`activate`](Self::activate) in one call, for a caller that knows
    /// its keys when it builds the transport.
    #[must_use]
    pub fn open(app_id: EndpointId, keys: NostrKeys, ranking: Vec<Url>) -> Self {
        let transport = Self::new(app_id);
        let _opened = transport.activate(keys, ranking);
        transport
    }

    /// The handle of the transport core: its custom transport, its counters and its allow rule.
    #[must_use]
    pub fn handle(&self) -> &GossipHandle {
        &self.handle
    }
}
