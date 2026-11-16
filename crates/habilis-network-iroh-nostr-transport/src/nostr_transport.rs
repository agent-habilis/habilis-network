//! The Nostr transport of one endpoint.

use std::sync::Arc;

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
/// endpoint builder. The data lane opens at once; dropping the value stops the receive task.
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
#[derive(Debug)]
pub struct NostrTransport {
    handle: GossipHandle,
    _receive: task::AbortOnDropHandle<()>,
}

impl NostrTransport {
    /// Open the data lane on the relays of `ranking`, the custom list in the order every member
    /// computes, and listen on the tag of `app_id`. The caller passes no relay it does not trust
    /// with payload. The byte budget of the node is the default of the transport core.
    #[must_use]
    pub fn open(app_id: EndpointId, keys: NostrKeys, ranking: Vec<Url>) -> Self {
        let handle = GossipHandle::with_transport_id(app_id, NOSTR_TRANSPORT_ID);
        handle.set_budget(Some(DEFAULT_BUDGET_BYTES_PER_SEC));
        let tag = keys.self_tag(&app_id);
        let (pool, mut datagrams) = DataPool::open(ranking, *app_id.as_bytes(), tag);
        // the handle keeps the sink to send frames, and the sink owns the pool
        handle.attach(Arc::new(DataSink::new(pool, keys)));
        let receiving = handle.clone();
        let receive = task::spawn(async move {
            while let Some(datagram) = datagrams.recv().await {
                let _ = receiving.deliver(&datagram.bytes);
            }
        });
        Self {
            handle,
            _receive: task::AbortOnDropHandle::new(receive),
        }
    }

    /// The handle of the transport core: its custom transport, its counters and its allow rule.
    #[must_use]
    pub fn handle(&self) -> &GossipHandle {
        &self.handle
    }
}
