//! The Nostr transport of one endpoint.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use habilis_network_iroh_gossip_transport::{Delivery, GossipHandle, NOSTR_TRANSPORT_ID};
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
    // the engine writes the members that it knows, and the receive task reads them
    known: Arc<Mutex<HashSet<EndpointId>>>,
    // the plan that the transport was activated with: the tag of its endpoint and the relays
    plan: Arc<OnceLock<([u8; 32], Vec<Url>)>>,
}

/// The core budget of the transport, in bytes of frame each second: below what the data lane lets
/// out, so that a flow at its budget does not keep the queue at its age limit. The data lane paces
/// one mebibyte each second of event text, and a frame is about 73 % of its event text after base64 and
/// the batch header.
pub const NOSTR_BUDGET_BYTES_PER_SEC: u64 = 700 * 1024;

impl NostrTransport {
    /// A transport that is not active yet: it has no relay and no tag, so its path is not valid.
    /// A mesh that creates its endpoint before it knows its topic registers this one, and calls
    /// [`activate`](Self::activate) once the keys exist. The byte budget of the node is the
    /// default of the transport core.
    #[must_use]
    pub fn new(app_id: EndpointId) -> Self {
        let handle = GossipHandle::with_transport_id(app_id, NOSTR_TRANSPORT_ID);
        handle.set_budget(Some(NOSTR_BUDGET_BYTES_PER_SEC));
        // The last rung: no frame and no address of it leaves for a peer until the engine allows
        // the pair, or a frame of that peer arrives and shows that it chose this path.
        handle.set_default_allow(false);
        Self {
            handle,
            // the clones of the transport share one receive task
            receive: Arc::new(OnceLock::new()),
            // the clones of the transport share the members
            known: Arc::new(Mutex::new(HashSet::new())),
            // the clones of the transport share the plan
            plan: Arc::new(OnceLock::new()),
        }
    }

    /// Tell the transport which members the engine knows. A datagram opens replies only to one of
    /// them: the sender that a batch names is not proven, so an id of a stranger must not open the
    /// handle, and the tables stay as small as the roster. The engine refreshes the set at its
    /// sweep.
    ///
    /// # Panics
    ///
    /// Panics if another thread panicked while it held the set.
    pub fn set_known_peers(&self, peers: impl IntoIterator<Item = EndpointId>) {
        *self.known.lock().expect("the known members") = peers.into_iter().collect();
    }

    /// Open the data lane on the relays of `ranking`, the custom list in the order every member
    /// computes, and listen on the tag of the endpoint. The caller passes no relay it does not
    /// trust with payload. It does nothing when the transport is active already, and returns
    /// whether it opened the lane. Call it inside a runtime.
    ///
    /// # Panics
    ///
    /// Panics if another thread panicked while it held the set of known members.
    #[must_use]
    pub fn activate(&self, keys: NostrKeys, ranking: Vec<Url>) -> bool {
        let app_id = self.handle.app_id();
        let mut opened = false;
        self.receive.get_or_init(|| {
            opened = true;
            let _ = self.plan.set((keys.self_tag(&app_id), ranking.clone()));
            let tag = keys.self_tag(&app_id);
            let (pool, mut datagrams) = DataPool::open(ranking, *app_id.as_bytes(), tag);
            // the handle keeps the sink to send frames, and the sink owns the pool
            self.handle.attach(Arc::new(DataSink::new(pool, keys)));
            let receiving = self.handle.clone();
            // the receive task reads the members that the engine writes
            let known = Arc::clone(&self.known);
            task::AbortOnDropHandle::new(task::spawn(async move {
                while let Some(datagram) = datagrams.recv().await {
                    // Only a frame that the core queues for this endpoint opens replies: a
                    // malformed batch, or one for another member, shows no path.
                    let delivery = receiving.deliver(&datagram.bytes);
                    if delivery != Delivery::Queued {
                        continue;
                    }
                    if let Ok(sender) = EndpointId::from_bytes(&datagram.from) {
                        let member = known.lock().expect("the known members").contains(&sender);
                        if member {
                            receiving.allow_reply(sender);
                        }
                    }
                }
            }))
        });
        opened
    }

    /// Whether `peer` is a member that this transport answers: see
    /// [`set_known_peers`](Self::set_known_peers).
    #[must_use]
    pub fn knows(&self, peer: EndpointId) -> bool {
        self.known
            .lock()
            .expect("the known members")
            .contains(&peer)
    }

    /// Whether an active transport serves the plan `keys` and `ranking`: `None` when it is not
    /// active, `Some(true)` for the same plan, and `Some(false)` for other keys or another relay
    /// list. A caller that hands one transport to a mesh refuses the second answer: the transport
    /// serves one mesh for its life.
    #[must_use]
    pub fn serves(&self, keys: &NostrKeys, ranking: &[Url]) -> Option<bool> {
        let (tag, relays) = self.plan.get()?;
        Some(*tag == keys.self_tag(&self.handle.app_id()) && relays.as_slice() == ranking)
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

#[cfg(test)]
mod tests {
    use super::{NOSTR_BUDGET_BYTES_PER_SEC, NostrTransport};
    use habilis_network_protocol::TopicId;
    use habilis_network_protocol::nostr::NostrKeys;

    /// A flow at the budget must not exceed what the data lane lets out: it paces one mebibyte each second
    /// of event text, and a frame is about 73 % of its event text (base64 and the batch header).
    #[test]
    fn the_core_budget_is_not_above_the_raw_rate_of_the_data_lane() {
        let _guard = ::habilis_network_test_tracing::init();
        let lane_raw_rate = (1024 * 1024) * 73 / 100;
        assert!(
            NOSTR_BUDGET_BYTES_PER_SEC <= lane_raw_rate,
            "the budget {NOSTR_BUDGET_BYTES_PER_SEC} B/s is above the lane's {lane_raw_rate} B/s"
        );
    }

    /// A transport that serves one mesh must not be activated for another: an injected transport
    /// that is active with other keys or another relay list is a conflict. The same plan is fine.
    #[test]
    fn an_active_transport_tells_whether_it_serves_a_plan() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let id = iroh::SecretKey::from_bytes(&[5; 32]).public();
            let keys = NostrKeys::derive(&TopicId::from_bytes([1u8; 32]));
            let other_keys = NostrKeys::derive(&TopicId::from_bytes([2u8; 32]));
            let relays: Vec<url::Url> = vec!["ws://127.0.0.1:9".parse().expect("a relay URL")];
            let other_relays: Vec<url::Url> =
                vec!["ws://127.0.0.1:10".parse().expect("a relay URL")];
            let transport = NostrTransport::new(id);
            assert_eq!(transport.serves(&keys, &relays), None, "not active yet");
            assert!(
                transport.activate(keys.clone(), relays.clone()),
                "the first activation opens the lane"
            );
            assert_eq!(
                transport.serves(&keys, &relays),
                Some(true),
                "the same plan"
            );
            assert_eq!(
                transport.serves(&other_keys, &relays),
                Some(false),
                "other keys"
            );
            assert_eq!(
                transport.serves(&keys, &other_relays),
                Some(false),
                "another list"
            );
        });
    }
}
