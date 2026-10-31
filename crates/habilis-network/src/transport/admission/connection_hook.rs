//! The hook that admits or refuses a connection at the endpoint.
use std::future::{self, Future};

use crate::transport::{direct_only_gossip, payload_path};

use std::sync::atomic::Ordering;

use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks};

use super::SignalAdmission;

use iroh_gossip::net;
/// Reports every connection of the endpoint it is installed on, in or out and
/// on any protocol, to its [`SignalAdmission`], which keeps them under their
/// peer so that it can close and prune them. It also watches the gossip
/// connections this node dials for the relay policy.
#[derive(Debug, Clone)]
pub struct ConnectionHook {
    pub(crate) admission: SignalAdmission,
}

impl EndpointHooks for ConnectionHook {
    fn after_handshake<'a>(
        &'a self,
        connection: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        self.admission.note_connection(connection);
        // A gossip connection on the gossip rung would carry the gossip that its frames need:
        // both ends close it, whatever the mesh policy says, and before the relay watch, which is
        // policy-gated.
        if connection.alpn() == net::GOSSIP_ALPN {
            payload_path::watch_gossip_recursion(connection, self.admission.clone());
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            payload_path::track_gossip_conn(connection);
        }
        // The accept side watches the gossip connections it holds
        // (`DirectOnlyGossip::accept`). iroh-gossip dials its own, so the
        // watch for those starts here, with the same rule.
        if connection.side().is_client()
            && self.admission.watch_dialed_gossip.load(Ordering::Relaxed)
            && connection.alpn() == net::GOSSIP_ALPN
        {
            direct_only_gossip::watch_relay_policy(connection, self.admission.path_sink());
        }
        future::ready(AfterHandshakeOutcome::accept())
    }
}
