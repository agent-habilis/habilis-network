//! Path selection for an endpoint that has gossip: the ladder of the other transports, IP,
//! then a session, then multihop, then gossip, then the relay.
//!
//! iroh's default selector treats a custom transport as primary, so an endpoint that registers
//! the gossip transport beside IP would select the gossip path over a direct one, and the mesh
//! topic would carry the bytes of every pair. This selector keeps gossip below every direct
//! path and above the relay. The order is the one of [`Rung`], shared with the selectors of the
//! other transports.

use habilis_network_iroh_transport_util::{
    climb, custom_rung, ip_remote, is_blocked_to, remote_id,
};
use iroh::endpoint::transports::{
    PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};

/// The ladder of one node. `local` is the endpoint this selector serves, so that a test can take
/// a rung away from this node alone.
#[derive(Debug)]
pub(crate) struct GossipLadder {
    local: iroh::EndpointId,
}

impl GossipLadder {
    pub(crate) fn new(local: iroh::EndpointId) -> Self {
        Self { local }
    }
}

impl PathSelector for GossipLadder {
    fn select(&self, context: &PathSelectionContext<'_>) -> PathSelection {
        let paths: Vec<PathSelectionData<'_>> = context.paths().collect();
        let chosen = climb(&paths, custom_rung, |rung, path| {
            !is_blocked_to(self.local, rung, ip_remote(path), remote_id(path))
        });
        let mut selection = PathSelection::none();
        if let Some(path) = chosen {
            selection.set(path);
        }
        selection
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_iroh_transport_util::Rung;
    use habilis_network_test_tracing::test;
    use std::net::SocketAddr;

    /// The ladder names this crate's transport by the id that the transport uses. The id is
    /// written twice, here and in the util crate, which is below this one; this is the guard
    /// that they stay equal.
    #[test]
    fn the_ladder_knows_the_gossip_transport_id_of_this_crate() {
        assert_eq!(
            super::custom_rung(crate::GOSSIP_TRANSPORT_ID),
            Rung::Gossip,
            "the ladder knows the gossip transport id of this crate"
        );
    }

    use std::time::Duration;

    use iroh::endpoint::{Connection, presets};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};

    use crate::hub::Hub;
    use crate::{GossipHandle, gossip_addr};

    const ALPN: &[u8] = b"habilis-network-gossip/test-selector/0";

    #[derive(Debug, Clone)]
    struct Hold;

    impl ProtocolHandler for Hold {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            connection.closed().await;
            Ok(())
        }
    }

    /// An endpoint with a loopback UDP socket and the gossip transport. With `ladder` it has the
    /// selector of the handle, without it iroh's default.
    async fn node(seed: u8, hub: &Hub, ladder: bool) -> Endpoint {
        let key = SecretKey::from_bytes(&[seed; 32]);
        let handle = GossipHandle::new(key.public());
        hub.join(&handle);
        let builder = Endpoint::builder(presets::Minimal);
        let builder = builder.secret_key(key);
        let builder = builder.relay_mode(RelayMode::Disabled);
        let builder = builder.bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)));
        let builder = builder.expect("bind address");
        let builder = builder.add_custom_transport(handle.custom_transport());
        let builder = if ladder {
            builder.path_selector(handle.path_selector())
        } else {
            builder
        };
        builder.bind().await.expect("bind")
    }

    /// Dial `bob` with both of his addresses, wait until the connection has both paths, and
    /// say whether the selected one is IP.
    async fn selects_ip(alice: &Endpoint, bob: &Endpoint) -> bool {
        let router = Router::builder(bob.clone()).accept(ALPN, Hold).spawn();
        let both = bob
            .addr()
            .addrs
            .into_iter()
            .chain([TransportAddr::Custom(gossip_addr(bob.id()))]);
        let connection = alice
            .connect(EndpointAddr::from_parts(bob.id(), both), ALPN)
            .await
            .expect("connect");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while connection.paths().len() < 2 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(connection.paths().len() >= 2, "both paths opened");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let open = connection.paths();
        let found = open.iter().find(iroh::endpoint::Path::is_selected);
        let selected_ip: bool = found.is_some_and(|path| path.is_ip());
        router.shutdown().await.expect("shutdown");
        selected_ip
    }

    /// The default selector of iroh treats a custom transport as primary: with IP and gossip
    /// both open, the mesh topic would carry the bytes. This is what the ladder prevents.
    #[test]
    async fn an_endpoint_with_ip_and_gossip_selects_ip() {
        let hub = Hub::new();
        let (alice, bob) = (node(31, &hub, true).await, node(32, &hub, true).await);
        assert!(
            selects_ip(&alice, &bob).await,
            "an endpoint with ip and gossip selects ip"
        );
        alice.close().await;
    }

    /// The same endpoints without the ladder: the guard that the test above can fail.
    #[test]
    async fn without_the_ladder_an_endpoint_with_ip_and_gossip_selects_gossip() {
        let hub = Hub::new();
        let (alice, bob) = (node(33, &hub, false).await, node(34, &hub, false).await);
        assert!(
            !selects_ip(&alice, &bob).await,
            "without the ladder an endpoint with ip and gossip selects gossip"
        );
        alice.close().await;
    }

    /// The ladder hides nothing: with no other path, gossip is the one that is selected.
    #[test]
    async fn the_ladder_selects_gossip_when_it_is_the_only_path() {
        let hub = Hub::new();
        let key = |seed: u8| SecretKey::from_bytes(&[seed; 32]);
        let bind = |seed: u8| {
            let handle = GossipHandle::new(key(seed).public());
            hub.join(&handle);
            async move {
                let builder = Endpoint::builder(presets::Minimal)
                    .secret_key(key(seed))
                    .relay_mode(RelayMode::Disabled)
                    .add_custom_transport(handle.custom_transport());
                let configured = builder.path_selector(handle.path_selector());
                configured
                    .clear_ip_transports()
                    .clear_relay_transports()
                    .bind()
                    .await
                    .expect("bind")
            }
        };
        let (alice, bob) = (bind(35).await, bind(36).await);
        let router = Router::builder(bob.clone()).accept(ALPN, Hold).spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(bob.id(), [TransportAddr::Custom(gossip_addr(bob.id()))]),
                ALPN,
            )
            .await
            .expect("connect");
        assert!(
            crate::selected_is_gossip(&connection),
            "the ladder selects gossip when it is the only path"
        );
        router.shutdown().await.expect("shutdown");
        alice.close().await;
    }
}
