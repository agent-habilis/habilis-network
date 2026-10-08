//! Path selection for an endpoint that has gossip: the ladder of the other transports, IP,
//! then a session, then multihop, then gossip, then the relay.
//!
//! iroh's default selector treats a custom transport as primary, so an endpoint that registers
//! the gossip transport beside IP would select the gossip path over a direct one, and the mesh
//! topic would carry the bytes of every pair. This selector keeps gossip below every direct
//! path and above the relay. The order is the one of [`Rung`], shared with the selectors of the
//! other transports.

use std::sync::Mutex;

use habilis_network_iroh_transport_util::{
    custom_rung, ip_remote, is_blocked_to, liveness::Liveness, remote_id,
};
use iroh::endpoint::transports::{
    PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};

/// The ladder of one node. `local` is the endpoint this selector serves, so that a test can take
/// a rung away from this node alone.
#[derive(Debug)]
pub(crate) struct GossipLadder {
    local: iroh::EndpointId,
    /// What each address received at the last calls: a path that the peer never sends on does not
    /// stay selected. One selector serves every remote of the endpoint.
    liveness: Mutex<Liveness>,
}

impl GossipLadder {
    pub(crate) fn new(local: iroh::EndpointId) -> Self {
        Self {
            local,
            liveness: Mutex::new(Liveness::new()),
        }
    }

    /// [`PathSelector::select`] at `now`, so that a test can move the clock.
    fn select_at(
        &self,
        now: n0_future::time::Instant,
        ctx: &PathSelectionContext<'_>,
    ) -> PathSelection {
        let paths: Vec<PathSelectionData<'_>> = ctx.paths().collect();
        let chosen = self
            .liveness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .choose(now, &paths, custom_rung, |rung, path| {
                !is_blocked_to(self.local, rung, ip_remote(path), remote_id(path))
            });
        let mut selection = PathSelection::none();
        if let Some(path) = chosen {
            selection.set(path);
        }
        selection
    }
}

impl PathSelector for GossipLadder {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        self.select_at(n0_future::time::Instant::now(), ctx)
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_iroh_transport_util::Rung;

    use super::*;

    /// The ladder names this crate's transport by the id that the transport uses. The id is
    /// written twice, here and in the util crate, which is below this one; this is the guard
    /// that they stay equal.
    #[test]
    fn the_ladder_knows_the_gossip_transport_id_of_this_crate() {
        assert_eq!(custom_rung(crate::GOSSIP_TRANSPORT_ID), Rung::Gossip);
    }

    /// A gossip path that receives nothing, while the relay is heard from, does not stay selected.
    #[test]
    fn a_gossip_path_that_receives_nothing_does_not_stay_selected() {
        use std::time::Duration;

        use iroh::endpoint::PathStats;
        use iroh::endpoint::transports::{Addr, FourTuple};

        let gossip = FourTuple::from_remote(Addr::Custom(iroh_base::CustomAddr::from_parts(
            crate::GOSSIP_TRANSPORT_ID,
            &[1],
        )));
        let remote = SecretKey::from_bytes(&[5; 32]).public();
        let relay = FourTuple::from_remote(Addr::Relay(
            "https://relay.test".parse().expect("a relay url"),
            remote,
        ));
        let entry = |path_address, rx| {
            let mut stats = PathStats::default();
            stats.udp_rx.datagrams = rx;
            PathSelectionData::for_test(path_address, Some(stats))
        };
        let ladder = GossipLadder::new(SecretKey::from_bytes(&[6; 32]).public());
        let start = n0_future::time::Instant::now();

        let first = PathSelectionContext::for_test(None, vec![entry(&gossip, 6), entry(&relay, 3)]);
        assert_eq!(
            ladder.select_at(start, &first).selected_for_test(),
            Some(&gossip)
        );
        let later =
            PathSelectionContext::for_test(None, vec![entry(&gossip, 6), entry(&relay, 23)]);
        assert_eq!(
            ladder
                .select_at(start + Duration::from_secs(10), &later)
                .selected_for_test(),
            Some(&relay)
        );
    }

    use std::time::Duration;

    use iroh::endpoint::{Connection, presets};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};

    use crate::memory::MemoryHub;
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
    async fn node(seed: u8, hub: &MemoryHub, ladder: bool) -> Endpoint {
        let key = SecretKey::from_bytes(&[seed; 32]);
        let handle = GossipHandle::new(key.public());
        hub.join(&handle);
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("loopback"),
            )
            .expect("bind address")
            .add_custom_transport(handle.custom_transport());
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
        let _router = Router::builder(bob.clone()).accept(ALPN, Hold).spawn();
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
        connection
            .paths()
            .iter()
            .find(iroh::endpoint::Path::is_selected)
            .is_some_and(|path| path.is_ip())
    }

    /// The default selector of iroh treats a custom transport as primary: with IP and gossip
    /// both open, the mesh topic would carry the bytes. This is what the ladder prevents.
    #[tokio::test]
    async fn an_endpoint_with_ip_and_gossip_selects_ip() {
        let hub = MemoryHub::new();
        let (alice, bob) = (node(31, &hub, true).await, node(32, &hub, true).await);
        assert!(selects_ip(&alice, &bob).await);
    }

    /// The same endpoints without the ladder: the guard that the test above can fail.
    #[tokio::test]
    async fn without_the_ladder_an_endpoint_with_ip_and_gossip_selects_gossip() {
        let hub = MemoryHub::new();
        let (alice, bob) = (node(33, &hub, false).await, node(34, &hub, false).await);
        assert!(!selects_ip(&alice, &bob).await);
    }

    /// The ladder hides nothing: with no other path, gossip is the one that is selected.
    #[tokio::test]
    async fn the_ladder_selects_gossip_when_it_is_the_only_path() {
        let hub = MemoryHub::new();
        let key = |seed: u8| SecretKey::from_bytes(&[seed; 32]);
        let bind = |seed: u8| {
            let handle = GossipHandle::new(key(seed).public());
            hub.join(&handle);
            async move {
                Endpoint::builder(presets::Minimal)
                    .secret_key(key(seed))
                    .relay_mode(RelayMode::Disabled)
                    .add_custom_transport(handle.custom_transport())
                    .path_selector(handle.path_selector())
                    .clear_ip_transports()
                    .clear_relay_transports()
                    .bind()
                    .await
                    .expect("bind")
            }
        };
        let (alice, bob) = (bind(35).await, bind(36).await);
        let _router = Router::builder(bob.clone()).accept(ALPN, Hold).spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(bob.id(), [TransportAddr::Custom(gossip_addr(bob.id()))]),
                ALPN,
            )
            .await
            .expect("connect");
        assert!(crate::selected_is_gossip(&connection));
    }
}
