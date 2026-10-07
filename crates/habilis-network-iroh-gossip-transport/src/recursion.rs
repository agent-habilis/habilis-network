//! The recursion rule: a connection whose selected path is the gossip rung is closed.
//!
//! The gossip links (the `GOSSIP_ALPN` connections) carry the frames. If one of
//! them were on the gossip path, its packets would ride frames that ride the same
//! connection, and nothing would ever be delivered. Path selection cannot prevent it,
//! because iroh picks one path per remote for all connections, so the connection
//! is closed and the gossip layer dials again.

use iroh::TransportAddr;
use iroh::endpoint::Connection;
use n0_future::StreamExt as _;

use crate::GOSSIP_TRANSPORT_ID;

/// Whether the selected path of `connection` is the gossip rung.
#[must_use]
pub fn selected_is_gossip(connection: &Connection) -> bool {
    connection.paths().iter().any(|path| {
        path.is_selected()
            && matches!(path.remote_addr(), TransportAddr::Custom(addr) if addr.id() == GOSSIP_TRANSPORT_ID)
    })
}

/// Close `connection` with `code` as soon as its selected path is the gossip rung,
/// now or after a path change, and call `on_close` once when it does. The watch
/// holds the connection weakly and ends when the connection closes.
///
/// It does not depend on any relay or mesh policy: the rule holds whatever the policy
/// says.
pub fn watch_recursion(
    connection: &Connection,
    code: u32,
    on_close: impl FnOnce() + Send + 'static,
) {
    let weak = connection.weak_handle();
    let mut events = connection.path_events();
    n0_future::task::spawn(async move {
        loop {
            let Some(live) = weak.upgrade() else {
                return;
            };
            if live.close_reason().is_some() {
                return;
            }
            if selected_is_gossip(&live) {
                live.close(code.into(), b"a gossip link on the gossip path");
                on_close();
                return;
            }
            // Do not hold the connection while waiting: the watch must not keep a
            // link open that the gossip layer has dropped.
            drop(live);
            if events.next().await.is_none() {
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use iroh::endpoint::{ConnectionError, presets};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
    use tokio::sync::oneshot;

    use super::{selected_is_gossip, watch_recursion};
    use crate::memory::MemoryHub;
    use crate::{GossipHandle, gossip_addr};

    const ALPN: &[u8] = b"habilis-network-gossip/test-recursion/0";
    const CODE: u32 = 77;

    fn secret(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    /// Reports how its connection was closed.
    #[derive(Debug, Clone)]
    struct CloseProbe(Arc<Mutex<Option<oneshot::Sender<ConnectionError>>>>);

    impl ProtocolHandler for CloseProbe {
        async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
            let reason = connection.closed().await;
            if let Some(tx) = self.0.lock().expect("probe lock").take() {
                let _ = tx.send(reason);
            }
            Ok(())
        }
    }

    async fn gossip_only_endpoint(key: SecretKey, handle: &GossipHandle) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .add_custom_transport(handle.custom_transport())
            .clear_ip_transports()
            .clear_relay_transports()
            .bind()
            .await
            .expect("bind")
    }

    /// A connection on the gossip path is closed with the code, at both ends, and the
    /// callback runs once.
    #[tokio::test]
    async fn a_connection_on_the_gossip_path_is_closed_with_the_code() {
        let hub = MemoryHub::new();
        let (alice_handle, bob_handle) = (
            GossipHandle::new(secret(1).public()),
            GossipHandle::new(secret(2).public()),
        );
        hub.join(&alice_handle);
        hub.join(&bob_handle);
        let alice = gossip_only_endpoint(secret(1), &alice_handle).await;
        let bob = gossip_only_endpoint(secret(2), &bob_handle).await;
        let (tx, rx) = oneshot::channel();
        let _router = Router::builder(bob.clone())
            .accept(ALPN, CloseProbe(Arc::new(Mutex::new(Some(tx)))))
            .spawn();
        let connection = alice
            .connect(
                EndpointAddr::from_parts(bob.id(), [TransportAddr::Custom(gossip_addr(bob.id()))]),
                ALPN,
            )
            .await
            .expect("connect over gossip");
        assert!(
            selected_is_gossip(&connection),
            "the test connection is on gossip"
        );
        let (called, called_rx) = oneshot::channel();

        watch_recursion(&connection, CODE, move || {
            let _ = called.send(());
        });

        let at_bob = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("the connection was not closed")
            .expect("the probe reported");
        assert!(
            matches!(&at_bob, ConnectionError::ApplicationClosed(close) if u64::from(close.error_code) == u64::from(CODE)),
            "{at_bob:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), called_rx)
            .await
            .expect("the callback did not run")
            .expect("the callback ran");
    }

    /// A connection on IP is left alone.
    #[tokio::test]
    async fn a_connection_on_ip_is_left_open() {
        let loopback = |key: SecretKey| async move {
            Endpoint::builder(presets::Minimal)
                .secret_key(key)
                .relay_mode(RelayMode::Disabled)
                .bind_addr(
                    "127.0.0.1:0"
                        .parse::<std::net::SocketAddr>()
                        .expect("loopback"),
                )
                .expect("bind address")
                .bind()
                .await
                .expect("bind")
        };
        let (alice, bob) = (loopback(secret(3)).await, loopback(secret(4)).await);
        let (tx, _rx) = oneshot::channel();
        let _router = Router::builder(bob.clone())
            .accept(ALPN, CloseProbe(Arc::new(Mutex::new(Some(tx)))))
            .spawn();
        let connection = alice.connect(bob.addr(), ALPN).await.expect("connect");
        assert!(!selected_is_gossip(&connection));

        watch_recursion(&connection, CODE, || panic!("closed a connection on IP"));
        tokio::time::sleep(Duration::from_millis(800)).await;

        assert!(
            connection.close_reason().is_none(),
            "the IP connection was closed"
        );
    }
}
