//! Two endpoints whose only transport is Nostr link and echo through an in-process relay.

use std::time::Duration;

use habilis_network_iroh_gossip_transport::{NOSTR_TRANSPORT_ID, transport_addr};
use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use habilis_network_iroh_nostr_transport::NostrTransport;
use habilis_network_protocol::TopicId;
use habilis_network_protocol::nostr::NostrKeys;
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
use tokio::{io, time};

const ECHO_ALPN: &[u8] = b"habilis-network-nostr/test-echo/0";

#[derive(Debug, Clone, Copy)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            io::copy(&mut recv, &mut send).await?;
            send.finish()?;
        }
        Ok(())
    }
}

async fn endpoint(key: SecretKey, transport: &NostrTransport) -> Endpoint {
    let builder = Endpoint::builder(presets::Minimal);
    let builder = builder.secret_key(key);
    let builder = builder.relay_mode(RelayMode::Disabled);
    let builder = builder.add_custom_transport(transport.handle().custom_transport());
    let builder = builder.clear_ip_transports();
    let builder = builder.clear_relay_transports();
    builder.bind().await.expect("bind a Nostr-only endpoint")
}

#[test]
fn two_endpoints_with_only_nostr_echo_through_a_relay() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let relay = TestRelay::spawn().await.expect("spawn a relay");
            let keys = NostrKeys::derive(&TopicId::from_bytes([9u8; 32]));
            let (alice_key, bob_key) = (
                SecretKey::from_bytes(&[1; 32]),
                SecretKey::from_bytes(&[2; 32]),
            );
            let alice_transport =
                NostrTransport::open(alice_key.public(), keys.clone(), vec![relay.url()]);
            let bob_transport = NostrTransport::open(bob_key.public(), keys, vec![relay.url()]);
            let alice = endpoint(alice_key, &alice_transport).await;
            let bob = endpoint(bob_key, &bob_transport).await;
            let router = Router::builder(bob.clone()).accept(ECHO_ALPN, Echo).spawn();

            let target = EndpointAddr::from_parts(
                bob.id(),
                [TransportAddr::Custom(transport_addr(
                    NOSTR_TRANSPORT_ID,
                    bob.id(),
                ))],
            );
            let connection =
                time::timeout(Duration::from_secs(20), alice.connect(target, ECHO_ALPN))
                    .await
                    .expect("the connect timed out")
                    .expect("connect over Nostr");
            let (mut send, mut recv) = connection.open_bi().await.expect("open a stream");
            send.write_all(b"hello over nostr").await.expect("write");
            send.finish().expect("finish");
            let echoed = time::timeout(Duration::from_secs(20), recv.read_to_end(1024))
                .await
                .expect("the echo timed out")
                .expect("read the echo");
            assert_eq!(echoed, b"hello over nostr", "the echo returns the message");
            assert!(relay.events() > 0, "the datagrams went through the relay");
            connection.close(0u32.into(), b"done");
            router.shutdown().await.expect("shutdown");
            alice.close().await;
        },
    );
}
