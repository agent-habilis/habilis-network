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
            // The transport starts closed: alice names bob, and bob's replies pass because a
            // frame of alice arrived first.
            alice_transport.handle().allow(bob.id(), true);
            // Bob knows alice as a member, so that a frame of hers opens his replies.
            bob_transport.set_known_peers([alice.id()]);

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

/// The engine binds its endpoint before it knows its topic: the transport is registered inactive
/// and activated when the keys exist. A second `activate` does nothing.
#[test]
fn a_transport_activated_after_the_bind_links_and_echoes() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let relay = TestRelay::spawn().await.expect("spawn a relay");
            let keys = NostrKeys::derive(&TopicId::from_bytes([8u8; 32]));
            let (alice_key, bob_key) = (
                SecretKey::from_bytes(&[3; 32]),
                SecretKey::from_bytes(&[4; 32]),
            );
            let alice_transport = NostrTransport::new(alice_key.public());
            let bob_transport = NostrTransport::new(bob_key.public());
            let alice = endpoint(alice_key, &alice_transport).await;
            let bob = endpoint(bob_key, &bob_transport).await;
            let router = Router::builder(bob.clone()).accept(ECHO_ALPN, Echo).spawn();
            // The transport starts closed: alice names bob, and bob's replies pass because a
            // frame of alice arrived first.
            alice_transport.handle().allow(bob.id(), true);
            // Bob knows alice as a member, so that a frame of hers opens his replies.
            bob_transport.set_known_peers([alice.id()]);
            assert!(
                alice_transport.activate(keys.clone(), vec![relay.url()]),
                "the first activation opens the lane"
            );
            assert!(
                !alice_transport.activate(keys.clone(), vec![relay.url()]),
                "a second activation does nothing"
            );
            assert!(
                bob_transport.activate(keys, vec![relay.url()]),
                "bob opens too"
            );

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
            send.write_all(b"late keys").await.expect("write");
            send.finish().expect("finish");
            let echoed = time::timeout(Duration::from_secs(20), recv.read_to_end(1024))
                .await
                .expect("the echo timed out")
                .expect("read the echo");
            assert_eq!(echoed, b"late keys", "the echo returns the message");
            connection.close(0u32.into(), b"done");
            router.shutdown().await.expect("shutdown");
            alice.close().await;
        },
    );
}

/// A transport starts closed: with no `allow` and no frame received, nothing of it reaches the
/// relay, so a healthy pair never carries a datagram on the last rung by accident.
#[test]
fn a_closed_transport_sends_nothing_to_a_peer_it_was_not_told_about() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let relay = TestRelay::spawn().await.expect("spawn a relay");
            let keys = NostrKeys::derive(&TopicId::from_bytes([5u8; 32]));
            let (alice_key, bob_key) = (
                SecretKey::from_bytes(&[7; 32]),
                SecretKey::from_bytes(&[8; 32]),
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

            let dialed = time::timeout(Duration::from_secs(4), alice.connect(target, ECHO_ALPN));
            assert!(
                !matches!(dialed.await, Ok(Ok(_))),
                "a closed transport links no pair"
            );
            assert_eq!(
                relay.data_events(),
                0,
                "nothing of the transport reached the relay"
            );
            assert!(
                alice_transport.handle().stats().dropped_not_allowed > 0,
                "the refused frames are counted"
            );
            router.shutdown().await.expect("shutdown");
            alice.close().await;
        },
    );
}

/// A datagram of an unknown sender, a known member and a member that the engine stopped: only the
/// known and not stopped member gets replies. The `from` of a batch is not proven, so a stranger
/// must neither open the handle to an id of its choice nor grow its tables.
#[test]
fn a_datagram_opens_replies_only_to_a_known_member_that_the_engine_did_not_stop() {
    use habilis_network_iroh_nostr_address_lookup::DataPool;

    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let relay = TestRelay::spawn().await.expect("spawn a relay");
            let keys = NostrKeys::derive(&TopicId::from_bytes([6u8; 32]));
            let alice_key = SecretKey::from_bytes(&[11; 32]);
            let (known, stopped, stranger) = (
                SecretKey::from_bytes(&[12; 32]).public(),
                SecretKey::from_bytes(&[13; 32]).public(),
                SecretKey::from_bytes(&[14; 32]).public(),
            );
            let alice = NostrTransport::open(alice_key.public(), keys.clone(), vec![relay.url()]);
            alice.set_known_peers([known, stopped]);
            alice.handle().allow(stopped, false);
            let alice_tag = keys.self_tag(&alice_key.public());

            // One sender writes batches that claim each id as their source.
            let (sender, _datagrams) = DataPool::open(
                vec![relay.url()],
                *stranger.as_bytes(),
                keys.self_tag(&stranger),
            );
            for claimed in [stranger, known, stopped] {
                let (pool, _rx) = DataPool::open(
                    vec![relay.url()],
                    *claimed.as_bytes(),
                    keys.self_tag(&claimed),
                );
                for _ in 0..30 {
                    pool.send(&alice_tag, b"not a frame".to_vec());
                    time::sleep(Duration::from_millis(100)).await;
                    if alice.handle().is_allowed(known) {
                        break;
                    }
                }
                drop(pool);
            }
            sender.send(&alice_tag, b"not a frame".to_vec());
            time::sleep(Duration::from_secs(1)).await;

            assert!(
                alice.handle().is_allowed(known),
                "a known member gets replies"
            );
            assert!(
                !alice.handle().is_allowed(stopped),
                "a frame does not lift the refusal of the engine"
            );
            assert!(
                !alice.handle().is_allowed(stranger),
                "a stranger gets no reply and no entry in the tables"
            );
        },
    );
}
