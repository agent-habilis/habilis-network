//! The Nostr rung under the ladder of the gossip transport core: IP above, Nostr below. A pair
//! with both selects IP, falls to Nostr when a test takes IP away, and climbs back when IP
//! returns. Here no admission table limits the frames, so the Nostr path is open and valid the
//! whole time, which is what lets the selector move onto it at once.

use std::net::SocketAddr;
use std::time::Duration;

use habilis_network_iroh_gossip_transport::{NOSTR_TRANSPORT_ID, transport_addr};
use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use habilis_network_iroh_nostr_transport::NostrTransport;
use habilis_network_iroh_transport_util::{Rung, block_rung};
use habilis_network_protocol::TopicId;
use habilis_network_protocol::nostr::NostrKeys;
use iroh::endpoint::{Connection, Path, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
use tokio::time;

const ALPN: &[u8] = b"habilis-network-nostr/test-ladder/0";

#[derive(Debug, Clone, Copy)]
struct Hold;

impl ProtocolHandler for Hold {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        connection.closed().await;
        Ok(())
    }
}

/// An endpoint with a loopback UDP socket and the Nostr transport, with the selector of the
/// transport core.
async fn node(key: SecretKey, transport: &NostrTransport) -> Endpoint {
    let builder = Endpoint::builder(presets::Minimal);
    let builder = builder.secret_key(key);
    let builder = builder.relay_mode(RelayMode::Disabled);
    let builder = builder.bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)));
    let builder = builder.expect("bind address");
    let builder = builder.add_custom_transport(transport.handle().custom_transport());
    let builder = builder.path_selector(transport.handle().path_selector());
    builder.bind().await.expect("bind")
}

/// The rung of the selected path of `connection`: `ip`, `nostr`, or `None` while none is selected.
fn rung(connection: &Connection) -> Option<&'static str> {
    let paths = connection.paths();
    let selected = paths.iter().find(Path::is_selected)?;
    if selected.is_ip() {
        return Some("ip");
    }
    match selected.remote_addr() {
        TransportAddr::Custom(address) if address.id() == NOSTR_TRANSPORT_ID => Some("nostr"),
        TransportAddr::Ip(_) | TransportAddr::Relay(_) | TransportAddr::Custom(_) => Some("other"),
        _ => None,
    }
}

/// Wait for the rung, and nudge the pair while waiting: iroh selects again only on a path event,
/// and a dial of the same peer is one (the engine nudges its pairs the same way).
async fn expect_rung(
    alice: &Endpoint,
    target: &EndpointAddr,
    connection: &Connection,
    expected: &str,
    step: &str,
) {
    let mut seen = None;
    for round in 0..120 {
        seen = rung(connection);
        if seen == Some(expected) {
            return;
        }
        if round % 4 == 3
            && let Ok(Ok(nudge)) =
                time::timeout(Duration::from_secs(5), alice.connect(target.clone(), ALPN)).await
        {
            nudge.close(0u32.into(), b"nudge");
        }
        time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{step}: expected the rung {expected}, the last rung read was {seen:?}");
}

#[test]
fn a_pair_falls_to_nostr_when_ip_is_taken_and_climbs_back_when_it_returns() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let relay = TestRelay::spawn().await.expect("spawn a relay");
            let keys = NostrKeys::derive(&TopicId::from_bytes([7u8; 32]));
            let (alice_key, bob_key) = (
                SecretKey::from_bytes(&[5; 32]),
                SecretKey::from_bytes(&[6; 32]),
            );
            let alice_transport =
                NostrTransport::open(alice_key.public(), keys.clone(), vec![relay.url()]);
            let bob_transport = NostrTransport::open(bob_key.public(), keys, vec![relay.url()]);
            let alice = node(alice_key, &alice_transport).await;
            let bob = node(bob_key, &bob_transport).await;
            let router = Router::builder(bob.clone()).accept(ALPN, Hold).spawn();

            let mut both: Vec<TransportAddr> = bob.addr().addrs.into_iter().collect();
            both.push(TransportAddr::Custom(transport_addr(
                NOSTR_TRANSPORT_ID,
                bob.id(),
            )));
            let target = EndpointAddr::from_parts(bob.id(), both);
            let dialing =
                time::timeout(Duration::from_secs(30), alice.connect(target.clone(), ALPN));
            let dialed = dialing.await.expect("the connect timed out");
            let connection: Connection = dialed.expect("connect");
            expect_rung(&alice, &target, &connection, "ip", "nothing blocked").await;

            block_rung(alice.id(), Rung::Ip, true);
            block_rung(bob.id(), Rung::Ip, true);
            expect_rung(&alice, &target, &connection, "nostr", "IP taken").await;
            assert!(relay.events() > 0, "the datagrams went through the relay");

            block_rung(alice.id(), Rung::Ip, false);
            block_rung(bob.id(), Rung::Ip, false);
            expect_rung(&alice, &target, &connection, "ip", "IP returned").await;

            connection.close(0u32.into(), b"done");
            router.shutdown().await.expect("shutdown");
            alice.close().await;
        },
    );
}
