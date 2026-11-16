//! The largest frame that iroh hands a frame transport fits the datagram limit of the data lane
//! (2048 B, see `DataPool`): QUIC sizes its packets by the path MTU, which iroh bounds at 1452 B
//! whatever the transport, and the frame adds a 66 B header. A bulk transfer shows it on a real
//! connection: path MTU discovery has probed as high as it goes by the end.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use habilis_network_iroh_gossip_transport::hub::Hub;
use habilis_network_iroh_gossip_transport::{
    FrameSink, GossipHandle, NOSTR_TRANSPORT_ID, transport_addr,
};
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
use tokio::io;

/// The datagram limit of the data lane.
const DATA_LANE_LIMIT: usize = 2048;
const ALPN: &[u8] = b"habilis-network-nostr/test-size/0";
/// Enough bytes for path MTU discovery to finish.
const BULK: usize = 4 << 20;

/// A sink that keeps the size of the largest frame, and passes every frame on to the hub.
#[derive(Debug)]
struct Measuring {
    hub: Hub,
    from: GossipHandle,
    // the sink, the test and the handle read the same counters
    largest: Arc<AtomicUsize>,
    // the sink, the test and the handle read the same counters
    frames: Arc<Mutex<usize>>,
}

impl FrameSink for Measuring {
    fn try_send(&self, frame: Bytes) -> bool {
        self.largest.fetch_max(frame.len(), Ordering::SeqCst);
        *self.frames.lock().expect("no poison") += 1;
        self.hub.flood(&self.from, &frame);
        true
    }
}

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

async fn endpoint(key: SecretKey, handle: &GossipHandle) -> Endpoint {
    let builder = Endpoint::builder(presets::Minimal);
    let builder = builder.secret_key(key);
    let builder = builder.relay_mode(RelayMode::Disabled);
    let builder = builder.add_custom_transport(handle.custom_transport());
    let builder = builder.clear_ip_transports();
    let builder = builder.clear_relay_transports();
    builder.bind().await.expect("bind a Nostr-only endpoint")
}

#[test]
fn the_largest_frame_of_a_bulk_transfer_fits_the_data_lane() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let hub = Hub::new();
            let (alice_key, bob_key) = (
                SecretKey::from_bytes(&[11; 32]),
                SecretKey::from_bytes(&[12; 32]),
            );
            let alice_handle =
                GossipHandle::with_transport_id(alice_key.public(), NOSTR_TRANSPORT_ID);
            let bob_handle = GossipHandle::with_transport_id(bob_key.public(), NOSTR_TRANSPORT_ID);
            hub.join(&bob_handle);
            // the sink, the test and the handle read the same counters
            let largest = Arc::new(AtomicUsize::new(0));
            // the sink, the test and the handle read the same counters
            let frames = Arc::new(Mutex::new(0usize));
            hub.join(&alice_handle);
            // `join` attached the sink of the hub to alice: the measuring sink replaces it, and
            // the handle keeps it while the test reads the counters through its clones.
            alice_handle.attach(Arc::new(Measuring {
                hub: hub.clone(),
                from: alice_handle.clone(),
                largest: Arc::clone(&largest),
                frames: Arc::clone(&frames),
            }));
            let alice = endpoint(alice_key, &alice_handle).await;
            let bob = endpoint(bob_key, &bob_handle).await;
            let router = Router::builder(bob.clone()).accept(ALPN, Echo).spawn();
            let target = EndpointAddr::from_parts(
                bob.id(),
                [TransportAddr::Custom(transport_addr(
                    NOSTR_TRANSPORT_ID,
                    bob.id(),
                ))],
            );
            let connection = alice.connect(target, ALPN).await.expect("connect");
            let (mut send, mut recv) = connection.open_bi().await.expect("open a stream");
            let writer = tokio::spawn(async move {
                let block = vec![0x5a_u8; 64 << 10];
                let mut written = 0;
                while written < BULK {
                    send.write_all(&block).await.expect("write");
                    written += block.len();
                }
                send.finish().expect("finish");
            });
            let echoed = recv.read_to_end(BULK + 1).await.expect("read the echo");
            writer.await.expect("the writer ends");
            assert_eq!(echoed.len(), BULK, "the whole transfer came back");

            let largest = largest.load(Ordering::SeqCst);
            assert!(
                largest > 1000,
                "the transfer carried full packets: the largest frame is {largest} B"
            );
            assert!(
                largest <= DATA_LANE_LIMIT,
                "the largest frame is {largest} B, over the {DATA_LANE_LIMIT} B of the data lane"
            );
            connection.close(0u32.into(), b"done");
            router.shutdown().await.expect("shutdown");
            alice.close().await;
        },
    );
}
