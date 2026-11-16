//! Where a frame goes: the data lane of the Nostr relay client.

use bytes::Bytes;
use habilis_network_iroh_gossip_transport::{FrameSink, frame};
use habilis_network_iroh_nostr_address_lookup::DataPool;
use habilis_network_protocol::nostr::NostrKeys;

/// Sends each frame to the tag of its destination. The pool drops what the socket cannot
/// carry, and QUIC sends it again. The sink refuses a frame while no data relay is connected.
#[derive(Debug)]
pub(crate) struct DataSink {
    pool: DataPool,
    keys: NostrKeys,
}

impl DataSink {
    pub(crate) fn new(pool: DataPool, keys: NostrKeys) -> Self {
        Self { pool, keys }
    }
}

impl FrameSink for DataSink {
    fn try_send(&self, frame: Bytes) -> bool {
        if !self.is_alive() {
            return false;
        }
        let Ok(decoded) = frame::decode(&frame) else {
            return false;
        };
        let tag = self.keys.self_tag(&decoded.dst);
        self.pool.send(&tag, frame.to_vec());
        true
    }

    /// The path is valid while a data relay takes a datagram: one that is `Up`, or one that a
    /// rate limit stopped and whose wait is over. In the second case the next frame is the probe
    /// that ends the limit: a path that is valid only while a relay is `Up` would drop every frame
    /// in the core, no probe would go out, and the lane would never return.
    fn is_alive(&self) -> bool {
        self.pool.sendable()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use habilis_network_iroh_gossip_transport::{Frame, FrameSink};
    use habilis_network_iroh_nostr_address_lookup::DataPool;
    use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
    use habilis_network_protocol::TopicId;
    use habilis_network_protocol::nostr::NostrKeys;
    use iroh::SecretKey;
    use tokio::time;

    use super::DataSink;

    fn frame(from: &SecretKey, to: &SecretKey) -> Bytes {
        let datagram = [1u8; 40];
        let frame = Frame::fixture(to.public(), from.public(), &datagram);
        frame.encode().expect("a frame")
    }

    /// The path of a sink is valid only while a data relay is connected, and a frame that no
    /// relay can take is refused, so the core counts it as refused and not as sent.
    #[test]
    fn a_sink_with_no_data_relay_is_not_alive_and_refuses_a_frame() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "habilis_network::lookup",
                "a pool with no relays reaches no one",
            );
            let keys = NostrKeys::derive(&TopicId::from_bytes([2u8; 32]));
            let (alice, bob) = (
                SecretKey::from_bytes(&[1; 32]),
                SecretKey::from_bytes(&[2; 32]),
            );
            let tag = keys.self_tag(&alice.public());
            let (pool, _datagrams) = DataPool::open(Vec::new(), *alice.public().as_bytes(), tag);
            let sink = DataSink::new(pool, keys);
            assert!(!sink.is_alive(), "no relay, no valid path");
            assert!(!sink.try_send(frame(&alice, &bob)), "no relay, no frame");
        });
    }

    #[test]
    fn a_sink_with_a_connected_data_relay_is_alive() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let relay = TestRelay::spawn().await.expect("spawn a relay");
            let keys = NostrKeys::derive(&TopicId::from_bytes([3u8; 32]));
            let (alice, bob) = (
                SecretKey::from_bytes(&[1; 32]),
                SecretKey::from_bytes(&[2; 32]),
            );
            let tag = keys.self_tag(&alice.public());
            let (pool, _datagrams) =
                DataPool::open(vec![relay.url()], *alice.public().as_bytes(), tag);
            let sink = DataSink::new(pool, keys);
            for _ in 0..100 {
                if sink.is_alive() {
                    break;
                }
                time::sleep(Duration::from_millis(100)).await;
            }
            assert!(
                sink.is_alive(),
                "a connected data relay makes the path valid"
            );
            assert!(sink.try_send(frame(&alice, &bob)), "and takes a frame");
        });
    }

    /// A relay that refuses a frame with "rate-limited:" limits the socket for a wait. With one data
    /// relay, the path must stay valid once the wait is over and hand the first frame to the sink:
    /// that frame is the probe, and its `OK` ends the limit. A path that is valid only while a
    /// relay is `Up` drops every frame in the core, so no probe goes out and the lane never
    /// returns.
    #[test]
    fn the_data_lane_recovers_after_a_rate_limited_answer_with_one_relay() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let relay = TestRelay::spawn().await.expect("spawn a relay");
                let keys = NostrKeys::derive(&TopicId::from_bytes([4u8; 32]));
                let (alice, bob) = (
                    SecretKey::from_bytes(&[1; 32]),
                    SecretKey::from_bytes(&[2; 32]),
                );
                let (alice_pool, _alice_datagrams) = DataPool::open(
                    vec![relay.url()],
                    *alice.public().as_bytes(),
                    keys.self_tag(&alice.public()),
                );
                let (_bob_pool, mut bob_datagrams) = DataPool::open(
                    vec![relay.url()],
                    *bob.public().as_bytes(),
                    keys.self_tag(&bob.public()),
                );
                let sink = DataSink::new(alice_pool, keys);
                for _ in 0..100 {
                    if sink.is_alive() {
                        break;
                    }
                    time::sleep(Duration::from_millis(100)).await;
                }
                assert!(sink.is_alive(), "the relay is Up");

                // One refusal limits the socket.
                relay.refuse_events(Some("rate-limited: slow down"));
                let first = frame(&alice, &bob);
                assert!(sink.try_send(first), "the frame goes out");
                time::sleep(Duration::from_millis(500)).await;
                relay.refuse_events(None);

                // The wait is over within a few seconds. The sink hands frames over from then on, and
                // the first one is the probe that ends the limit.
                let wanted = frame(&alice, &bob);
                let delivered = time::timeout(Duration::from_secs(30), async {
                    loop {
                        if sink.is_alive() {
                            let _ = sink.try_send(wanted.clone());
                        }
                        if let Ok(Some(datagram)) =
                            time::timeout(Duration::from_millis(300), bob_datagrams.recv()).await
                            && datagram.bytes == wanted
                        {
                            return;
                        }
                    }
                })
                .await;
                assert!(
                    delivered.is_ok(),
                    "the lane never recovered after one rate-limited answer"
                );
            },
        );
    }
}
