//! The messages of the iroh-gossip protocol, by variant and in bytes, from the metrics of the
//! gossip actor: the membership layer (`join` to `disconnect`) and the broadcast layer, where
//! `gossip` carries the payload (our frames) and `ihave`, `graft` and `prune` are control. One size
//! is the 4 bytes of the length prefix and the encoding of the message. The counters are totals
//! since the actor started, so the census keeps the last reading and reports the difference.

use std::sync::{Mutex, PoisonError};

use iroh_gossip::metrics::Metrics;

/// The variants, in the order of the arrays below.
const VARIANTS: [&str; 10] = [
    "join",
    "forward_join",
    "shuffle",
    "shuffle_reply",
    "neighbor",
    "disconnect",
    "gossip",
    "ihave",
    "graft",
    "prune",
];

/// The gossip messages at one moment, or the difference of two readings.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct GossipMsgs {
    pub(crate) sent: [u64; 10],
    pub(crate) sent_bytes: [u64; 10],
    pub(crate) recv: [u64; 10],
    pub(crate) recv_bytes: [u64; 10],
    /// The bytes of the control and of the data messages, in and out.
    pub(crate) ctrl_out: u64,
    pub(crate) data_out: u64,
    pub(crate) ctrl_in: u64,
    pub(crate) data_in: u64,
}

impl GossipMsgs {
    /// The counters of `metrics` now.
    pub(crate) fn read(metrics: &Metrics) -> Self {
        Self {
            sent: [
                metrics.msgs_join_sent.get(),
                metrics.msgs_forward_join_sent.get(),
                metrics.msgs_shuffle_sent.get(),
                metrics.msgs_shuffle_reply_sent.get(),
                metrics.msgs_neighbor_sent.get(),
                metrics.msgs_disconnect_sent.get(),
                metrics.msgs_gossip_sent.get(),
                metrics.msgs_ihave_sent.get(),
                metrics.msgs_graft_sent.get(),
                metrics.msgs_prune_sent.get(),
            ],
            sent_bytes: [
                metrics.msgs_join_sent_size.get(),
                metrics.msgs_forward_join_sent_size.get(),
                metrics.msgs_shuffle_sent_size.get(),
                metrics.msgs_shuffle_reply_sent_size.get(),
                metrics.msgs_neighbor_sent_size.get(),
                metrics.msgs_disconnect_sent_size.get(),
                metrics.msgs_gossip_sent_size.get(),
                metrics.msgs_ihave_sent_size.get(),
                metrics.msgs_graft_sent_size.get(),
                metrics.msgs_prune_sent_size.get(),
            ],
            recv: [
                metrics.msgs_join_recv.get(),
                metrics.msgs_forward_join_recv.get(),
                metrics.msgs_shuffle_recv.get(),
                metrics.msgs_shuffle_reply_recv.get(),
                metrics.msgs_neighbor_recv.get(),
                metrics.msgs_disconnect_recv.get(),
                metrics.msgs_gossip_recv.get(),
                metrics.msgs_ihave_recv.get(),
                metrics.msgs_graft_recv.get(),
                metrics.msgs_prune_recv.get(),
            ],
            recv_bytes: [
                metrics.msgs_join_recv_size.get(),
                metrics.msgs_forward_join_recv_size.get(),
                metrics.msgs_shuffle_recv_size.get(),
                metrics.msgs_shuffle_reply_recv_size.get(),
                metrics.msgs_neighbor_recv_size.get(),
                metrics.msgs_disconnect_recv_size.get(),
                metrics.msgs_gossip_recv_size.get(),
                metrics.msgs_ihave_recv_size.get(),
                metrics.msgs_graft_recv_size.get(),
                metrics.msgs_prune_recv_size.get(),
            ],
            ctrl_out: metrics.msgs_ctrl_sent_size.get(),
            data_out: metrics.msgs_data_sent_size.get(),
            ctrl_in: metrics.msgs_ctrl_recv_size.get(),
            data_in: metrics.msgs_data_recv_size.get(),
        }
    }

    /// The counts since `earlier`, field by field. Zero, not a wrap, if a field went back.
    pub(crate) fn since(self, earlier: Self) -> Self {
        let minus = |current: [u64; 10], previous: [u64; 10]| {
            let mut out = [0u64; 10];
            for (slot, (new_count, old_count)) in
                out.iter_mut().zip(current.into_iter().zip(previous))
            {
                *slot = new_count.saturating_sub(old_count);
            }
            out
        };
        Self {
            sent: minus(self.sent, earlier.sent),
            sent_bytes: minus(self.sent_bytes, earlier.sent_bytes),
            recv: minus(self.recv, earlier.recv),
            recv_bytes: minus(self.recv_bytes, earlier.recv_bytes),
            ctrl_out: self.ctrl_out.saturating_sub(earlier.ctrl_out),
            data_out: self.data_out.saturating_sub(earlier.data_out),
            ctrl_in: self.ctrl_in.saturating_sub(earlier.ctrl_in),
            data_in: self.data_in.saturating_sub(earlier.data_in),
        }
    }
}

/// `variant:value` for each variant with a value, joined by `,`, or `-`.
pub(crate) fn by_variant(values: &[u64; 10]) -> String {
    let named: Vec<String> = VARIANTS
        .iter()
        .zip(values)
        .filter(|(_, value)| **value > 0)
        .map(|(name, value)| format!("{name}:{value}"))
        .collect();
    if named.is_empty() {
        "-".to_owned()
    } else {
        named.join(",")
    }
}

/// The reading at the last census, for the gossip actor of the process.
static MARK: Mutex<Option<GossipMsgs>> = Mutex::new(None);

/// What the gossip actor counted since the last call. The first call covers the time since the
/// actor started.
pub(crate) fn gossip_msgs_delta(metrics: &Metrics) -> GossipMsgs {
    let now = GossipMsgs::read(metrics);
    let mut mark = MARK.lock().unwrap_or_else(PoisonError::into_inner);
    let earlier = mark.replace(now).unwrap_or_default();
    now.since(earlier)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh_gossip::api::Event;
    use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
    use iroh_gossip::proto;
    use n0_future::StreamExt as _;
    use tokio::time;

    use super::{GossipMsgs, by_variant};
    use crate::lookup;

    #[test]
    fn the_variants_are_named_and_the_empty_reads_a_dash() {
        assert_eq!(by_variant(&[0; 10]), "-");
        let mut counts = [0u64; 10];
        counts[0] = 3;
        counts[6] = 90;
        assert_eq!(by_variant(&counts), "join:3,gossip:90");
        let mut later = counts;
        later[6] = 120;
        let delta = GossipMsgs {
            sent: later,
            ..GossipMsgs::default()
        }
        .since(GossipMsgs {
            sent: counts,
            ..GossipMsgs::default()
        });
        assert_eq!(
            by_variant(&delta.sent),
            "gossip:30",
            "the difference, saturating"
        );
    }

    /// A broadcast between two real gossip nodes shows in the metrics of both: data messages out
    /// of the sender and into the receiver, and the join as control messages, by variant.
    #[test]
    fn a_broadcast_between_two_nodes_shows_in_the_message_counters() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let bind = || async {
                    iroh::Endpoint::builder(presets::Minimal)
                        .relay_mode(iroh::RelayMode::Disabled)
                        .bind()
                        .await
                        .expect("bind a loopback endpoint")
                };
                let (first, second) = (bind().await, bind().await);
                let (go_first, go_second) = (
                    Gossip::builder().spawn(first.clone()),
                    Gossip::builder().spawn(second.clone()),
                );
                let router_first = Router::builder(first.clone())
                    .accept(GOSSIP_ALPN, go_first.clone())
                    .spawn();
                let router_second = Router::builder(second.clone())
                    .accept(GOSSIP_ALPN, go_second.clone())
                    .spawn();
                lookup::add_peer_addr(&lookup::address_book(&second), first.addr());
                lookup::add_peer_addr(&lookup::address_book(&first), second.addr());

                let topic = proto::TopicId::from_bytes([3u8; 32]);
                let first_topic = go_first.subscribe(topic, vec![]).await.expect("subscribe");
                let mut second_topic = go_second
                    .subscribe_and_join(topic, vec![first.id()])
                    .await
                    .expect("join the first node");
                let (sink, _stream) = first_topic.split();
                let payload = bytes::Bytes::from(vec![9u8; 300]);
                sink.broadcast(payload.clone()).await.expect("broadcast");
                time::timeout(Duration::from_secs(10), async {
                    while let Some(event) = second_topic.next().await {
                        if let Ok(Event::Received(message)) = event {
                            assert_eq!(message.content, payload);
                            return;
                        }
                    }
                })
                .await
                .expect("the payload arrives");

                let sent = GossipMsgs::read(go_first.metrics());
                let got = GossipMsgs::read(go_second.metrics());
                assert!(
                    sent.sent[6] >= 1,
                    "the sender sent a gossip message: {sent:?}"
                );
                assert!(
                    sent.data_out >= 304,
                    "its bytes hold the payload: {}",
                    sent.data_out
                );
                assert!(got.recv[6] >= 1, "the receiver read it: {got:?}");
                assert!(got.data_in >= 304);
                assert!(got.ctrl_out > 0, "the joiner sent control messages");
                assert!(sent.ctrl_in > 0, "and the first node read them");
                let _ = Arc::clone(go_first.metrics());

                router_first.shutdown().await.expect("shutdown");
                router_second.shutdown().await.expect("shutdown");
            },
        );
    }
}
