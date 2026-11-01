//! The bytes that the iroh socket moved, from the endpoint metrics: the `UDP` payload of everything
//! `QUIC` sends and receives, so what the frames of the wire census cost once `QUIC` has framed,
//! acknowledged and encrypted them. The counters are totals since the endpoint started, so the
//! census keeps the last reading and reports the difference.

use std::mem;

use habilis_network_iroh_gossip_transport::{GossipHandle, Stats};
use iroh::Endpoint;

/// The bytes of an `IPv4` header (20) and a `UDP` header (8), which the socket counters do not
/// include.
const IPV4_UDP_HEADER: u64 = 28;
/// The bytes of an `IPv6` header (40) and a `UDP` header (8).
const IPV6_UDP_HEADER: u64 = 48;

/// The bytes that the socket moved since the reading in `mark`, which becomes the new reading. The
/// mark belongs to the loop that owns `endpoint`: a process with two loops has two endpoints and
/// two marks. The first call, with a zero mark, covers the time since the endpoint started.
pub(crate) fn socket_delta(mark: &mut SocketBytes, endpoint: &Endpoint) -> SocketBytes {
    let now = SocketBytes::read(endpoint);
    now.since(mem::replace(mark, now))
}

/// The socket counters at one moment, or the difference of two readings.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct SocketBytes {
    /// Bytes sent over `IPv4` and `IPv6`.
    pub(crate) send_ip: u64,
    pub(crate) send_relay: u64,
    /// Data bytes received over `IPv4` and `IPv6`.
    pub(crate) recv_ip: u64,
    /// Of those, the bytes received over `IPv6`.
    pub(crate) recv_ipv6: u64,
    pub(crate) recv_relay: u64,
    pub(crate) recv_custom: u64,
    /// `QUIC` datagrams received. The send side has no such counter.
    pub(crate) recv_datagrams: u64,
    /// Paths opened and closed, by kind of transport, and the custom paths that were made. A
    /// custom path is a `WebRTC`, multihop or gossip path.
    pub(crate) paths_custom: u64,
    pub(crate) ip_paths_added: u64,
    pub(crate) ip_paths_removed: u64,
    pub(crate) relay_paths_added: u64,
    pub(crate) relay_paths_removed: u64,
    pub(crate) custom_paths_added: u64,
    pub(crate) custom_paths_removed: u64,
}

impl SocketBytes {
    /// The counters of `endpoint` now.
    pub(crate) fn read(endpoint: &Endpoint) -> Self {
        let socket = &endpoint.metrics().socket;
        Self {
            send_ip: socket
                .send_ipv4
                .get()
                .saturating_add(socket.send_ipv6.get()),
            send_relay: socket.send_relay.get(),
            recv_ip: socket
                .recv_data_ipv4
                .get()
                .saturating_add(socket.recv_data_ipv6.get()),
            recv_ipv6: socket.recv_data_ipv6.get(),
            recv_relay: socket.recv_data_relay.get(),
            recv_custom: socket.recv_data_custom.get(),
            recv_datagrams: socket.recv_datagrams.get(),
            paths_custom: socket.paths_custom.get(),
            ip_paths_added: socket.transport_ip_paths_added.get(),
            ip_paths_removed: socket.transport_ip_paths_removed.get(),
            relay_paths_added: socket.transport_relay_paths_added.get(),
            relay_paths_removed: socket.transport_relay_paths_removed.get(),
            custom_paths_added: socket.transport_custom_paths_added.get(),
            custom_paths_removed: socket.transport_custom_paths_removed.get(),
        }
    }

    /// The bytes since `earlier`, field by field. Zero, not a wrap, if a field went back.
    pub(crate) fn since(self, earlier: Self) -> Self {
        Self {
            send_ip: self.send_ip.saturating_sub(earlier.send_ip),
            send_relay: self.send_relay.saturating_sub(earlier.send_relay),
            recv_ip: self.recv_ip.saturating_sub(earlier.recv_ip),
            recv_ipv6: self.recv_ipv6.saturating_sub(earlier.recv_ipv6),
            recv_relay: self.recv_relay.saturating_sub(earlier.recv_relay),
            recv_custom: self.recv_custom.saturating_sub(earlier.recv_custom),
            recv_datagrams: self.recv_datagrams.saturating_sub(earlier.recv_datagrams),
            paths_custom: self.paths_custom.saturating_sub(earlier.paths_custom),
            ip_paths_added: self.ip_paths_added.saturating_sub(earlier.ip_paths_added),
            ip_paths_removed: self
                .ip_paths_removed
                .saturating_sub(earlier.ip_paths_removed),
            relay_paths_added: self
                .relay_paths_added
                .saturating_sub(earlier.relay_paths_added),
            relay_paths_removed: self
                .relay_paths_removed
                .saturating_sub(earlier.relay_paths_removed),
            custom_paths_added: self
                .custom_paths_added
                .saturating_sub(earlier.custom_paths_added),
            custom_paths_removed: self
                .custom_paths_removed
                .saturating_sub(earlier.custom_paths_removed),
        }
    }

    /// The `IP` and `UDP` header bytes of the received datagrams, which only the host sees: 28
    /// bytes for a datagram over `IPv4` and 48 over `IPv6`. The socket counts datagrams without the
    /// family, so the share of `IPv6` datagrams is taken from the share of `IPv6` bytes, and the
    /// result is an estimate.
    pub(crate) fn header_bytes_in(self) -> u64 {
        let ipv6_datagrams = if self.recv_ip == 0 {
            0
        } else {
            let share = u128::from(self.recv_datagrams) * u128::from(self.recv_ipv6)
                / u128::from(self.recv_ip);
            u64::try_from(share)
                .unwrap_or(u64::MAX)
                .min(self.recv_datagrams)
        };
        let ipv4_datagrams = self.recv_datagrams - ipv6_datagrams;
        ipv4_datagrams
            .saturating_mul(IPV4_UDP_HEADER)
            .saturating_add(ipv6_datagrams.saturating_mul(IPV6_UDP_HEADER))
    }
}

/// What the gossip transport counted: `QUIC` packets that the mesh topic carried for a pair with
/// no other path, from [`GossipHandle::stats`]. Totals since the handle was made, or the difference
/// of two readings. A frame here is a flood on the topic, so its bytes are paid by every member.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct GossipPathBytes {
    pub(crate) frames_out: u64,
    pub(crate) bytes_out: u64,
    pub(crate) frames_in: u64,
    pub(crate) bytes_in: u64,
    /// Frames of the topic that were for another member.
    pub(crate) not_for_us: u64,
    /// Frames and datagrams that were dropped, whatever the reason.
    pub(crate) dropped: u64,
}

impl GossipPathBytes {
    pub(crate) fn from_stats(stats: Stats) -> Self {
        let dropped = [
            stats.queue_full,
            stats.dropped_no_sink,
            stats.dropped_too_large,
            stats.dropped_empty,
            stats.dropped_sink_refused,
            stats.dropped_not_allowed,
            stats.dropped_budget,
            stats.dropped_oversized_in,
        ];
        Self {
            frames_out: stats.frames_out,
            bytes_out: stats.bytes_out,
            frames_in: stats.frames_in,
            bytes_in: stats.bytes_in,
            not_for_us: stats.not_for_us,
            dropped: dropped
                .iter()
                .fold(0, |sum, count| sum.saturating_add(*count)),
        }
    }

    /// The counts since `earlier`, field by field. Zero, not a wrap, if a field went back.
    pub(crate) fn since(self, earlier: Self) -> Self {
        Self {
            frames_out: self.frames_out.saturating_sub(earlier.frames_out),
            bytes_out: self.bytes_out.saturating_sub(earlier.bytes_out),
            frames_in: self.frames_in.saturating_sub(earlier.frames_in),
            bytes_in: self.bytes_in.saturating_sub(earlier.bytes_in),
            not_for_us: self.not_for_us.saturating_sub(earlier.not_for_us),
            dropped: self.dropped.saturating_sub(earlier.dropped),
        }
    }
}

/// What the gossip transport counted since the reading in `mark`, which becomes the new reading:
/// all zero when the mesh has no gossip transport. The mark belongs to the loop that owns
/// `handle`. The first call, with a zero mark, covers the time since the handle was made.
pub(crate) fn gossip_path_delta(
    mark: &mut GossipPathBytes,
    handle: Option<&GossipHandle>,
) -> GossipPathBytes {
    let Some(handle) = handle else {
        return GossipPathBytes::default();
    };
    let now = GossipPathBytes::from_stats(handle.stats());
    now.since(mem::replace(mark, now))
}

#[cfg(test)]
mod tests {
    use iroh::endpoint::{self, presets};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};

    use habilis_network_iroh_gossip_transport::Stats;

    use super::{GossipPathBytes, SocketBytes, gossip_path_delta, socket_delta};
    use crate::lookup;

    const ALPN: &[u8] = b"socket-bytes-test";

    #[test]
    fn since_is_the_difference_and_saturates() {
        let earlier = SocketBytes {
            send_ip: 10,
            recv_datagrams: 7,
            ..SocketBytes::default()
        };
        let later = SocketBytes {
            send_ip: 25,
            recv_datagrams: 3,
            ..SocketBytes::default()
        };
        let delta = later.since(earlier);
        assert_eq!(delta.send_ip, 15);
        assert_eq!(delta.recv_datagrams, 0, "a field that went back reads zero");
    }

    /// The header of a datagram is 28 bytes over `IPv4` and 48 over `IPv6`.
    #[test]
    fn the_header_bytes_follow_the_share_of_ipv6() {
        let received = |recv_ip, recv_ipv6| SocketBytes {
            recv_datagrams: 4,
            recv_ip,
            recv_ipv6,
            ..SocketBytes::default()
        };

        assert_eq!(received(1000, 0).header_bytes_in(), 4 * 28, "all IPv4");
        assert_eq!(received(1000, 1000).header_bytes_in(), 4 * 48, "all IPv6");
        assert_eq!(
            received(1000, 500).header_bytes_in(),
            2 * 28 + 2 * 48,
            "half of the bytes over IPv6: 2 datagrams each"
        );
        assert_eq!(
            received(0, 0).header_bytes_in(),
            4 * 28,
            "no bytes to tell by"
        );
    }

    #[test]
    fn the_gossip_transport_stats_are_summed_and_differenced() {
        let mut stats = Stats::default();
        stats.frames_out = 4;
        stats.bytes_out = 4_000;
        stats.frames_in = 9;
        stats.bytes_in = 9_000;
        stats.not_for_us = 5;
        stats.queue_full = 1;
        stats.dropped_budget = 2;
        stats.dropped_empty = 3;
        let reading = GossipPathBytes::from_stats(stats);
        assert_eq!(reading.dropped, 6, "every kind of drop is in the sum");
        assert_eq!(reading.bytes_in, 9_000);

        stats.frames_out = 7;
        stats.bytes_out = 5_500;
        let later = GossipPathBytes::from_stats(stats).since(reading);
        assert_eq!((later.frames_out, later.bytes_out), (3, 1_500));
        assert_eq!(later.frames_in, 0, "nothing came in since");
        assert_eq!(
            GossipPathBytes::default().since(reading).bytes_in,
            0,
            "saturates"
        );
        assert_eq!(
            gossip_path_delta(&mut GossipPathBytes::default(), None),
            GossipPathBytes::default(),
            "no handle, no count"
        );
    }

    #[derive(Debug, Clone)]
    struct ReadAll;

    impl ProtocolHandler for ReadAll {
        async fn accept(&self, connection: endpoint::Connection) -> Result<(), AcceptError> {
            let mut stream = connection
                .accept_uni()
                .await
                .map_err(AcceptError::from_err)?;
            let _ = stream.read_to_end(1 << 20).await;
            connection.closed().await;
            Ok(())
        }
    }

    /// A client that sends bytes over a loopback connection moves the socket counters of both
    /// ends: the client sends them and the server receives them.
    #[test]
    fn the_bytes_of_a_loopback_transfer_show_in_the_socket_counters() {
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
                let server = bind().await;
                let router = Router::builder(server.clone())
                    .accept(ALPN, ReadAll)
                    .spawn();
                let client = bind().await;
                lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
                let (client_before, server_before) =
                    (SocketBytes::read(&client), SocketBytes::read(&server));
                let (mut client_mark, mut server_mark) =
                    (SocketBytes::default(), SocketBytes::default());
                socket_delta(&mut client_mark, &client);
                socket_delta(&mut server_mark, &server);

                let connection = client
                    .connect(server.id(), ALPN)
                    .await
                    .expect("connect over loopback");
                let sent: usize = 20_000;
                let mut stream = connection.open_uni().await.expect("open a stream");
                stream.write_all(&vec![7u8; sent]).await.expect("write");
                stream.finish().expect("finish");
                stream.stopped().await.expect("the server reads it all");

                let sent_by_client = SocketBytes::read(&client).since(client_before);
                let received_by_server = SocketBytes::read(&server).since(server_before);
                assert!(
                    sent_by_client.send_ip >= sent as u64,
                    "the client sent {} bytes over IP for {sent}",
                    sent_by_client.send_ip
                );
                assert!(
                    received_by_server.recv_ip >= sent as u64,
                    "the server received {} bytes over IP for {sent}",
                    received_by_server.recv_ip
                );
                assert!(received_by_server.recv_datagrams > 0);
                assert_eq!(sent_by_client.send_relay, 0, "no relay on loopback");
                let paths = SocketBytes::read(&client).since(client_before);
                assert!(
                    paths.ip_paths_added >= 1,
                    "the client opened an IP path: {paths:?}"
                );
                assert_eq!(paths.custom_paths_added, 0, "no custom path on loopback");

                // Two loops in one process: the read of the server does not take the bytes that
                // the client is about to report.
                let by_server = socket_delta(&mut server_mark, &server);
                let by_client = socket_delta(&mut client_mark, &client);
                assert!(by_server.recv_ip >= sent as u64, "{by_server:?}");
                assert!(
                    by_client.send_ip >= sent as u64,
                    "the client keeps its own mark: {by_client:?}"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }
}
