//! The bytes that the iroh socket moved, from the endpoint metrics: the `UDP` payload of everything
//! `QUIC` sends and receives, so what the frames of the wire census cost once `QUIC` has framed,
//! acknowledged and encrypted them. The counters are totals since the endpoint started, so the
//! census keeps the last reading and reports the difference.

use std::mem;
use std::sync::{Mutex, PoisonError};

use iroh::Endpoint;

/// The bytes of an `IPv4` and a `UDP` header, which the socket counters do not include.
const IP_UDP_HEADER: u64 = 28;

/// The reading at the last census. The counters belong to the endpoint, which a process has one of,
/// so the mark is kept here and not in the state of the loop.
static MARK: Mutex<SocketBytes> = Mutex::new(SocketBytes::ZERO);

/// The bytes that the socket moved since the last call. The first call covers the time since the
/// endpoint started.
pub(crate) fn socket_delta(endpoint: &Endpoint) -> SocketBytes {
    let now = SocketBytes::read(endpoint);
    let mut mark = MARK.lock().unwrap_or_else(PoisonError::into_inner);
    now.since(mem::replace(&mut *mark, now))
}

/// The socket counters at one moment, or the difference of two readings.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct SocketBytes {
    /// Bytes sent over `IPv4` and `IPv6`.
    pub(crate) send_ip: u64,
    pub(crate) send_relay: u64,
    /// Data bytes received over `IPv4` and `IPv6`.
    pub(crate) recv_ip: u64,
    pub(crate) recv_relay: u64,
    pub(crate) recv_custom: u64,
    /// `QUIC` datagrams received. The send side has no such counter.
    pub(crate) recv_datagrams: u64,
}

impl SocketBytes {
    const ZERO: Self = Self {
        send_ip: 0,
        send_relay: 0,
        recv_ip: 0,
        recv_relay: 0,
        recv_custom: 0,
        recv_datagrams: 0,
    };

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
            recv_relay: socket.recv_data_relay.get(),
            recv_custom: socket.recv_data_custom.get(),
            recv_datagrams: socket.recv_datagrams.get(),
        }
    }

    /// The bytes since `earlier`, field by field. Zero, not a wrap, if a field went back.
    pub(crate) fn since(self, earlier: Self) -> Self {
        Self {
            send_ip: self.send_ip.saturating_sub(earlier.send_ip),
            send_relay: self.send_relay.saturating_sub(earlier.send_relay),
            recv_ip: self.recv_ip.saturating_sub(earlier.recv_ip),
            recv_relay: self.recv_relay.saturating_sub(earlier.recv_relay),
            recv_custom: self.recv_custom.saturating_sub(earlier.recv_custom),
            recv_datagrams: self.recv_datagrams.saturating_sub(earlier.recv_datagrams),
        }
    }

    /// The `IPv4` and `UDP` header bytes of the received datagrams, which only the host sees.
    pub(crate) fn header_bytes_in(self) -> u64 {
        self.recv_datagrams.saturating_mul(IP_UDP_HEADER)
    }
}

#[cfg(test)]
mod tests {
    use iroh::endpoint::{self, presets};
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};

    use super::SocketBytes;
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
        assert_eq!(
            SocketBytes {
                recv_datagrams: 4,
                ..SocketBytes::default()
            }
            .header_bytes_in(),
            4 * 28
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

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }
}
