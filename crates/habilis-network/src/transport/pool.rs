//! The dial side of the unicast plane: a per-peer connection pool that dials
//! lazily, reuses a warm QUIC connection across messages, and re-dials after a
//! close. Modeled on the application bridge's shared connection, but keyed per endpoint
//! and with a short dial budget so a send to an unreachable peer fails fast
//! rather than stalling the event loop.

mod in_flight_dial;
mod registration;
mod timeouts;
pub(crate) use timeouts::{COOLDOWN_REFUSED, DIAL_TIMEOUT};
mod unicast_pool;
pub(crate) use unicast_pool::UnicastPool;
mod warm_send;
pub(crate) use warm_send::WarmSend;

#[cfg(test)]
mod tests {
    use crate::testing;
    use crate::util::clock::Instant;
    use habilis_network_test_tracing::test;
    use std::time::Duration;

    use super::timeouts::DIAL_FAILURE_COOLDOWN;
    use crate::util::cooldown::Cooldown;

    use crate::util::tuning;
    use iroh::endpoint::presets;
    use tokio::sync::mpsc;
    #[test]
    fn a_fresh_failure_puts_the_endpoint_on_cooldown() {
        let mut failures = Cooldown::new(DIAL_FAILURE_COOLDOWN);
        let bob = testing::endpoint_id(1);
        let now = Instant::now();
        failures.note(bob, now);
        assert!(
            failures.on_cooldown(&bob, now),
            "a fresh failure puts the endpoint on cooldown"
        );
        // Another endpoint is unaffected.
        assert!(
            !failures.on_cooldown(&testing::endpoint_id(2), now),
            "another endpoint is not on cooldown"
        );
    }

    #[test]
    fn an_expired_failure_allows_the_dial_and_is_pruned() {
        let mut failures = Cooldown::new(DIAL_FAILURE_COOLDOWN);
        let bob = testing::endpoint_id(1);
        let failed_at = Instant::now();
        failures.note(bob, failed_at);
        let later = failed_at + DIAL_FAILURE_COOLDOWN + Duration::from_millis(1);
        assert!(
            !failures.on_cooldown(&bob, later),
            "an expired failure allows the dial again"
        );
        // Pruning happens on the next write rather than on the read, so the
        // table still cannot grow without bound.
        failures.note(testing::endpoint_id(2), later);
        assert_eq!(
            failures.len(),
            1,
            "the stale entry is dropped, not retained"
        );
    }

    /// The offer decision reads the pooled connection synchronously: a UDP
    /// connection reads `true`, while a busy lock or an unknown peer reads
    /// `false`, so the node offers rather than wrongly skipping the race.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pooled_udp_connection_reads_as_udp_selected() {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }
        let bind = || async {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, Hold)
            .spawn();
        let client = bind().await;
        crate::lookup::add_peer_addr(&crate::lookup::address_book(&client), server.addr());
        let pool = super::UnicastPool::new(client.clone(), false);

        assert!(!pool.selected_is_ip(server.id()), "nothing pooled yet");
        pool.warm_or_dial(server.id()).await.expect("dial");
        let started = Instant::now();
        while !pool.selected_is_ip(server.id()) {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "udp never selected"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let held = pool.inner.conns.lock().await;
        assert!(
            !pool.selected_is_ip(server.id()),
            "a busy lock reads as not selected"
        );
        drop(held);

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A loopback server that holds every unicast connection open, and a pool
    /// dialed to it with the given idle timeout.
    async fn pool_with_idle(
        idle: Duration,
    ) -> (
        super::UnicastPool,
        iroh::EndpointId,
        iroh::protocol::Router,
        iroh::Endpoint,
    ) {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }
        let bind = || async {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, Hold)
            .spawn();
        let client = bind().await;
        crate::lookup::add_peer_addr(&crate::lookup::address_book(&client), server.addr());
        let pool = super::UnicastPool::with_idle(client.clone(), false, idle);
        (pool, server.id(), router, client)
    }

    /// Step the paused clock a second at a time, so the sweeper's timer fires
    /// in order with the connection's own.
    async fn advance_secs(seconds: u64) {
        for _ in 0..seconds {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
    }

    /// Closed by this side, not timed out by QUIC and not closed by the peer.
    fn closed_as_idle(connection: &iroh::endpoint::Connection) -> bool {
        matches!(
            connection.close_reason(),
            Some(iroh::endpoint::ConnectionError::LocallyClosed)
        )
    }

    #[test]
    async fn a_pooled_connection_nothing_sends_on_is_closed_after_the_idle_timeout() {
        let (pool, server, router, client) = pool_with_idle(Duration::from_secs(8)).await;
        let connection = pool.warm_or_dial(server).await.expect("dial");
        tokio::time::pause();

        advance_secs(6).await;
        assert!(
            connection.close_reason().is_none() && pool.connection(server).is_some(),
            "inside the idle timeout the connection stays pooled"
        );

        advance_secs(6).await;
        assert!(
            pool.inner.conns.lock().await.is_empty(),
            "an unused connection leaves the pool"
        );
        assert!(
            closed_as_idle(&connection),
            "and is closed, not just dropped"
        );

        tokio::time::resume();
        pool.warm_or_dial(server).await.expect("a send dials again");
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    #[test]
    async fn a_send_restarts_the_idle_timeout() {
        let (pool, server, router, client) = pool_with_idle(Duration::from_secs(8)).await;
        let connection = pool.warm_or_dial(server).await.expect("dial");
        tokio::time::pause();

        advance_secs(5).await;
        assert!(
            pool.warm(server).await.is_some(),
            "a send takes the connection"
        );
        advance_secs(5).await;
        assert!(
            connection.close_reason().is_none() && pool.connection(server).is_some(),
            "five seconds after a send is inside the timeout"
        );

        advance_secs(7).await;
        assert!(closed_as_idle(&connection), "then it idles out as well");

        tokio::time::resume();
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A loopback server that holds every unicast connection open, and a pool
    /// dialed to it with the given idle timeout and probe hold.
    async fn pool_with_holds(
        idle: Duration,
        probe_hold: Duration,
    ) -> (
        super::UnicastPool,
        iroh::EndpointId,
        iroh::protocol::Router,
        iroh::Endpoint,
    ) {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }
        let bind = || async {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, Hold)
            .spawn();
        let client = bind().await;
        crate::lookup::add_peer_addr(&crate::lookup::address_book(&client), server.addr());
        let pool = super::UnicastPool::with_timeouts(client.clone(), false, idle, probe_hold);
        (pool, server.id(), router, client)
    }

    /// The connection of a direct-path probe is not a send: it counts as no use,
    /// and is closed a fixed hold after the probe ends, long before the idle
    /// timeout, unless a send takes it first.
    #[test]
    async fn a_probe_connection_is_closed_after_the_hold_unless_a_send_takes_it() {
        let (pool, server, router, client) =
            pool_with_holds(Duration::from_secs(80), Duration::from_secs(8)).await;
        let connection = pool.probe_connection(server).await.expect("dial");
        assert!(
            pool.used_connection(server).is_none(),
            "a probe is not a send"
        );
        pool.probe_done(server).await;
        tokio::time::pause();

        advance_secs(6).await;
        assert!(
            connection.close_reason().is_none() && pool.connection(server).is_some(),
            "inside the hold the probe connection stays, so the graft can form on it"
        );
        advance_secs(6).await;
        assert!(
            pool.inner.conns.lock().await.is_empty(),
            "after the hold the connection leaves the pool"
        );
        assert!(
            closed_as_idle(&connection),
            "and is closed, not just dropped"
        );

        tokio::time::resume();
        let probed = pool.probe_connection(server).await.expect("probe again");
        pool.probe_done(server).await;
        tokio::time::pause();
        advance_secs(5).await;
        assert!(
            pool.warm_or_dial(server).await.is_ok(),
            "a send takes the probe connection"
        );
        assert!(pool.used_connection(server).is_some(), "and now it is used");
        advance_secs(20).await;
        assert!(
            probed.close_reason().is_none(),
            "a used connection follows the idle timeout, not the hold"
        );

        tokio::time::resume();
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A background dial that ends early — dropped with its runtime here, the
    /// same unwinding a panic in the dial gives — must still clear its
    /// in-flight entry, or every later cold send to that peer is refused.
    #[test]
    fn a_background_dial_dropped_mid_flight_clears_its_in_flight_entry() {
        // The endpoint lives on a runtime of its own, so that dropping the runtime of the dial
        // leaves the endpoint a runtime to close on.
        let endpoint_runtime = tokio::runtime::Runtime::new().expect("an endpoint runtime");
        let endpoint = endpoint_runtime.block_on(async {
            let builder =
                iroh::Endpoint::builder(presets::Minimal).relay_mode(iroh::RelayMode::Disabled);
            builder.bind().await.expect("bind a loopback endpoint")
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
        let bob = iroh::SecretKey::generate().public();
        let pool = runtime.block_on(async {
            let bob_addr = iroh::EndpointAddr::from_parts(
                bob,
                [iroh::TransportAddr::Ip(
                    silent.local_addr().expect("silent addr"),
                )],
            );
            crate::lookup::add_peer_addr(&crate::lookup::address_book(&endpoint), bob_addr);
            let pool = super::UnicastPool::new(endpoint.clone(), false);
            assert!(
                pool.dial_and_send_in_background(bob, bytes::Bytes::new())
                    .await,
                "a background send is accepted after the dropped dial"
            );
            tokio::task::yield_now().await;
            pool
        });

        drop(runtime);

        let still_in_flight = pool.inner.dialing.lock().contains_key(&bob);
        // The dropped runtime also held the driver of the connection that the dial had started. In
        // 1 run of 10 under load no close can drain that connection, and `Endpoint::close` waits
        // for it for good. A drop without a close logs an ERROR, and the drop of the runtime of
        // the endpoint logs a WARN of the network monitor. So when the close does not end, the
        // endpoint and its runtime stay as they are until the process ends.
        let closed = endpoint_runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), endpoint.close())
                .await
                .is_ok()
        });
        if !closed {
            std::mem::forget(pool);
            std::mem::forget(endpoint);
            std::mem::forget(endpoint_runtime);
        }
        assert!(
            !still_in_flight,
            "the dropped dial left {bob} marked in flight"
        );
    }

    /// A loopback server that keeps the frame of every unicast stream it is sent, and a pool
    /// dialed to it.
    async fn pool_with_collecting_server() -> (
        super::UnicastPool,
        iroh::EndpointId,
        iroh::protocol::Router,
        iroh::Endpoint,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Collect(mpsc::UnboundedSender<Vec<u8>>);
        impl ProtocolHandler for Collect {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                while let Ok(mut stream) = connection.accept_uni().await {
                    if let Ok(frame) = stream.read_to_end(64 * 1024).await {
                        let _ = self.0.send(frame);
                    }
                }
                Ok(())
            }
        }
        let bind = || async {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let (frames_tx, frames) = mpsc::unbounded_channel();
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, Collect(frames_tx))
            .spawn();
        let client = bind().await;
        crate::lookup::add_peer_addr(&crate::lookup::address_book(&client), server.addr());
        let pool = super::UnicastPool::new(client.clone(), false);
        (pool, server.id(), router, client, frames)
    }

    /// A pool whose only known peer is an address that nobody answers, so that a dial to it stays
    /// in flight for the whole dial budget. The socket keeps the address silent: drop it last.
    async fn pool_with_silent_peer() -> (
        super::UnicastPool,
        iroh::EndpointId,
        iroh::Endpoint,
        std::net::UdpSocket,
    ) {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
        let bob = iroh::SecretKey::generate().public();
        let endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let bob_addr = iroh::EndpointAddr::from_parts(
            bob,
            [iroh::TransportAddr::Ip(
                silent.local_addr().expect("silent addr"),
            )],
        );
        crate::lookup::add_peer_addr(&crate::lookup::address_book(&endpoint), bob_addr);
        let pool = super::UnicastPool::new(endpoint.clone(), false);
        (pool, bob, endpoint, silent)
    }

    async fn next_frame(frames: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(10), frames.recv())
            .await
            .expect("a frame arrives in time")
            .expect("the server keeps its channel")
    }

    /// Two sends to one cold peer share one dial: the second caller waits for the dial in flight
    /// and writes on the connection it made, as a warm send. Each dial is a handshake and a
    /// connection, and the pool keeps only the last one.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_send_during_a_dial_waits_and_writes_warm() {
        let (pool, server, router, client, mut frames) = pool_with_collecting_server().await;

        let (first, second) = tokio::join!(
            pool.dial_or_warm_send(server, bytes::Bytes::from_static(b"one")),
            pool.dial_or_warm_send(server, bytes::Bytes::from_static(b"two")),
        );

        first.expect("the dialer sends");
        second.expect("the waiter sends");
        assert_eq!(pool.dial_attempts(), 1, "the second send dialed again");
        let mut got = vec![next_frame(&mut frames).await, next_frame(&mut frames).await];
        got.sort();
        assert_eq!(
            got,
            vec![b"one".to_vec(), b"two".to_vec()],
            "two sends during a dial arrive in order and warm the pool"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// Two sends to a peer that nobody serves: the waiter gets the error of the one dial there was,
    /// and does not dial again. The peer is on the dial-failure cooldown afterwards.
    #[test]
    async fn a_waiter_gets_the_dial_error_without_a_second_dial() {
        let (pool, bob, endpoint, _silent) = pool_with_silent_peer().await;

        let (first, second) = tokio::join!(
            pool.dial_or_warm_send(bob, bytes::Bytes::new()),
            pool.dial_or_warm_send(bob, bytes::Bytes::new()),
        );

        let first = first.expect_err("the dialer fails");
        let second = second.expect_err("the waiter fails");
        assert_eq!(
            first.to_string(),
            second.to_string(),
            "the waiter gets the text of the dial it waited for"
        );
        assert_eq!(pool.dial_attempts(), 1, "the waiter dialed again");
        assert!(
            pool.is_cooling(bob).await,
            "the failed dial puts the peer on cooldown"
        );

        endpoint.close().await;
    }

    /// A background send during a dial is not dropped: it waits for the dial and is delivered after
    /// it. It used to return `false` and send nothing.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_background_frame_during_a_dial_is_delivered_after_it() {
        let (pool, server, router, client, mut frames) = pool_with_collecting_server().await;

        let gate = pool.hold_next_dial();
        assert!(
            pool.dial_and_send_in_background(server, bytes::Bytes::from_static(b"one"))
                .await,
            "the first frame starts the dial"
        );
        assert!(
            pool.dial_and_send_in_background(server, bytes::Bytes::from_static(b"two"))
                .await,
            "the second frame waits for the dial instead of being dropped"
        );
        gate.notify_one();

        let mut got = vec![next_frame(&mut frames).await, next_frame(&mut frames).await];
        got.sort();
        assert_eq!(
            got,
            vec![b"one".to_vec(), b"two".to_vec()],
            "a background frame during a dial is delivered after the earlier frame"
        );
        assert_eq!(pool.dial_attempts(), 1, "the second frame dialed again");

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A dialer that is aborted mid-dial wakes the callers that wait on it, with an error, long
    /// before the dial would have timed out, and leaves no entry behind.
    #[test]
    async fn a_cancelled_dialer_wakes_its_waiters() {
        let (pool, bob, endpoint, _silent) = pool_with_silent_peer().await;
        let dialer = tokio::spawn({
            let pool = pool.clone();
            async move { pool.dial_or_warm_send(bob, bytes::Bytes::new()).await }
        });
        let started = Instant::now();
        while !pool.inner.dialing.lock().contains_key(&bob) {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "the dialer never registered"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let waiter = tokio::spawn({
            let pool = pool.clone();
            async move { pool.dial_or_warm_send(bob, bytes::Bytes::new()).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        dialer.abort();

        let outcome = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("the waiter wakes long before the dial times out")
            .expect("the waiter task ends");
        let error = outcome.expect_err("a waiter of a cancelled dial gets an error");
        assert!(
            error.to_string().contains("cancelled"),
            "the error says that the dial was cancelled: {error}"
        );
        assert!(
            !pool.inner.dialing.lock().contains_key(&bob),
            "the cancelled dialer left its entry"
        );

        endpoint.close().await;
    }

    /// A test that needs a cold send drops the pooled connection of a peer: the cooldown goes with
    /// it, the address stays, and the next send dials again.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_a_pooled_connection_keeps_the_address_and_clears_the_cooldown() {
        let (pool, server, router, client, mut frames) = pool_with_collecting_server().await;
        assert!(!pool.drop_connection(server).await, "nothing is pooled yet");
        pool.dial_or_warm_send(server, bytes::Bytes::from_static(b"one"))
            .await
            .expect("a cold send dials");
        assert_eq!(
            next_frame(&mut frames).await,
            b"one".to_vec(),
            "the first frame after dropping the pooled connection arrives"
        );
        pool.note_dial_failure(server).await;
        assert!(
            pool.is_cooling(server).await,
            "the failure put the peer on cooldown"
        );

        assert!(
            pool.drop_connection(server).await,
            "a connection was pooled"
        );

        assert!(!pool.is_cooling(server).await, "the cooldown went with it");
        assert!(
            !pool.drop_connection(server).await,
            "and now none is pooled"
        );
        pool.dial_or_warm_send(server, bytes::Bytes::from_static(b"two"))
            .await
            .expect("the address stays, so the send dials again");
        assert_eq!(
            next_frame(&mut frames).await,
            b"two".to_vec(),
            "the next frame after the drop arrives too"
        );
        assert_eq!(pool.dial_attempts(), 2, "the second send was cold");

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A graceful `Left` forgets the peer's pool slots: the dial cooldown is
    /// cleared so a rejoin dials immediately, and forgetting an unknown
    /// endpoint is a no-op. (Closing a warm `Connection` needs a live
    /// endpoint pair; that path is covered by the network suite.)
    #[test]
    async fn forget_clears_the_cooldown_and_tolerates_absence() {
        let pool = super::UnicastPool::disconnected();
        let bob = testing::endpoint_id(1);
        pool.inner
            .dial_failures
            .lock()
            .await
            .note(bob, Instant::now());

        pool.forget(bob).await;

        assert!(
            pool.inner.dial_failures.lock().await.is_empty(),
            "forget clears the dial failures"
        );
        assert!(
            pool.inner.conns.lock().await.is_empty(),
            "forget clears the pooled connections"
        );
        // Absent endpoint: nothing to drop, nothing panics.
        pool.forget(testing::endpoint_id(2)).await;
    }

    /// A send over a pooled connection is a use of it: the ledger of the ceiling moves its
    /// last use to the end of the send, so the connection of a peer that is being talked to
    /// is not the least recently used.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_marks_its_connection_as_used_in_the_ledger() {
        use iroh::protocol::Router;

        use super::super::admission::SignalAdmission;
        use super::super::unicast_acceptor::UnicastAcceptor;

        let (tx, _frames) = mpsc::channel(8);
        let server = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let router = Router::builder(server.clone())
            .accept(
                super::super::UNICAST_ALPN,
                UnicastAcceptor::new(tx, crate::transport::PayloadPath::RelayAllowed),
            )
            .spawn();
        let admission = SignalAdmission::new(8);
        let hook = admission.connection_hook();
        let node: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .hooks(hook)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        crate::lookup::add_peer_addr(&crate::lookup::address_book(&node), server.addr());
        let pool = super::UnicastPool::new(node.clone(), true);
        pool.set_admission(admission.clone());

        pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"one"))
            .await
            .expect("the first send");
        let first = admission
            .last_use(server.id())
            .expect("the ledger holds it");
        tokio::time::sleep(Duration::from_millis(300)).await;
        pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"two"))
            .await
            .expect("the second send");
        let second = admission
            .last_use(server.id())
            .expect("the ledger holds it");

        assert!(second > first, "the second send is a later use");
        router.shutdown().await.expect("shutdown");
        node.close().await;
    }

    /// A peer that evicted us is left alone by the proactive dial of a probe, and a send to
    /// it dials at once.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_evicting_peer_is_not_probed_but_a_send_dials_it() {
        use iroh::protocol::Router;

        use super::super::admission::SignalAdmission;
        use super::super::unicast_acceptor::UnicastAcceptor;

        let (tx, _frames) = mpsc::channel(8);
        let server = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let router = Router::builder(server.clone())
            .accept(
                super::super::UNICAST_ALPN,
                UnicastAcceptor::new(tx, crate::transport::PayloadPath::RelayAllowed),
            )
            .spawn();
        let admission = SignalAdmission::new(8);
        let hook = admission.connection_hook();
        let node: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .hooks(hook)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        crate::lookup::add_peer_addr(&crate::lookup::address_book(&node), server.addr());
        let pool = super::UnicastPool::new(node.clone(), true);
        pool.set_admission(admission.clone());
        admission.note_evicted(server.id());

        assert!(
            pool.probe_connection(server.id()).await.is_err(),
            "the probe waits"
        );
        pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"now"))
            .await
            .expect("a send dials at once");

        router.shutdown().await.expect("shutdown");
        node.close().await;
    }

    /// The idle close of a pooled connection is the one backstop of the direct connections.
    #[test]
    fn a_pool_closes_an_idle_connection_after_the_one_backstop() {
        assert_eq!(
            super::UnicastPool::disconnected().inner.idle,
            tuning::DIRECT_IDLE_BACKSTOP,
            "the idle backstop is the one set on a disconnected pool"
        );
    }

    /// **The busy mark lasts until the peer has read the frame.** `finish()` returns while the frame
    /// is still in flight, so a mark that ended there left a connection with a slow reader open to
    /// eviction, with its frame in the air. The mark now ends when the peer has read the stream to the
    /// end, or after 2 s.
    #[test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_keeps_its_connection_busy_until_the_peer_has_read_the_frame() {
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        use super::super::admission::SignalAdmission;

        #[derive(Debug, Clone)]
        struct SlowReader;
        impl ProtocolHandler for SlowReader {
            async fn accept(
                &self,
                connection: iroh::endpoint::Connection,
            ) -> Result<(), AcceptError> {
                let mut stream = connection
                    .accept_uni()
                    .await
                    .map_err(AcceptError::from_err)?;
                tokio::time::sleep(Duration::from_millis(800)).await;
                let _ = stream.read_to_end(1 << 20).await;
                connection.closed().await;
                Ok(())
            }
        }

        let server = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, SlowReader)
            .spawn();
        let admission = SignalAdmission::new(8);
        let hook = admission.connection_hook();
        let node: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .hooks(hook)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        crate::lookup::add_peer_addr(&crate::lookup::address_book(&node), server.addr());
        let pool = super::UnicastPool::new(node.clone(), true);
        pool.set_admission(admission.clone());

        pool.dial_and_send(server.id(), bytes::Bytes::from(vec![7u8; 3000]))
            .await
            .expect("the send");
        assert!(
            admission.is_busy(server.id()),
            "the frame is in flight: the peer has not read it"
        );

        let mut idle = false;
        for _ in 0..60 {
            if !admission.is_busy(server.id()) {
                idle = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(idle, "the mark ends once the peer has read the frame");

        router.shutdown().await.expect("shutdown");
        node.close().await;
    }
}
