//! The dial side of the unicast plane: a per-peer connection pool that dials
//! lazily, reuses a warm QUIC connection across messages, and re-dials after a
//! close. Modeled on the application bridge's shared connection, but keyed per endpoint
//! and with a short dial budget so a send to an unreachable peer fails fast
//! rather than stalling the event loop.

mod committed;
mod in_flight_dial;
mod outgoing_frame;
mod plan_release;
mod registration;
mod send_fault;
mod uncommitted_stream;
pub(crate) use send_fault::SendFault;
mod timeouts;
pub use timeouts::LONGEST_SEND_CALL;
#[cfg(test)]
pub(crate) use timeouts::SEND_ANSWER_TIMEOUT;
pub(crate) use timeouts::{COOLDOWN_REFUSED, DIAL_TIMEOUT};
mod unicast_pool;
pub(crate) use unicast_pool::UnicastPool;
mod warm_send;
pub(crate) use warm_send::WarmSend;

#[cfg(test)]
mod tests {
    use crate::testing;
    use crate::util::clock::Instant;
    use std::time::Duration;

    use super::timeouts::DIAL_FAILURE_COOLDOWN;
    use crate::util::cooldown::Cooldown;

    use crate::lookup;
    use crate::transport::PayloadPath;
    use crate::util::tuning;
    use iroh::endpoint::{ConnectionError, presets};
    use iroh::{endpoint, protocol};
    use std::{future, mem, net};
    use tokio::sync::mpsc;
    use tokio::{runtime, task, time};
    #[test]
    fn a_fresh_failure_puts_the_endpoint_on_cooldown() {
        let _guard = ::habilis_network_test_tracing::init();
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
        let _guard = ::habilis_network_test_tracing::init();
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
    #[test]
    fn a_pooled_udp_connection_reads_as_udp_selected() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::endpoint::Connection;
                use iroh::protocol::{AcceptError, ProtocolHandler, Router};

                #[derive(Debug, Clone, Copy)]
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
                lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
                let pool = super::UnicastPool::new(client.clone(), false);

                assert!(!pool.selected_is_ip(server.id()), "nothing pooled yet");
                pool.warm_or_dial(server.id()).await.expect("dial");
                let started = Instant::now();
                while !pool.selected_is_ip(server.id()) {
                    assert!(
                        started.elapsed() < Duration::from_secs(10),
                        "udp never selected"
                    );
                    time::sleep(Duration::from_millis(50)).await;
                }
                let held = pool.inner.conns.lock().await;
                assert!(
                    !pool.selected_is_ip(server.id()),
                    "a busy lock reads as not selected"
                );
                drop(held);

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// A loopback server that holds every unicast connection open, and a pool
    /// dialed to it with the given idle timeout.
    async fn pool_with_idle(
        idle: Duration,
    ) -> (
        super::UnicastPool,
        iroh::EndpointId,
        protocol::Router,
        iroh::Endpoint,
    ) {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler};

        /// A server that reads each frame and acknowledges it.
        #[derive(Debug, Clone, Copy)]
        struct Acknowledge;
        impl ProtocolHandler for Acknowledge {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                while let Ok((acknowledgement, stream)) = connection.accept_bi().await {
                    let _ =
                        super::super::unicast_acceptor::receive_for_test(acknowledgement, stream)
                            .await;
                }
                Ok(())
            }
        }
        pool_serving(idle, Acknowledge).await
    }

    /// [`pool_with_idle`] with the handler that the server runs.
    async fn pool_serving<Serving: protocol::ProtocolHandler>(
        idle: Duration,
        handler: Serving,
    ) -> (
        super::UnicastPool,
        iroh::EndpointId,
        protocol::Router,
        iroh::Endpoint,
    ) {
        use iroh::protocol::Router;

        let bind = || async {
            iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, handler)
            .spawn();
        let client = bind().await;
        lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
        let pool = super::UnicastPool::with_idle(client.clone(), false, idle);
        (pool, server.id(), router, client)
    }

    /// Step the paused clock a second at a time, so the sweeper's timer fires
    /// in order with the connection's own.
    async fn advance_secs(seconds: u64) {
        for _ in 0..seconds {
            time::advance(Duration::from_secs(1)).await;
            task::yield_now().await;
        }
    }

    /// Closed by this side, not timed out by QUIC and not closed by the peer.
    fn closed_as_idle(connection: &endpoint::Connection) -> bool {
        matches!(
            connection.close_reason(),
            Some(ConnectionError::LocallyClosed)
        )
    }

    /// A pinned connection rides multihop for a peer that the node could not dial directly, and
    /// the members that forward for it pay for each minute it stays. It closes after the pinned
    /// idle (60 s), which is shorter than the idle timeout of a direct connection.
    #[test]
    fn a_pinned_connection_is_closed_after_a_minute_idle_and_a_direct_one_is_not() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) =
                pool_with_holds(Duration::from_secs(300), Duration::from_secs(8)).await;
            let connection = pool.warm_or_dial(server).await.expect("dial");
            time::pause();

            advance_secs(61).await;
            assert!(
                connection.close_reason().is_none(),
                "a direct connection keeps the idle timeout of the pool"
            );

            {
                let mut conns = pool.inner.conns.lock().await;
                let pooled = conns.get_mut(&server).expect("the connection is pooled");
                pooled.pinned = true;
                pooled.last_used = time::Instant::now();
            }
            advance_secs(55).await;
            assert!(
                connection.close_reason().is_none(),
                "inside the pinned idle the connection stays"
            );
            advance_secs(10).await;
            assert!(
                closed_as_idle(&connection),
                "a pinned connection idle for a minute is closed as idle"
            );

            time::resume();
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A connection that took no unit (the ceiling holds only a busy peer) is an extra: it closes
    /// after the extra idle, as a pinned one does.
    #[test]
    fn a_connection_that_took_no_unit_is_closed_after_a_minute_idle() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) =
                pool_with_holds(Duration::from_secs(300), Duration::from_secs(8)).await;
            let admission = SignalAdmission::new(1);
            admission.note_success(testing::endpoint_id(7));
            let _busy = admission.busy(testing::endpoint_id(7));
            pool.set_admission(admission.clone());
            let connection = pool.warm_or_dial(server).await.expect("dial");
            admission.note_connection(&connection);
            assert!(admission.is_extra(server), "no unit was free or evictable");
            time::pause();

            advance_secs(55).await;
            assert!(
                connection.close_reason().is_none(),
                "inside the extra idle the connection stays"
            );
            advance_secs(10).await;
            assert!(
                closed_as_idle(&connection),
                "an extra idle for a minute is closed as idle"
            );

            time::resume();
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// The pool counts its dials for each peer, so that a test can say that a node dialed nobody
    /// for a peer. A dial counts when it reaches the endpoint, and a send over a warm connection
    /// does not.
    #[test]
    fn the_pool_counts_each_dial_it_makes_for_a_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(300)).await;
            let other = testing::endpoint_id(8);
            assert_eq!(pool.dials_to(server), 0, "no dial before the first send");
            pool.warm_or_dial(server).await.expect("dial");
            assert_eq!(pool.dials_to(server), 1, "the first send dials once");
            pool.warm_or_dial(server).await.expect("warm");
            assert_eq!(
                pool.dials_to(server),
                1,
                "a send over the warm connection is not a dial"
            );
            assert_eq!(pool.dials_to(other), 0, "another peer is counted apart");
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A direct dial that has a route takes it as one more address, beside the address of the peer:
    /// a peer that no direct path reaches is reached through the route. A pinned dial takes the
    /// route alone.
    #[test]
    fn a_direct_dial_adds_its_route_to_the_address_and_a_pinned_dial_takes_the_route_alone() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(300)).await;
            let known = iroh::EndpointAddr::new(server).with_ip_addr(([192, 0, 2, 1], 4433).into());
            pool.note_addr(&known);

            let roomy = SignalAdmission::new(4);
            pool.set_admission(roomy);
            let registration = pool.register_planned_dial(server, || Some(a_route()));
            let planned = pool.inner.routes.lock().remove(&server);
            let address = pool.dial_address(server, planned);
            assert!(
                address.addrs.contains(&a_route())
                    && address.addrs.iter().any(iroh::TransportAddr::is_ip),
                "a direct dial keeps the address of the peer and adds the route: {address:?}"
            );
            drop(registration);

            let full = SignalAdmission::new(1);
            full.note_success(testing::endpoint_id(7));
            let (full_pool, full_server, router_two, client_two) =
                pool_with_idle(Duration::from_secs(300)).await;
            full_pool.note_addr(
                &iroh::EndpointAddr::new(full_server).with_ip_addr(([192, 0, 2, 2], 4433).into()),
            );
            full_pool.set_admission(full);
            let pinned_registration =
                full_pool.register_planned_dial(full_server, || Some(a_route()));
            let pinned_plan = full_pool.inner.routes.lock().remove(&full_server);
            let pinned_address = full_pool.dial_address(full_server, pinned_plan);
            let pinned_addrs: Vec<iroh::TransportAddr> =
                pinned_address.addrs.iter().cloned().collect();
            assert_eq!(
                pinned_addrs,
                vec![a_route()],
                "a pinned dial takes the route and no other address"
            );
            drop(pinned_registration);
            router.shutdown().await.expect("shutdown");
            router_two.shutdown().await.expect("shutdown");
            client.close().await;
            client_two.close().await;
        });
    }

    /// A route to a peer, for the tests of a pinned dial: the dial itself fails, as the test
    /// endpoints run no multihop transport.
    fn a_route() -> iroh::TransportAddr {
        iroh::TransportAddr::Custom(habilis_network_iroh_gossip_transport::gossip_addr(
            testing::endpoint_id(9),
        ))
    }

    /// A dial that ends with no connection gives its unit back: a peer on the dial-failure
    /// cooldown, and a send that finds a warm connection, both planned a dial and reserved a unit.
    #[test]
    fn a_planned_dial_that_ends_without_a_connection_gives_its_unit_back() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(300)).await;
            let admission = SignalAdmission::new(2);
            admission.note_success(testing::endpoint_id(7));
            pool.set_admission(admission.clone());
            let other = testing::endpoint_id(8);

            pool.note_dial_failure(server).await;
            let registration = pool.register_planned_dial(server, || None);
            let refused = pool
                .send_registered(registration, server, bytes::Bytes::from_static(b"one"))
                .await;
            assert!(refused.is_err(), "a peer on the cooldown is not dialed");
            assert!(
                admission.has_room(other),
                "the dial that the cooldown stopped gave its unit back"
            );

            pool.inner.dial_failures.lock().await.forget(&server);
            pool.warm_or_dial(server).await.expect("dial");
            admission.release_dial(server);
            let warm_registration = pool.register_planned_dial(server, || None);
            pool.send_registered(warm_registration, server, bytes::Bytes::from_static(b"two"))
                .await
                .expect("send over the warm connection");
            assert!(
                admission.has_room(other),
                "a send that found a warm connection gave back the unit that it planned"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A courtesy dial at the ceiling with a route pins the peer and dials through the route. The
    /// dial is held at its gate, so the test reads the pin before the dial ends and gives it back.
    #[test]
    fn a_courtesy_dial_at_the_ceiling_with_a_route_pins_the_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(300)).await;
            let admission = SignalAdmission::new(1);
            admission.note_success(testing::endpoint_id(7));
            pool.set_admission(admission.clone());
            let gate = pool.hold_next_dial();
            assert!(
                pool.dial_and_send_in_background(server, bytes::Bytes::from_static(b"hi"), || {
                    Some(a_route())
                })
                .await,
                "a courtesy reply with a route is sent"
            );
            assert!(
                admission.is_pinned(server),
                "the courtesy dial at the ceiling pins the peer on its route"
            );
            gate.notify_one();
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A courtesy dial at the ceiling with no route evicts nobody and sends nothing: a backfill is
    /// not the answer to a request. With a free unit it dials.
    #[test]
    fn a_courtesy_dial_at_the_ceiling_with_no_route_dials_nobody() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(300)).await;
            let admission = SignalAdmission::new(1);
            admission.note_success(testing::endpoint_id(7));
            pool.set_admission(admission.clone());
            assert!(
                !pool
                    .dial_and_send_in_background(server, bytes::Bytes::from_static(b"hi"), || None)
                    .await,
                "no route and no free unit: no courtesy dial"
            );
            assert!(!pool.is_dialing(server), "no dial is in flight");
            assert!(
                !admission.has_room(testing::endpoint_id(8)),
                "the ledger still holds its one unit and reserves no other"
            );

            let roomy = SignalAdmission::new(2);
            roomy.note_success(testing::endpoint_id(7));
            let (roomy_pool, roomy_server, router_two, client_two) =
                pool_with_idle(Duration::from_secs(300)).await;
            roomy_pool.set_admission(roomy);
            assert!(
                roomy_pool
                    .dial_and_send_in_background(
                        roomy_server,
                        bytes::Bytes::from_static(b"hi"),
                        || None
                    )
                    .await,
                "a free unit: the courtesy dial goes"
            );
            router.shutdown().await.expect("shutdown");
            router_two.shutdown().await.expect("shutdown");
            client.close().await;
            client_two.close().await;
        });
    }

    /// A pinned peer is not dialed again by the pool: only the loop holds a fresh route, so the next
    /// send plans the dial. Any other peer is planned with no route.
    #[test]
    fn a_redial_of_a_pinned_peer_is_not_made_and_another_peer_is_planned() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(300)).await;
            let admission = SignalAdmission::new(1);
            admission.note_success(testing::endpoint_id(7));
            pool.set_admission(admission.clone());
            let first = pool.register_planned_dial(server, || Some(a_route()));
            assert!(admission.is_pinned(server), "the first dial pins the peer");
            assert!(
                pool.redial_registration(server).is_none(),
                "a pinned peer is not dialed again with a route that may be gone"
            );
            drop(first);
            assert!(
                pool.redial_registration(server).is_some(),
                "a peer that is not pinned is planned as any send"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A probe that is cancelled while its dial runs gives its unit back.
    #[test]
    fn a_probe_that_is_dropped_mid_dial_gives_its_unit_back() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(300)).await;
            let admission = SignalAdmission::new(2);
            admission.note_success(testing::endpoint_id(7));
            pool.set_admission(admission.clone());
            let _gate = pool.hold_next_dial();
            let probing = pool.clone();
            let probe = tokio::spawn(async move { probing.probe_connection(server).await });
            while admission.has_room(testing::endpoint_id(8)) {
                task::yield_now().await;
            }
            probe.abort();
            let _ = probe.await;
            assert!(
                admission.has_room(testing::endpoint_id(8)),
                "the probe that was dropped gave its unit back"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// The route of a pinned connection is gone, but the peer became a gossip neighbor: it is a
    /// direct peer now, and its connection is not closed for the route.
    #[test]
    fn a_connection_of_a_peer_that_is_no_longer_pinned_is_not_closed_for_its_route() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) =
                pool_with_holds(Duration::from_secs(300), Duration::from_secs(8)).await;
            let admission = SignalAdmission::new(2);
            pool.set_admission(admission.clone());
            let connection = pool.warm_or_dial(server).await.expect("dial");
            pool.inner
                .conns
                .lock()
                .await
                .get_mut(&server)
                .expect("the connection is pooled")
                .pinned = true;
            assert!(
                !pool.close_pinned(server).await && connection.close_reason().is_none(),
                "the ledger does not pin the peer any more: the connection stays"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A probe is a dial that no send asked for. It takes a free unit and never the last one at the
    /// ceiling: it is refused and evicts nobody. With a free unit it dials.
    #[test]
    fn a_probe_at_the_ceiling_dials_nobody() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(300)).await;
            let admission = SignalAdmission::new(1);
            admission.note_success(testing::endpoint_id(7));
            pool.set_admission(admission.clone());
            assert!(
                !pool.has_room_for_unprompted_dial(server),
                "a ceiling of 1 with 1 unit has no room"
            );

            let probe = pool.probe_connection(server).await;
            assert!(
                probe.is_err_and(|error| error.to_string().contains("at its ceiling")),
                "a probe at the ceiling is refused"
            );

            let roomy = SignalAdmission::new(2);
            roomy.note_success(testing::endpoint_id(7));
            let (roomy_pool, roomy_server, router_two, client_two) =
                pool_with_idle(Duration::from_secs(300)).await;
            roomy_pool.set_admission(roomy);
            assert!(
                roomy_pool.probe_connection(roomy_server).await.is_ok(),
                "a probe with a free unit dials"
            );
            router.shutdown().await.expect("shutdown");
            router_two.shutdown().await.expect("shutdown");
            client.close().await;
            client_two.close().await;
        });
    }

    /// The route of a pinned connection is gone: the connection closes, and a direct connection
    /// of the same pool is left alone.
    #[test]
    fn a_pinned_connection_closes_when_its_route_is_gone_and_a_direct_one_stays() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) =
                pool_with_holds(Duration::from_secs(300), Duration::from_secs(8)).await;
            let connection = pool.warm_or_dial(server).await.expect("dial");
            assert!(
                !pool.close_pinned(server).await && connection.close_reason().is_none(),
                "a direct connection stays"
            );
            pool.inner
                .conns
                .lock()
                .await
                .get_mut(&server)
                .expect("the connection is pooled")
                .pinned = true;
            assert!(
                pool.close_pinned(server).await,
                "a pinned connection closes"
            );
            assert!(
                closed_as_idle(&connection) && pool.inner.conns.lock().await.is_empty(),
                "and leaves the pool, so that the next send is cold"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    #[test]
    fn a_pooled_connection_nothing_sends_on_is_closed_after_the_idle_timeout() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(8)).await;
            let connection = pool.warm_or_dial(server).await.expect("dial");
            time::pause();

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

            time::resume();
            pool.warm_or_dial(server).await.expect("a send dials again");
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A peer that answers each frame by its first byte. A frame that starts with `a` gets no answer
    /// at all, or `NOT_TAKEN` when `refuse_a` is set. Any other frame is held, committed and
    /// acknowledged.
    #[derive(Debug, Clone, Copy)]
    struct Picky {
        refuse_a: bool,
    }

    impl protocol::ProtocolHandler for Picky {
        async fn accept(
            &self,
            connection: endpoint::Connection,
        ) -> Result<(), protocol::AcceptError> {
            use super::super::unicast_acceptor::{HELD, NOT_TAKEN};

            let refuse_a = self.refuse_a;
            let mut streams = task::JoinSet::new();
            while let Ok((mut ack, mut recv)) = connection.accept_bi().await {
                streams.spawn(async move {
                    let mut prefix = [0u8; 4];
                    recv.read_exact(&mut prefix).await.ok()?;
                    let mut frame = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).ok()?];
                    recv.read_exact(&mut frame).await.ok()?;
                    if frame.first() == Some(&b'a') {
                        if refuse_a {
                            ack.reset(NOT_TAKEN.into()).ok()?;
                        } else {
                            let () = future::pending().await;
                        }
                        return Some(());
                    }
                    ack.write_all(&[HELD]).await.ok()?;
                    recv.read_to_end(0).await.ok()?;
                    ack.finish().ok()?;
                    ack.stopped().await.ok()?;
                    Some(())
                });
            }
            Ok(())
        }
    }

    /// **A caller that waits for the dial of another is not held up by the frame of the dialer.** The
    /// dialer sends a frame that the peer never answers, and its send waits for the whole wait of a
    /// send. The waiter wanted a connection, and it has one as soon as the dial is ready: it sends its
    /// own frame, and the peer takes it. Before, the dialer told its waiters only when its own send
    /// ended, so every frame behind it waited for the verdict of a frame that was not its own.
    #[test]
    fn a_waiter_sends_its_own_frame_while_the_frame_of_its_dialer_waits_for_the_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) =
                pool_serving(Duration::from_secs(600), Picky { refuse_a: false }).await;
            let dialer = pool.register_dial(server);
            let waiter = pool.register_dial(server);
            let first = pool.send_registered(dialer, server, bytes::Bytes::from_static(b"a frame"));
            let second =
                pool.send_registered(waiter, server, bytes::Bytes::from_static(b"b frame"));
            tokio::pin!(first);

            let outcome = tokio::select! {
                _ = &mut first => panic!("the frame that the peer never answers ended at once"),
                outcome = time::timeout(Duration::from_secs(5), second) => outcome,
            };

            assert!(
                matches!(outcome, Ok(Ok(()))),
                "the waiter did not deliver its own frame while the frame of its dialer waited: {outcome:?}"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **A caller that waits for the dial of another gets the verdict of its own frame.** The peer
    /// refuses the frame of the dialer and takes the frame of the waiter. The dialer says "not
    /// delivered", and the waiter says "delivered": before, the waiter got the error of the frame of
    /// the dialer, and its own frame was never sent.
    #[test]
    fn a_waiter_delivers_its_own_frame_when_the_frame_of_its_dialer_is_refused() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) =
                pool_serving(Duration::from_secs(600), Picky { refuse_a: true }).await;
            let dialer = pool.register_dial(server);
            let waiter = pool.register_dial(server);
            let first = pool.send_registered(dialer, server, bytes::Bytes::from_static(b"a frame"));
            let second =
                pool.send_registered(waiter, server, bytes::Bytes::from_static(b"b frame"));

            let (first, second) = tokio::join!(first, second);

            assert!(first.is_err(), "the peer refused the frame of the dialer");
            assert!(
                second.is_ok(),
                "the waiter got the verdict of the frame of its dialer: {second:?}"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **No path of one send call is longer than `LONGEST_SEND_CALL`.** The paths are the ones of the
    /// code: a call that dials and dials again after a lost connection (`dial_and_send`), a send on a
    /// warm connection that dials after it was lost (`send_if_warm`, `redial_and_send`), and a caller
    /// that waits for the dial of another, sends its own frame, and dials after a lost connection.
    /// Each is a sum of the named bounds, and the longest is the constant.
    #[test]
    fn no_path_of_a_send_call_is_longer_than_the_longest_send_call() {
        use super::timeouts::{
            DIAL_TIMEOUT, PATH_SELECT_TIMEOUT, SEND_ANSWER_TIMEOUT, SEND_TIMEOUT,
        };

        let send: Duration = SEND_TIMEOUT + SEND_ANSWER_TIMEOUT * 2;
        let connection: Duration = DIAL_TIMEOUT + PATH_SELECT_TIMEOUT;
        let paths = [
            (
                "dial_and_send, then redial_and_send",
                connection + send + connection + send,
            ),
            (
                "send_if_warm, then redial_and_send",
                send + connection + send,
            ),
            (
                "a waiter: the connection of its dialer, its own send, then a redial",
                connection + send + connection + send,
            ),
        ];

        for (name, length) in paths {
            assert!(
                length <= super::LONGEST_SEND_CALL,
                "{name} takes {length:?}, longer than {:?}",
                super::LONGEST_SEND_CALL
            );
        }
        assert_eq!(
            paths.iter().map(|(_, length)| *length).max(),
            Some(super::LONGEST_SEND_CALL),
            "the constant is the longest path, and no more"
        );
    }

    /// A send to a peer that reads nothing ends. The peer accepts the connection, never accepts a stream and keeps
    /// the connection alive, so no stream gets its acknowledgement: the send ends with the deadline of a send, and
    /// not with a wait without a bound. Each send sits in a task of its own, so a wait without a bound grows the
    /// tasks of the node for as long as the peer answers nothing.
    #[test]
    fn a_send_to_a_peer_that_reads_nothing_ends_within_its_budget() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use iroh::endpoint::Connection;
            use iroh::protocol::{AcceptError, ProtocolHandler};

            #[derive(Debug, Clone, Copy)]
            struct Mute;
            impl ProtocolHandler for Mute {
                async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                    connection.closed().await;
                    Ok(())
                }
            }
            let (pool, server, router, client) = pool_serving(Duration::from_secs(600), Mute).await;
            let connection = pool.warm_or_dial(server).await.expect("dial");
            time::pause();

            let ended = time::timeout(
                super::timeouts::SEND_TIMEOUT + super::timeouts::SEND_ANSWER_TIMEOUT * 2,
                super::unicast_pool::send_one(&connection, b"frame", None, None),
            )
            .await;

            let refusal: String = ended
                .expect("a send to a peer that reads nothing is still waiting, so the wait of a send has no bound")
                .expect_err("a peer that reads nothing acknowledges nothing")
                .to_string();
            assert!(
                refusal.contains(super::timeouts::SEND_TIMED_OUT),
                "the send ended with \"{refusal}\", which is not the deadline of a send"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A write that fails drops the connection it failed on, and not the one that another dial
    /// pooled while it waited. A send that times out holds for `SEND_ANSWER_TIMEOUT`, which is long enough
    /// for a parallel send to replace a dead connection, and an eviction by endpoint id alone would
    /// put that replacement out of the pool as well.
    #[test]
    fn a_write_that_fails_leaves_the_connection_that_a_later_dial_pooled() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(600)).await;
            let dead = pool.warm_or_dial(server).await.expect("dial");
            // The pool must hold a replacement, so the dead connection leaves the map open: a
            // second dial pools the replacement under the same endpoint id.
            pool.inner.conns.lock().await.remove(&server);
            let live = pool.warm_or_dial(server).await.expect("dial again");
            assert_ne!(
                dead.stable_id(),
                live.stable_id(),
                "two dials give two connections"
            );
            dead.close(0u32.into(), b"dead");

            assert!(
                pool.send_marked(server, &dead, b"frame").await.is_err(),
                "the write on the closed connection fails"
            );

            assert_eq!(
                pool.connection(server).map(|pooled| pooled.stable_id()),
                Some(live.stable_id()),
                "the write failed on the closed connection, so the pool keeps the live one"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    #[test]
    fn a_send_restarts_the_idle_timeout() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) = pool_with_idle(Duration::from_secs(8)).await;
            let connection = pool.warm_or_dial(server).await.expect("dial");
            time::pause();

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

            time::resume();
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A loopback server that holds every unicast connection open, and a pool
    /// dialed to it with the given idle timeout and probe hold.
    async fn pool_with_holds(
        idle: Duration,
        probe_hold: Duration,
    ) -> (
        super::UnicastPool,
        iroh::EndpointId,
        protocol::Router,
        iroh::Endpoint,
    ) {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone, Copy)]
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
        lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
        let pool = super::UnicastPool::with_timeouts(client.clone(), false, idle, probe_hold);
        (pool, server.id(), router, client)
    }

    /// The connection of a direct-path probe is not a send: it counts as no use,
    /// and is closed a fixed hold after the probe ends, long before the idle
    /// timeout, unless a send takes it first.
    #[test]
    fn a_probe_connection_is_closed_after_the_hold_unless_a_send_takes_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client) =
                pool_with_holds(Duration::from_secs(80), Duration::from_secs(8)).await;
            let connection = pool.probe_connection(server).await.expect("dial");
            assert!(
                pool.used_connection(server).is_none(),
                "a probe is not a send"
            );
            pool.probe_done(server).await;
            time::pause();

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

            time::resume();
            let probed = pool.probe_connection(server).await.expect("probe again");
            pool.probe_done(server).await;
            time::pause();
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

            time::resume();
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// A background dial that ends early — dropped with its runtime here, the
    /// same unwinding a panic in the dial gives — must still clear its
    /// in-flight entry, or every later cold send to that peer is refused.
    #[test]
    fn a_background_dial_dropped_mid_flight_clears_its_in_flight_entry() {
        // The endpoint lives on a runtime of its own, so that dropping the runtime of the dial
        // leaves the endpoint a runtime to close on.
        let _guard = ::habilis_network_test_tracing::init();
        let endpoint_runtime = runtime::Runtime::new().expect("an endpoint runtime");
        let endpoint = endpoint_runtime.block_on(async {
            let builder =
                iroh::Endpoint::builder(presets::Minimal).relay_mode(iroh::RelayMode::Disabled);
            builder.bind().await.expect("bind a loopback endpoint")
        });
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let silent = net::UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
        let bob = iroh::SecretKey::generate().public();
        let pool = runtime.block_on(async {
            let bob_addr = iroh::EndpointAddr::from_parts(
                bob,
                [iroh::TransportAddr::Ip(
                    silent.local_addr().expect("silent addr"),
                )],
            );
            lookup::add_peer_addr(&lookup::address_book(&endpoint), bob_addr);
            let pool = super::UnicastPool::new(endpoint.clone(), false);
            assert!(
                pool.dial_and_send_in_background(bob, bytes::Bytes::new(), || None)
                    .await,
                "a background send is accepted after the dropped dial"
            );
            task::yield_now().await;
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
            time::timeout(Duration::from_secs(5), endpoint.close())
                .await
                .is_ok()
        });
        if !closed {
            mem::forget(pool);
            mem::forget(endpoint);
            mem::forget(endpoint_runtime);
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
        protocol::Router,
        iroh::Endpoint,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Collect(mpsc::UnboundedSender<Vec<u8>>);
        impl ProtocolHandler for Collect {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                while let Ok((acknowledgement, stream)) = connection.accept_bi().await {
                    if let Some(frame) =
                        super::super::unicast_acceptor::receive_for_test(acknowledgement, stream)
                            .await
                    {
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
        lookup::add_peer_addr(&lookup::address_book(&client), server.addr());
        let pool = super::UnicastPool::new(client.clone(), false);
        (pool, server.id(), router, client, frames)
    }

    /// A pool whose only known peer is an address that nobody answers, so that a dial to it stays
    /// in flight for the whole dial budget. The socket keeps the address silent: drop it last.
    async fn pool_with_silent_peer() -> (
        super::UnicastPool,
        iroh::EndpointId,
        iroh::Endpoint,
        net::UdpSocket,
    ) {
        let silent = net::UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
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
        lookup::add_peer_addr(&lookup::address_book(&endpoint), bob_addr);
        let pool = super::UnicastPool::new(endpoint.clone(), false);
        (pool, bob, endpoint, silent)
    }

    async fn next_frame(frames: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<u8> {
        time::timeout(Duration::from_secs(10), frames.recv())
            .await
            .expect("a frame arrives in time")
            .expect("the server keeps its channel")
    }

    /// A unicast write is counted in the tally of its own pool, once, under the tag of the frame,
    /// and not in the tally of another loop.
    #[test]
    fn a_unicast_write_is_counted_in_the_sent_bytes() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::daemon::state::{WireOutTally, app_frame_with_tag};

                let (pool, server, router, client, mut frames) =
                    pool_with_collecting_server().await;
                let (ours, other) = (WireOutTally::default(), WireOutTally::default());
                pool.set_tally(ours.clone());
                let frame = app_frame_with_tag("unicast_count_probe");

                pool.dial_or_warm_send(server, bytes::Bytes::from(frame.clone()))
                    .await
                    .expect("the pool sends");

                assert_eq!(next_frame(&mut frames).await, frame, "the frame arrives");
                assert_eq!(
                    ours.tag_bytes("unicast_count_probe"),
                    frame.len() as u64,
                    "the one frame, once"
                );
                assert_eq!(
                    other.tag_bytes("unicast_count_probe"),
                    0,
                    "the tally of another loop does not take the bytes"
                );

                router.shutdown().await.expect("shutdown");
                client.close().await;
            },
        );
    }

    /// Two sends to one cold peer share one dial: the second caller waits for the dial in flight
    /// and writes on the connection it made, as a warm send. Each dial is a handshake and a
    /// connection, and the pool keeps only the last one.
    #[test]
    fn a_second_send_during_a_dial_waits_and_writes_warm() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (pool, server, router, client, mut frames) =
                    pool_with_collecting_server().await;

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
            },
        );
    }

    /// **A send that registers after a dial published its outcome dials again.**
    ///
    /// The dialer publishes, then its guard leaves the map of dials in flight when it drops. A
    /// register in that gap must not wait on the dial that ended: it would take the old outcome at
    /// once, without a dial of its own.
    #[test]
    fn a_register_after_the_outcome_is_a_new_dialer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, bob, endpoint, _silent) = pool_with_silent_peer().await;

            let super::registration::Registration::Dialer(first) = pool.register_dial(bob) else {
                panic!("the first register of a peer is its dialer");
            };
            first.publish(Err("an old dial failed".to_owned()));
            let second = pool.register_dial(bob);
            let is_dialer = matches!(second, super::registration::Registration::Dialer(_));
            drop(second);
            drop(first);

            assert!(
                is_dialer,
                "a register after the outcome waited on the dial that had ended"
            );
            endpoint.close().await;
        });
    }

    /// **The plan of a dial that published is released before its entry leaves the map.**
    ///
    /// The dial A publishes, so that its entry leaves and B registers and plans a dial of the same
    /// peer. The drop of A must not release the plan by peer: that is the reservation of B, and B
    /// would dial without the unit that its plan holds. With 1 unit, the reservation of B keeps
    /// another peer out until B ends.
    #[test]
    fn the_drop_of_a_dial_that_published_keeps_the_reservation_of_the_next_dial() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use super::super::admission::SignalAdmission;
            let (pool, bob, endpoint, _silent) = pool_with_silent_peer().await;
            let admission = SignalAdmission::new(1);
            pool.set_admission(admission.clone());

            let first = pool.register_planned_dial(bob, || None);
            if let super::registration::Registration::Dialer(first) = &first {
                first.publish(Err("an old dial failed".to_owned()));
            }
            let second = pool.register_planned_dial(bob, || None);
            drop(first);

            let room_for_another = admission.has_room(testing::endpoint_id(8));
            drop(second);
            endpoint.close().await;
            assert!(
                !room_for_another,
                "the drop of the old dial released the reservation of the new one"
            );
        });
    }

    /// **The guard of an old dial that drops keeps the entry of the new dialer.**
    ///
    /// A third send while the new dial is in flight waits for it, and does not start a second dial.
    #[test]
    fn an_old_dial_that_drops_keeps_the_entry_of_the_new_dialer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, bob, endpoint, _silent) = pool_with_silent_peer().await;

            let old = pool.register_dial(bob);
            if let super::registration::Registration::Dialer(old) = &old {
                old.publish(Err("an old dial failed".to_owned()));
            }
            let new = pool.register_dial(bob);
            drop(old);
            let third = pool.register_dial(bob);
            let is_waiter = matches!(third, super::registration::Registration::Waiter(_));
            drop(third);
            drop(new);

            assert!(
                is_waiter,
                "the drop of the old dial removed the entry of the new dial"
            );
            endpoint.close().await;
        });
    }

    /// Two sends to a peer that nobody serves: the waiter gets the error of the one dial there was,
    /// and does not dial again. The peer is on the dial-failure cooldown afterwards.
    #[test]
    fn a_waiter_gets_the_dial_error_without_a_second_dial() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
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
        });
    }

    /// A background send during a dial is not dropped: it waits for the dial and is delivered after
    /// it. It used to return `false` and send nothing.
    #[test]
    fn a_background_frame_during_a_dial_is_delivered_after_it() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (pool, server, router, client, mut frames) =
                    pool_with_collecting_server().await;

                let gate = pool.hold_next_dial();
                assert!(
                    pool.dial_and_send_in_background(
                        server,
                        bytes::Bytes::from_static(b"one"),
                        || None
                    )
                    .await,
                    "the first frame starts the dial"
                );
                assert!(
                    pool.dial_and_send_in_background(
                        server,
                        bytes::Bytes::from_static(b"two"),
                        || None
                    )
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
            },
        );
    }

    /// A dialer that is aborted mid-dial wakes the callers that wait on it, with an error, long
    /// before the dial would have timed out, and leaves no entry behind.
    #[test]
    fn a_cancelled_dialer_wakes_its_waiters() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
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
                time::sleep(Duration::from_millis(5)).await;
            }
            let waiter = tokio::spawn({
                let pool = pool.clone();
                async move { pool.dial_or_warm_send(bob, bytes::Bytes::new()).await }
            });
            time::sleep(Duration::from_millis(100)).await;

            dialer.abort();

            let outcome = time::timeout(Duration::from_secs(1), waiter)
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
        });
    }

    /// A test that needs a cold send drops the pooled connection of a peer: the cooldown goes with
    /// it, the address stays, and the next send dials again.
    #[test]
    fn dropping_a_pooled_connection_keeps_the_address_and_clears_the_cooldown() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (pool, server, router, client, mut frames) =
                    pool_with_collecting_server().await;
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
            },
        );
    }

    /// A graceful `Left` forgets the peer's pool slots: the dial cooldown is
    /// cleared so a rejoin dials immediately, and forgetting an unknown
    /// endpoint is a no-op. (Closing a warm `Connection` needs a live
    /// endpoint pair; that path is covered by the network suite.)
    #[test]
    fn forget_clears_the_cooldown_and_tolerates_absence() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
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
        });
    }

    /// A send over a pooled connection is a use of it: the ledger of the ceiling moves its
    /// last use to the end of the send, so the connection of a peer that is being talked to
    /// is not the least recently used.
    /// Two frames sent at once to a peer with no warm connection both arrive. A leaver's mirror of its two
    /// channels is this case.
    #[test]
    fn two_frames_sent_at_once_to_a_cold_peer_both_arrive() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use std::sync::atomic::Ordering;

                use iroh::protocol::Router;

                use super::super::unicast_acceptor::UnicastAcceptor;

                let (tx, mut frames) = mpsc::channel(8);
                let server = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                let router = Router::builder(server.clone())
                    .accept(
                        super::super::UNICAST_ALPN,
                        UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
                    )
                    .spawn();
                let node: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
                let pool = super::UnicastPool::new(node.clone(), true);

                // The first dial is held until the second send has started its own dial, so the race is the
                // same on each run: a pool that dials twice replaces the first connection, and its frame is lost.
                let gate = pool.hold_next_dial();
                let first_send = pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"one"));
                let second_send = async {
                    time::sleep(Duration::from_millis(200)).await;
                    pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"two"))
                        .await
                };
                let release = async {
                    time::sleep(Duration::from_millis(600)).await;
                    gate.notify_one();
                };
                let (first, second, ()) = tokio::join!(first_send, second_send, release);
                first.expect("the first send");
                second.expect("the second send");
                let dials = pool.inner.dials_started.load(Ordering::Relaxed);
                assert_eq!(
                    dials, 1,
                    "two sends at once to a cold peer make one dial, not {dials}"
                );

                let mut arrived = 0;
                while arrived < 2 {
                    match time::timeout(Duration::from_secs(5), frames.recv()).await {
                        Ok(Some(_)) => arrived += 1,
                        _ => {
                            panic!("only {arrived} of the 2 frames sent at once arrived within 5 s")
                        }
                    }
                }
                router.shutdown().await.expect("shutdown");
                node.close().await;
                server.close().await;
            },
        );
    }

    /// Waits until `condition` holds, polling every 10 ms, so that a test orders its calls by what the pool shows and
    /// not by a sleep. It fails after 5 s.
    async fn wait_until(mut condition: impl FnMut() -> bool) {
        let started = time::Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the pool did not reach the state that the test waits for"
            );
            time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The handles that hold the dial lock of a peer: the map, and the turn of each dial that waits or dials.
    fn lock_handles(pool: &super::UnicastPool) -> usize {
        use std::sync::Arc;

        let locks = pool.inner.dial_locks.lock();
        locks.values().map(Arc::strong_count).max().unwrap_or(0)
    }

    /// Two probes that dial one cold peer at once share one connection, and it keeps the hold of a probe: `Probing`
    /// while the probes run, and `Probed` once they end. A send is what turns it into `Used`.
    #[test]
    fn two_probes_at_once_leave_the_hold_probing() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::protocol::Router;

                use super::super::unicast_acceptor::UnicastAcceptor;
                use super::unicast_pool::Hold;

                let (tx, _frames) = mpsc::channel(8);
                let server = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                let router = Router::builder(server.clone())
                    .accept(
                        super::super::UNICAST_ALPN,
                        UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
                    )
                    .spawn();
                let node: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
                let pool = super::UnicastPool::new(node.clone(), true);
                let peer = server.id();

                let gate = pool.hold_next_dial();
                let first_probe = pool.probe_connection(peer);
                let second_probe = async {
                    wait_until(|| lock_handles(&pool) >= 2).await;
                    pool.probe_connection(peer).await
                };
                let release = async {
                    wait_until(|| lock_handles(&pool) >= 3).await;
                    gate.notify_one();
                };
                let (one, two, ()) = tokio::join!(first_probe, second_probe, release);
                one.expect("the first probe connection");
                two.expect("the second probe connection");
                let running = pool
                    .inner
                    .conns
                    .lock()
                    .await
                    .get(&peer)
                    .map(|pooled| pooled.hold);
                assert!(
                    matches!(running, Some(Hold::Probing)),
                    "two probes that share a connection leave it probing, not {running:?}"
                );
                pool.probe_done(peer).await;
                let ended = pool
                    .inner
                    .conns
                    .lock()
                    .await
                    .get(&peer)
                    .map(|pooled| pooled.hold);
                assert!(
                    matches!(ended, Some(Hold::Probed(_))),
                    "the connection is probed once the probes end, not {ended:?}"
                );
                router.shutdown().await.expect("shutdown");
                node.close().await;
                server.close().await;
            },
        );
    }

    /// **A forced dial failure waits for the dial that runs.** A dial that passed the cooldown check
    /// before the failure was forced ends with a success, clears the cooldown and pools a connection.
    /// The next send then succeeds instead of meeting the cooldown that the test forced, and the test
    /// is a race. The forced failure takes the dial lock of the peer, so it comes after that dial.
    #[test]
    fn a_forced_dial_failure_waits_for_the_dial_in_flight_and_so_it_stays() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::protocol::Router;

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
                        UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
                    )
                    .spawn();
                let node: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
                let pool = super::UnicastPool::new(node.clone(), true);
                let peer = server.id();

                let gate = pool.hold_next_dial();
                let dial = pool.probe_connection(peer);
                let force = async {
                    wait_until(|| lock_handles(&pool) >= 2).await;
                    let forcing = pool.fail_dial_for_test(peer);
                    tokio::pin!(forcing);
                    let early = time::timeout(Duration::from_millis(300), &mut forcing).await;
                    assert!(
                        early.is_err(),
                        "the forced failure did not wait for the dial that was in flight"
                    );
                    gate.notify_one();
                    forcing.await;
                };
                let (connected, ()) = tokio::join!(dial, force);
                connected.expect("the dial in flight ends with a connection");

                assert!(
                    pool.is_cooling(peer).await,
                    "the dial in flight cleared the cooldown that the test forced"
                );
                assert!(
                    !pool.has_warm(peer).await,
                    "the dial in flight left a pooled connection after the forced failure"
                );
                router.shutdown().await.expect("shutdown");
                node.close().await;
                server.close().await;
            },
        );
    }

    /// A dial that is cancelled leaves no lock behind: the lock of the peer goes when the dial future is dropped, not
    /// only when the dial ends.
    #[test]
    fn a_cancelled_dial_leaves_no_lock_behind() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let node: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                let pool = super::UnicastPool::new(node.clone(), true);
                let peer = testing::endpoint_id(7);
                let _gate = pool.hold_next_dial();
                let sender = pool.clone();
                let task = tokio::spawn(async move {
                    sender
                        .dial_and_send(peer, bytes::Bytes::from_static(b"one"))
                        .await
                });
                time::sleep(Duration::from_millis(300)).await;
                assert!(
                    !pool.inner.dial_locks.lock().is_empty(),
                    "a dial that waits holds the lock of its peer"
                );
                task.abort();
                let _ = task.await;
                assert!(
                    pool.inner.dial_locks.lock().is_empty(),
                    "a cancelled dial leaves no lock behind"
                );
                node.close().await;
            },
        );
    }

    /// A send that waits on the dial of a probe finds the probe's connection and takes it: the hold becomes `Used`, so
    /// the sweeper does not close a connection that a send used when the probe ends. The first dial is held until the
    /// send waits on its lock, so the order of the two calls comes from the pool, not from a sleep.
    #[test]
    fn a_send_that_waits_on_a_probe_dial_takes_the_connection_as_used() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::protocol::Router;

                use super::super::unicast_acceptor::UnicastAcceptor;

                let (tx, mut frames) = mpsc::channel(8);
                let server = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                let router = Router::builder(server.clone())
                    .accept(
                        super::super::UNICAST_ALPN,
                        UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
                    )
                    .spawn();
                let node: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
                let pool = super::UnicastPool::new(node.clone(), true);

                let gate = pool.hold_next_dial();
                let probe_dial = pool.probe_connection(server.id());
                let send = async {
                    wait_until(|| lock_handles(&pool) >= 2).await;
                    pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"one"))
                        .await
                };
                let release = async {
                    wait_until(|| lock_handles(&pool) >= 3).await;
                    gate.notify_one();
                };
                let (dialed, outcome, ()) = tokio::join!(probe_dial, send, release);
                dialed.expect("the probe connection");
                outcome.expect("the send");
                let used: bool = pool
                    .inner
                    .conns
                    .lock()
                    .await
                    .get(&server.id())
                    .is_some_and(|pooled| matches!(pooled.hold, super::unicast_pool::Hold::Used));
                assert!(
                    used,
                    "a send that used the probe's connection holds it as used"
                );
                assert!(
                    frames.recv().await.is_some(),
                    "the frame of the send arrives"
                );
                router.shutdown().await.expect("shutdown");
                node.close().await;
                server.close().await;
            },
        );
    }

    #[test]
    fn a_send_marks_its_connection_as_used_in_the_ledger() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
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
                        UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
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
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
                let pool = super::UnicastPool::new(node.clone(), true);
                pool.set_admission(admission.clone());

                pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"one"))
                    .await
                    .expect("the first send");
                let first = admission
                    .last_use(server.id())
                    .expect("the ledger holds it");
                time::sleep(Duration::from_millis(300)).await;
                pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"two"))
                    .await
                    .expect("the second send");
                let second = admission
                    .last_use(server.id())
                    .expect("the ledger holds it");

                assert!(second > first, "the second send is a later use");
                router.shutdown().await.expect("shutdown");
                node.close().await;
            },
        );
    }

    /// A peer that evicted us is left alone by the proactive dial of a probe, and a send to
    /// it dials at once.
    #[test]
    fn an_evicting_peer_is_not_probed_but_a_send_dials_it() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
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
                        UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
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
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
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
            },
        );
    }

    /// The idle close of a pooled connection is the one backstop of the direct connections.
    #[test]
    fn a_pool_closes_an_idle_connection_after_the_one_backstop() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            super::UnicastPool::disconnected().inner.idle,
            tuning::DIRECT_IDLE_BACKSTOP,
            "the idle backstop is the one set on a disconnected pool"
        );
    }

    /// **A frame that the sender drops before the commit is reset, never finished.** A stream that is
    /// dropped finishes by itself, and the finish is the commit: any early return of a send, or a
    /// send task that is cancelled, would have told the peer to take a frame that the user was told
    /// had failed. The peer reads a reset, and takes nothing.
    #[test]
    fn a_frame_that_is_dropped_before_the_commit_is_reset_and_the_peer_takes_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (pool, server, router, client, mut frames) = pool_with_collecting_server().await;
            let connection = pool.warm_or_dial(server).await.expect("dial");
            let (stream, held) = connection.open_bi().await.expect("open a stream");
            let mut frame = super::outgoing_frame::OutgoingFrame::new(stream, held);
            frame.write(b"frame").await.expect("write");
            frame.held().await.expect("the peer holds the frame");

            drop(frame);

            // The commit of a frame crosses loopback in well under a millisecond: a second is
            // thousands of round trips, so a frame that the peer meant to take is in by then.
            time::sleep(Duration::from_secs(1)).await;
            assert!(
                frames.try_recv().is_err(),
                "the peer took a frame that the sender dropped before the commit"
            );
            router.shutdown().await.expect("shutdown");
            client.close().await;
        });
    }

    /// **The busy mark lasts until the peer has acknowledged the frame.** `finish()` returns while
    /// the frame is still in flight, so a mark that ended there left a connection with a slow reader
    /// open to eviction, with its frame in the air. The send holds the mark until the peer took the
    /// frame, and the send ends then.
    #[test]
    fn a_send_keeps_its_connection_busy_until_the_peer_has_acknowledged_the_frame() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::protocol::{AcceptError, ProtocolHandler, Router};

                use super::super::admission::SignalAdmission;

                #[derive(Debug, Clone)]
                struct SlowReader;
                impl ProtocolHandler for SlowReader {
                    async fn accept(
                        &self,
                        connection: endpoint::Connection,
                    ) -> Result<(), AcceptError> {
                        let (acknowledgement, stream) = connection
                            .accept_bi()
                            .await
                            .map_err(AcceptError::from_err)?;
                        time::sleep(Duration::from_millis(800)).await;
                        let _ = super::super::unicast_acceptor::receive_for_test(
                            acknowledgement,
                            stream,
                        )
                        .await;
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
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
                let pool = super::UnicastPool::new(node.clone(), true);
                pool.set_admission(admission.clone());

                let sending = {
                    let pool = pool.clone();
                    let id = server.id();
                    task::spawn(async move {
                        pool.dial_and_send(id, bytes::Bytes::from(vec![7u8; 3000]))
                            .await
                    })
                };
                let mut busy = false;
                for _ in 0..8 {
                    busy |= admission.is_busy(server.id());
                    time::sleep(Duration::from_millis(50)).await;
                }
                assert!(
                    busy,
                    "the frame is in flight: the peer has not read it, so it has not acknowledged it"
                );
                sending
                    .await
                    .expect("the send task")
                    .expect("the peer acknowledged the frame");
                assert!(
                    !admission.is_busy(server.id()),
                    "the mark ends with the acknowledgement"
                );

                router.shutdown().await.expect("shutdown");
                node.close().await;
            },
        );
    }
}
