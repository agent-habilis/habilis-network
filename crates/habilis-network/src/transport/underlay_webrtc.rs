//! A `WebRTC` leg on the multihop underlay, so that a cell can be forwarded over a
//! session between two members that have no IP path to each other.
//!
//! The underlay is an endpoint of its own with its own key. It gets its own
//! `WebRtcHandle`, its own admission table (cap G) and the signal protocol on
//! its router. A session opens only to a member whose application path is
//! `WebRTC`: where IP works, the underlay reaches the member over IP already. A
//! node without `udp` has an underlay with no IP socket, and a session opens to
//! every member it holds a link vector from.
//!
//! The members are read from the roster, not from the live gossip links. The
//! relay watcher closes a gossip link on purpose, and a route that other
//! members use must not end with it. So there is one session per known member
//! that needs one, and the cap of the admission table bounds them.

mod allowed;
pub(crate) use allowed::Allowed;
mod plan;
pub(crate) use plan::plan;
mod tick;
pub(crate) use tick::{held_members, tick, tick_now};
mod underlay_signal_gate;
pub(crate) use underlay_signal_gate::UnderlaySignalGate;
mod underlay_web_rtc;
pub(crate) use underlay_web_rtc::UnderlayWebRtc;

#[cfg(test)]
mod tests {
    use crate::transport::UdpTransport;
    use iroh::{EndpointId, SecretKey};
    use std::net::SocketAddr;

    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, EndpointAddr, RelayMode};

    use super::plan::{self, Plan};
    use super::{Allowed, UnderlaySignalGate, tick};
    use crate::transport::probe::PathKind;
    use crate::transport::{
        IceProfile, MESH_WEBRTC_SIGNAL_ALPN, SignalAdmission, WebRtcSignalAcceptor,
    };

    use crate::lookup::EndpointError;
    use crate::transport::webrtc;
    use crate::{lookup, testing};
    use iroh::endpoint;
    use std::time::{Duration, Duration as std_Duration};
    use tokio::{time, time as tokio_time};
    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// Two ids, the lower first.
    fn ordered() -> (EndpointId, EndpointId) {
        let (first, second) = (id(1), id(2));
        if first < second {
            (first, second)
        } else {
            (second, first)
        }
    }

    #[test]
    fn the_lower_id_dials_a_wanted_neighbor_with_no_session() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = ordered();
        assert_eq!(
            plan::plan(low, &[high], &[high], &[], usize::MAX),
            Plan {
                dial: vec![high],
                detach: vec![]
            },
            "the lower id dials a wanted neighbor with no session"
        );
    }

    #[test]
    fn the_higher_id_waits_to_be_dialed() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = ordered();
        assert_eq!(
            plan::plan(high, &[low], &[low], &[], usize::MAX),
            Plan::default(),
            "the higher id waits to be dialed"
        );
    }

    #[test]
    fn a_neighbor_that_has_a_session_is_not_dialed_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = ordered();
        assert_eq!(
            plan::plan(low, &[high], &[high], &[high], usize::MAX),
            Plan::default(),
            "a neighbor with a session is not dialed again"
        );
    }

    #[test]
    fn a_session_with_a_peer_that_is_not_kept_is_detached() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = ordered();
        assert_eq!(
            plan::plan(low, &[], &[], &[high], usize::MAX),
            Plan {
                dial: vec![],
                detach: vec![high]
            },
            "a session with a peer that is not kept is detached"
        );
    }

    #[test]
    fn a_session_with_a_kept_peer_stays_even_when_it_is_not_wanted() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = ordered();
        assert_eq!(
            plan::plan(low, &[], &[high], &[high], usize::MAX),
            Plan::default(),
            "a session with a kept peer stays even when it is not wanted"
        );
    }

    fn neighbor_kinds(
        walking: EndpointId,
        on_ip: EndpointId,
        on_relay: EndpointId,
    ) -> impl Fn(EndpointId) -> Option<PathKind> {
        move |member| {
            if member == walking {
                Some(PathKind::WebRtc)
            } else if member == on_ip {
                Some(PathKind::Ip)
            } else if member == on_relay {
                Some(PathKind::Relay)
            } else {
                None
            }
        }
    }

    #[test]
    fn only_a_neighbor_whose_application_path_is_webrtc_is_wanted() {
        let _guard = ::habilis_network_test_tracing::init();
        let (webrtc, ip, relay, unknown) = (id(11), id(12), id(13), id(14));
        let neighbors: Vec<(EndpointId, EndpointAddr)> = [webrtc, ip, relay, unknown]
            .into_iter()
            .map(|member| (member, reachable_over_ip(id(member.as_bytes()[0] ^ 0x55))))
            .collect();
        let wanted = plan::wanted_underlays(
            &neighbors,
            UdpTransport::Present,
            neighbor_kinds(webrtc, ip, relay),
        );
        assert_eq!(
            wanted,
            vec![&neighbors[0].1],
            "only a neighbor whose application path is webrtc is wanted"
        );
    }

    /// The underlay address of a neighbor that has an IP socket.
    fn reachable_over_ip(underlay: EndpointId) -> EndpointAddr {
        EndpointAddr::new(underlay).with_ip_addr("127.0.0.1:4433".parse().expect("an address"))
    }

    /// The underlay address of a neighbor without an IP socket, as its link vector gives it: the
    /// relay and nothing else.
    fn relay_only(underlay: EndpointId) -> EndpointAddr {
        EndpointAddr::new(underlay).with_relay_url("https://relay.test".parse().expect("a url"))
    }

    /// A neighbor whose underlay address has no IP entry (a node without `udp`) can only be
    /// reached by a session, so a node with `udp` wants it too, whatever the application path is.
    /// A neighbor with an IP entry on the relay path is not wanted.
    #[test]
    fn a_neighbor_whose_underlay_has_no_ip_is_wanted_by_a_node_with_udp() {
        let _guard = ::habilis_network_test_tracing::init();
        let (no_ip, with_ip) = (id(41), id(42));
        let neighbors = vec![
            (no_ip, relay_only(id(51))),
            (with_ip, reachable_over_ip(id(52))),
        ];
        let on_relay = |_member: EndpointId| Some(PathKind::Relay);
        assert_eq!(
            plan::wanted_underlays(&neighbors, UdpTransport::Present, on_relay),
            vec![&neighbors[0].1],
            "a neighbor whose underlay has no ip is wanted by a node with udp"
        );
    }

    /// The rule above is for the lower id: `plan` dials only from there. A node with the higher
    /// underlay id wants the session and waits for the offer.
    #[test]
    fn the_higher_underlay_id_wants_a_session_and_does_not_dial() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = ordered();
        assert_eq!(
            plan::plan(high, &[low], &[low], &[], usize::MAX),
            Plan::default(),
            "the higher underlay id wants a session and does not dial"
        );
        assert_eq!(
            plan::plan(low, &[high], &[high], &[], usize::MAX).dial,
            vec![high],
            "the lower underlay id dials the higher one's neighbor"
        );
    }

    /// A node without `udp` has no IP on its underlay: the session is the only path to every
    /// neighbor, so each one is wanted, whatever the application path is (a lookup-only mesh
    /// can leave the pair on the relay or unread).
    #[test]
    fn a_node_without_udp_wants_a_session_to_every_neighbor() {
        let _guard = ::habilis_network_test_tracing::init();
        let (webrtc, ip, relay, unknown) = (id(11), id(12), id(13), id(14));
        let neighbors: Vec<(EndpointId, EndpointAddr)> = [webrtc, ip, relay, unknown]
            .into_iter()
            .map(|member| (member, EndpointAddr::new(id(member.as_bytes()[0] ^ 0x55))))
            .collect();
        let wanted = plan::wanted_underlays(
            &neighbors,
            UdpTransport::Absent,
            neighbor_kinds(webrtc, ip, relay),
        );
        let all: Vec<&EndpointAddr> = neighbors.iter().map(|(_, address)| address).collect();
        assert_eq!(
            wanted, all,
            "a node without udp wants a session to every neighbor"
        );
    }

    #[test]
    fn a_denied_member_is_not_a_neighbor_of_the_underlay() {
        let _guard = ::habilis_network_test_tracing::init();
        let (kept, denied) = (id(21), id(22));
        let neighbors: Vec<(EndpointId, EndpointAddr)> = [kept, denied]
            .into_iter()
            .map(|member| (member, EndpointAddr::new(id(member.as_bytes()[0] ^ 0x55))))
            .collect();
        let left = plan::undenied(neighbors.clone(), |member| member == denied);
        assert_eq!(
            left,
            vec![neighbors[0].clone()],
            "a denied member is not a neighbor of the underlay"
        );
    }

    /// A neighbor whose path is not read for the moment (an idle connection of the
    /// pool closed), or is on another rung, keeps its session. It goes only when
    /// the neighbor leaves the view or the pair climbs to IP.
    #[test]
    fn a_session_is_detached_only_when_the_neighbor_climbs_to_ip_or_leaves() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = ordered();
        let (member, other) = (id(31), id(32));
        let neighbor = vec![(member, EndpointAddr::new(high))];
        let kept_with = |kind_of: &dyn Fn(EndpointId) -> Option<PathKind>| {
            plan::kept_underlays(&neighbor, kind_of)
        };

        let on_webrtc = kept_with(&neighbor_kinds(member, other, other));
        assert_eq!(
            plan::plan(low, &[], &on_webrtc, &[high], usize::MAX),
            Plan::default(),
            "a session is detached only when the neighbor climbs to ip or leaves"
        );
        let unread = kept_with(&neighbor_kinds(other, other, other));
        assert_eq!(
            plan::plan(low, &[], &unread, &[high], usize::MAX),
            Plan::default(),
            "unread"
        );
        let on_relay = kept_with(&neighbor_kinds(other, other, member));
        assert_eq!(
            plan::plan(low, &[], &on_relay, &[high], usize::MAX),
            Plan::default(),
            "relay"
        );

        let on_ip = kept_with(&neighbor_kinds(other, member, other));
        assert_eq!(
            plan::plan(low, &[], &on_ip, &[high], usize::MAX),
            Plan {
                dial: vec![],
                detach: vec![high]
            },
            "the pair climbed to IP"
        );

        let left = plan::kept_underlays(&[], neighbor_kinds(member, other, other));
        assert_eq!(
            plan::plan(low, &[], &left, &[high], usize::MAX),
            Plan {
                dial: vec![],
                detach: vec![high]
            },
            "the member left the roster"
        );
    }

    /// A session is named by the underlay id of its member, and the edge by the member id.
    #[test]
    fn a_member_whose_underlay_holds_a_session_is_listed_by_its_member_id() {
        let _guard = ::habilis_network_test_tracing::init();
        let (with_session, without) = (id(61), id(62));
        let neighbors = vec![
            (with_session, relay_only(id(71))),
            (without, relay_only(id(72))),
        ];
        assert_eq!(
            tick::members_with_session(&neighbors, &[id(71)]),
            vec![with_session],
            "a member whose underlay holds a session is listed by its member id"
        );
        assert!(
            tick::members_with_session(&neighbors, &[]).is_empty(),
            "a member without a session is not listed"
        );
    }

    #[test]
    fn plan_dials_the_lowest_ids_that_the_room_allows() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut ids: Vec<EndpointId> = (1..=4).map(id).collect();
        ids.sort_unstable();
        let (low, higher) = (ids[0], ids[1..].to_vec());
        let all = plan::plan(low, &higher, &higher, &[], usize::MAX);
        assert_eq!(all.dial, higher, "no limit: every wanted id above ours");
        let one = plan::plan(low, &higher, &higher, &[], 1);
        assert_eq!(one.dial, higher[..1].to_vec(), "room 1: the lowest id");
        let none = plan::plan(low, &higher, &higher, &[], 0);
        assert!(none.dial.is_empty(), "no room: no offer");
    }

    async fn loopback_endpoint() -> Endpoint {
        let builder = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("valid bind addr");
        builder.bind().await.expect("bind a loopback endpoint")
    }

    /// The code that the gate closes a connection with when the dialer is not a
    /// neighbor.
    fn closed_with(reason: &endpoint::ConnectionError) -> Option<u64> {
        match reason {
            endpoint::ConnectionError::ApplicationClosed(close) => {
                Some(close.error_code.into_inner())
            }
            endpoint::ConnectionError::VersionMismatch
            | endpoint::ConnectionError::TransportError(_)
            | endpoint::ConnectionError::ConnectionClosed(_)
            | endpoint::ConnectionError::Reset
            | endpoint::ConnectionError::TimedOut
            | endpoint::ConnectionError::LocallyClosed
            | endpoint::ConnectionError::CidsExhausted => None,
        }
    }

    #[test]
    fn the_gate_refuses_a_signal_from_an_endpoint_that_is_not_a_neighbor() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (logs, _log_guard) = testing::LogCapture::start(tracing::Level::DEBUG);
            let server = loopback_endpoint().await;
            let allowed = Allowed::default();
            let acceptor: WebRtcSignalAcceptor = WebRtcSignalAcceptor::new(
                lookup::build_webrtc_handle(server.id()),
                server.clone(),
                lookup::address_book(&server.clone()),
                server.id(),
                SignalAdmission::new(4),
                IceProfile { host_only: true },
            );
            let router: Router = Router::builder(server.clone())
                .accept(
                    MESH_WEBRTC_SIGNAL_ALPN,
                    UnderlaySignalGate::new(acceptor, allowed.clone()),
                )
                .spawn();
            let client = loopback_endpoint().await;

            let refused = client
                .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
                .await
                .expect("the connection opens");
            let reason = tokio_time::timeout(std_Duration::from_secs(5), refused.closed())
                .await
                .expect("the gate closes the connection of a stranger");
            assert_eq!(closed_with(&reason), Some(9), "{reason:?}");
            let logged = logs.text();
            assert!(
                logged.contains("underlay signal refused")
                    && logged.contains(&client.id().to_string()),
                "the refusal names the peer and the reason: {logged}"
            );

            // Once the client is a neighbor, the gate hands the connection to the
            // acceptor, which waits for an offer and does not close it.
            allowed.replace([client.id()].into_iter().collect());
            let accepted = client
                .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
                .await
                .expect("the connection opens");
            assert!(
                tokio_time::timeout(std_Duration::from_millis(700), accepted.closed())
                    .await
                    .is_err(),
                "a neighbor is not turned away"
            );
            router.shutdown().await.expect("the router stops");
        });
    }

    /// The offerer must tell a stranger's turn-away from a refusal at the cap: the first is a
    /// race that the next offer wins, the second backs off.
    #[test]
    fn an_offer_that_the_gate_turns_away_is_told_apart_from_a_cap_refusal() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let server = loopback_endpoint().await;
            let allowed = Allowed::default();
            let acceptor: WebRtcSignalAcceptor = WebRtcSignalAcceptor::new(
                lookup::build_webrtc_handle(server.id()),
                server.clone(),
                lookup::address_book(&server.clone()),
                server.id(),
                SignalAdmission::new(4),
                IceProfile { host_only: true },
            );
            let router: Router = Router::builder(server.clone())
                .accept(
                    MESH_WEBRTC_SIGNAL_ALPN,
                    UnderlaySignalGate::new(acceptor, allowed.clone()),
                )
                .spawn();
            let client = loopback_endpoint().await;
            let handle = lookup::build_webrtc_handle(client.id());
            let book = lookup::address_book(&client);

            let error = webrtc::dial_signal::dial_signal(
                &client,
                &book,
                server.addr(),
                &handle,
                IceProfile { host_only: true },
            )
            .await
            .expect_err("the gate turns a stranger away");
            assert!(
                matches!(error, EndpointError::NotANeighbor { .. }),
                "the refusal is read from the close code: {error:#}"
            );
            assert!(
                !matches!(error, EndpointError::CapRefused { .. }),
                "a stranger is not a cap refusal: {error:#}"
            );

            // Once the client is a neighbor the same dial is not turned away as one.
            allowed.replace([client.id()].into_iter().collect());
            if let Ok(Err(late_error)) = time::timeout(
                Duration::from_secs(3),
                webrtc::dial_signal::dial_signal(
                    &client,
                    &book,
                    server.addr(),
                    &handle,
                    IceProfile { host_only: true },
                ),
            )
            .await
            {
                assert!(
                    !matches!(late_error, EndpointError::NotANeighbor { .. }),
                    "a neighbor is not turned away: {late_error:#}"
                );
            }
            router.shutdown().await.expect("the router stops");
            client.close().await;
        });
    }
}
