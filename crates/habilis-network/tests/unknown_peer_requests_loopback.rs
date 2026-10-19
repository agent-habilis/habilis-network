//! A request that names a member the node does not know does not apply, and the node says so.
//!
//! The cut of a rung to one member, the deny of one member, the offer of a session to one
//! member and the close of the gossip link to one member are made on the book of the node. Before this test they answered `()` for a member the
//! book did not hold, and did nothing: a test that cut a member it had not learned yet went on as
//! if the cut stood.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use habilis_network::membership::{self, Request, Rung, UnknownPeer};
use habilis_network::protocol::{Lookup, Transport};

#[test]
fn a_cut_a_deny_an_offer_and_a_close_on_a_member_the_node_does_not_know_are_refused() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (relay, _server) = habilis_network::net::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let (sink, _events) = membership::json_sink();
        let member = membership::join(
            &membership::Opts {
                nick: Some("alice".to_owned()),
                lookup: vec![Lookup::Relay],
                transport: vec![Transport::Udp],
                relay_urls: vec![relay.to_string()],
                ..membership::Opts::default()
            },
            sink,
        )
        .await
        .expect("open a member");
        let nobody = || "nobody".to_owned();

        let cut = member
            .request(|reply| Request::BlockRungTo {
                rung: Rung::WebRtc,
                peer: nobody(),
                blocked: true,
                reply,
            })
            .await
            .expect("the loop answers");
        let deny = member
            .request(|reply| Request::DenyPeer {
                peer: nobody(),
                denied: true,
                reply,
            })
            .await
            .expect("the loop answers");
        let offer = member
            .request(|reply| Request::OfferSession {
                peer: nobody(),
                reply,
            })
            .await
            .expect("the loop answers");
        let close = member
            .request(|reply| Request::CloseLink {
                peer: nobody(),
                reply,
            })
            .await
            .expect("the loop answers");

        let _ = member.node.leave().await;
        let unknown = Err(UnknownPeer(nobody()));
        assert_eq!(
            cut, unknown,
            "the cut of a rung to an unknown member was acknowledged"
        );
        assert_eq!(
            deny, unknown,
            "the deny of an unknown member was acknowledged"
        );
        assert_eq!(
            offer, unknown,
            "the offer to an unknown member was acknowledged"
        );
        assert_eq!(
            close, unknown,
            "the close of a link to an unknown member was acknowledged"
        );
    });
}
