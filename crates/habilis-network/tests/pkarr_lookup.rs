//! The pkarr lookup resolves a peer from its endpoint id alone. Each side
//! homes on a local relay, publishes its record to a local pkarr relay, and
//! the dialer is handed nothing but the id.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::time::Duration;

use habilis_network::iroh::{Endpoint, EndpointAddr, RelayUrl};
use habilis_network::net::{TransportHandles, build_endpoint, test_pkarr, test_relay};
use habilis_network::protocol::{LookupOpts, PkarrChoice, RelayChoice, Url};

const ALPN: &[u8] = b"habilis-network/pkarr-test/0";
const DEADLINE: Duration = Duration::from_secs(20);

async fn endpoint(relay: &RelayUrl, pkarr: PkarrChoice) -> Endpoint {
    let lookups = LookupOpts {
        mdns: false,
        dht: false,
        relay_lookup: RelayChoice::Custom(vec![relay.clone()]),
        pkarr,
    };
    build_endpoint(
        &lookups,
        None,
        None,
        vec![ALPN.to_vec()],
        TransportHandles::default(),
    )
    .await
    .expect("bind")
}

/// Accept one connection, so the dial has a peer that completes it.
fn serve(endpoint: &Endpoint) {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await
            && let Ok(connection) = incoming.await
        {
            connection.closed().await;
        }
    });
}

/// The first URL refuses every connection, so only the fallback can answer.
#[tokio::test]
async fn a_bare_id_resolves_through_the_pkarr_list_past_a_dead_relay() {
    let (relay, _relay_server) = test_relay::spawn_plain().await.expect("relay");
    let (live, _pkarr_server) = test_pkarr::spawn_plain().await.expect("pkarr relay");
    let dead: Url = "http://127.0.0.1:1/pkarr".parse().unwrap();
    let urls = PkarrChoice::Custom(vec![dead, live]);

    let target = endpoint(&relay, urls.clone()).await;
    serve(&target);
    target.online().await;
    let dialer = endpoint(&relay, urls).await;

    let connection = tokio::time::timeout(
        DEADLINE,
        dialer.connect(EndpointAddr::new(target.id()), ALPN),
    )
    .await
    .expect("the dial finishes before the deadline")
    .expect("the bare id resolves through pkarr");
    assert_eq!(connection.remote_id(), target.id());
}

/// The control: the same dial with pkarr off has nothing to resolve the id.
#[tokio::test]
async fn a_bare_id_does_not_resolve_without_pkarr() {
    let (relay, _relay_server) = test_relay::spawn_plain().await.expect("relay");
    let target = endpoint(&relay, PkarrChoice::Disabled).await;
    serve(&target);
    target.online().await;
    let dialer = endpoint(&relay, PkarrChoice::Disabled).await;

    let dial = tokio::time::timeout(
        DEADLINE,
        dialer.connect(EndpointAddr::new(target.id()), ALPN),
    )
    .await;
    assert!(
        !matches!(dial, Ok(Ok(_))),
        "without a lookup the bare id must not resolve"
    );
}
