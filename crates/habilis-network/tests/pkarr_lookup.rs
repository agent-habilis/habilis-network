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
    let (live, pkarr_server) = test_pkarr::spawn_plain().await.expect("pkarr relay");
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

    // The record on the pkarr relay names the home relay, and no IP address.
    let record = pkarr_server
        .info(&target.id().to_z32())
        .expect("the relay holds the target's record");
    assert_eq!(
        record.data.relay_urls().collect::<Vec<_>>(),
        vec![&relay],
        "the record names the home relay"
    );
    assert_eq!(record.data.ip_addrs().count(), 0, "and no direct address");
    assert_eq!(pkarr_server.rejected(), 0, "no write was refused");
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

/// The relay is as strict as the real ones, so the tests below hold the relay
/// to it: a client that works against a lax stand-in and fails on n0's server
/// would otherwise pass here.
mod strict_relay {
    use habilis_network::iroh::endpoint_info::{EndpointData, EndpointInfo};
    use habilis_network::iroh::{RelayUrl, SecretKey, TransportAddr};
    use habilis_network::net::test_pkarr::{self, TestPkarr};
    use habilis_network::protocol::Url;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    struct Reply {
        status: u16,
        headers: String,
        body: Vec<u8>,
    }

    /// One HTTP/1.1 request, read to the end of the connection.
    async fn http(url: &Url, method: &str, key: &str, extra: &str, body: &[u8]) -> Reply {
        let host = url.host_str().expect("a host");
        let port = url.port().expect("a port");
        let path = format!("{}/{key}", url.path().trim_end_matches('/'));
        let mut stream = TcpStream::connect((host, port)).await.expect("connect");
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.expect("write head");
        stream.write_all(body).await.expect("write body");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read");
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("a header block");
        let headers = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
        let status = headers
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("a status line");
        Reply {
            status,
            headers,
            body: raw[split + 4..].to_vec(),
        }
    }

    fn payload(secret: &SecretKey, relay_port: u16) -> Vec<u8> {
        let relay: RelayUrl = format!("http://127.0.0.1:{relay_port}/")
            .parse()
            .expect("a relay url");
        let data = EndpointData::new(vec![TransportAddr::Relay(relay)]);
        let info = EndpointInfo::from_parts(secret.public(), data);
        info.to_pkarr_signed_packet(secret, 30)
            .expect("a signed packet")
            .to_relay_payload()
    }

    async fn relays() -> Vec<(Url, TestPkarr)> {
        vec![
            test_pkarr::spawn_plain().await.expect("relay under /pkarr"),
            test_pkarr::spawn_at("").await.expect("relay at the root"),
        ]
    }

    #[tokio::test]
    async fn it_stores_a_signed_record_and_serves_it_back() {
        for (url, relay) in relays().await {
            let secret = SecretKey::from_bytes(&[1; 32]);
            let key = secret.public().to_z32();
            let body = payload(&secret, 1111);
            assert_eq!(http(&url, "PUT", &key, "", &body).await.status, 204);
            let got = http(&url, "GET", &key, "", &[]).await;
            assert_eq!((got.status, got.body), (200, body));
            assert!(relay.holds(&key));
            let info = relay.info(&key).expect("a decodable record");
            assert_eq!(info.data.relay_urls().count(), 1);
        }
    }

    #[tokio::test]
    async fn it_refuses_a_record_whose_signature_does_not_verify() {
        for (url, relay) in relays().await {
            let secret = SecretKey::from_bytes(&[2; 32]);
            let key = secret.public().to_z32();
            let mut body = payload(&secret, 1111);
            *body.last_mut().expect("a body") ^= 1;
            assert_eq!(http(&url, "PUT", &key, "", &body).await.status, 400);
            let other = SecretKey::from_bytes(&[3; 32]);
            let foreign = payload(&other, 1111);
            assert_eq!(http(&url, "PUT", &key, "", &foreign).await.status, 400);
            assert!(!relay.holds(&key));
            assert_eq!(relay.rejected(), 2);
        }
    }

    #[tokio::test]
    async fn it_refuses_a_write_that_is_not_newer() {
        for (url, relay) in relays().await {
            let secret = SecretKey::from_bytes(&[4; 32]);
            let key = secret.public().to_z32();
            let first = payload(&secret, 1111);
            assert_eq!(http(&url, "PUT", &key, "", &first).await.status, 204);
            assert_eq!(http(&url, "PUT", &key, "", &first).await.status, 409);
            assert_eq!(relay.rejected(), 1);
        }
    }

    #[tokio::test]
    async fn it_says_which_key_each_refusal_was_for() {
        let (url, relay) = test_pkarr::spawn_plain().await.expect("relay");
        let stale = SecretKey::from_bytes(&[7; 32]);
        let stale_key = stale.public().to_z32();
        let body = payload(&stale, 1111);
        assert_eq!(http(&url, "PUT", &stale_key, "", &body).await.status, 204);
        assert_eq!(http(&url, "PUT", &stale_key, "", &body).await.status, 409);

        let forged = SecretKey::from_bytes(&[8; 32]);
        let forged_key = forged.public().to_z32();
        let mut bad = payload(&forged, 1111);
        *bad.last_mut().expect("a body") ^= 1;
        assert_eq!(http(&url, "PUT", &forged_key, "", &bad).await.status, 400);

        assert_eq!(
            relay.refusals(),
            vec![(stale_key, 409), (forged_key, 400)],
            "each refusal carries its key and status, in order"
        );
        assert_eq!(relay.rejected(), 2);
    }

    #[tokio::test]
    async fn it_answers_the_cors_preflight() {
        for (url, _relay) in relays().await {
            let key = SecretKey::from_bytes(&[5; 32]).public().to_z32();
            let extra = "Origin: http://example.test\r\nAccess-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: content-type\r\n";
            let reply = http(&url, "OPTIONS", &key, extra, &[]).await;
            assert_eq!(reply.status, 204);
            assert!(reply.headers.contains("access-control-allow-origin: *"));
            assert!(
                reply
                    .headers
                    .contains("access-control-allow-methods: get, put")
            );
            assert!(
                reply
                    .headers
                    .contains("access-control-allow-headers: content-type")
            );
        }
    }

    #[tokio::test]
    async fn it_serves_only_under_its_prefix() {
        let (url, _relay) = test_pkarr::spawn_plain().await.expect("relay");
        let key = SecretKey::from_bytes(&[6; 32]).public().to_z32();
        let root: Url = format!(
            "http://{}:{}/",
            url.host_str().unwrap(),
            url.port().unwrap()
        )
        .parse()
        .unwrap();
        assert_eq!(http(&root, "GET", &key, "", &[]).await.status, 404);
    }
}
