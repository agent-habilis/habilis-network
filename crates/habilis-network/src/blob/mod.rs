//! The blob channel — direct point-to-point transfer of payloads too large for a
//! gossip frame, off the gossip plane entirely. The producer serves the content,
//! content-addressed by SHA-256, over a dedicated QUIC endpoint and mints a bare
//! [`ticket::BlobTicket`] referencing it. The consumer dials the producer,
//! presents the ticket's bearer secret, and streams the bytes — verified against
//! the advertised hash.
//!
//! Layering: a *transport* parallel to the gossip binding — its own ALPN, its own
//! bearer-secret handshake, its own bare-base58 ticket. The bytes never touch
//! gossip; only the small reference does, and getting that reference to the
//! consumer is the application's job (it is a short string, so a single
//! [`crate::gossip::send_app`] frame carries it).
//!
//! A mesh with only the gossip rung does not carry blobs. The producer and the consumer each
//! bind an endpoint of their own with no custom transport, and the gossip transport lives on
//! the member endpoint alone, so a fetch needs an IP path (or the relay, when the mesh allows
//! it for payload).
//!
//! Raw bytes, not text: unlike a frame body, nothing here is UTF-8-constrained or
//! re-encoded, and the transfer streams in bounded chunks so memory stays flat
//! regardless of size.
//!
//! Producing is path-based — [`BlobServer::register`] stream-hashes a file and
//! snapshots it into a spool dir — so an in-memory payload has to be written to a
//! temp file first. A streaming produce path would have to rework hashing and the
//! `MAX_BLOB_BYTES` check, which cannot run before the length is known.

mod blob_digest;
mod consts;
mod consume;
mod content_id;
mod error;
mod offload_request;
mod online;
mod produce;
mod store;
mod ticket;

pub use blob_digest::BlobDigest;
pub(crate) use consts::{BAD_SECRET, BLOB_ALPN, DONE, RELAY_REFUSED_CODE, UNKNOWN_BLOB};
pub use consts::{HASH_LEN, SECRET_LEN};
pub use consume::{fetch, fetch_hedged, fetch_with_endpoint};
pub use content_id::ContentId;
pub use error::BlobError;
pub use offload_request::{OffloadRequest, offload};
pub(crate) use online::wait_online;
pub use produce::BlobServer;
pub use ticket::BlobTicket;

#[cfg(test)]
mod tests {
    use super::{BlobError, BlobServer, BlobTicket, ContentId, fetch};
    use crate::protocol::meshes::LookupOpts;
    use crate::transport::PayloadPath;
    use rand::RngCore;
    use std::path::PathBuf;
    use std::time::Duration;
    use std::{fs, io};

    use crate::lookup;
    use crate::protocol::crypto;
    use iroh::endpoint::presets;
    use std::collections::HashMap;
    use std::env;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::net::UdpSocket;
    use tokio::time;
    /// A secret that is already in a wiped buffer (the blob salt, the token read off
    /// the wire) moves into its type whole, through the constructor that takes the
    /// buffer, with no plain `[u8; 32]` copy on the way. This does not compile
    /// outside the protocol crate unless that constructor is public.
    #[test]
    fn a_secret_in_a_wiped_buffer_moves_into_its_type_whole() {
        use crate::protocol::crypto::{SymmetricKey, TicketSecret};
        use zeroize::Zeroizing;

        let _guard = ::habilis_network_test_tracing::init();
        let secret = TicketSecret::from(Zeroizing::new([5u8; super::SECRET_LEN]));
        assert_eq!(
            secret.as_bytes(),
            &[5u8; super::SECRET_LEN],
            "a secret moves into its type whole"
        );
        let key = SymmetricKey::from(Zeroizing::new([6u8; 32]));
        assert_eq!(
            key.as_bytes(),
            &[6u8; 32],
            "a key moves into its type whole"
        );
    }

    /// A throwaway file under the OS temp dir holding `bytes`; the caller drops it.
    fn temp_file(bytes: &[u8]) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "habilis-network-blob-src-{}",
            rand::rng().next_u64()
        ));
        fs::write(&path, bytes).expect("write temp file");
        path
    }

    fn temp_spool() -> PathBuf {
        env::temp_dir().join(format!(
            "habilis-network-blob-spool-{}",
            rand::rng().next_u64()
        ))
    }

    /// A tripwire on the source, not a test of the endpoint: `Endpoint::addr` does not list a
    /// custom transport, so nothing here can read what an endpoint holds. The gossip transport
    /// lives on the member endpoint, and `TransportHandles::default()` is what says that an
    /// endpoint gets no handle. The blob server passes it to `build_endpoint`, and the consumer
    /// goes through `build_peer_endpoint`, which passes the same. Neither can hold a gossip
    /// handle, so a blob fetch cannot ride the gossip rung. A change to either call fails here
    /// and asks for a new decision.
    #[test]
    fn a_blob_endpoint_is_built_with_no_custom_transport() {
        let _guard = ::habilis_network_test_tracing::init();
        let defaults = lookup::TransportHandles::default();
        assert!(
            defaults.gossip.is_none() && defaults.webrtc.is_none(),
            "a blob endpoint has no custom transport by default"
        );

        let server = include_str!("produce.rs");
        let start = server
            .find("async fn start_with_limits")
            .expect("the server builder");
        let built = &server[start..];
        let call = &built[built.find("build_endpoint(").expect("the server builds")..];
        let call_args = &call[..call.find(".await?").expect("the call ends")];
        let args: String = call_args.chars().filter(|ch| !ch.is_whitespace()).collect();
        assert!(
            args.ends_with("lookup::TransportHandles::default(),)"),
            "the blob server must pass no transport handle: {args}"
        );

        let consumer = include_str!("consume.rs");
        assert!(
            consumer.contains("build_peer_endpoint(&ticket.lookups)"),
            "the blob consumer must build its endpoint with the peer builder"
        );
        let lookup = include_str!("../lookup/peer.rs");
        let peer = &lookup[lookup
            .find("pub async fn build_peer_endpoint")
            .expect("the peer builder")..];
        assert!(
            peer[..peer.find("\n}").expect("the builder ends")]
                .contains("TransportHandles::default()"),
            "the peer builder must pass no handle"
        );
    }

    /// Start a loopback producer serving `payload`, fetch it back over a second
    /// loopback endpoint, and return the fetched bytes.
    async fn round_trip(payload: &[u8]) -> Vec<u8> {
        let server = BlobServer::start(
            LookupOpts::loopback(),
            temp_spool(),
            None,
            PayloadPath::RelayAllowed,
        )
        .await
        .expect("start producer");
        let src = temp_file(payload);
        let ticket = server
            .register(&src, ContentId::new("blob-test-content"))
            .await
            .expect("register");
        let mut out = Vec::new();
        fetch(&ticket, &mut out, None).await.expect("fetch");
        fs::remove_file(&src).ok();
        server.shutdown().await;
        out
    }

    /// **A caller's long-lived endpoint serves many fetches and stays open.**
    ///
    /// `fetch` binds a cold endpoint and closes it on every call. A caller that
    /// already holds an endpoint passes it to `fetch_with_endpoint`, which must
    /// dial from it and leave it open for the next fetch.
    #[test]
    fn a_caller_endpoint_serves_two_fetches_and_stays_open() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::RelayAllowed,
                )
                .await
                .expect("start producer");
                let endpoint = lookup::build_peer_endpoint(&LookupOpts::loopback())
                    .await
                    .expect("caller endpoint");
                let services = || endpoint.address_lookup().expect("lookup services").len();
                let services_before = services();
                for (name, payload) in [
                    ("blob-test-reuse-a", &b"first bytes"[..]),
                    ("blob-test-reuse-b", &b"second bytes"[..]),
                ] {
                    let src = temp_file(payload);
                    let ticket = server
                        .register(&src, ContentId::new(name))
                        .await
                        .expect("register");
                    let mut out = Vec::new();
                    super::fetch_with_endpoint(&endpoint, &ticket, &mut out, None)
                        .await
                        .expect("fetch from the caller endpoint");
                    assert_eq!(out, payload, "the fetch returns the registered bytes");
                    assert!(
                        !endpoint.is_closed(),
                        "the caller endpoint stays open after a fetch"
                    );
                    fs::remove_file(&src).ok();
                }
                assert_eq!(
                    services(),
                    services_before,
                    "a fetch adds no lookup service to a long-lived endpoint"
                );
                endpoint.close().await;
                server.shutdown().await;
            },
        );
    }

    /// **A caller can watch the address of the blob server and wait for it to be online.**
    ///
    /// The ticket holds the address of the server at the time of `register`. A caller that
    /// keeps the server for a long time needs the address as it changes, and needs to know when
    /// the server has a home relay.
    #[test]
    fn a_blob_server_exposes_its_address_watcher_and_online_wait() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use iroh::Watcher as _;
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::RelayAllowed,
                )
                .await
                .expect("start producer");
                assert_eq!(
                    server.watch_addr().get(),
                    server.address(),
                    "the watcher holds the address that a ticket carries"
                );
                assert!(
                    time::timeout(Duration::from_millis(200), server.online())
                        .await
                        .is_err(),
                    "with the relay disabled there is no home relay, so online never returns"
                );
                server.shutdown().await;
            },
        );
    }

    /// **The address watcher follows the home relay, so a ticket minted earlier goes stale.**
    ///
    /// A ticket holds the address at `register` time. When the home relay of the server goes
    /// away, the endpoint homes on another relay and the watcher shows the new address. The old
    /// ticket still names the dead relay, and a registered blob gets a fresh ticket from
    /// `register` again.
    #[test]
    #[ignore = "45 s: waits for iroh to drop a dead home relay"]
    fn the_address_watcher_follows_the_home_relay_while_an_old_ticket_goes_stale() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::lookup::test_relay::spawn_plain;
                use crate::protocol::meshes::RelayChoice;
                use iroh::Watcher as _;
                // Dropping the home relay is the point of the test, so its probes and its
                // sockets fail on purpose.
                ::habilis_network_test_tracing::allow_warn(
                    "iroh::net_report::reportgen",
                    "probe failed",
                );
                ::habilis_network_test_tracing::allow_warn(
                    "iroh_relay::server::http_server",
                    "error accepting upgraded connection",
                );
                let (url_a, relay_a) = spawn_plain().await.expect("relay a");
                let (url_b, relay_b) = spawn_plain().await.expect("relay b");
                let mut lookups = LookupOpts::loopback();
                lookups.relay_lookup = RelayChoice::Custom(vec![url_a.clone(), url_b.clone()]);
                let server =
                    BlobServer::start(lookups, temp_spool(), None, PayloadPath::RelayAllowed)
                        .await
                        .expect("start producer");
                server.online().await;
                let src = temp_file(b"stale ticket bytes");
                let content_id = ContentId::new("blob-test-stale-ticket");
                let old_ticket = server
                    .register(&src, content_id.clone())
                    .await
                    .expect("register");
                let home: iroh::RelayUrl = old_ticket
                    .address
                    .relay_urls()
                    .next()
                    .cloned()
                    .expect("the first ticket names the home relay");
                let (survivor, survivor_relay, dead_relay) = if home == url_a {
                    (url_b, relay_b, relay_a)
                } else {
                    (url_a, relay_a, relay_b)
                };
                drop(dead_relay);
                let mut watcher = server.watch_addr();
                let moved = time::timeout(Duration::from_secs(120), async {
                    loop {
                        let address = watcher.get();
                        if address.relay_urls().any(|url| url == &survivor) {
                            break address;
                        }
                        watcher.updated().await.expect("the endpoint is alive");
                    }
                })
                .await
                .expect("the watcher shows the surviving relay");
                assert_eq!(
                    old_ticket.address.relay_urls().next(),
                    Some(&home),
                    "the ticket minted before the move still names the dead relay"
                );
                let fresh = server
                    .register(&src, content_id)
                    .await
                    .expect("register again");
                assert_eq!(
                    fresh.address, moved,
                    "register on a spooled blob mints a ticket with the current address"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
                drop(survivor_relay);
            },
        );
    }

    /// A loopback fetch runs on a direct path, so a producer whose mesh keeps
    /// the relay for lookup only (the default) serves it — and the ticket
    /// carries the policy to the consumer.
    #[test]
    fn relay_lookup_only_still_serves_a_direct_fetch() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::DirectOnly,
                )
                .await
                .expect("start producer");
                let src = temp_file(b"direct bytes");
                let ticket = server
                    .register(&src, ContentId::new("blob-test-direct"))
                    .await
                    .expect("register");
                assert_eq!(
                    ticket.relay_transport,
                    PayloadPath::DirectOnly,
                    "a relay lookup-only ticket keeps the direct payload path"
                );
                let decoded = BlobTicket::decode(&ticket.encode()).expect("ticket round-trips");
                assert_eq!(
                    decoded.relay_transport,
                    PayloadPath::DirectOnly,
                    "the decoded ticket keeps the direct payload path"
                );
                let mut out = Vec::new();
                fetch(&decoded, &mut out, None)
                    .await
                    .expect("fetch over a direct path");
                assert_eq!(
                    out, b"direct bytes",
                    "the direct fetch still returns the bytes"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A peer that connects and goes quiet must not accumulate serve tasks.**
    ///
    /// Everything before the bearer-secret check runs on the requester's
    /// schedule: the handshake, opening a stream, and sending the 64-byte
    /// request. Authentication cannot come earlier, because the secret is
    /// inside the request being awaited. So a connection that never sends parks
    /// a task, and nothing bounded how many could park at once or freed the
    /// ones that had.
    #[test]
    fn a_peer_that_never_sends_does_not_pin_serve_tasks() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use super::produce::ServeLimits;

                let limits = ServeLimits {
                    pre_auth: Duration::from_millis(300),
                    max_inflight: 4,
                };
                let server = BlobServer::start_with_limits(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::RelayAllowed,
                    limits,
                )
                .await
                .expect("start producer");

                // Connect and then do nothing at all — never open a stream, never send.
                let mut clients = Vec::new();
                let mut idle = Vec::new();
                for _ in 0..12u8 {
                    let client = iroh::Endpoint::builder(presets::Minimal)
                        .relay_mode(iroh::RelayMode::Disabled)
                        .bind()
                        .await
                        .expect("bind client");
                    if let Ok(connection) = client.connect(server.address(), super::BLOB_ALPN).await
                    {
                        idle.push(connection);
                    }
                    clients.push(client);
                }
                time::sleep(Duration::from_millis(100)).await;
                assert!(
                    server.inflight() <= limits.max_inflight,
                    "{} serves in flight, over the {} ceiling",
                    server.inflight(),
                    limits.max_inflight
                );

                // Past the deadline they must be gone, or the ceiling above is just a
                // slower way to run out.
                time::sleep(limits.pre_auth + Duration::from_millis(400)).await;
                assert_eq!(
                    server.inflight(),
                    0,
                    "a silent peer still holds serve tasks after the pre-auth deadline"
                );

                for connection in idle {
                    connection.close(0u32.into(), b"done");
                }
                for client in clients {
                    client.close().await;
                }
                server.shutdown().await;
            },
        );
    }

    #[test]
    fn round_trips_a_blob_byte_for_byte() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let payload = vec![7u8; 200_000];
                assert_eq!(
                    round_trip(&payload).await,
                    payload,
                    "a blob round trips byte for byte"
                );
            },
        );
    }

    #[test]
    fn round_trips_an_empty_blob() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                assert_eq!(
                    round_trip(b"").await,
                    b"",
                    "an empty blob round trips to empty bytes"
                );
            },
        );
    }

    /// The whole produce → reference → consume path through the **public** surface
    /// only: [`offload`] mints a ticket, `encode`/`decode` round-trips it as the
    /// string an application would ship over gossip, and [`fetch`] streams the
    /// bytes back. Nothing here names an application type, which is the point —
    /// this is the shape any consumer writes, whatever its data model.
    #[test]
    fn offload_to_fetch_needs_no_application_type() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let payload: Vec<u8> = (0..40_000_u32).map(|byte| byte.to_le_bytes()[0]).collect();
                let src = temp_file(&payload);
                let mut server: Option<BlobServer> = None;

                let ticket = super::offload(
                    &mut server,
                    &LookupOpts::loopback(),
                    PayloadPath::RelayAllowed,
                    super::OffloadRequest {
                        path: src.clone(),
                        spool_dir: temp_spool(),
                        content_id: ContentId::new("generic-consumer-group"),
                        password: None,
                    },
                )
                .await
                .expect("offload");

                // Raw bytes, so no base64/UTF-8 detour: the payload cycles 0..=255,
                // which a frame body would reject outright.
                let wire = ticket.encode();
                let decoded = BlobTicket::decode(&wire).expect("ticket round-trips as a string");

                let mut out = Vec::new();
                fetch(&decoded, &mut out, None).await.expect("fetch");
                assert_eq!(out, payload, "bytes must survive byte-for-byte");

                // Content-addressed dedup: the same bytes offload to the same ticket
                // without re-hashing.
                let again = super::offload(
                    &mut server,
                    &LookupOpts::loopback(),
                    PayloadPath::RelayAllowed,
                    super::OffloadRequest {
                        path: src.clone(),
                        spool_dir: temp_spool(),
                        content_id: ContentId::new("generic-consumer-group"),
                        password: None,
                    },
                )
                .await
                .expect("second offload");
                assert_eq!(
                    again.sha256_hex(),
                    ticket.sha256_hex(),
                    "offloading to fetch needs no application type and keeps the digest"
                );

                fs::remove_file(&src).ok();
                if let Some(server) = server {
                    server.shutdown().await;
                }
            },
        );
    }

    #[test]
    fn passworded_blob_requires_the_password() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use crate::protocol::crypto::Password;
                let password = Password::new("hunter2".to_owned());
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    Some(password.clone()),
                    PayloadPath::RelayAllowed,
                )
                .await
                .expect("the loopback blob server starts");
                let src = temp_file(b"secret bytes");
                let ticket = server
                    .register(&src, ContentId::new("blob-test-content"))
                    .await
                    .expect("the password-protected blob registers");
                assert!(ticket.password, "the ticket must be password-protected");

                // Missing password and a wrong password are both refused.
                let mut out = Vec::new();
                assert!(
                    fetch(&ticket, &mut out, None).await.is_err(),
                    "a passworded ticket must not redeem without the password"
                );
                out.clear();
                assert!(
                    fetch(&ticket, &mut out, Some(Password::new("wrong".to_owned())))
                        .await
                        .is_err(),
                    "a wrong password must be refused"
                );
                // The mesh password fetches byte-for-byte.
                out.clear();
                fetch(&ticket, &mut out, Some(password))
                    .await
                    .expect("fetch");
                assert_eq!(
                    out, b"secret bytes",
                    "a passworded blob returns its bytes with the password"
                );

                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// The same bytes offloaded under two groups share one spool file, so
    /// evicting one group must leave the other's ticket redeemable.
    #[test]
    fn evicting_one_group_keeps_a_shared_blob_for_the_other() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::RelayAllowed,
                )
                .await
                .expect("the loopback blob server starts");
                let src = temp_file(b"shared bytes");
                let group_a = ContentId::new("blob-test-group-a");
                let group_b = ContentId::new("blob-test-group-b");
                server
                    .register(&src, group_a.clone())
                    .await
                    .expect("the first group registers the file");
                let ticket_b = server
                    .register(&src, group_b.clone())
                    .await
                    .expect("the second group registers the same file");

                server.evict_content(&group_a).await;
                let mut out = Vec::new();
                fetch(&ticket_b, &mut out, None)
                    .await
                    .expect("group B still holds the blob");
                assert_eq!(
                    out, b"shared bytes",
                    "evicting one group keeps the shared blob for the other group"
                );

                server.evict_content(&group_b).await;
                out.clear();
                assert!(
                    fetch(&ticket_b, &mut out, None).await.is_err(),
                    "the blob goes once its last group is evicted"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    #[test]
    fn a_bad_secret_is_refused() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::RelayAllowed,
                )
                .await
                .expect("the loopback blob server starts");
                let src = temp_file(b"secret payload");
                let mut ticket = server
                    .register(&src, ContentId::new("blob-test-content"))
                    .await
                    .expect("the secret blob registers");
                ticket.secret = crypto::TicketSecret::from([0u8; super::SECRET_LEN]);
                let mut out = Vec::new();
                assert!(
                    fetch(&ticket, &mut out, None).await.is_err(),
                    "a wrong secret must be refused"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    #[test]
    fn an_unknown_hash_is_refused() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::RelayAllowed,
                )
                .await
                .expect("the loopback blob server starts");
                let src = temp_file(b"real content");
                let mut ticket = server
                    .register(&src, ContentId::new("blob-test-content"))
                    .await
                    .expect("the blob registers");
                ticket.sha256 = super::BlobDigest::from([0xabu8; super::HASH_LEN]);
                let mut out = Vec::new();
                assert!(
                    fetch(&ticket, &mut out, None).await.is_err(),
                    "an unknown hash must be refused"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    #[test]
    fn a_size_disagreement_is_rejected() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::RelayAllowed,
                )
                .await
                .expect("the loopback blob server starts");
                let src = temp_file(b"exactly this many bytes");
                let mut ticket = server
                    .register(&src, ContentId::new("blob-test-content"))
                    .await
                    .expect("the blob registers");
                ticket.size += 1; // producer will offer the true size, which won't match
                let mut out = Vec::new();
                assert!(
                    fetch(&ticket, &mut out, None).await.is_err(),
                    "a size disagreement must be rejected"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// A UDP relay on loopback between a consumer and `upstream`. With `drop_first_socket` it drops
    /// every datagram of the first socket that talks to it, both ways, and forwards every later
    /// socket: a path where the handshake of one consumer endpoint never completes while a new
    /// endpoint gets through. `delay` holds each datagram for that long in each direction.
    async fn lossy_proxy(
        upstream: SocketAddr,
        drop_first_socket: bool,
        delay: Duration,
    ) -> SocketAddr {
        let front = UdpSocket::bind("127.0.0.1:0").await.expect("bind proxy");
        let address = front.local_addr().expect("proxy address");
        // The reply tasks send through the front socket, so they share it with the loop.
        let front = Arc::new(front);
        tokio::spawn(async move {
            let mut dropped = None;
            // One socket per client, shared by its reply task and the loop.
            let mut routes: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buffer = vec![0u8; 2048];
            loop {
                let Ok((read, client)) = front.recv_from(&mut buffer).await else {
                    return;
                };
                if drop_first_socket && *dropped.get_or_insert(client) == client {
                    continue;
                }
                let route = if let Some(route) = routes.get(&client) {
                    Arc::clone(route)
                } else {
                    let route = UdpSocket::bind("127.0.0.1:0").await.expect("bind route");
                    route.connect(upstream).await.expect("connect route");
                    // One socket per client, read by a task and written by this loop.
                    let route = Arc::new(route);
                    let (reply, front) = (Arc::clone(&route), Arc::clone(&front));
                    tokio::spawn(async move {
                        let mut reply_buffer = vec![0u8; 2048];
                        while let Ok(replied) = reply.recv(&mut reply_buffer).await {
                            let datagram = reply_buffer[..replied].to_vec();
                            let front = Arc::clone(&front);
                            tokio::spawn(async move {
                                time::sleep(delay).await;
                                let _ = front.send_to(&datagram, client).await;
                            });
                        }
                    });
                    routes.insert(client, Arc::clone(&route));
                    route
                };
                let datagram = buffer[..read].to_vec();
                tokio::spawn(async move {
                    time::sleep(delay).await;
                    let _ = route.send(&datagram).await;
                });
            }
        });
        address
    }

    /// **A handshake that stalls is retried on a new endpoint, not waited out.**
    ///
    /// On a LAN with two interfaces, the reply flight of the producer to one consumer endpoint is
    /// sometimes lost for good, and every retry from the same endpoint is lost as well. The dial
    /// waited 30 s for each attempt on that one endpoint. Here the first socket of the consumer
    /// gets no reply at all. The fetch must give up that attempt after a few seconds, bind a new
    /// endpoint, and complete through it.
    #[test]
    fn a_stalled_handshake_is_retried_on_a_new_endpoint() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::DirectOnly,
                )
                .await
                .expect("start producer");
                let src = temp_file(b"bytes behind a stalled path");
                let mut ticket = server
                    .register(&src, ContentId::new("blob-test-stalled-handshake"))
                    .await
                    .expect("register");
                let upstream = only_ip_address(&ticket.address);
                let proxy = lossy_proxy(upstream, true, Duration::ZERO).await;
                ticket.address = iroh::EndpointAddr::new(ticket.address.id).with_ip_addr(proxy);
                let mut out = Vec::new();
                let fetched =
                    time::timeout(Duration::from_secs(20), fetch(&ticket, &mut out, None)).await;
                assert!(
                    matches!(fetched, Ok(Ok(()))),
                    "the fetch completes through a new endpoint within 20 s: {fetched:?}"
                );
                assert_eq!(
                    out, b"bytes behind a stalled path",
                    "the fetch returns the registered bytes"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A fetch that the caller drops closes the endpoint that it bound.**
    ///
    /// `Endpoint::close` is async, so a dropped future cannot await it. A caller that cancels a
    /// fetch (a deadline, a superseded attempt) must not leave the endpoint open: the task that
    /// follows its home relay holds a clone of it for the life of the process.
    #[test]
    fn a_dropped_fetch_closes_its_endpoint() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::DirectOnly,
                )
                .await
                .expect("start producer");
                let src = temp_file(b"bytes that are never fetched");
                let mut ticket = server
                    .register(&src, ContentId::new("blob-test-dropped-fetch"))
                    .await
                    .expect("register");
                let upstream = only_ip_address(&ticket.address);
                let proxy = lossy_proxy(upstream, true, Duration::ZERO).await;
                ticket.address = iroh::EndpointAddr::new(ticket.address.id).with_ip_addr(proxy);
                // The test keeps a clone of each endpoint that the fetch binds.
                let bound = Bound::default();
                let build = || bound.build_anyhow();
                let mut out = Vec::new();
                let cancelled = time::timeout(
                    Duration::from_secs(1),
                    super::consume::fetch_building(
                        &ticket,
                        &mut out,
                        &ticket.secret,
                        &[Duration::from_secs(5); 3],
                        None,
                        build,
                    ),
                )
                .await;
                assert!(
                    cancelled.is_err(),
                    "the fetch still waits for the handshake when the caller drops it"
                );
                let endpoint = bound.first();
                for _ in 0..30 {
                    if endpoint.is_closed() {
                        break;
                    }
                    time::sleep(Duration::from_millis(100)).await;
                }
                assert!(
                    endpoint.is_closed(),
                    "the endpoint that a dropped fetch bound is closed within 3 s"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A slow handshake gets a longer attempt, not the same short one again.**
    ///
    /// A new endpoint is online about 3 s after it binds, and a lossy or distant link needs more
    /// than 5 s for a handshake. Here every datagram takes 400 ms in each direction, so the
    /// handshake needs about 0.8 s. The first attempt (500 ms) must give up, and a later attempt
    /// must wait long enough. A fixed cap of 500 ms never completes.
    #[test]
    fn a_slow_handshake_gets_a_longer_attempt() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::DirectOnly,
                )
                .await
                .expect("start producer");
                let src = temp_file(b"bytes behind a slow path");
                let mut ticket = server
                    .register(&src, ContentId::new("blob-test-slow-handshake"))
                    .await
                    .expect("register");
                let upstream = only_ip_address(&ticket.address);
                let proxy = lossy_proxy(upstream, false, Duration::from_millis(400)).await;
                ticket.address = iroh::EndpointAddr::new(ticket.address.id).with_ip_addr(proxy);
                let caps = [
                    Duration::from_millis(500),
                    Duration::from_millis(1500),
                    Duration::from_secs(3),
                ];
                let build = fresh_endpoint;
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(30),
                    super::consume::fetch_building(
                        &ticket,
                        &mut out,
                        &ticket.secret,
                        &caps,
                        None,
                        build,
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Ok(()))),
                    "the fetch completes on a later, longer attempt within 30 s: {fetched:?}"
                );
                assert_eq!(
                    out, b"bytes behind a slow path",
                    "the fetch returns the registered bytes"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A caller endpoint that stalls on every attempt gets a typed error.**
    ///
    /// A retry from an endpoint that the producer cannot answer stalls again, and the caller owns
    /// the endpoint, so only the caller can build a new one. `fetch_with_endpoint` must stop after
    /// the attempts of its caps and return `BlobError::HandshakeStalled`, and leave the endpoint
    /// open for the caller to close.
    #[test]
    fn a_stalled_caller_endpoint_gets_a_handshake_stalled_error() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::DirectOnly,
                )
                .await
                .expect("start producer");
                let src = temp_file(b"bytes behind a dead path");
                let mut ticket = server
                    .register(&src, ContentId::new("blob-test-stalled-caller"))
                    .await
                    .expect("register");
                let upstream = only_ip_address(&ticket.address);
                let proxy = lossy_proxy(upstream, true, Duration::ZERO).await;
                ticket.address = iroh::EndpointAddr::new(ticket.address.id).with_ip_addr(proxy);
                let endpoint = lookup::build_peer_endpoint(&LookupOpts::loopback())
                    .await
                    .expect("caller endpoint");
                let caps = [
                    Duration::from_millis(200),
                    Duration::from_millis(300),
                    Duration::from_millis(400),
                ];
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(10),
                    super::consume::fetch_with_endpoint_caps(
                        &endpoint, &ticket, &mut out, None, &caps,
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Err(BlobError::HandshakeStalled))),
                    "every attempt stalls, so the fetch returns HandshakeStalled within 10 s: {fetched:?}"
                );
                assert!(
                    !endpoint.is_closed(),
                    "the caller endpoint stays open for the caller to close"
                );
                endpoint.close().await;
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// Builds loopback peer endpoints and keeps a clone of each, so that a test sees what a fetch
    /// binds.
    #[derive(Clone, Default)]
    struct Bound(Arc<Mutex<Vec<iroh::Endpoint>>>); // clones share the list of one test

    impl Bound {
        async fn build(&self) -> Result<iroh::Endpoint, lookup::EndpointError> {
            let endpoint = lookup::build_peer_endpoint(&LookupOpts::loopback()).await?;
            self.0.lock().expect("lock").push(endpoint.clone());
            Ok(endpoint)
        }

        /// The same build, with the error of an `anyhow` builder.
        async fn build_anyhow(&self) -> Result<iroh::Endpoint, anyhow::Error> {
            Ok(self.build().await?)
        }

        /// The first endpoint that was built.
        fn first(&self) -> iroh::Endpoint {
            self.0.lock().expect("lock")[0].clone()
        }

        fn count(&self) -> usize {
            self.0.lock().expect("lock").len()
        }

        /// Whether every endpoint built so far is closed within 6 s. A close that waits for a dial
        /// with no reply takes about 3 s.
        async fn all_closed(&self) -> bool {
            for _ in 0..60 {
                let open: usize = {
                    let endpoints = self.0.lock().expect("lock");
                    endpoints
                        .iter()
                        .filter(|endpoint| !endpoint.is_closed())
                        .count()
                };
                if open == 0 {
                    return true;
                }
                time::sleep(Duration::from_millis(100)).await;
            }
            false
        }
    }

    /// The one IP address of a loopback ticket.
    fn only_ip_address(address: &iroh::EndpointAddr) -> SocketAddr {
        let first: Option<SocketAddr> = address.ip_addrs().next().copied();
        first.expect("a loopback ticket carries one IP address")
    }

    /// A builder of a loopback peer endpoint, for a fetch that binds its own.
    async fn fresh_endpoint() -> Result<iroh::Endpoint, anyhow::Error> {
        Ok(lookup::build_peer_endpoint(&LookupOpts::loopback()).await?)
    }

    /// A builder that fails, with the error of a custom builder.
    fn build_error(text: &str) -> Result<iroh::Endpoint, io::Error> {
        Err(io::Error::other(text.to_owned()))
    }

    /// A builder whose endpoint is closed when it returns.
    async fn build_closed(bound: &Bound) -> Result<iroh::Endpoint, lookup::EndpointError> {
        let closed = bound.build().await?;
        closed.close().await;
        Ok(closed)
    }

    /// A producer behind `lossy_proxy`, and a ticket that dials the proxy.
    async fn ticket_behind_proxy(
        content: &str,
        bytes: &[u8],
        drop_first_socket: bool,
        delay: Duration,
    ) -> (BlobServer, BlobTicket, PathBuf) {
        let server = BlobServer::start(
            LookupOpts::loopback(),
            temp_spool(),
            None,
            PayloadPath::DirectOnly,
        )
        .await
        .expect("start producer");
        let src = temp_file(bytes);
        let mut ticket = server
            .register(&src, ContentId::new(content))
            .await
            .expect("register");
        let upstream = only_ip_address(&ticket.address);
        let proxy = lossy_proxy(upstream, drop_first_socket, delay).await;
        ticket.address = iroh::EndpointAddr::new(ticket.address.id).with_ip_addr(proxy);
        (server, ticket, src)
    }

    /// **A dial that gets no reply is hedged from a new endpoint at once, not after its cap.**
    ///
    /// The reply flight of the producer to one consumer socket is lost for 30 s or more, while a
    /// new socket gets through at once. Here the first socket gets no reply, and every attempt may
    /// wait 30 s. The fetch must start a second dial from a new endpoint after the hedge delay and
    /// complete through it, and it must close both endpoints.
    #[test]
    fn a_stalled_first_dial_is_hedged_from_a_new_endpoint() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, ticket, src) = ticket_behind_proxy(
                    "blob-test-hedged-dial",
                    b"bytes behind a stalled flow",
                    true,
                    Duration::ZERO,
                )
                .await;
                let bound = Bound::default();
                let build = || bound.build_anyhow();
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(15),
                    super::consume::fetch_building(
                        &ticket,
                        &mut out,
                        &ticket.secret,
                        &[Duration::from_secs(30); 3],
                        Some(Duration::from_millis(300)),
                        build,
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Ok(()))),
                    "the fetch completes through the hedge within 15 s, long before the 30 s cap: {fetched:?}"
                );
                assert_eq!(
                    out, b"bytes behind a stalled flow",
                    "the fetch returns the registered bytes"
                );
                assert_eq!(
                    bound.count(),
                    2,
                    "the first attempt binds one endpoint and the hedge binds one"
                );
                assert!(
                    bound.all_closed().await,
                    "both endpoints are closed within 6 s"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A handshake that completes in time starts no hedge.**
    ///
    /// The hedge costs nothing in the good case: a second endpoint is bound only for a dial that
    /// has no reply after the hedge delay.
    #[test]
    fn a_fast_handshake_starts_no_hedge() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, ticket, src) = ticket_behind_proxy(
                    "blob-test-no-hedge",
                    b"bytes behind a good path",
                    false,
                    Duration::ZERO,
                )
                .await;
                let bound = Bound::default();
                let build = || bound.build_anyhow();
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(15),
                    super::consume::fetch_building(
                        &ticket,
                        &mut out,
                        &ticket.secret,
                        &[Duration::from_secs(30); 3],
                        Some(Duration::from_secs(5)),
                        build,
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Ok(()))),
                    "the fetch completes within 15 s: {fetched:?}"
                );
                assert_eq!(
                    bound.count(),
                    1,
                    "a handshake that completes before the hedge delay binds no second endpoint"
                );
                assert!(
                    bound.all_closed().await,
                    "the endpoint is closed within 6 s"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A caller endpoint that stalls is hedged from a new endpoint, and stays open.**
    ///
    /// `fetch_hedged` dials first from the endpoint of the caller. When that dial has no reply
    /// after the hedge delay, it binds one more endpoint with the builder of the caller and dials
    /// from it. The fetch completes, the hedge endpoint is closed, and the caller endpoint is not.
    #[test]
    fn a_stalled_caller_endpoint_is_hedged_and_stays_open() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, ticket, src) = ticket_behind_proxy(
                    "blob-test-hedged-caller",
                    b"bytes behind a stalled caller",
                    true,
                    Duration::ZERO,
                )
                .await;
                let caller = lookup::build_peer_endpoint(&LookupOpts::loopback())
                    .await
                    .expect("caller endpoint");
                let bound = Bound::default();
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(15),
                    super::consume::fetch_hedged_caps(
                        &caller,
                        || bound.build(),
                        &ticket,
                        &mut out,
                        None,
                        &[Duration::from_secs(30); 3],
                        Some(Duration::from_millis(300)),
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Ok(()))),
                    "the fetch completes through the hedge within 15 s: {fetched:?}"
                );
                assert_eq!(
                    out, b"bytes behind a stalled caller",
                    "the fetch returns the registered bytes"
                );
                assert_eq!(bound.count(), 1, "the hedge binds one endpoint");
                assert!(
                    bound.all_closed().await,
                    "the hedge endpoint is closed within 6 s"
                );
                assert!(
                    !caller.is_closed(),
                    "the caller endpoint stays open for the caller to close"
                );
                caller.close().await;
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A hedge that loses closes its endpoint.**
    ///
    /// Every datagram takes 600 ms in each direction, so the handshake needs more than the hedge
    /// delay and the hedge starts. The first dial began earlier and wins. The endpoint of the hedge
    /// has no connection to carry, so it must close, and no connection is left half open.
    #[test]
    fn a_hedge_that_loses_closes_its_endpoint() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let server = BlobServer::start(
                    LookupOpts::loopback(),
                    temp_spool(),
                    None,
                    PayloadPath::DirectOnly,
                )
                .await
                .expect("start producer");
                let src = temp_file(b"bytes behind a slow flow");
                let mut ticket = server
                    .register(&src, ContentId::new("blob-test-losing-hedge"))
                    .await
                    .expect("register");
                let upstream = only_ip_address(&ticket.address);
                let proxy = lossy_proxy(upstream, false, Duration::from_millis(600)).await;
                ticket.address = iroh::EndpointAddr::new(ticket.address.id).with_ip_addr(proxy);
                let bound = Bound::default();
                let build = || bound.build_anyhow();
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(30),
                    super::consume::fetch_building(
                        &ticket,
                        &mut out,
                        &ticket.secret,
                        &[Duration::from_secs(20); 3],
                        Some(Duration::from_millis(300)),
                        build,
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Ok(()))),
                    "the fetch completes within 30 s: {fetched:?}"
                );
                assert_eq!(
                    bound.count(),
                    2,
                    "the handshake is slower than the hedge delay, so the hedge binds an endpoint"
                );
                assert!(
                    bound.all_closed().await,
                    "both endpoints are closed within 6 s, the loser too"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A hedge whose endpoint is slow to build does not hold the dial past its cap.**
    ///
    /// The builder of the second endpoint can be slow: a ladder walk with every relay down takes
    /// 10 s for each rung. The cap of the attempt still applies while it builds.
    #[test]
    fn a_slow_hedge_build_keeps_the_cap() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, ticket, src) = ticket_behind_proxy(
                    "blob-test-slow-hedge-build",
                    b"bytes behind a stalled flow",
                    true,
                    Duration::ZERO,
                )
                .await;
                let caller = lookup::build_peer_endpoint(&LookupOpts::loopback())
                    .await
                    .expect("caller endpoint");
                // The first endpoint of the caller stalls, and the builder never returns.
                let build = || async {
                    time::sleep(Duration::from_secs(3600)).await;
                    build_error("never built")
                };
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(10),
                    super::consume::fetch_hedged_caps(
                        &caller,
                        build,
                        &ticket,
                        &mut out,
                        None,
                        &[Duration::from_secs(1); 3],
                        Some(Duration::from_millis(300)),
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Err(BlobError::HandshakeStalled))),
                    "every attempt ends at its 1 s cap, so the fetch returns HandshakeStalled within 10 s: {fetched:?}"
                );
                caller.close().await;
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A hedge that cannot be built leaves the first dial alone.**
    ///
    /// Every datagram takes 600 ms in each direction, so the handshake needs more than the hedge
    /// delay but completes. A builder that fails at once must not end the attempt: the first dial
    /// keeps waiting for its handshake until its cap.
    #[test]
    fn a_failed_hedge_build_keeps_the_first_dial() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, ticket, src) = ticket_behind_proxy(
                    "blob-test-failed-hedge-build",
                    b"bytes behind a slow flow",
                    false,
                    Duration::from_millis(600),
                )
                .await;
                let caller = lookup::build_peer_endpoint(&LookupOpts::loopback())
                    .await
                    .expect("caller endpoint");
                let build = || async { build_error("cannot build") };
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(30),
                    super::consume::fetch_hedged_caps(
                        &caller,
                        build,
                        &ticket,
                        &mut out,
                        None,
                        &[Duration::from_secs(20); 3],
                        Some(Duration::from_millis(300)),
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Ok(()))),
                    "the first dial completes although the hedge cannot be built: {fetched:?}"
                );
                assert_eq!(
                    out, b"bytes behind a slow flow",
                    "the fetch returns the registered bytes"
                );
                caller.close().await;
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A first dial that fails leaves the hedge its chance.**
    ///
    /// The first dial gets no reply, and its endpoint is closed after the hedge started, so the dial
    /// fails. The hedge needs more time than that, because each datagram takes 500 ms. The fresh
    /// socket of the hedge is the point of the hedge: the fetch completes through it, and does not
    /// return the error of the old endpoint.
    #[test]
    fn a_first_dial_that_fails_leaves_the_hedge_its_chance() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, ticket, src) = ticket_behind_proxy(
                    "blob-test-failed-first-dial",
                    b"bytes behind a failed dial",
                    true,
                    Duration::from_millis(500),
                )
                .await;
                let caller = lookup::build_peer_endpoint(&LookupOpts::loopback())
                    .await
                    .expect("caller endpoint");
                let closing = caller.clone();
                let closer = tokio::spawn(async move {
                    time::sleep(Duration::from_millis(800)).await;
                    closing.close().await;
                });
                let bound = Bound::default();
                let mut out = Vec::new();
                let fetched = time::timeout(
                    Duration::from_secs(15),
                    super::consume::fetch_hedged_caps(
                        &caller,
                        || bound.build(),
                        &ticket,
                        &mut out,
                        None,
                        &[Duration::from_secs(30); 3],
                        Some(Duration::from_millis(300)),
                    ),
                )
                .await;
                assert!(
                    matches!(fetched, Ok(Ok(()))),
                    "the fetch completes through the hedge after the first dial fails: {fetched:?}"
                );
                assert_eq!(
                    out, b"bytes behind a failed dial",
                    "the fetch returns the registered bytes"
                );
                closer.await.expect("the caller endpoint closes");
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A first dial that fails and a hedge that stays silent is a stall.**
    ///
    /// Neither dial got a handshake by the cap, so the caller must retire its endpoint, as it
    /// does for any stall. The error of the first dial is not what the caller acts on. This calls
    /// one attempt: a second attempt on the closed endpoint would fail at once for another reason.
    #[test]
    fn a_failed_first_dial_and_a_silent_hedge_is_a_stall() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, mut ticket, src) = ticket_behind_proxy(
                    "blob-test-failed-first-silent-hedge",
                    b"bytes never fetched",
                    false,
                    Duration::ZERO,
                )
                .await;
                // A socket that nobody reads: no reply ever comes, on any endpoint.
                let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind silent");
                ticket.address = iroh::EndpointAddr::new(ticket.address.id)
                    .with_ip_addr(silent.local_addr().expect("silent address"));
                let caller = lookup::build_peer_endpoint(&LookupOpts::loopback())
                    .await
                    .expect("caller endpoint");
                let closing = caller.clone();
                let closer = tokio::spawn(async move {
                    time::sleep(Duration::from_millis(800)).await;
                    closing.close().await;
                });
                let bound = Bound::default();
                let attempt = time::timeout(
                    Duration::from_secs(10),
                    super::consume::dial_once(
                        &caller,
                        &ticket,
                        Duration::from_secs(2),
                        Some(Duration::from_millis(300)),
                        &|| async { Ok(bound.build().await?) },
                    ),
                )
                .await;
                let error = attempt
                    .expect("the attempt ends at its cap")
                    .err()
                    .expect("no dial connects");
                assert!(
                    error.to_string().starts_with("no handshake within"),
                    "the first dial fails at 800 ms and the hedge gets no reply, so the attempt is a stall: {error}"
                );
                closer.await.expect("the caller endpoint closes");
                assert!(
                    bound.all_closed().await,
                    "every hedge endpoint is closed within 6 s"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// **A hedge whose dial fails leaves the first dial waiting.**
    ///
    /// The hedge endpoint has no transport, so its dial fails at once. Every datagram takes
    /// 600 ms in each direction, so the first dial needs more than the hedge delay and still
    /// completes. The failed hedge must not end the attempt.
    #[test]
    fn a_failed_hedge_dial_leaves_the_first_dial_waiting() {
        let guard = ::habilis_network_test_tracing::init();
        // The hedge endpoint is closed, and the address book of a closed endpoint says so.
        guard.allow_warn("habilis_network::lookup", "no lookup services");
        ::habilis_network_test_tracing::run_multi_thread(guard, 2, async {
            let (server, ticket, src) = ticket_behind_proxy(
                "blob-test-failed-hedge-dial",
                b"bytes behind a slow flow",
                false,
                Duration::from_millis(600),
            )
            .await;
            let caller = lookup::build_peer_endpoint(&LookupOpts::loopback())
                .await
                .expect("caller endpoint");
            let bound = Bound::default();
            let build = || build_closed(&bound);
            let mut out = Vec::new();
            let fetched = time::timeout(
                Duration::from_secs(30),
                super::consume::fetch_hedged_caps(
                    &caller,
                    build,
                    &ticket,
                    &mut out,
                    None,
                    &[Duration::from_secs(20); 3],
                    Some(Duration::from_millis(300)),
                ),
            )
            .await;
            assert!(
                matches!(fetched, Ok(Ok(()))),
                "the first dial completes although the hedge dial fails: {fetched:?}"
            );
            assert_eq!(
                out, b"bytes behind a slow flow",
                "the fetch returns the registered bytes"
            );
            assert_eq!(bound.count(), 1, "the hedge bound one endpoint");
            caller.close().await;
            fs::remove_file(&src).ok();
            server.shutdown().await;
        });
    }

    /// **A hedged fetch that the caller drops closes both endpoints.**
    ///
    /// Both dials get no reply (a socket that nobody reads), and the caller gives up while they
    /// wait. The endpoint of the first attempt and the endpoint of the hedge must both close.
    #[test]
    fn a_dropped_hedged_fetch_closes_both_endpoints() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let (server, mut ticket, src) = ticket_behind_proxy(
                    "blob-test-dropped-hedge",
                    b"bytes never fetched",
                    false,
                    Duration::ZERO,
                )
                .await;
                // A socket that nobody reads: no reply ever comes.
                let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind silent");
                ticket.address = iroh::EndpointAddr::new(ticket.address.id)
                    .with_ip_addr(silent.local_addr().expect("silent address"));
                let bound = Bound::default();
                let build = || bound.build_anyhow();
                let mut out = Vec::new();
                let cancelled = time::timeout(
                    Duration::from_millis(2500),
                    super::consume::fetch_building(
                        &ticket,
                        &mut out,
                        &ticket.secret,
                        &[Duration::from_secs(30); 3],
                        Some(Duration::from_millis(300)),
                        build,
                    ),
                )
                .await;
                assert!(
                    cancelled.is_err(),
                    "the fetch still waits when the caller drops it"
                );
                assert_eq!(
                    bound.count(),
                    2,
                    "the first attempt and the hedge each bound an endpoint"
                );
                assert!(
                    bound.all_closed().await,
                    "both endpoints are closed within 6 s of the drop"
                );
                fs::remove_file(&src).ok();
                server.shutdown().await;
            },
        );
    }

    /// The caps of the dial attempts grow, and the last one repeats. The tests above pass their own
    /// caps, so this pins the real ones.
    #[test]
    fn the_dial_caps_grow_and_the_last_one_repeats() {
        let caps: Vec<u64> = (0..5)
            .map(|attempt| super::consume::cap_of(&super::consume::DIAL_CAPS, attempt).as_secs())
            .collect();
        assert_eq!(
            caps,
            [5, 10, 20, 20, 20],
            "the caps of the first 5 attempts, in seconds"
        );
    }
}
