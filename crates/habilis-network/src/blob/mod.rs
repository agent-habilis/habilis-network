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
pub use consume::fetch;
pub use content_id::ContentId;
pub use error::BlobError;
pub use offload_request::{OffloadRequest, offload};
pub(crate) use online::wait_online;
pub use produce::BlobServer;
pub use ticket::BlobTicket;

#[cfg(test)]
mod tests {
    use super::{BlobServer, ContentId, fetch};
    use crate::protocol::meshes::LookupOpts;
    use crate::transport::PayloadPath;
    use rand::RngCore;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::lookup;
    use crate::protocol::crypto;
    use iroh::endpoint::presets;
    use std::env;
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
                let decoded =
                    super::BlobTicket::decode(&ticket.encode()).expect("ticket round-trips");
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
                let decoded =
                    super::BlobTicket::decode(&wire).expect("ticket round-trips as a string");

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
}
