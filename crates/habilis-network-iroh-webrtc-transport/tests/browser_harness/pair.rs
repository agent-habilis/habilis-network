use super::{BENCH_ALPN, Bench, Direction, browser_endpoint, exchange, js_error, on_webrtc};
use habilis_network_iroh_webrtc_transport::iroh::protocol::Router;
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr,
};
use habilis_network_iroh_webrtc_transport::{
    BrowserHubTransport, IceServers, WebRtcHandle, browser_answer, browser_offer, custom_addr,
};
use n0_future::{future, time};
use std::sync::Arc;
use std::time::Duration;

/// A negotiated browser↔browser pair, both ends live in this tab.
#[derive(Debug, Clone)]
pub(crate) struct Pair {
    client: Endpoint,
    server_addr: EndpointAddr,
    // both ends of the harness share the hub with the test
    pub(crate) client_hub: Arc<BrowserHubTransport>,
    pub(crate) server_id: EndpointId,
    router: Router,
}

impl Pair {
    /// Stand up both endpoints, negotiate one data channel between them, and
    /// leave the server accepting [`BENCH_ALPN`].
    pub(crate) async fn negotiate() -> anyhow::Result<Self> {
        let key_client = SecretKey::generate();
        let key_server = SecretKey::generate();
        let id_client = key_client.public();
        let id_server = key_server.public();

        let client_hub = WebRtcHandle::hub(id_client);
        let server_hub = WebRtcHandle::hub(id_server);

        let client = browser_endpoint(key_client, &client_hub).await?;
        let server = browser_endpoint(key_server, &server_hub).await?;
        let router = Router::builder(server)
            .accept(BENCH_ALPN, Bench::new())
            .spawn();

        // Host-only ICE: both agents are in this tab, so loopback candidates
        // pair without a STUN round trip — and a test that reached a public
        // STUN server would be measuring the network, not the transport.
        let (pending_offer, offer_env) = browser_offer(id_client, &IceServers::host_only())
            .await
            .map_err(|error| js_error(&error))?;
        let (pending_answer, answer_env) =
            browser_answer(id_server, &offer_env, &IceServers::host_only())
                .await
                .map_err(|error| js_error(&error))?;

        // Concurrently, and this is load-bearing: the answerer is waiting for
        // `ondatachannel`, which only fires once the offerer applies the
        // answer. Awaiting them in sequence deadlocks.
        let client_transport = client_hub.transport();
        let server_transport = server_hub.transport();
        let offer = pending_offer.complete(client_transport.as_ref(), &answer_env);
        let answer = pending_answer.complete(server_transport.as_ref(), id_client);
        let (client_session, server_session) = future::zip(offer, answer).await;
        client_session.map_err(|error| js_error(&error))?;
        server_session.map_err(|error| js_error(&error))?;

        anyhow::ensure!(client_hub.has_session(&id_server), "client session is live");
        anyhow::ensure!(server_hub.has_session(&id_client), "server session is live");

        Ok(Self {
            client,
            server_addr: EndpointAddr::from_parts(
                id_server,
                [TransportAddr::Custom(custom_addr(id_server))],
            ),
            client_hub: client_hub.transport(),
            server_id: id_server,
            router,
        })
    }

    /// One exchange in `direction`, sized `bulk`, bounded by `deadline`.
    ///
    /// A fresh connection per call for the same reason `loopback.rs` uses one:
    /// [`Bench`] serves a single bi-stream then parks on `closed()`. Callers
    /// that want many exchanges over *one* data channel get that for free —
    /// the channel is the session, the QUIC connection is not.
    pub(crate) async fn exchange(
        &self,
        direction: Direction,
        bulk: usize,
        deadline: Duration,
    ) -> anyhow::Result<()> {
        let connection = self
            .client
            .connect(self.server_addr.clone(), BENCH_ALPN)
            .await?;

        // The only transport is WebRTC, but assert the selected path anyway so
        // a future regression can't silently reroute and call it a pass.
        anyhow::ensure!(
            on_webrtc(&connection),
            "no WebRTC path on the connection: {:?}",
            connection.paths()
        );

        // The whole exchange under one deadline, both legs inside it. A stall
        // is silent and indefinite — the harness would simply never finish — so
        // the failure has to be manufactured, and it has to cover the send leg
        // too: an upload that wedges in `write_all` is exactly the pump
        // starvation this is hunting.
        let run = exchange(&connection, direction, bulk);
        let Ok(body) = time::timeout(deadline, run).await else {
            let counters = self.client_hub.session_counters(&self.server_id);
            let (out_bytes, in_bytes) = self.channel_bytes().await;
            anyhow::bail!(
                "{} of {bulk} bytes stalled past {deadline:?}; \
                 data-channel bytes sent={out_bytes} received={in_bytes}; \
                 outbound lane = {counters:?}",
                direction.label()
            );
        };
        body?;
        connection.close(0u32.into(), b"done");
        Ok(())
    }

    /// Bytes this session's data channel has carried, both directions.
    ///
    /// Deliberately **not** `selected_pair_stats`: this test caught that reader
    /// reporting 7400 bytes and 28 packets on a connection that had just
    /// carried a verified megabyte, intermittently and on the transport row as
    /// well as the candidate pair. The `data-channel` row comes from the layer
    /// that actually carries our datagrams and names this channel by its label,
    /// so it cannot be describing someone else's traffic.
    ///
    /// An instantaneous sample, which is what a *failure* path wants — see
    /// [`Self::channel_bytes_settled`] for the one a report wants.
    pub(crate) async fn channel_bytes(&self) -> (f64, f64) {
        let counters = self
            .client_hub
            .data_channel_bytes(&self.server_id)
            .await
            .unwrap_or_default();
        (counters.bytes_sent, counters.bytes_received)
    }

    /// [`Self::channel_bytes`], sampled until it stops moving.
    ///
    /// The browser updates these counters on its own cadence, not ours, so a
    /// read taken the instant a transfer's last byte is delivered can still be
    /// reporting the state before it. Measured on a passing 64 `KiB` cell: a
    /// verified transfer completed and the counter said zero.
    ///
    /// That is intolerable in a table built to hunt a stall, because "0 bytes
    /// received" is the exact signature being hunted — a sampling artefact
    /// dressed as the bug. So: poll until two consecutive reads agree, or give
    /// up and say so. `None` means "not observed", which a caller must render
    /// as unknown rather than as zero.
    pub(crate) async fn channel_bytes_settled(&self) -> Option<(f64, f64)> {
        const SETTLE_ATTEMPTS: usize = 60;
        const SETTLE_GAP: Duration = Duration::from_millis(25);

        let mut previous = self.channel_bytes().await;
        for _ in 0..SETTLE_ATTEMPTS {
            time::sleep(SETTLE_GAP).await;
            let current = self.channel_bytes().await;
            // Stability is judged on *received* alone. QUIC keeps acknowledging
            // after the last payload byte lands, so the sent counter can still
            // be creeping when the received one is final — waiting for both to
            // hold still would sometimes wait out the whole budget and then
            // report "not observed" for a transfer that plainly finished.
            //
            // Non-zero as well as stable: two zeros in a row means the row has
            // not appeared yet, not that nothing crossed.
            if (current.1 - previous.1).abs() < f64::EPSILON && current.1 > 0.0 {
                return Some(current);
            }
            previous = current;
        }
        (previous.1 > 0.0).then_some(previous)
    }

    pub(crate) async fn shutdown(self) {
        let _ = self.router.shutdown().await;
        self.client.close().await;
    }
}
