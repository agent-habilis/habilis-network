//! A stream node: one endpoint that produces streams, opens them, or both.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use habilis_network::iroh::Endpoint;
use habilis_network::iroh::address_lookup::memory::MemoryLookup;
use habilis_network::iroh::protocol::Router;
use habilis_network::net::TransportOpts;
use habilis_network::net::direct::{
    IceProfile, MAX_DIRECT_PEERS, MESH_WEBRTC_SIGNAL_ALPN, PROBE_DEADLINE, SignalAdmission,
    WebRtcHandle, WebRtcSignalAcceptor, build_peer_webrtc, dial_signal, pair_needs_lane,
    wait_direct,
};
use habilis_network::protocol::{
    Lookup, LookupOpts, MeshConfig, RelayChoice, RelayLadder, Transport, TransportPolicy,
};
use rand::RngCore as _;
use serde::Deserialize;

use crate::code;
use crate::hash::{ID_LEN, SECRET_LEN, StreamHash};
use crate::produce::{Producer, Registry, StreamAcceptor};
use crate::read::{Reader, Refused};

/// How long `create` waits for the endpoint to reach its home relay, so the
/// hash it mints carries it. Best effort: it never blocks past this.
const ONLINE_WAIT: Duration = Duration::from_secs(5);

/// How a node finds peers and what may carry its bytes — the same three lists
/// a mesh create takes, so a producer and a tab agree on them.
///
/// `Deserialize` so a browser hands its constructor a plain object;
/// `deny_unknown_fields` so a typo is an error, not a silent loopback node.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct StreamOpts {
    /// How peers find each other: any of `mdns`, `dht`, `relay`, `pkarr`.
    /// None is a loopback node.
    pub lookup: Vec<Lookup>,
    /// What may carry bytes: any of `udp`, `webrtc`, `relay`, with `udp` or
    /// `webrtc` among them. Empty ⇒ `udp,webrtc`.
    pub transport: Vec<Transport>,
    /// A custom relay ladder, first preferred. Empty is the default ladder.
    pub relay_urls: Vec<String>,
    /// Custom pkarr relays; the node publishes to all of them. Needs `pkarr`
    /// in `lookup`. Empty is the default list.
    pub pkarr_urls: Vec<String>,
}

impl StreamOpts {
    /// The config these lists name.
    ///
    /// # Errors
    /// The lists conflict, or a URL is invalid.
    pub fn config(&self) -> Result<MeshConfig> {
        MeshConfig::resolve(
            &self.lookup,
            relay_ladder(&self.relay_urls)?,
            habilis_network::protocol::parse_pkarr_urls(&self.pkarr_urls)?,
            &self.transport,
        )
    }
}

/// One endpoint serving and opening streams. It never joins a gossip mesh.
#[derive(Debug)]
pub struct StreamNode {
    endpoint: Endpoint,
    router: Router,
    webrtc: WebRtcHandle,
    registry: Arc<Registry>,
    lookups: LookupOpts,
    transport: TransportPolicy,
    transports: TransportOpts,
    ice: IceProfile,
    /// The producers this node has opened, by address. One lookup for all of
    /// them, so a node that opens many streams does not grow its address book
    /// by one lookup service per open.
    producers: MemoryLookup,
}

impl StreamNode {
    /// Stand up an endpoint with `opts`.
    ///
    /// # Errors
    /// Conflicting or invalid options, a loopback node in a browser, or an
    /// endpoint that fails to bind.
    pub async fn bind(opts: &StreamOpts) -> Result<Self> {
        let config = opts.config()?;
        let transports = TransportOpts::default().within(&config.transport);
        Self::bind_with(config.lookups, config.transport, transports).await
    }

    /// Stand up an endpoint that can reach the producer of `hash`: the hash's
    /// own lookups and transport list, narrowed to what this target has.
    ///
    /// # Errors
    /// As [`bind`](Self::bind).
    pub async fn bind_for(hash: &StreamHash) -> Result<Self> {
        let transports = TransportOpts::default().within(&hash.transport);
        Self::bind_with(hash.lookups.clone(), hash.transport, transports).await
    }

    async fn bind_with(
        lookups: LookupOpts,
        transport: TransportPolicy,
        transports: TransportOpts,
    ) -> Result<Self> {
        #[cfg(target_arch = "wasm32")]
        habilis_network::runtime::refuse_in_browser(&lookups, transport, transports)?;
        let (endpoint, webrtc) = build_peer_webrtc(&lookups, transports).await?;
        let registry = Arc::new(Registry::default());
        let ice = IceProfile {
            host_only: lookups.is_loopback(),
        };
        let mut router = Router::builder(endpoint.clone()).accept(
            crate::STREAM_ALPN,
            StreamAcceptor {
                registry: Arc::clone(&registry),
                relay_transport: transport.relay_transport,
            },
        );
        if transports.webrtc {
            router = router.accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                WebRtcSignalAcceptor::new(
                    webrtc.clone(),
                    endpoint.clone(),
                    endpoint.id(),
                    SignalAdmission::new(MAX_DIRECT_PEERS),
                    ice,
                ),
            );
        }
        let router = router.spawn();
        let producers = MemoryLookup::new();
        endpoint.address_lookup()?.add(producers.clone());
        Ok(Self {
            endpoint,
            router,
            webrtc,
            registry,
            lookups,
            transport,
            transports,
            ice,
            producers,
        })
    }

    /// Open a new stream and return its writing end. Hand its
    /// [`hash`](Producer::hash) to the one consumer.
    ///
    /// With a relay lookup, it first waits (at most [`ONLINE_WAIT`], once) for
    /// the endpoint to reach its home relay, so the hash carries it. Here and
    /// not in `bind`: a node that only reads never pays for it.
    pub async fn create(&self) -> Producer {
        // `online` resolves only once a home relay is reached, so without a
        // relay lookup it would cost the whole wait.
        if self.lookups.relay_lookup != RelayChoice::Disabled {
            let _ = n0_future::time::timeout(ONLINE_WAIT, self.endpoint.online()).await;
        }
        let mut id = [0; ID_LEN];
        let mut secret = [0; SECRET_LEN];
        rand::rng().fill_bytes(&mut id);
        rand::rng().fill_bytes(&mut secret);
        Producer::new(
            StreamHash {
                addr: self.endpoint.addr(),
                lookups: self.lookups.clone(),
                transport: self.transport,
                id,
                secret,
            },
            Arc::clone(&self.registry),
        )
    }

    /// Take the consumer slot of the stream behind `hash`.
    ///
    /// # Errors
    /// The producer cannot be reached, the only path is a relay the stream
    /// refuses, or the producer refuses the hash (a [`Refused`]).
    pub async fn open(&self, hash: &StreamHash) -> Result<Reader> {
        let needs_lane = pair_needs_lane(&hash.addr, self.transports.udp);
        // A data channel needs `webrtc` on both ends: the producer's list is in
        // the hash, and a producer without it answers no offer.
        let can_lane = self.transports.webrtc && hash.transport.webrtc;
        // The relay carries the bytes only if both lists allow it: the
        // producer enforces its own, so this side enforces the consumer's.
        let relay_ok = self.transport.relay_transport && hash.transport.relay_transport;
        // Only a data channel could carry the bytes, and the pair has none:
        // what is left is the relay the stream refuses, so say so now rather
        // than after the direct-path probe.
        if needs_lane && !can_lane && !relay_ok {
            bail!(Refused::RelayRefused);
        }
        self.producers.add_endpoint_info(hash.addr.clone());
        // The WebRTC lane first: the connect below then finds the session's
        // path in the address book and can start on the data channel, rather
        // than on the relay a later attach would have to move it off.
        if can_lane
            && needs_lane
            && !self.webrtc.has_session(&hash.addr.id)
            && let Err(error) =
                dial_signal(&self.endpoint, hash.addr.clone(), &self.webrtc, self.ice).await
            && !relay_ok
        {
            return Err(error.context("opening a WebRTC lane to the producer"));
        }
        let conn = self
            .endpoint
            .connect(hash.addr.clone(), crate::STREAM_ALPN)
            .await
            .context("connecting to the producer")?;
        if !relay_ok && !wait_direct(&conn, PROBE_DEADLINE).await {
            conn.close(code::RELAY_REFUSED.into(), b"relay path refused");
            bail!(Refused::RelayRefused);
        }
        let (mut send, recv) = conn.open_bi().await.context("opening the stream")?;
        send.write_all(&hash.id).await?;
        send.write_all(&hash.secret).await?;
        send.finish()?;
        Ok(Reader::new(conn, recv))
    }

    /// Shut the node down. Every stream still open is abandoned.
    pub async fn close(self) {
        self.registry.clear();
        let _ = self.router.shutdown().await;
        self.endpoint.close().await;
    }
}

/// The ladder `urls` name, or `None` for the default. Parsed as one list, so an
/// empty or bad entry is an error rather than a shrunk ladder.
fn relay_ladder(urls: &[String]) -> Result<Option<RelayLadder>> {
    if urls.is_empty() {
        return Ok(None);
    }
    urls.join(",")
        .parse::<RelayLadder>()
        .map(Some)
        .map_err(|error| anyhow::anyhow!("{error}"))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use habilis_network::runtime::refuse_in_browser;

    use super::*;

    /// A tab passes the pkarr list by its camelCase name, and it reaches
    /// the config the node binds with.
    #[test]
    fn pkarr_urls_reach_the_stream_config() {
        let opts: StreamOpts = serde_json::from_str(
            r#"{"lookup":["pkarr","relay"],"pkarrUrls":["https://pkarr.example/"]}"#,
        )
        .expect("pkarrUrls parses");
        let config = opts.config().expect("valid");
        assert_eq!(
            config.lookups.pkarr,
            habilis_network::protocol::PkarrChoice::Custom(vec![
                "https://pkarr.example/".parse().unwrap()
            ])
        );
    }

    // A browser has no UDP, so a list without `webrtc` leaves relay payload as
    // its only path: without `relay` in the list, nothing carries its bytes.
    #[test]
    fn a_browser_refuses_a_list_with_no_path_it_can_run() {
        let refused = |transport: &[Transport]| {
            let config =
                MeshConfig::resolve(&[Lookup::Relay], None, None, transport).expect("valid");
            let transports = TransportOpts::default().within(&config.transport);
            refuse_in_browser(&config.lookups, config.transport, transports).is_err()
        };
        assert!(refused(&[Transport::Udp]), "udp only");
        assert!(
            !refused(&[Transport::Udp, Transport::Relay]),
            "relay payload"
        );
        assert!(!refused(&[Transport::WebRtc]), "a data channel");
    }

    // A data channel's handshake crosses the relay, and a browser has no
    // other way to reach a producer.
    #[test]
    fn a_browser_refuses_a_stream_with_no_relay_lookup() {
        let config = MeshConfig::resolve(
            &[Lookup::Dht],
            None,
            None,
            &[Transport::Udp, Transport::WebRtc],
        )
        .expect("valid");
        let transports = TransportOpts::default().within(&config.transport);
        let error = refuse_in_browser(&config.lookups, config.transport, transports)
            .expect_err("no path to signal on");
        assert_eq!(
            error.to_string(),
            habilis_network::runtime::BROWSER_NEEDS_RELAY_LOOKUP
        );
    }

    // A reader runs only the paths the producer runs: an offer to a producer
    // with no data channel would fail only after its whole JSEP round.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reader_takes_the_producers_transport_list() {
        let producer_node = StreamNode::bind(&StreamOpts {
            transport: vec![Transport::Udp],
            ..StreamOpts::default()
        })
        .await
        .expect("bind");
        let hash = producer_node.create().await.hash().clone();
        let reader_node = StreamNode::bind_for(&hash).await.expect("bind for");
        assert!(reader_node.transports.udp);
        assert!(
            !reader_node.transports.webrtc,
            "no data channel to offer to"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn opening_many_streams_adds_one_address_lookup() {
        let producer_node = StreamNode::bind(&StreamOpts::default())
            .await
            .expect("bind");
        let consumer_node = StreamNode::bind(&StreamOpts::default())
            .await
            .expect("bind");
        let lookups = || {
            consumer_node
                .endpoint
                .address_lookup()
                .expect("an address book")
                .len()
        };
        let before = lookups();
        for _ in 0..5 {
            let producer = producer_node.create().await;
            consumer_node.open(producer.hash()).await.expect("open");
        }
        let after = lookups();
        assert!(after <= before + 1, "{before} lookups grew to {after}");
    }
}
