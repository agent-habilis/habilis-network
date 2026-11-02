//! The stream node: one endpoint that serves and opens streams.

use std::sync::Arc;

use habilis_network::iroh::Endpoint;
use habilis_network::iroh::address_lookup::memory::MemoryLookup;
use habilis_network::iroh::protocol::Router;
use habilis_network::net::direct::{
    IceProfile, MAX_DIRECT_PEERS, MESH_WEBRTC_SIGNAL_ALPN, NUDGE_ALPN, NudgeAcceptor,
    PROBE_DEADLINE, PayloadPath, SignalAdmission, UdpTransport, WebRtcHandle, WebRtcSignalAcceptor,
    build_peer_webrtc, dial_signal, pair_needs_lane, wait_direct,
};
use habilis_network::net::{TransportOpts, add_peer_addr, address_book};
use habilis_network::protocol::{
    LookupOpts, MeshConfig, RelayChoice, RelayLadder, RelayLadderError, Transport, TransportPolicy,
};
use zeroize::Zeroizing;

use super::{ONLINE_WAIT, StreamOpts};
use crate::code;
use crate::error::StreamError;
use crate::hash::{ID_LEN, SECRET_LEN, StreamHash, StreamId, StreamSecret};
use crate::produce::{Producer, Registry, StreamAcceptor};
use crate::read::{Reader, Refused};

use habilis_network::net::EndpointError;
#[cfg(target_arch = "wasm32")]
use habilis_network::runtime;
use n0_future::time;
/// One endpoint serving and opening streams. It never joins a gossip mesh.
///
/// # Examples
///
/// A node binds an endpoint, and it creates the streams that it serves. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_stream::{StreamError, StreamNode, StreamOpts};
///
/// # async fn demo() -> Result<(), StreamError> {
/// let node = StreamNode::bind(&StreamOpts::default()).await?;
/// let mut producer = node.create().await;
/// producer.write(b"hello").await?;
/// producer.close().await?;
/// node.close().await;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct StreamNode {
    pub(super) endpoint: Endpoint,
    router: Router,
    webrtc: WebRtcHandle,
    // the node shares the registry with its producers and its acceptor
    registry: Arc<Registry>,
    lookups: LookupOpts,
    pub(super) transport: TransportPolicy,
    pub(super) transports: TransportOpts,
    ice: IceProfile,
    /// The address book of the endpoint: the producers this node has opened, and
    /// the peers of its `WebRTC` sessions.
    producers: MemoryLookup,
}

impl StreamNode {
    /// Stand up an endpoint with `opts`.
    ///
    /// # Errors
    /// # Errors
    /// [`StreamError::Options`] for a transport a stream does not use,
    /// [`StreamError::Bind`] when the relay list or the node does not start.
    pub async fn bind(options: &StreamOpts) -> Result<Self, StreamError> {
        if options.transport.contains(&Transport::Multihop) {
            return Err(StreamError::Options(
                "a stream has no multihop: it is one direct lane",
            ));
        }
        if options.transport.contains(&Transport::Gossip) {
            return Err(StreamError::Options(
                "a stream has no gossip: its node never joins a gossip mesh",
            ));
        }
        // An empty list is `udp,webrtc` for a stream: the mesh default has multihop.
        let list = if options.transport.is_empty() {
            &[Transport::Udp, Transport::WebRtc][..]
        } else {
            &options.transport
        };
        let relays =
            relay_ladder(&options.relay_urls).map_err(StreamError::bind("parse the relay list"))?;
        let config = MeshConfig::resolve(&options.lookup, relays, list)
            .map_err(StreamError::bind("resolve the mesh config"))?;
        let transports = TransportOpts::default().within(&config.transport);
        Self::bind_with(config.lookups, config.transport, transports).await
    }

    /// Stand up an endpoint that can reach the producer of `hash`: the hash's
    /// own lookups and transport list, narrowed to what this target has.
    ///
    /// # Errors
    /// # Errors
    /// As [`bind`](Self::bind): [`StreamError::Bind`] when the node does not start.
    pub async fn bind_for(hash: &StreamHash) -> Result<Self, StreamError> {
        let transports = TransportOpts::default().within(&hash.transport);
        Self::bind_with(hash.lookups.clone(), hash.transport.clone(), transports).await
    }

    async fn bind_with(
        lookups: LookupOpts,
        transport: TransportPolicy,
        transports: TransportOpts,
    ) -> Result<Self, StreamError> {
        #[cfg(target_arch = "wasm32")]
        runtime::refuse_in_browser(&lookups, &transport, transports)
            .map_err(StreamError::bind("start the stream node"))?;
        let (endpoint, webrtc) = build_peer_webrtc(&lookups, transports)
            .await
            .map_err(StreamError::bind("start the stream node"))?;
        let producers = address_book(&endpoint);
        // the producers and the acceptor share this registry with the node
        let registry = Arc::new(Registry::default());
        let ice = IceProfile::default().host_only(lookups.is_loopback());
        let mut router = Router::builder(endpoint.clone()).accept(
            crate::STREAM_ALPN,
            StreamAcceptor {
                registry: Arc::clone(&registry),
                relay_transport: PayloadPath::from(transport.allows(Transport::Relay)),
            },
        );
        if transports.webrtc {
            let endpoint_id = endpoint.id();
            let acceptor = WebRtcSignalAcceptor::new(
                webrtc.clone(),
                endpoint.clone(),
                producers.clone(),
                endpoint_id,
                SignalAdmission::new(MAX_DIRECT_PEERS),
                ice,
            );
            router = router.accept(MESH_WEBRTC_SIGNAL_ALPN, acceptor);
            // The answerer of a session dials this when the session attaches.
            router = router.accept(NUDGE_ALPN, NudgeAcceptor::new());
        }
        let router = router.spawn();
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
    /// With a relay lookup, it first waits (at most `ONLINE_WAIT`, once) for
    /// the endpoint to reach its home relay, so the hash carries it. Here and
    /// not in `bind`: a node that only reads never pays for it.
    pub async fn create(&self) -> Producer {
        use rand::RngCore as _;
        // `online` resolves only once a home relay is reached, so without a
        // relay lookup it would cost the whole wait.
        if self.lookups.relay_lookup != RelayChoice::Disabled {
            let _ = time::timeout(ONLINE_WAIT, self.endpoint.online()).await;
        }
        let mut id = [0; ID_LEN];
        let mut secret = Zeroizing::new([0; SECRET_LEN]);
        rand::rng().fill_bytes(&mut id);
        rand::rng().fill_bytes(&mut *secret);
        let hash = StreamHash {
            address: self.endpoint.addr(),
            lookups: self.lookups.clone(),
            transport: self.transport.clone(),
            id: StreamId::from(id),
            secret: StreamSecret::from(secret),
        };
        Producer::new(hash, Arc::clone(&self.registry))
    }

    /// Take the consumer slot of the stream behind `hash`.
    ///
    /// # Errors
    /// # Errors
    /// [`StreamError::Refused`] when the producer refuses the hash, or the only path is
    /// a relay the stream refuses. [`StreamError::Open`] when the producer cannot be
    /// reached or the stream cannot be opened.
    pub async fn open(&self, hash: &StreamHash) -> Result<Reader, StreamError> {
        let needs_lane = pair_needs_lane(&hash.address, UdpTransport::from(self.transports.udp));
        // A data channel needs `webrtc` on both ends: the producer's list is in
        // the hash, and a producer without it answers no offer.
        let can_lane = self.transports.webrtc && hash.transport.allows(Transport::WebRtc);
        // The relay carries the bytes only if both lists allow it: the
        // producer enforces its own, so this side enforces the consumer's.
        let relay_ok =
            self.transport.allows(Transport::Relay) && hash.transport.allows(Transport::Relay);
        // Only a data channel could carry the bytes, and the pair has none:
        // what is left is the relay the stream refuses, so say so now rather
        // than after the direct-path probe.
        if needs_lane && !can_lane && !relay_ok {
            return Err(StreamError::Refused(Refused::RelayRefused));
        }
        add_peer_addr(&self.producers, hash.address.clone());
        // The WebRTC lane first: the connect below then finds the session's
        // path in the address book and can start on the data channel, rather
        // than on the relay a later attach would have to move it off.
        if can_lane
            && needs_lane
            && !self.webrtc.has_session(&hash.address.id)
            && let Err(error) = dial_signal(
                &self.endpoint,
                &self.producers,
                hash.address.clone(),
                &self.webrtc,
                self.ice,
            )
            .await
            && !relay_ok
        {
            if matches!(error, EndpointError::CapRefused { .. }) {
                return Err(StreamError::Refused(Refused::AtCap));
            }
            return Err(StreamError::Open {
                step: "open a WebRTC lane to the producer",
                source: error.into(),
            });
        }
        let connection = self
            .endpoint
            .connect(hash.address.clone(), crate::STREAM_ALPN)
            .await
            .map_err(StreamError::open("connect to the producer"))?;
        if !relay_ok && !wait_direct(&connection, PROBE_DEADLINE).await {
            connection.close(code::RELAY_REFUSED.into(), b"relay path refused");
            return Err(StreamError::Refused(Refused::RelayRefused));
        }
        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(StreamError::open("open the stream"))?;
        send.write_all(hash.header_bytes().as_slice())
            .await
            .map_err(StreamError::open("send the stream hash"))?;
        send.finish()
            .map_err(StreamError::open("send the stream hash"))?;
        Ok(Reader::new(connection, recv))
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
fn relay_ladder(urls: &[String]) -> Result<Option<RelayLadder>, RelayLadderError> {
    if urls.is_empty() {
        return Ok(None);
    }
    let ladder: Result<RelayLadder, _> = urls.join(",").parse();
    ladder.map(Some)
}
