//! The nudge: a tickle that asks a peer to offer a session again.

use std::future::{self, Future};

use super::consts::NUDGE_ALPN;
use crate::transport::pool;

use anyhow::Result;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};

use crate::transport::LOG_TARGET;

use crate::transport::probe;

use n0_future::time;
/// Closes every nudge at once. See [`NUDGE_ALPN`]. An endpoint that runs the `WebRTC` signal
/// acceptor must serve this too: its answerer dials the nudge when a session attaches.
///
/// # Examples
///
/// A nudge acceptor takes the nudges that ask a peer to open a direct path. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::direct::NudgeAcceptor;
///
/// # fn demo(acceptor: NudgeAcceptor) {
/// drop(acceptor);
/// # }
/// ```
#[derive(Debug, Clone, Default, Copy)]
#[non_exhaustive]
pub struct NudgeAcceptor;

impl NudgeAcceptor {
    /// The acceptor of the nudge ALPN.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolHandler for NudgeAcceptor {
    fn accept(
        &self,
        connection: Connection,
    ) -> impl Future<Output = Result<(), AcceptError>> + Send {
        connection.close(0u32.into(), b"nudge");
        future::ready(Ok(()))
    }
}

/// Make iroh re-run path selection to `peer` now. Bounded, and every outcome
/// is ignored.
pub(crate) async fn nudge(endpoint: &Endpoint, peer: EndpointId) {
    nudge_addr(endpoint, EndpointAddr::new(peer)).await;
}

/// [`nudge`] for a peer whose `WebRTC` session has just attached. The dial names
/// the session's custom address, so that iroh puts it in the path book of the
/// remote and opens that path on a connection that it already holds. A bare-id
/// dial finds the address only through the address lookup, and iroh does not ask
/// the lookup again for a remote it already knows.
pub(crate) async fn nudge_session(endpoint: &Endpoint, peer: EndpointId) {
    let session = probe::NudgeAddrs {
        session: true,
        route: None,
        gossip: false,
    };
    nudge_with(endpoint, peer, &session).await;
}

/// [`nudge`] with the addresses that `addrs` names, in one dial: the session's
/// custom address, the multihop route, or both. The one nudge path, so that what
/// teaches iroh a `WebRTC` address teaches it a multihop route the same way.
pub(crate) async fn nudge_with(endpoint: &Endpoint, peer: EndpointId, addrs: &probe::NudgeAddrs) {
    let known = probe::nudge_known(peer, addrs);
    nudge_addr(endpoint, EndpointAddr::from_parts(peer, known)).await;
}

pub(crate) async fn nudge_addr(endpoint: &Endpoint, address: EndpointAddr) {
    let peer = address.id;
    if let Ok(Ok(connection)) =
        time::timeout(pool::DIAL_TIMEOUT, endpoint.connect(address, NUDGE_ALPN)).await
    {
        connection.close(0u32.into(), b"nudge");
    }
    if tracing::enabled!(target: LOG_TARGET, tracing::Level::TRACE)
        && let Some(info) = endpoint.remote_info(peer).await
    {
        let kinds: Vec<String> = info
            .addrs()
            .map(|known| {
                if let iroh::TransportAddr::Custom(custom) = known.addr() {
                    format!("custom:{}", custom.id())
                } else {
                    format!("{:?}", known.addr())
                }
            })
            .collect();
        tracing::trace!(target: LOG_TARGET, %peer, ?kinds, "nudged; the remote knows these addresses");
    }
}
