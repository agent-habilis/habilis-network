//! The socket and engine of a negotiation that has not finished.

use std::net::SocketAddr;
use std::time::Instant;
use str0m::Rtc;
use tokio::net::UdpSocket;

use super::driver::{add_host_candidate, add_reflexive_candidate, bind_ephemeral_udp, build_rtc};
use super::ice_config::IceConfig;
use super::jsep_error::JsepError;

pub(super) struct Negotiating {
    pub(super) rtc: Rtc,
    pub(super) socket: UdpSocket,
    pub(super) advertised: SocketAddr,
}

impl std::fmt::Debug for Negotiating {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Negotiating")
            .field("advertised", &self.advertised)
            .finish_non_exhaustive()
    }
}

/// Bind the session's socket and gather its candidates.
///
/// Both roles funnel through here, which is what keeps the offerer and the
/// answerer advertising the same *kinds* of candidate. Gathering must happen
/// before the SDP is produced: this is vanilla ICE, so candidates ride inside
/// the SDP and there is no trickle message to add them later.
pub(super) async fn start(ice: &IceConfig) -> Result<Negotiating, JsepError> {
    let mut rtc = build_rtc(Instant::now());
    let (socket, advertised) = bind_ephemeral_udp()
        .await
        .map_err(|error| JsepError::Bind(Box::new(error)))?;
    add_host_candidate(&mut rtc, advertised)?;
    // Same socket as the media, or the NAT mapping we learn describes a hole
    // the data will not arrive through.
    add_reflexive_candidate(&mut rtc, &socket, advertised, ice).await;
    Ok(Negotiating {
        rtc,
        socket,
        advertised,
    })
}
