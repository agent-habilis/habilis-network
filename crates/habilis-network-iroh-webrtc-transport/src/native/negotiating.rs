//! The socket and engine of a negotiation that has not finished.

use std::net::SocketAddr;
use std::time::Instant;
use str0m::Rtc;
use tokio::net::UdpSocket;

use super::driver::{add_host_candidate, add_reflexive_candidate, bind_ephemeral_udp, build_rtc};
use super::ice_config::IceConfig;
use super::jsep_error::JsepError;

use std::fmt;
pub(super) struct Negotiating {
    pub(super) rtc: Rtc,
    pub(super) socket: UdpSocket,
    pub(super) advertised: SocketAddr,
}

impl fmt::Debug for Negotiating {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    let (socket, advertised) = bind_ephemeral_udp(ice.bind_ip)
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

#[cfg(test)]
mod tests {
    use super::start;
    use crate::native::ice_config::IceConfig;

    /// **A negotiation with the loopback-only configuration binds its socket on loopback and
    /// advertises it.** The default binds every interface.
    #[test]
    fn a_loopback_only_negotiation_binds_and_advertises_loopback() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let negotiating = start(&IceConfig::loopback_only())
                .await
                .expect("start a negotiation");
            let local = negotiating.socket.local_addr().expect("local addr");
            assert!(
                local.ip().is_loopback(),
                "the socket listens beyond the host: {local}"
            );
            assert!(
                negotiating.advertised.ip().is_loopback(),
                "the candidate names another address: {}",
                negotiating.advertised
            );
        });
    }
}
