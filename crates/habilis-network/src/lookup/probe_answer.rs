use crate::util::clock;
// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use iroh_gossip::net::GOSSIP_ALPN;

use iroh::endpoint;
use n0_future::time;
/// What a connect-probe found at an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeAnswer {
    /// The connection opened: the listener presented the identity that was asked for.
    Ours,
    /// The handshake failed on the identity: our own verifier rejected the key that the listener
    /// presented ([`CERTIFICATE_ALERTS`]), or iroh could not read an identity from it. This, and
    /// only this, proves that what answers is not the mesh that was asked for.
    Foreign,
    /// A listener answered and ended the dial without proving an identity: a close, a refusal, a
    /// reset, a version mismatch, an alert that is not about the key (a holder of our own mesh
    /// that is bound and not serving yet answers `no_application_protocol`, which the server
    /// sends before its certificate), or a transport error. A busy, closing or starting holder
    /// of our own mesh sends these, so they say nothing about the mesh: a caller reads them as
    /// silence.
    Refused,
    /// Nothing answered inside the timeout, or there was nothing to dial. A port that nobody is
    /// bound on reads the same: UDP does not tell. A host too loaded to answer reads the same.
    NoAnswer,
}

/// [`probe_connect`] with the failure told apart: a listener that answered and refused is not a
/// listener that said nothing, and a listener that failed the identity is not one that refused.
/// A caller that must not act on silence (a bind cannot be taken back) acts on
/// [`ProbeAnswer::Foreign`] only and waits on [`ProbeAnswer::Refused`] and
/// [`ProbeAnswer::NoAnswer`].
pub(crate) async fn probe_answer(
    endpoint: &Endpoint,
    target: impl Into<EndpointAddr>,
    timeout: Duration,
) -> ProbeAnswer {
    let address: EndpointAddr = target.into();
    let started = clock::Instant::now();
    let mut failure = None;
    let connecting = endpoint.connect(address.clone(), GOSSIP_ALPN);
    let answer = match time::timeout(timeout, connecting).await {
        Ok(Ok(connection)) => {
            // Close explicitly, not via drop: the resolution side effect is
            // done, and an orderly CONNECTION_CLOSE lets the accept side
            // (the beacon's gossip, which adopts GOSSIP_ALPN connections)
            // release the connection immediately instead of via its own
            // error path.
            connection.close(0u32.into(), b"probe");
            ProbeAnswer::Ours
        }
        Ok(Err(error)) => {
            failure = Some(error.to_string());
            answer_of_connect_error(&error)
        }
        Err(_) => ProbeAnswer::NoAnswer,
    };
    let connected = answer == ProbeAnswer::Ours;
    // `?addr`: a loopback/private direct addr means a *local*
    // rendezvous co-host (self-partition signature); relay/public is
    // the cross-machine path. `elapsed_ms` exposes a slow relay
    // re-home outrunning the steady probe budget.
    //
    // A *failed* probe is the diagnostic signal a partition/post-sleep
    // re-bootstrap can't re-home the rendezvous, so it lands at `info`
    // (always-on file); a steady success every heal tick would be a
    // firehose, so it stays `debug`.
    let elapsed_ms = clock::millis_saturating(started.elapsed());
    if connected {
        tracing::debug!(target: "habilis_network::lookup", connected, elapsed_ms, address = ?address, "rendezvous connect-probe finished");
    } else {
        tracing::info!(target: "habilis_network::lookup", connected, elapsed_ms, ?answer, ?failure, address = ?address, "rendezvous connect-probe finished");
    }
    answer
}

/// The TLS alerts that a certificate verifier raises about the key of the peer, by alert number
/// (QUIC carries each as crypto error `0x100` plus the alert). `unknown_ca` 48 is the one that
/// this mesh produces: our verifier returns `InvalidCertificate(UnknownIssuer)` for another key
/// (iroh `tls/verifier.rs`), and rustls sends that as `UnknownCA` (rustls 0.23 `error.rs`,
/// `From<CertificateError> for AlertDescription`). The others are the alerts of the same verifier family: `bad_certificate`
/// 42 (`NotValidForName`), `unsupported_certificate` 43, `certificate_revoked` 44,
/// `certificate_expired` 45, `certificate_unknown` 46 and `decrypt_error` 51 (a bad signature).
/// Every other alert, `no_application_protocol` 120 included, is sent before a certificate is
/// seen and proves nothing about the identity.
const CERTIFICATE_ALERTS: [u8; 7] = [48, 42, 43, 44, 45, 46, 51];

/// A dial that ended in an error: a handshake that failed on the identity is
/// [`ProbeAnswer::Foreign`], a listener that closed or refused is [`ProbeAnswer::Refused`], and
/// every other failure said nothing.
fn answer_of_connect_error(error: &endpoint::ConnectError) -> ProbeAnswer {
    use iroh::endpoint::{AuthenticationError, ConnectError, ConnectingError};

    match error {
        ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        }
        | ConnectError::Connection { source, .. } => answer_of_connection_error(source),
        ConnectError::Connecting {
            source:
                ConnectingError::HandshakeFailure {
                    source: AuthenticationError::RemoteId { .. },
                    ..
                },
            ..
        } => ProbeAnswer::Foreign,
        ConnectError::Connecting {
            source: ConnectingError::HandshakeFailure { .. },
            ..
        } => ProbeAnswer::Refused,
        ConnectError::Connect { .. }
        | ConnectError::Connecting {
            source:
                ConnectingError::InternalConsistencyError { .. }
                | ConnectingError::LocallyRejected { .. },
            ..
        }
        | _ => ProbeAnswer::NoAnswer,
    }
}

/// A connection error, during the handshake or after it. Only a certificate alert that our own
/// verifier raises about the key is [`ProbeAnswer::Foreign`]. A close, a reset, a refusal and
/// any other alert are [`ProbeAnswer::Refused`]. A timeout, a close of ours and exhausted
/// connection ids say nothing.
pub(crate) fn answer_of_connection_error(error: &endpoint::ConnectionError) -> ProbeAnswer {
    use iroh::endpoint::{ConnectionError, TransportErrorCode};

    match error {
        // Foreign is what our own verifier said about the key of the peer, nothing else.
        ConnectionError::TransportError(failure)
            if CERTIFICATE_ALERTS
                .iter()
                .any(|&alert| failure.code == TransportErrorCode::crypto(alert)) =>
        {
            ProbeAnswer::Foreign
        }
        ConnectionError::TransportError(_)
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::ApplicationClosed(_)
        | ConnectionError::Reset
        | ConnectionError::VersionMismatch => ProbeAnswer::Refused,
        ConnectionError::TimedOut
        | ConnectionError::LocallyClosed
        | ConnectionError::CidsExhausted => ProbeAnswer::NoAnswer,
    }
}
