use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;
use iroh::EndpointId;
use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::session::{InboundPacket, SessionRegistry};

/// Consecutive receive errors a live session tolerates before giving up. Sized
/// to ride out a burst of ICMP port-unreachables (one per dead STUN server,
/// which Windows surfaces here) while still ending a session whose socket has
/// genuinely stopped reading. Any successful receive resets the count.
const MAX_CONSECUTIVE_RECV_ERRORS: usize = 32;

/// A `WebRTC` data channel negotiated via JSEP and ready to carry datagrams —
/// the value handed to [`crate::WebRtcTransport::attach`].
pub struct NegotiatedSession {
    pub(crate) rtc: Rtc,
    pub(crate) socket: UdpSocket,
    pub(crate) channel_id: ChannelId,
    pub(crate) advertised: SocketAddr,
}

impl std::fmt::Debug for NegotiatedSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NegotiatedSession")
            .field("advertised", &self.advertised)
            .finish_non_exhaustive()
    }
}

pub(crate) fn build_rtc(now: Instant) -> Rtc {
    Rtc::builder()
        .set_crypto_provider(Arc::new(str0m_aws_lc_rs::default_provider()))
        .build(now)
}

/// Binds an ephemeral UDP socket for the str0m session. When the bind is
/// unspecified, advertise a non-loopback interface address so the single
/// (vanilla-ICE) host candidate is reachable beyond this machine; the
/// loopback fallback is what makes same-host tests work.
pub(crate) async fn bind_ephemeral_udp() -> std::io::Result<(UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let local = socket.local_addr()?;
    let ip = if local.ip().is_unspecified() {
        if_addrs::get_if_addrs()
            .ok()
            .into_iter()
            .flatten()
            .find(|iface| !iface.is_loopback() && iface.addr.ip().is_ipv4())
            .map_or(Ipv4Addr::LOCALHOST.into(), |iface| iface.addr.ip())
    } else {
        local.ip()
    };
    Ok((socket, SocketAddr::new(ip, local.port())))
}

pub(crate) fn add_host_candidate(rtc: &mut Rtc, advertised: SocketAddr) -> anyhow::Result<()> {
    let candidate = Candidate::host(advertised, "udp").context("ICE host candidate")?;
    rtc.add_local_candidate(candidate);
    Ok(())
}

/// Ask STUN what this socket looks like from outside and, if anything
/// answers, offer that as a server-reflexive candidate too.
///
/// This is what lifts the transport off the LAN. `str0m` gathers nothing on
/// its own, so without this the SDP carries a single host candidate on a
/// private interface and two peers behind different NATs never meet.
///
/// A failure here is logged and swallowed: the host candidate still stands,
/// and the relay fallback covers what ICE cannot reach.
pub(crate) async fn add_reflexive_candidate(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    base: SocketAddr,
    config: &super::stun::IceConfig,
) -> bool {
    let Some(reflexive) = super::stun::gather_reflexive(socket, config).await else {
        return false;
    };
    // A NAT that does not translate reports the base back; adding it again
    // would just duplicate the host candidate.
    if reflexive == base {
        tracing::debug!(%reflexive, "reflexive address equals the base; not on a NAT");
        return false;
    }
    // str0m rejects a reflexive/base pair on different IP versions, so a v6
    // answer for a v4 socket surfaces here as an error rather than a candidate
    // that never pairs.
    match Candidate::server_reflexive(reflexive, base, "udp") {
        Ok(candidate) => {
            rtc.add_local_candidate(candidate);
            tracing::debug!(%reflexive, %base, "added a server-reflexive candidate");
            true
        }
        Err(error) => {
            tracing::debug!(%error, "str0m rejected the reflexive candidate");
            false
        }
    }
}

pub(crate) enum ChannelReadyTarget {
    Offerer(ChannelId),
    Answerer,
}

/// Drives ICE/DTLS/SCTP until the data channel opens. Returns the open
/// channel's id (the answerer learns it from the `ChannelOpen` event).
pub(crate) async fn drive_until_channel_ready(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    advertised: SocketAddr,
    target: &ChannelReadyTarget,
    deadline: Duration,
) -> anyhow::Result<ChannelId> {
    let give_up = Instant::now() + deadline;
    let mut buf = vec![0u8; 2000];
    let mut next_wake = Instant::now();
    let mut opened: Option<ChannelId> = None;
    let mut noise = HandshakeNoise::default();

    while Instant::now() < give_up {
        let sleep_for = next_wake
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1))
            .min(Duration::from_millis(50));

        tokio::select! {
            () = tokio::time::sleep(sleep_for) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .context("str0m timeout input")?;
            }
            received = socket.recv_from(&mut buf) => {
                // Never fatal, for the reason the STUN gather sharing this
                // socket is not: Windows reports an ICMP port-unreachable from
                // a dead server as a receive error, and several dead servers
                // burst them. The deadline already bounds this loop, and the
                // pause keeps a persistent error from spinning it hot.
                let (len, src) = match received {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::debug!(%error, "transient error reading during the JSEP handshake");
                        noise.recv_errors += 1;
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                if len == 0 {
                    continue;
                }
                // The destination must be the advertised candidate address,
                // not the socket's 0.0.0.0 bind — str0m matches it against
                // its local ICE candidate.
                //
                // This socket is reachable by anything that can route to the
                // host candidate we advertised in the SDP, so an unparseable
                // datagram says nothing about the peer we are negotiating
                // with: a port scanner, a late reply from the STUN gather
                // sharing this socket, or any stray sender produces one, and
                // failing the handshake hands all of them a way to break it.
                // The live-session loop below already treats such a datagram
                // as noise; this loop disagreeing with it was the bug.
                //
                // What the old bail did buy was a *named* failure instead of a
                // silent timeout, so the count is carried to the deadline and
                // reported there.
                let Ok(receive) = Receive::new(Protocol::Udp, src, advertised, &buf[..len]) else {
                    if super::stun::is_plain_stun_response(&buf[..len]) {
                        tracing::trace!(%src, "ignoring a late STUN gather reply during the handshake");
                    } else {
                        tracing::debug!(%src, len, "ignoring an unparseable datagram during the handshake");
                        noise.unparseable += 1;
                        noise.last_source = Some(src);
                    }
                    continue;
                };
                rtc.handle_input(Input::Receive(Instant::now(), receive))
                    .context("str0m receive input")?;
            }
        }

        loop {
            match rtc.poll_output().context("str0m poll_output")? {
                Output::Timeout(wake) => {
                    next_wake = wake;
                    break;
                }
                Output::Transmit(transmit) => {
                    let _ = socket
                        .send_to(&transmit.contents, transmit.destination)
                        .await;
                }
                Output::Event(Event::ChannelOpen(id, _)) => match target {
                    ChannelReadyTarget::Offerer(expected) if id == *expected => {
                        opened = Some(id);
                    }
                    ChannelReadyTarget::Offerer(_) => {}
                    ChannelReadyTarget::Answerer => {
                        opened = Some(id);
                    }
                },
                Output::Event(_) => {}
            }
        }

        // Return only after the drain hit `Timeout`: quitting mid-drain
        // would swallow queued transmits (notably the DCEP ACK the remote
        // offerer is waiting on to open its side of the channel).
        if let Some(id) = opened {
            return Ok(id);
        }
    }

    Err(noise.into_timeout_error())
}

/// What the handshake loop ignored while it waited, so a timeout can say
/// whether anything was arriving and from where. Tolerating a stray datagram
/// must not cost the named failure the old fail-fast gave.
#[derive(Default)]
struct HandshakeNoise {
    unparseable: usize,
    recv_errors: usize,
    last_source: Option<SocketAddr>,
}

impl HandshakeNoise {
    fn into_timeout_error(self) -> anyhow::Error {
        let base = "timed out waiting for the WebRTC data channel to open";
        match (self.unparseable, self.recv_errors) {
            (0, 0) => anyhow::anyhow!("{base}"),
            (unparseable, errors) => {
                let from = self.last_source.map_or_else(
                    || String::from("no source recorded"),
                    |src| format!("last from {src}"),
                );
                anyhow::anyhow!(
                    "{base}; ignored {unparseable} unparseable datagrams ({from}) \
                     and {errors} receive errors"
                )
            }
        }
    }
}

enum SessionEnd {
    Closed(&'static str),
    Failed(anyhow::Error),
}

/// Per-session driver: pumps the sans-io `Rtc` between its UDP socket, the
/// bounded outbound queue, and the shared inbound fan-in until the channel
/// closes or ICE gives up, then removes itself from the registry.
pub(crate) async fn drive_session(
    session: NegotiatedSession,
    remote: EndpointId,
    generation: u64,
    registry: Arc<SessionRegistry>,
    mut out_rx: mpsc::Receiver<Bytes>,
    in_tx: mpsc::Sender<InboundPacket>,
    dropped_rx: Arc<AtomicU64>,
) {
    let NegotiatedSession {
        mut rtc,
        socket,
        channel_id,
        advertised,
    } = session;
    let mut buf = vec![0u8; 2000];
    let mut next_wake = Instant::now();
    let mut consecutive_recv_errors: usize = 0;

    let end = loop {
        let sleep_for = next_wake
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1))
            .min(Duration::from_millis(100));

        tokio::select! {
            () = tokio::time::sleep(sleep_for) => {
                if let Err(error) = rtc.handle_input(Input::Timeout(Instant::now())) {
                    break SessionEnd::Failed(error.into());
                }
            }
            received = socket.recv_from(&mut buf) => {
                // A single receive error must not tear down a working session:
                // this is the socket the STUN gather shares, and Windows
                // reports an ICMP port-unreachable from a dead server as one.
                // A *persistent* error still ends the session, since a socket
                // that never reads again is not one to keep pumping.
                let (len, src) = match received {
                    Ok(pair) => {
                        consecutive_recv_errors = 0;
                        pair
                    }
                    Err(error) => {
                        consecutive_recv_errors += 1;
                        if consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                            break SessionEnd::Failed(anyhow::Error::new(error).context(
                                "session UDP socket failed repeatedly",
                            ));
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                if len == 0 {
                    continue;
                }
                let Ok(receive) = Receive::new(Protocol::Udp, src, advertised, &buf[..len]) else {
                    continue;
                };
                if let Err(error) = rtc.handle_input(Input::Receive(Instant::now(), receive)) {
                    break SessionEnd::Failed(error.into());
                }
            }
            outbound = out_rx.recv() => {
                let Some(datagram) = outbound else {
                    // Detached. Close DTLS so the far side ends its session
                    // now, not when ICE consent times out. (str0m's data
                    // channel close is local only: it sends no reset.)
                    let _ = rtc.close();
                    flush_transmits(&mut rtc, &socket).await;
                    break SessionEnd::Closed("detached");
                };
                if let Some(mut channel) = rtc.channel(channel_id) {
                    // One QUIC datagram = one binary SCTP message; boundaries
                    // are preserved end to end, so no framing header.
                    if channel.write(true, &datagram).is_err() {
                        // The channel refused the write (e.g. buffer full or
                        // closing): drop the datagram, QUIC retransmits.
                        let total = dropped_rx.fetch_add(1, Ordering::Relaxed) + 1;
                        super::session::note_dropped(&remote, total, "channel write refused");
                    }
                }
            }
        }

        match pump_outputs(&mut rtc, &socket, channel_id, remote, &in_tx).await {
            Ok(wake) => next_wake = wake,
            Err(end) => break end,
        }
    };

    match end {
        SessionEnd::Closed(reason) => {
            tracing::debug!(%remote, reason, "webrtc session closed");
        }
        SessionEnd::Failed(error) if closed_by_peer(&error) => {
            tracing::debug!(%remote, "webrtc session closed by the peer: {error:#}");
        }
        SessionEnd::Failed(error) => {
            tracing::warn!(%remote, "webrtc session failed: {error:#}");
        }
    }
    let dropped_total = dropped_rx.load(Ordering::Relaxed);
    if dropped_total > 0 {
        tracing::info!(%remote, dropped_total, "webrtc session dropped datagrams over its lifetime");
    }
    registry.remove_if_generation(&remote, generation);
}

/// Whether a session "failure" is the far side closing DTLS, which is how a
/// detach there reaches us. str0m surfaces it as an error from its DTLS crate
/// (dimpl's `ConnectionClosed`, rendered "connection closed"), which is not a
/// dependency of ours to match on, hence the text. A str0m or dimpl bump that
/// changes the text only turns this debug line back into a warning.
fn closed_by_peer(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains("connection closed")
}

/// Send everything str0m has queued, ignoring events: after a local close the
/// channel's own close event comes first, and [`pump_outputs`] would stop
/// there, before the reset that tells the far side.
async fn flush_transmits(rtc: &mut Rtc, socket: &UdpSocket) {
    while let Ok(output) = rtc.poll_output() {
        match output {
            Output::Timeout(_) => return,
            Output::Transmit(transmit) => {
                let _ = socket
                    .send_to(&transmit.contents, transmit.destination)
                    .await;
            }
            Output::Event(_) => {}
        }
    }
}

async fn pump_outputs(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    channel_id: ChannelId,
    remote: EndpointId,
    in_tx: &mpsc::Sender<InboundPacket>,
) -> Result<Instant, SessionEnd> {
    loop {
        let output = rtc
            .poll_output()
            .map_err(|error| SessionEnd::Failed(error.into()))?;
        match output {
            Output::Timeout(wake) => return Ok(wake),
            Output::Transmit(transmit) => {
                let _ = socket
                    .send_to(&transmit.contents, transmit.destination)
                    .await;
            }
            Output::Event(Event::ChannelData(data)) if data.id == channel_id => {
                let packet = InboundPacket {
                    from: remote,
                    payload: Bytes::from(data.data),
                };
                // Lossy on overflow, like the UDP it stands in for.
                let _ = in_tx.try_send(packet);
            }
            Output::Event(Event::ChannelClose(id)) if id == channel_id => {
                return Err(SessionEnd::Closed("data channel closed"));
            }
            Output::Event(Event::IceConnectionStateChange(IceConnectionState::Disconnected)) => {
                return Err(SessionEnd::Closed("ICE disconnected"));
            }
            Output::Event(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChannelReadyTarget, HandshakeNoise, bind_ephemeral_udp, build_rtc,
        drive_until_channel_ready,
    };
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;

    #[test]
    fn a_quiet_timeout_says_only_that_it_timed_out() {
        let text = HandshakeNoise::default().into_timeout_error().to_string();
        assert!(text.contains("timed out"), "{text}");
        assert!(
            !text.contains("unparseable"),
            "nothing was ignored, so nothing should be reported: {text}"
        );
    }

    #[test]
    fn a_noisy_timeout_reports_what_it_ignored() {
        // Tolerating stray datagrams must not cost the diagnosis the old
        // fail-fast gave: a timeout has to say something was arriving.
        let noise = HandshakeNoise {
            unparseable: 3,
            recv_errors: 1,
            last_source: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9999))),
        };
        let text = noise.into_timeout_error().to_string();
        assert!(text.contains("timed out"), "{text}");
        assert!(text.contains('3') && text.contains("unparseable"), "{text}");
        assert!(text.contains("127.0.0.1:9999"), "{text}");
    }

    #[tokio::test]
    async fn a_stray_datagram_does_not_abort_the_handshake() {
        // The socket is reachable by anything that can route to the host
        // candidate we put in the SDP, so one garbage packet from a scanner
        // used to kill a negotiation that was otherwise fine.
        let (socket, advertised) = bind_ephemeral_udp().await.expect("bind media socket");
        // The socket binds to the wildcard address, so reach it on loopback
        // rather than the 0.0.0.0 that `local_addr` reports.
        let local = SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            socket.local_addr().expect("local addr").port(),
        ));
        let mut rtc = build_rtc(Instant::now());

        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind sender");
        let noise = tokio::spawn(async move {
            for _ in 0..5u8 {
                let _ = sender.send_to(&[0xFF; 32], local).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        let started = Instant::now();
        let outcome = drive_until_channel_ready(
            &mut rtc,
            &socket,
            advertised,
            &ChannelReadyTarget::Answerer,
            Duration::from_millis(400),
        )
        .await;
        let elapsed = started.elapsed();
        noise.abort();

        let error = outcome.expect_err("no channel can open without a peer");
        let text = error.to_string();
        assert!(
            text.contains("timed out"),
            "a stray datagram must not end the handshake early: {text}"
        );
        assert!(
            elapsed >= Duration::from_millis(300),
            "the loop returned after {elapsed:?}, so it bailed rather than waiting"
        );
        assert!(
            text.contains("unparseable"),
            "the timeout must name what it ignored: {text}"
        );
    }
}
