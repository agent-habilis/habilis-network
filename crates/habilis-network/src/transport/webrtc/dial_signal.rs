//! Dialling a peer over the signalling plane.

use super::consts::MESH_WEBRTC_SIGNAL_ALPN;
use super::ice_profile::IceProfile;
use super::signal_deadlines::SignalDeadlines;
use super::web_rtc_signal_acceptor;

use anyhow::Result;
use habilis_network_iroh_webrtc_transport::{SignalEnvelope, WebRtcHandle};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::{Endpoint, EndpointAddr};

use crate::transport::LOG_TARGET;

use crate::lookup::EndpointError;

/// Offer a session to `peer` and attach it. The caller decides *whether* to
/// dial (see the role rule in `lifecycle`); this only performs the exchange.
///
/// # Errors
/// The signalling dial fails, the peer refuses, or the negotiation does not
/// complete before the deadline.
pub async fn dial_signal(
    endpoint: &Endpoint,
    book: &MemoryLookup,
    peer: EndpointAddr,
    handle: &WebRtcHandle,
    ice: IceProfile,
) -> Result<(), EndpointError> {
    Box::pin(dial_signal_with(
        endpoint,
        book,
        peer,
        handle,
        SignalDeadlines::DEFAULT,
        ice,
    ))
    .await
}

/// [`dial_signal`] with the deadlines spelled out, so tests need not wait them.
///
/// # Errors
/// As [`dial_signal`].
pub(crate) async fn dial_signal_with(
    endpoint: &Endpoint,
    book: &MemoryLookup,
    peer: EndpointAddr,
    handle: &WebRtcHandle,
    deadlines: SignalDeadlines,
    ice: IceProfile,
) -> Result<(), EndpointError> {
    // Bounded as a whole, because every step below can hang and only some of
    // them have a budget of their own. Nothing here was bounded before: the old
    // `JSEP_DEADLINE` wrapped only `complete()`, which runs *after* the answer
    // is read — so a peer that accepted our connection and then stalled before
    // writing kept this future alive for the life of the process, and its QUIC
    // keep-alives meant the connection never idled out either.
    let remote = peer.id;
    match n0_future::time::timeout(
        deadlines.round,
        // Boxed for the same reason `answer_one` is: the pending session state
        // is large, and this future is held across a spawn.
        Box::pin(dial_signal_round(
            endpoint, book, peer, handle, deadlines, ice,
        )),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(EndpointError::internal(anyhow::anyhow!(
            "webrtc signalling with {remote} exceeded {:?}",
            deadlines.round
        ))),
    }
}

pub(crate) async fn dial_signal_round(
    endpoint: &Endpoint,
    book: &MemoryLookup,
    peer: EndpointAddr,
    handle: &WebRtcHandle,
    deadlines: SignalDeadlines,
    ice: IceProfile,
) -> Result<(), EndpointError> {
    let remote = peer.id;
    let local = endpoint.id();

    // Built before the dial, not after: the answerer's `accept_bi` returns as
    // soon as our stream opens, and it then sits through our whole gathering
    // budget waiting to read. Gathering first shortens its read window by
    // several seconds and costs us nothing.
    let offer = super::build_offer(local, handle, ice)
        .await
        .map_err(EndpointError::internal)?;

    // The connect holds the peer's slot like every later step does, and an id that nobody serves
    // never answers it: without its own bound the round lives to the round deadline.
    let conn = match n0_future::time::timeout(
        deadlines.exchange,
        endpoint.connect(peer, MESH_WEBRTC_SIGNAL_ALPN),
    )
    .await
    {
        Ok(conn) => conn.map_err(|error| {
            EndpointError::internal(
                anyhow::Error::new(error).context("dial the mesh WebRTC signal ALPN"),
            )
        })?,
        Err(_elapsed) => {
            return Err(EndpointError::internal(anyhow::anyhow!(
                "dial of the mesh WebRTC signal ALPN of {remote} exceeded {:?}",
                deadlines.exchange
            )));
        }
    };

    // Any step of the exchange can be the one that trips over a refusal: a peer
    // at its cap closes as soon as it sees the connection, often before our
    // offer is even written. Consulting the close reason once, on whichever step
    // noticed, is what makes the refusal visible — checking it on only the
    // timeout branch missed every prompt refusal, which is all of them.
    let offer_bytes = serde_json::to_vec(offer.envelope())
        .map_err(|error| EndpointError::Internal(error.into()))?;
    let raw =
        match web_rtc_signal_acceptor::exchange_envelopes(&conn, &offer_bytes, remote, deadlines)
            .await
        {
            Ok(raw) => raw,
            Err(error) => return Err(web_rtc_signal_acceptor::with_refusal(&conn, error, remote)),
        };
    let answer: SignalEnvelope = serde_json::from_slice(&raw).map_err(|error| {
        EndpointError::internal(anyhow::Error::new(error).context("parse signal answer"))
    })?;

    offer
        .with_answer(answer)
        .complete(remote, handle)
        .await
        .map_err(EndpointError::internal)?;
    web_rtc_signal_acceptor::register_session_addr(book, remote);
    // Signalling is done the moment the session is attached; the data rides its
    // own connections from here.
    conn.close(0u32.into(), b"jsep done");
    tracing::debug!(target: LOG_TARGET, %remote, "webrtc session attached (offerer)");
    Ok(())
}
