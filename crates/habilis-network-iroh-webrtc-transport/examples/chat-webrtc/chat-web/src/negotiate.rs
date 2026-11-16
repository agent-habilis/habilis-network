use crate::js_error;
use chat_proto::{SIGNAL_ALPN, Ticket};
use habilis_network_iroh_webrtc_transport::iroh::{Endpoint, EndpointAddr, EndpointId};
use habilis_network_iroh_webrtc_transport::{
    BrowserHubTransport, IceServers, MAX_ENVELOPE_BYTES, SignalEnvelope, browser_offer,
};
use wasm_bindgen::prelude::JsValue;

/// Swap one envelope each way over the relay, and attach the session.
///
/// Vanilla ICE: candidates ride inside the SDP, so gathering must finish before
/// the offer goes out. There is no trickle message to add them later, which is
/// why this can take seconds and why the tab is told it is happening.
pub(crate) async fn negotiate(
    signalling: &Endpoint,
    ticket: &Ticket,
    local: EndpointId,
    hub: &BrowserHubTransport,
) -> Result<EndpointId, JsValue> {
    let mut room = EndpointAddr::new(ticket.id);
    if let Some(url) = ticket.relay.clone() {
        room = room.with_relay_url(url);
    }

    let connection = signalling
        .connect(room, SIGNAL_ALPN)
        .await
        .map_err(|error| js_error::err("dial the signalling lane", &error))?;
    // The TLS-proven id, not the envelope's claim.
    let remote = connection.remote_id();

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| js_error::err("open the signal stream", &error))?;

    // STUN only. TURN is refused by the transport at the enforcement point: a
    // pair that cannot ICE falls back to the iroh relay rather than to a second
    // relay at the ICE layer.
    let (pending, offer) = browser_offer(local, &IceServers::default()).await?;
    let encoded =
        serde_json::to_vec(&offer).map_err(|error| js_error::err("encode the offer", &error))?;
    send.write_all(&encoded)
        .await
        .map_err(|error| js_error::err("write the offer", &error))?;
    // `finish` is the frame boundary: one envelope per direction, delimited by
    // the end of the stream. No length prefix, unlike the chat.
    send.finish()
        .map_err(|error| js_error::err("finish the offer", &error))?;

    let raw = recv
        .read_to_end(MAX_ENVELOPE_BYTES)
        .await
        .map_err(|error| js_error::err("read the answer", &error))?;
    let answer: SignalEnvelope =
        serde_json::from_slice(&raw).map_err(|error| js_error::err("decode the answer", &error))?;
    match &answer {
        SignalEnvelope::Answer { .. } => {}
        SignalEnvelope::Offer { .. } => {
            return Err(JsValue::from_str(
                "the room sent an offer where an answer belongs",
            ));
        }
        SignalEnvelope::Error { reason, .. } => {
            return Err(JsValue::from_str(&format!("the room refused: {reason}")));
        }
        _ => {
            return Err(JsValue::from_str(
                "the room sent an envelope this client does not know",
            ));
        }
    }

    let session = pending.complete(hub, &answer).await?;
    if session.remote != remote {
        return Err(JsValue::from_str(
            "the answer was signed by a different endpoint than the connection",
        ));
    }

    connection.close(0u32.into(), b"jsep done");
    Ok(remote)
}
