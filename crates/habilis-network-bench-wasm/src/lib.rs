//! One browser endpoint of the transport benchmark, as free functions a page
//! puts on `window.bench`.
//!
//! Everything crosses the JS boundary as a string: the JSEP envelopes as JSON
//! (the runner ferries them between two tabs verbatim), ids as hex, and each
//! result as a JSON object. The runner cannot await a promise through CDP, so
//! the page wraps every call in a completion flag; nothing here knows that.
//!
//! One endpoint per page, held in a thread-local: the browser is
//! single-threaded and the JSEP handles are `JsValue`s, which are neither
//! `Send` nor `Sync`.

#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;

use habilis_network_iroh_webrtc_transport::bench::{
    BENCH_ALPN, Bench, Direction, browser_endpoint, exchange, on_webrtc,
};
use habilis_network_iroh_webrtc_transport::iroh::endpoint::Connection;
use habilis_network_iroh_webrtc_transport::iroh::protocol::Router;
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr,
};
use habilis_network_iroh_webrtc_transport::{
    BrowserPendingAnswer, BrowserPendingOffer, IceServers, SignalEnvelope, WebRtcHandle,
    browser_answer, browser_offer, custom_addr,
};
use wasm_bindgen::prelude::*;

struct State {
    endpoint: Endpoint,
    hub: WebRtcHandle,
    /// Whichever side of the JSEP round this page took, until `complete`.
    pending: Pending,
    /// Kept alive for the page's lifetime: dropping it would stop accepting.
    router: Option<Router>,
    /// The client side's connection, reused by every `download` to the same
    /// peer so only the warm-up round pays the handshake and slow start.
    connection: Option<(EndpointId, Connection)>,
}

enum Pending {
    None,
    Offer(BrowserPendingOffer),
    Answer(BrowserPendingAnswer, EndpointId),
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}

fn with_state<T>(body: impl FnOnce(&mut State) -> Result<T, JsValue>) -> Result<T, JsValue> {
    STATE.with(|cell| {
        let mut state = cell.borrow_mut();
        let state = state
            .as_mut()
            .ok_or_else(|| js_error("call init() first"))?;
        body(state)
    })
}

/// Bind this page's endpoint: `WebRTC` only, no relay, so a run that claims to
/// be browser↔browser can be shown to be one. Resolves to the endpoint id.
///
/// # Errors
/// The endpoint cannot bind, or `init` was already called.
#[wasm_bindgen]
pub async fn init() -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    if STATE.with(|cell| cell.borrow().is_some()) {
        return Err(js_error("init() was already called"));
    }
    let key = SecretKey::generate();
    let id = key.public();
    let hub = WebRtcHandle::hub(id);
    let endpoint = browser_endpoint(key, &hub).await.map_err(js_error)?;
    STATE.with(|cell| {
        *cell.borrow_mut() = Some(State {
            endpoint,
            hub,
            pending: Pending::None,
            router: None,
            connection: None,
        });
    });
    Ok(id.to_string())
}

/// Start a negotiation as the offerer. Resolves to the offer envelope as
/// JSON, for the other page's `answer`.
///
/// # Errors
/// No `init`, or the browser cannot build an offer.
#[wasm_bindgen]
pub async fn offer() -> Result<String, JsValue> {
    let id = with_state(|state| Ok(state.endpoint.id()))?;
    // Host-only ICE: both pages are on this machine, and a STUN round trip
    // would measure the network rather than the transport.
    let (pending, envelope) = browser_offer(id, &IceServers::host_only()).await?;
    with_state(|state| {
        state.pending = Pending::Offer(pending);
        Ok(())
    })?;
    serde_json::to_string(&envelope).map_err(js_error)
}

/// Answer `offer_json`. Resolves to the answer envelope as JSON, for the
/// offerer's `complete`.
///
/// # Errors
/// No `init`, a malformed envelope, or the browser cannot build an answer.
#[wasm_bindgen]
pub async fn answer(offer_json: String) -> Result<String, JsValue> {
    let id = with_state(|state| Ok(state.endpoint.id()))?;
    let offer: SignalEnvelope = serde_json::from_str(&offer_json).map_err(js_error)?;
    let remote = offer.claimed_endpoint().map_err(js_error)?;
    let (pending, envelope) = browser_answer(id, &offer, &IceServers::host_only()).await?;
    with_state(|state| {
        state.pending = Pending::Answer(pending, remote);
        Ok(())
    })?;
    serde_json::to_string(&envelope).map_err(js_error)
}

/// Finish the round: the offerer applies `answer_json`, the answerer passes
/// an empty string and waits for the channel. Both attach the session.
///
/// # Errors
/// No pending round, a malformed answer, or the channel never opening.
#[wasm_bindgen]
pub async fn complete(answer_json: String) -> Result<String, JsValue> {
    let (pending, hub) = with_state(|state| {
        Ok((
            std::mem::replace(&mut state.pending, Pending::None),
            state.hub.clone(),
        ))
    })?;
    match pending {
        Pending::None => return Err(js_error("no negotiation in progress")),
        Pending::Offer(pending) => {
            let answer: SignalEnvelope = serde_json::from_str(&answer_json).map_err(js_error)?;
            pending.complete(hub.transport().as_ref(), &answer).await?;
        }
        Pending::Answer(pending, remote) => {
            pending.complete(hub.transport().as_ref(), remote).await?;
        }
    }
    Ok("ok".to_owned())
}

/// Accept bulk requests on this endpoint until the page goes away.
///
/// # Errors
/// No `init`.
#[wasm_bindgen]
pub fn serve() -> Result<String, JsValue> {
    with_state(|state| {
        if state.router.is_none() {
            let router = Router::builder(state.endpoint.clone())
                .accept(BENCH_ALPN, Bench)
                .spawn();
            state.router = Some(router);
        }
        Ok("ok".to_owned())
    })
}

async fn connection_to(remote: EndpointId) -> Result<Connection, JsValue> {
    let (endpoint, open) = with_state(|state| {
        let open = state
            .connection
            .as_ref()
            .filter(|(id, connection)| *id == remote && connection.close_reason().is_none())
            .map(|(_, connection)| connection.clone());
        Ok((state.endpoint.clone(), open))
    })?;
    if let Some(connection) = open {
        return Ok(connection);
    }
    let addr = EndpointAddr::from_parts(remote, [TransportAddr::Custom(custom_addr(remote))]);
    let connection = endpoint.connect(addr, BENCH_ALPN).await.map_err(js_error)?;
    with_state(|state| {
        state.connection = Some((remote, connection.clone()));
        Ok(())
    })?;
    Ok(connection)
}

/// One timed exchange of `bytes` in `direction` (`down`, `up`, `both`) with
/// the peer `remote` (hex id) over this page's connection to it. Resolves to
/// `{"bytes", "elapsed_ms", "path"}`: `elapsed_ms` covers the stream open
/// through the last verified byte, not the connection, and `path` is
/// `webrtc` or `other`.
///
/// # Errors
/// No `init`, a bad id or direction, or the exchange failing.
#[wasm_bindgen]
pub async fn download(remote: String, bytes: usize, direction: String) -> Result<String, JsValue> {
    let direction = Direction::from_label(&direction)
        .ok_or_else(|| js_error(format!("unknown direction {direction:?}")))?;
    let remote: EndpointId = remote.parse().map_err(js_error)?;
    let connection = connection_to(remote).await?;
    let path = if on_webrtc(&connection) {
        "webrtc"
    } else {
        "other"
    };

    let started = web_time::Instant::now();
    let received = exchange(&connection, direction, bytes)
        .await
        .map_err(js_error)?;
    let elapsed = started.elapsed();

    Ok(serde_json::json!({
        "bytes": received,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "path": path,
    })
    .to_string())
}
