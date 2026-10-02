//! `chat-native join` — a terminal peer, optionally over WebRTC.
//!
//! Two modes, and the contrast between them is half the demo:
//!
//! - **default** — dial the room over iroh's own transports. This is what a
//!   native peer should normally do, and what the WebRTC path is measured
//!   against.
//! - **`--webrtc`** — do exactly what a browser tab does: swap JSEP over the
//!   relay, then dial the room on an address that names only the WebRTC
//!   transport. It exists so the transport can be exercised end to end with no
//!   browser in the loop.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use chat_proto::{CHAT_ALPN, ClientMsg, ServerMsg, Ticket};
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{Connection, presets};
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr,
};
use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport, custom_addr};
use tokio::sync::mpsc;

use crate::{ice_config, path, signal, terminal, wire};

const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many unrendered messages to buffer between the reader task and the
/// terminal loop.
const INBOX_CAPACITY: usize = 64;

pub async fn run(ticket: &str, nick: &str, webrtc: bool, host_ice: bool) -> Result<()> {
    let ticket = Ticket::decode(ticket).context("decode the ticket")?;
    let relay_mode = match ticket.relay.clone() {
        Some(url) => RelayMode::custom([url]),
        None => RelayMode::Default,
    };
    let mut room_addr = EndpointAddr::new(ticket.id);
    if let Some(url) = ticket.relay.clone() {
        room_addr = room_addr.with_relay_url(url);
    }

    // One key, however many endpoints. The room keys its roster, its registry
    // and its TLS by endpoint id, so a second identity would arrive as a second
    // stranger.
    let key = SecretKey::generate();
    let id = key.public();

    // Held so it can be closed at the end; `None` outside `--webrtc`.
    let mut signal_endpoint = None;

    let (endpoint, target) = if webrtc {
        let transport = WebRtcTransport::new(id);
        let handle = WebRtcHandle::new(Arc::clone(&transport));

        // The signalling endpoint: relay on, WebRTC absent. Its only job is to
        // reach the room and swap one envelope each way.
        let signalling = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .relay_mode(relay_mode)
            .bind()
            .await
            .context("bind the signalling endpoint")?;
        if tokio::time::timeout(ONLINE_TIMEOUT, signalling.online())
            .await
            .is_err()
        {
            println!("* no relay reached in {ONLINE_TIMEOUT:?}; the JSEP dial may fail");
        }

        println!("* negotiating a data channel over the relay…");
        // Boxed for the same reason the answering side is: the str0m state this
        // future carries is large enough that clippy asks for the heap.
        Box::pin(signal::dial(
            &signalling,
            room_addr,
            id,
            &handle,
            &ice_config(host_ice),
        ))
        .await
        .context("negotiate a WebRTC session")?;
        println!("* data channel up");
        signal_endpoint = Some(signalling);

        // A *second* endpoint for the chat, on the same key, carrying nothing
        // but the WebRTC transport (`preset()` is Minimal with the IP and relay
        // transports and the address lookup cleared).
        //
        // Why not reuse the one above: iroh only fans a connect's Initial out
        // to candidate paths while the remote has no selected path, so a live
        // connection cannot be upgraded onto a transport attached after it. An
        // endpoint that still holds a relay would settle the chat dial there
        // and never move. Giving the chat an endpoint with no other path to
        // lose to is what makes `webrtc` the answer rather than a coin flip —
        // and it is the same reason a browser tab needs two endpoints.
        let chat = Endpoint::builder(transport.preset())
            .secret_key(key)
            .bind()
            .await
            .context("bind the chat endpoint")?;

        // Addressed by the identity alone: the WebRTC address convention
        // derives from the endpoint id, so both sides already know it once a
        // session exists.
        let target =
            EndpointAddr::from_parts(ticket.id, [TransportAddr::Custom(custom_addr(ticket.id))]);
        (chat, target)
    } else {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(relay_mode)
            .bind()
            .await
            .context("bind the endpoint")?;
        if tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online())
            .await
            .is_err()
        {
            println!("* no relay reached in {ONLINE_TIMEOUT:?}; trying anyway");
        }
        (endpoint, room_addr)
    };

    let connection = endpoint
        .connect(target, CHAT_ALPN)
        .await
        .context("dial the room")?;
    println!(
        "* connected over {}",
        path::settled_label(&connection).await
    );

    let outcome = chat(&connection, nick).await;

    connection.close(0u32.into(), b"bye");
    endpoint.close().await;
    if let Some(signalling) = signal_endpoint {
        signalling.close().await;
    }
    outcome
}

async fn chat(connection: &Connection, nick: &str) -> Result<()> {
    let (mut send, mut recv) = connection.open_bi().await.context("open the chat stream")?;

    wire::write_msg(
        &mut send,
        &ClientMsg::Join {
            nick: nick.to_owned(),
        },
    )
    .await
    .context("send the join")?;
    let welcome: ServerMsg = wire::read_msg(&mut recv)
        .await
        .context("read the welcome")?;
    match &welcome {
        ServerMsg::Welcome { .. } => println!("{}", terminal::render(&welcome)),
        ServerMsg::Joined { .. } | ServerMsg::Left { .. } | ServerMsg::Said { .. } => {
            bail!("the room answered the join with something else")
        }
    }

    // The reader owns the stream in a task of its own; `wire::read_msg` is two
    // reads and must never be cancelled between them.
    let (tx, incoming) = mpsc::channel::<ServerMsg>(INBOX_CAPACITY);
    tokio::spawn(async move {
        while let Ok(msg) = wire::read_msg::<ServerMsg>(&mut recv).await {
            if tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Behind a mutex only so the closure can hand an owned guard to each
    // future: `participate` awaits every `say` before reading the next line, so
    // there is never real contention.
    let send = Arc::new(tokio::sync::Mutex::new(send));
    terminal::participate(incoming, move |text| {
        let send = Arc::clone(&send);
        async move {
            let mut stream = send.lock().await;
            wire::write_msg(&mut stream, &ClientMsg::Say { text }).await
        }
    })
    .await
}
