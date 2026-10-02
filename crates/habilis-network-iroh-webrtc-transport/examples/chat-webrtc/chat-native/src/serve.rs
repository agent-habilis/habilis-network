//! The room, wired to a QUIC stream. One connection, one member.

use anyhow::{Result, bail};
use chat_proto::{ClientMsg, ServerMsg};
use habilis_network_iroh_webrtc_transport::WebRtcHandle;
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{Connection, SendStream};
use habilis_network_iroh_webrtc_transport::iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::mpsc;

use crate::path;
use crate::room::{Membership, Room};
use crate::wire;

/// How many unhandled inbound messages to buffer before back-pressuring the
/// reader task. Small on purpose: the only thing downstream is a broadcast
/// send, so a backlog here means the room is wedged, not busy.
const INBOX_CAPACITY: usize = 32;

/// Accepts [`chat_proto::CHAT_ALPN`] and turns each connection into a member.
#[derive(Debug, Clone)]
pub struct ChatAcceptor {
    room: Room,
    /// Only so a departing peer's session can be released — see
    /// [`ChatAcceptor::accept`].
    handle: WebRtcHandle,
}

impl ChatAcceptor {
    #[must_use]
    pub fn new(room: Room, handle: WebRtcHandle) -> Self {
        Self { room, handle }
    }
}

impl ProtocolHandler for ChatAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        // Errors are reported, not propagated: one peer's stream dying is
        // ordinary (a tab closed), and returning it would only log the same
        // thing one layer up while telling the Router something went wrong with
        // *it*.
        if let Err(error) = serve(&self.room, connection).await {
            tracing::debug!(%remote, %error, "chat connection ended");
        }
        // The session was attached by the signalling handler and would
        // otherwise sit in the registry until its driver noticed the channel
        // die — long enough that the census reports a data channel for a peer
        // that has visibly left. A peer that joined without WebRTC has no
        // session and this is a no-op.
        if self.handle.detach(&remote) {
            tracing::debug!(%remote, "released the WebRTC session");
        }
        Ok(())
    }
}

async fn serve(room: &Room, connection: Connection) -> Result<()> {
    let (mut send, mut recv) = connection.accept_bi().await?;

    let hello: ClientMsg = wire::read_msg(&mut recv).await?;
    hello.validate()?;
    let nick = match hello {
        ClientMsg::Join { nick } => nick,
        ClientMsg::Say { .. } => bail!("first frame was a message, not a join"),
    };

    let mut membership = room.join(&nick);
    // The one line this prints. Everything else about arriving and leaving
    // reaches the host through the room's own fan-out, exactly as it reaches
    // every other member; this says the thing the fan-out cannot, which is
    // *how* the peer got here.
    println!(
        "* {} connected over {}",
        membership.nick,
        path::selected_label(&connection)
    );
    wire::write_msg(
        &mut send,
        &ServerMsg::Welcome {
            you: membership.nick.clone(),
            roster: membership.roster.clone(),
        },
    )
    .await?;

    // Inbound frames get a task of their own. `wire::read_msg` reads a header
    // and then a body sized by it, so it must never be a `select!` branch — a
    // cancellation between the two leaves the stream mid-frame. An mpsc
    // receiver in its place is cancel-safe.
    let (tx, mut rx) = mpsc::channel::<ClientMsg>(INBOX_CAPACITY);
    let reader = tokio::spawn(async move {
        while let Ok(msg) = wire::read_msg::<ClientMsg>(&mut recv).await {
            if tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let outcome = pump(room, &mut membership, &mut send, &mut rx).await;

    reader.abort();
    // Dropping the membership is what announces the departure, to the host's
    // terminal along with everyone else's.
    drop(membership);
    outcome
}

async fn pump(
    room: &Room,
    membership: &mut Membership,
    send: &mut SendStream,
    rx: &mut mpsc::Receiver<ClientMsg>,
) -> Result<()> {
    loop {
        tokio::select! {
            inbound = rx.recv() => {
                let Some(msg) = inbound else { return Ok(()) };
                if let Err(error) = msg.validate() {
                    tracing::debug!(nick = %membership.nick, %error, "refused a frame");
                    continue;
                }
                match msg {
                    ClientMsg::Say { text } => room.say(membership.id, text),
                    ClientMsg::Join { .. } => bail!("a second join on one stream"),
                }
            }
            fanout = membership.next_broadcast() => {
                let Some(fanout) = fanout else { return Ok(()) };
                wire::write_msg(send, &fanout.msg).await?;
            }
        }
    }
}
