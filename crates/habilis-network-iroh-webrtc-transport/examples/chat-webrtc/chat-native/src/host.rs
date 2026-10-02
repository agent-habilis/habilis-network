//! `chat-native host` — the room, and the third participant.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use chat_proto::{CHAT_ALPN, SIGNAL_ALPN, Ticket};
use habilis_network_iroh_webrtc_transport::iroh::endpoint::presets;
use habilis_network_iroh_webrtc_transport::iroh::protocol::Router;
use habilis_network_iroh_webrtc_transport::iroh::{Endpoint, RelayMode, SecretKey};
use habilis_network_iroh_webrtc_transport::iroh_base::RelayUrl;
use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};

use crate::ice_config;
use crate::room::Room;
use crate::serve::ChatAcceptor;
use crate::signal::SignalAcceptor;
use crate::terminal;

/// How long to wait for a relay before printing a ticket anyway.
///
/// A ticket with no relay in it is still useful — a peer on the same LAN can be
/// found other ways — so a room with no internet should start and say so rather
/// than hang on a spinner.
const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often to re-read the census. Only printed when it changes.
const CENSUS_INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(nick: &str, relay: Option<RelayUrl>, host_ice: bool) -> Result<()> {
    let key = SecretKey::generate();
    let id = key.public();

    let transport = WebRtcTransport::new(id);
    let handle = WebRtcHandle::new(Arc::clone(&transport));

    let relay_mode = match relay {
        Some(url) => RelayMode::custom([url]),
        None => RelayMode::Default,
    };

    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .relay_mode(relay_mode)
        // Additive — deliberately *not* `transport.preset()`, which would make
        // WebRTC this endpoint's only transport. That is right for a browser
        // and wrong for the room: a native peer joining without `--webrtc`
        // reaches it over iroh's own transports, and should.
        .add_custom_transport(handle.transport())
        // Registering the transport is not enough on its own. iroh's default
        // selector skips paths it has no RTT sample for yet, which is every
        // freshly attached WebRTC path — so a connection would settle on the
        // relay and stay there for its whole life. This selector ranks
        // ip > webrtc > relay, which is to say: the relay is a rendezvous, not
        // a data path.
        .path_selector(handle.path_selector())
        .bind()
        .await
        .context("bind the room's endpoint")?;

    // The ticket needs a relay in it, and `addr()` only carries one once the
    // endpoint has actually reached a relay server.
    if tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online())
        .await
        .is_err()
    {
        println!("* no relay reached in {ONLINE_TIMEOUT:?}; the ticket will carry no relay");
    }

    let room = Room::new();
    let ice = ice_config(host_ice);
    let router = Router::builder(endpoint.clone())
        .accept(SIGNAL_ALPN, SignalAcceptor::new(handle.clone(), id, ice))
        .accept(CHAT_ALPN, ChatAcceptor::new(room.clone(), handle.clone()))
        .spawn();

    let ticket = Ticket {
        id,
        relay: endpoint.addr().relay_urls().next().cloned(),
    };
    banner(&ticket);

    spawn_census(room.clone(), handle);

    // The host is a member on the same terms as everyone else — same roster,
    // same fan-out, same nick collision rules. It just skips the network.
    let membership = room.join(nick);
    println!("* you are \"{}\"", membership.nick);
    // Taken before the membership moves into the drain task: `say` needs the id
    // to tag the host's own lines, which is what keeps them from echoing back.
    let host_id = membership.id;
    let incoming = terminal::from_membership(membership);
    let outcome = terminal::participate(incoming, |text| {
        let room = room.clone();
        async move {
            room.say(host_id, text);
            Ok(())
        }
    })
    .await;

    router.shutdown().await.context("shut the router down")?;
    outcome
}

/// Print the census whenever it changes.
///
/// `session_count` is the number the demo turns on: it is how many peers hold a
/// live data channel, as distinct from how many are merely in the room. A tab
/// that fell back to the relay shows up in one number and not the other.
fn spawn_census(room: Room, handle: WebRtcHandle) {
    tokio::spawn(async move {
        let mut last = None;
        loop {
            tokio::time::sleep(CENSUS_INTERVAL).await;
            let now = (room.len(), handle.session_count());
            if last != Some(now) {
                let (members, sessions) = now;
                println!(
                    "* room: {members} member{}, {sessions} webrtc session{}",
                    plural(members),
                    plural(sessions)
                );
                last = Some(now);
            }
        }
    });
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn banner(ticket: &Ticket) {
    let encoded = ticket.encode();
    println!("── the room is open ──");
    println!();
    println!("  ticket  {encoded}");
    println!();
    println!("  browser  http://localhost:3000/#{encoded}");
    println!("  native   cargo run -p chat-native -- join {encoded} --nick bob --webrtc");
    println!();
    println!("type to talk, ^D to close the room");
    println!();
}
