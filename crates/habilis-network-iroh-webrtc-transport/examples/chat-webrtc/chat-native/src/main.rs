//! A chat room over iroh, reachable from a terminal and from a browser tab.
//!
//! The room is a native process. Peers join it from a terminal (this binary,
//! `join`) or from a tab (`chat-web`, next door). Every peer↔room link is one
//! QUIC connection; a tab's rides a `WebRTC` data channel, which is the thing
//! this example exists to show.
//!
//! There is no signalling server. The iroh relay two peers already use to find
//! each other carries the JSEP exchange on an ALPN of its own, and the data
//! channel that produces carries everything after — see [`signal`].
//!
//! Run `chat-native host`, then follow the two lines it prints.

mod host;
mod join;
mod path;
mod room;
mod serve;
mod signal;
mod terminal;
mod wire;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use habilis_network_iroh_webrtc_transport::IceConfig;
use habilis_network_iroh_webrtc_transport::iroh_base::RelayUrl;

#[derive(Debug, Parser)]
#[command(
    name = "chat-native",
    version,
    about = "A chat room over iroh and WebRTC"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Open a room, and join it from this terminal.
    Host {
        /// The name to appear under. Collisions are resolved by the room.
        #[arg(long, default_value = "host")]
        nick: String,
        /// Use this relay instead of the default ladder.
        #[arg(long)]
        relay: Option<RelayUrl>,
        /// Gather host ICE candidates only — no STUN.
        ///
        /// Skips a round trip that has nothing to answer it when there is no
        /// internet. Reaches the same machine and a flat LAN, nothing else.
        #[arg(long)]
        host_ice: bool,
    },
    /// Join a room from this terminal.
    Join {
        /// The ticket the room printed.
        ticket: String,
        #[arg(long)]
        nick: String,
        /// Reach the room over a `WebRTC` data channel, exactly as a tab does.
        ///
        /// Off by default: a native peer should prefer iroh's own transports,
        /// which are faster. This is here so the WebRTC path can be exercised
        /// end to end without a browser.
        #[arg(long)]
        webrtc: bool,
        /// See `host --host-ice`.
        #[arg(long)]
        host_ice: bool,
    },
}

/// STUN, or not.
///
/// Shared by both roles so a `--host-ice` room and a `--host-ice` peer cannot
/// mean different things.
pub(crate) fn ice_config(host_ice: bool) -> IceConfig {
    if host_ice {
        IceConfig::host_only()
    } else {
        IceConfig::default()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Quiet unless asked: `RUST_LOG=chat_native=debug,habilis_network_iroh_webrtc_transport=debug`
    // is the interesting setting when a negotiation misbehaves.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Host {
            nick,
            relay,
            host_ice,
        } => host::run(&nick, relay, host_ice)
            .await
            .context("host a room"),
        Command::Join {
            ticket,
            nick,
            webrtc,
            host_ice,
        } => join::run(&ticket, &nick, webrtc, host_ice)
            .await
            .context("join a room"),
    }
}
