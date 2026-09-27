//! Whether a connection's data is on a direct path right now, and whether the
//! mesh's transport policy lets payload ride it.
//!
//! iroh keeps every path it has to a peer open and picks one to carry data;
//! the relay path is never closed, only demoted. So "is this peer relayed" is
//! a question about the *selected* path, not about which paths exist —
//! `gossip::conn_path` answers the latter, for diagnostics.

use std::time::Duration;

use futures_util::StreamExt as _;
use iroh::endpoint::Connection;

use super::LOG_TARGET;

/// How long a hold waits for iroh to select a non-relay path. Hole punching
/// starts as soon as the connection has both sides' candidates, and a first
/// round lands within seconds; a punch that has not landed by now is
/// retried later rather than waited on.
pub const PROBE_DEADLINE: Duration = Duration::from_secs(15);

/// Close code an inbound gossip connection gets when the relay is lookup
/// only and no direct path was selected within the deadline. Distinct from
/// the blob lane's code so a log reader can tell the two refusals apart.
pub(crate) const GOSSIP_RELAY_REFUSED_CODE: u32 = 4;

/// Whether iroh's selected path to the remote is not the relay: a direct UDP
/// path, or a custom transport (`WebRTC`, multihop), which is peer to peer as
/// far as the relay is concerned. `false` while no path is selected yet.
pub(crate) fn selected_is_direct(conn: &Connection) -> bool {
    conn.paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .is_some_and(|path| !path.is_relay())
}

/// Whether payload may go out on `conn` under the mesh's transport policy.
/// With the relay allowed as a transport, anything goes — decided before the
/// path snapshot, which locks and clones. With the relay lookup only, the
/// selected path must be a proven non-relay one: "not selected yet" is
/// refused, not trusted.
pub(crate) fn payload_allowed_on(conn: &Connection, relay_transport: bool) -> bool {
    relay_transport || selected_is_direct(conn)
}

/// The refusal every payload lane reports when the relay is lookup only and
/// the only path is the relay. One string, so a log reader can grep for it.
pub(crate) const RELAY_REFUSED: &str =
    "relay-only path refused: the relay is lookup only on this mesh";

/// Wait until `conn`'s selected path is not the relay, or `deadline` passes.
/// Every path event is a reason to re-read the path list: the event's own
/// address may be stale by the time it is handled.
pub async fn wait_direct(conn: &Connection, deadline: Duration) -> bool {
    let mut events = conn.path_events();
    let proven = async {
        loop {
            if selected_is_direct(conn) {
                return true;
            }
            if events.next().await.is_none() {
                return false;
            }
        }
    };
    n0_future::time::timeout(deadline, proven)
        .await
        .unwrap_or(false)
}

/// The hold every inbound lane applies before reading a byte: with the relay
/// allowed as a transport, pass at once; otherwise wait up to `deadline` for
/// iroh to select a non-relay path, and on timeout close `conn` with
/// `close_code` so the other end reads the cause. Returns whether payload
/// may flow on `conn`.
pub async fn refuse_unless_direct(
    conn: &Connection,
    relay_transport: bool,
    deadline: Duration,
    close_code: u32,
) -> bool {
    if relay_transport || wait_direct(conn, deadline).await {
        tracing::debug!(target: LOG_TARGET, remote = %conn.remote_id(), "payload path admitted");
        return true;
    }
    // The paths iroh held at refusal time, because "which paths existed and
    // which was selected" is the whole diagnosis when a link that should
    // have gone direct did not.
    let paths: Vec<String> = conn
        .paths()
        .iter()
        .map(|path| {
            format!(
                "{:?}{}{}",
                path.remote_addr(),
                if path.is_selected() { " selected" } else { "" },
                if path.is_relay() { " relay" } else { "" },
            )
        })
        .collect();
    tracing::info!(target: LOG_TARGET, remote = %conn.remote_id(), paths = ?paths, "{RELAY_REFUSED}");
    conn.close(close_code.into(), b"relay path refused");
    false
}

/// [`refuse_unless_direct`] as a guard: waits up to `deadline` for the punch
/// a fresh connection is still making, and on refusal returns the error after
/// closing `conn` with `close_code`.
///
/// # Errors
/// The relay is lookup only and no direct path was selected on `conn` within
/// `deadline`.
#[cfg(feature = "blob")]
pub(crate) async fn refuse_relayed(
    conn: &Connection,
    relay_transport: bool,
    deadline: Duration,
    close_code: u32,
) -> anyhow::Result<()> {
    if refuse_unless_direct(conn, relay_transport, deadline, close_code).await {
        return Ok(());
    }
    anyhow::bail!("{RELAY_REFUSED}")
}
