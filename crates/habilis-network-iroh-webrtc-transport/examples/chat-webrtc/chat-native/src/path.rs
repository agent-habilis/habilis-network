//! Which transport is actually carrying a connection.
//!
//! The whole demo is this label. "It connected" proves nothing — a peer that
//! silently fell back to the relay connects perfectly well, and looks identical
//! from the chat's point of view. Printing the selected path is what turns the
//! example into evidence.

use std::time::Duration;

use habilis_network_iroh_webrtc_transport::WEBRTC_TRANSPORT_ID;
use habilis_network_iroh_webrtc_transport::iroh::TransportAddr;
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{Connection, Path};

/// The label a settled `webrtc` path reports. Compared against rather than
/// spelled out at each site, since the UI and the tests both key off it.
pub const WEBRTC: &str = "webrtc";

/// How long to let path selection settle before believing the answer.
///
/// Reading `paths()` the instant `connect` returns reports a race, not a
/// result: the handshake completes on whichever path answered first and the
/// selector may move it moments later. Three seconds is well past that, and
/// short enough that a peer which is never going to move does not look hung.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(3);
const SETTLE_POLL: Duration = Duration::from_millis(100);

/// The selected path's label, once it has settled — or after
/// [`SETTLE_TIMEOUT`], whatever it is by then.
///
/// Resolves early the moment the answer is `webrtc`, since that is the one
/// outcome that will not change for the better.
pub async fn settled_label(connection: &Connection) -> String {
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        let label = selected_label(connection);
        if label == WEBRTC || tokio::time::Instant::now() >= deadline {
            return label;
        }
        tokio::time::sleep(SETTLE_POLL).await;
    }
}

/// The selected path's label right now.
#[must_use]
pub fn selected_label(connection: &Connection) -> String {
    let paths = connection.paths();
    let Some(selected) = paths.iter().find(Path::is_selected) else {
        return "none".to_owned();
    };
    label_of(selected.remote_addr())
}

fn label_of(addr: &TransportAddr) -> String {
    match addr {
        TransportAddr::Custom(custom) if custom.id() == WEBRTC_TRANSPORT_ID => WEBRTC.to_owned(),
        // A different custom transport is not a case this example produces, but
        // saying which one beats reporting "custom" and leaving the reader to
        // guess whether it was ours.
        TransportAddr::Custom(custom) => format!("custom({})", custom.id()),
        TransportAddr::Ip(_) => "ip".to_owned(),
        TransportAddr::Relay(_) => "relay".to_owned(),
        other => format!("{other:?}"),
    }
}
