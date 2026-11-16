use habilis_network_iroh_webrtc_transport::WEBRTC_TRANSPORT_ID;
use habilis_network_iroh_webrtc_transport::iroh::TransportAddr;

/// `host (192.168.1.4)`, or just `host` when the browser withholds the address.
pub(crate) fn candidate(address: &str, kind: &str) -> String {
    if address.is_empty() {
        kind.to_owned()
    } else {
        format!("{kind} ({address})")
    }
}

pub(crate) fn label_of(address: &TransportAddr) -> String {
    match address {
        TransportAddr::Custom(custom) if custom.id() == WEBRTC_TRANSPORT_ID => {
            String::from("webrtc")
        }
        TransportAddr::Custom(custom) => format!("custom({})", custom.id()),
        TransportAddr::Ip(_) => String::from("ip"),
        TransportAddr::Relay(_) => String::from("relay"),
        other => format!("{other:?}"),
    }
}

// ── framing ──────────────────────────────────────────────────────────────────
//
// The same two reads the CLI does, against the same `chat_proto` helpers. Not
// shared code only because the stream types cannot be: there is no tokio here.
