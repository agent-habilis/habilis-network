//! Which ICE URLs may reach a browser's `RTCPeerConnection`.
//!
//! At the crate root, always compiled, for the reason `registry.rs` gives: the
//! browser backend cannot be tested at all (no `RTCPeerConnection` in node, no
//! webdriver in CI), so the decisions it depends on live out here where
//! `cargo test` reaches them whatever features are on.
//!
//! # TURN is disabled by policy
//!
//! This project relays through its **own iroh relay**, not through TURN. Both
//! do the same job — carry bytes when peers cannot reach each other directly —
//! and running two relay systems at different layers means operating two things
//! to solve one problem, one of which was a third party's demo service.
//!
//! So `turn:` and `turns:` are rejected here rather than merely left
//! unconfigured. "No TURN server in the list" is an absence someone can undo by
//! accident; a scheme this function refuses is a property of the build.

/// Accept `uri` for use as an ICE server, normalised, or reject it.
///
/// Two rules, and both are load-bearing:
///
/// **1. STUN only.** `turn:`/`turns:` are refused — see the module note. STUN
/// is pure address discovery: it tells a peer its own reflexive address and
/// never carries traffic, so it costs no third-party bandwidth and creates no
/// dependency in the data plane.
///
/// **2. No query string.** That constraint is Safari's, not the RFC's. RFC 7065
/// permits `?transport=udp|tcp`, Chrome accepts it, and credential services
/// emit it routinely — but `WebKit` throws on *any* query. Measured in Safari 26,
/// one server per `RTCPeerConnection`:
///
/// ```text
/// stun:example.com:3478                  OK
/// stun:example.com:3478?transport=udp    SyntaxError: Invalid STUN URL
/// turn:example.com:3478                  OK
/// turn:example.com:3478?transport=udp    SyntaxError: Invalid TURN URL query string
/// ```
///
/// The throw comes from the *constructor*, so one bad URI costs the whole peer
/// connection rather than that one server — which is how a bad entry leaves a
/// browser with no WebRTC at all, quietly falling back to the relay. A `stun:`
/// query is meaningless anyway (RFC 7064 defines none), so it is stripped
/// rather than dropped: that recovers the server the caller meant.
#[must_use]
pub fn accept_ice_uri(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once(':')?;
    // TURN is refused, not merely absent.
    if !matches!(scheme, "stun" | "stuns") || rest.is_empty() {
        return None;
    }
    let Some((host, _query)) = rest.split_once('?') else {
        return Some(uri.to_owned());
    };
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}:{host}"))
}

#[cfg(test)]
mod tests {
    use super::accept_ice_uri;

    #[test]
    fn accepts_stun() {
        for uri in [
            "stun:stun1.l.google.com:19302",
            "stun:stun.cloudflare.com:3478",
            "stuns:example.com:5349",
            "stun:example.com",
        ] {
            assert_eq!(accept_ice_uri(uri).as_deref(), Some(uri), "{uri}");
        }
    }

    #[test]
    fn refuses_turn_by_policy() {
        // Not "we happen to configure none" — the scheme cannot get through.
        for uri in [
            "turn:example.com:3478",
            "turns:example.com:5349",
            "turn:167.235.241.140:3478?transport=udp",
            "turns:example.com:5349?transport=tcp",
        ] {
            assert_eq!(accept_ice_uri(uri), None, "{uri} must be refused");
        }
    }

    #[test]
    fn strips_a_query_safari_would_throw_on() {
        // RFC 7064 gives `stun:` no query at all, so this is meaningless rather
        // than merely redundant — stripping recovers the intended server.
        assert_eq!(
            accept_ice_uri("stun:example.com:3478?transport=udp").as_deref(),
            Some("stun:example.com:3478")
        );
    }

    #[test]
    fn refuses_junk() {
        for uri in [
            "",
            "example.com:3478",
            "http://example.com",
            "https://turn.example.com/?service=turn",
            "stun:",
            "stun",
            "stun:?transport=udp",
        ] {
            assert_eq!(accept_ice_uri(uri), None, "{uri}");
        }
    }
}
