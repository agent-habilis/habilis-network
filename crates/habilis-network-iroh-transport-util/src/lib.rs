//! The two pieces both custom iroh transports need and neither can host.
//!
//! `habilis-network-iroh-webrtc-transport` and `habilis-network-iroh-multihop-transport` are
//! deliberately standalone: neither depends on the other, and neither depends
//! on `habilis-network-util` — so a shared helper has nowhere else to live.
//!
//! That is the whole justification for a crate this small. Unlike the two
//! crates recently folded back into `habilis-network-protocol`, this one is not
//! isolating a dependency it could have inherited; it exists because there is
//! no other sharing point between two otherwise-independent crates. It adds no
//! external dependency — `iroh` is already in both manifests.
//!
//! # Example
//!
//! ```
//! use habilis_network_iroh_transport_util::split_segments;
//!
//! let segments: Vec<&[u8]> = split_segments(b"abcdef", Some(4)).collect();
//! assert_eq!(segments, [&b"abcd"[..], &b"ef"[..]], "the last segment holds the rest");
//! ```

mod protocol_set;
mod rung;

pub use protocol_set::ProtocolSet;

pub use rung::{
    GOSSIP_TRANSPORT_ID, MULTIHOP_TRANSPORT_ID, Rung, WEBRTC_TRANSPORT_ID, best_of, blocked, climb,
    custom_rung, datagrams, expected_rung, ip_remote, remote_id, remote_id_of, rung_of,
    split_segments,
};
#[cfg(feature = "test-hooks")]
pub use rung::{block_ip_paths, block_ip_to, block_rung, block_rung_to, is_blocked, is_blocked_to};
#[cfg(not(feature = "test-hooks"))]
pub use rung::{is_blocked, is_blocked_to};

#[cfg(test)]
mod tests {
    use super::{
        GOSSIP_TRANSPORT_ID, MULTIHOP_TRANSPORT_ID, Rung, WEBRTC_TRANSPORT_ID, block_ip_to,
        block_rung, block_rung_to, custom_rung, expected_rung, is_blocked, is_blocked_to,
        remote_id_of, split_segments,
    };
    use iroh::endpoint::transports::Addr;

    #[test]
    fn the_ladder_runs_from_ip_to_the_relay() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            Rung::LADDER.is_sorted(),
            "the declaration order is the ladder"
        );
        assert!(
            Rung::Ip < Rung::WebRtc,
            "the ip rung sits before the webrtc rung"
        );
        assert!(Rung::WebRtc < Rung::Multihop, "multihop is below WebRTC");
        assert!(Rung::Multihop < Rung::Gossip, "gossip is below multihop");
        assert!(Rung::Gossip < Rung::Relay, "the relay is below gossip");
        assert!(Rung::Relay < Rung::Other, "a foreign transport is last");
    }

    /// The pure ladder: over every set of allowed rungs and every set of
    /// available ones, the node stands on the best rung in both. The order is
    /// written out here and not read from `LADDER`, so that a rung missing from
    /// `LADDER` fails this test.
    #[test]
    fn the_expected_rung_is_the_best_rung_that_is_allowed_and_available() {
        const ORDER: [Rung; 6] = [
            Rung::Ip,
            Rung::WebRtc,
            Rung::Multihop,
            Rung::Gossip,
            Rung::Relay,
            Rung::Other,
        ];
        let set = |mask: u8| move |rung: Rung| mask >> (rung as u8) & 1 == 1;
        for allowed in 0..64u8 {
            for available in 0..64u8 {
                let expected = ORDER
                    .into_iter()
                    .find(|&rung| set(allowed)(rung) && set(available)(rung));
                assert_eq!(
                    expected_rung(set(allowed), set(available)),
                    expected,
                    "allowed {allowed:#08b}, available {available:#08b}"
                );
            }
        }

        let _guard = ::habilis_network_test_tracing::init();
    }

    /// One function names the rung of a custom transport id, for every selector.
    #[test]
    fn a_custom_transport_id_names_its_rung() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            custom_rung(WEBRTC_TRANSPORT_ID),
            Rung::WebRtc,
            "the webrtc transport id names the webrtc rung"
        );
        assert_eq!(
            custom_rung(MULTIHOP_TRANSPORT_ID),
            Rung::Multihop,
            "the multihop transport id names the multihop rung"
        );
        assert_eq!(
            custom_rung(GOSSIP_TRANSPORT_ID),
            Rung::Gossip,
            "the gossip transport id names the gossip rung"
        );
        assert_eq!(custom_rung(0x1234), Rung::Other, "a foreign id is last");
    }

    #[test]
    fn the_expected_rung_reads_as_the_ladder_does() {
        let _guard = ::habilis_network_test_tracing::init();
        let all = |_: Rung| true;
        let only = |rungs: &'static [Rung]| move |rung: Rung| rungs.contains(&rung);
        assert_eq!(
            expected_rung(all, only(&[Rung::Relay, Rung::Ip])),
            Some(Rung::Ip),
            "the expected rung is the relay when the relay is the only usable rung"
        );
        assert_eq!(
            expected_rung(all, only(&[Rung::Relay, Rung::Multihop])),
            Some(Rung::Multihop),
            "the expected rung is the relay when all rungs are usable"
        );
        // A rung that policy does not allow is passed over, however good.
        assert_eq!(
            expected_rung(
                only(&[Rung::Multihop, Rung::Relay]),
                only(&[Rung::Ip, Rung::WebRtc, Rung::Relay])
            ),
            Some(Rung::Relay),
            "the expected rung is multihop when only multihop is usable"
        );
        assert_eq!(
            expected_rung(all, |_| false),
            None,
            "no rung is expected when none is usable"
        );
        assert_eq!(
            expected_rung(|_| false, all),
            None,
            "no rung is expected when none is allowed"
        );
    }

    /// A relay path and a `WebRTC` path name the endpoint they lead to in their
    /// address; an IP path and the custom path of another transport do not.
    #[test]
    fn a_relay_or_webrtc_path_names_its_remote_and_no_other_does() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = iroh::SecretKey::from_bytes(&[31; 32]).public();
        let relay: iroh::RelayUrl = "https://relay.example".parse().expect("a relay url");
        assert_eq!(
            remote_id_of(&Addr::Relay(relay, id)),
            Some(id),
            "a relay path names its remote"
        );
        let webrtc = iroh_base::CustomAddr::from_parts(WEBRTC_TRANSPORT_ID, id.as_bytes());
        assert_eq!(
            remote_id_of(&Addr::Custom(webrtc)),
            Some(id),
            "a custom webrtc path names its remote"
        );
        let foreign = iroh_base::CustomAddr::from_parts(0x1234, id.as_bytes());
        assert_eq!(
            remote_id_of(&Addr::Custom(foreign)),
            None,
            "a custom multihop path names its remote"
        );
        let ip = std::net::SocketAddr::from(([127, 0, 0, 1], 4000));
        assert_eq!(
            remote_id_of(&Addr::Ip(ip)),
            None,
            "an ip path names no remote"
        );
    }

    /// The relay rung can be taken from one remote: the block reads the endpoint id
    /// that the relay address names.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn a_relay_block_takes_the_relay_rung_to_one_remote_only() {
        let _guard = ::habilis_network_test_tracing::init();
        let (local, remote, other) = (node(32), node(33), node(34));
        let relay: iroh::RelayUrl = "https://relay.example".parse().expect("a relay url");
        let to = |id| remote_id_of(&Addr::Relay(relay.clone(), id));
        block_rung_to(local, Rung::Relay, remote, true);
        assert!(
            is_blocked_to(local, Rung::Relay, None, to(remote)),
            "a relay block takes the relay rung to one remote"
        );
        assert!(
            !is_blocked_to(local, Rung::Relay, None, to(other)),
            "another remote"
        );
        assert!(
            !is_blocked_to(local, Rung::Ip, None, to(remote)),
            "another rung"
        );
        block_rung_to(local, Rung::Relay, remote, false);
        assert!(
            !is_blocked_to(local, Rung::Relay, None, to(remote)),
            "a relay block leaves the relay rung to other remotes"
        );
    }

    #[cfg(feature = "test-hooks")]
    fn node(seed: u8) -> iroh::EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// A block on IP ports of one node leaves the others alone, whatever rung or
    /// port they ask about.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn an_ip_port_block_takes_one_port_of_the_ip_rung_from_one_node() {
        let _guard = ::habilis_network_test_tracing::init();
        let (blocked, other) = (node(11), node(12));
        let at = |port: u16| Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        block_ip_to(blocked, [4000, 4001]);
        assert!(
            is_blocked(blocked, Rung::Ip, at(4000)),
            "an ip port block takes one port of the ip rung"
        );
        assert!(
            is_blocked(blocked, Rung::Ip, at(4001)),
            "an ip port block takes that port from the node"
        );
        assert!(!is_blocked(blocked, Rung::Ip, at(4002)), "another port");
        assert!(!is_blocked(other, Rung::Ip, at(4000)), "another node");
        assert!(!is_blocked(blocked, Rung::Relay, None), "another rung");
        block_ip_to(blocked, []);
        assert!(
            !is_blocked(blocked, Rung::Ip, at(4000)),
            "an empty set clears"
        );
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn a_rung_block_takes_one_whole_rung_from_one_node() {
        let _guard = ::habilis_network_test_tracing::init();
        let (blocked, other) = (node(13), node(14));
        block_rung(blocked, Rung::Multihop, true);
        assert!(
            is_blocked(blocked, Rung::Multihop, None),
            "a rung block takes the whole multihop rung from the node"
        );
        assert!(!is_blocked(blocked, Rung::WebRtc, None), "another rung");
        assert!(!is_blocked(other, Rung::Multihop, None), "another node");
        block_rung(blocked, Rung::Multihop, false);
        assert!(
            !is_blocked(blocked, Rung::Multihop, None),
            "a rung block leaves other rungs alone"
        );
    }

    /// A block of one remote takes the `WebRTC` rung from one remote only: another
    /// remote, another node, another rung and a path with no remote id are not
    /// touched.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn a_remote_block_takes_a_rung_from_one_remote_only() {
        let _guard = ::habilis_network_test_tracing::init();
        let (local, other_node) = (node(15), node(16));
        let (cut, kept) = (node(17), node(18));
        block_rung_to(local, Rung::WebRtc, cut, true);
        assert!(
            is_blocked_to(local, Rung::WebRtc, None, Some(cut)),
            "a remote block takes the webrtc rung from one remote"
        );
        assert!(
            !is_blocked_to(local, Rung::WebRtc, None, Some(kept)),
            "another remote"
        );
        assert!(
            !is_blocked_to(other_node, Rung::WebRtc, None, Some(cut)),
            "another node"
        );
        assert!(
            !is_blocked_to(local, Rung::Multihop, None, Some(cut)),
            "another rung"
        );
        assert!(
            !is_blocked_to(local, Rung::WebRtc, None, None),
            "a path that names no remote"
        );
        assert!(
            !is_blocked(local, Rung::WebRtc, None),
            "is_blocked reads no remote block"
        );
        block_rung_to(local, Rung::WebRtc, cut, false);
        assert!(
            !is_blocked_to(local, Rung::WebRtc, None, Some(cut)),
            "a remote block leaves the webrtc rung to other remotes"
        );
    }

    /// A block of the whole rung still takes it from every remote.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn a_whole_rung_block_still_takes_the_rung_from_every_remote() {
        let _guard = ::habilis_network_test_tracing::init();
        let (local, remote) = (node(19), node(20));
        block_rung(local, Rung::WebRtc, true);
        assert!(
            is_blocked_to(local, Rung::WebRtc, None, Some(remote)),
            "a whole rung block takes the rung from every remote"
        );
        block_rung(local, Rung::WebRtc, false);
        assert!(
            !is_blocked_to(local, Rung::WebRtc, None, Some(remote)),
            "a whole rung block leaves other rungs alone"
        );
    }

    /// The property the three copies disagreed on.
    #[test]
    fn an_empty_transmit_still_yields_one_datagram() {
        let _guard = ::habilis_network_test_tracing::init();
        let out: Vec<&[u8]> = split_segments(&[], None).collect();
        assert_eq!(out.len(), 1, "a keep-alive must not be dropped");
        assert!(
            out[0].is_empty(),
            "an empty transmit still yields one datagram"
        );
    }

    #[test]
    fn a_batched_transmit_splits_on_the_segment_size() {
        let _guard = ::habilis_network_test_tracing::init();
        let out: Vec<&[u8]> = split_segments(&[1, 2, 3, 4, 5], Some(2)).collect();
        assert_eq!(
            out,
            vec![&[1u8, 2][..], &[3, 4][..], &[5][..]],
            "a batched transmit splits on the segment size"
        );
    }

    #[test]
    fn an_unbatched_transmit_is_one_datagram() {
        let _guard = ::habilis_network_test_tracing::init();
        let out: Vec<&[u8]> = split_segments(&[1, 2, 3], None).collect();
        assert_eq!(
            out,
            vec![&[1u8, 2, 3][..]],
            "an unbatched transmit is one datagram"
        );
    }

    /// A zero segment size must not divide by zero or spin.
    #[test]
    fn a_zero_segment_size_is_clamped() {
        let _guard = ::habilis_network_test_tracing::init();
        let out: Vec<&[u8]> = split_segments(&[1, 2], Some(0)).collect();
        assert_eq!(
            out,
            vec![&[1u8][..], &[2][..]],
            "a zero segment size is clamped to one byte per datagram"
        );
    }
}
