//! The liveness rule of the proposer: a path that the peer never sends on does not stay selected.
//!
//! The ladder in [`climb`](crate::climb) is rung-first and has no sense of life. A path that opened
//! and then went quiet from the peer, because the peer sends on another one, still outranks a live
//! path of a lower rung, and when the two ends choose different paths both die at the idle timeout
//! of a path. This rule keeps, for each address, the datagrams received on it at the last call. An
//! address is judged by what the connection received on all its entries (one address can appear
//! more than once in the list), not by one entry and not by a rung.
//!
//! An address that did not grow since the last call, while an address of another rung did, is
//! silent: it is vetoed for [`VETO_EXPIRY`], then tried again. A first sighting counts as growth,
//! so a new path is never vetoed on the call that sees it.
//!
//! One [`Liveness`] serves every remote of one local endpoint: a selector holds one behind a mutex,
//! and the list of a call has the paths of one remote. The key of the state is the whole
//! [`FourTuple`], so two local interfaces give two keys for one remote socket; that is harmless,
//! each is judged on what arrives on it.

use std::collections::HashMap;
use std::time::Duration;

use iroh::endpoint::transports::{FourTuple, PathSelectionData};
use n0_future::time::Instant;

use crate::{Rung, best_of, climb, rung_of};

/// How long a silent address stays vetoed: six heartbeats of five seconds.
pub const VETO_EXPIRY: Duration = Duration::from_secs(30);

/// How long an address that is not in the list stays in the state. One selector serves every remote
/// of its endpoint and the list of a call has the paths of one remote, so the state of an address
/// cannot be dropped for being absent from one call.
const PRUNE_AFTER: Duration = Duration::from_mins(1);

/// What the rule remembers of one address.
#[derive(Debug)]
struct Seen {
    /// Datagrams received on the address at the last call. A count that differs, up or down (the
    /// path was opened again and its statistics restarted), is a sign of life.
    rx: u64,
    /// Since when the address is vetoed, if it is.
    vetoed_since: Option<Instant>,
    /// The last call that had the address in its list.
    last_call: Instant,
}

/// The state of the liveness rule: one per local endpoint, keyed by the address.
#[derive(Debug, Default)]
pub struct Liveness {
    seen: HashMap<FourTuple, Seen>,
}

impl Liveness {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The path to select at `now`: the ladder of [`climb`], minus the addresses that are silent.
    ///
    /// Only usable paths are judged. An address that did not grow, while an address of another
    /// rung did, is vetoed. The proposer takes the best rung that has a non-vetoed address, and in
    /// it the best of the addresses that grew, or of all non-vetoed ones when none grew. When every
    /// address is vetoed the plain ladder decides.
    pub fn choose<'a>(
        &mut self,
        now: Instant,
        paths: &'a [PathSelectionData<'a>],
        custom: impl Fn(u64) -> Rung,
        usable: impl Fn(Rung, &PathSelectionData<'_>) -> bool,
    ) -> Option<&'a PathSelectionData<'a>> {
        let candidates: Vec<(Rung, &'a PathSelectionData<'a>)> = paths
            .iter()
            .filter_map(|path| {
                let rung = rung_of(path, &custom);
                usable(rung, path).then_some((rung, path))
            })
            .collect();

        // The datagrams received on each address, over all its entries.
        let mut received: HashMap<&FourTuple, u64> = HashMap::new();
        for (_, path) in &candidates {
            let rx = path.stats().map_or(0, |stats| stats.udp_rx.datagrams);
            *received.entry(path.network_path()).or_default() += rx;
        }
        self.seen
            .retain(|_, seen| now.saturating_duration_since(seen.last_call) < PRUNE_AFTER);

        // Expired vetoes are forgotten, so that the address is a first sighting again.
        self.seen.retain(|_, seen| {
            seen.vetoed_since
                .is_none_or(|since| now.saturating_duration_since(since) < VETO_EXPIRY)
        });

        let grew: HashMap<&FourTuple, bool> = received
            .iter()
            .map(|(&address, &rx)| {
                (
                    address,
                    self.seen.get(address).is_none_or(|seen| rx != seen.rx),
                )
            })
            .collect();
        let rung_of_address: HashMap<&FourTuple, Rung> = candidates
            .iter()
            .map(|&(rung, path)| (path.network_path(), rung))
            .collect();
        let grown_rungs: Vec<Rung> = grew
            .iter()
            .filter(|&(_, &grown)| grown)
            .map(|(address, _)| rung_of_address[address])
            .collect();

        for (&address, &rx) in &received {
            let rung = rung_of_address[address];
            let seen = self.seen.entry(address.clone()).or_insert(Seen {
                rx,
                vetoed_since: None,
                last_call: now,
            });
            seen.last_call = now;
            if grew[address] {
                seen.vetoed_since = None;
            } else if seen.vetoed_since.is_none() && grown_rungs.iter().any(|&other| other != rung)
            {
                seen.vetoed_since = Some(now);
            }
            seen.rx = rx;
        }

        let vetoed = |address: &FourTuple| {
            self.seen
                .get(address)
                .is_some_and(|seen| seen.vetoed_since.is_some())
        };
        let rung = Rung::LADDER.into_iter().find(|&rung| {
            candidates
                .iter()
                .any(|&(candidate, path)| candidate == rung && !vetoed(path.network_path()))
        });
        let Some(rung) = rung else {
            return climb(paths, custom, usable);
        };
        let eligible: Vec<&'a PathSelectionData<'a>> = candidates
            .iter()
            .filter(|&&(candidate, path)| candidate == rung && !vetoed(path.network_path()))
            .map(|&(_, path)| path)
            .collect();
        let grown: Vec<&'a PathSelectionData<'a>> = eligible
            .iter()
            .copied()
            .filter(|path| grew[path.network_path()])
            .collect();
        best_of(grown.iter().copied()).or_else(|| best_of(eligible.iter().copied()))
    }
}

#[cfg(test)]
mod tests {
    use iroh::endpoint::{
        PathStats,
        transports::{Addr, FourTuple, PathSelectionData},
    };

    use super::*;
    use crate::{MULTIHOP_TRANSPORT_ID, WEBRTC_TRANSPORT_ID, custom_rung};

    fn address(transport: u64, tag: u8) -> FourTuple {
        FourTuple::from_remote(Addr::Custom(iroh_base::CustomAddr::from_parts(
            transport,
            &[tag],
        )))
    }

    fn webrtc(tag: u8) -> FourTuple {
        address(WEBRTC_TRANSPORT_ID, tag)
    }

    fn multihop(tag: u8) -> FourTuple {
        address(MULTIHOP_TRANSPORT_ID, tag)
    }

    /// One entry of the list of paths, with the datagrams received on it.
    fn entry(address: &FourTuple, rx: u64) -> PathSelectionData<'_> {
        let mut stats = PathStats::default();
        stats.udp_rx.datagrams = rx;
        PathSelectionData::for_test(address, Some(stats))
    }

    fn choose<'a>(
        liveness: &mut Liveness,
        now: Instant,
        paths: &'a [PathSelectionData<'a>],
    ) -> Option<&'a FourTuple> {
        liveness
            .choose(now, paths, custom_rung, |_, _| true)
            .map(PathSelectionData::network_path)
    }

    /// The shape of flake A: WebRTC outranks multihop, the WebRTC path stays at 6 datagrams
    /// while the multihop path grows.
    #[test]
    fn the_first_call_is_rung_first() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let mut liveness = Liveness::new();
        let paths = [entry(&webrtc_addr, 6), entry(&multihop_addr, 3)];
        assert_eq!(
            choose(&mut liveness, Instant::now(), &paths),
            Some(&webrtc_addr)
        );
    }

    #[test]
    fn an_address_that_stays_flat_while_another_rung_grows_is_vetoed() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        let first = [entry(&webrtc_addr, 6), entry(&multihop_addr, 3)];
        assert_eq!(choose(&mut liveness, start, &first), Some(&webrtc_addr));
        let later = [entry(&webrtc_addr, 6), entry(&multihop_addr, 23)];
        assert_eq!(
            choose(&mut liveness, start + Duration::from_secs(10), &later),
            Some(&multihop_addr),
            "the WebRTC path received nothing in ten seconds and multihop grew"
        );
    }

    #[test]
    fn nothing_is_vetoed_when_no_address_grows() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        let paths = [entry(&webrtc_addr, 6), entry(&multihop_addr, 3)];
        assert_eq!(choose(&mut liveness, start, &paths), Some(&webrtc_addr));
        assert_eq!(
            choose(&mut liveness, start + Duration::from_secs(10), &paths),
            Some(&webrtc_addr),
            "an idle pair has no evidence against its best rung"
        );
    }

    #[test]
    fn the_entries_of_one_address_are_summed() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        let first = [
            entry(&webrtc_addr, 2),
            entry(&webrtc_addr, 4),
            entry(&multihop_addr, 3),
        ];
        assert_eq!(choose(&mut liveness, start, &first), Some(&webrtc_addr));
        // One entry of the address grew, the other did not: the address is alive.
        let alive = [
            entry(&webrtc_addr, 2),
            entry(&webrtc_addr, 5),
            entry(&multihop_addr, 23),
        ];
        assert_eq!(
            choose(&mut liveness, start + Duration::from_secs(10), &alive),
            Some(&webrtc_addr)
        );
        // No entry grew: the sum is flat.
        let flat = [
            entry(&webrtc_addr, 2),
            entry(&webrtc_addr, 5),
            entry(&multihop_addr, 31),
        ];
        assert_eq!(
            choose(&mut liveness, start + Duration::from_secs(15), &flat),
            Some(&multihop_addr)
        );
    }

    #[test]
    fn a_vetoed_address_that_grows_again_is_taken_back() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        assert_eq!(
            choose(
                &mut liveness,
                start,
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 3)]
            ),
            Some(&webrtc_addr)
        );
        assert_eq!(
            choose(
                &mut liveness,
                start + Duration::from_secs(10),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 23)]
            ),
            Some(&multihop_addr)
        );
        assert_eq!(
            choose(
                &mut liveness,
                start + Duration::from_secs(15),
                &[entry(&webrtc_addr, 9), entry(&multihop_addr, 31)]
            ),
            Some(&webrtc_addr),
            "the peer sends on the WebRTC path again"
        );
    }

    #[test]
    fn a_veto_expires_and_the_address_is_tried_again() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 3)],
        );
        let veto = start + Duration::from_secs(10);
        assert_eq!(
            choose(
                &mut liveness,
                veto,
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 23)]
            ),
            Some(&multihop_addr)
        );
        assert_eq!(
            choose(
                &mut liveness,
                veto + Duration::from_secs(20),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 40)]
            ),
            Some(&multihop_addr),
            "still vetoed before the expiry"
        );
        assert_eq!(
            choose(
                &mut liveness,
                veto + VETO_EXPIRY + Duration::from_secs(1),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 60)]
            ),
            Some(&webrtc_addr),
            "tried again after the expiry"
        );
    }

    #[test]
    fn a_new_address_is_not_vetoed_on_the_call_that_sees_it() {
        let (webrtc_addr, webrtc_second, multihop_addr) = (webrtc(1), webrtc(2), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 3)],
        );
        let later = [
            entry(&webrtc_addr, 6),
            entry(&webrtc_second, 1),
            entry(&multihop_addr, 23),
        ];
        assert_eq!(
            choose(&mut liveness, start + Duration::from_secs(10), &later),
            Some(&webrtc_second),
            "the old WebRTC address is silent, the new one is a first sighting"
        );
    }

    /// One selector serves every remote of its endpoint, so a call for another remote must not
    /// make it forget this one.
    #[test]
    fn the_state_of_one_remote_survives_a_call_for_another() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (other_webrtc, other_multihop) = (webrtc(2), multihop(2));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        let first = [entry(&webrtc_addr, 6), entry(&multihop_addr, 3)];
        choose(&mut liveness, start, &first);
        let other = [entry(&other_webrtc, 1), entry(&other_multihop, 1)];
        choose(&mut liveness, start + Duration::from_secs(5), &other);
        let later = [entry(&webrtc_addr, 6), entry(&multihop_addr, 23)];
        assert_eq!(
            choose(&mut liveness, start + Duration::from_secs(10), &later),
            Some(&multihop_addr),
            "the first remote was judged on its own history"
        );
    }

    /// A path that is opened again starts its statistics at zero. The count is lower than the one
    /// seen before, and that is life, not silence.
    #[test]
    fn a_count_that_goes_backwards_is_not_silence() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[entry(&webrtc_addr, 60), entry(&multihop_addr, 3)],
        );
        assert_eq!(
            choose(
                &mut liveness,
                start + Duration::from_secs(10),
                &[entry(&webrtc_addr, 2), entry(&multihop_addr, 23)]
            ),
            Some(&webrtc_addr),
            "the WebRTC path was opened again and counts from zero"
        );
    }

    #[test]
    fn the_usable_filter_still_applies() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        let paths = [entry(&webrtc_addr, 6), entry(&multihop_addr, 3)];
        let chosen = liveness
            .choose(start, &paths, custom_rung, |rung, _| rung != Rung::WebRtc)
            .map(PathSelectionData::network_path);
        assert_eq!(
            chosen,
            Some(&multihop_addr),
            "a blocked rung is not a candidate"
        );
    }
}
