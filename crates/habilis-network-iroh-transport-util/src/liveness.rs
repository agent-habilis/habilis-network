//! The liveness rule: a path that the peer never sends on does not stay selected.
//!
//! The ladder in [`climb`](crate::climb) is rung-first and has no sense of life. A path that opened
//! and then went quiet from the peer, because the peer sends on another one, still outranks a live
//! path of a lower rung, and when the two ends choose different paths both die at the idle timeout
//! of a path. This rule keeps, for each address, what the connection received on each of its entries
//! (one address can appear more than once in the list), sorted from the highest count to the lowest.
//!
//! An address is judged over a window of [`JUDGE_WINDOW`]. A call inside the window changes
//! nothing, because calls come in bursts of path events and two calls a few milliseconds apart
//! prove nothing. At the end of a window the address has grown or it has not. It grew when
//! some rank of the sorted counts is present in the baseline and now, and the count is higher now.
//! A rank that is only present now is a new entry, a path opened again, and is not growth. A rank
//! that is gone is ignored. A count that went down is not growth. When every rank went down and no
//! entry left, the whole address was opened again and it is fresh again.
//!
//! An address is *alive* when it grew in two windows in a row. A new address, one that was never
//! judged, is *fresh*: it can be chosen, but it is never evidence for or against another address.
//! An address is *silent* when it was judged, did not grow in its last window, and an address of
//! another rung is alive. A silent address is vetoed for [`VETO_EXPIRY`], then it is fresh again,
//! once. Only growth in two windows in a row lifts a veto earlier.
//!
//! The choice is the first rung that has an address that is not vetoed; inside it, an alive address,
//! else a fresh one, else any other. When every address is vetoed the plain ladder decides.
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

/// The window over which an address is judged.
pub const JUDGE_WINDOW: Duration = Duration::from_secs(10);

/// How long a silent address stays vetoed: six heartbeats of five seconds.
pub const VETO_EXPIRY: Duration = Duration::from_secs(30);

/// How long an address that is not in the list stays in the state. One selector serves every remote
/// of its endpoint and the list of a call has the paths of one remote, so the state of an address
/// cannot be dropped for being absent from one call.
const PRUNE_AFTER: Duration = Duration::from_mins(1);

/// What the rule remembers of one address.
#[derive(Debug)]
struct Seen {
    /// The counts of the entries of the address, highest first, when the current window began.
    baseline: Vec<u64>,
    /// When the current window began.
    window_start: Instant,
    /// Whether a window of the address ended at least once.
    judged: bool,
    /// Whether the address grew in its last window.
    grew_last: bool,
    /// Whether the address grew in the window before.
    grew_before: bool,
    /// Since when the address is vetoed, if it is.
    vetoed_since: Option<Instant>,
    /// The last call that had the address in its list.
    last_call: Instant,
}

impl Seen {
    fn fresh(received: Vec<u64>, now: Instant) -> Self {
        Self {
            baseline: received,
            window_start: now,
            judged: false,
            grew_last: false,
            grew_before: false,
            vetoed_since: None,
            last_call: now,
        }
    }

    /// Grew in two windows in a row.
    fn alive(&self) -> bool {
        self.grew_last && self.grew_before
    }

    /// Ends the window if it is over; a call inside the window changes nothing.
    fn judge(&mut self, received: Vec<u64>, now_instant: Instant) {
        if now_instant.saturating_duration_since(self.window_start) < JUDGE_WINDOW {
            return;
        }
        self.window_start = now_instant;
        if received
            .iter()
            .zip(&self.baseline)
            .all(|(now, before)| now < before)
            && !received.is_empty()
            && !self.baseline.is_empty()
            && received.len() >= self.baseline.len()
        {
            // Every entry counts less than before and none left: the whole address was opened again.
            *self = Self::fresh(received, now_instant);
            return;
        }
        self.grew_before = self.grew_last;
        self.grew_last = received
            .iter()
            .zip(&self.baseline)
            .any(|(now, before)| now > before);
        self.baseline = received;
        self.judged = true;
        if self.alive() {
            self.vetoed_since = None;
        }
    }
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

        // The datagrams received on each entry of each address.
        let mut received: HashMap<&FourTuple, Vec<u64>> = HashMap::new();
        let mut rung_of_address: HashMap<&FourTuple, Rung> = HashMap::new();
        for &(rung, path) in &candidates {
            let count = path.stats().map_or(0, |stats| stats.udp_rx.datagrams);
            received.entry(path.network_path()).or_default().push(count);
            rung_of_address.insert(path.network_path(), rung);
        }

        self.seen
            .retain(|_, seen| now.saturating_duration_since(seen.last_call) < PRUNE_AFTER);
        // An expired veto is forgotten, so that the address is fresh again.
        self.seen.retain(|_, seen| {
            seen.vetoed_since
                .is_none_or(|since| now.saturating_duration_since(since) < VETO_EXPIRY)
        });

        for counts in received.values_mut() {
            counts.sort_unstable_by(|left, right| right.cmp(left));
        }
        for (&address, counts) in &received {
            let seen = self
                .seen
                .entry(address.clone())
                .or_insert_with(|| Seen::fresh(counts.clone(), now));
            seen.last_call = now;
            seen.judge(counts.clone(), now);
        }

        let alive_rungs: Vec<Rung> = received
            .keys()
            .filter(|&&address| self.seen[address].alive())
            .map(|&address| rung_of_address[address])
            .collect();
        for &address in received.keys() {
            let rung = rung_of_address[address];
            let silent = alive_rungs.iter().any(|&other| other != rung);
            if let Some(seen) = self.seen.get_mut(address)
                && silent
                && seen.judged
                && !seen.grew_last
                && seen.vetoed_since.is_none()
            {
                seen.vetoed_since = Some(now);
            }
        }

        let vetoed = |address: &FourTuple| self.seen[address].vetoed_since.is_some();
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
        let of_state = |keep: fn(&Seen) -> bool| -> Vec<&'a PathSelectionData<'a>> {
            eligible
                .iter()
                .copied()
                .filter(|path| keep(&self.seen[path.network_path()]))
                .collect()
        };
        let alive = of_state(Seen::alive);
        let fresh = of_state(|seen| !seen.judged);
        best_of(alive.iter().copied())
            .or_else(|| best_of(fresh.iter().copied()))
            .or_else(|| best_of(eligible.iter().copied()))
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

    fn relay() -> FourTuple {
        FourTuple::from_remote(Addr::Relay(
            "https://relay.test".parse().expect("a relay url"),
            iroh_base::SecretKey::from_bytes(&[9; 32]).public(),
        ))
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

    /// `windows` judgement windows after `start`.
    fn after(start: Instant, windows: u32) -> Instant {
        start + JUDGE_WINDOW * windows
    }

    /// The WebRTC address at 6 datagrams is silent for good, and multihop grows by 20 a window:
    /// the shape of flake A. Three calls make multihop alive and the WebRTC address silent.
    fn silent_webrtc(
        liveness: &mut Liveness,
        start: Instant,
        webrtc: &FourTuple,
        multihop: &FourTuple,
    ) {
        choose(liveness, start, &[entry(webrtc, 6), entry(multihop, 3)]);
        choose(
            liveness,
            after(start, 1),
            &[entry(webrtc, 6), entry(multihop, 23)],
        );
    }

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

    /// Changed from the first version: an address is alive after two windows of growth, so the
    /// veto comes at the third call, not at the second.
    #[test]
    fn an_address_that_stays_flat_while_another_rung_is_alive_is_vetoed() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        silent_webrtc(&mut liveness, start, &webrtc_addr, &multihop_addr);
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 2),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 43)]
            ),
            Some(&multihop_addr),
            "the WebRTC path received nothing in two windows and multihop grew in both"
        );
    }

    #[test]
    fn nothing_is_vetoed_when_no_address_grows() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        let paths = [entry(&webrtc_addr, 6), entry(&multihop_addr, 3)];
        for windows in 0..4 {
            assert_eq!(
                choose(&mut liveness, after(start, windows), &paths),
                Some(&webrtc_addr),
                "an idle pair has no evidence against its best rung"
            );
        }
    }

    /// Changed: one window of growth is not life, so the second call keeps WebRTC.
    #[test]
    fn one_growing_window_is_not_alive() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 3)],
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 1),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 23)]
            ),
            Some(&webrtc_addr),
            "multihop grew once: it is no evidence yet"
        );
    }

    /// Changed: three calls, and the growth is rank-wise on the counts sorted from the highest.
    #[test]
    fn one_entry_that_grows_is_growth_of_the_address() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[
                entry(&webrtc_addr, 2),
                entry(&webrtc_addr, 4),
                entry(&multihop_addr, 3),
            ],
        );
        // One entry of the address grew, the other did not: the address grew.
        choose(
            &mut liveness,
            after(start, 1),
            &[
                entry(&webrtc_addr, 2),
                entry(&webrtc_addr, 5),
                entry(&multihop_addr, 23),
            ],
        );
        // No entry grew, and multihop is alive.
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 2),
                &[
                    entry(&webrtc_addr, 2),
                    entry(&webrtc_addr, 5),
                    entry(&multihop_addr, 43)
                ]
            ),
            Some(&multihop_addr)
        );
    }

    /// Changed: an address is taken back only when it grows in two windows in a row.
    #[test]
    fn a_vetoed_address_that_grows_in_two_windows_is_taken_back() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        silent_webrtc(&mut liveness, start, &webrtc_addr, &multihop_addr);
        choose(
            &mut liveness,
            after(start, 2),
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 43)],
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 3),
                &[entry(&webrtc_addr, 9), entry(&multihop_addr, 63)]
            ),
            Some(&multihop_addr),
            "one window of growth does not lift the veto"
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 4),
                &[entry(&webrtc_addr, 12), entry(&multihop_addr, 83)]
            ),
            Some(&webrtc_addr),
            "the peer sends on the WebRTC path again, in two windows in a row"
        );
    }

    /// Changed: the veto starts at the third call and the times follow.
    #[test]
    fn a_veto_expires_and_the_address_is_tried_again() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        silent_webrtc(&mut liveness, start, &webrtc_addr, &multihop_addr);
        let veto = after(start, 2);
        assert_eq!(
            choose(
                &mut liveness,
                veto,
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 43)]
            ),
            Some(&multihop_addr)
        );
        assert_eq!(
            choose(
                &mut liveness,
                veto + VETO_EXPIRY - Duration::from_secs(10),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 83)]
            ),
            Some(&multihop_addr),
            "still vetoed before the expiry"
        );
        assert_eq!(
            choose(
                &mut liveness,
                veto + VETO_EXPIRY + Duration::from_secs(1),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 123)]
            ),
            Some(&webrtc_addr),
            "fresh again after the expiry"
        );
    }

    /// Changed: the old address is vetoed first, then the new one appears.
    #[test]
    fn a_new_address_is_eligible_but_never_evidence() {
        let (webrtc_addr, webrtc_second, multihop_addr) = (webrtc(1), webrtc(2), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        silent_webrtc(&mut liveness, start, &webrtc_addr, &multihop_addr);
        choose(
            &mut liveness,
            after(start, 2),
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 43)],
        );
        let later = [
            entry(&webrtc_addr, 6),
            entry(&webrtc_second, 1),
            entry(&multihop_addr, 44),
        ];
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 2) + Duration::from_secs(1),
                &later
            ),
            Some(&webrtc_second),
            "the old WebRTC address is vetoed, the new one is fresh and eligible"
        );
    }

    /// Changed: the history of remote A is kept across a call for remote B, over three windows.
    #[test]
    fn the_state_of_one_remote_survives_a_call_for_another() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (other_webrtc, other_multihop) = (webrtc(2), multihop(2));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 3)],
        );
        choose(
            &mut liveness,
            start + Duration::from_secs(5),
            &[entry(&other_webrtc, 1), entry(&other_multihop, 1)],
        );
        choose(
            &mut liveness,
            after(start, 1),
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 23)],
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 2),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 43)]
            ),
            Some(&multihop_addr),
            "the first remote was judged on its own history"
        );
    }

    /// Changed: the old test asserted that a count that goes down is a reopen with no verdict
    /// change. Now, when every entry counts less than before, the whole address was opened again:
    /// it is fresh, chosen for one window, and it is no evidence. Multihop is flat at the same
    /// call, and nothing is held against it, because the fresh address proves nothing.
    #[test]
    fn an_address_that_counts_less_in_every_entry_is_fresh_again() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[entry(&webrtc_addr, 60), entry(&multihop_addr, 3)],
        );
        choose(
            &mut liveness,
            after(start, 1),
            &[entry(&webrtc_addr, 64), entry(&multihop_addr, 23)],
        );
        choose(
            &mut liveness,
            after(start, 2),
            &[entry(&webrtc_addr, 68), entry(&multihop_addr, 43)],
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 3),
                &[entry(&webrtc_addr, 2), entry(&multihop_addr, 43)]
            ),
            Some(&webrtc_addr),
            "the path was opened again: it is fresh and has the higher rung"
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 4),
                &[entry(&webrtc_addr, 2), entry(&multihop_addr, 63)]
            ),
            Some(&webrtc_addr),
            "multihop grew in one window: it is not alive yet"
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 5),
                &[entry(&webrtc_addr, 2), entry(&multihop_addr, 83)]
            ),
            Some(&multihop_addr),
            "multihop is alive and the WebRTC address did not grow"
        );
    }

    /// Run a16, bob, one step later: the highest entry of a vetoed address leaves, {6, 1} becomes
    /// {1}. The one rank that is left counts less, but an entry left, and that is not a path opened
    /// again: the veto stands.
    #[test]
    fn an_entry_that_leaves_is_not_a_reopen() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[
                entry(&webrtc_addr, 6),
                entry(&webrtc_addr, 1),
                entry(&multihop_addr, 3),
            ],
        );
        choose(
            &mut liveness,
            after(start, 1),
            &[
                entry(&webrtc_addr, 6),
                entry(&webrtc_addr, 1),
                entry(&multihop_addr, 23),
            ],
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 2),
                &[
                    entry(&webrtc_addr, 6),
                    entry(&webrtc_addr, 1),
                    entry(&multihop_addr, 43)
                ]
            ),
            Some(&multihop_addr),
            "the WebRTC address is flat while multihop is alive: vetoed"
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 3),
                &[entry(&webrtc_addr, 1), entry(&multihop_addr, 63)]
            ),
            Some(&multihop_addr),
            "the entry with 6 left: the address is not fresh again and the veto stands"
        );
    }

    /// Run a10, alice (replay of the counts and times of the log): the multihop entries went from
    /// {1} to {30, 26, 1} and then, 20 ms later, to {30, 27}, while the relay grew and a fresh WebRTC
    /// entry appeared. The old rule summed the entries (57 and 57) and vetoed multihop. Alice does
    /// not use the WebRTC entry, so the filter blocks it.
    #[test]
    fn a_burst_inside_a_window_vetoes_nothing() {
        let (multihop_addr, relay_addr, webrtc_addr) = (multihop(1), relay(), webrtc(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        let mut call = |seconds: f64, paths: &[PathSelectionData<'_>]| {
            liveness
                .choose(
                    start + Duration::from_secs_f64(seconds),
                    paths,
                    custom_rung,
                    |rung, _| rung != Rung::WebRtc,
                )
                .map(PathSelectionData::network_path)
                .cloned()
        };
        let chosen = Some(multihop_addr.clone());
        assert_eq!(
            call(0.0, &[entry(&multihop_addr, 1), entry(&relay_addr, 37)]),
            chosen
        );
        assert_eq!(
            call(
                15.0,
                &[
                    entry(&multihop_addr, 30),
                    entry(&multihop_addr, 26),
                    entry(&multihop_addr, 1),
                    entry(&relay_addr, 40)
                ]
            ),
            chosen
        );
        assert_eq!(
            call(
                15.02,
                &[
                    entry(&webrtc_addr, 1),
                    entry(&multihop_addr, 27),
                    entry(&multihop_addr, 30),
                    entry(&relay_addr, 41)
                ]
            ),
            chosen,
            "inside the window, nothing is judged"
        );
        assert_eq!(
            call(
                30.0,
                &[
                    entry(&multihop_addr, 30),
                    entry(&multihop_addr, 28),
                    entry(&relay_addr, 44)
                ]
            ),
            chosen,
            "rank 1 grew from 26 to 28: the address is alive"
        );
    }

    /// Run a16, bob: the dead WebRTC path (6 datagrams) is opened again by the nudge and a new
    /// entry with 1 datagram appears: {6} becomes {6, 1}. A rank that is only present now is a new
    /// entry, not growth.
    #[test]
    fn a_reopened_dead_path_stays_vetoed() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        silent_webrtc(&mut liveness, start, &webrtc_addr, &multihop_addr);
        choose(
            &mut liveness,
            after(start, 2),
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 43)],
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 3),
                &[
                    entry(&webrtc_addr, 6),
                    entry(&webrtc_addr, 1),
                    entry(&multihop_addr, 63)
                ]
            ),
            Some(&multihop_addr),
            "the validation packets of the reopened path are not life"
        );
    }

    /// A path that carries only keep-alives (one datagram a window) is alive, and it beats a
    /// silent path of a higher rung.
    #[test]
    fn a_keepalive_only_path_is_alive_and_beats_a_vetoed_higher_rung() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 3)],
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 1),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 4)]
            ),
            Some(&webrtc_addr),
            "one window is no evidence"
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 2),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 5)]
            ),
            Some(&multihop_addr),
            "multihop grew by one in two windows in a row"
        );
    }

    /// A call inside the window does not move the baseline: the growth of the window is measured
    /// from its start.
    #[test]
    fn a_call_inside_the_window_does_not_move_the_baseline() {
        let (webrtc_addr, multihop_addr) = (webrtc(1), multihop(1));
        let (mut liveness, start) = (Liveness::new(), Instant::now());
        choose(
            &mut liveness,
            start,
            &[entry(&webrtc_addr, 6), entry(&multihop_addr, 5)],
        );
        assert_eq!(
            choose(
                &mut liveness,
                start + Duration::from_secs(5),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 10)]
            ),
            Some(&webrtc_addr),
            "inside the window nothing is judged"
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 1),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 10)]
            ),
            Some(&webrtc_addr),
            "multihop grew from 5 to 10 in the first window: one window is not life"
        );
        assert_eq!(
            choose(
                &mut liveness,
                after(start, 2),
                &[entry(&webrtc_addr, 6), entry(&multihop_addr, 15)]
            ),
            Some(&multihop_addr),
            "multihop grew from 5 to 10 in the first window and from 10 to 15 in the second"
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
