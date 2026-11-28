//! The rules of a holder that asks who serves its own beacon. One value holds the state, one call
//! takes one answer and gives one action, and nothing here touches a socket, so that a model of the
//! relay can test the rules.

use iroh::EndpointId;

use std::fmt;

use super::{Cause, Contest, Held, WhoAnswer};

/// How many answers of `Unknown` in a row a holder reads before it claims its rendezvous again.
pub(crate) const UNKNOWN_BEFORE_CLAIM: u32 = 3;

/// How many times a holder claims again against one rival before it yields to that rival.
pub(crate) const CLAIMS_BEFORE_YIELD: u32 = 2;

/// How many answers of `Ours` in a row end a contest: the claims against a rival are forgotten.
/// One `Ours` between two claims is not the end: a relay that changes the served claim at each
/// event, read with answers a period old, shows one.
pub(crate) const OURS_BEFORE_PEACE: u32 = 2;

/// What a holder does with an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContestAction {
    /// Keep the beacon as it is.
    Stay,
    /// Bind a new beacon and close the old one in the same step.
    ClaimAgain,
    /// Let go of the beacon: the rival keeps the rendezvous.
    YieldTo(EndpointId),
}

impl ContestAction {
    /// The word of the action in the log line of the holder probe. A parser reads this word, not the
    /// `Debug` text; the words are pinned by a test.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Stay => "stay",
            Self::ClaimAgain => "claim_again",
            Self::YieldTo(_) => "yield",
        }
    }
}

/// Write the log line of one answer of the holder probe. The fields are a contract with the parsers
/// of the soak and the analysers, and a test pins the line as written. Every field is always there
/// and holds one word with no space: `kind`, `cause` and `action` are words (`Cause::word` for the
/// cause), and `rival` is the short id. `cause` is `-` unless the answer is reached or unknown, and
/// `rival` is `-` unless the answer names one.
pub(crate) fn log_holder_probe(node: EndpointId, answer: WhoAnswer, action: ContestAction) {
    if answer == WhoAnswer::Ours {
        tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), "holder probe: ours");
        return;
    }
    let cause = answer.cause().map_or("-", Cause::word);
    let rival = match answer {
        WhoAnswer::Rival(id) => id.fmt_short().to_string(),
        WhoAnswer::Ours | WhoAnswer::Reached(_) | WhoAnswer::Unknown(_) => "-".to_owned(),
    };
    tracing::info!(
        target: "habilis_network::beacon",
        node = %node.fmt_short(),
        kind = %answer.kind(),
        cause = %cause,
        rival = %rival,
        action = %action.word(),
        "holder probe"
    );
}

/// Write the log line of a member that read the rendezvous free twice and claims it. It is the start
/// of the bind: the line of `beacon assumed` of the same node ends it, so the time between the two
/// is the time of the bind of this host. The line is a contract with the soak counters, and a test
/// pins it as written. It sits beside `log_holder_probe` so that the log words of the beacon claim
/// have one place and one pin test.
///
/// The span of a claim, from this line to `beacon assumed` or `log_claim_missed`, is written inside
/// one await of one turn of the event loop of the node (`probe_verdict`, or the claim again of
/// `apply_holder_answer`). The loop runs one turn at a time, so the spans of a node never overlap
/// and a reader can pair them by order.
pub(crate) fn log_claim_on_free(node: EndpointId) {
    tracing::info!(
        target: "habilis_network::beacon",
        node = %node.fmt_short(),
        "rendezvous read free twice: claiming"
    );
}

/// Why a claim ended with no beacon. One word with no space for each, as for `Cause`. A claim
/// that a probe read free (the start line of `log_claim_on_free`) and a claim again are public
/// claims, and the rival of a public claim is read before the start: after a start the claim ends
/// with a beacon, or with 1 of these 2 words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Miss {
    /// The beacon slot of this node is taken: a reclaim tick or a re-stand-up took the role while
    /// the probe ran.
    SlotTaken,
    /// No endpoint of the beacon was bound: the build failed (a public claim), or the ladder walk
    /// bound none (a private claim).
    NoBind,
}

impl Miss {
    /// The word of the miss in the log line of a claim that ended with no beacon.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::SlotTaken => "slot_taken",
            Self::NoBind => "no_bind",
        }
    }

    /// The miss that a call of the claim left, and nothing for a call that stood a beacon up.
    pub(crate) fn of(held: Held) -> Option<Self> {
        match held {
            Held::Claimed => None,
            Held::Rival | Held::Idle | Held::NoRung => Some(Self::NoBind),
        }
    }
}

impl fmt::Display for Miss {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.word())
    }
}

/// Write the log line of a claim that ended with no beacon: the bind failed, or no rung was free,
/// or another node held the rendezvous. It ends the span that `log_claim_on_free` starts, so that
/// the soak counters pair each start with its own end and do not read the next beacon of the node
/// as the end of a bind that did not happen.
pub(crate) fn log_claim_missed(node: EndpointId, miss: Miss) {
    tracing::info!(
        target: "habilis_network::beacon",
        node = %node.fmt_short(),
        cause = %miss,
        "rendezvous claim ended with no beacon"
    );
}

/// What a holder remembers between two answers.
#[derive(Debug, Default)]
pub(crate) struct HolderContest {
    unknown: u32,
    ours: u32,
    claims: Option<(EndpointId, u32)>,
}

impl HolderContest {
    /// The action for `answer`, from the holder `own`.
    ///
    /// `Ours` clears the count of `Unknown`, and `OURS_BEFORE_PEACE` of them in a row clear the
    /// claims. A rival with a lower id than ours keeps the rendezvous (`Contest::own_yields`), so
    /// we yield. A rival with a higher id loses it, so we claim again, and when the relay does not
    /// serve the new claim we yield after `CLAIMS_BEFORE_YIELD` of them: the contest then ends on
    /// every rule of the relay, and the higher id keeps the rendezvous where the relay lets it.
    /// `Reached` and `Unknown` say nothing about a rival: only `UNKNOWN_BEFORE_CLAIM` of them in a
    /// row make us claim again, which repairs a beacon that stopped answering and a claim that the
    /// relay lost.
    pub(crate) fn on_answer(&mut self, own: EndpointId, answer: WhoAnswer) -> ContestAction {
        match answer {
            WhoAnswer::Ours => {
                self.unknown = 0;
                self.ours += 1;
                if self.ours >= OURS_BEFORE_PEACE {
                    *self = Self::default();
                }
                ContestAction::Stay
            }
            WhoAnswer::Rival(rival) => {
                self.unknown = 0;
                self.ours = 0;
                let contest = Contest { own, rival };
                if contest.own_yields() {
                    *self = Self::default();
                    return ContestAction::YieldTo(rival);
                }
                let claims = match self.claims {
                    Some((against, claims)) if against == rival => claims,
                    _ => 0,
                };
                if claims >= CLAIMS_BEFORE_YIELD {
                    *self = Self::default();
                    return ContestAction::YieldTo(rival);
                }
                self.claims = Some((rival, claims + 1));
                ContestAction::ClaimAgain
            }
            WhoAnswer::Reached(_) | WhoAnswer::Unknown(_) => {
                self.ours = 0;
                self.unknown += 1;
                if self.unknown >= UNKNOWN_BEFORE_CLAIM {
                    self.unknown = 0;
                    return ContestAction::ClaimAgain;
                }
                ContestAction::Stay
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh::{EndpointId, SecretKey};

    use super::{
        ContestAction, HolderContest, Miss, log_claim_missed, log_claim_on_free, log_holder_probe,
    };
    use crate::beacon::{Cause, Held, WhoAnswer};
    use crate::testing::LogCapture;

    /// The rule by which a relay picks the claim of an id that it serves. The weak assumption of the
    /// design: it serves at most 1 claim, and it changes it only when a session registers or leaves.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Relay {
        /// The newest claim is served, and when it leaves the newest that remains.
        NewestWins,
        /// The oldest claim is served, and when it leaves the oldest that remains.
        OldestWins,
        /// The newest on one event and the oldest on the next.
        Flip,
        /// The newest claim at a registration; when the served claim leaves, nobody is served.
        NoPromotion,
    }

    /// The claims of 1 id on 1 relay, and which is served.
    struct Model {
        relay: Relay,
        /// The holders that have a live claim, with the stamp of the claim, oldest first.
        claims: Vec<(usize, u64)>,
        served: Option<usize>,
        events: u64,
        stamp: u64,
    }

    impl Model {
        fn new(relay: Relay) -> Self {
            Self {
                relay,
                claims: Vec::new(),
                served: None,
                events: 0,
                stamp: 0,
            }
        }

        /// A claim of `holder`; its old claim, if any, closes in the same step.
        fn register(&mut self, holder: usize) {
            self.claims.retain(|(claimer, _)| *claimer != holder);
            self.stamp += 1;
            self.claims.push((holder, self.stamp));
            self.events += 1;
            self.served = self.pick(true);
        }

        /// The claim of `holder` closes.
        fn leave(&mut self, holder: usize) {
            let was_served = self.served == Some(holder);
            self.claims.retain(|(claimer, _)| *claimer != holder);
            self.events += 1;
            self.served = if self.relay == Relay::NoPromotion {
                if was_served { None } else { self.served }
            } else {
                self.pick(false)
            };
        }

        /// The holder whose claim the relay serves after an event.
        fn pick(&self, registered: bool) -> Option<usize> {
            let newest = self.claims.last().map(|(holder, _)| *holder);
            let oldest = self.claims.first().map(|(holder, _)| *holder);
            match self.relay {
                Relay::NewestWins => newest,
                Relay::OldestWins => oldest,
                Relay::Flip => {
                    if self.events.is_multiple_of(2) {
                        newest
                    } else {
                        oldest
                    }
                }
                Relay::NoPromotion => {
                    if registered {
                        newest
                    } else {
                        self.served
                    }
                }
            }
        }

        /// What the probe of `holder` reads.
        fn answer(&self, holder: usize, ids: &[EndpointId]) -> WhoAnswer {
            match self.served {
                None => WhoAnswer::Unknown(Cause::NoConnection),
                Some(served) if served == holder => WhoAnswer::Ours,
                Some(served) => WhoAnswer::Rival(ids[served]),
            }
        }

        fn alive(&self) -> Vec<usize> {
            self.claims.iter().map(|(holder, _)| *holder).collect()
        }
    }

    fn permutations(items: &[usize]) -> Vec<Vec<usize>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut all = Vec::new();
        for position in 0..items.len() {
            let mut rest = items.to_vec();
            let first = rest.remove(position);
            for mut tail in permutations(&rest) {
                tail.insert(0, first);
                all.push(tail);
            }
        }
        all
    }

    /// How many periods a rendezvous that nobody holds waits for a claim: the probe before a claim
    /// reads it as free twice in a row.
    const RECLAIM_PERIODS: u32 = 2;

    /// The ids of `count` holders, lowest first (the lowest id keeps the rendezvous).
    fn ids_of(count: usize) -> Vec<EndpointId> {
        let mut ids: Vec<EndpointId> = (1..=count)
            .map(|seed| {
                SecretKey::from_bytes(&[u8::try_from(seed).expect("a small seed"); 32]).public()
            })
            .collect();
        ids.sort();
        ids
    }

    /// The periods until 1 holder is left and reads `Ours`, or `None` when the contest does not end.
    /// It also tells whether at some period every holder had yielded, so that nobody held the
    /// rendezvous.
    /// Every holder reads from the same snapshot of the relay in a period, and the actions then apply
    /// one by one in `apply_order`: this is the worst staleness, a claim on an answer that an earlier
    /// action of the same period has made old.
    fn periods_to_end(
        relay: Relay,
        initial: &[usize],
        apply_order: &[usize],
        ids: &[EndpointId],
        old_answers: bool,
    ) -> Option<(u32, usize, bool)> {
        let mut model = Model::new(relay);
        let mut contests: Vec<HolderContest> =
            initial.iter().map(|_| HolderContest::default()).collect();
        for holder in initial {
            model.register(*holder);
        }
        let mut previous: Vec<(usize, WhoAnswer)> = Vec::new();
        let mut empty_periods = 0;
        let mut ever_empty = false;
        for period in 1..=60 {
            let alive = model.alive();
            let current: Vec<(usize, WhoAnswer)> = alive
                .iter()
                .map(|holder| (*holder, model.answer(*holder, ids)))
                .collect();
            // A holder that acts on the answer of the period before: a probe has a budget, and a
            // claim takes time.
            let answers = if old_answers && !previous.is_empty() {
                previous.clone()
            } else {
                current.clone()
            };
            previous = current;
            let mut quiet = true;
            for holder in apply_order {
                let Some((_, answer)) = answers.iter().find(|(asked, _)| asked == holder) else {
                    continue;
                };
                if !model.alive().contains(holder) {
                    continue;
                }
                match contests[*holder].on_answer(ids[*holder], *answer) {
                    ContestAction::Stay => {}
                    ContestAction::ClaimAgain => {
                        quiet = false;
                        if model.alive().contains(holder) {
                            model.register(*holder);
                        }
                    }
                    ContestAction::YieldTo(_) => {
                        quiet = false;
                        model.leave(*holder);
                    }
                }
            }
            let left = model.alive();
            if quiet && left.len() == 1 && model.served == Some(left[0]) {
                return Some((period, left[0], ever_empty));
            }
            // Every holder yielded, each on an answer that the other's yield had made old: nobody
            // holds the rendezvous. Each of them probes it before a claim, and reads it as free
            // twice in a row (`probe_verdict` in `daemon/event_loop.rs`, then `claim_after_probe`).
            // Any member may claim, not the lowest id, and the probes are spread by a random
            // spread (`probe_backoff.note_verdict`), so one of them is first: it claims, and the
            // others read the rendezvous as held and stay peers. The first is any of them: the
            // first of the actions of the period, here. 2 periods.
            if left.is_empty() {
                ever_empty = true;
                empty_periods += 1;
                if empty_periods >= RECLAIM_PERIODS {
                    empty_periods = 0;
                    let first = apply_order[0];
                    model.register(first);
                    contests[first] = HolderContest::default();
                }
            }
        }
        None
    }

    /// The bound of the note, in periods, for `count` holders: `count + 2` (the last period is the
    /// quiet one that confirms the end). A holder that acts on the answer of the period before can
    /// also yield with every other holder on answers that the others' yields made old, and the
    /// rendezvous then waits `RECLAIM_PERIODS` for a claim and the period before.
    fn bound(_relay: Relay, count: usize, old_answers: bool) -> u32 {
        let count = u32::try_from(count).expect("a small count");
        let older = if old_answers { 1 + RECLAIM_PERIODS } else { 0 };
        count + 2 + older
    }

    /// The words of the log line of the holder probe are a contract with the parsers of the soak and
    /// of the analysers: a test fails if one changes, so that no parser reads a renamed word as zero.
    #[test]
    fn the_words_of_the_log_line_of_the_holder_probe_are_pinned() {
        let id = SecretKey::from_bytes(&[3u8; 32]).public();
        let answers = [
            (WhoAnswer::Ours, "ours", None),
            (WhoAnswer::Rival(id), "rival", None),
            (
                WhoAnswer::Reached(Cause::NoFrame),
                "reached",
                Some(Cause::NoFrame),
            ),
            (
                WhoAnswer::Unknown(Cause::NoConnection),
                "unknown",
                Some(Cause::NoConnection),
            ),
        ];
        for (answer, kind, cause) in answers {
            assert_eq!(answer.kind(), kind, "the word of {answer:?}");
            assert_eq!(answer.cause(), cause, "the cause of {answer:?}");
        }
        let actions = [
            (ContestAction::Stay, "stay"),
            (ContestAction::ClaimAgain, "claim_again"),
            (ContestAction::YieldTo(id), "yield"),
        ];
        for (action, word) in actions {
            assert_eq!(action.word(), word, "the word of {action:?}");
        }
        let causes = [
            (Cause::DialOrAlpnRefused, "dial_or_alpn_refused"),
            (Cause::NoConnection, "no_connection"),
            (Cause::NoFrame, "no_frame"),
            (Cause::FrameNot32Bytes, "frame_not_32_bytes"),
            (Cause::FrameNotAnId, "frame_not_an_id"),
            (Cause::NoStream, "no_stream"),
            (Cause::FrameNotRead, "frame_not_read"),
            (Cause::ProberNotBound, "prober_not_bound"),
            (Cause::ProbeTaskEnded, "probe_task_ended"),
            (Cause::Cancelled, "cancelled"),
            (Cause::NoBusyRung, "no_busy_rung"),
            (Cause::RungAnsweredAsId, "rung_answered_as_id"),
            (Cause::NoRungAnswered, "no_rung_answered"),
            (Cause::NothingToDial, "nothing_to_dial"),
        ];
        for (cause, word) in causes {
            assert_eq!(cause.word(), word, "the word of {cause:?}");
            assert_eq!(cause.to_string(), word, "the display of {cause:?}");
            assert!(
                !word.contains(|letter: char| !(letter.is_ascii_lowercase()
                    || letter == '_'
                    || letter.is_ascii_digit())),
                "{word} is one word of lowercase letters, digits and underscores"
            );
        }
    }

    /// The words are pinned above. This test pins the line as written: every field is there, each
    /// holds one word with no quote and no space, and a field that does not apply is `-`.
    #[test]
    fn the_line_of_the_holder_probe_is_pinned_as_written() {
        let (capture, _guard) = LogCapture::start(tracing::Level::DEBUG);
        let node = SecretKey::from_bytes(&[1u8; 32]).public();
        let rival = SecretKey::from_bytes(&[2u8; 32]).public();
        let node_short = node.fmt_short().to_string();
        let rival_short = rival.fmt_short().to_string();
        let cases = [
            (
                WhoAnswer::Rival(rival),
                ContestAction::ClaimAgain,
                format!(
                    "holder probe node={node_short} kind=rival cause=- rival={rival_short} action=claim_again"
                ),
            ),
            (
                WhoAnswer::Rival(rival),
                ContestAction::YieldTo(rival),
                format!(
                    "holder probe node={node_short} kind=rival cause=- rival={rival_short} action=yield"
                ),
            ),
            (
                WhoAnswer::Reached(Cause::NoFrame),
                ContestAction::Stay,
                format!(
                    "holder probe node={node_short} kind=reached cause=no_frame rival=- action=stay"
                ),
            ),
            (
                WhoAnswer::Unknown(Cause::NoConnection),
                ContestAction::ClaimAgain,
                format!(
                    "holder probe node={node_short} kind=unknown cause=no_connection rival=- action=claim_again"
                ),
            ),
            (
                WhoAnswer::Ours,
                ContestAction::Stay,
                format!("holder probe: ours node={node_short}"),
            ),
        ];
        for (answer, action, line) in cases {
            let mark = capture.text().len();
            log_holder_probe(node, answer, action);
            let logs = capture.text()[mark..].to_owned();
            assert!(
                logs.lines().any(|captured| captured.ends_with(&line)),
                "the line of {answer:?} ends with `{line}` in:\n{logs}"
            );
        }
        let claim_mark = capture.text().len();
        log_claim_on_free(node);
        let line = format!("rendezvous read free twice: claiming node={node_short}");
        let logs = capture.text()[claim_mark..].to_owned();
        assert!(
            logs.lines().any(|captured| captured.ends_with(&line)),
            "the claim line ends with `{line}` in:\n{logs}"
        );
        let misses = [(Miss::SlotTaken, "slot_taken"), (Miss::NoBind, "no_bind")];
        for (miss, word) in misses {
            let mark = capture.text().len();
            log_claim_missed(node, miss);
            let miss_line =
                format!("rendezvous claim ended with no beacon node={node_short} cause={word}");
            let miss_logs = capture.text()[mark..].to_owned();
            assert!(
                miss_logs
                    .lines()
                    .any(|captured| captured.ends_with(&miss_line)),
                "the missed claim line ends with `{miss_line}` in:\n{miss_logs}"
            );
            assert_eq!(miss.to_string(), word, "the display of {miss:?}");
        }
        assert_eq!(
            Miss::of(Held::Claimed),
            None,
            "a claim that stood up has no miss"
        );
        for held in [Held::Rival, Held::Idle, Held::NoRung] {
            assert_eq!(
                Miss::of(held),
                Some(Miss::NoBind),
                "{held:?} bound no endpoint"
            );
        }
    }

    /// **The contest ends with 1 holder on every rule of the relay, in the bound of the note.**
    ///
    /// For 2, 3 and 4 holders, every order of the first claims, every order in which the actions of
    /// one period apply, and holders that act on the answer of the period before as well as on the
    /// answer of this one.
    ///
    /// Only `NewestWins` is measured: a relay with 2 claims of one id served the newest in 200 of
    /// 200 dials. `OldestWins`, `Flip` and `NoPromotion` are assumed rules, and 3 claims or more are
    /// not measured; the test holds the bound under them so that a relay that differs from the
    /// measure does not break the contest. The lowest id wins only on `NewestWins`.
    #[test]
    fn the_contest_ends_with_one_holder_on_every_rule_of_the_relay() {
        for count in 2..=4 {
            let ids = ids_of(count);
            let holders: Vec<usize> = (0..count).collect();
            for relay in [
                Relay::NewestWins,
                Relay::OldestWins,
                Relay::Flip,
                Relay::NoPromotion,
            ] {
                for old_answers in [false, true] {
                    let limit = bound(relay, count, old_answers);
                    let mut slowest = 0;
                    let mut cases = 0;
                    for initial in permutations(&holders) {
                        for apply_order in permutations(&holders) {
                            let ended =
                                periods_to_end(relay, &initial, &apply_order, &ids, old_answers);
                            let Some((periods, survivor, ever_empty)) = ended else {
                                panic!(
                                    "{relay:?}, {count} holders, old answers {old_answers}, claims {initial:?}, actions {apply_order:?}: the contest did not end"
                                );
                            };
                            assert!(
                                periods <= limit,
                                "{relay:?}, {count} holders, old answers {old_answers}, claims {initial:?}, actions {apply_order:?}: {periods} periods, over the bound of {limit}"
                            );
                            if relay == Relay::NewestWins && !old_answers {
                                assert_eq!(
                                    survivor, 0,
                                    "{relay:?}: the lowest id keeps the rendezvous"
                                );
                                assert!(
                                    !ever_empty,
                                    "{relay:?}, {count} holders, claims {initial:?}, actions {apply_order:?}: every holder yielded, and nobody held the rendezvous"
                                );
                            }
                            slowest = slowest.max(periods);
                            cases += 1;
                        }
                    }
                    eprintln!(
                        "{relay:?}, {count} holders, old answers {old_answers}: {cases} cases, slowest {slowest} periods, bound {limit}"
                    );
                }
            }
        }
    }
}
