//! Beacon **policy**: who co-hosts the rendezvous, when they claim it, and how
//! a rival claim is re-checked.
//!
//! The mechanism lives in `crate::beacon`; this is the decision layer above it.
//! Split out of `event_loop` because it was the single hardest thing to hold in
//! mind while reading that file — nine functions spread across four claim
//! sites, interleaved with the tick arms they have nothing to do with.

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::daemon::state::TestHold;
use crate::daemon::state::{RendezvousFlag, Standing};
use tokio::sync::oneshot;

use iroh::EndpointId;

use super::config::CoHostPolicy;
use super::handler_ctx::HandlerCtx;
use super::state::EventLoopState;
use crate::beacon;
use crate::gossip::event::NodeEvent;
use crate::util::clock::Instant;

use crate::gossip::heal;
use crate::lookup;
use crate::transport::webrtc;
use crate::util::tuning;
/// Close the co-hosted rendezvous endpoint before this loop's stack unwinds.
///
/// The `Rendezvous` is a loop local, and letting it merely *drop* aborts its
/// tasks while leaving the endpoint open — iroh then logs `Endpoint dropped
/// without calling Endpoint::close. Aborting ungracefully.` and tears the
/// socket down without the QUIC close. Every co-hosting member hits this on
/// every departure, which in a public mesh is every member.
///
/// A graceful close is not just quieter: it is the same courtesy
/// [`beacon::Rendezvous::shed`] pays mid-run, so peers holding a link to our
/// beacon see an immediate `NeighborDown` rather than waiting out the QUIC
/// idle timeout on a corpse.
///
/// Not in `shutdown()` — the loop owns the `Rendezvous`. The CLI's `exit_on_quit` path
/// `process::exit`s only after the loop has run this, so the peers of the beacon see it close
/// at once.
///
/// An outstanding probe-before-claim goes the same way, and for the same
/// reason: its throwaway endpoint is just as capable of reaching `Drop` open.
/// So does the startup rung probe, which walks the relay ladder on endpoints
/// of its own, and so do the rung probes that are still out: each closes a
/// prober endpoint of its own, which a departure would drop open. The
/// endpoints of the node close with them. All of these close
/// concurrently, so the whole release costs one close budget. `NODE_LEAVE` adds the
/// 2 steps of `Loop::finish` that follow it.
pub(super) async fn release_rendezvous(
    rendezvous: &mut Option<beacon::Rendezvous>,
    probe: &mut Option<beacon::RivalProbe>,
    rung_probe: &mut Option<lookup::StoppableTask>,
    rungs: &mut beacon::RungWatch,
    owned: super::shutdown::OwnedEndpoints,
) {
    let (rendezvous, probe, rung_probe) = (rendezvous.take(), probe.take(), rung_probe.take());
    tokio::join!(
        async {
            if let Some(rung_probe) = rung_probe {
                rung_probe.stop_and_wait().await;
            }
        },
        async {
            if let Some(rendezvous) = rendezvous {
                rendezvous.shed_and_wait().await;
            }
        },
        async {
            if let Some(probe) = probe {
                probe.abort_and_close().await;
            }
        },
        rungs.finish(),
        owned.close(),
    );
}
/// Whether a co-hosting member probes the rendezvous before claiming it —
/// the single source of truth for the `probe_first` flag passed to
/// `beacon::ensure` from every claim site (startup, heal tick, reclaim
/// window). Only `Eager` (the mesh origin) skips the probe: a brand-new
/// mesh has no peers to self-collide with. Every other policy probes, so
/// it never binds a duplicate of a rendezvous a peer already serves — the
/// directory advertiser's shared `rendezvous_id` (`EagerProbed`) or a
/// survivor mid-failover (`Deferred`). Exhaustive on purpose: a new variant
/// must make this decision explicitly rather than defaulting to "probe".
pub(super) fn probes_before_claim(cohost: CoHostPolicy) -> bool {
    match cohost {
        CoHostPolicy::Eager => false,
        CoHostPolicy::EagerProbed | CoHostPolicy::Deferred | CoHostPolicy::Never => true,
    }
}
/// Whether this member claims the rendezvous **at startup** (t=0) rather
/// than deferring to the heal gate ([`may_cohost`]) or never co-hosting.
/// The eager policies claim immediately so a beacon exists before any
/// joiner/discoverer subscribes; whether that claim probes first is the
/// orthogonal [`probes_before_claim`] axis.
pub(super) fn claims_at_startup(cohost: CoHostPolicy) -> bool {
    match cohost {
        CoHostPolicy::Eager | CoHostPolicy::EagerProbed => true,
        CoHostPolicy::Deferred | CoHostPolicy::Never => false,
    }
}
/// May this member co-host the rendezvous yet? See [`CoHostPolicy`].
/// `Never` never co-hosts (a pure consumer); `Eager`/`EagerProbed` always
/// may; a `Deferred` member only once `meshed`, or after
/// `cohost_grace` for an empty mesh (then probe-gated in
/// `beacon::ensure`). Pure + cheap; never blocks `ready`.
pub(super) fn may_cohost(cohost: CoHostPolicy, meshed: bool, started: Instant) -> bool {
    match cohost {
        CoHostPolicy::Never => false,
        CoHostPolicy::Eager | CoHostPolicy::EagerProbed => true,
        CoHostPolicy::Deferred => meshed || started.elapsed() >= tuning::cohost_grace(),
    }
}
/// Does this member read the busy rungs of a private ladder by itself? A member that is not meshed
/// and may not co-host yet has no walk that acts on a probe report, and its book offers only the
/// rungs that were read as ours: the read finds the rung of the beacon. It holds for every policy
/// that may not co-host, a `discover` session (`Never`) included: the session dials the beacon and
/// has no other way to learn its rung.
pub(super) fn reads_ladder_while_unmeshed(
    cohost: CoHostPolicy,
    meshed: bool,
    started: Instant,
    ladder_len: usize,
    holds_beacon: bool,
    reclaim_open: bool,
) -> bool {
    let walk_acts = may_cohost(cohost, meshed, started) && reclaim_open;
    !meshed && !holds_beacon && !walk_acts && ladder_len > 0
}
/// The co-host decision inputs a heal/reclaim tick needs: which policy
/// governs this session, the rendezvous params to (re)claim under, and
/// (for the unmeshed-joiner grace `maybe_cohost` alone reads) when the
/// event loop started.
#[derive(Debug, Clone)]
pub(super) struct CohostArm<'params> {
    pub(super) policy: CoHostPolicy,
    pub(super) params: &'params beacon::RendezvousParams,
    pub(super) started: Instant,
}
/// Heal-tick co-host: stand up the beacon if this member may serve it
/// now (`may_cohost`). Claim-if-free in private; in public a non-`Eager`
/// member probes first (`beacon::ensure`) so it never registers a
/// duplicate rendezvous that would capture its own bootstrap dial.
pub(super) async fn maybe_cohost(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    arm: &CohostArm<'_>,
    current: &mut Option<beacon::Rendezvous>,
    probe: &mut Option<beacon::RivalProbe>,
) {
    if state.claims_are_held() {
        return;
    }
    // A loopback holder above the first rung yields it when a lower rung answers as our mesh. The
    // public shed is on a timer that backs off; here the question is positive and cheap, so it
    // is asked on every heal tick, and nothing is asked of a holder on the first rung. The
    // answer is a reading in `state.rungs`, which the walk after the shed reads as ours.
    //
    // The same tick asks whether the rung that this holder serves still answers: a beacon that
    // stopped answering keeps its rung, nobody else claims it, and the members that joined
    // through it hold other links. It sheds at the second check that does not answer, never at
    // the first, and claims again.
    if let Some(held) = current.as_ref()
        && !arm.params.bind_ports.is_empty()
        && let Some(own) = held.rung_in(&arm.params.bind_ports)
        && let Some(&own_port) = arm.params.bind_ports.get(own)
    {
        let node = context.endpoint.id();
        let stopped = state.rungs.own_rung_failed(arm.params, node, own_port);
        let yields = own > 0
            && state
                .rungs
                .lower_rung_that_answers(arm.params, node, own)
                .is_some();
        if stopped || yields {
            state.rungs.own_check_done();
            shed_beacon(state, arm.params, current);
            return;
        }
    }
    if may_cohost(
        arm.policy,
        state.standing.contains(&Standing::Meshed),
        arm.started,
    ) {
        // A member that keeps finding the rival probes less often; the reclaim window is not held back.
        let would_probe = arm.params.bind_ports.is_empty() && probes_before_claim(arm.policy);
        if would_probe && probe.is_none() && !state.probe_backoff.due(Instant::now()) {
            return;
        }
        let held = if may_probe_to_claim(state) {
            beacon::walk_ladder(
                arm.params,
                context.endpoint,
                &state.address_book,
                current,
                probes_before_claim(arm.policy),
                probe,
                &mut state.rungs,
            )
            .await
        } else {
            // A holder is known, so the ladder is not walked. If the link to it is lost, it may
            // have moved to another rung, and the book names the rung that was read last.
            if !state.rendezvous_flags.contains(&RendezvousFlag::Linked) {
                beacon::refresh_holder_rung(
                    arm.params,
                    context.endpoint,
                    &state.address_book,
                    &mut state.rungs,
                )
                .await;
            }
            beacon::Held::Idle
        };
        match held {
            beacon::Held::Claimed => {
                arm_holder_probe(state, arm.policy, arm.params);
                // The new rendezvous never dials us; the reclaim tick re-grafts it.
                state.arm_reclaim(Instant::now());
                offer_to_the_new_holder(state, context);
            }
            beacon::Held::Rival => state.note_holder_outside_mesh(Instant::now()),
            beacon::Held::NoRung => note_no_rung_free(state, context, arm.params.bind_ports.len()),
            beacon::Held::Idle => {}
        }
    }
}
/// Every rung of the ladder is held by another process, so no member can serve the rendezvous and
/// the room cannot be joined through it until one lets go. Said once per repeat interval, however
/// often the walk runs: to the log, and to the sink so that the app can tell its user.
fn note_no_rung_free(state: &mut EventLoopState, context: &HandlerCtx<'_>, ports: usize) {
    let now = Instant::now();
    let repeat = tuning::NO_RUNG_REPEAT;
    if state
        .no_rung_noted_at
        .is_some_and(|at| now.saturating_duration_since(at) < repeat)
    {
        return;
    }
    state.no_rung_noted_at = Some(now);
    tracing::warn!(
        target: "habilis_network::beacon",
        ports,
        "no rendezvous port is free: other processes hold every port of this room"
    );
    context.sink.emit(NodeEvent::Info(format!(
        "no rendezvous port is free: other processes hold all {ports} ports of this room"
    )));
}

/// Offer to our new beacon at once, to the address that the claim just registered. The round of
/// this member that was started while nobody held the rendezvous was ended by
/// [`schedule_rival_recheck`].
pub(super) fn offer_to_the_new_holder(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    webrtc::rendezvous::offer_rendezvous_off_tick(state, context);
}

/// A probe found a holder of the rendezvous that is not us ("staying peer"): the holder changed for
/// this member too. The round that it started while nobody held the rendezvous cannot find the
/// holder, so it is ended and the offer is made anew, as at a claim.
///
/// It is also a holder that no member of our mesh may be known to host: the member then owes a
/// return to it ([`EventLoopState::note_holder_outside_mesh`]).
pub(super) fn note_rival_holds(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    state.cancel_rendezvous_round();
    offer_to_the_new_holder(state, context);
    state.note_holder_outside_mesh(Instant::now());
}

/// Fast event-driven failover: while the post-`NeighborDown` reclaim
/// window is open, retry the rendezvous claim so a survivor takes the
/// freed port in ~1s instead of waiting for the 15s heal tick. A no-op
/// outside the window (just an `Instant` compare) and idempotent once
/// the rendezvous is held. `Never` consumers never reclaim; everyone
/// else probes first (`!Eager`) so a survivor that already took over
/// isn't displaced by a colliding duplicate.
///
/// Reclaiming the identity is only half of what the window is for. The
/// other half is the *symmetric* loss: the beacon is alive and what we lost
/// is our own gossip link to it — to somebody else's beacon, or to one we
/// hold, which never dials its own peer (`beacon::claim`). `ensure` then
/// returns `false`, which used to end the tick — leaving us off the mesh
/// until the heal arm's re-graft came round, up to 15s later. On a loopback
/// mesh that is the whole
/// bootstrap: a peer whose rendezvous link drops in the first
/// milliseconds sees an empty roster for 15s, and a two-peer mesh simply
/// never forms in time. So the re-graft rides this ticker too.
pub(super) async fn maybe_reclaim(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    arm: &CohostArm<'_>,
    current: &mut Option<beacon::Rendezvous>,
    probe: &mut Option<beacon::RivalProbe>,
) {
    if state.claims_are_held() {
        return;
    }
    if arm.policy != CoHostPolicy::Never
        && state
            .reclaim_until
            .is_some_and(|deadline| Instant::now() < deadline)
    {
        let held = if may_probe_to_claim(state) {
            beacon::walk_ladder(
                arm.params,
                context.endpoint,
                &state.address_book,
                current,
                probes_before_claim(arm.policy),
                probe,
                &mut state.rungs,
            )
            .await
        } else {
            beacon::Held::Idle
        };
        match held {
            beacon::Held::Claimed => {
                arm_holder_probe(state, arm.policy, arm.params);
                offer_to_the_new_holder(state, context);
                return;
            }
            beacon::Held::Rival => state.note_holder_outside_mesh(Instant::now()),
            beacon::Held::NoRung => note_no_rung_free(state, context, arm.params.bind_ports.len()),
            beacon::Held::Idle => {}
        }
        if regrafts_rendezvous(
            state.rendezvous_flags.contains(&RendezvousFlag::Linked),
            state.rendezvous_wanted(),
        ) && webrtc::rendezvous::rendezvous_graftable(state)
        {
            tracing::info!(
                target: "habilis_network::gossip",
                "reclaim tick: re-graft the rendezvous (link lost)"
            );
            heal::tick_heal(arm.params.id, context.sender).await;
        }
    }
}

/// Waits for the close of a beacon that was shed, so that the run does not end with the close of its
/// endpoint in flight. A receiver whose task was cancelled ends the wait too.
pub(super) async fn wait_for_shed_close(state: &mut EventLoopState) {
    if let Some(closed) = state.beacon_closing.take() {
        let _ = closed.await;
    }
}

/// Waits for the closes of the endpoints that read the busy rungs at setup, so that the run does
/// not end with one of them in flight. Each is bounded where it was spawned, and a receiver whose
/// task was cancelled ends its wait too.
pub(super) async fn wait_for_prober_closes(closes: Vec<oneshot::Receiver<()>>) {
    for closed in closes {
        let _ = closed.await;
    }
}

/// Let go of the beacon at once and read the ladder again: the endpoint is closed, the address of
/// the shed beacon leaves the book, and the reclaim window opens, so that the next walk reads
/// whoever holds a rung (and claims the lowest free one when nobody does).
fn shed_beacon(
    state: &mut EventLoopState,
    params: &beacon::RendezvousParams,
    rendezvous: &mut Option<beacon::Rendezvous>,
) {
    let Some(held) = rendezvous.take() else {
        return;
    };
    tracing::info!(
        target: "habilis_network::gossip",
        "beacon shed: a lower rung of the ladder answers as our mesh"
    );
    let released = held
        .rung_in(&params.bind_ports)
        .map(|index| params.bind_ports[index]);
    state.beacon_closing = Some(held.shed_then());
    state.next_holder_probe = None;
    state.cancel_rendezvous_round();
    forget_the_shed_rung(state, params, released);
    state.rendezvous_flags.remove(&RendezvousFlag::Linked);
    state.forget_rendezvous_verdict();
    state.arm_reclaim(Instant::now());
}

/// The book after the beacon was shed on the rung `released`. A shed is evidence about one rung:
/// the rung that the beacon was on is not ours any more, and so is a rung that a reading took back
/// (`RungWatch::not_ours_rungs`). Every other rung of the ladder stays, as at the heal registration:
/// a rung that was read as ours and that nobody read since is no evidence against it. The endpoint
/// forgets the released rung at the next heal tick (`RungWatch::take_retired`). A public mesh has
/// no ladder: the entry holds the addresses of the beacon that was shed and what the mesh
/// registered by itself (a relay rung), which is written back.
fn forget_the_shed_rung(
    state: &mut EventLoopState,
    params: &beacon::RendezvousParams,
    released: Option<u16>,
) {
    if let Some(port) = released {
        state.rungs.release_rung(port);
    }
    if params.bind_ports.is_empty() {
        state.address_book.remove_endpoint_info(params.id);
    } else {
        let not_ours = state.rungs.not_ours_rungs();
        beacon::forget_rungs_in_book(params, &state.address_book, |port| {
            released == Some(port) || not_ours.contains(&port)
        });
    }
    super::setup::register_rendezvous(&state.address_book, params, &state.rungs.offered_rungs());
}

/// Tests only: make the beacon stop answering, if a test asked for it (`Beacons::StallBeacon`).
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(super) fn stall_on_request(
    state: &mut EventLoopState,
    rendezvous: Option<&beacon::Rendezvous>,
) {
    if state.test_holds.remove(&TestHold::Stall)
        && let Some(held) = rendezvous
    {
        tracing::info!(
            target: "habilis_network::gossip",
            "beacon stalled at the request of a test"
        );
        held.stall();
    }
}

/// Tests only: shed the beacon now, if a test asked for it (`Beacons::ShedBeacon`), as the check
/// of the lower rungs does after its decision.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(super) fn shed_on_request(
    state: &mut EventLoopState,
    params: &beacon::RendezvousParams,
    rendezvous: &mut Option<beacon::Rendezvous>,
) {
    if state.test_holds.remove(&TestHold::Shed) {
        shed_beacon(state, params, rendezvous);
    }
}

/// Whether a reclaim tick that did not claim should re-graft.
///
/// Only when the link is lost: a peer that still holds a live link must not
/// dial again — both heal legs dial `GOSSIP_ALPN`, which the beacon's gossip
/// adopts, superseding the healthy link and flapping it once per tick.
/// Holding the beacon is no exception: our own rendezvous never dials us
/// (`beacon::claim`), so our side re-grafts it like any other. That is the
/// condition [`super::heal::run_heal`] gates its own re-graft on; this one
/// just gets there sooner.
///
/// And only a node that wants the rendezvous: one with enough links to others
/// let it go on purpose, and a graft here would undo that.
fn regrafts_rendezvous(rendezvous_linked: bool, rendezvous_wanted: bool) -> bool {
    !rendezvous_linked && rendezvous_wanted
}
/// Whether this session's beacon is subject to the periodic rival
/// re-check shed: any **public** co-host that had to *probe* for the
/// identity rather than owning it.
///
/// `EagerProbed` claimants share a `rendezvous_id` with concurrent peers
/// (topic joiners, directory advertisers) and can double-claim inside each
/// other's probe window. `Deferred` was excluded here on the premise that it
/// "meshes before claiming" — but `may_cohost` also lets an unmeshed joiner
/// claim after the co-host grace, and a meshed one still claims on the word of
/// a probe. When that probe could not resolve the id (the defect
/// `beacon::spawn_rival_probe` documents), *every* survivor of a departed
/// origin claimed a duplicate, and this shed was the one mechanism that would
/// have re-arbitrated it — switched off for the policy that needed it. So the
/// gate is now "did a probe decide this claim", which is the property that
/// makes a same-id split possible in the first place.
///
/// Still excluded: `Eager` (the mesh origin owns the identity from t=0, and
/// shedding it would churn the only beacon a cold mesh has), `Never` (claims
/// nothing), and every loopback mesh. A port ladder arbitrates atomically at
/// bind time, but the identity probe that follows a failed bind can read a
/// loaded host wrongly, and two holders then serve one mesh. The loopback
/// repair is not this timer: a holder above the first rung asks, on every heal
/// tick, whether a lower rung answers as our mesh, and yields on a positive
/// answer only (`maybe_cohost`, `beacon::lower_rung_that_answers`).
pub(super) fn rival_recheck_applies(policy: CoHostPolicy, public: bool) -> bool {
    matches!(policy, CoHostPolicy::EagerProbed | CoHostPolicy::Deferred) && public
}
/// Whether a member that does not hold the rendezvous may probe it in order to claim it. Not
/// while it knows a holder: its own shed makes the shared id read free for a moment, and a claim
/// on that reading stands up the second holder again.
pub(super) fn may_probe_to_claim(state: &EventLoopState) -> bool {
    !state.rival_holder_known()
}

/// A probe that was already in flight when a holder became known must not decide a claim.
pub(super) fn verdict_after_known_holders(found_rival: bool, state: &EventLoopState) -> bool {
    found_rival || state.rival_holder_known()
}

/// Arm the probe of the holder after a claim, and end the round of this member that was started
/// while nobody held the rendezvous: that round cannot find the beacon just claimed. The one funnel
/// that every claim passes. A claim again passes it too, so it does not reset the contest: the
/// count of claims against a rival must survive a claim. A contest starts clean where a holder
/// starts or ends (the first claim, [`release_to_rival`], a rehome).
pub(super) fn arm_holder_probe(
    state: &mut EventLoopState,
    policy: CoHostPolicy,
    params: &beacon::RendezvousParams,
) {
    state.cancel_rendezvous_round();
    if !rival_recheck_applies(policy, params.bind_ports.is_empty()) {
        return;
    }
    state.next_holder_probe = Some(Instant::now() + tuning::heal_interval());
}

/// Start the probe of the holder when it is due: it asks who serves the rendezvous on the rung of
/// its own beacon. One period after the start, the next one is due, whether or not this one could
/// start.
pub(super) async fn start_holder_probe_if_due(
    state: &mut EventLoopState,
    arm: &CohostArm<'_>,
    rendezvous: Option<&beacon::Rendezvous>,
    probe: &mut Option<beacon::RivalProbe>,
    node: EndpointId,
) {
    if rendezvous.is_none()
        || probe.is_some()
        || !rival_recheck_applies(arm.policy, arm.params.bind_ports.is_empty())
    {
        return;
    }
    if state
        .next_holder_probe
        .is_none_or(|deadline| Instant::now() < deadline)
    {
        return;
    }
    state.next_holder_probe = Some(Instant::now() + tuning::heal_interval());
    *probe = beacon::spawn_holder_probe(arm.params, node).await;
}

/// The answer of the probe of the holder. The contest decides: stay, claim again (make before
/// break: the new beacon binds first and the old one closes in the same step), or yield to the
/// rival. An answer that comes after the beacon went is about nothing and is dropped.
pub(super) async fn apply_holder_answer(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    arm: &CohostArm<'_>,
    rendezvous: &mut Option<beacon::Rendezvous>,
    answer: beacon::WhoAnswer,
) {
    if rendezvous.is_none() {
        return;
    }
    let node = context.endpoint.id();
    let action = state.holder_contest.on_answer(node, answer);
    if answer == beacon::WhoAnswer::Ours {
        tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), "holder probe: ours");
    } else {
        // The fields are a contract with the parsers of the soak and the analysers (a test pins the
        // words). `cause` is empty unless the answer is reached or unknown; `rival` is empty unless
        // the answer names one.
        let rival = if let beacon::WhoAnswer::Rival(id) = answer {
            id.fmt_short().to_string()
        } else {
            String::new()
        };
        tracing::info!(
            target: "habilis_network::beacon",
            node = %node.fmt_short(),
            kind = answer.kind(),
            cause = answer.cause(),
            rival = %rival,
            action = action.word(),
            "holder probe"
        );
    }
    match action {
        beacon::ContestAction::Stay => {}
        beacon::ContestAction::ClaimAgain => {
            let held = beacon::claim::claim_again(
                arm.params,
                context.endpoint,
                &state.address_book,
                rendezvous,
                &mut state.rungs,
            )
            .await;
            if held == beacon::Held::Claimed {
                arm_holder_probe(state, arm.policy, arm.params);
                state.arm_reclaim(Instant::now());
                offer_to_the_new_holder(state, context);
            }
        }
        beacon::ContestAction::YieldTo(rival) => {
            tracing::info!(
                target: "habilis_network::beacon",
                node = %node.fmt_short(),
                rival = %rival.fmt_short(),
                "beacon yielded: another member serves the rendezvous"
            );
            release_to_rival(state, arm, rendezvous);
        }
    }
}

/// Let go of the beacon for a rival that keeps the rendezvous, and read the ladder again: the
/// endpoint closes, the address of the beacon leaves the book, and the reclaim window opens, so that
/// the next walk reads the rival and the overlays merge.
fn release_to_rival(
    state: &mut EventLoopState,
    arm: &CohostArm<'_>,
    rendezvous: &mut Option<beacon::Rendezvous>,
) {
    // `shed`, not a plain drop: the graceful endpoint close turns the
    // peer's link to its own dead beacon into an immediate
    // `NeighborDown` instead of a zombie that only dies at the QUIC idle
    // timeout — the zombie both stalls the post-shed re-graft and leaves
    // a poisoned pool entry under the shared id.
    let mut released: Option<u16> = None;
    if let Some(held) = rendezvous.take() {
        released = held
            .rung_in(&arm.params.bind_ports)
            .map(|index| arm.params.bind_ports[index]);
        state.beacon_closing = Some(held.shed_then());
    }
    state.next_holder_probe = None;
    state.holder_contest = beacon::HolderContest::default();
    // A round that was running against our own beacon now has nothing to find.
    state.cancel_rendezvous_round();
    // The book still names the beacon just shed; the next holder writes its own address.
    forget_the_shed_rung(state, arm.params, released);
    // Don't wait for that `NeighborDown` either — clear the link flag now
    // (mirroring the hard resume edge), or a yielding node's heal ticks
    // idle on "rendezvous linked" instead of grafting the rival's beacon.
    state.rendezvous_flags.remove(&RendezvousFlag::Linked);
    // We just released the identity to re-probe it, so the reading that
    // stood before the release answers a question we have re-asked.
    state.forget_rendezvous_verdict();
    // Arm the fast burst explicitly rather than waiting for our own
    // beacon's `NeighborDown` to do it — the re-probe (and the re-claim
    // when no rival exists) then runs within ~RECLAIM_INTERVAL.
    state.arm_reclaim(Instant::now());
}

#[cfg(test)]
mod tests {
    use super::super::config::CoHostPolicy;
    use super::super::state::RivalFlag;
    use super::{
        claims_at_startup, probes_before_claim, regrafts_rendezvous, rival_recheck_applies,
    };
    use crate::daemon::state::Standing;
    use std::time::Duration;

    use crate::beacon::claim;
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::{cohost_arm, config, state};
    use crate::gossip::event::SilentSink;
    use crate::protocol::identity::Identity;
    use crate::protocol::{MeshId, Nickname, meshes};
    use crate::transport::{MeshSender, PayloadPath};
    use crate::util::{clock, tuning};
    use crate::{beacon, lookup, protocol, testing};
    use iroh_gossip::proto;
    use n0_future::task;
    use std::{future, net};
    use tokio::sync::{mpsc, oneshot};
    use tokio::time;

    /// A shed takes out of the book the rung that the beacon was on, and nothing else on evidence
    /// that it is not ours: a rung that was read as ours before, and that nobody read since, stays,
    /// as the heal registration keeps it. The rung that was released is queued for the endpoint.
    #[test]
    fn a_shed_forgets_the_rung_it_released_and_keeps_the_rung_that_was_read_as_ours() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut params = public_params();
        params.bind_ports = vec![41_001, 41_002];
        let at = |port: u16| {
            iroh::EndpointAddr::new(params.id)
                .with_ip_addr(net::SocketAddr::from((net::Ipv4Addr::LOCALHOST, port)))
        };
        let mut state = testing::fresh_state();
        state.rungs.clear_foreign(41_001);
        state.rungs.clear_foreign(41_002);
        lookup::add_peer_addr(&state.address_book, at(41_001));
        lookup::add_peer_addr(&state.address_book, at(41_002));
        state.rungs.expire_ours();

        cohost_arm::forget_the_shed_rung(&mut state, &params, Some(41_001));

        let info = state.address_book.get_endpoint_info(params.id);
        let mut booked: Vec<u16> = Vec::new();
        if let Some(info) = info {
            booked = info.ip_addrs().map(net::SocketAddr::port).collect();
        }
        assert_eq!(
            booked,
            vec![41_002],
            "the book keeps the rung that was read as ours, and only that one"
        );
        assert_eq!(
            state.rungs.take_retired(),
            vec![41_001],
            "the endpoint is told to forget the rung that was released"
        );
    }

    /// A `discover` session never co-hosts and dials the beacon, and its book offers only the
    /// rungs that were read as ours, so it reads the ladder while it is not meshed, as a joiner.
    #[test]
    fn a_discover_session_reads_the_ladder_while_it_is_not_meshed() {
        let _guard = ::habilis_network_test_tracing::init();
        let started = clock::Instant::now();
        assert!(
            cohost_arm::reads_ladder_while_unmeshed(
                CoHostPolicy::Never,
                false,
                started,
                8,
                false,
                false
            ),
            "a discover session that is not meshed reads the ladder"
        );
        assert!(
            !cohost_arm::reads_ladder_while_unmeshed(
                CoHostPolicy::Never,
                true,
                started,
                8,
                false,
                false
            ),
            "a meshed session reads no ladder"
        );
        assert!(
            !cohost_arm::reads_ladder_while_unmeshed(
                CoHostPolicy::Never,
                false,
                started,
                0,
                false,
                false
            ),
            "a public mesh has no ladder"
        );
        assert!(
            cohost_arm::reads_ladder_while_unmeshed(
                CoHostPolicy::Deferred,
                false,
                started,
                8,
                false,
                false
            ),
            "a deferred joiner that is not meshed reads the ladder"
        );
        assert!(
            !cohost_arm::reads_ladder_while_unmeshed(
                CoHostPolicy::Eager,
                false,
                started,
                8,
                false,
                true
            ),
            "an eager member walks the ladder while the reclaim window is open"
        );
    }

    /// An eager joiner walks the ladder only while the reclaim window is open (6 s). After that
    /// no walk acts on a probe report until the heal tick, 15 s later, and the book offers only the
    /// rungs read as ours: a probe that timed out on a loaded host left the joiner with no address
    /// for the 30 s that iroh-gossip waits before it warns. It reads the ladder by itself then.
    #[test]
    fn an_eager_joiner_without_a_proven_rung_reads_the_ladder_when_the_walk_is_over() {
        let _guard = ::habilis_network_test_tracing::init();
        let started = clock::Instant::now();
        assert!(
            cohost_arm::reads_ladder_while_unmeshed(
                CoHostPolicy::Eager,
                false,
                started,
                8,
                false,
                false
            ),
            "the walk is over: the joiner reads the ladder"
        );
        assert!(
            !cohost_arm::reads_ladder_while_unmeshed(
                CoHostPolicy::Eager,
                false,
                started,
                8,
                false,
                true
            ),
            "the walk acts while the reclaim window is open"
        );
        assert!(
            !cohost_arm::reads_ladder_while_unmeshed(
                CoHostPolicy::Eager,
                false,
                started,
                8,
                true,
                false
            ),
            "a member that holds the beacon does not read its own rung"
        );
    }

    /// Public-mesh rendezvous parameters: the rival re-check applies to them.
    fn public_params() -> beacon::RendezvousParams {
        let secret = iroh::SecretKey::generate();
        beacon::RendezvousParams {
            topic_id: proto::TopicId::from_bytes([7u8; 32]),
            id: secret.public(),
            secret,
            bind_ports: Vec::new(),
            lookups: meshes::LookupOpts::loopback(),
            relay_transport: PayloadPath::DirectOnly,
            bootstrap_relay: None,
            rung_tx: mpsc::unbounded_channel().0,
            bind_options: lookup::TransportOpts::default(),
        }
    }

    /// An endpoint on loopback, closed at the end of the test whatever the test does with it.
    async fn loopback_endpoint() -> iroh::Endpoint {
        let endpoint = lookup::build_endpoint(
            &meshes::LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            lookup::TransportHandles::default(),
        )
        .await
        .expect("loopback endpoint");
        let closer = endpoint.clone();
        habilis_network_test_tracing::at_end(async move { closer.close().await });
        endpoint
    }

    /// A member for the tests of the holder probe: its endpoint, the pieces of a handler context, its
    /// state, and the beacon that it holds.
    struct Member {
        endpoint: iroh::Endpoint,
        sender: MeshSender,
        mesh: MeshId,
        author: Nickname,
        identity: Identity,
        sink: SilentSink,
        state: state::EventLoopState,
        rendezvous: Option<beacon::Rendezvous>,
    }

    impl Member {
        async fn new(params: &beacon::RendezvousParams) -> Self {
            use iroh_gossip::net::Gossip;

            let endpoint = loopback_endpoint().await;
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let (gossip_sender, _receiver) = gossip
                .subscribe(params.topic_id, Vec::new())
                .await
                .expect("subscribe without a bootstrap")
                .split();
            let mut state = testing::fresh_state();
            state.rungs = beacon::RungWatch::detached();
            Self {
                endpoint,
                sender: MeshSender::new(gossip_sender),
                mesh: MeshId::from("test"),
                author: testing::nick("member"),
                identity: Identity::generate(),
                sink: SilentSink,
                state,
                rendezvous: None,
            }
        }

        async fn claim(&mut self, params: &beacon::RendezvousParams) {
            let book = lookup::address_book(&self.endpoint);
            let claimed = claim::claim(params, &self.endpoint, &book, &mut self.rendezvous).await;
            assert!(claimed, "the member claims the rendezvous");
        }

        /// The probe of the holder, as the loop runs it: ask who serves the id on the own rung from a
        /// throwaway endpoint, then give the answer to the contest.
        async fn ask_and_apply(&mut self, params: &beacon::RendezvousParams) {
            use iroh::endpoint::presets;
            use iroh::{EndpointAddr, RelayMode};

            let rung = params.bootstrap_relay.clone().expect("a rung");
            let prober: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::custom([rung.clone()]))
                .bind()
                .await
                .expect("a prober");
            let target = EndpointAddr::new(params.id).with_relay_url(rung);
            let answer =
                beacon::ask_who(&prober, target, self.endpoint.id(), tuning::HEAL_PROBE).await;
            prober.close().await;
            self.apply(params, answer).await;
        }

        /// The answer of the probe of the holder, given to the contest as the loop gives it.
        async fn apply(&mut self, params: &beacon::RendezvousParams, answer: beacon::WhoAnswer) {
            let context = HandlerCtx {
                sender: &self.sender,
                endpoint: &self.endpoint,
                mesh: &self.mesh,
                author: &self.author,
                identity: &self.identity,
                our_pubkey: self.identity.author_key(),
                max_connections: 16,
                rendezvous_id: params.id,
                external_msg_tx: None,
                sink: &self.sink,
            };
            let arm = super::CohostArm {
                policy: CoHostPolicy::EagerProbed,
                params,
                started: clock::Instant::now(),
            };
            super::apply_holder_answer(
                &mut self.state,
                &context,
                &arm,
                &mut self.rendezvous,
                answer,
            )
            .await;
        }

        fn sockets(&self) -> Vec<net::SocketAddr> {
            self.rendezvous
                .as_ref()
                .map(|held| held.endpoint.bound_sockets())
                .unwrap_or_default()
        }
    }

    /// **The count of claims against a rival survives a claim again, so the bound acts.**
    ///
    /// On a relay that keeps the older claim served, a holder with the lower id reads the same rival
    /// each period. It claims again `CLAIMS_BEFORE_YIELD` times, and then yields. If a claim reset the
    /// count, it would claim for ever and the 2 groups would never merge.
    #[test]
    fn a_holder_that_keeps_reading_the_same_higher_rival_yields_after_its_claims() {
        use crate::lookup::test_relay;
        use crate::protocol::meshes::{LookupOpts, RelayChoice};

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Another endpoint connected with the same endpoint id",
            );
            let (relay, _server) = test_relay::spawn_plain().await.expect("a local relay");
            let mut params = public_params();
            params.lookups = LookupOpts::new(RelayChoice::Custom(vec![relay.clone()]));
            params.bootstrap_relay = Some(relay);
            let mut holder = Member::new(&params).await;
            holder.claim(&params).await;
            let mut rival = iroh::SecretKey::generate().public();
            while rival < holder.endpoint.id() {
                rival = iroh::SecretKey::generate().public();
            }
            let answer = beacon::WhoAnswer::Rival(rival);

            let first = holder.sockets();
            holder.apply(&params, answer).await;
            assert!(
                holder.rendezvous.is_some(),
                "the first read: claim again, not yield"
            );
            let second = holder.sockets();
            assert_ne!(first, second, "the first read made a new claim");
            holder.apply(&params, answer).await;
            assert!(
                holder.rendezvous.is_some(),
                "the second read: claim again, not yield"
            );
            assert_ne!(second, holder.sockets(), "the second read made a new claim");
            holder.apply(&params, answer).await;
            assert!(
                holder.rendezvous.is_none(),
                "the third read of the same rival: the holder yields"
            );
            super::wait_for_shed_close(&mut holder.state).await;
            holder.endpoint.close().await;
        });
    }

    /// **A claim does not clear the count of answers with no proof.**
    ///
    /// 2 `Unknown`, a claim that the funnel of every claim sees, and 1 more `Unknown` make 3 in a
    /// row: the holder claims again, as if the claim had not come between.
    #[test]
    fn a_claim_between_unknown_answers_does_not_clear_their_count() {
        use crate::lookup::test_relay;
        use crate::protocol::meshes::{LookupOpts, RelayChoice};

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::allow_warn(
                "iroh::socket::transports::relay::actor",
                "Another endpoint connected with the same endpoint id",
            );
            let (relay, _server) = test_relay::spawn_plain().await.expect("a local relay");
            let mut params = public_params();
            params.lookups = LookupOpts::new(RelayChoice::Custom(vec![relay.clone()]));
            params.bootstrap_relay = Some(relay);
            let mut holder = Member::new(&params).await;
            holder.claim(&params).await;
            let unknown = beacon::WhoAnswer::Unknown("a test");
            let before = holder.sockets();

            holder.apply(&params, unknown).await;
            holder.apply(&params, unknown).await;
            assert_eq!(before, holder.sockets(), "2 unknown answers claim nothing");
            super::arm_holder_probe(&mut holder.state, CoHostPolicy::EagerProbed, &params);
            holder.apply(&params, unknown).await;

            assert_ne!(
                before,
                holder.sockets(),
                "the third unknown answer in a row claims again"
            );
            let held = holder.rendezvous.take().expect("the beacon");
            held.shed_and_wait().await;
            holder.endpoint.close().await;
        });
    }

    /// **Two holders of one rendezvous id end with one, and the lower id keeps it.**
    ///
    /// On a relay that serves the newest claim, in both orders of the first claims. A holder that is
    /// not served and has the lower id claims again, make before break; the other reads the rival and
    /// yields. The loop of asks is the one of the event loop, without its timers.
    #[test]
    fn two_holders_of_one_rendezvous_end_with_one_and_the_lower_id_keeps_it() {
        use crate::lookup::test_relay;
        use crate::protocol::meshes::{LookupOpts, RelayChoice};

        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // The second claim of one id displaces the first on the relay, and the relay tells the
            // session that it displaced. A handover does the same by design.
            ::habilis_network_test_tracing::expect_warn(
                "iroh::socket::transports::relay::actor",
                "Another endpoint connected with the same endpoint id",
            );
            let (relay, _server) = test_relay::spawn_plain().await.expect("a local relay");
            for lower_claims_first in [true, false] {
                let mut params = public_params();
                params.lookups = LookupOpts::new(RelayChoice::Custom(vec![relay.clone()]));
                params.bootstrap_relay = Some(relay.clone());
                let first = Member::new(&params).await;
                let second = Member::new(&params).await;
                let (mut lower, mut higher) = if first.endpoint.id() < second.endpoint.id() {
                    (first, second)
                } else {
                    (second, first)
                };
                if lower_claims_first {
                    lower.claim(&params).await;
                    higher.claim(&params).await;
                } else {
                    higher.claim(&params).await;
                    lower.claim(&params).await;
                }

                let mut rounds = 0;
                let mut claimed_again = 0;
                while lower.rendezvous.is_some() && higher.rendezvous.is_some() {
                    assert!(rounds < 6, "the contest did not end in 6 rounds");
                    let before = lower.rendezvous.as_ref().map(|held| held.endpoint.clone());
                    lower.ask_and_apply(&params).await;
                    // A node has 1 live endpoint of the id after a claim again: the old one closed in
                    // the same step as the new one bound.
                    if let (Some(old), Some(held)) = (before, lower.rendezvous.as_ref())
                        && old.bound_sockets() != held.endpoint.bound_sockets()
                    {
                        for _ in 0..100 {
                            if old.is_closed() {
                                break;
                            }
                            time::sleep(Duration::from_millis(50)).await;
                        }
                        assert!(
                            old.is_closed(),
                            "the old endpoint closed after the claim again"
                        );
                        assert!(!held.endpoint.is_closed(), "the new endpoint is live");
                        claimed_again += 1;
                    }
                    higher.ask_and_apply(&params).await;
                    rounds += 1;
                }
                assert_eq!(
                    claimed_again,
                    u32::from(lower_claims_first),
                    "the lower id claims again once, when it is not served"
                );
                assert!(
                    lower.rendezvous.is_some(),
                    "the lower id keeps the rendezvous (it claimed first: {lower_claims_first})"
                );
                assert!(
                    higher.rendezvous.is_none(),
                    "the higher id yielded (the lower claimed first: {lower_claims_first})"
                );
                // The node that claimed again closed its old endpoint: one endpoint of the id.
                let held = lower.rendezvous.take().expect("the beacon of the lower id");
                held.shed_and_wait().await;
                super::wait_for_shed_close(&mut higher.state).await;
                lower.endpoint.close().await;
                higher.endpoint.close().await;
            }
        });
    }

    /// A member that knows a holder and holds nothing does not probe to claim: its own shed makes
    /// the shared id read free for a moment, and a claim on that reading stands up the second
    /// holder again. The holder's `PeerInfo` without the flag ends it.
    #[test]
    fn a_known_holder_keeps_us_from_probing_to_claim() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = testing::fresh_state();
        let own = iroh::SecretKey::generate().public();
        let holder = iroh::SecretKey::generate().public();
        let now = clock::Instant::now();
        assert!(super::may_probe_to_claim(&state), "no holder known: probe");

        state.note_rival_beacon_flag(
            own,
            protocol::AuthorKey::from([9u8; 32]),
            holder,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );
        assert!(!super::may_probe_to_claim(&state), "a holder is known");

        state.note_rival_beacon_flag(
            own,
            protocol::AuthorKey::from([9u8; 32]),
            holder,
            RivalFlag {
                proven: true,
                held: false,
            },
            now,
        );
        assert!(super::may_probe_to_claim(&state), "it let go: probe again");
    }

    /// A probe that was already out when the holder became known reads the id as free. It must
    /// not decide a claim.
    #[test]
    fn a_probe_that_read_free_does_not_claim_while_a_holder_is_known() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = testing::fresh_state();
        let own = iroh::SecretKey::generate().public();
        let holder = iroh::SecretKey::generate().public();
        assert!(
            !super::verdict_after_known_holders(false, &state),
            "a probe that reads free does not claim while a holder is known"
        );

        state.note_rival_beacon_flag(
            own,
            protocol::AuthorKey::from([9u8; 32]),
            holder,
            RivalFlag {
                proven: true,
                held: true,
            },
            clock::Instant::now(),
        );

        assert!(
            super::verdict_after_known_holders(false, &state),
            "free is read as held"
        );
        assert!(
            super::verdict_after_known_holders(true, &state),
            "the verdict after a known holder is still taken"
        );
    }

    /// Regression for a two-peer loopback mesh that never formed: a peer
    /// whose rendezvous link dropped in the first milliseconds after
    /// joining waited for the 15s heal tick to re-graft, and the mesh
    /// missed its window. The reclaim tick now re-grafts — but only when
    /// there is a link to regain, whoever holds the beacon.
    #[test]
    fn a_reclaim_tick_regrafts_only_when_the_link_is_lost() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            regrafts_rendezvous(false, true),
            "link lost: the case that stalled, and the only way a beacon we hold gets linked"
        );
        assert!(
            !regrafts_rendezvous(false, false),
            "a link let go of on purpose must stay let go of"
        );
        assert!(
            !regrafts_rendezvous(true, true),
            "a live link must not be re-dialled — both heal legs dial GOSSIP_ALPN, and the \
             beacon adopting the new one flaps the healthy link once per tick"
        );
    }

    /// Our rendezvous never dials us, so a fresh claim is linked only by our
    /// own re-graft. The reclaim tick does that within `RECLAIM_INTERVAL`,
    /// but only while its window is open, and a heal-tick claim happens with
    /// no window open: without one, the link waits for the next heal tick.
    #[test]
    fn a_heal_tick_claim_opens_the_reclaim_window() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use iroh_gossip::net::Gossip;

            use super::{CohostArm, maybe_cohost};
            use crate::daemon::handler_ctx::HandlerCtx;
            use crate::gossip::event::SilentSink;
            use crate::protocol::MeshId;
            use crate::protocol::identity::Identity;
            use crate::protocol::meshes::LookupOpts;
            use crate::testing::{fresh_state, nick};
            use crate::transport::MeshSender;
            use crate::util::clock::Instant;

            let port: u16 = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
                .and_then(|socket| socket.local_addr())
                .expect("a free loopback port")
                .port();
            let secret = iroh::SecretKey::generate();
            let params = beacon::RendezvousParams {
                topic_id: proto::TopicId::from_bytes([5u8; 32]),
                id: secret.public(),
                secret,
                bind_ports: vec![port],
                lookups: LookupOpts::loopback(),
                relay_transport: PayloadPath::DirectOnly,
                bootstrap_relay: None,
                rung_tx: mpsc::unbounded_channel().0,
                bind_options: lookup::TransportOpts::default(),
            };

            let endpoint = lookup::build_endpoint(
                &LookupOpts::loopback(),
                None,
                None,
                Vec::new(),
                lookup::TransportHandles::default(),
            )
            .await
            .expect("loopback endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let (gossip_sender, _receiver) = gossip
                .subscribe(params.topic_id, Vec::new())
                .await
                .expect("subscribe without a bootstrap")
                .split();
            let sender = MeshSender::new(gossip_sender);
            let mesh = MeshId::from("test");
            let author = nick("holder");
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let sink = SilentSink;
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &endpoint,
                mesh: &mesh,
                author: &author,
                identity: &identity,
                our_pubkey,
                max_connections: 16,
                rendezvous_id: params.id,
                external_msg_tx: None,
                sink: &sink,
            };

            let mut state = fresh_state();
            state.standing.insert(Standing::Meshed);
            assert!(
                state.reclaim_until.is_none(),
                "no window is open before the tick"
            );
            let mut rendezvous = None;
            let mut probe = None;
            let arm = CohostArm {
                policy: CoHostPolicy::Deferred,
                params: &params,
                started: Instant::now(),
            };
            maybe_cohost(&mut state, &context, &arm, &mut rendezvous, &mut probe).await;
            let claimed = rendezvous.is_some();
            let window_open = state.reclaim_until.is_some();

            if let Some(held) = rendezvous.take() {
                held.shed_and_wait().await;
            }
            endpoint.close().await;
            assert!(claimed, "a meshed Deferred member claims a free rung");
            assert!(
                window_open,
                "a heal-tick claim left the reclaim window closed: our rendezvous never dials us, so nothing links it until the next heal tick"
            );
        });
    }

    /// One heal-tick claim attempt of a meshed `Deferred` member while somebody else holds the only
    /// rung of the ladder. `configure` sets the member's state before the tick. Returns the state
    /// after it, and whether the member still holds no beacon.
    async fn heal_tick_beside_a_foreign_holder(
        configure: impl FnOnce(&mut state::EventLoopState),
    ) -> (state::EventLoopState, bool) {
        use iroh_gossip::net::Gossip;

        use super::{CohostArm, maybe_cohost};
        use crate::daemon::handler_ctx::HandlerCtx;
        use crate::gossip::event::SilentSink;
        use crate::protocol::MeshId;
        use crate::protocol::identity::Identity;
        use crate::protocol::meshes::LookupOpts;
        use crate::testing::{fresh_state, nick};
        use crate::transport::MeshSender;
        use crate::util::clock::Instant;

        let port: u16 = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let secret = iroh::SecretKey::generate();
        let params = beacon::RendezvousParams {
            topic_id: proto::TopicId::from_bytes([6u8; 32]),
            id: secret.public(),
            secret,
            bind_ports: vec![port],
            lookups: LookupOpts::loopback(),
            relay_transport: PayloadPath::DirectOnly,
            bootstrap_relay: None,
            rung_tx: mpsc::unbounded_channel().0,
            bind_options: lookup::TransportOpts::default(),
        };

        // The holder: another member of the same room, on the only rung.
        let holder_endpoint = loopback_endpoint().await;
        let holder_book = lookup::address_book(&holder_endpoint);
        let mut held = None;
        let mut holder_probe = None;
        assert!(
            claim::ensure(
                &params,
                &holder_endpoint,
                &holder_book,
                &mut held,
                false,
                &mut holder_probe,
            )
            .await,
            "the holder claims the free rung"
        );

        let endpoint = loopback_endpoint().await;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let (gossip_sender, _receiver) = gossip
            .subscribe(params.topic_id, Vec::new())
            .await
            .expect("subscribe without a bootstrap")
            .split();
        let sender = MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let author = nick("member");
        let identity = Identity::generate();
        let our_pubkey = identity.author_key();
        let sink = SilentSink;
        let context = HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey,
            max_connections: 16,
            rendezvous_id: params.id,
            external_msg_tx: None,
            sink: &sink,
        };

        let mut state = fresh_state();
        state.standing.insert(Standing::Meshed);
        configure(&mut state);
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        state.rungs = beacon::RungWatch::new(reports);
        let mut rendezvous = None;
        let mut probe = None;
        let arm = CohostArm {
            policy: CoHostPolicy::Deferred,
            params: &params,
            started: Instant::now(),
        };
        // The walk asks the probe tasks and returns; the loop notes their reports and walks
        // again. This does what the loop does.
        for _ in 0..4 {
            maybe_cohost(&mut state, &context, &arm, &mut rendezvous, &mut probe).await;
            if !state.rungs.waiting() {
                break;
            }
            match time::timeout(Duration::from_secs(5), arrivals.recv()).await {
                Ok(Some(report)) => state.rungs.note(report, Instant::now()),
                Ok(None) | Err(_) => break,
            }
        }
        let holds_nothing = rendezvous.is_none();

        if let Some(cohosted) = rendezvous.take() {
            cohosted.shed_and_wait().await;
        }
        if let Some(held) = held.take() {
            held.shed_and_wait().await;
        }
        state.rungs.finish().await;
        endpoint.close().await;
        holder_endpoint.close().await;
        (state, holds_nothing)
    }

    /// The one-by-one path: the holder left, a joiner took the free rung, and the old members
    /// have links enough to have let go of the rendezvous. Their ladder walk reads "ours" and used
    /// to return nothing, so nothing was owed and nothing was grafted, for ever. Now a member that
    /// reads a holder that none of its mesh hosts owes a return.
    #[test]
    fn a_released_member_that_reads_a_holder_outside_its_mesh_owes_a_return() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (state, holds_nothing) = Box::pin(heal_tick_beside_a_foreign_holder(|state| {
                state.rendezvous_release_links = 1;
                state.linked_endpoints.insert(testing::endpoint_id(1));
            }))
            .await;

            assert!(holds_nothing, "the rung is served: the member stays a peer");
            assert!(
                state.rendezvous_wanted(),
                "the walk read a holder that none of the mesh hosts, and nothing was owed: the member \
                 has links enough, so no graft ever follows"
            );
        });
    }

    /// The healthy case, read on every heal tick by every released member: the holder is a member
    /// of the mesh and its flag is known. Nothing is owed.
    #[test]
    fn a_released_member_that_knows_the_holder_of_its_mesh_owes_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (state, holds_nothing) = Box::pin(heal_tick_beside_a_foreign_holder(|state| {
                state.rendezvous_release_links = 1;
                state.linked_endpoints.insert(testing::endpoint_id(1));
                state.rival_holders.insert(
                    protocol::AuthorKey::from([9u8; 32]),
                    testing::endpoint_id(2),
                );
            }))
            .await;

            assert!(holds_nothing, "the released member holds nothing");
            assert!(
                state.rendezvous_comeback_until.is_none(),
                "the released member has no comeback window"
            );
            assert!(
                !state.rendezvous_wanted(),
                "the released member does not want the rendezvous"
            );
        });
    }

    /// A joiner that has fewer links than the release count wants the rendezvous anyway. It owes
    /// nothing, and so its first visit is not made a dwell longer.
    #[test]
    fn a_joiner_under_the_release_count_owes_no_return() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (state, holds_nothing) = Box::pin(heal_tick_beside_a_foreign_holder(|_| {})).await;

            assert!(
                holds_nothing,
                "a joiner under the release count holds nothing"
            );
            assert!(
                state.rendezvous_comeback_until.is_none(),
                "a joiner under the release count owes no return"
            );
        });
    }

    /// Every rung of the ladder is held by another process: nobody can serve the rendezvous and
    /// the room cannot be joined. The member says so once per repeat interval, to its log and to
    /// its sink, however often the walk runs.
    #[test]
    fn a_ladder_that_is_taken_whole_is_said_once_per_repeat_interval() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use iroh_gossip::net::Gossip;

            use super::{CohostArm, maybe_cohost};
            use crate::daemon::handler_ctx::HandlerCtx;
            use crate::gossip::event::CountingSink;
            use crate::protocol::MeshId;
            use crate::protocol::identity::Identity;
            use crate::protocol::meshes::LookupOpts;
            use crate::testing::{fresh_state, nick};
            use crate::transport::MeshSender;
            use crate::util::clock::Instant;

            ::habilis_network_test_tracing::expect_warn(
                "habilis_network::beacon",
                "no rendezvous port is free: other processes hold every port of this room",
            );

            let port: u16 = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
                .and_then(|socket| socket.local_addr())
                .expect("a free loopback port")
                .port();
            let params_of = |seed: u8| {
                let secret = iroh::SecretKey::generate();
                beacon::RendezvousParams {
                    topic_id: proto::TopicId::from_bytes([seed; 32]),
                    id: secret.public(),
                    secret,
                    bind_ports: vec![port],
                    lookups: LookupOpts::loopback(),
                    relay_transport: PayloadPath::DirectOnly,
                    bootstrap_relay: None,
                    rung_tx: mpsc::unbounded_channel().0,
                    bind_options: lookup::TransportOpts::default(),
                }
            };
            let params = params_of(6);

            // The beacon of another mesh holds the only rung.
            let other = params_of(9);
            let other_endpoint = loopback_endpoint().await;
            let other_book = lookup::address_book(&other_endpoint);
            let mut other_held = None;
            let mut other_probe = None;
            assert!(
                claim::ensure(
                    &other,
                    &other_endpoint,
                    &other_book,
                    &mut other_held,
                    false,
                    &mut other_probe,
                )
                .await,
                "the other mesh claims the free rung"
            );

            let endpoint = loopback_endpoint().await;
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let (gossip_sender, _receiver) = gossip
                .subscribe(params.topic_id, Vec::new())
                .await
                .expect("subscribe without a bootstrap")
                .split();
            let sender = MeshSender::new(gossip_sender);
            let mesh = MeshId::from("test");
            let author = nick("member");
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let sink = CountingSink::new();
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &endpoint,
                mesh: &mesh,
                author: &author,
                identity: &identity,
                our_pubkey,
                max_connections: 16,
                rendezvous_id: params.id,
                external_msg_tx: None,
                sink: &sink,
            };

            let mut state = fresh_state();
            state.standing.insert(Standing::Meshed);
            let (reports, mut arrivals) = mpsc::unbounded_channel();
            state.rungs = beacon::RungWatch::new(reports);
            let mut rendezvous = None;
            let mut probe = None;
            let arm = CohostArm {
                policy: CoHostPolicy::Deferred,
                params: &params,
                started: Instant::now(),
            };
            // The walk asks the probe task and returns; the loop notes its report and walks again.
            for _ in 0..4 {
                maybe_cohost(&mut state, &context, &arm, &mut rendezvous, &mut probe).await;
                if !state.rungs.waiting() {
                    break;
                }
                match time::timeout(Duration::from_secs(5), arrivals.recv()).await {
                    Ok(Some(report)) => state.rungs.note(report, Instant::now()),
                    Ok(None) | Err(_) => break,
                }
            }
            let said = sink.count();
            maybe_cohost(&mut state, &context, &arm, &mut rendezvous, &mut probe).await;
            let again = sink.count();
            let repeat = tuning::NO_RUNG_REPEAT + Duration::from_secs(1);
            state.no_rung_noted_at = state.no_rung_noted_at.and_then(|at| at.checked_sub(repeat));
            maybe_cohost(&mut state, &context, &arm, &mut rendezvous, &mut probe).await;
            let later = sink.count();

            if let Some(held) = other_held.take() {
                held.shed_and_wait().await;
            }
            state.rungs.finish().await;
            other_endpoint.close().await;
            endpoint.close().await;
            assert_eq!(said, 1, "a ladder that is taken whole is said");
            assert_eq!(
                again, 1,
                "a second walk inside the repeat interval says nothing"
            );
            assert_eq!(later, 2, "the repeat interval later it is said again");
        });
    }

    /// The state of one holder on a two-rung ladder, and the means to run a heal tick on it. The
    /// first rung is taken by a beacon of another mesh while this member walks, so that it binds
    /// the second; the first rung is then free, or served by another member of this mesh.
    struct HolderOnTheSecondRung {
        params: beacon::RendezvousParams,
        endpoint: iroh::Endpoint,
        rendezvous: Option<beacon::Rendezvous>,
        probe: Option<beacon::RivalProbe>,
        first_port: u16,
        state: state::EventLoopState,
        arrivals: mpsc::UnboundedReceiver<beacon::RungReport>,
    }

    impl HolderOnTheSecondRung {
        async fn new() -> Self {
            let free_port = || {
                let socket = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
                    .expect("a free loopback port");
                socket.local_addr().expect("a free loopback port").port()
            };
            let (first_port, second_port) = (free_port(), free_port());
            let secret = iroh::SecretKey::generate();
            let params = beacon::RendezvousParams {
                topic_id: proto::TopicId::from_bytes([8u8; 32]),
                id: secret.public(),
                secret,
                bind_ports: vec![first_port, second_port],
                lookups: meshes::LookupOpts::loopback(),
                relay_transport: PayloadPath::DirectOnly,
                bootstrap_relay: None,
                rung_tx: mpsc::unbounded_channel().0,
                bind_options: lookup::TransportOpts::default(),
            };
            // A beacon of another mesh holds the first rung: this member reads it as foreign and
            // binds the second.
            let other_secret = iroh::SecretKey::generate();
            let other = beacon::RendezvousParams {
                topic_id: proto::TopicId::from_bytes([9u8; 32]),
                id: other_secret.public(),
                secret: other_secret,
                bind_ports: vec![first_port],
                lookups: meshes::LookupOpts::loopback(),
                relay_transport: PayloadPath::DirectOnly,
                bootstrap_relay: None,
                rung_tx: mpsc::unbounded_channel().0,
                bind_options: lookup::TransportOpts::default(),
            };
            let other_endpoint = loopback_endpoint().await;
            let other_book = lookup::address_book(&other_endpoint);
            let mut other_beacon = None;
            let mut other_probe = None;
            assert!(
                claim::ensure(
                    &other,
                    &other_endpoint,
                    &other_book,
                    &mut other_beacon,
                    false,
                    &mut other_probe,
                )
                .await,
                "the other mesh claims the first rung"
            );

            let endpoint = loopback_endpoint().await;
            let book = lookup::address_book(&endpoint);
            let mut rendezvous = None;
            let mut probe = None;
            assert!(
                claim::ensure(
                    &params,
                    &endpoint,
                    &book,
                    &mut rendezvous,
                    false,
                    &mut probe
                )
                .await,
                "the member walks past the foreign rung and binds the second"
            );
            if let Some(held) = other_beacon.take() {
                held.shed_and_wait().await;
            }
            other_endpoint.close().await;
            let mut state = testing::fresh_state();
            state.standing.insert(Standing::Meshed);
            let (reports, arrivals) = mpsc::unbounded_channel();
            state.rungs = beacon::RungWatch::new(reports);
            Self {
                params,
                endpoint,
                rendezvous,
                probe,
                first_port,
                state,
                arrivals,
            }
        }

        /// A member of this mesh takes the first rung, which the foreign beacon left free.
        async fn another_member_takes_the_first_rung(
            &self,
        ) -> (iroh::Endpoint, beacon::Rendezvous) {
            let member = loopback_endpoint().await;
            let book = lookup::address_book(&member);
            let mut beacon = None;
            let mut probe = None;
            assert!(
                claim::ensure(&self.params, &member, &book, &mut beacon, false, &mut probe).await,
                "a member of the mesh binds the first rung"
            );
            (member, beacon.expect("it holds the beacon"))
        }

        /// One heal tick of this holder.
        async fn heal_tick(&mut self) {
            use iroh_gossip::net::Gossip;

            use super::{CohostArm, maybe_cohost};
            use crate::daemon::handler_ctx::HandlerCtx;
            use crate::gossip::event::SilentSink;
            use crate::protocol::MeshId;
            use crate::protocol::identity::Identity;
            use crate::testing;
            use crate::transport::MeshSender;
            use crate::util::clock::Instant;

            let gossip = Gossip::builder().spawn(self.endpoint.clone());
            let (gossip_sender, _receiver) = gossip
                .subscribe(self.params.topic_id, Vec::new())
                .await
                .expect("subscribe without a bootstrap")
                .split();
            let sender = MeshSender::new(gossip_sender);
            let mesh = MeshId::from("test");
            let author = testing::nick("holder");
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let sink = SilentSink;
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &self.endpoint,
                mesh: &mesh,
                author: &author,
                identity: &identity,
                our_pubkey,
                max_connections: 16,
                rendezvous_id: self.params.id,
                external_msg_tx: None,
                sink: &sink,
            };
            let arm = CohostArm {
                policy: CoHostPolicy::Deferred,
                params: &self.params,
                started: Instant::now(),
            };
            // The check and the walk ask the probe tasks and return; the loop notes their reports
            // and walks again. This does what the loop does.
            for _ in 0..4 {
                maybe_cohost(
                    &mut self.state,
                    &context,
                    &arm,
                    &mut self.rendezvous,
                    &mut self.probe,
                )
                .await;
                if !self.state.rungs.waiting() {
                    break;
                }
                match time::timeout(Duration::from_secs(5), self.arrivals.recv()).await {
                    Ok(Some(report)) => self.state.rungs.note(report, Instant::now()),
                    Ok(None) | Err(_) => break,
                }
            }
        }

        async fn close(mut self) {
            // A shed closes its endpoint on a task of its own. A test that ends before that task
            // does lets iroh log "Endpoint dropped without calling `Endpoint::close`".
            if let Some(closed) = self.state.beacon_closing.take() {
                let _ = closed.await;
            }
            if let Some(held) = self.rendezvous.take() {
                held.shed_and_wait().await;
            }
            self.state.rungs.finish().await;
            self.endpoint.close().await;
        }
    }

    /// The rung of a beacon that was shed is not ours any more: another mesh whose ladder shares the
    /// port can bind it, and each heal tick registers what the watch offers. A rung that stays in
    /// `ours` after the shed goes back into the book with the next registration.
    #[test]
    fn a_shed_beacon_leaves_its_rung_out_of_what_the_book_offers() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut holder = HolderOnTheSecondRung::new().await;
            let shed_rung = holder.params.bind_ports[1];
            // The loop binds through its own watch, which then reads the rung of its beacon as ours.
            holder.state.rungs.clear_foreign(shed_rung);
            let (lower_endpoint, lower_beacon) = holder.another_member_takes_the_first_rung().await;

            holder.heal_tick().await;

            let shed = holder.rendezvous.is_none();
            let offered = holder.state.rungs.offered_rungs();
            Box::pin(holder.close()).await;
            lower_beacon.shed_and_wait().await;
            lower_endpoint.close().await;
            assert!(shed, "the holder on the second rung did not shed");
            assert!(
                !offered.contains(&shed_rung),
                "the rung {shed_rung} of the shed beacon is still offered: {offered:?}"
            );
        });
    }

    /// A holder on a rung above a live one yields it. A split of two beacons on one ladder came
    /// from a rung probe that timed out, and nothing on a loopback ladder ever repaired it: the
    /// holder on the higher rung stayed for ever.
    #[test]
    fn a_holder_on_a_higher_rung_sheds_when_a_lower_rung_answers_as_our_mesh() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut holder = HolderOnTheSecondRung::new().await;
            let (lower_endpoint, lower_beacon) = holder.another_member_takes_the_first_rung().await;

            holder.heal_tick().await;

            let shed = holder.rendezvous.is_none();
            Box::pin(holder.close()).await;
            lower_beacon.shed_and_wait().await;
            lower_endpoint.close().await;
            assert!(
                shed,
                "a member of our mesh serves the first rung, and the holder on the second kept its bind"
            );
        });
    }

    /// Silence is not an answer. A lower rung that nobody serves, or whose listener says nothing,
    /// never makes the holder shed: a wrong reading of a loaded host would otherwise take the
    /// beacon away from every member that joined through it.
    #[test]
    fn a_lower_rung_that_does_not_answer_never_makes_the_holder_shed() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut holder = HolderOnTheSecondRung::new().await;
            for _ in 0..2 {
                holder.heal_tick().await;
                assert!(holder.rendezvous.is_some(), "the first rung is free");
            }
            let silent = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, holder.first_port))
                .expect("the first rung, taken by a socket that says nothing");
            for _ in 0..2 {
                holder.heal_tick().await;
                assert!(
                    holder.rendezvous.is_some(),
                    "the first rung is silent: nothing answers, and silence is no reading"
                );
            }
            drop(silent);
            Box::pin(holder.close()).await;
        });
    }

    /// A beacon that stopped answering keeps its rung. The holder notices at the second check
    /// that does not answer, and not at the first: a busy moment must not take a healthy beacon
    /// from the members that joined through it.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[test]
    fn a_holder_whose_beacon_stops_answering_sheds_at_the_second_check_and_not_the_first() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use habilis_network_test_tracing;

            // The stalled beacon serves no protocol, so each check that dials it is refused with
            // alert 120 and the router of the beacon logs it: the stall causes this WARN.
            ::habilis_network_test_tracing::expect_warn(
                "iroh::protocol",
                "peer doesn't support any known protocol",
            );
            let mut holder = HolderOnTheSecondRung::new().await;
            holder
                .rendezvous
                .as_ref()
                .expect("the holder holds its rung")
                .stall();

            holder.heal_tick().await;
            let kept_at_the_first = holder.rendezvous.is_some();
            holder.state.rungs.expire_readings();
            holder.heal_tick().await;
            let shed_at_the_second = holder.rendezvous.is_none();
            for _ in 0..100 {
                if habilis_network_test_tracing::saw_warn(
                    "iroh::protocol",
                    "peer doesn't support any known protocol",
                ) {
                    break;
                }
                time::sleep(Duration::from_millis(50)).await;
            }

            Box::pin(holder.close()).await;
            assert!(
                kept_at_the_first,
                "one check that does not answer shed the beacon"
            );
            assert!(
                shed_at_the_second,
                "the beacon stopped answering at two checks and was kept"
            );
        });
    }

    /// The run ends after the close of a shed beacon, not during it. The close of the endpoint runs on
    /// a task of its own, and a host that ends the loop and drops its runtime would cut it short:
    /// the peers of the shed beacon wait for the idle timeout, and iroh logs an ERROR. The close is
    /// a task that ends after a delay here, so that the wait is the only thing that can cover it.
    #[test]
    fn the_end_of_the_run_waits_for_the_close_of_a_shed_beacon() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            const CLOSE_TAKES: Duration = Duration::from_millis(200);
            let mut state = testing::fresh_state();
            let (done, closed) = oneshot::channel();
            state.beacon_closing = Some(closed);
            task::spawn(async move {
                time::sleep(CLOSE_TAKES).await;
                let _ = done.send(());
            });
            let started = time::Instant::now();

            super::wait_for_shed_close(&mut state).await;

            assert!(
                started.elapsed() >= CLOSE_TAKES,
                "the end of the run returned before the close of the shed beacon was done"
            );
            assert!(
                state.beacon_closing.is_none(),
                "the wait leaves the close of the beacon in the state"
            );
        });
    }

    /// The run ends after the closes of the endpoints that read the busy rungs at setup. Closing
    /// one that dialed a silent rung takes seconds, and a host that ends the loop and drops its
    /// runtime cuts a close that nothing waits for short: iroh logs an ERROR for the endpoint.
    #[test]
    fn the_end_of_the_run_waits_for_the_closes_of_the_rung_probers() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            const CLOSE_TAKES: Duration = Duration::from_millis(200);
            let (done, closed) = oneshot::channel();
            task::spawn(async move {
                time::sleep(CLOSE_TAKES).await;
                let _ = done.send(());
            });
            let started = time::Instant::now();

            super::wait_for_prober_closes(vec![closed]).await;

            assert!(
                started.elapsed() >= CLOSE_TAKES,
                "the end of the run returned before the close of a rung prober was done"
            );
        });
    }

    /// A prober close that was cancelled never answers, and the end of the run must not wait for it.
    #[test]
    fn the_end_of_the_run_does_not_wait_for_a_prober_close_that_was_cancelled() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (done, closed): (oneshot::Sender<()>, _) = oneshot::channel();
            drop(done);

            time::timeout(
                Duration::from_secs(5),
                super::wait_for_prober_closes(vec![closed]),
            )
            .await
            .expect("the wait ends when the close task is gone");
        });
    }

    /// A close task that was cancelled never answers, and the end of the run must not wait for it.
    #[test]
    fn the_end_of_the_run_does_not_wait_for_a_close_that_was_cancelled() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut state = testing::fresh_state();
            let (done, closed): (oneshot::Sender<()>, _) = oneshot::channel();
            state.beacon_closing = Some(closed);
            drop(done);

            time::timeout(
                Duration::from_secs(5),
                super::wait_for_shed_close(&mut state),
            )
            .await
            .expect("the wait ends when the close task is gone");
        });
    }

    /// A beacon that answers is never shed by the check of its own rung, however many ticks
    /// read it: the count of checks that did not answer starts again at every answer.
    #[test]
    fn a_holder_whose_beacon_answers_is_kept_by_the_check_of_its_own_rung() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut holder = HolderOnTheSecondRung::new().await;

            for _ in 0..3 {
                holder.heal_tick().await;
                holder.state.rungs.expire_readings();
            }

            let kept = holder.rendezvous.is_some();
            Box::pin(holder.close()).await;
            assert!(kept, "a beacon that answers was shed by its own check");
        });
    }

    /// A holder that shed because a lower rung answered stays a peer of that rung, even when its
    /// own probe of the rung then reads silence. A host that stays slow made the probe of the
    /// walk read "not ours" over and over: the walk bound the rung it had just shed, the check of
    /// the next tick shed it again, and the member flapped for ever without ever merging.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[test]
    fn a_holder_that_shed_for_a_live_lower_rung_stays_a_peer_when_its_probe_is_silent() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let mut holder = HolderOnTheSecondRung::new().await;
            let (lower_endpoint, lower_beacon) = holder.another_member_takes_the_first_rung().await;
            beacon::set_blind_rung_probes(holder.endpoint.id(), true);

            holder.heal_tick().await;
            let shed = holder.rendezvous.is_none();
            // The close of the shed beacon is done before the walk, or it would find its own rung
            // still bound and read that as a foreign squat.
            if let Some(closed) = holder.state.beacon_closing.take() {
                let _ = closed.await;
            }
            holder.heal_tick().await;
            let peer = holder.rendezvous.is_none();

            beacon::set_blind_rung_probes(holder.endpoint.id(), false);
            Box::pin(holder.close()).await;
            lower_beacon.shed_and_wait().await;
            lower_endpoint.close().await;
            assert!(shed, "the first tick reads the lower rung and sheds");
            assert!(
                peer,
                "the walk that followed read the rung that had just answered as foreign, and bound the rung it shed"
            );
        });
    }

    /// The book kept the address of every beacon that this process held under the id, so a dial to
    /// the id tried the ports of beacons that were gone (the N=2 round: a claim-time offer that hung
    /// for the whole connect bound while the next offer took 37 ms). A release takes the entry out.
    #[test]
    fn a_release_takes_the_address_of_the_released_beacon_out_of_the_book() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let params = public_params();
            let arm = super::CohostArm {
                policy: CoHostPolicy::EagerProbed,
                params: &params,
                started: clock::Instant::now(),
            };
            let endpoint = loopback_endpoint().await;
            let mut state = testing::fresh_state();
            let old_beacon = iroh::EndpointAddr::new(params.id)
                .with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
            lookup::add_peer_addr(&state.address_book, old_beacon);
            let mut rendezvous = Some(beacon::Rendezvous::for_test(endpoint));

            super::release_to_rival(&mut state, &arm, &mut rendezvous);
            assert!(rendezvous.is_none(), "the beacon was released");

            assert!(
                state.address_book.get_endpoint_info(params.id).is_none(),
                "the book still names the beacon that was shed"
            );
        });
    }

    /// Every claim passes `arm_holder_probe`, the verdict arm of the event loop among them,
    /// and the claim of the split round came through that arm: it ends the round that ran against
    /// the missing holder.
    #[test]
    fn the_claim_funnel_ends_the_round_that_ran_against_the_missing_holder() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let params = public_params();
            let endpoint = loopback_endpoint().await;
            let mut state = testing::fresh_state();
            state.rendezvous_id = Some(params.id);
            let hub = lookup::build_webrtc_handle(endpoint.id());
            let held_round = state
                .webrtc_admission
                .try_admit(params.id, &hub)
                .expect("a free slot");
            let epoch = held_round.epoch();
            let task = task::spawn(async move {
                let _held_round = held_round;
                let forever: future::Pending<()> = future::pending();
                forever.await;
            });
            state
                .webrtc_admission
                .track(params.id, epoch, task.abort_handle());
            assert_eq!(
                state.webrtc_admission.in_flight(),
                1,
                "one admission slot is in flight after the claim funnel"
            );

            super::arm_holder_probe(&mut state, CoHostPolicy::EagerProbed, &params);

            let round_running = state.webrtc_admission.in_flight() != 0;
            endpoint.close().await;
            assert!(
                !round_running,
                "the round that ran against the missing holder still holds the slot of the rendezvous"
            );
        });
    }

    /// An offer to the rendezvous that started while nobody held it never finds the beacon that
    /// this member claims next, and held the slot for the whole round deadline (observed: a
    /// split of two members that stayed 25 s or more with `not negotiating with the rendezvous
    /// reason=InFlight`). The claim ends it.
    #[test]
    fn a_claim_ends_the_offer_that_ran_against_the_missing_holder() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use iroh_gossip::net::Gossip;

            use super::{CohostArm, maybe_cohost};
            use crate::daemon::handler_ctx::HandlerCtx;
            use crate::gossip::event::SilentSink;
            use crate::protocol::MeshId;
            use crate::protocol::identity::Identity;
            use crate::protocol::meshes::LookupOpts;
            use crate::testing::{fresh_state, nick};
            use crate::transport::MeshSender;
            use crate::util::clock::Instant;

            let port: u16 = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
                .and_then(|socket| socket.local_addr())
                .expect("a free loopback port")
                .port();
            let secret = iroh::SecretKey::generate();
            let params = beacon::RendezvousParams {
                topic_id: proto::TopicId::from_bytes([5u8; 32]),
                id: secret.public(),
                secret,
                bind_ports: vec![port],
                lookups: LookupOpts::loopback(),
                relay_transport: PayloadPath::DirectOnly,
                bootstrap_relay: None,
                rung_tx: mpsc::unbounded_channel().0,
                bind_options: lookup::TransportOpts::default(),
            };

            let endpoint = lookup::build_endpoint(
                &LookupOpts::loopback(),
                None,
                None,
                Vec::new(),
                lookup::TransportHandles::default(),
            )
            .await
            .expect("loopback endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let (gossip_sender, _receiver) = gossip
                .subscribe(params.topic_id, Vec::new())
                .await
                .expect("subscribe without a bootstrap")
                .split();
            let sender = MeshSender::new(gossip_sender);
            let mesh = MeshId::from("test");
            let author = nick("holder");
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let sink = SilentSink;
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &endpoint,
                mesh: &mesh,
                author: &author,
                identity: &identity,
                our_pubkey,
                max_connections: 16,
                rendezvous_id: params.id,
                external_msg_tx: None,
                sink: &sink,
            };

            let mut state = fresh_state();
            state.standing.insert(Standing::Meshed);
            state.rendezvous_id = Some(params.id);
            let hub = lookup::build_webrtc_handle(endpoint.id());
            let held_round = state
                .webrtc_admission
                .try_admit(params.id, &hub)
                .expect("a free slot");
            let epoch = held_round.epoch();
            let task = task::spawn(async move {
                let _held_round = held_round;
                let forever: future::Pending<()> = future::pending();
                forever.await;
            });
            state
                .webrtc_admission
                .track(params.id, epoch, task.abort_handle());
            let mut rendezvous = None;
            let mut probe = None;
            let arm = CohostArm {
                policy: CoHostPolicy::Deferred,
                params: &params,
                started: Instant::now(),
            };
            maybe_cohost(&mut state, &context, &arm, &mut rendezvous, &mut probe).await;
            let claimed = rendezvous.is_some();
            let offer_running = state.webrtc_admission.in_flight() != 0;

            if let Some(held) = rendezvous.take() {
                held.shed_and_wait().await;
            }
            endpoint.close().await;
            assert!(claimed, "a meshed Deferred member claims a free rung");
            assert!(
                !offer_running,
                "the offer that ran against the missing holder still holds the slot of the rendezvous: every offer to our new beacon is refused InFlight until the round deadline"
            );
        });
    }

    /// A member whose probe finds the holder (the N=3 round: "staying peer" at 48.69 s) did not
    /// claim, so the claim funnel never ran for it: its round from before the holder stays until
    /// the connect bound. The held verdict ends it.
    #[test]
    fn a_held_verdict_ends_the_round_that_ran_against_the_missing_holder() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use iroh_gossip::net::Gossip;

            use crate::daemon::handler_ctx::HandlerCtx;
            use crate::gossip::event::SilentSink;
            use crate::protocol::MeshId;
            use crate::protocol::identity::Identity;
            use crate::protocol::meshes::LookupOpts;
            use crate::testing::{fresh_state, nick};
            use crate::transport::MeshSender;

            let port: u16 = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
                .and_then(|socket| socket.local_addr())
                .expect("a free loopback port")
                .port();
            let secret = iroh::SecretKey::generate();
            let params = beacon::RendezvousParams {
                topic_id: proto::TopicId::from_bytes([5u8; 32]),
                id: secret.public(),
                secret,
                bind_ports: vec![port],
                lookups: LookupOpts::loopback(),
                relay_transport: PayloadPath::DirectOnly,
                bootstrap_relay: None,
                rung_tx: mpsc::unbounded_channel().0,
                bind_options: lookup::TransportOpts::default(),
            };

            let endpoint = lookup::build_endpoint(
                &LookupOpts::loopback(),
                None,
                None,
                Vec::new(),
                lookup::TransportHandles::default(),
            )
            .await
            .expect("loopback endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let (gossip_sender, _receiver) = gossip
                .subscribe(params.topic_id, Vec::new())
                .await
                .expect("subscribe without a bootstrap")
                .split();
            let sender = MeshSender::new(gossip_sender);
            let mesh = MeshId::from("test");
            let author = nick("holder");
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let sink = SilentSink;
            let context = HandlerCtx {
                sender: &sender,
                endpoint: &endpoint,
                mesh: &mesh,
                author: &author,
                identity: &identity,
                our_pubkey,
                max_connections: 16,
                rendezvous_id: params.id,
                external_msg_tx: None,
                sink: &sink,
            };

            let mut state = fresh_state();
            state.rendezvous_id = Some(params.id);
            let hub = lookup::build_webrtc_handle(endpoint.id());
            let held_round = state
                .webrtc_admission
                .try_admit(params.id, &hub)
                .expect("a free slot");
            let epoch = held_round.epoch();
            let task = task::spawn(async move {
                let _held_round = held_round;
                let forever: future::Pending<()> = future::pending();
                forever.await;
            });
            state
                .webrtc_admission
                .track(params.id, epoch, task.abort_handle());
            assert_eq!(
                state.webrtc_admission.in_flight(),
                1,
                "one admission slot is in flight after the held verdict"
            );

            super::note_rival_holds(&mut state, &context);

            let round_running = state.webrtc_admission.in_flight() != 0;
            endpoint.close().await;
            assert!(
                !round_running,
                "the round that ran against the missing holder still holds the slot of the rendezvous"
            );
        });
    }

    #[test]
    fn directory_advertiser_claims_at_startup_with_probe() {
        // Regression for the duplicate-beacon directory bug: an advertiser
        // must co-host the shared rendezvous from t=0 *and* probe-first, so a
        // second advertiser into the same directory defers instead of binding
        // a duplicate (which partitioned the directory in public mode — only
        // one mesh was discoverable). The pre-fix policy was the no-probe
        // `Eager` (claims, doesn't probe), which the probe assertion guards.
        let _guard = ::habilis_network_test_tracing::init();
        let advertiser = config::DIRECTORY_ADVERTISER_COHOST;
        assert!(claims_at_startup(advertiser), "must claim at t=0");
        assert!(
            probes_before_claim(advertiser),
            "must probe before claiming"
        );

        // The mesh origin (`create`) claims at startup but skips the probe;
        // joiners and consumers don't claim at startup at all.
        assert!(
            claims_at_startup(CoHostPolicy::Eager),
            "an eager directory advertiser claims at startup"
        );
        assert!(
            !probes_before_claim(CoHostPolicy::Eager),
            "an eager policy does not probe before the claim"
        );
        assert!(
            !claims_at_startup(CoHostPolicy::Deferred),
            "a deferred policy does not claim at startup"
        );
        assert!(
            !claims_at_startup(CoHostPolicy::Never),
            "a never policy does not claim at startup"
        );
    }

    #[test]
    fn rival_recheck_gates_on_probed_claims_and_public() {
        // The shed exists for claimants that took the identity on the word of
        // a probe and can therefore have raced each other into a same-id
        // split: directory advertisers and topic joiners (`EagerProbed`)…
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            rival_recheck_applies(CoHostPolicy::EagerProbed, true),
            "an eager-probe policy with probed claims applies the rival recheck"
        );
        // …and ordinary joiners (`Deferred`), which this used to exclude.
        // Regression: a survivor of a departed origin claims on a probe like
        // anyone else, and with the shed off there was nothing to re-arbitrate
        // the duplicate beacons that followed. See `rival_recheck_applies`.
        assert!(
            rival_recheck_applies(CoHostPolicy::Deferred, true),
            "a deferred policy applies the rival recheck when public"
        );
        // The loopback ladder has no timed re-check: a second beacon on a loopback
        // mesh is repaired by the lower-rung check and the own-rung check of the
        // holder (`maybe_cohost`), not by a shed on a timer.
        assert!(
            !rival_recheck_applies(CoHostPolicy::EagerProbed, false),
            "the rival recheck is off for an eager-probe policy without probed claims"
        );
        assert!(
            !rival_recheck_applies(CoHostPolicy::Deferred, false),
            "the rival recheck is off for a deferred policy that is not public"
        );
        // The origin owns the identity from t=0 and a consumer claims nothing.
        assert!(
            !rival_recheck_applies(CoHostPolicy::Eager, true),
            "the rival recheck is off for an eager policy"
        );
        assert!(
            !rival_recheck_applies(CoHostPolicy::Never, true),
            "the rival recheck is off for a never policy"
        );
    }

    /// **A rung that the monitor of a retired beacon decided is not applied.**
    ///
    /// A beacon that was shed ends its monitor, and a decision that the monitor published at the
    /// same time can still reach the loop. The loop must not re-home the beacon that it holds now
    /// on it: that beacon has a monitor of its own.
    #[test]
    fn a_rung_decision_of_a_retired_monitor_is_ignored() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rung_of = |host: &str| -> iroh::RelayUrl {
                format!("https://{host}.example/")
                    .parse()
                    .expect("a test host forms a valid https URL")
            };
            let mut params = public_params();
            params.bootstrap_relay = Some(rung_of("second"));
            let mut state = testing::fresh_state();
            let beacon = beacon::Rendezvous::for_test(loopback_endpoint().await);
            let retired = lookup::Generation::next();
            let decision = lookup::RungDecision {
                from: Some(retired),
                rung: Some(rung_of("first")),
                change: lookup::RungChange::Rehome,
            };
            let mut rendezvous = Some(beacon);

            super::super::heal::apply_rung_change(
                &mut state,
                &mut params,
                &mut rendezvous,
                decision,
            );

            assert_eq!(
                params.bootstrap_relay,
                Some(rung_of("second")),
                "a retired monitor moved the rung of the beacon that it did not watch"
            );
            let held = rendezvous
                .take()
                .expect("a retired monitor shed the beacon that it did not watch");
            held.shed_and_wait().await;
        });
    }

    /// **The rung that the monitor of the held beacon decided, or the startup probe, is applied.**
    #[test]
    fn a_rung_decision_of_the_held_beacon_or_of_the_startup_probe_is_applied() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rung_of = |host: &str| -> iroh::RelayUrl {
                format!("https://{host}.example/")
                    .parse()
                    .expect("a test host forms a valid https URL")
            };
            for from_monitor in [true, false] {
                let mut params = public_params();
                params.bootstrap_relay = Some(rung_of("second"));
                let mut state = testing::fresh_state();
                let endpoint = loopback_endpoint().await;
                let beacon = beacon::Rendezvous::for_test(endpoint.clone());
                let from = from_monitor.then_some(beacon.generation);
                let decision = lookup::RungDecision {
                    from,
                    rung: Some(rung_of("first")),
                    change: lookup::RungChange::Rehome,
                };
                let mut rendezvous = Some(beacon);

                super::super::heal::apply_rung_change(
                    &mut state,
                    &mut params,
                    &mut rendezvous,
                    decision,
                );
                endpoint.close().await;

                assert_eq!(
                    params.bootstrap_relay,
                    Some(rung_of("first")),
                    "the rung is applied (from the monitor: {from_monitor})"
                );
                assert!(
                    rendezvous.is_none(),
                    "the beacon is shed for a re-home (from the monitor: {from_monitor})"
                );
            }
        });
    }

    /// **A failover that follows a move in place is applied, whatever the loop read in between.**
    ///
    /// The beacon on rung 1 returns to rung 0 and connects, and its monitor publishes `Moved(0)`.
    /// Rung 0 fails before the loop reads that, and the monitor publishes `Rehome(1)`. The loop
    /// must see both, in order: the move sets the rung of the beacon to 0, and the failover to 1
    /// then differs from it and sheds the beacon. A channel that keeps the last value only lost the
    /// move, compared `Rehome(1)` with the rung 1 that was registered before, found no change, and
    /// left the beacon on the failed rung 0 with no monitor to publish again.
    #[test]
    fn a_move_in_place_and_a_failover_that_the_loop_reads_together_shed_the_beacon() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rung_of = |host: &str| -> iroh::RelayUrl {
                format!("https://{host}.example/")
                    .parse()
                    .expect("a test host forms a valid https URL")
            };
            let mut params = public_params();
            params.bootstrap_relay = Some(rung_of("second"));
            let mut state = testing::fresh_state();
            let beacon = beacon::Rendezvous::for_test(loopback_endpoint().await);
            let generation = beacon.generation;
            let (tx, mut rx): (
                mpsc::UnboundedSender<lookup::RungDecision>,
                mpsc::UnboundedReceiver<lookup::RungDecision>,
            ) = mpsc::unbounded_channel();
            tx.send(lookup::RungDecision {
                from: Some(generation),
                rung: Some(rung_of("first")),
                change: lookup::RungChange::Moved,
            })
            .expect("the receiver is alive");
            tx.send(lookup::RungDecision {
                from: Some(generation),
                rung: Some(rung_of("second")),
                change: lookup::RungChange::Rehome,
            })
            .expect("the receiver is alive");
            let mut rendezvous = Some(beacon);

            while let Ok(decision) = rx.try_recv() {
                super::super::heal::apply_rung_change(
                    &mut state,
                    &mut params,
                    &mut rendezvous,
                    decision,
                );
            }

            assert_eq!(
                params.bootstrap_relay,
                Some(rung_of("second")),
                "the failover rung is the one of the next claim"
            );
            let shed = rendezvous.is_none();
            if let Some(held) = rendezvous.take() {
                held.shed_and_wait().await;
            }
            assert!(
                shed,
                "the beacon stayed on the failed rung 0: the failover was compared with a rung that the move had not set"
            );
        });
    }

    /// **The move in place of a retired monitor does not take the place of the failover that the
    /// replacement published before it.**
    ///
    /// A beacon that is shed drops the stop of its monitor, which may still be in the await of its
    /// move in place. The replacement beacon fails over and publishes `Rehome`, and the old monitor
    /// then publishes its `Moved`. A channel that kept the last value only held the `Moved` of the
    /// retired generation, which the loop ignores, and the `Rehome` was lost, with no monitor left
    /// to publish it again. The loop reads both: it ignores the old one and applies the failover.
    #[test]
    fn a_retired_move_after_a_failover_does_not_hide_the_failover() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rung_of = |host: &str| -> iroh::RelayUrl {
                format!("https://{host}.example/")
                    .parse()
                    .expect("a test host forms a valid https URL")
            };
            let mut params = public_params();
            params.bootstrap_relay = Some(rung_of("first"));
            let mut state = testing::fresh_state();
            let beacon = beacon::Rendezvous::for_test(loopback_endpoint().await);
            let (tx, mut rx): (
                mpsc::UnboundedSender<lookup::RungDecision>,
                mpsc::UnboundedReceiver<lookup::RungDecision>,
            ) = mpsc::unbounded_channel();
            tx.send(lookup::RungDecision {
                from: Some(beacon.generation),
                rung: Some(rung_of("second")),
                change: lookup::RungChange::Rehome,
            })
            .expect("the receiver is alive");
            tx.send(lookup::RungDecision {
                from: Some(lookup::Generation::next()),
                rung: Some(rung_of("first")),
                change: lookup::RungChange::Moved,
            })
            .expect("the receiver is alive");
            let mut rendezvous = Some(beacon);

            while let Ok(decision) = rx.try_recv() {
                super::super::heal::apply_rung_change(
                    &mut state,
                    &mut params,
                    &mut rendezvous,
                    decision,
                );
            }

            assert_eq!(
                params.bootstrap_relay,
                Some(rung_of("second")),
                "the failover of the held beacon was lost behind the move of a retired one"
            );
            let shed = rendezvous.is_none();
            if let Some(held) = rendezvous.take() {
                held.shed_and_wait().await;
            }
            assert!(shed, "the beacon was not re-homed on the failover rung");
        });
    }

    /// **A beacon that moved its own relay in place is followed by the loop, not shed.**
    ///
    /// The beacon serves on, so nothing of a new claim applies: the beacon stays held, the contest of
    /// the holder goes on, and the reading of the rendezvous stays. The loop only follows
    /// the rung: the parameters of the next claim, and the address that joiners are given.
    #[test]
    fn a_beacon_that_moved_in_place_is_followed_not_shed() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rung_of = |host: &str| -> iroh::RelayUrl {
                format!("https://{host}.example/")
                    .parse()
                    .expect("a test host forms a valid https URL")
            };
            let mut params = public_params();
            params.bootstrap_relay = Some(rung_of("second"));
            let mut state = testing::fresh_state();
            state
                .rendezvous_flags
                .insert(state::RendezvousFlag::ProbeReadFree);
            let beacon = beacon::Rendezvous::for_test(loopback_endpoint().await);
            let decision = lookup::RungDecision {
                from: Some(beacon.generation),
                rung: Some(rung_of("first")),
                change: lookup::RungChange::Moved,
            };
            let mut rendezvous = Some(beacon);

            super::super::heal::apply_rung_change(
                &mut state,
                &mut params,
                &mut rendezvous,
                decision,
            );

            assert_eq!(
                params.bootstrap_relay,
                Some(rung_of("first")),
                "the next claim homes on the rung that the beacon moved to"
            );
            let info = state.address_book.get_endpoint_info(params.id);
            let first_rung = rung_of("first");
            assert!(
                info.is_some_and(|info| info
                    .into_endpoint_addr()
                    .relay_urls()
                    .any(|url| *url == first_rung)),
                "joiners are not given the rung that the beacon moved to"
            );
            assert!(
                state
                    .rendezvous_flags
                    .contains(&state::RendezvousFlag::ProbeReadFree),
                "a move in place forgot the reading of the rendezvous"
            );
            let held = rendezvous
                .take()
                .expect("the loop shed a beacon that moved in place");
            held.shed_and_wait().await;
        });
    }
}
