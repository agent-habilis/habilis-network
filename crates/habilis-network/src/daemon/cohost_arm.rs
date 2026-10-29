//! Beacon **policy**: who co-hosts the rendezvous, when they claim it, and how
//! a rival claim is re-checked.
//!
//! The mechanism lives in `crate::beacon`; this is the decision layer above it.
//! Split out of `event_loop` because it was the single hardest thing to hold in
//! mind while reading that file — nine functions spread across four claim
//! sites, interleaved with the tick arms they have nothing to do with.

use std::time::Duration;

use iroh::{Endpoint, EndpointId};

use super::config::CoHostPolicy;
use super::handler_ctx::HandlerCtx;
use super::state::EventLoopState;
use crate::beacon;
use crate::gossip::event::NodeEvent;
use crate::util::clock::Instant;

use crate::gossip::heal;
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
/// concurrently, so the whole release costs one close budget, which is what
/// `NODE_LEAVE` is sized for.
pub(super) async fn release_rendezvous(
    rendezvous: &mut Option<beacon::Rendezvous>,
    probe: &mut Option<beacon::RivalProbe>,
    rung_probe: &mut Option<crate::lookup::StoppableTask>,
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
/// [`beacon::ensure`] from every claim site (startup, heal tick, reclaim
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
/// The co-host decision inputs a heal/reclaim tick needs: which policy
/// governs this session, the rendezvous params to (re)claim under, and
/// (for the unmeshed-joiner grace `maybe_cohost` alone reads) when the
/// event loop started.
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
    if may_cohost(arm.policy, state.meshed, arm.started) {
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
            if !state.rendezvous_linked {
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
                schedule_rival_recheck(state, arm.policy, arm.params, context.endpoint);
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
                schedule_rival_recheck(state, arm.policy, arm.params, context.endpoint);
                offer_to_the_new_holder(state, context);
                return;
            }
            beacon::Held::Rival => state.note_holder_outside_mesh(Instant::now()),
            beacon::Held::NoRung => note_no_rung_free(state, context, arm.params.bind_ports.len()),
            beacon::Held::Idle => {}
        }
        if regrafts_rendezvous(state.rendezvous_linked, state.rendezvous_wanted())
            && webrtc::rendezvous::rendezvous_graftable(state)
        {
            tracing::info!(
                target: "habilis_network::gossip",
                "reclaim tick: re-graft the rendezvous (link lost)"
            );
            heal::tick_heal(arm.params.id, context.sender).await;
        }
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
    state.beacon_closing = Some(held.shed_then());
    state.next_rival_recheck = None;
    state.cancel_rendezvous_round();
    state.address_book.remove_endpoint_info(params.id);
    super::setup::register_rendezvous(&state.address_book, params, &state.rungs.withheld_rungs());
    state.rendezvous_linked = false;
    state.forget_rendezvous_verdict();
    state.arm_reclaim(Instant::now());
}

/// Tests only: make the beacon stop answering, if a test asked for it (`Request::StallBeacon`).
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(super) fn stall_on_request(
    state: &mut EventLoopState,
    rendezvous: Option<&beacon::Rendezvous>,
) {
    if std::mem::take(&mut state.stall_requested)
        && let Some(held) = rendezvous
    {
        tracing::info!(
            target: "habilis_network::gossip",
            "beacon stalled at the request of a test"
        );
        held.stall();
    }
}

/// Tests only: shed the beacon now, if a test asked for it (`Request::ShedBeacon`), as the check
/// of the lower rungs does after its decision.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(super) fn shed_on_request(
    state: &mut EventLoopState,
    params: &beacon::RendezvousParams,
    rendezvous: &mut Option<beacon::Rendezvous>,
) {
    if std::mem::take(&mut state.shed_requested) {
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
/// When the next rival re-check shed should run, from the moment of a
/// claim. Round 0 (a startup claim) is the *fast first* check plus a
/// deterministic endpoint-id phase offset — the tie-break that orders
/// simultaneous claimants so the earlier one sheds, finds the later
/// one's still-held beacon, and yields. Later rounds run the steady
/// cadence plus fresh random jitter, breaking the residual
/// both-shed-together collision geometrically.
///
/// `roster` is the membership count (`EventLoopState::peers`), and it picks
/// the steady tier: a shed's cost is what the blip disturbs, which is how
/// many members may be bootstrapped through this beacon. The live-link count
/// this used to read mismeasured exactly when it mattered — a survivor
/// claiming right after an origin's death holds two links in a twenty-member
/// mesh, links regrow over seconds, and by shed time the whole mesh paid a
/// cadence priced for a two-tab room. The roster survives that churn. See
/// [`RIVAL_RECHECK_SMALL_ROSTER`](crate::util::tuning::RIVAL_RECHECK_SMALL_ROSTER).
///
/// Small rosters also back off geometrically: each steady round doubles the
/// brisk base, capped at the island backstop. A re-check that keeps finding
/// no rival is evidence there is none, and without the backoff a stable
/// two-tab mesh blipped its beacon every 30-60s forever. Rounds reset when a
/// rival wins an arbitration, so a fresh claim epoch starts brisk again.
///
/// An **empty** roster ramps past the island backstop to
/// [`RIVAL_RECHECK_ALONE`](crate::util::tuning::RIVAL_RECHECK_ALONE).
/// The brisk rounds are the same — a double-claim inside a probe window is
/// repaired by the first few sheds, and those are untouched — but a node that
/// has found no rival and knows no peer has nothing left to arbitrate, and the
/// 300s cap only rebinds its public endpoint every few minutes forever. The
/// tier is `roster == 0`, not "small": two survivors of a departed origin each
/// count the other, and that split is the one the brisk cap exists for.
pub(super) fn next_recheck_delay(round: u32, roster: usize, endpoint_id: EndpointId) -> Duration {
    use crate::util::clock;
    use crate::util::tuning::{
        RIVAL_RECHECK_OFFSET_SPAN, RIVAL_RECHECK_SMALL_ROSTER, rival_recheck, rival_recheck_alone,
        rival_recheck_first, rival_recheck_meshed,
    };

    if round == 0 {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&endpoint_id.as_bytes()[..8]);
        // Pubkey bytes are already uniform — no hashing needed.
        let offset_ms =
            u64::from_le_bytes(prefix) % clock::millis_saturating(RIVAL_RECHECK_OFFSET_SPAN);
        return rival_recheck_first() + Duration::from_millis(offset_ms);
    }
    let base = if roster > RIVAL_RECHECK_SMALL_ROSTER {
        rival_recheck_meshed()
    } else {
        let backstop = if roster == 0 {
            rival_recheck_alone()
        } else {
            rival_recheck_meshed()
        };
        // Seven doublings reach the alone ceiling from the brisk base
        // (30s << 7 = 3840s); capped well before the shift could overflow, and
        // the base is capped at the backstop regardless.
        let doublings = round.saturating_sub(1).min(7);
        rival_recheck()
            .saturating_mul(1u32 << doublings)
            .min(backstop)
    };
    // Jitter spans the full base: two split holders re-jitter from
    // near-aligned schedules every round, and the wider the span the more
    // likely one's probe window lands while the other still holds.
    base + rand::Rng::random_range(&mut rand::rng(), Duration::ZERO..=base)
}
/// How many steady intervals a shed may be held back while a data-channel
/// peer depends on this beacon.
///
/// A shed drops the rendezvous a browser reached us through, and a browser
/// has no second path to fall back on: the tab's roster empties and its
/// transfer stops. Native peers re-dial, so the wait is for the lane that
/// cannot. Bounded rather than indefinite because the shed is also how two
/// split holders discover each other, and a pair that each kept a tab would
/// otherwise never merge.
const MAX_SHED_DEFERRALS: u32 = 3;

/// Whether this due shed waits a round: someone is on the data channel, or
/// negotiating one, and we have not already waited our limit.
pub(super) fn defer_shed(dependents: usize, deferrals: u32) -> bool {
    dependents > 0 && deferrals < MAX_SHED_DEFERRALS
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

/// Arm the next rival re-check after a fresh claim (a `None` → live
/// `beacon::ensure` transition). No-op for sessions the shed doesn't
/// apply to, so every claim site can call it unconditionally. A fresh claim
/// is a new beacon, so it also starts with the full shed wait: a beacon
/// replaced without a shed would otherwise inherit its predecessor's count.
///
/// The one funnel every claim passes, so it also ends the round of this member that was started
/// while nobody held the rendezvous: that round cannot find the beacon just claimed.
pub(super) fn schedule_rival_recheck(
    state: &mut EventLoopState,
    policy: CoHostPolicy,
    params: &beacon::RendezvousParams,
    endpoint: &Endpoint,
) {
    state.cancel_rendezvous_round();
    state.rival_recheck_deferrals = 0;
    state.yield_to_lower = false;
    if !rival_recheck_applies(policy, params.bind_ports.is_empty()) {
        return;
    }
    let delay = next_recheck_delay(state.rival_recheck_rounds, state.peers.len(), endpoint.id());
    state.next_rival_recheck = Some(Instant::now() + delay);
}
/// The rival re-check itself: at the scheduled deadline, **release** the
/// held beacon and let probe-before-claim re-arbitrate on the reclaim
/// burst. Two `EagerProbed` members that claimed inside each other's
/// probe window both hold the same `rendezvous_id` and each captures its
/// own bootstrap dial — a split nothing else repairs, because a holder's
/// dial of the shared id preferentially reaches itself. Dropping our copy
/// first removes us from every resolution channel (relay registration,
/// mDNS record, pooled connection), so the re-probe's answer is finally
/// meaningful: *connects* ⇒ a rival serves it, stay a peer and let
/// the heal re-graft merge the overlays; *times out* ⇒ genuinely alone,
/// re-claim. Returns whether a shed happened (the caller then skips this
/// tick's synchronous re-claim).
pub(super) fn shed_rival_beacon_if_due(
    state: &mut EventLoopState,
    arm: &CohostArm<'_>,
    rendezvous: &mut Option<beacon::Rendezvous>,
    peer: EndpointId,
) -> bool {
    if rendezvous.is_none() || !rival_recheck_applies(arm.policy, arm.params.bind_ports.is_empty())
    {
        return false;
    }
    let due = state
        .next_rival_recheck
        .is_some_and(|deadline| Instant::now() >= deadline);
    if !due {
        return false;
    }
    let dependents = rendezvous
        .as_ref()
        .map_or_else(beacon::Dependents::default, |held| held.dependents(peer));
    if !state.yield_to_lower && defer_shed(dependents.count(), state.rival_recheck_deferrals) {
        state.rival_recheck_deferrals = state.rival_recheck_deferrals.saturating_add(1);
        state.next_rival_recheck = Some(Instant::now() + tuning::rival_recheck());
        let live_ids = dependents.live_ids();
        let own_ids = dependents.own_ids();
        tracing::info!(
            target: "habilis_network::gossip",
            node = %peer.fmt_short(),
            dependents = dependents.count(),
            dependent_ids = ?dependents.foreign_ids(),
            live_ids = ?live_ids,
            own_ids = ?own_ids,
            in_flight = dependents.in_flight,
            deferrals = state.rival_recheck_deferrals,
            "beacon rival re-check deferred: a data-channel peer is hanging off this beacon"
        );
        return false;
    }
    state.rival_recheck_deferrals = 0;
    tracing::info!(
        target: "habilis_network::gossip",
        node = %peer.fmt_short(),
        yield_to_lower = state.yield_to_lower,
        "beacon rival re-check: releasing the rendezvous to re-probe for a same-id co-host"
    );
    state.yield_to_lower = false;
    // `shed`, not a plain drop: the graceful endpoint close turns the
    // peer's link to its own dead beacon into an immediate
    // `NeighborDown` instead of a zombie that only dies at the QUIC idle
    // timeout — the zombie both stalls the post-shed re-graft and leaves
    // a poisoned pool entry under the shared id.
    if let Some(held) = rendezvous.take() {
        state.beacon_closing = Some(held.shed_then());
    }
    state.next_rival_recheck = None;
    state.rival_recheck_rounds = state.rival_recheck_rounds.saturating_add(1);
    // A round that was running against our own beacon now has nothing to find.
    state.cancel_rendezvous_round();
    // The book still names the beacon just shed; the next holder writes its own address. What the
    // mesh registered for the id by itself (a relay rung) is written back.
    state.address_book.remove_endpoint_info(arm.params.id);
    super::setup::register_rendezvous(
        &state.address_book,
        arm.params,
        &state.rungs.withheld_rungs(),
    );
    // Don't wait for that `NeighborDown` either — clear the link flag now
    // (mirroring the hard resume edge), or a yielding node's heal ticks
    // idle on "rendezvous linked" instead of grafting the rival's beacon.
    state.rendezvous_linked = false;
    // We just released the identity to re-probe it, so the reading that
    // stood before the release answers a question we have re-asked.
    state.forget_rendezvous_verdict();
    // Arm the fast burst explicitly rather than waiting for our own
    // beacon's `NeighborDown` to do it — the re-probe (and the re-claim
    // when no rival exists) then runs within ~RECLAIM_INTERVAL.
    state.arm_reclaim(Instant::now());
    true
}

#[cfg(test)]
mod tests {
    use super::super::config::CoHostPolicy;
    use super::super::state::RivalFlag;
    use super::{
        MAX_SHED_DEFERRALS, claims_at_startup, defer_shed, next_recheck_delay, probes_before_claim,
        regrafts_rendezvous, rival_recheck_applies,
    };
    use habilis_network_test_tracing::{expect_warn, test};
    use std::time::Duration;

    use crate::beacon::claim;
    use crate::daemon::{config, state};
    use crate::protocol::mesh;
    use crate::util::{clock, tuning};
    use tokio::sync::{mpsc, watch};
    /// A shed cuts the rendezvous a browser reached us through, and the tab
    /// has nothing else: its roster empties mid-transfer. Observed as a
    /// terminal cycling claim and release while a tab saw no peers at all.
    #[test]
    fn a_due_shed_waits_while_a_data_channel_peer_depends_on_us() {
        assert!(defer_shed(1, 0), "a tab is hanging off this beacon");
        assert!(!defer_shed(0, 0), "nobody on the channel: shed on time");
    }

    /// Public-mesh rendezvous parameters: the rival re-check applies to them.
    fn public_params() -> crate::beacon::RendezvousParams {
        let secret = iroh::SecretKey::generate();
        crate::beacon::RendezvousParams {
            topic_id: iroh_gossip::proto::TopicId::from_bytes([7u8; 32]),
            id: secret.public(),
            secret,
            bind_ports: Vec::new(),
            lookups: mesh::LookupOpts::loopback(),
            relay_transport: crate::transport::PayloadPath::DirectOnly,
            bootstrap_relay: None,
            rung_tx: watch::channel(None).0,
        }
    }

    /// An endpoint on loopback, closed at the end of the test whatever the test does with it.
    async fn loopback_endpoint() -> iroh::Endpoint {
        let endpoint = crate::lookup::build_endpoint(
            &mesh::LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            crate::lookup::TransportHandles::default(),
        )
        .await
        .expect("loopback endpoint");
        let closer = endpoint.clone();
        habilis_network_test_tracing::at_end(async move { closer.close().await });
        endpoint
    }

    /// A held beacon with one tab negotiating on it. The tab counts as a
    /// dependent for as long as the returned guard lives.
    fn beacon_with_a_negotiating_tab(
        params: &crate::beacon::RendezvousParams,
        endpoint: iroh::Endpoint,
    ) -> (Option<crate::beacon::Rendezvous>, impl Sized) {
        use crate::transport::{MAX_DIRECT_PEERS, SignalAdmission};
        let handle = crate::lookup::build_webrtc_handle(params.id);
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let tab = iroh::SecretKey::generate().public();
        let round = admission.try_admit(tab, &handle).expect("a free slot");
        let rendezvous = crate::beacon::Rendezvous::for_test(endpoint, Some((handle, admission)));
        (Some(rendezvous), round)
    }

    /// A tab negotiating with the beacon has no session yet, and a shed then
    /// cuts the rendezvous it is about to link through. Observed: a shed 7 ms
    /// before the tab's session attached, after which the tab found the
    /// rendezvous free and claimed it. The count is the beacon's own answerer:
    /// the peer's handle never holds a tab's session with the beacon.
    #[test]
    async fn a_due_shed_waits_for_a_tab_negotiating_with_the_beacon() {
        let params = public_params();
        let arm = super::CohostArm {
            policy: CoHostPolicy::EagerProbed,
            params: &params,
            started: clock::Instant::now(),
        };
        let mut state = crate::testing::fresh_state();
        state.next_rival_recheck = Some(clock::Instant::now());
        let (mut rendezvous, _round) =
            beacon_with_a_negotiating_tab(&params, loopback_endpoint().await);

        assert!(
            !super::shed_rival_beacon_if_due(
                &mut state,
                &arm,
                &mut rendezvous,
                iroh::SecretKey::generate().public(),
            ),
            "a due shed waits while a tab negotiates with the beacon"
        );
        assert!(rendezvous.is_some(), "the beacon is still held");
    }

    /// A member that knows a holder and holds nothing does not probe to claim: its own shed makes
    /// the shared id read free for a moment, and a claim on that reading stands up the second
    /// holder again. The holder's `PeerInfo` without the flag ends it.
    #[test]
    fn a_known_holder_keeps_us_from_probing_to_claim() {
        let mut state = crate::testing::fresh_state();
        let own = iroh::SecretKey::generate().public();
        let holder = iroh::SecretKey::generate().public();
        let now = clock::Instant::now();
        assert!(super::may_probe_to_claim(&state), "no holder known: probe");

        state.note_rival_beacon_flag(
            own,
            crate::protocol::AuthorKey::from([9u8; 32]),
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
            crate::protocol::AuthorKey::from([9u8; 32]),
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
        let mut state = crate::testing::fresh_state();
        let own = iroh::SecretKey::generate().public();
        let holder = iroh::SecretKey::generate().public();
        assert!(
            !super::verdict_after_known_holders(false, &state),
            "a probe that reads free does not claim while a holder is known"
        );

        state.note_rival_beacon_flag(
            own,
            crate::protocol::AuthorKey::from([9u8; 32]),
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

    /// A lower holder in our overlay already settled who keeps the rendezvous, so a tab on this
    /// beacon must not hold the release back: the tab re-dials, and two holders that each
    /// kept a tab would stay split.
    #[test]
    async fn a_due_shed_does_not_wait_when_a_lower_holder_was_seen() {
        let params = public_params();
        let arm = super::CohostArm {
            policy: CoHostPolicy::EagerProbed,
            params: &params,
            started: clock::Instant::now(),
        };
        let mut state = crate::testing::fresh_state();
        state.next_rival_recheck = Some(clock::Instant::now());
        state.yield_to_lower = true;
        let (mut rendezvous, _round) =
            beacon_with_a_negotiating_tab(&params, loopback_endpoint().await);

        assert!(
            super::shed_rival_beacon_if_due(
                &mut state,
                &arm,
                &mut rendezvous,
                iroh::SecretKey::generate().public(),
            ),
            "a due shed does not wait when a lower holder was seen"
        );
        assert!(rendezvous.is_none(), "the beacon was released");
        assert!(!state.yield_to_lower, "the release uses the request up");
    }

    /// A yield request belongs to the beacon it was made for: a new claim starts clean.
    #[test]
    async fn a_new_claim_forgets_a_yield_request() {
        let params = public_params();
        let endpoint = loopback_endpoint().await;
        let mut state = crate::testing::fresh_state();
        state.yield_to_lower = true;

        super::schedule_rival_recheck(&mut state, CoHostPolicy::EagerProbed, &params, &endpoint);

        assert!(!state.yield_to_lower, "a new claim forgets a yield request");
    }

    /// A beacon claimed after another went without a shed (a co-host task
    /// ended, `ensure` claimed again) is a new beacon: the deferrals its
    /// predecessor used up must not cut short the wait for a tab on this one.
    #[test]
    async fn a_new_claim_starts_with_the_full_wait() {
        let params = public_params();
        let arm = super::CohostArm {
            policy: CoHostPolicy::EagerProbed,
            params: &params,
            started: clock::Instant::now(),
        };
        let endpoint = loopback_endpoint().await;
        let mut state = crate::testing::fresh_state();
        // The previous beacon waited its limit.
        state.rival_recheck_deferrals = MAX_SHED_DEFERRALS;

        super::schedule_rival_recheck(&mut state, arm.policy, &params, &endpoint);

        let (mut rendezvous, _round) = beacon_with_a_negotiating_tab(&params, endpoint);
        state.next_rival_recheck = Some(clock::Instant::now());
        assert!(
            !super::shed_rival_beacon_if_due(
                &mut state,
                &arm,
                &mut rendezvous,
                iroh::SecretKey::generate().public()
            ),
            "the new beacon's first due shed must wait for its tab"
        );
        assert!(rendezvous.is_some(), "the beacon is still held");
    }

    /// Bounded, or two holders that each kept a tab would never find each
    /// other and the overlays would stay split for good.
    #[test]
    fn the_wait_runs_out() {
        assert!(
            defer_shed(2, MAX_SHED_DEFERRALS - 1),
            "the deferral wait runs out at its last deferral"
        );
        assert!(
            !defer_shed(2, MAX_SHED_DEFERRALS),
            "past the limit the shed happens anyway, so split holders still merge"
        );
    }

    /// Regression for a two-peer loopback mesh that never formed: a peer
    /// whose rendezvous link dropped in the first milliseconds after
    /// joining waited for the 15s heal tick to re-graft, and the mesh
    /// missed its window. The reclaim tick now re-grafts — but only when
    /// there is a link to regain, whoever holds the beacon.
    #[test]
    fn a_reclaim_tick_regrafts_only_when_the_link_is_lost() {
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
    async fn a_heal_tick_claim_opens_the_reclaim_window() {
        use iroh_gossip::net::Gossip;

        use super::{CohostArm, maybe_cohost};
        use crate::daemon::handler_ctx::HandlerCtx;
        use crate::gossip::event::SilentSink;
        use crate::protocol::MeshId;
        use crate::protocol::identity::Identity;
        use crate::protocol::mesh::LookupOpts;
        use crate::testing::{fresh_state, nick};
        use crate::transport::MeshSender;
        use crate::util::clock::Instant;

        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let secret = iroh::SecretKey::generate();
        let params = crate::beacon::RendezvousParams {
            topic_id: iroh_gossip::proto::TopicId::from_bytes([5u8; 32]),
            id: secret.public(),
            secret,
            bind_ports: vec![port],
            lookups: LookupOpts::loopback(),
            relay_transport: crate::transport::PayloadPath::DirectOnly,
            bootstrap_relay: None,
            rung_tx: watch::channel(None).0,
        };

        let endpoint = crate::lookup::build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            crate::lookup::TransportHandles::default(),
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
            max_peers: 16,
            rendezvous_id: params.id,
            external_msg_tx: None,
            sink: &sink,
        };

        let mut state = fresh_state();
        state.meshed = true;
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
        use crate::protocol::mesh::LookupOpts;
        use crate::testing::{fresh_state, nick};
        use crate::transport::MeshSender;
        use crate::util::clock::Instant;

        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let secret = iroh::SecretKey::generate();
        let params = crate::beacon::RendezvousParams {
            topic_id: iroh_gossip::proto::TopicId::from_bytes([6u8; 32]),
            id: secret.public(),
            secret,
            bind_ports: vec![port],
            lookups: LookupOpts::loopback(),
            relay_transport: crate::transport::PayloadPath::DirectOnly,
            bootstrap_relay: None,
            rung_tx: watch::channel(None).0,
        };

        // The holder: another member of the same room, on the only rung.
        let holder_endpoint = loopback_endpoint().await;
        let holder_book = crate::lookup::address_book(&holder_endpoint);
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
            max_peers: 16,
            rendezvous_id: params.id,
            external_msg_tx: None,
            sink: &sink,
        };

        let mut state = fresh_state();
        state.meshed = true;
        configure(&mut state);
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        state.rungs = crate::beacon::RungWatch::new(reports);
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
            match tokio::time::timeout(Duration::from_secs(5), arrivals.recv()).await {
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
    async fn a_released_member_that_reads_a_holder_outside_its_mesh_owes_a_return() {
        let (state, holds_nothing) = Box::pin(heal_tick_beside_a_foreign_holder(|state| {
            state.rendezvous_release_links = 1;
            state
                .linked_endpoints
                .insert(crate::testing::endpoint_id(1));
        }))
        .await;

        assert!(holds_nothing, "the rung is served: the member stays a peer");
        assert!(
            state.rendezvous_wanted(),
            "the walk read a holder that none of the mesh hosts, and nothing was owed: the member \
             has links enough, so no graft ever follows"
        );
    }

    /// The healthy case, read on every heal tick by every released member: the holder is a member
    /// of the mesh and its flag is known. Nothing is owed.
    #[test]
    async fn a_released_member_that_knows_the_holder_of_its_mesh_owes_nothing() {
        let (state, holds_nothing) = Box::pin(heal_tick_beside_a_foreign_holder(|state| {
            state.rendezvous_release_links = 1;
            state
                .linked_endpoints
                .insert(crate::testing::endpoint_id(1));
            state.rival_holders.insert(
                crate::protocol::AuthorKey::from([9u8; 32]),
                crate::testing::endpoint_id(2),
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
    }

    /// A joiner that has fewer links than the release count wants the rendezvous anyway. It owes
    /// nothing, and so its first visit is not made a dwell longer.
    #[test]
    async fn a_joiner_under_the_release_count_owes_no_return() {
        let (state, holds_nothing) = Box::pin(heal_tick_beside_a_foreign_holder(|_| {})).await;

        assert!(
            holds_nothing,
            "a joiner under the release count holds nothing"
        );
        assert!(
            state.rendezvous_comeback_until.is_none(),
            "a joiner under the release count owes no return"
        );
    }

    /// Every rung of the ladder is held by another process: nobody can serve the rendezvous and
    /// the room cannot be joined. The member says so once per repeat interval, to its log and to
    /// its sink, however often the walk runs.
    #[test]
    async fn a_ladder_that_is_taken_whole_is_said_once_per_repeat_interval() {
        use iroh_gossip::net::Gossip;

        use super::{CohostArm, maybe_cohost};
        use crate::daemon::handler_ctx::HandlerCtx;
        use crate::gossip::event::CountingSink;
        use crate::protocol::MeshId;
        use crate::protocol::identity::Identity;
        use crate::protocol::mesh::LookupOpts;
        use crate::testing::{fresh_state, nick};
        use crate::transport::MeshSender;
        use crate::util::clock::Instant;

        expect_warn(
            "habilis_network::beacon",
            "no rendezvous port is free: other processes hold every port of this room",
        );

        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let params_of = |seed: u8| {
            let secret = iroh::SecretKey::generate();
            crate::beacon::RendezvousParams {
                topic_id: iroh_gossip::proto::TopicId::from_bytes([seed; 32]),
                id: secret.public(),
                secret,
                bind_ports: vec![port],
                lookups: LookupOpts::loopback(),
                relay_transport: crate::transport::PayloadPath::DirectOnly,
                bootstrap_relay: None,
                rung_tx: watch::channel(None).0,
            }
        };
        let params = params_of(6);

        // The beacon of another mesh holds the only rung.
        let other = params_of(9);
        let other_endpoint = loopback_endpoint().await;
        let other_book = crate::lookup::address_book(&other_endpoint);
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
            max_peers: 16,
            rendezvous_id: params.id,
            external_msg_tx: None,
            sink: &sink,
        };

        let mut state = fresh_state();
        state.meshed = true;
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        state.rungs = crate::beacon::RungWatch::new(reports);
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
            match tokio::time::timeout(Duration::from_secs(5), arrivals.recv()).await {
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
    }

    /// The state of one holder on a two-rung ladder, and the means to run a heal tick on it. The
    /// first rung is taken by a beacon of another mesh while this member walks, so that it binds
    /// the second; the first rung is then free, or served by another member of this mesh.
    struct HolderOnTheSecondRung {
        params: crate::beacon::RendezvousParams,
        endpoint: iroh::Endpoint,
        rendezvous: Option<crate::beacon::Rendezvous>,
        probe: Option<crate::beacon::RivalProbe>,
        first_port: u16,
        state: state::EventLoopState,
        arrivals: mpsc::UnboundedReceiver<crate::beacon::RungReport>,
    }

    impl HolderOnTheSecondRung {
        async fn new() -> Self {
            let free_port = || {
                std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .and_then(|socket| socket.local_addr())
                    .expect("a free loopback port")
                    .port()
            };
            let (first_port, second_port) = (free_port(), free_port());
            let secret = iroh::SecretKey::generate();
            let params = crate::beacon::RendezvousParams {
                topic_id: iroh_gossip::proto::TopicId::from_bytes([8u8; 32]),
                id: secret.public(),
                secret,
                bind_ports: vec![first_port, second_port],
                lookups: mesh::LookupOpts::loopback(),
                relay_transport: crate::transport::PayloadPath::DirectOnly,
                bootstrap_relay: None,
                rung_tx: watch::channel(None).0,
            };
            // A beacon of another mesh holds the first rung: this member reads it as foreign and
            // binds the second.
            let other_secret = iroh::SecretKey::generate();
            let other = crate::beacon::RendezvousParams {
                topic_id: iroh_gossip::proto::TopicId::from_bytes([9u8; 32]),
                id: other_secret.public(),
                secret: other_secret,
                bind_ports: vec![first_port],
                lookups: mesh::LookupOpts::loopback(),
                relay_transport: crate::transport::PayloadPath::DirectOnly,
                bootstrap_relay: None,
                rung_tx: watch::channel(None).0,
            };
            let other_endpoint = loopback_endpoint().await;
            let other_book = crate::lookup::address_book(&other_endpoint);
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
            let book = crate::lookup::address_book(&endpoint);
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
            let mut state = crate::testing::fresh_state();
            state.meshed = true;
            let (reports, arrivals) = mpsc::unbounded_channel();
            state.rungs = crate::beacon::RungWatch::new(reports);
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
        ) -> (iroh::Endpoint, crate::beacon::Rendezvous) {
            let member = loopback_endpoint().await;
            let book = crate::lookup::address_book(&member);
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
                max_peers: 16,
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
                match tokio::time::timeout(Duration::from_secs(5), self.arrivals.recv()).await {
                    Ok(Some(report)) => self.state.rungs.note(report, Instant::now()),
                    Ok(None) | Err(_) => break,
                }
            }
        }

        async fn close(mut self) {
            if let Some(held) = self.rendezvous.take() {
                held.shed_and_wait().await;
            }
            self.state.rungs.finish().await;
            self.endpoint.close().await;
        }
    }

    /// A holder on a rung above a live one yields it. A split of two beacons on one ladder came
    /// from a rung probe that timed out, and nothing on a loopback ladder ever repaired it: the
    /// holder on the higher rung stayed for ever.
    #[test]
    async fn a_holder_on_a_higher_rung_sheds_when_a_lower_rung_answers_as_our_mesh() {
        let mut holder = HolderOnTheSecondRung::new().await;
        let (lower_endpoint, lower_beacon) = holder.another_member_takes_the_first_rung().await;

        holder.heal_tick().await;

        let shed = holder.rendezvous.is_none();
        holder.close().await;
        lower_beacon.shed_and_wait().await;
        lower_endpoint.close().await;
        assert!(
            shed,
            "a member of our mesh serves the first rung, and the holder on the second kept its bind"
        );
    }

    /// Silence is not an answer. A lower rung that nobody serves, or whose listener says nothing,
    /// never makes the holder shed: a wrong reading of a loaded host would otherwise take the
    /// beacon away from every member that joined through it.
    #[test]
    async fn a_lower_rung_that_does_not_answer_never_makes_the_holder_shed() {
        let mut holder = HolderOnTheSecondRung::new().await;
        for _ in 0..2 {
            holder.heal_tick().await;
            assert!(holder.rendezvous.is_some(), "the first rung is free");
        }
        let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, holder.first_port))
            .expect("the first rung, taken by a socket that says nothing");
        for _ in 0..2 {
            holder.heal_tick().await;
            assert!(
                holder.rendezvous.is_some(),
                "the first rung is silent: nothing answers, and silence is no reading"
            );
        }
        drop(silent);
        holder.close().await;
    }

    /// A beacon that stopped answering keeps its rung. The holder notices at the second check
    /// that does not answer, and not at the first: a busy moment must not take a healthy beacon
    /// from the members that joined through it.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[test]
    async fn a_holder_whose_beacon_stops_answering_sheds_at_the_second_check_and_not_the_first() {
        use habilis_network_test_tracing;

        // The stalled beacon serves no protocol, so each check that dials it is refused with
        // alert 120 and the router of the beacon logs it: the stall causes this WARN.
        expect_warn("iroh::protocol", "peer doesn't support any known protocol");
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
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        holder.close().await;
        assert!(
            kept_at_the_first,
            "one check that does not answer shed the beacon"
        );
        assert!(
            shed_at_the_second,
            "the beacon stopped answering at two checks and was kept"
        );
    }

    /// A beacon that answers is never shed by the check of its own rung, however many ticks
    /// read it: the count of checks that did not answer starts again at every answer.
    #[test]
    async fn a_holder_whose_beacon_answers_is_kept_by_the_check_of_its_own_rung() {
        let mut holder = HolderOnTheSecondRung::new().await;

        for _ in 0..3 {
            holder.heal_tick().await;
            holder.state.rungs.expire_readings();
        }

        let kept = holder.rendezvous.is_some();
        holder.close().await;
        assert!(kept, "a beacon that answers was shed by its own check");
    }

    /// A holder that shed because a lower rung answered stays a peer of that rung, even when its
    /// own probe of the rung then reads silence. A host that stays slow made the probe of the
    /// walk read "not ours" over and over: the walk bound the rung it had just shed, the check of
    /// the next tick shed it again, and the member flapped for ever without ever merging.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[test]
    async fn a_holder_that_shed_for_a_live_lower_rung_stays_a_peer_when_its_probe_is_silent() {
        let mut holder = HolderOnTheSecondRung::new().await;
        let (lower_endpoint, lower_beacon) = holder.another_member_takes_the_first_rung().await;
        crate::beacon::set_blind_rung_probes(holder.endpoint.id(), true);

        holder.heal_tick().await;
        let shed = holder.rendezvous.is_none();
        // The close of the shed beacon is done before the walk, or it would find its own rung
        // still bound and read that as a foreign squat.
        if let Some(closed) = holder.state.beacon_closing.take() {
            let _ = closed.await;
        }
        holder.heal_tick().await;
        let peer = holder.rendezvous.is_none();

        crate::beacon::set_blind_rung_probes(holder.endpoint.id(), false);
        holder.close().await;
        lower_beacon.shed_and_wait().await;
        lower_endpoint.close().await;
        assert!(shed, "the first tick reads the lower rung and sheds");
        assert!(
            peer,
            "the walk that followed read the rung that had just answered as foreign, and bound the rung it shed"
        );
    }

    /// The book kept the address of every beacon that this process held under the id, so a dial to
    /// the id tried the ports of beacons that were gone (the N=2 round: a claim-time offer that hung
    /// for the whole connect bound while the next offer took 37 ms). A shed takes the entry out.
    #[test]
    async fn a_shed_takes_the_address_of_the_shed_beacon_out_of_the_book() {
        let params = public_params();
        let arm = super::CohostArm {
            policy: CoHostPolicy::EagerProbed,
            params: &params,
            started: clock::Instant::now(),
        };
        let endpoint = loopback_endpoint().await;
        let mut state = crate::testing::fresh_state();
        state.next_rival_recheck = Some(clock::Instant::now());
        let old_beacon = iroh::EndpointAddr::new(params.id)
            .with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
        crate::lookup::add_peer_addr(&state.address_book, old_beacon);
        let mut rendezvous = Some(crate::beacon::Rendezvous::for_test(endpoint, None));

        assert!(
            super::shed_rival_beacon_if_due(
                &mut state,
                &arm,
                &mut rendezvous,
                iroh::SecretKey::generate().public(),
            ),
            "a shed takes the address of the shed beacon out of the book"
        );

        assert!(
            state.address_book.get_endpoint_info(params.id).is_none(),
            "the book still names the beacon that was shed"
        );
    }

    /// Every claim passes `schedule_rival_recheck`, the verdict arm of the event loop among them,
    /// and the claim of the split round came through that arm: it ends the round that ran against
    /// the missing holder.
    #[test]
    async fn the_claim_funnel_ends_the_round_that_ran_against_the_missing_holder() {
        let params = public_params();
        let endpoint = loopback_endpoint().await;
        let mut state = crate::testing::fresh_state();
        state.rendezvous_id = Some(params.id);
        let hub = crate::lookup::build_webrtc_handle(endpoint.id());
        let held_round = state
            .webrtc_admission
            .try_admit(params.id, &hub)
            .expect("a free slot");
        let epoch = held_round.epoch();
        let task = n0_future::task::spawn(async move {
            let _held_round = held_round;
            std::future::pending::<()>().await;
        });
        state
            .webrtc_admission
            .track(params.id, epoch, task.abort_handle());
        assert_eq!(
            state.webrtc_admission.in_flight(),
            1,
            "one admission slot is in flight after the claim funnel"
        );

        super::schedule_rival_recheck(&mut state, CoHostPolicy::EagerProbed, &params, &endpoint);

        let round_running = state.webrtc_admission.in_flight() != 0;
        endpoint.close().await;
        assert!(
            !round_running,
            "the round that ran against the missing holder still holds the slot of the rendezvous"
        );
    }

    /// An offer to the rendezvous that started while nobody held it never finds the beacon that
    /// this member claims next, and held the slot for the whole round deadline (observed: a
    /// split of two members that stayed 25 s or more with `not negotiating with the rendezvous
    /// reason=InFlight`). The claim ends it.
    #[test]
    async fn a_claim_ends_the_offer_that_ran_against_the_missing_holder() {
        use iroh_gossip::net::Gossip;

        use super::{CohostArm, maybe_cohost};
        use crate::daemon::handler_ctx::HandlerCtx;
        use crate::gossip::event::SilentSink;
        use crate::protocol::MeshId;
        use crate::protocol::identity::Identity;
        use crate::protocol::mesh::LookupOpts;
        use crate::testing::{fresh_state, nick};
        use crate::transport::MeshSender;
        use crate::util::clock::Instant;

        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let secret = iroh::SecretKey::generate();
        let params = crate::beacon::RendezvousParams {
            topic_id: iroh_gossip::proto::TopicId::from_bytes([5u8; 32]),
            id: secret.public(),
            secret,
            bind_ports: vec![port],
            lookups: LookupOpts::loopback(),
            relay_transport: crate::transport::PayloadPath::DirectOnly,
            bootstrap_relay: None,
            rung_tx: watch::channel(None).0,
        };

        let endpoint = crate::lookup::build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            crate::lookup::TransportHandles::default(),
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
            max_peers: 16,
            rendezvous_id: params.id,
            external_msg_tx: None,
            sink: &sink,
        };

        let mut state = fresh_state();
        state.meshed = true;
        state.rendezvous_id = Some(params.id);
        let hub = crate::lookup::build_webrtc_handle(endpoint.id());
        let held_round = state
            .webrtc_admission
            .try_admit(params.id, &hub)
            .expect("a free slot");
        let epoch = held_round.epoch();
        let task = n0_future::task::spawn(async move {
            let _held_round = held_round;
            std::future::pending::<()>().await;
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
    }

    /// A member whose probe finds the holder (the N=3 round: "staying peer" at 48.69 s) did not
    /// claim, so the claim funnel never ran for it: its round from before the holder stays until
    /// the connect bound. The held verdict ends it.
    #[test]
    async fn a_held_verdict_ends_the_round_that_ran_against_the_missing_holder() {
        use iroh_gossip::net::Gossip;

        use crate::daemon::handler_ctx::HandlerCtx;
        use crate::gossip::event::SilentSink;
        use crate::protocol::MeshId;
        use crate::protocol::identity::Identity;
        use crate::protocol::mesh::LookupOpts;
        use crate::testing::{fresh_state, nick};
        use crate::transport::MeshSender;

        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let secret = iroh::SecretKey::generate();
        let params = crate::beacon::RendezvousParams {
            topic_id: iroh_gossip::proto::TopicId::from_bytes([5u8; 32]),
            id: secret.public(),
            secret,
            bind_ports: vec![port],
            lookups: LookupOpts::loopback(),
            relay_transport: crate::transport::PayloadPath::DirectOnly,
            bootstrap_relay: None,
            rung_tx: watch::channel(None).0,
        };

        let endpoint = crate::lookup::build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            crate::lookup::TransportHandles::default(),
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
            max_peers: 16,
            rendezvous_id: params.id,
            external_msg_tx: None,
            sink: &sink,
        };

        let mut state = fresh_state();
        state.rendezvous_id = Some(params.id);
        let hub = crate::lookup::build_webrtc_handle(endpoint.id());
        let held_round = state
            .webrtc_admission
            .try_admit(params.id, &hub)
            .expect("a free slot");
        let epoch = held_round.epoch();
        let task = n0_future::task::spawn(async move {
            let _held_round = held_round;
            std::future::pending::<()>().await;
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
    }

    #[test]
    fn directory_advertiser_claims_at_startup_with_probe() {
        // Regression for the duplicate-beacon directory bug: an advertiser
        // must co-host the shared rendezvous from t=0 *and* probe-first, so a
        // second advertiser into the same directory defers instead of binding
        // a duplicate (which partitioned the directory in public mode — only
        // one mesh was discoverable). The pre-fix policy was the no-probe
        // `Eager` (claims, doesn't probe), which the probe assertion guards.
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

    #[test]
    fn first_recheck_delay_is_deterministic_and_bounded() {
        use crate::util::tuning::{RIVAL_RECHECK_FIRST, RIVAL_RECHECK_OFFSET_SPAN};

        let id = |byte: u8| iroh::SecretKey::from_bytes(&[byte; 32]).public();

        // Round 0 must be a *deterministic* function of the endpoint id — it
        // is the tie-break ordering simultaneous claimants, so per-call
        // randomness would defeat it.
        assert_eq!(
            next_recheck_delay(0, 0, id(1)),
            next_recheck_delay(0, 0, id(1)),
            "the first recheck delay is the same for the same inputs"
        );

        // Base + phase offset, offset strictly inside the span.
        let base = RIVAL_RECHECK_FIRST;
        let span = RIVAL_RECHECK_OFFSET_SPAN;
        for byte in 0..8u8 {
            let delay = next_recheck_delay(0, 0, id(byte));
            assert!(
                delay >= base && delay < base + span,
                "out of bounds: {delay:?}"
            );
        }

        // Distinct ids must (in practice) spread across the span — all-equal
        // offsets would mean the tie-break never orders anyone.
        let all_equal = (1..8u8)
            .all(|byte| next_recheck_delay(0, 0, id(byte)) == next_recheck_delay(0, 0, id(0)));
        assert!(!all_equal, "phase offsets did not spread across ids");
    }

    #[test]
    fn steady_recheck_delay_is_jittered_within_bounds() {
        use crate::util::tuning::{
            RIVAL_RECHECK, RIVAL_RECHECK_MESHED, RIVAL_RECHECK_SMALL_ROSTER,
        };

        let id = iroh::SecretKey::from_bytes(&[9; 32]).public();

        // Steady rounds: base by tier plus jitter in [0, base].
        let lone_base = RIVAL_RECHECK;
        let meshed_base = RIVAL_RECHECK_MESHED;
        for _ in 0..8 {
            let lone = next_recheck_delay(1, 0, id);
            assert!(
                lone >= lone_base && lone <= lone_base * 2,
                "the lone steady recheck delay is within its jitter bounds"
            );
            let meshed = next_recheck_delay(1, RIVAL_RECHECK_SMALL_ROSTER + 1, id);
            assert!(
                meshed >= meshed_base && meshed <= meshed_base * 2,
                "the meshed steady recheck delay is within its jitter bounds"
            );
        }
    }

    #[test]
    fn a_small_roster_rechecks_at_the_brisk_cadence() {
        use crate::util::tuning::{RIVAL_RECHECK, RIVAL_RECHECK_SMALL_ROSTER};

        let id = iroh::SecretKey::from_bytes(&[9; 32]).public();
        let lone_base = RIVAL_RECHECK;

        // The workload this exists for: an origin dies and two survivors are
        // left holding same-id beacons. Waiting out a cadence priced for two
        // multi-member islands is how that split lasted minutes.
        for roster in 0..=RIVAL_RECHECK_SMALL_ROSTER {
            let delay = next_recheck_delay(1, roster, id);
            assert!(
                delay <= lone_base * 2,
                "a {roster}-member roster must not pay the island backstop cadence: {delay:?}"
            );
        }
    }

    #[test]
    fn rival_free_rounds_back_off_geometrically_to_the_backstop() {
        use crate::util::tuning::{
            RIVAL_RECHECK, RIVAL_RECHECK_MESHED, RIVAL_RECHECK_SMALL_ROSTER,
        };

        let id = iroh::SecretKey::from_bytes(&[9; 32]).public();

        // Each rival-free round doubles the brisk base, capped at the island
        // backstop: a stable small mesh must stop blipping its beacon every
        // half-minute forever. Every small roster with at least one peer pays
        // that cap — two survivors of a departed origin each count the other,
        // and their same-id split is what the cap is priced for.
        for roster in 1..=RIVAL_RECHECK_SMALL_ROSTER {
            for round in 1..=10u32 {
                let base = RIVAL_RECHECK
                    .saturating_mul(1u32 << round.saturating_sub(1).min(7))
                    .min(RIVAL_RECHECK_MESHED);
                for _ in 0..4 {
                    let delay = next_recheck_delay(round, roster, id);
                    assert!(
                        delay >= base && delay <= base * 2,
                        "roster {roster}, round {round}: expected base {base:?}, got {delay:?}"
                    );
                }
            }
        }

        // A large roster pays the backstop from round one, backoff or not.
        let backstop = RIVAL_RECHECK_MESHED;
        let delay = next_recheck_delay(1, 20, id);
        assert!(
            delay >= backstop && delay <= backstop * 2,
            "a rival-free round's delay stays between the backstop bounds"
        );
    }

    /// Regression for a permanently-alone public topic peer that rebound its
    /// endpoint every few minutes forever: an empty roster has no split to
    /// repair once its brisk rounds have found nobody, so its ramp continues
    /// past the island backstop to the alone ceiling.
    #[test]
    fn an_empty_roster_ramps_past_the_island_backstop_to_the_alone_ceiling() {
        use crate::util::tuning::{RIVAL_RECHECK, RIVAL_RECHECK_ALONE, RIVAL_RECHECK_MESHED};

        let id = iroh::SecretKey::from_bytes(&[9; 32]).public();

        for round in 1..=12u32 {
            let base = RIVAL_RECHECK
                .saturating_mul(1u32 << round.saturating_sub(1).min(7))
                .min(RIVAL_RECHECK_ALONE);
            for _ in 0..4 {
                let delay = next_recheck_delay(round, 0, id);
                assert!(
                    delay >= base && delay <= base * 2,
                    "round {round}: expected base {base:?}, got {delay:?}"
                );
            }
        }

        // The brisk rounds are untouched: an empty roster's early sheds are
        // the double-claim repair, so they must match a two-member mesh's.
        for round in 1..=4u32 {
            let alone = next_recheck_delay(round, 0, id);
            let pair = next_recheck_delay(round, 1, id);
            let base = RIVAL_RECHECK.saturating_mul(1u32 << round.saturating_sub(1));
            assert!(
                alone >= base && alone <= base * 2,
                "round {round}: {alone:?}"
            );
            assert!(pair >= base && pair <= base * 2, "round {round}: {pair:?}");
        }

        // The settled cadence is well past the island backstop.
        let settled = next_recheck_delay(12, 0, id);
        let island_cap = RIVAL_RECHECK_MESHED * 2;
        assert!(
            settled > island_cap,
            "a settled lone holder must idle past the island cap: {settled:?}"
        );
        assert!(
            settled >= RIVAL_RECHECK_ALONE,
            "the settled delay reaches the alone ceiling"
        );
    }

    /// A rehome is a fresh arbitration epoch, so the backoff restarts with it.
    ///
    /// Without the reset the next claim inherits whatever round the previous
    /// epoch reached, and `next_recheck_delay`'s round-0 branch — the
    /// deterministic tie-break two simultaneous claimants rely on to shed in a
    /// decidable order — never runs again for the life of the process.
    #[test]
    fn a_rehome_restarts_the_rival_recheck_backoff() {
        let id = iroh::SecretKey::from_bytes(&[7; 32]).public();

        // Round 0 is the tie-break branch: bounded by the phase-offset span
        // rather than by the geometric backoff.
        let fresh = next_recheck_delay(0, 0, id);
        let settled = next_recheck_delay(5, 0, id);
        assert!(
            fresh < settled,
            "a fresh epoch must re-check sooner than a settled one: {fresh:?} vs {settled:?}"
        );

        // What `apply_rung_change` now does on a rehome.
        let mut state = crate::testing::fresh_state();
        state.rival_recheck_rounds = 5;
        state.rival_recheck_rounds = 0;
        assert_eq!(
            next_recheck_delay(state.rival_recheck_rounds, 0, id),
            fresh,
            "after a rehome the next claim is scheduled off round 0"
        );
    }
}
