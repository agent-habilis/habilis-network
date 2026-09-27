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
use super::ctx::HandlerCtx;
use super::state::EventLoopState;
use crate::beacon;
use crate::util::clock::Instant;

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
/// Not in `shutdown()` — the loop owns the `Rendezvous`, and the CLI's
/// `exit_on_quit` path `process::exit`s from inside `shutdown` before any of
/// this could run (that path skips every destructor by design, so there is no
/// warning to silence there either).
///
/// An outstanding probe-before-claim goes the same way, and for the same
/// reason: its throwaway endpoint is just as capable of reaching `Drop` open.
/// So does the startup rung probe, which walks the relay ladder on endpoints
/// of its own. All three close concurrently, so the whole release costs one
/// close budget, which is what `NODE_LEAVE_SECS` is sized for.
pub(super) async fn release_rendezvous(
    rendezvous: &mut Option<beacon::Rendezvous>,
    probe: &mut Option<beacon::RivalProbe>,
    rung_probe: &mut Option<crate::lookup::StoppableTask>,
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
/// `cohost_grace_secs` for an empty mesh (then probe-gated in
/// `beacon::ensure`). Pure + cheap; never blocks `ready`.
pub(super) fn may_cohost(cohost: CoHostPolicy, meshed: bool, started: Instant) -> bool {
    match cohost {
        CoHostPolicy::Never => false,
        CoHostPolicy::Eager | CoHostPolicy::EagerProbed => true,
        CoHostPolicy::Deferred => {
            meshed || started.elapsed().as_secs() >= crate::util::tuning::cohost_grace_secs()
        }
    }
}
/// The co-host decision inputs a heal/reclaim tick needs: which policy
/// governs this session, the rendezvous params to (re)claim under, and
/// (for the unmeshed-joiner grace `maybe_cohost` alone reads) when the
/// event loop started.
pub(super) struct CohostArm<'a> {
    pub(super) policy: CoHostPolicy,
    pub(super) params: &'a beacon::RendezvousParams,
    pub(super) started: Instant,
}
/// Heal-tick co-host: stand up the beacon if this member may serve it
/// now (`may_cohost`). Claim-if-free in private; in public a non-`Eager`
/// member probes first (`beacon::ensure`) so it never registers a
/// duplicate rendezvous that would capture its own bootstrap dial.
pub(super) async fn maybe_cohost(
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    arm: &CohostArm<'_>,
    current: &mut Option<beacon::Rendezvous>,
    probe: &mut Option<beacon::RivalProbe>,
) {
    if may_cohost(arm.policy, state.meshed, arm.started) {
        let claimed = beacon::ensure(
            arm.params,
            ctx.endpoint,
            current,
            probes_before_claim(arm.policy),
            probe,
        )
        .await;
        if claimed {
            schedule_rival_recheck(state, arm.policy, arm.params, ctx.endpoint);
            // The new rendezvous never dials us; the reclaim tick re-grafts it.
            state.arm_reclaim(Instant::now());
        }
    }
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
    ctx: &HandlerCtx<'_>,
    arm: &CohostArm<'_>,
    current: &mut Option<beacon::Rendezvous>,
    probe: &mut Option<beacon::RivalProbe>,
) {
    if arm.policy != CoHostPolicy::Never
        && state
            .reclaim_until
            .is_some_and(|deadline| Instant::now() < deadline)
    {
        let claimed = beacon::ensure(
            arm.params,
            ctx.endpoint,
            current,
            probes_before_claim(arm.policy),
            probe,
        )
        .await;
        if claimed {
            schedule_rival_recheck(state, arm.policy, arm.params, ctx.endpoint);
            return;
        }
        if regrafts_rendezvous(state.rendezvous_linked)
            && crate::transport::webrtc::rendezvous_graftable(state)
        {
            tracing::info!(
                target: "fofoca::gossip",
                "reclaim tick: re-graft the rendezvous (link lost)"
            );
            crate::gossip::heal::tick_heal(arm.params.id, ctx.sender).await;
        }
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
fn regrafts_rendezvous(rendezvous_linked: bool) -> bool {
    !rendezvous_linked
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
/// nothing), and every loopback mesh — a port ladder arbitrates atomically at
/// bind time (`AddrInUse` + identity probe), so no split exists to fix there.
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
/// [`RIVAL_RECHECK_ALONE_SECS`](crate::util::tuning::RIVAL_RECHECK_ALONE_SECS).
/// The brisk rounds are the same — a double-claim inside a probe window is
/// repaired by the first few sheds, and those are untouched — but a node that
/// has found no rival and knows no peer has nothing left to arbitrate, and the
/// 300s cap only rebinds its public endpoint every few minutes forever. The
/// tier is `roster == 0`, not "small": two survivors of a departed origin each
/// count the other, and that split is the one the brisk cap exists for.
pub(super) fn next_recheck_delay(round: u32, roster: usize, endpoint_id: EndpointId) -> Duration {
    use crate::util::tuning::{RIVAL_RECHECK_OFFSET_SPAN_SECS, RIVAL_RECHECK_SMALL_ROSTER};
    use crate::util::tuning::{
        rival_recheck_alone_secs, rival_recheck_first_secs, rival_recheck_meshed_secs,
        rival_recheck_secs,
    };

    if round == 0 {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&endpoint_id.as_bytes()[..8]);
        // Pubkey bytes are already uniform — no hashing needed.
        let offset_ms = u64::from_le_bytes(prefix) % (RIVAL_RECHECK_OFFSET_SPAN_SECS * 1000);
        return Duration::from_secs(rival_recheck_first_secs()) + Duration::from_millis(offset_ms);
    }
    let base_secs = if roster > RIVAL_RECHECK_SMALL_ROSTER {
        rival_recheck_meshed_secs()
    } else {
        let backstop_secs = if roster == 0 {
            rival_recheck_alone_secs()
        } else {
            rival_recheck_meshed_secs()
        };
        // Seven doublings reach the alone ceiling from the brisk base
        // (30s << 7 = 3840s); capped well before the shift could overflow, and
        // the base is capped at the backstop regardless.
        let doublings = round.saturating_sub(1).min(7);
        rival_recheck_secs()
            .saturating_mul(1u64 << doublings)
            .min(backstop_secs)
    };
    // Jitter spans the full base: two split holders re-jitter from
    // near-aligned schedules every round, and the wider the span the more
    // likely one's probe window lands while the other still holds.
    let jitter_ms = rand::Rng::random_range(&mut rand::rng(), 0..=base_secs.saturating_mul(1000));
    Duration::from_secs(base_secs) + Duration::from_millis(jitter_ms)
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

/// Arm the next rival re-check after a fresh claim (a `None` → live
/// `beacon::ensure` transition). No-op for sessions the shed doesn't
/// apply to, so every claim site can call it unconditionally. A fresh claim
/// is a new beacon, so it also starts with the full shed wait: a beacon
/// replaced without a shed would otherwise inherit its predecessor's count.
pub(super) fn schedule_rival_recheck(
    state: &mut EventLoopState,
    policy: CoHostPolicy,
    params: &beacon::RendezvousParams,
    endpoint: &Endpoint,
) {
    state.rival_recheck_deferrals = 0;
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
        .map_or(0, beacon::Rendezvous::dependents);
    if defer_shed(dependents, state.rival_recheck_deferrals) {
        state.rival_recheck_deferrals = state.rival_recheck_deferrals.saturating_add(1);
        state.next_rival_recheck =
            Some(Instant::now() + Duration::from_secs(crate::util::tuning::rival_recheck_secs()));
        tracing::info!(
            target: "fofoca::gossip",
            dependents,
            deferrals = state.rival_recheck_deferrals,
            "beacon rival re-check deferred: a data-channel peer is hanging off this beacon"
        );
        return false;
    }
    state.rival_recheck_deferrals = 0;
    tracing::info!(
        target: "fofoca::gossip",
        "beacon rival re-check: releasing the rendezvous to re-probe for a same-id co-host"
    );
    // `shed`, not a plain drop: the graceful endpoint close turns the
    // peer's link to its own dead beacon into an immediate
    // `NeighborDown` instead of a zombie that only dies at the QUIC idle
    // timeout — the zombie both stalls the post-shed re-graft and leaves
    // a poisoned pool entry under the shared id.
    if let Some(held) = rendezvous.take() {
        held.shed();
    }
    state.next_rival_recheck = None;
    state.rival_recheck_rounds = state.rival_recheck_rounds.saturating_add(1);
    // Don't wait for that `NeighborDown` either — clear the link flag now
    // (mirroring the hard resume edge), or a yielding node's heal ticks
    // idle on "rendezvous linked" instead of grafting the rival's beacon.
    state.rendezvous_linked = false;
    // We just released the identity to re-probe it, so the reading that
    // stood before the release answers a question we have re-asked.
    state.forget_rendezvous_verdict();
    // Arm the fast burst explicitly rather than waiting for our own
    // beacon's `NeighborDown` to do it — the re-probe (and the re-claim
    // when no rival exists) then runs within ~RECLAIM_INTERVAL_MS.
    state.arm_reclaim(Instant::now());
    true
}

#[cfg(test)]
mod tests {
    use super::super::config::CoHostPolicy;
    use super::{
        MAX_SHED_DEFERRALS, claims_at_startup, defer_shed, next_recheck_delay, probes_before_claim,
        regrafts_rendezvous, rival_recheck_applies,
    };
    use std::time::Duration;

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
            lookups: crate::protocol::mesh::LookupOpts::loopback(),
            relay_transport: false,
            bootstrap_relay: None,
            rung_tx: tokio::sync::watch::channel(None).0,
        }
    }

    async fn loopback_endpoint() -> iroh::Endpoint {
        crate::lookup::build_endpoint(
            &crate::protocol::mesh::LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            crate::lookup::TransportHandles::default(),
        )
        .await
        .expect("loopback endpoint")
    }

    /// A held beacon with one tab negotiating on it. The tab counts as a
    /// dependent for as long as the returned guard lives.
    fn beacon_with_a_negotiating_tab(
        params: &crate::beacon::RendezvousParams,
        endpoint: iroh::Endpoint,
    ) -> (Option<crate::beacon::Rendezvous>, impl Sized) {
        use crate::transport::{MAX_DIRECT_PEERS, SignalAdmission};
        let handle = crate::lookup::new_webrtc_handle(params.id);
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
    #[tokio::test]
    async fn a_due_shed_waits_for_a_tab_negotiating_with_the_beacon() {
        let params = public_params();
        let arm = super::CohostArm {
            policy: CoHostPolicy::EagerProbed,
            params: &params,
            started: crate::util::clock::Instant::now(),
        };
        let mut state = crate::testing::fresh_state();
        state.next_rival_recheck = Some(crate::util::clock::Instant::now());
        let (mut rendezvous, _round) =
            beacon_with_a_negotiating_tab(&params, loopback_endpoint().await);

        assert!(!super::shed_rival_beacon_if_due(
            &mut state,
            &arm,
            &mut rendezvous
        ));
        assert!(rendezvous.is_some(), "the beacon is still held");
    }

    /// A beacon claimed after another went without a shed (a co-host task
    /// ended, `ensure` claimed again) is a new beacon: the deferrals its
    /// predecessor used up must not cut short the wait for a tab on this one.
    #[tokio::test]
    async fn a_new_claim_starts_with_the_full_wait() {
        let params = public_params();
        let arm = super::CohostArm {
            policy: CoHostPolicy::EagerProbed,
            params: &params,
            started: crate::util::clock::Instant::now(),
        };
        let endpoint = loopback_endpoint().await;
        let mut state = crate::testing::fresh_state();
        // The previous beacon waited its limit.
        state.rival_recheck_deferrals = MAX_SHED_DEFERRALS;

        super::schedule_rival_recheck(&mut state, arm.policy, &params, &endpoint);

        let (mut rendezvous, _round) = beacon_with_a_negotiating_tab(&params, endpoint);
        state.next_rival_recheck = Some(crate::util::clock::Instant::now());
        assert!(
            !super::shed_rival_beacon_if_due(&mut state, &arm, &mut rendezvous),
            "the new beacon's first due shed must wait for its tab"
        );
        assert!(rendezvous.is_some(), "the beacon is still held");
    }

    /// Bounded, or two holders that each kept a tab would never find each
    /// other and the overlays would stay split for good.
    #[test]
    fn the_wait_runs_out() {
        assert!(defer_shed(2, MAX_SHED_DEFERRALS - 1));
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
            regrafts_rendezvous(false),
            "link lost: the case that stalled, and the only way a beacon we hold gets linked"
        );
        assert!(
            !regrafts_rendezvous(true),
            "a live link must not be re-dialled — both heal legs dial GOSSIP_ALPN, and the \
             beacon adopting the new one flaps the healthy link once per tick"
        );
    }

    /// Our rendezvous never dials us, so a fresh claim is linked only by our
    /// own re-graft. The reclaim tick does that within `RECLAIM_INTERVAL_MS`,
    /// but only while its window is open, and a heal-tick claim happens with
    /// no window open: without one, the link waits for the next heal tick.
    #[tokio::test]
    async fn a_heal_tick_claim_opens_the_reclaim_window() {
        use iroh_gossip::net::Gossip;

        use super::{CohostArm, maybe_cohost};
        use crate::daemon::ctx::HandlerCtx;
        use crate::gossip::event::SilentSink;
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
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
            relay_transport: false,
            bootstrap_relay: None,
            rung_tx: tokio::sync::watch::channel(None).0,
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
        let our_pubkey = encode_pubkey(&identity.public());
        let sink = SilentSink;
        let ctx = HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
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
        maybe_cohost(&mut state, &ctx, &arm, &mut rendezvous, &mut probe).await;
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

    #[test]
    fn directory_advertiser_claims_at_startup_with_probe() {
        // Regression for the duplicate-beacon directory bug: an advertiser
        // must co-host the shared rendezvous from t=0 *and* probe-first, so a
        // second advertiser into the same directory defers instead of binding
        // a duplicate (which partitioned the directory in public mode — only
        // one mesh was discoverable). The pre-fix policy was the no-probe
        // `Eager` (claims, doesn't probe), which the probe assertion guards.
        let advertiser = crate::daemon::config::DIRECTORY_ADVERTISER_COHOST;
        assert!(claims_at_startup(advertiser), "must claim at t=0");
        assert!(
            probes_before_claim(advertiser),
            "must probe before claiming"
        );

        // The mesh origin (`create`) claims at startup but skips the probe;
        // joiners and consumers don't claim at startup at all.
        assert!(claims_at_startup(CoHostPolicy::Eager));
        assert!(!probes_before_claim(CoHostPolicy::Eager));
        assert!(!claims_at_startup(CoHostPolicy::Deferred));
        assert!(!claims_at_startup(CoHostPolicy::Never));
    }

    #[test]
    fn rival_recheck_gates_on_probed_claims_and_public() {
        // The shed exists for claimants that took the identity on the word of
        // a probe and can therefore have raced each other into a same-id
        // split: directory advertisers and topic joiners (`EagerProbed`)…
        assert!(rival_recheck_applies(CoHostPolicy::EagerProbed, true));
        // …and ordinary joiners (`Deferred`), which this used to exclude.
        // Regression: a survivor of a departed origin claims on a probe like
        // anyone else, and with the shed off there was nothing to re-arbitrate
        // the duplicate beacons that followed. See `rival_recheck_applies`.
        assert!(rival_recheck_applies(CoHostPolicy::Deferred, true));
        // The loopback port ladder arbitrates atomically at bind time — no
        // split to fix, shedding would only churn the beacon.
        assert!(!rival_recheck_applies(CoHostPolicy::EagerProbed, false));
        assert!(!rival_recheck_applies(CoHostPolicy::Deferred, false));
        // The origin owns the identity from t=0 and a consumer claims nothing.
        assert!(!rival_recheck_applies(CoHostPolicy::Eager, true));
        assert!(!rival_recheck_applies(CoHostPolicy::Never, true));
    }

    #[test]
    fn first_recheck_delay_is_deterministic_and_bounded() {
        use crate::util::tuning::{RIVAL_RECHECK_FIRST_SECS, RIVAL_RECHECK_OFFSET_SPAN_SECS};

        let id = |byte: u8| iroh::SecretKey::from_bytes(&[byte; 32]).public();

        // Round 0 must be a *deterministic* function of the endpoint id — it
        // is the tie-break ordering simultaneous claimants, so per-call
        // randomness would defeat it.
        assert_eq!(
            next_recheck_delay(0, 0, id(1)),
            next_recheck_delay(0, 0, id(1))
        );

        // Base + phase offset, offset strictly inside the span.
        let base = Duration::from_secs(RIVAL_RECHECK_FIRST_SECS);
        let span = Duration::from_secs(RIVAL_RECHECK_OFFSET_SPAN_SECS);
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
            RIVAL_RECHECK_MESHED_SECS, RIVAL_RECHECK_SECS, RIVAL_RECHECK_SMALL_ROSTER,
        };

        let id = iroh::SecretKey::from_bytes(&[9; 32]).public();

        // Steady rounds: base by tier plus jitter in [0, base].
        let lone_base = Duration::from_secs(RIVAL_RECHECK_SECS);
        let meshed_base = Duration::from_secs(RIVAL_RECHECK_MESHED_SECS);
        for _ in 0..8 {
            let lone = next_recheck_delay(1, 0, id);
            assert!(lone >= lone_base && lone <= lone_base * 2);
            let meshed = next_recheck_delay(1, RIVAL_RECHECK_SMALL_ROSTER + 1, id);
            assert!(meshed >= meshed_base && meshed <= meshed_base * 2);
        }
    }

    #[test]
    fn a_small_roster_rechecks_at_the_brisk_cadence() {
        use crate::util::tuning::{RIVAL_RECHECK_SECS, RIVAL_RECHECK_SMALL_ROSTER};

        let id = iroh::SecretKey::from_bytes(&[9; 32]).public();
        let lone_base = Duration::from_secs(RIVAL_RECHECK_SECS);

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
            RIVAL_RECHECK_MESHED_SECS, RIVAL_RECHECK_SECS, RIVAL_RECHECK_SMALL_ROSTER,
        };

        let id = iroh::SecretKey::from_bytes(&[9; 32]).public();

        // Each rival-free round doubles the brisk base, capped at the island
        // backstop: a stable small mesh must stop blipping its beacon every
        // half-minute forever. Every small roster with at least one peer pays
        // that cap — two survivors of a departed origin each count the other,
        // and their same-id split is what the cap is priced for.
        for roster in 1..=RIVAL_RECHECK_SMALL_ROSTER {
            for round in 1..=10u32 {
                let expected = (RIVAL_RECHECK_SECS << round.saturating_sub(1).min(7))
                    .min(RIVAL_RECHECK_MESHED_SECS);
                let base = Duration::from_secs(expected);
                for _ in 0..4 {
                    let delay = next_recheck_delay(round, roster, id);
                    assert!(
                        delay >= base && delay <= base * 2,
                        "roster {roster}, round {round}: expected base {expected}s, got {delay:?}"
                    );
                }
            }
        }

        // A large roster pays the backstop from round one, backoff or not.
        let backstop = Duration::from_secs(RIVAL_RECHECK_MESHED_SECS);
        let delay = next_recheck_delay(1, 20, id);
        assert!(delay >= backstop && delay <= backstop * 2);
    }

    /// Regression for a permanently-alone public topic peer that rebound its
    /// endpoint every few minutes forever: an empty roster has no split to
    /// repair once its brisk rounds have found nobody, so its ramp continues
    /// past the island backstop to the alone ceiling.
    #[test]
    fn an_empty_roster_ramps_past_the_island_backstop_to_the_alone_ceiling() {
        use crate::util::tuning::{
            RIVAL_RECHECK_ALONE_SECS, RIVAL_RECHECK_MESHED_SECS, RIVAL_RECHECK_SECS,
        };

        let id = iroh::SecretKey::from_bytes(&[9; 32]).public();

        for round in 1..=12u32 {
            let expected = (RIVAL_RECHECK_SECS << round.saturating_sub(1).min(7))
                .min(RIVAL_RECHECK_ALONE_SECS);
            let base = Duration::from_secs(expected);
            for _ in 0..4 {
                let delay = next_recheck_delay(round, 0, id);
                assert!(
                    delay >= base && delay <= base * 2,
                    "round {round}: expected base {expected}s, got {delay:?}"
                );
            }
        }

        // The brisk rounds are untouched: an empty roster's early sheds are
        // the double-claim repair, so they must match a two-member mesh's.
        for round in 1..=4u32 {
            let alone = next_recheck_delay(round, 0, id);
            let pair = next_recheck_delay(round, 1, id);
            let base = Duration::from_secs(RIVAL_RECHECK_SECS << round.saturating_sub(1));
            assert!(
                alone >= base && alone <= base * 2,
                "round {round}: {alone:?}"
            );
            assert!(pair >= base && pair <= base * 2, "round {round}: {pair:?}");
        }

        // The settled cadence is well past the island backstop.
        let settled = next_recheck_delay(12, 0, id);
        let island_cap = Duration::from_secs(RIVAL_RECHECK_MESHED_SECS) * 2;
        assert!(
            settled > island_cap,
            "a settled lone holder must idle past the island cap: {settled:?}"
        );
        assert!(settled >= Duration::from_secs(RIVAL_RECHECK_ALONE_SECS));
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
