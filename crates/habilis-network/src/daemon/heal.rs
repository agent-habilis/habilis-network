//! Healing the gossip mesh: the heal tick, the resubscribe path when the
//! stream ends, and applying a rung change chosen off-loop.
//!
//! Split out of `event_loop` for the same reason as `beacon_arm` — this is
//! recovery, not the loop, and it reads better without the tick arms around it.

use std::time::Duration;

use anyhow::Result;

use iroh::{Endpoint, RelayUrl};
use iroh_gossip::api::{GossipReceiver, GossipSender};
use tokio::sync::watch;

use super::ctx::HandlerCtx;
use super::event_loop::{CtxParts, TickGap};
use super::setup;
use super::state::EventLoopState;
use crate::gossip::app::NodeApp;
use crate::gossip::event::NodeEvent;
use crate::transport::MeshSender;
use crate::util::clock::{Instant, millis_saturating};
use crate::util::tuning::{RESUBSCRIBE_MAX_ATTEMPTS, heal_stall_threshold_secs};
use crate::{beacon, gossip, lookup};

/// Monotonic `gap` past `stall_threshold`: the process was throttled
/// (but not fully frozen) between heal ticks (macOS App Nap / timer
/// coalescing) long enough that the mesh died of idle timeout.
pub(super) fn is_resume(gap: Duration, stall_threshold: Duration) -> bool {
    gap > stall_threshold
}
/// The macOS-sleep signature the monotonic gap is blind to: the
/// monotonic clock pauses in lockstep with the frozen process, so a
/// day-long suspend shows only a few seconds of `mono_gap` while the
/// wall clock jumped the whole way. A `wall_gap` exceeding `mono_gap`
/// by more than `stall_threshold` means time elapsed that the process
/// could not observe — it was suspended and the mesh is dead.
pub(super) fn is_wall_resume(
    wall_gap: Duration,
    mono_gap: Duration,
    stall_threshold: Duration,
) -> bool {
    wall_gap.saturating_sub(mono_gap) > stall_threshold
}
/// One heal tick (factored out of `event_loop` for the line budget).
/// On a resume edge the steady probe can't rebuild a mesh that fully
/// died while the timers were frozen, so re-enter cold-joiner mode,
/// re-assert the relay-homed rendezvous hint (the network changed),
/// and run the long re-bootstrap probe. Otherwise the normal probe.
///
/// A resume is either a monotonic stall (throttle) OR a wall-vs-
/// monotonic divergence (suspend/sleep) — the latter is the only
/// signal that survives a macOS sleep, which freezes the monotonic
/// clock with the process.
pub(super) async fn run_heal(
    gap: TickGap,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
    params: &beacon::RendezvousParams,
) {
    // A browser-shaped peer's rendezvous link can only ever be admitted on
    // a data channel; keep offering one while the link is down.
    crate::transport::webrtc::negotiate_rendezvous_session(state, ctx);
    // A node that came back to a mesh whose links are all up gets no link
    // event to release on, so the heal tick checks too.
    gossip::heal::release_rendezvous_if_due(state, ctx).await;
    let threshold = Duration::from_secs(heal_stall_threshold_secs());
    let hard_edge = is_resume(gap.mono, threshold) || is_wall_resume(gap.wall, gap.mono, threshold);
    if hard_edge {
        tracing::warn!(
            target: "habilis_network::gossip",
            mono_gap_ms = millis_saturating(gap.mono),
            wall_gap_ms = millis_saturating(gap.wall),
            "heal: hard re-bootstrap edge"
        );
        state.note_degraded();
        // The frozen-era link view is stale by definition; clearing this
        // re-arms the regular tick's probe until a fresh NeighborUp. Every link
        // is stale too, so a node that had let go of the rendezvous is owed
        // one return to it.
        state.rendezvous_linked = false;
        state.owe_rendezvous_return(Instant::now());
        // A free reading taken before the freeze is stale for the same
        // reason, across the widest gap any of these deadlines can span.
        state.forget_rendezvous_verdict();
        // A rival re-check deadline that "matured" while the process was
        // frozen would shed the beacon into a mesh that is still
        // re-forming; push it out a steady interval so the re-bootstrap
        // settles first.
        if state.next_rival_recheck.is_some() {
            state.next_rival_recheck = Some(
                Instant::now() + Duration::from_secs(crate::util::tuning::rival_recheck_secs()),
            );
        }
        // Re-assert the rendezvous hint (the network changed). The rung
        // is re-validated off-loop by the beacon's liveness self-monitor,
        // so a rung that died during the freeze self-corrects — no inline
        // ladder walk on the event loop here.
        setup::register_rendezvous(ctx.endpoint, params);
        if crate::transport::webrtc::rendezvous_graftable(state) {
            gossip::heal::tick_heal_hard(ctx.endpoint, params.id, ctx.sender).await;
        }
    } else if state.rendezvous_linked {
        // A live rendezvous link has nothing to heal — and healing it
        // anyway is what flapped it once per tick (both heal legs dial
        // `GOSSIP_ALPN`, which the beacon's gossip adopts, superseding
        // the healthy link; see `tick_heal`). `NeighborDown` re-arms
        // this gate instantly.
        tracing::debug!(
            target: "habilis_network::gossip",
            "heal tick: rendezvous linked; idle"
        );
    } else if !state.rendezvous_wanted() {
        // Enough links to others: the rendezvous was let go of on purpose, and
        // grafting it now would undo that. A node that falls below the count
        // comes back through the next tick.
        tracing::debug!(
            target: "habilis_network::gossip",
            "heal tick: rendezvous released; idle"
        );
    } else if crate::transport::webrtc::rendezvous_graftable(state) {
        gossip::heal::tick_heal(params.id, ctx.sender).await;
    } else {
        // The JSEP offer fired at the top of this tick; the graft waits for
        // the session it needs to survive the beacon's accept gate.
        tracing::debug!(
            target: "habilis_network::gossip",
            "heal tick: rendezvous graft held until a webrtc session attaches"
        );
    }
    // Rendezvous-independent re-bridge. Fires on the hard (resume) edge —
    // where a reused endpoint id can be stuck behind a stale *accepted*
    // rendezvous connection (iroh-gossip#10), so the rendezvous re-graft
    // alone may not re-admit us — or on steady-state loss of every live
    // link (relay flap). Re-dials remembered peers directly. Skipped when
    // healthy (`hard_edge` false and links remain) and for a lone node
    // (nothing remembered), so it adds no churn. `linked_endpoints` is
    // not cleared on the resume edge, hence the explicit `hard_edge` arm.
    if (hard_edge || state.linked_endpoints.is_empty()) && !state.known_endpoints.is_empty() {
        gossip::heal::rebridge_known(state, ctx).await;
    }
    // Starvation watchdog: links/heal can look busy while no traffic
    // flows (the roster-collapse signature), so the last word every heal
    // tick is a check on verified *inbound* silence.
    if state.starvation_due(
        Instant::now(),
        Duration::from_secs(crate::util::tuning::starvation_threshold_secs()),
    ) {
        gossip::heal::recover_from_starvation(state, ctx).await;
    }
}
/// Outcome of one resubscribe attempt (the heal arm drives one per
/// tick while the gossip stream is down).
pub(super) enum Resubscribe {
    Restored(GossipSender, GossipReceiver),
    Pending,
    Fatal,
}
/// The resubscribe attempt's read-only environment: the gossip frontend to
/// re-subscribe through, the rendezvous params to bootstrap from, the shared
/// ctx-building parts (for its `sink` and to rebuild a [`HandlerCtx`] once the
/// sender is swapped), and the CLI hard-exit flag for the `Fatal` path.
pub(super) struct ResubscribeEnv<'a> {
    pub(super) gossip: &'a iroh_gossip::net::Gossip,
    pub(super) params: &'a beacon::RendezvousParams,
    pub(super) parts: &'a CtxParts<'a>,
    pub(super) exit_on_quit: bool,
}
/// The live gossip link a resubscribe mutates: the sender/receiver pair
/// swapped in on success, and the consecutive-failure counter it resets or
/// increments.
pub(super) struct GossipLink<'a> {
    pub(super) sender: &'a mut MeshSender,
    pub(super) receiver: &'a mut GossipReceiver,
    pub(super) attempts: &'a mut u32,
}
/// One heal-tick turn while the gossip stream is down: attempt the
/// resubscribe and, on success, swap in the fresh sender/receiver,
/// drain the dead subscription's buffer (the actor counts those
/// messages as delivered — overlay dedup will never re-push them, and
/// anti-entropy resends of them are deduped too, so the buffer is the
/// only copy), then re-enter the overlay via the starvation-recovery
/// primitive (degraded mesh, throttles cleared, known peers re-dialed,
/// arrival re-announced). On `Fatal` (the actor itself is gone) the
/// daemon stops posing as a live member: statusline state file cleared
/// (a `Left` broadcast is pointless on a dead topic), `exit(1)` on the
/// CLI path, `Err` for in-process drivers.
pub(super) async fn resubscribe_tick(
    env: &ResubscribeEnv<'_>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    link: GossipLink<'_>,
) -> Result<()> {
    match try_resubscribe(env, state, link.attempts).await {
        Resubscribe::Restored(new_sender, new_receiver) => {
            let mut dead_receiver = std::mem::replace(link.receiver, new_receiver);
            link.sender.replace_gossip(new_sender);
            state.gossip_open = true;
            // The dead subscription's link view is void; the fresh one
            // emits its own NeighborUps (and re-arms the probe gate).
            state.rendezvous_linked = false;
            let ctx = env.parts.ctx(link.sender);
            gossip::drain_dead_receiver(&mut dead_receiver, state, app, &ctx).await;
            drop(dead_receiver);
            gossip::heal::recover_from_starvation(state, &ctx).await;
        }
        Resubscribe::Pending => {}
        Resubscribe::Fatal => {
            #[cfg(feature = "host")]
            if let Some(state_file) = state.state_file.as_ref() {
                state_file.remove();
            }
            env.parts.sink.emit(NodeEvent::Error(
                "gossip subscription unrecoverable; shutting down".to_owned(),
            ));
            #[cfg(not(feature = "dhat-heap"))]
            if env.exit_on_quit {
                std::process::exit(1);
            }
            #[cfg(feature = "dhat-heap")]
            let _ = env.exit_on_quit;
            anyhow::bail!("gossip subscription unrecoverable after repeated resubscribe attempts");
        }
    }
    Ok(())
}
/// Re-open the gossip topic after its stream terminally ended. The
/// designed-for remedy, not a workaround: iroh-gossip closes a lagging
/// subscriber outright and its docs instruct "close and re-open".
/// Bootstrap is the rendezvous plus every remembered peer so the fresh
/// subscription re-grafts without waiting for lookups. `Fatal` after
/// `RESUBSCRIBE_MAX_ATTEMPTS` consecutive failures: a subscribe error
/// means the gossip actor itself is gone (endpoint closed), which no
/// retry can fix.
pub(super) async fn try_resubscribe(
    env: &ResubscribeEnv<'_>,
    state: &EventLoopState,
    attempts: &mut u32,
) -> Resubscribe {
    let mut bootstrap = Vec::new();
    if !state.rendezvous_graft_needs_session && state.rendezvous_wanted() {
        bootstrap.push(env.params.id);
    }
    bootstrap.extend(state.known_endpoints.iter().copied());
    match env.gossip.subscribe(env.params.topic_id, bootstrap).await {
        Ok(topic) => {
            *attempts = 0;
            tracing::warn!(
                target: "habilis_network::gossip",
                "gossip stream restored (resubscribed)"
            );
            env.parts.sink.emit(NodeEvent::Info(
                "gossip stream restored; rejoining the mesh".to_owned(),
            ));
            let (sender, receiver) = topic.split();
            Resubscribe::Restored(sender, receiver)
        }
        Err(error) => {
            *attempts += 1;
            tracing::warn!(
                target: "habilis_network::gossip",
                %error,
                attempts = *attempts,
                "gossip resubscribe failed"
            );
            if *attempts >= RESUBSCRIBE_MAX_ATTEMPTS {
                Resubscribe::Fatal
            } else {
                Resubscribe::Pending
            }
        }
    }
}
/// Apply a bootstrap rung chosen **off the event loop** (the startup
/// confirmation probe or the beacon's liveness self-monitor publishing
/// through `rendezvous_params.rung_tx`). Cheap and non-blocking — the
/// ladder walk already ran in the background task. If the new rung
/// differs from the one we're homed on, re-pre-register `rendezvous_id`
/// at it and drop the beacon so `maybe_cohost` rebuilds it homed on the
/// new rung.
pub(super) fn apply_rung_change(
    state: &mut EventLoopState,
    params: &mut beacon::RendezvousParams,
    endpoint: &Endpoint,
    rendezvous: &mut Option<beacon::Rendezvous>,
    rung_rx: &watch::Receiver<Option<RelayUrl>>,
) {
    let selected = rung_rx.borrow().clone();
    if let lookup::RungRefresh::Rehome(new) =
        lookup::plan_rung_refresh(params.bootstrap_relay.as_ref(), selected)
    {
        tracing::info!(
            target: "habilis_network::beacon",
            old = ?params.bootstrap_relay,
            new = ?new,
            "bootstrap relay rung changed; re-registering rendezvous and re-homing the beacon"
        );
        params.bootstrap_relay = new;
        setup::register_rendezvous(endpoint, params);
        // Release the beacon so `maybe_cohost` → `beacon::ensure` rebuilds it
        // homed on the new rung at the next heal/reclaim tick — `shed`, not a
        // plain drop. The old endpoint is still open and still homed on the
        // rung we are abandoning; dropping it leaves iroh to tear the socket
        // down ungracefully and leaves peers linked to a corpse until the QUIC
        // idle timeout. This fires exactly when relays are flaky, which is
        // when a graceful handover matters most.
        if let Some(old) = rendezvous.take() {
            old.shed();
        }
        // A rehome starts a fresh arbitration epoch, so the re-check backoff
        // starts over with it. Without this the next claim reads the round
        // count the *previous* epoch reached and backs off as though it were
        // still contending, which defeats `next_recheck_delay`'s round-0
        // branch — the deterministic tie-break that exists precisely so two
        // simultaneous claimants shed in a decidable order.
        state.rival_recheck_rounds = 0;
        // The rendezvous now answers at a different rung, so a free reading
        // taken against the old one is not about this identity at all.
        state.forget_rendezvous_verdict();
    }
}

#[cfg(test)]
mod tests {
    use super::{is_resume, is_wall_resume};
    use std::time::Duration;

    #[test]
    fn is_resume_only_past_threshold() {
        let threshold = Duration::from_mins(1);
        // A normal heal cadence (≤ ~15s) is never a resume.
        assert!(!is_resume(Duration::from_secs(0), threshold));
        assert!(!is_resume(Duration::from_secs(15), threshold));
        assert!(!is_resume(Duration::from_secs(59), threshold));
        // Exactly at the threshold is not yet a stall (strictly `>`).
        assert!(!is_resume(Duration::from_mins(1), threshold));
        // A multi-minute gap = the process was frozen → hard re-bootstrap.
        assert!(is_resume(Duration::from_secs(61), threshold));
        assert!(is_resume(Duration::from_hours(1), threshold));
    }

    #[test]
    fn is_resume_respects_injected_threshold() {
        // The subprocess stall regression shortens the threshold via
        // the env knob; the comparison must track whatever is passed.
        let short = Duration::from_secs(4);
        assert!(!is_resume(Duration::from_secs(3), short));
        assert!(is_resume(Duration::from_secs(5), short));
    }

    #[test]
    fn wall_resume_detects_macos_sleep_signature() {
        let threshold = Duration::from_mins(1);
        // macOS sleep: the monotonic clock froze (a few seconds of
        // real post-wake time) while the wall clock jumped a full day.
        // The monotonic gap alone misses it; the divergence catches it.
        let mono_gap = Duration::from_secs(3);
        let wall_gap = Duration::from_hours(24);
        assert!(!is_resume(mono_gap, threshold));
        assert!(is_wall_resume(wall_gap, mono_gap, threshold));
    }

    #[test]
    fn wall_resume_ignores_clocks_advancing_together() {
        let threshold = Duration::from_mins(1);
        // Steady operation: wall and monotonic advance in lockstep, so
        // their divergence is ~0 — never a resume, whatever the cadence.
        assert!(!is_wall_resume(
            Duration::from_secs(15),
            Duration::from_secs(15),
            threshold
        ));
        // A wall clock running slightly behind monotonic (NTP step
        // back) saturates to 0 divergence, not a spurious resume.
        assert!(!is_wall_resume(
            Duration::from_secs(10),
            Duration::from_secs(15),
            threshold
        ));
    }
}
