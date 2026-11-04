//! Heartbeat: the `Alive` keepalive emitter and the silence sweep
//! that evicts peers we've stopped hearing from. Part of the
//! lifecycle subsystem (it drives `peer_timeout` / the roster).

use crate::daemon::state::{PendingSuspend, RendezvousFlag};
use crate::transport::MeshSender;

use crate::daemon::state::EventLoopState;
use crate::gossip::event::{NodeEvent, NodeSink};
use crate::protocol::{AuthorKey, MeshId, Message, Nickname, UnixSecs};
use crate::util::clock::Instant;
use iroh::EndpointId;
use std::collections::HashSet;
use std::time::Duration;

use crate::util::tuning::{ALIVE_INTERVAL, alive_timeout};

/// How long a quiet peer stays in `quiet` and in the roster snapshot. A peer that has not come back
/// after this long is gone: it would only take a slot of the bounded `quiet` set from a peer that
/// can still return.
pub(crate) const QUIET_TTL: Duration = Duration::from_hours(1);

/// Emit an `Alive` keepalive if we haven't broadcast anything
/// recently. Chatty daemons pay zero heartbeat cost.
pub(crate) async fn tick_alive(
    state: &mut EventLoopState,
    sender: &MeshSender,
    mesh: &MeshId,
    author: &Nickname,
) {
    if state.last_sent_at.elapsed() < ALIVE_INTERVAL {
        return;
    }
    let message = Message::new_alive(mesh, author).sign(&state.identity);
    if let Ok(bytes) = message.serialize() {
        let _ = sender.broadcast(bytes).await;
    }
    state.idle.broadcasts += 1;
    state.last_sent_at = Instant::now();
    tracing::trace!("alive keepalive broadcast");
}

/// A sweep that comes later than one alive timeout means that this node did not run: the process
/// was suspended or starved. The silence of every peer is then our own, so each peer gets a full
/// timeout again from now to be heard, instead of leaving the roster all at once and returning
/// all at once. `gap` is the larger of the monotonic and the wall-clock gap between two sweeps.
///
/// Limit: a step forward of the wall clock (NTP, or a clock that was set) by more than one alive
/// timeout looks like a stall. Each peer then gets a full timeout again, so a peer that died in
/// that time stays in the roster up to one alive timeout (90 s) longer. A step back of the wall
/// clock does not trigger it. Only a gap above one alive timeout acts.
///
/// The roster keeps reporting the real last-heard time of a peer, which `clock_evidence.heard`
/// holds: the forgiveness moves the eviction mark only.
pub(crate) fn forgive_stall(state: &mut EventLoopState, gap: Duration) {
    if gap <= alive_timeout() {
        return;
    }
    let now = Instant::now();
    for seen in state.last_seen.values_mut() {
        *seen = now;
    }
    tracing::debug!(
        target: "habilis_network::lifecycle",
        gap_secs = gap.as_secs(),
        "the sweep came late: peers get a full alive timeout from now"
    );
}

/// A sweep that sees the wall clock run on while the monotonic clock did not (a suspend, or a step
/// of the wall clock) notes the stretch. It ages nothing yet: a suspend and a forward step look the
/// same on this host, and a step must not remove a quiet peer early. A live peer vouches for the
/// stretch (see [`confirm_suspend`]); until then, and for one alive timeout, it waits. A gap of one
/// alive timeout or less is clock noise and is not noted.
pub(crate) fn note_suspend(state: &mut EventLoopState, missed: Duration) {
    if missed <= alive_timeout() {
        return;
    }
    let now = Instant::now();
    let pending = match state.clock_evidence.suspend {
        Some(before) if now.duration_since(before.at) <= alive_timeout() => PendingSuspend {
            missed: before.missed.saturating_add(missed),
            at: before.at,
        },
        _ => PendingSuspend { missed, at: now },
    };
    state.clock_evidence.suspend = Some(pending);
}

/// A live frame stamped within one alive timeout of our wall clock shows that our clock agrees with
/// the clock of a peer that sends now. After a suspend the clock is right, so the stretch that
/// [`note_suspend`] holds is real and the quiet peers age by it. After a forward step our clock
/// runs ahead of every peer, so no frame agrees and the stretch lapses one alive timeout after the
/// sweep noted it. The error is bounded by that timeout and by the skew of the clock of the peer,
/// unless the clock of that peer took the same forward step: a peer on this host shares the step
/// and agrees with it, and the quiet peers then age by time that did not pass.
///
/// Limit: with no live peer after a wake, nothing vouches, and a quiet peer stays past one hour of
/// real silence until the monotonic clock has run that hour (at most `QUIET_CAP` stay).
pub(crate) fn confirm_suspend(state: &mut EventLoopState, stamp: UnixSecs) {
    let Some(pending) = state.clock_evidence.suspend else {
        return;
    };
    if Instant::now().duration_since(pending.at) > alive_timeout() {
        state.clock_evidence.suspend = None;
        return;
    }
    let ahead: u64 = UnixSecs::now().as_secs().abs_diff(stamp.as_secs());
    if ahead <= alive_timeout().as_secs() {
        state.clock_evidence.suspend = None;
        age_quiet_peers(state, pending.missed);
    }
}

/// Each quiet peer is older by `missed`, the time that the wall clock counted and the monotonic
/// clock did not, so a long sleep does not hold a quiet peer, or its endpoint binding, past one
/// hour of real silence.
fn age_quiet_peers(state: &mut EventLoopState, missed: Duration) {
    for key in state.quiet_since.keys() {
        let aged = state.clock_evidence.quiet_aged.entry(*key).or_default();
        *aged = aged.saturating_add(missed);
    }
}

/// Sweep `last_seen` for peers we've not heard from past the
/// timeout. Each eviction removes them from `last_seen`/`peers`
/// and rewrites the statusline. A peer whose arrival we
/// *surfaced* is also inserted into `quiet` and emits `peer_timeout`;
/// a ghost known only through pre-join anti-entropy backlog is evicted
/// silently (never surfaced as arriving, so never surfaced as
/// leaving) — keeps the join-horizon view symmetric.
pub(crate) fn tick_sweep(state: &mut EventLoopState, sink: &dyn NodeSink) {
    let now = Instant::now();
    let timeout = alive_timeout();
    let silent = state
        .last_seen
        .iter()
        .filter(|(_, seen)| now.duration_since(**seen) > timeout);
    let expired: Vec<(AuthorKey, Instant)> = silent.map(|(key, seen)| (*key, *seen)).collect();
    for (key, forgiven) in expired {
        state.last_seen.remove(&key);
        // The eviction mark may be a stall forgiveness. The roster and the event report when the
        // peer was really heard.
        let seen = state.clock_evidence.heard.remove(&key).unwrap_or(forgiven);
        let age = now.duration_since(seen).as_secs();
        if state.peers.remove(&key) {
            state.write_peer_count();
            let nick: Option<Nickname> = state.names.get(&key).cloned();
            // Remembered as a quiet peer, but no longer a holder: its flag was last said before it
            // went silent, and a crashed holder never says it again. The claim is the key's own;
            // another key on the same endpoint keeps its claim.
            state.rival_holders.remove(&key);
            if state.surfaced.remove(&key) {
                // A peer we knew went silent: a partition may have split the
                // mesh, and the rendezvous is where its islands meet again. A
                // node that let go of the rendezvous owes it one return. A node
                // that still holds the link owes nothing: it would be owed
                // after the next release, and make the node grab it again.
                if !state.rendezvous_flags.contains(&RendezvousFlag::Linked) {
                    state.owe_rendezvous_return(now);
                }
                state.quiet.insert(key);
                // Retain the last-heard instant so the roster can still
                // report this evictee's recency (its `last_seen` is gone).
                // The endpoint binding is retained too: a quiet peer is the
                // one expected to *return*, and its return (any signed
                // message) re-adds it to the roster without a `PeerInfo`
                // re-broadcast — dropping the binding here would leave a
                // returned peer undeliverable for directed frames until its
                // gossip link happens to bounce.
                state.quiet_since.insert(key, seen);
                if let Some(nickname) = nick {
                    tracing::debug!(nickname = %nickname, age_secs = age, "peer evicted (silence timeout)");
                    sink.emit(NodeEvent::PeerTimeout {
                        nickname,
                        last_seen_secs_ago: age,
                    });
                }
            } else {
                if let Some(nickname) = nick.filter(|nick| state.hint_owner.get(nick) == Some(&key))
                {
                    state.forget_peer_endpoint(nickname.as_str());
                }
                tracing::trace!(
                    key = %key,
                    age_secs = age,
                    "ghost evicted silently (pre-join backlog, never surfaced)"
                );
            }
        }
    }
    // A quiet peer that did not come back within the TTL is gone for good.
    let too_old = state
        .quiet_since
        .keys()
        .filter(|key| state.quiet_silence(key, now) > Some(QUIET_TTL));
    let gone: Vec<AuthorKey> = too_old.copied().collect();
    for key in gone {
        state.quiet.remove(&key);
        state.quiet_since.remove(&key);
        state.clock_evidence.quiet_aged.remove(&key);
        state.clock_evidence.lapsed_quiet.insert(key);
    }
    // Keep `quiet_since` bounded to current `quiet` membership: peers that
    // returned (drained from `quiet`) or fell off the bounded `quiet` FIFO
    // drop their stale recency here.
    let quiet = &state.quiet;
    state.quiet_since.retain(|key, _| quiet.contains(key));
    state
        .clock_evidence
        .quiet_aged
        .retain(|key, _| quiet.contains(key));
    prune_per_key_state(state);
    prune_dial_hints(state);
    #[cfg(feature = "multihop")]
    state.parked_link_states.expire(now);
}

/// The per-key state follows the roster: a key that is neither a peer nor quiet drops it.
fn prune_per_key_state(state: &mut EventLoopState) {
    let (roster, evicted) = (&state.peers, &state.quiet);
    let is_peer = |key: &AuthorKey| roster.contains(key);
    let is_quiet = |key: &AuthorKey| evicted.contains(key);
    state
        .peer_stamp
        .retain(|key, _| is_peer(key) || is_quiet(key));
    state
        .clock_evidence
        .step_back
        .retain(|key, _| is_peer(key) || is_quiet(key));
    state
        .clock_evidence
        .live_run
        .retain(|key, _| is_peer(key) || is_quiet(key));
    state.clock_evidence.heard.retain(|key, _| is_peer(key));
    state
        .clock_evidence
        .returned_unshown
        .retain(|key| is_peer(key));
    let lapsed = &state.clock_evidence.lapsed_quiet;
    state
        .names
        .retain(|key, _| is_peer(key) || is_quiet(key) || lapsed.contains(key));
    state
        .proven_endpoints
        .retain_trusted(|key| is_peer(key) || is_quiet(key) || lapsed.contains(key));
}

/// Prune the dial hints and the state that is keyed by their endpoints.
fn prune_dial_hints(state: &mut EventLoopState) {
    // Same bound for the endpoint dial hints: a hint lives as long as the key that made it is an
    // active peer, a quiet evictee, or one of the last `QUIET_CAP` that outlived the quiet TTL, so
    // the map is capped at |peers| + 2 * QUIET_CAP even under nickname churn.
    // (Safe against a just-arrived `PeerInfo`: `lifecycle::observe` runs
    // before `handle_peer_info`, so a recorded endpoint's author is already a
    // peer.)
    let (peers, quiet, lapsed) = (
        &state.peers,
        &state.quiet,
        &state.clock_evidence.lapsed_quiet,
    );
    let (owners, names) = (&state.hint_owner, &state.names);
    let in_roster =
        |key: &AuthorKey| peers.contains(key) || quiet.contains(key) || lapsed.contains(key);
    // A hint made from a card has no owner: it stays while a key of the roster uses the nickname.
    // A hint with an owner stays while that key is in the roster and still uses the nickname: a key
    // that renames leaves the hint of its old nickname behind, and it goes.
    let uses = |key: &AuthorKey, nick: &Nickname| names.get(key) == Some(nick);
    let is_kept = |nick: &Nickname| match owners.get(nick) {
        Some(key) => in_roster(key) && uses(key, nick),
        None => names
            .iter()
            .any(|(key, name)| name == nick && in_roster(key)),
    };
    let unkept = state
        .peer_endpoints
        .iter()
        .filter(|(nick, _)| !is_kept(nick));
    let dropped: Vec<(Nickname, EndpointId)> = unkept
        .map(|(nick, address)| (nick.clone(), address.id))
        .collect();
    let mut pruned: Vec<EndpointId> = Vec::with_capacity(dropped.len());
    for (nick, endpoint) in dropped {
        state.peer_endpoints.remove(&nick);
        state.hint_owner.remove(&nick);
        pruned.push(endpoint);
    }
    // The state of a pruned endpoint goes with it, or the maps that it keys grow with each
    // endpoint that ever bound a nickname. An endpoint that a kept nickname still binds, or that
    // has a live link, keeps its state.
    let kept_ids: HashSet<EndpointId> = state
        .peer_endpoints
        .values()
        .map(|address| address.id)
        .collect();
    forget_pruned_endpoints(state, pruned, &kept_ids);
    drop_orphaned_endpoint_state(state, &kept_ids);
}

/// Drop the state of each pruned endpoint that no kept nickname binds. A linked endpoint keeps its
/// proof, direct path and backoff for the regraft after the link loss, and a later sweep drops them.
fn forget_pruned_endpoints(
    state: &mut EventLoopState,
    pruned: Vec<EndpointId>,
    kept_ids: &HashSet<EndpointId>,
) {
    for endpoint in pruned {
        if kept_ids.contains(&endpoint) {
            continue;
        }
        state.release_unbound_endpoint(endpoint);
    }
}

/// Drop the state of each orphaned endpoint whose link has ended. An endpoint that a nickname
/// binds again keeps its state, and so does one that is still linked.
fn drop_orphaned_endpoint_state(state: &mut EventLoopState, kept_ids: &HashSet<EndpointId>) {
    let orphans: Vec<EndpointId> = state.orphaned_endpoints.iter().copied().collect();
    for endpoint in orphans {
        if state.linked_endpoints.contains(&endpoint) {
            continue;
        }
        state.orphaned_endpoints.remove(&endpoint);
        if !kept_ids.contains(&endpoint) {
            state.forget_endpoint_state(endpoint);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::daemon::state::{
        DirectState, EventLoopState, LiveRun, PendingSuspend, RendezvousFlag,
    };
    use crate::testing::{fresh_state, nick, test_key};
    use crate::transport::probe::PathKind;
    use std::collections::HashSet;

    use super::{
        AuthorKey, Instant, QUIET_TTL, confirm_suspend, forgive_stall, note_suspend, tick_sweep,
    };
    use crate::gossip::event::SilentSink;
    use crate::util::tuning;
    use std::time::Duration;

    use crate::{protocol, testing};
    #[test]
    fn a_late_sweep_gives_every_peer_a_new_timeout() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let silent_for = tuning::alive_timeout() + Duration::from_secs(30);
        for name in ["swift-cedar", "lost-heron"] {
            let seen = Instant::now()
                .checked_sub(silent_for)
                .expect("the monotonic clock has run past the alive timeout since boot");
            state.last_seen.insert(test_key(name), seen);
            state.peer_for_test(name);
            state.surfaced_for_test(name);
        }

        // The loop did not run for 4.5 min (one alive timeout and one starvation threshold).
        let stall = tuning::alive_timeout() + tuning::starvation_threshold();
        forgive_stall(&mut state, stall);
        tick_sweep(&mut state, &SilentSink);
        assert_eq!(
            state.peers.len(),
            2,
            "a stalled loop evicted peers that it could not have heard"
        );

        // A sweep that came on time changes nothing: the silent peers go.
        let mut punctual = fresh_state();
        let seen = Instant::now()
            .checked_sub(silent_for)
            .expect("the monotonic clock has run past the alive timeout since boot");
        punctual.last_seen.insert(test_key("swift-cedar"), seen);
        punctual.peer_for_test("swift-cedar");
        punctual.surfaced_for_test("swift-cedar");
        forgive_stall(&mut punctual, tuning::sweep_interval());
        tick_sweep(&mut punctual, &SilentSink);
        assert!(
            punctual.peers.is_empty() && punctual.quiet.contains(&test_key("swift-cedar")),
            "an on-time sweep still evicts a peer that is silent past the timeout"
        );
    }

    #[test]
    fn a_peer_that_died_during_a_stall_is_evicted_one_timeout_later() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let timeout = tuning::alive_timeout();
        let long_ago = Instant::now()
            .checked_sub(timeout * 3)
            .expect("the monotonic clock has run past three alive timeouts since boot");
        for name in ["swift-cedar", "lost-heron"] {
            state.last_seen.insert(test_key(name), long_ago);
            state.peer_for_test(name);
            state.surfaced_for_test(name);
        }

        forgive_stall(&mut state, timeout * 2);
        tick_sweep(&mut state, &SilentSink);
        assert_eq!(state.peers.len(), 2, "the stall is forgiven");

        // One timeout later: swift-cedar spoke 5 s ago, lost-heron died during the stall.
        let spoke = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .expect("the monotonic clock has run past 5 s since boot");
        let silent = Instant::now()
            .checked_sub(timeout + Duration::from_secs(1))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("swift-cedar"), spoke);
        state.last_seen.insert(test_key("lost-heron"), silent);
        tick_sweep(&mut state, &SilentSink);
        assert!(
            state.peers.contains(&test_key("swift-cedar"))
                && !state.peers.contains(&test_key("lost-heron")),
            "the peer that died in the stall goes one timeout later: {:?}",
            state.peers
        );
        assert!(
            state.quiet.contains(&test_key("lost-heron")),
            "and it is quiet"
        );
    }

    #[test]
    fn a_peer_that_died_before_two_stalls_in_a_row_is_evicted_one_timeout_after_the_last() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let timeout = tuning::alive_timeout();
        let ago = |span: Duration| {
            Instant::now()
                .checked_sub(span)
                .expect("the monotonic clock has run past the span since boot")
        };
        for name in ["swift-cedar", "lost-heron"] {
            state.last_seen.insert(test_key(name), ago(timeout * 3));
            state.peer_for_test(name);
            state.surfaced_for_test(name);
        }

        // First stall: both peers are forgiven.
        forgive_stall(&mut state, timeout * 2);
        tick_sweep(&mut state, &SilentSink);
        assert_eq!(state.peers.len(), 2, "the first stall is forgiven");

        // The loop runs for 100 s, then stalls again. Only swift-cedar spoke in between.
        state
            .last_seen
            .insert(test_key("swift-cedar"), ago(Duration::from_secs(5)));
        state
            .last_seen
            .insert(test_key("lost-heron"), ago(Duration::from_secs(100)));
        forgive_stall(&mut state, timeout * 2);
        tick_sweep(&mut state, &SilentSink);
        assert_eq!(
            state.peers.len(),
            2,
            "the second stall is forgiven, as the first one was"
        );

        // One timeout after the last stall the dead peer goes and the live one stays.
        state
            .last_seen
            .insert(test_key("swift-cedar"), ago(Duration::from_secs(5)));
        state.last_seen.insert(
            test_key("lost-heron"),
            ago(timeout + Duration::from_secs(1)),
        );
        tick_sweep(&mut state, &SilentSink);
        assert!(
            state.peers.contains(&test_key("swift-cedar"))
                && !state.peers.contains(&test_key("lost-heron")),
            "the dead peer goes one timeout after the last stall: {:?}",
            state.peers
        );
        assert!(
            state.quiet.contains(&test_key("lost-heron")),
            "and it is quiet"
        );
    }

    #[test]
    fn the_names_follow_the_roster() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.peer_for_test("swift-cedar");
        state.quiet_for_test("lost-heron");
        state.name_key("calm-otter");

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.names.contains_key(&test_key("swift-cedar"))
                && state.names.contains_key(&test_key("lost-heron")),
            "a peer and a quiet peer keep their name"
        );
        assert!(
            !state.names.contains_key(&test_key("calm-otter")),
            "a key that is neither a peer nor quiet drops its name"
        );
    }

    /// `peer_stamp`, the step-back runs and the pre-join records follow the roster like the holder
    /// keys: a nickname that is neither a peer nor quiet loses them, or they grow with every
    /// nickname that ever spoke.
    #[test]
    fn the_stamp_records_follow_the_roster() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.peer_for_test("swift-cedar");
        state.quiet_for_test("lost-heron");
        for name in ["swift-cedar", "lost-heron", "calm-otter"] {
            state
                .peer_stamp
                .insert(test_key(name), protocol::UnixSecs::now());
            state.clock_evidence.step_back.insert(
                test_key(name),
                LiveRun {
                    last: protocol::UnixSecs::now(),
                    at: Instant::now(),
                    count: 1,
                },
            );
        }

        tick_sweep(&mut state, &SilentSink);

        for kept in ["swift-cedar", "lost-heron"] {
            assert!(
                state.peer_stamp.contains_key(&test_key(kept))
                    && state.clock_evidence.step_back.contains_key(&test_key(kept)),
                "{kept} is a peer or a quiet peer and keeps its stamp records"
            );
        }
        assert!(
            !state.peer_stamp.contains_key(&test_key("calm-otter")),
            "a nickname that is neither a peer nor quiet drops its newest stamp"
        );
        assert!(
            !state
                .clock_evidence
                .step_back
                .contains_key(&test_key("calm-otter")),
            "a nickname that is neither a peer nor quiet drops its step-back run"
        );
    }

    #[test]
    fn a_quiet_peer_expires_after_the_quiet_ttl() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let long_gone = Instant::now()
            .checked_sub(QUIET_TTL + Duration::from_secs(60))
            .expect("the monotonic clock has run past the quiet TTL since boot");
        let recent = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .expect("the monotonic clock has run past 60 s since boot");
        for (name, heard) in [("swift-cedar", long_gone), ("lost-heron", recent)] {
            state.quiet_for_test(name);
            state.quiet_since.insert(test_key(name), heard);
        }

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.quiet.contains(&test_key("swift-cedar"))
                && !state.quiet_since.contains_key(&test_key("swift-cedar")),
            "a peer quiet for more than the TTL leaves the quiet set"
        );
        assert!(
            state.quiet.contains(&test_key("lost-heron")),
            "a peer quiet for a minute stays"
        );
    }

    /// A peer that is silent for more than the quiet TTL and then sends again comes back as an
    /// arrival, and no `PeerInfo` of its own may follow: its links did not change. Its dial hint
    /// must be there when it returns, or a directed frame to it fails until a `PeerInfo` comes.
    #[test]
    fn a_peer_that_returns_after_the_quiet_ttl_keeps_its_dial_hint() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let long_gone = Instant::now()
            .checked_sub(QUIET_TTL + Duration::from_secs(60))
            .expect("the monotonic clock has run past the quiet TTL since boot");
        let endpoint = iroh::SecretKey::from_bytes(&[9; 32]).public();
        state.quiet_for_test("swift-cedar");
        state.quiet_since.insert(test_key("swift-cedar"), long_gone);
        state.bind_peer_endpoint(
            test_key("swift-cedar"),
            nick("swift-cedar"),
            iroh::EndpointAddr::new(endpoint),
        );

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.quiet.contains(&test_key("swift-cedar")),
            "the peer left the quiet set"
        );
        assert_eq!(
            state.peer_endpoints.get("swift-cedar"),
            Some(&iroh::EndpointAddr::new(endpoint)),
            "the quiet TTL dropped the dial hint of a peer that can still come back"
        );
    }

    /// Two suspends noted inside one confirmation window keep the time of the first one: the
    /// window is one alive timeout from the first gap, so a second gap cannot extend it.
    #[test]
    fn a_second_suspend_does_not_extend_the_confirmation_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let first_gap_at = Instant::now()
            .checked_sub(Duration::from_secs(80))
            .expect("the monotonic clock has run past 80 s since boot");
        state.clock_evidence.suspend = Some(PendingSuspend {
            missed: Duration::from_hours(1),
            at: first_gap_at,
        });

        note_suspend(&mut state, Duration::from_hours(1));

        let pending = state
            .clock_evidence
            .suspend
            .expect("the second gap is noted");
        assert_eq!(pending.missed, Duration::from_hours(2), "both gaps add up");
        assert_eq!(
            pending.at, first_gap_at,
            "the second gap moved the start of the window"
        );
    }

    /// A suspend longer than the monotonic clock has run (a browser clock counts from the page
    /// load) cannot be taken off an `Instant`: `checked_sub` gives `None`. The quiet peer must
    /// still be older by the whole suspend, so the aged silence is kept as a span.
    #[test]
    fn a_suspend_longer_than_the_clock_origin_still_ages_a_quiet_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.quiet_for_test("lost-heron");
        state
            .quiet_since
            .insert(test_key("lost-heron"), Instant::now());
        let longer_than_any_clock = Duration::MAX;

        note_suspend(&mut state, longer_than_any_clock);
        confirm_suspend(&mut state, protocol::UnixSecs::now());
        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.quiet.contains(&test_key("lost-heron")),
            "a quiet peer survived a suspend that the clock cannot subtract"
        );
    }

    /// The path state of an endpoint goes with its dial hint: a pruned binding that leaves a
    /// `WebRtc` path kind behind keeps the alive tick dialing a peer that is gone.
    #[test]
    fn pruning_a_dial_hint_drops_the_path_state_of_its_endpoint() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        state.bind_peer_endpoint(
            test_key("gone-fern"),
            nick("gone-fern"),
            iroh::EndpointAddr::new(endpoint),
        );
        state.path_kinds.insert(endpoint, PathKind::WebRtc);
        state.path_watchers.insert(endpoint, None);

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.path_kinds.contains_key(&endpoint)
                && !state.path_watchers.contains_key(&endpoint),
            "the path state of a pruned endpoint stays"
        );
    }

    /// A pruned binding takes every state that is keyed by its endpoint, or the maps grow with each
    /// distinct endpoint that ever bound a nickname.
    #[test]
    fn pruning_a_dial_hint_drops_the_direct_and_backoff_state_of_its_endpoint() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        state.bind_peer_endpoint(
            test_key("gone-fern"),
            nick("gone-fern"),
            iroh::EndpointAddr::new(endpoint),
        );
        state.direct.insert(endpoint, DirectState::Direct);
        let asked = Instant::now();
        state.graft_backoff.asked(endpoint, asked);
        let settled = asked + Duration::from_secs(600);
        state.graft_backoff.settle(settled, |_| false, 0.0);
        assert!(
            state.graft_backoff.is_blocked(&endpoint, settled),
            "the refusal is on record"
        );

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.direct.contains_key(&endpoint),
            "the direct state of a pruned endpoint stays"
        );
        assert!(
            !state.graft_backoff.is_blocked(&endpoint, settled),
            "the backoff of a pruned endpoint stays"
        );
    }

    /// A nickname that moves to a new endpoint leaves the old one with no name. The sweep only sees
    /// the endpoints that it removes from the dial hints, so the move must drop the state of the old
    /// endpoint itself.
    #[test]
    fn a_hint_that_moves_to_a_new_endpoint_drops_the_state_of_the_old_one() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let old = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let new = iroh::SecretKey::from_bytes(&[9; 32]).public();
        state.bind_peer_endpoint(
            test_key("moved-fern"),
            nick("moved-fern"),
            iroh::EndpointAddr::new(old),
        );
        state.direct.insert(old, DirectState::Direct);
        state.path_kinds.insert(old, PathKind::WebRtc);
        state.path_watchers.insert(old, None);
        let asked = Instant::now();
        state.graft_backoff.asked(old, asked);
        let settled = asked + Duration::from_secs(600);
        state.graft_backoff.settle(settled, |_| false, 0.0);

        state.bind_peer_endpoint(
            test_key("moved-fern"),
            nick("moved-fern"),
            iroh::EndpointAddr::new(new),
        );

        assert!(
            !state.direct.contains_key(&old)
                && !state.path_kinds.contains_key(&old)
                && !state.path_watchers.contains_key(&old)
                && !state.graft_backoff.is_blocked(&old, settled),
            "the state of the endpoint that the nickname left stays"
        );
    }

    /// The move keeps the state of an old endpoint that another nickname still binds, and the
    /// proof, direct path and backoff of one that a gossip link still holds.
    #[test]
    fn a_hint_that_moves_away_keeps_an_endpoint_that_is_still_in_use() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let shared = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let linked = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let new = iroh::SecretKey::from_bytes(&[9; 32]).public();
        for (who, endpoint) in [("mover-fern", shared), ("stayer-fern", shared)] {
            state.bind_peer_endpoint(test_key(who), nick(who), iroh::EndpointAddr::new(endpoint));
        }
        state.bind_peer_endpoint(
            test_key("linked-fern"),
            nick("linked-fern"),
            iroh::EndpointAddr::new(linked),
        );
        state.linked_endpoints.insert(linked);
        for endpoint in [shared, linked] {
            state.direct.insert(endpoint, DirectState::Direct);
        }
        state.path_kinds.insert(linked, PathKind::WebRtc);

        for who in ["mover-fern", "linked-fern"] {
            state.bind_peer_endpoint(test_key(who), nick(who), iroh::EndpointAddr::new(new));
        }

        assert!(
            state.direct.contains_key(&shared) && state.direct.contains_key(&linked),
            "an endpoint in use lost its direct state"
        );
        assert!(
            !state.path_kinds.contains_key(&linked),
            "a linked endpoint that no name binds keeps its path kind"
        );
    }

    /// Two nicknames can bind one endpoint (a node that restarted under a new name). The pruning
    /// of the old name must leave the state of the endpoint to the name that is kept.
    #[test]
    fn pruning_a_dial_hint_keeps_the_state_of_an_endpoint_that_a_kept_nickname_binds() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        state.bind_peer_endpoint(
            test_key("gone-fern"),
            nick("gone-fern"),
            iroh::EndpointAddr::new(endpoint),
        );
        state.bind_peer_endpoint(
            test_key("kept-fern"),
            nick("kept-fern"),
            iroh::EndpointAddr::new(endpoint),
        );
        state.peer_for_test("kept-fern");
        state
            .last_seen
            .insert(test_key("kept-fern"), Instant::now());
        state.path_kinds.insert(endpoint, PathKind::WebRtc);
        state.path_watchers.insert(endpoint, None);
        state.direct.insert(endpoint, DirectState::Direct);

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.peer_endpoints.contains_key("kept-fern")
                && !state.peer_endpoints.contains_key("gone-fern"),
            "only the old name is pruned"
        );
        assert!(
            state.path_kinds.contains_key(&endpoint)
                && state.path_watchers.contains_key(&endpoint)
                && state.direct.contains_key(&endpoint),
            "the state of an endpoint that a kept nickname binds went with the pruned one"
        );
    }

    /// A live key that renames leaves its old nickname behind. The hint under the old nickname
    /// belongs to a nickname that the key no longer uses, and without this the map grows with each
    /// nickname that a key has used.
    #[test]
    fn pruning_a_dial_hint_drops_the_old_nickname_of_a_key_that_renamed() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let key = test_key("renamer");
        let first = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let second = iroh::SecretKey::from_bytes(&[9; 32]).public();
        state.peers.insert(key);
        state.last_seen.insert(key, Instant::now());
        state.names.insert(key, nick("old-name"));
        state.bind_peer_endpoint(key, nick("old-name"), iroh::EndpointAddr::new(first));
        state.names.insert(key, nick("new-name"));
        state.bind_peer_endpoint(key, nick("new-name"), iroh::EndpointAddr::new(second));

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.peer_endpoints.contains_key("new-name"),
            "the hint under the current nickname of the key went"
        );
        assert!(
            !state.peer_endpoints.contains_key("old-name"),
            "the hint under a nickname that the key left stayed"
        );
    }

    /// A live link keeps its proof, its direct path and its backoff whatever the roster says about
    /// the nickname that bound it. The path watch goes: it would nudge a link that no hint names.
    #[test]
    fn pruning_a_dial_hint_drops_the_path_watch_of_a_linked_endpoint_and_keeps_the_rest() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        state.bind_peer_endpoint(
            test_key("gone-fern"),
            nick("gone-fern"),
            iroh::EndpointAddr::new(endpoint),
        );
        state.linked_endpoints.insert(endpoint);
        state.path_kinds.insert(endpoint, PathKind::WebRtc);
        state.path_watchers.insert(endpoint, None);
        state.direct.insert(endpoint, DirectState::Direct);

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.direct.contains_key(&endpoint),
            "the direct path of a linked endpoint went with the pruned dial hint"
        );
        assert!(
            !state.path_kinds.contains_key(&endpoint)
                && !state.path_watchers.contains_key(&endpoint),
            "the path watch of a pruned linked endpoint stays and nudges it on each tick"
        );
    }

    /// The link ends after the hint is pruned: no nickname names the endpoint, so a later sweep
    /// must still drop its state. `unlink` keeps the state on purpose (the regraft reads it).
    #[test]
    fn a_later_sweep_drops_the_state_of_a_pruned_endpoint_whose_link_ended() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        state.bind_peer_endpoint(
            test_key("gone-fern"),
            nick("gone-fern"),
            iroh::EndpointAddr::new(endpoint),
        );
        state.linked_endpoints.insert(endpoint);
        state.direct.insert(endpoint, DirectState::Direct);
        tick_sweep(&mut state, &SilentSink);
        state.unlink(endpoint);
        assert!(
            state.direct.contains_key(&endpoint),
            "the sweep that ran before the unlink dropped the direct state of a linked endpoint"
        );

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.direct.contains_key(&endpoint),
            "the state of an endpoint with no link and no nickname stays after a later sweep"
        );
    }

    /// The dial address in the unicast pool goes with the dial hint of a pruned endpoint, or the
    /// pool grows with each endpoint that ever lapsed without a goodbye. A linked endpoint keeps
    /// it until the link ends and a later sweep runs.
    #[test]
    fn pruning_a_dial_hint_drops_the_pool_address_of_its_endpoint() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let unlinked = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let linked = iroh::SecretKey::from_bytes(&[9; 32]).public();
        for (name, endpoint) in [("gone-fern", unlinked), ("gone-moss", linked)] {
            let address = iroh::EndpointAddr::new(endpoint);
            state.unicast_pool.note_addr(&address);
            state.bind_peer_endpoint(test_key(name), nick(name), address);
        }
        state.linked_endpoints.insert(linked);

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.unicast_pool.has_addr(unlinked),
            "the pool kept the address of a pruned endpoint"
        );
        assert!(
            state.unicast_pool.has_addr(linked),
            "the pool lost the address of a pruned endpoint that still has a link"
        );
        state.unlink(linked);

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.unicast_pool.has_addr(linked),
            "the pool kept the address after the link ended and a later sweep ran"
        );
    }

    /// A nickname that binds the endpoint again after the prune keeps the state when the link ends.
    #[test]
    fn a_later_sweep_keeps_the_state_of_an_endpoint_that_a_nickname_binds_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        state.bind_peer_endpoint(
            test_key("gone-fern"),
            nick("gone-fern"),
            iroh::EndpointAddr::new(endpoint),
        );
        state.linked_endpoints.insert(endpoint);
        state.direct.insert(endpoint, DirectState::Direct);
        tick_sweep(&mut state, &SilentSink);
        state.unlink(endpoint);
        state.bind_peer_endpoint(
            test_key("back-fern"),
            nick("back-fern"),
            iroh::EndpointAddr::new(endpoint),
        );
        state.peer_for_test("back-fern");
        state
            .last_seen
            .insert(test_key("back-fern"), Instant::now());

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.direct.contains_key(&endpoint),
            "the state of an endpoint that a kept nickname binds went with the old link"
        );
    }

    /// The dial hints that outlive the quiet TTL are bounded by `QUIET_CAP`: a stream of one-shot
    /// nicknames cannot grow the map.
    #[test]
    fn the_dial_hints_that_outlive_the_quiet_ttl_stay_bounded() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let long_gone = Instant::now()
            .checked_sub(QUIET_TTL + Duration::from_secs(60))
            .expect("the monotonic clock has run past the quiet TTL since boot");
        let endpoint = iroh::SecretKey::from_bytes(&[9; 32]).public();
        for index in 0..(tuning::QUIET_CAP + 50) {
            let name = format!("peer-{index}");
            state.quiet_for_test(&name);
            state.quiet_since.insert(test_key(&name), long_gone);
            state.bind_peer_endpoint(
                test_key(&name),
                nick(&name),
                iroh::EndpointAddr::new(endpoint),
            );
        }

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.peer_endpoints.len() <= tuning::QUIET_CAP,
            "the dial hints passed the cap: {}",
            state.peer_endpoints.len()
        );
    }

    #[test]
    fn sweep_evicts_surfaced_peer_into_quiet() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("swift-cedar"), expired_at);
        state.peer_for_test("swift-cedar");
        // Arrival was surfaced => departure must be too.
        state.surfaced_for_test("swift-cedar");

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.last_seen.contains_key(&test_key("swift-cedar")),
            "a swept surfaced peer leaves the last-seen map"
        );
        assert!(
            !state.peers.contains(&test_key("swift-cedar")),
            "a swept surfaced peer leaves the roster"
        );
        assert!(
            state.quiet.contains(&test_key("swift-cedar")),
            "a swept surfaced peer goes quiet"
        );
        assert!(
            !state.surfaced.contains(&test_key("swift-cedar")),
            "a swept surfaced peer is no longer surfaced"
        );
    }

    /// A node that let go of the rendezvous, whose silent neighbour is swept,
    /// owes it one return: the silence may be a partition, and the rendezvous
    /// is where the islands meet.
    #[test]
    fn sweeping_a_silent_known_peer_owes_a_return_to_the_rendezvous() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(testing::endpoint_id(1));
        assert!(!state.rendezvous_wanted(), "enough links: it let go");
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("lost-heron"), expired_at);
        state.peer_for_test("lost-heron");
        state.surfaced_for_test("lost-heron");

        tick_sweep(&mut state, &SilentSink);

        assert!(state.rendezvous_wanted(), "one return is owed");
    }

    /// A node that still holds the rendezvous owes no return: it would be owed
    /// after the next release, and make the node grab the link again.
    #[test]
    fn a_node_still_linked_to_the_rendezvous_owes_no_return() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(testing::endpoint_id(1));
        state.rendezvous_flags.insert(RendezvousFlag::Linked);
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("lost-heron"), expired_at);
        state.peer_for_test("lost-heron");
        state.surfaced_for_test("lost-heron");

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.rendezvous_comeback_until.is_none(),
            "a node still linked to the rendezvous owes no return"
        );
    }

    /// A claim is made by a key. When one key goes silent, only its claim is void: another live
    /// key that holds the same endpoint keeps its own.
    #[test]
    fn the_sweep_drops_only_the_flag_of_the_key_that_expired() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let holder = testing::endpoint_id(7);
        state.bind_peer_endpoint(
            test_key("lost-heron"),
            nick("lost-heron"),
            iroh::EndpointAddr::new(holder),
        );
        state.rival_holders.insert(test_key("lost-heron"), holder);
        state.rival_holders.insert(test_key("live-heron"), holder);
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("lost-heron"), expired_at);
        state.peer_for_test("lost-heron");
        state.surfaced_for_test("lost-heron");
        state.peer_for_test("live-heron");

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.rival_holders.contains_key(&test_key("lost-heron")),
            "the claim of the expired key stays"
        );
        assert!(
            state.rival_holders.contains_key(&test_key("live-heron")),
            "the sweep dropped the claim of a live key"
        );
    }

    /// A holder that crashed or was killed never sends a `PeerInfo` without the flag. The sweep
    /// keeps its binding (a quiet peer returns), and must drop its claim to hold the rendezvous:
    /// a flag that stays known shuts every debt to a new holder for as long as it lives.
    #[test]
    fn the_flag_of_an_evicted_holder_is_forgotten() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let holder = testing::endpoint_id(7);
        state.bind_peer_endpoint(
            test_key("lost-heron"),
            nick("lost-heron"),
            iroh::EndpointAddr::new(holder),
        );
        state.rival_holders.insert(test_key("lost-heron"), holder);
        assert!(
            state.rival_holder_known(),
            "the evicted holder's flag is known before the sweep"
        );
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("lost-heron"), expired_at);
        state.peer_for_test("lost-heron");
        state.surfaced_for_test("lost-heron");

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.quiet.contains(&test_key("lost-heron")),
            "it is remembered as quiet"
        );
        assert!(
            state.peer_endpoints.contains_key("lost-heron"),
            "its binding stays, a quiet peer returns"
        );
        assert!(!state.rival_holder_known(), "its claim to hold is void");
    }

    #[test]
    fn sweeping_a_ghost_owes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(testing::endpoint_id(1));
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("ghost-oak"), expired_at);
        state.peer_for_test("ghost-oak");

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.rendezvous_wanted(),
            "a ghost of the pre-join backlog says nothing about a partition"
        );
    }

    /// Mark `who` as last heard `ago` ago, for the eviction mark and for the recency of the roster.
    fn heard_ago(state: &mut EventLoopState, who: &str, ago: Duration) {
        let seen = Instant::now()
            .checked_sub(ago)
            .expect("the monotonic clock has run past the span since boot");
        state.last_seen.insert(test_key(who), seen);
        state.clock_evidence.heard.insert(test_key(who), seen);
    }

    /// A late sweep forgives the silence that it caused, and the roster still reports how long ago
    /// the peer was really heard: the forgiveness moves the deadline, not the fact.
    #[test]
    fn a_late_sweep_keeps_the_real_recency_of_a_silent_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.peer_for_test("swift-cedar");
        state.surfaced_for_test("swift-cedar");
        heard_ago(&mut state, "swift-cedar", Duration::from_secs(100));

        forgive_stall(&mut state, tuning::alive_timeout() * 2);
        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.peers.contains(&test_key("swift-cedar")),
            "the forgiven peer was evicted"
        );
        let roster = state.roster_snapshot();
        let found = roster
            .peers
            .iter()
            .find(|entry| entry.nickname.as_str() == "swift-cedar");
        let secs: u64 = found
            .and_then(|entry| entry.last_seen_secs_ago)
            .expect("the peer is in the roster with a recency");
        assert!(
            secs >= 100,
            "the roster says the peer was heard {secs} s ago, but it was heard 100 s ago"
        );
    }

    #[test]
    fn quiet_peer_reports_real_recency_in_roster() {
        // Regression: a quiet peer must still report how long ago it was
        // last heard (not `null`), even though eviction drops `last_seen`.
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("calm-otter"), expired_at);
        state.peer_for_test("calm-otter");
        state.surfaced_for_test("calm-otter");

        tick_sweep(&mut state, &SilentSink);

        let roster = state.roster_snapshot();
        let found = roster
            .peers
            .iter()
            .find(|entry| entry.nickname.as_str() == "calm-otter");
        let entry = found.expect("quiet peer present in roster");
        assert!(entry.quiet, "evicted peer is marked quiet");
        let secs = entry
            .last_seen_secs_ago
            .expect("quiet peer reports real recency, not null");
        assert!(
            secs >= tuning::alive_timeout().as_secs(),
            "recency reflects the actual silence age, got {secs}s"
        );
    }

    #[test]
    fn sweep_keeps_a_quiet_peers_endpoint_for_its_return() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("swift-cedar"), expired_at);
        state.peer_for_test("swift-cedar");
        state.surfaced_for_test("swift-cedar");
        let endpoint = iroh::SecretKey::from_bytes(&[7; 32]).public();
        state.bind_peer_endpoint(
            test_key("swift-cedar"),
            nick("swift-cedar"),
            iroh::EndpointAddr::new(endpoint),
        );

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.quiet.contains(&test_key("swift-cedar")),
            "a sweep keeps a quiet peer's name in quiet for its return"
        );
        assert_eq!(
            state.peer_endpoints.get("swift-cedar"),
            Some(&iroh::EndpointAddr::new(endpoint)),
            "a returnable quiet peer keeps its dial hint — its return never re-broadcasts PeerInfo"
        );
    }

    #[test]
    fn sweep_prunes_endpoints_of_nicks_neither_active_nor_quiet() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        // Not in `peers`, not in `quiet`: fell off the quiet FIFO or
        // departed via `left` churn — the dial hint must not outlive it.
        state.bind_peer_endpoint(
            test_key("gone-fern"),
            nick("gone-fern"),
            iroh::EndpointAddr::new(endpoint),
        );

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.peer_endpoints.contains_key("gone-fern"),
            "a sweep prunes endpoints of names that are neither active nor quiet"
        );
    }

    #[test]
    fn sweep_evicts_unsurfaced_peer_silently() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("ghost-elm"), expired_at);
        state.peer_for_test("ghost-elm");
        // Never in `surfaced`: known only via pre-join backlog.

        tick_sweep(&mut state, &SilentSink);

        // Still evicted from the roster (hygiene preserved)...
        assert!(
            !state.last_seen.contains_key(&test_key("ghost-elm")),
            "a sweep evicts an unsurfaced peer from last-seen"
        );
        assert!(
            !state.peers.contains(&test_key("ghost-elm")),
            "a sweep evicts an unsurfaced peer from the roster"
        );
        // ...but never parked in `quiet` => no `went quiet` emitted.
        assert!(
            !state.quiet.contains(&test_key("ghost-elm")),
            "a sweep never puts an unsurfaced peer in quiet"
        );
    }

    #[test]
    fn sweep_keeps_recent_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state
            .last_seen
            .insert(test_key("swift-cedar"), Instant::now());
        state.peer_for_test("swift-cedar");

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.last_seen.contains_key(&test_key("swift-cedar")),
            "a recent peer stays in last-seen"
        );
        assert!(
            state.peers.contains(&test_key("swift-cedar")),
            "a recent peer stays in the roster"
        );
        assert!(
            !state.quiet.contains(&test_key("swift-cedar")),
            "a recent peer is not quiet"
        );
    }

    #[test]
    fn sweep_noop_on_empty_last_seen() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        tick_sweep(&mut state, &SilentSink);
        assert!(
            state.peers.is_empty(),
            "a sweep on empty last-seen keeps the roster empty"
        );
        assert!(
            state.quiet.is_empty(),
            "a sweep on empty last-seen keeps quiet empty"
        );
    }

    #[test]
    fn sweep_preserves_other_peers() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(test_key("stale-nick"), expired_at);
        state.peer_for_test("stale-nick");
        state
            .last_seen
            .insert(test_key("fresh-nick"), Instant::now());
        state.peer_for_test("fresh-nick");

        tick_sweep(&mut state, &SilentSink);

        let expected_peers: HashSet<AuthorKey> = [test_key("fresh-nick")].into_iter().collect();
        assert_eq!(
            state.peers, expected_peers,
            "a sweep preserves the other peers"
        );
    }
}
