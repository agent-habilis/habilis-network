//! Heartbeat: the `Alive` keepalive emitter and the silence sweep
//! that evicts peers we've stopped hearing from. Part of the
//! lifecycle subsystem (it drives `peer_timeout` / the roster).

use crate::transport::MeshSender;

use crate::daemon::state::EventLoopState;
use crate::gossip::event::{NodeEvent, NodeSink};
use crate::protocol::{MeshId, Message, Nickname};
use crate::util::clock::Instant;
use crate::util::tuning::{ALIVE_INTERVAL, alive_timeout};

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
    let expired: Vec<(Nickname, Instant, u64)> = state
        .last_seen
        .iter()
        .filter_map(|(nick, seen)| {
            let age = now.duration_since(*seen);
            (age > timeout).then(|| (nick.clone(), *seen, age.as_secs()))
        })
        .collect();
    for (nick, seen, age) in expired {
        state.last_seen.remove(nick.as_str());
        if state.peers.remove(nick.as_str()) {
            state.write_peer_count();
            // Remembered as a quiet peer, but no longer a holder: its flag was last said before it
            // went silent, and a crashed holder never says it again.
            if let Some(endpoint) = state
                .peer_endpoints
                .get(nick.as_str())
                .map(|address| address.id)
            {
                state.forget_rival_holder(endpoint);
            }
            if state.surfaced.remove(nick.as_str()) {
                // A peer we knew went silent: a partition may have split the
                // mesh, and the rendezvous is where its islands meet again. A
                // node that let go of the rendezvous owes it one return. A node
                // that still holds the link owes nothing: it would be owed
                // after the next release, and make the node grab it again.
                if !state.rendezvous_linked {
                    state.owe_rendezvous_return(now);
                }
                state.quiet.insert(nick.clone());
                // Retain the last-heard instant so the roster can still
                // report this evictee's recency (its `last_seen` is gone).
                // The endpoint binding is retained too: a quiet peer is the
                // one expected to *return*, and its return (any signed
                // message) re-adds it to the roster without a `PeerInfo`
                // re-broadcast — dropping the binding here would leave a
                // returned peer undeliverable for directed frames until its
                // gossip link happens to bounce.
                state.quiet_since.insert(nick.clone(), seen);
                sink.emit(NodeEvent::PeerTimeout {
                    nickname: nick.clone(),
                    last_seen_secs_ago: age,
                });
                tracing::debug!(nickname = %nick, age_secs = age, "peer evicted (silence timeout)");
            } else {
                state.forget_peer_endpoint(nick.as_str());
                tracing::trace!(
                    nickname = %nick,
                    age_secs = age,
                    "ghost evicted silently (pre-join backlog, never surfaced)"
                );
            }
        }
    }
    // Keep `quiet_since` bounded to current `quiet` membership: peers that
    // returned (drained from `quiet`) or fell off the bounded `quiet` FIFO
    // drop their stale recency here.
    let quiet = &state.quiet;
    state
        .quiet_since
        .retain(|nick, _| quiet.contains(nick.as_str()));
    // The same for the goodbyes: a mark of a peer that fell off the bounded `left` FIFO goes.
    let left = &state.left;
    state.left_at.retain(|nick, _| left.contains(nick.as_str()));
    // Same bound for the endpoint dial hints: an entry lives as long as its
    // nick is an active peer or a returnable quiet evictee, so the map
    // is capped at |peers| + QUIET_CAP even under nickname churn.
    // (Safe against a just-arrived `PeerInfo`: `lifecycle::observe` runs
    // before `handle_peer_info`, so a recorded endpoint's author is already a
    // peer.)
    let peers = &state.peers;
    state
        .peer_endpoints
        .retain(|nick, _| peers.contains(nick) || quiet.contains(nick.as_str()));
}

#[cfg(test)]
mod tests {
    use crate::testing::{fresh_state, nick};
    use habilis_network_test_tracing::test;
    use std::collections::HashSet;

    use super::{Instant, Nickname, tick_sweep};
    use crate::gossip::event::SilentSink;
    use crate::util::tuning;
    use std::time::Duration;

    #[test]
    fn sweep_evicts_surfaced_peer_into_quiet() {
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("swift-cedar"), expired_at);
        state.peers.insert(nick("swift-cedar"));
        // Arrival was surfaced => departure must be too.
        state.surfaced.insert(nick("swift-cedar"));

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.last_seen.contains_key("swift-cedar"),
            "a swept surfaced peer leaves the last-seen map"
        );
        assert!(
            !state.peers.contains("swift-cedar"),
            "a swept surfaced peer leaves the roster"
        );
        assert!(
            state.quiet.contains("swift-cedar"),
            "a swept surfaced peer goes quiet"
        );
        assert!(
            !state.surfaced.contains("swift-cedar"),
            "a swept surfaced peer is no longer surfaced"
        );
    }

    /// A node that let go of the rendezvous, whose silent neighbour is swept,
    /// owes it one return: the silence may be a partition, and the rendezvous
    /// is where the islands meet.
    #[test]
    fn sweeping_a_silent_known_peer_owes_a_return_to_the_rendezvous() {
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state
            .linked_endpoints
            .insert(crate::testing::endpoint_id(1));
        assert!(!state.rendezvous_wanted(), "enough links: it let go");
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("lost-heron"), expired_at);
        state.peers.insert(nick("lost-heron"));
        state.surfaced.insert(nick("lost-heron"));

        tick_sweep(&mut state, &SilentSink);

        assert!(state.rendezvous_wanted(), "one return is owed");
    }

    /// A node that still holds the rendezvous owes no return: it would be owed
    /// after the next release, and make the node grab the link again.
    #[test]
    fn a_node_still_linked_to_the_rendezvous_owes_no_return() {
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state
            .linked_endpoints
            .insert(crate::testing::endpoint_id(1));
        state.rendezvous_linked = true;
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("lost-heron"), expired_at);
        state.peers.insert(nick("lost-heron"));
        state.surfaced.insert(nick("lost-heron"));

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.rendezvous_comeback_until.is_none(),
            "a node still linked to the rendezvous owes no return"
        );
    }

    /// A holder that crashed or was killed never sends a `PeerInfo` without the flag. The sweep
    /// keeps its binding (a quiet peer returns), and must drop its claim to hold the rendezvous:
    /// a flag that stays known shuts every debt to a new holder for as long as it lives.
    #[test]
    fn the_flag_of_an_evicted_holder_is_forgotten() {
        let mut state = fresh_state();
        let holder = crate::testing::endpoint_id(7);
        state
            .peer_endpoints
            .insert(nick("lost-heron"), iroh::EndpointAddr::new(holder));
        state
            .rival_holders
            .insert(crate::protocol::AuthorKey::from_bytes([4u8; 32]), holder);
        assert!(
            state.rival_holder_known(),
            "the evicted holder's flag is known before the sweep"
        );
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("lost-heron"), expired_at);
        state.peers.insert(nick("lost-heron"));
        state.surfaced.insert(nick("lost-heron"));

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.quiet.contains("lost-heron"),
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
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state
            .linked_endpoints
            .insert(crate::testing::endpoint_id(1));
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("ghost-oak"), expired_at);
        state.peers.insert(nick("ghost-oak"));

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.rendezvous_wanted(),
            "a ghost of the pre-join backlog says nothing about a partition"
        );
    }

    #[test]
    fn quiet_peer_reports_real_recency_in_roster() {
        // Regression: a quiet peer must still report how long ago it was
        // last heard (not `null`), even though eviction drops `last_seen`.
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("calm-otter"), expired_at);
        state.peers.insert(nick("calm-otter"));
        state.surfaced.insert(nick("calm-otter"));

        tick_sweep(&mut state, &SilentSink);

        let roster = state.roster_snapshot();
        let entry = roster
            .peers
            .iter()
            .find(|entry| entry.nickname.as_str() == "calm-otter")
            .expect("quiet peer present in roster");
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
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("swift-cedar"), expired_at);
        state.peers.insert(nick("swift-cedar"));
        state.surfaced.insert(nick("swift-cedar"));
        let endpoint = iroh::SecretKey::from_bytes(&[7; 32]).public();
        state
            .peer_endpoints
            .insert(nick("swift-cedar"), iroh::EndpointAddr::new(endpoint));

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.quiet.contains("swift-cedar"),
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
        let mut state = fresh_state();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        // Not in `peers`, not in `quiet`: fell off the quiet FIFO or
        // departed via `left` churn — the dial hint must not outlive it.
        state
            .peer_endpoints
            .insert(nick("gone-fern"), iroh::EndpointAddr::new(endpoint));

        tick_sweep(&mut state, &SilentSink);

        assert!(
            !state.peer_endpoints.contains_key("gone-fern"),
            "a sweep prunes endpoints of names that are neither active nor quiet"
        );
    }

    #[test]
    fn sweep_evicts_unsurfaced_peer_silently() {
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("ghost-elm"), expired_at);
        state.peers.insert(nick("ghost-elm"));
        // Never in `surfaced`: known only via pre-join backlog.

        tick_sweep(&mut state, &SilentSink);

        // Still evicted from the roster (hygiene preserved)...
        assert!(
            !state.last_seen.contains_key("ghost-elm"),
            "a sweep evicts an unsurfaced peer from last-seen"
        );
        assert!(
            !state.peers.contains("ghost-elm"),
            "a sweep evicts an unsurfaced peer from the roster"
        );
        // ...but never parked in `quiet` => no `went quiet` emitted.
        assert!(
            !state.quiet.contains("ghost-elm"),
            "a sweep never puts an unsurfaced peer in quiet"
        );
    }

    #[test]
    fn sweep_keeps_recent_peer() {
        let mut state = fresh_state();
        state.last_seen.insert(nick("swift-cedar"), Instant::now());
        state.peers.insert(nick("swift-cedar"));

        tick_sweep(&mut state, &SilentSink);

        assert!(
            state.last_seen.contains_key("swift-cedar"),
            "a recent peer stays in last-seen"
        );
        assert!(
            state.peers.contains("swift-cedar"),
            "a recent peer stays in the roster"
        );
        assert!(
            !state.quiet.contains("swift-cedar"),
            "a recent peer is not quiet"
        );
    }

    #[test]
    fn sweep_noop_on_empty_last_seen() {
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
        let mut state = fresh_state();
        let expired_at = Instant::now()
            .checked_sub(tuning::alive_timeout() + Duration::from_secs(10))
            .unwrap();
        state.last_seen.insert(nick("stale-nick"), expired_at);
        state.peers.insert(nick("stale-nick"));
        state.last_seen.insert(nick("fresh-nick"), Instant::now());
        state.peers.insert(nick("fresh-nick"));

        tick_sweep(&mut state, &SilentSink);

        let expected_peers: HashSet<Nickname> = [nick("fresh-nick")].into_iter().collect();
        assert_eq!(
            state.peers, expected_peers,
            "a sweep preserves the other peers"
        );
    }
}
