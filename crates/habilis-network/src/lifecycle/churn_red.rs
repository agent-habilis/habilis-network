//! Evidence for issue 75 (peer churn): H5 (ghosts are counted), H6 (a peer that left stays listed),
//! and the claim that a link gap makes a 4.5 min cycle. Tests only. They use no API that is new in
//! PR 47, so the same file runs on the unfixed rev f7cd9bb (red) and on the fixed rev (green).

use std::time::Duration;

use crate::daemon::setup::LiveCount;
use crate::daemon::state::{EventLoopState, Standing};
use crate::gossip::event::SilentSink;
use crate::lifecycle::heartbeat;
use crate::lifecycle::membership_update::{apply, compute_for};
use crate::protocol::identity::Identity;
use crate::protocol::{AppFrameParams, AppTag, MeshId, Message, MessageBody, UnixSecs, Verified};
use crate::testing::{endpoint_id, fresh_state, nick};
use crate::util::clock::Instant;
use crate::util::tuning::{alive_timeout, starvation_threshold};

use std::sync::atomic::Ordering;

/// A chat frame of `author`, stamped `at`. An app frame is what anti-entropy replays from the
/// message log to a new joiner.
fn chat(author: &str, by: &Identity, at: UnixSecs) -> Verified {
    let mut message = Message::new_app(
        &MeshId::from("test"),
        &nick(author),
        AppFrameParams::new(
            AppTag::try_new("app_msg").expect("a valid app tag"),
            None,
            None,
            MessageBody::from("hello"),
        ),
    );
    message.timestamp = at;
    message.sign(by)
}

/// H5. A new joiner receives the message log of the mesh. A frame in it that is older than the
/// join of this node, from a peer that left before, must not count as a member: this node would
/// show a count that is too high until the sweep evicts the ghost, and the ghost never surfaced.
#[test]
fn h5_a_pre_join_backlog_frame_adds_no_ghost_to_the_count() {
    let _guard = ::habilis_network_test_tracing::init();
    let mut state = fresh_state();
    let live = LiveCount::default();
    state.live_count = Some(live.clone());
    state.write_peer_count();
    assert_eq!(live.load(Ordering::Relaxed), 1, "alone: this node only");

    state.joined_at = UnixSecs::now();
    let before_join = state.joined_at - Duration::from_secs(600);
    for ghost in ["swift-cedar", "lost-heron", "calm-otter"] {
        let frame = chat(ghost, &Identity::generate(), before_join);
        let update = compute_for(&frame, &state);
        apply(&update, &frame.author, &mut state);
    }

    assert_eq!(
        live.load(Ordering::Relaxed),
        1,
        "3 peers known only from the pre-join backlog are counted: peers={:?}",
        state.peers
    );
}

/// H6. A surfaced peer goes silent and is swept into `quiet`. It does not come back. One hour
/// later the roster must not list it any more: only 1024 other departures pushed it out before,
/// so on a calm mesh it stayed for ever.
#[test]
fn h6_a_peer_that_left_leaves_the_roster_after_an_hour() {
    let _guard = ::habilis_network_test_tracing::init();
    let mut state = fresh_state();
    let who = nick("swift-cedar");
    let silent = Instant::now()
        .checked_sub(alive_timeout() + Duration::from_secs(10))
        .expect("the monotonic clock has run past the alive timeout since boot");
    state.last_seen.insert(who.clone(), silent);
    state.peers.insert(who.clone());
    state.surfaced.insert(who.clone());
    heartbeat::tick_sweep(&mut state, &SilentSink);
    let listed = |held: &EventLoopState| {
        held.roster_snapshot()
            .peers
            .iter()
            .any(|entry| entry.nickname == who)
    };
    assert!(listed(&state), "precondition: a quiet peer is listed");

    // An hour and a minute pass: the last frame of the peer is that old.
    let long_ago = Instant::now()
        .checked_sub(Duration::from_mins(61))
        .expect("the monotonic clock has run past one hour since boot");
    state.quiet_since.insert(who.clone(), long_ago);
    heartbeat::tick_sweep(&mut state, &SilentSink);

    assert!(
        !listed(&state),
        "a peer silent for 61 min is still in the roster as quiet"
    );
}

/// The claim: the cycle of about 4.5 min is `alive_timeout` (90 s) plus `starvation_threshold`
/// (180 s). Time is controlled: `last_seen` is backdated, and the starvation clock reads a `now`
/// that this test moves. The test pins what the code does after a link gap of this node.
#[test]
fn a_link_gap_has_no_270_second_cycle() {
    let _guard = ::habilis_network_test_tracing::init();
    let timeout = alive_timeout();
    let starved = starvation_threshold();
    assert_eq!(timeout, Duration::from_secs(90), "the alive timeout");
    assert_eq!(
        starved,
        Duration::from_secs(180),
        "the starvation threshold"
    );

    // The last frame arrives at t0. The link then drops: nothing more arrives.
    let mut state = fresh_state();
    state.standing.insert(Standing::Announced);
    state.known_endpoints.insert(endpoint_id(1));
    let t0 = Instant::now();
    state.note_inbound(t0);
    let who = nick("swift-cedar");
    state.peers.insert(who.clone());
    state.surfaced.insert(who.clone());

    // t0 + 95 s: the first sweep after the alive timeout evicts the peer.
    state.last_seen.insert(
        who.clone(),
        Instant::now()
            .checked_sub(timeout + Duration::from_secs(5))
            .expect("the monotonic clock has run past the alive timeout since boot"),
    );
    heartbeat::tick_sweep(&mut state, &SilentSink);
    assert!(state.quiet.contains(who.as_str()), "timeout at about 90 s");

    // The starvation watchdog reads the same last inbound, not the eviction: it is due at 180 s.
    assert!(
        !state.starvation_due(t0 + starved.saturating_sub(Duration::from_secs(1)), starved),
        "not due before 180 s"
    );
    let first = t0 + starved + Duration::from_secs(1);
    assert!(
        state.starvation_due(first, starved),
        "due at 180 s, not 270 s"
    );

    // After a recovery the backoff doubles: the next one is 360 s later, then 720 s.
    state.note_recovery(first);
    assert!(
        !state.starvation_due(
            first + (starved * 2).saturating_sub(Duration::from_secs(1)),
            starved
        ),
        "the second recovery waits 2 x 180 s"
    );
    assert!(
        state.starvation_due(first + starved * 2 + Duration::from_secs(1), starved),
        "due 2 x 180 s after the first recovery"
    );
    assert_ne!(
        timeout + starved,
        starved,
        "the sum 90 + 180 is not a period of the watchdog: it fires at 180, 540, 1260 s"
    );
}
