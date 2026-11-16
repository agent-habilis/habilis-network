//! The simulation: one tick at a time, from a state and one input per
//! player.
//!
//! This is the `advance_frame` a rollback session drives, so it must obey
//! `habilis_network_netplay::Config`'s determinism contract — every peer runs this
//! same function over the same inputs and has to get a bit-identical
//! [`World`], or they are playing different games. It does: integer
//! arithmetic only, no hashed-collection iteration, no clock, no entropy.
//! `tests/sync_test.rs` checks that claim rather than trusting it.
//!
//! Elimination is *derived* here, never announced over the wire.

use crate::grid::ROUND_MAX_TICKS;
use crate::input::Input;
use crate::outcome::Outcome;
use crate::world::World;

/// Advances `world` by one tick. `inputs[i]` is player `i`'s input, in
/// roster order.
///
/// Two-phase and therefore evaluation-order-independent: (1) compute every
/// live cycle's next cell, (2) decide deaths (a wall/trail hit, or a
/// head-on into another live cycle's next cell) purely from that snapshot,
/// (3) apply. Nothing here depends on which index is processed first.
pub fn step(world: &mut World, inputs: &[Input]) {
    // A decided round is a fixed point: stepping it again changes nothing,
    // not even the tick.
    //
    // This is what makes it safe for a peer to keep advancing after the
    // match looks over, and it has to keep advancing — the world it
    // decided on may rest on *predicted* remote inputs, and only a later
    // `advance_frame` can roll that back and correct it. A peer that
    // stopped the moment its own screen said "won" would freeze on the
    // guess, and two peers would then disagree about who won with no
    // checksum mismatch to show for it, because neither is still
    // simulating the frames the other is.
    //
    // Stopping here rather than in the caller also keeps the rule inside
    // the determinism contract: every peer reaches the same fixed point on
    // the same frame, and re-simulating a rolled-back frame lands on it
    // again.
    if outcome(world) != Outcome::InProgress {
        return;
    }
    let n = world.cycles.len();
    let mut next: Vec<Option<(i16, i16)>> = Vec::with_capacity(n);
    let mut dies = vec![false; n];

    for (i, cycle) in world.cycles.iter_mut().enumerate() {
        if !cycle.alive {
            next.push(None);
            continue;
        }
        // A reversal is refused rather than rejected upstream: it is the
        // one illegal steer, and the sim is the only place every peer is
        // guaranteed to agree on what the cycle was facing at this tick.
        if let Some(dir) = inputs.get(i).and_then(|input| input.steer)
            && !dir.is_reverse_of(cycle.dir)
        {
            cycle.dir = dir;
        }
        let (dx, dy) = cycle.dir.delta();
        next.push(Some((cycle.x + dx, cycle.y + dy)));
    }

    for i in 0..n {
        let Some((nx, ny)) = next[i] else { continue };
        let head_on = next
            .iter()
            .enumerate()
            .any(|(j, other)| j != i && *other == Some((nx, ny)));
        dies[i] = world.occupied(nx, ny) || head_on;
    }

    for i in 0..n {
        let Some((nx, ny)) = next[i] else { continue };
        if dies[i] {
            world.cycles[i].alive = false;
        } else {
            world.cycles[i].x = nx;
            world.cycles[i].y = ny;
            let (x, y) = (u8::try_from(nx).unwrap_or(0), u8::try_from(ny).unwrap_or(0));
            world.mark(x, y, i);
        }
    }
    world.tick = world.tick.saturating_add(1);
}

/// A round with 0 or 1 players never ends by elimination — only by the
/// tick cap — since "last one standing" is meaningless with nobody to
/// stand against.
#[must_use]
pub fn outcome(world: &World) -> Outcome {
    let mut alive = world.cycles.iter().enumerate().filter(|(_, c)| c.alive);
    let first = alive.next();
    let more_than_one = alive.next().is_some();

    // Whatever this round would resolve to *if* it ended right now.
    let decided = match first {
        Some((index, _)) if !more_than_one => Outcome::Winner(index),
        _ => Outcome::Draw,
    };

    let eliminated = world.cycles.len() > 1 && !more_than_one;
    if eliminated || world.tick >= ROUND_MAX_TICKS {
        return decided;
    }
    Outcome::InProgress
}

#[cfg(test)]
mod tests {
    use super::{Outcome, World, outcome, step};
    use crate::cycle::Cycle;
    use crate::dir::Dir;
    use crate::input::Input;
    use crate::round_descriptor::RoundDescriptor;
    use proptest::prelude::{
        Arbitrary, Just, Strategy, prop, prop_assert_eq, prop_oneof, proptest,
    };

    /// Runs `count` ticks with nobody steering.
    fn coast(desc: &RoundDescriptor, count: u16) -> World {
        let mut world = World::spawn(desc);
        let idle = vec![Input::default(); desc.roster.len()];
        for _ in 0..count {
            step(&mut world, &idle);
            if outcome(&world) != Outcome::InProgress {
                break;
            }
        }
        world
    }

    #[test]
    fn two_players_driving_straight_at_each_other_end_in_a_draw_or_a_winner() {
        let _guard = ::habilis_network_test_tracing::init();
        let desc = RoundDescriptor::derive(7, vec!["a".into(), "b".into()]);
        assert_ne!(
            outcome(&coast(&desc, 200)),
            Outcome::InProgress,
            "the head-on round reaches an outcome"
        );
    }

    #[test]
    fn a_solo_round_never_ends_by_elimination() {
        let _guard = ::habilis_network_test_tracing::init();
        let desc = RoundDescriptor::derive(7, vec!["solo".into()]);
        assert_eq!(
            outcome(&coast(&desc, 50)),
            Outcome::InProgress,
            "a solo round never ends by elimination"
        );
    }

    #[test]
    fn a_reversal_is_refused_and_the_cycle_holds_course() {
        let _guard = ::habilis_network_test_tracing::init();
        let desc = RoundDescriptor::derive(7, vec!["a".into(), "b".into()]);
        let mut world = World::spawn(&desc);
        let facing = world.cycles[0].dir;
        let reverse = match facing {
            Dir::Up => Dir::Down,
            Dir::Down => Dir::Up,
            Dir::Left => Dir::Right,
            Dir::Right => Dir::Left,
        };
        step(
            &mut world,
            &[
                Input {
                    steer: Some(reverse),
                },
                Input::default(),
            ],
        );
        assert_eq!(
            world.cycles[0].dir, facing,
            "reversing would drive straight into the trail cell just left"
        );
    }

    #[test]
    fn stepping_never_un_draws_a_trail_or_revives_a_cycle() {
        let _guard = ::habilis_network_test_tracing::init();
        let desc = RoundDescriptor::derive(7, vec!["a".into(), "b".into(), "c".into()]);
        let short = coast(&desc, 5);
        let long = coast(&desc, 20);
        assert!(
            long.tick > short.tick,
            "the longer run must advance further"
        );
        let indexed_cells: Vec<(usize, &u8)> = short.grid.iter().enumerate().collect();
        for (index, owner) in indexed_cells {
            if *owner != 0 {
                assert_eq!(
                    long.grid[index], *owner,
                    "cell {index} changed owner between a short and a longer run"
                );
            }
        }
        let paired: Vec<(&Cycle, &Cycle)> = short.cycles.iter().zip(long.cycles.iter()).collect();
        for (a, b) in paired {
            assert!(a.alive || !b.alive, "a dead cycle came back to life");
        }
    }

    fn arbitrary_dir() -> impl Strategy<Value = Dir> {
        prop_oneof![
            Just(Dir::Up),
            Just(Dir::Right),
            Just(Dir::Down),
            Just(Dir::Left),
        ]
    }

    proptest! {
        /// The determinism contract, as a property: same descriptor, same
        /// input script, same world — down to the checksum the session
        /// uses to detect desync.
        #[test]
        fn stepping_is_a_pure_function_of_its_inputs(
            seed in u64::arbitrary(),
            player_count in 2usize..5,
            script in prop::collection::vec(
                prop::collection::vec(prop::option::of(arbitrary_dir()), 2..5),
                1..80,
            ),
        ) {
            let _guard = ::habilis_network_test_tracing::init();
            let roster: Vec<String> = (0..player_count).map(|i| format!("p{i}")).collect();
            let desc = RoundDescriptor::derive(seed, roster);

            let run = || {
                let mut world = World::spawn(&desc);
                for frame in &script {
                    let inputs: Vec<Input> = (0..player_count)
                        .map(|i| Input { steer: frame.get(i).copied().flatten() })
                        .collect();
                    step(&mut world, &inputs);
                }
                world
            };
            prop_assert_eq!(run().checksum(), run().checksum());
                }

        #[test]
        fn a_finished_outcome_never_reverts_to_in_progress(
            seed in u64::arbitrary(),
            player_count in 2usize..5,
        ) {
            let _guard = ::habilis_network_test_tracing::init();
            let roster: Vec<String> = (0..player_count).map(|i| format!("p{i}")).collect();
            let desc = RoundDescriptor::derive(seed, roster);

            let at_100 = coast(&desc, 100);
            if outcome(&at_100) != Outcome::InProgress {
                prop_assert_eq!(outcome(&at_100), outcome(&coast(&desc, 200)));
            }
                }
    }
}
