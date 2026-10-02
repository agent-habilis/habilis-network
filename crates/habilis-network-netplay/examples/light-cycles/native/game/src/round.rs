//! Round descriptors: a pure function of `(session id, sorted roster)`,
//! so every peer in a match derives byte-identical spawn assignments
//! with no negotiation at all — the descriptor never travels over the
//! wire.
//!
//! Both inputs come straight from `habilis_network_netplay::StartedMatch`, which
//! is the agreement. That matters more than it sounds: the roster here is
//! *fixed for the match*, not a live liveness estimate, so two peers can
//! no longer briefly disagree about who is playing and therefore lay out
//! entirely different arenas.

use serde::{Deserialize, Serialize};

use crate::grid::{Dir, GRID_H, GRID_W};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spawn {
    pub x: u8,
    pub y: u8,
    pub dir: Dir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundDescriptor {
    /// Sorted, deduplicated pubkey hex — canonical order, so index `i`
    /// here is index `i` into `spawns` and handle `i` in the session.
    pub roster: Vec<String>,
    pub spawns: Vec<Spawn>,
}

impl RoundDescriptor {
    /// Derives the descriptor for `session_id` and `roster`.
    ///
    /// The roster is sorted and deduplicated here, which is also what
    /// makes index `i` in [`Self::roster`] the same player as handle `i`
    /// in the session: the lobby sorts by public key too, so the two
    /// orders coincide. Nothing downstream re-derives that mapping.
    #[must_use]
    pub fn derive(session_id: u64, mut roster: Vec<String>) -> Self {
        roster.sort_unstable();
        roster.dedup();
        let seed = seed_for(session_id, &roster);
        let mut rng = SplitMix64::new(seed);
        let spawns = place_spawns(&mut rng, roster.len());
        Self { roster, spawns }
    }
}

fn seed_for(session_id: u64, roster: &[String]) -> u64 {
    let mut hasher = Fnv1a64::new();
    hasher.write(&session_id.to_le_bytes());
    for pubkey in roster {
        hasher.write(b":");
        hasher.write(pubkey.as_bytes());
    }
    hasher.finish()
}

/// Walks spawn points out from the seed, spaced away from walls and from
/// each other so nobody starts inside another player's very first trail
/// cell, facing inward (toward the arena's center) so an opening move
/// never immediately re-enters a wall.
fn place_spawns(rng: &mut SplitMix64, count: usize) -> Vec<Spawn> {
    const MARGIN: u8 = 4;
    let usable_w = GRID_W.saturating_sub(2 * MARGIN).max(1);
    let usable_h = GRID_H.saturating_sub(2 * MARGIN).max(1);
    let center_x = GRID_W / 2;
    let center_y = GRID_H / 2;

    let mut placed: Vec<(u8, u8)> = Vec::with_capacity(count);
    let mut spawns = Vec::with_capacity(count);
    let divisor: u32 = u32::try_from(count).unwrap_or(1).max(3);
    let min_separation: u32 = u32::from(usable_w.min(usable_h)) / divisor;

    for _ in 0..count {
        let mut best: Option<(u8, u8)> = None;
        // A handful of candidate draws, keeping whichever is farthest from
        // every already-placed spawn — cheap rejection sampling rather
        // than a real Poisson-disc pass, plenty for a handful of players.
        for _ in 0..16 {
            let x = MARGIN + u8::try_from(rng.next_bounded(u64::from(usable_w))).unwrap_or(0);
            let y = MARGIN + u8::try_from(rng.next_bounded(u64::from(usable_h))).unwrap_or(0);
            let min_dist: u32 = placed
                .iter()
                .map(|&(px, py)| u32::from(x.abs_diff(px)).max(u32::from(y.abs_diff(py))))
                .min()
                .unwrap_or(u32::MAX);
            if best.is_none() || min_dist >= min_separation {
                best = Some((x, y));
                if min_dist >= min_separation {
                    break;
                }
            }
        }
        let (x, y) = best.unwrap_or((center_x, center_y));
        placed.push((x, y));
        let dir = if i32::from(x) < i32::from(center_x) {
            Dir::Right
        } else if i32::from(x) > i32::from(center_x) {
            Dir::Left
        } else if i32::from(y) < i32::from(center_y) {
            Dir::Down
        } else {
            Dir::Up
        };
        spawns.push(Spawn { x, y, dir });
    }
    spawns
}

/// A tiny, dependency-free FNV-1a — only used to turn a match/roster
/// tuple into a seed, never anything security-sensitive.
struct Fnv1a64(u64);

impl Fnv1a64 {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// A tiny, dependency-free splitmix64 — deterministic across platforms,
/// which `std`'s `HashMap`-oriented `RandomState` is explicitly not.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_bounded(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RoundDescriptor;

    #[test]
    fn deriving_twice_with_the_same_inputs_is_byte_identical() {
        let roster = vec!["bob".to_string(), "alice".to_string()];
        let a = RoundDescriptor::derive(3, roster.clone());
        let b = RoundDescriptor::derive(3, roster);
        assert_eq!(a, b);
    }

    #[test]
    fn roster_order_does_not_affect_the_result() {
        let a = RoundDescriptor::derive(1, vec!["a".into(), "b".into(), "c".into()]);
        let b = RoundDescriptor::derive(1, vec!["c".into(), "a".into(), "b".into()]);
        assert_eq!(a, b);
    }

    /// A rematch gets a fresh session id, and this is what makes that
    /// visible to the players: a different arena, not the same one again.
    #[test]
    fn a_different_session_id_gives_a_different_layout_in_practice() {
        let roster = vec!["a".to_string(), "b".to_string()];
        let a = RoundDescriptor::derive(1, roster.clone());
        let b = RoundDescriptor::derive(2, roster);
        assert_ne!(a.spawns, b.spawns);
    }

    #[test]
    fn a_different_roster_gives_a_different_descriptor() {
        let a = RoundDescriptor::derive(1, vec!["a".into(), "b".into()]);
        let b = RoundDescriptor::derive(1, vec!["a".into(), "c".into()]);
        assert_ne!(a, b);
    }

    #[test]
    fn every_roster_member_gets_a_distinct_spawn() {
        let roster: Vec<String> = (0..6).map(|i| format!("player-{i}")).collect();
        let desc = RoundDescriptor::derive(0, roster);
        let mut points: Vec<(u8, u8)> = desc.spawns.iter().map(|s| (s.x, s.y)).collect();
        points.sort_unstable();
        points.dedup();
        assert_eq!(points.len(), desc.spawns.len());
    }
}
