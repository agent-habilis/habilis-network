use crate::cycle::Cycle;
use crate::grid::{GRID_H, GRID_W};
use crate::round_descriptor::RoundDescriptor;

/// `PartialEq` (and, transitively, on [`crate::snapshot::Snapshot`]) is what
/// lets `Signal::set` skip a render when a UI-tick snapshot is unchanged
/// from the last one — `World`'s own `PartialEq` derive already does the
/// right thing (deep-compares `grid` and `cycles`), no manual impl needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct World {
    pub tick: u16,
    /// Row-major, `GRID_W * GRID_H`. `0` = empty, else roster index + 1.
    pub grid: Vec<u8>,
    pub cycles: Vec<Cycle>,
}

/// An empty arena with nobody in it — what the client shows while it is
/// still waiting for a match to start.
impl Default for World {
    fn default() -> Self {
        Self {
            tick: 0,
            grid: vec![0; usize::from(GRID_W) * usize::from(GRID_H)],
            cycles: Vec::new(),
        }
    }
}

impl World {
    /// The world at tick 0: everyone on their spawn, facing outward from
    /// it, with that first cell already claimed.
    #[must_use]
    pub fn spawn(desc: &RoundDescriptor) -> Self {
        let cycles = desc
            .spawns
            .iter()
            .map(|s| Cycle {
                x: i16::from(s.x),
                y: i16::from(s.y),
                dir: s.dir,
                alive: true,
            })
            .collect();
        let mut world = World {
            tick: 0,
            grid: vec![0; usize::from(GRID_W) * usize::from(GRID_H)],
            cycles,
        };
        for (i, s) in desc.spawns.iter().enumerate() {
            world.mark(s.x, s.y, i);
        }
        world
    }

    /// A cheap state checksum for the session's desync detection. Order-
    /// dependent and position-dependent, which is the point: two peers
    /// whose worlds differ anywhere must differ here.
    #[must_use]
    pub fn checksum(&self) -> u128 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |byte: u8| {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        };
        for byte in &self.grid {
            eat(*byte);
        }
        for cycle in &self.cycles {
            for byte in cycle.x.to_le_bytes() {
                eat(byte);
            }
            for byte in cycle.y.to_le_bytes() {
                eat(byte);
            }
            eat(cycle.dir as u8);
            eat(u8::from(cycle.alive));
        }
        u128::from(hash) | (u128::from(self.tick) << 64)
    }

    pub(crate) fn mark(&mut self, x: u8, y: u8, player: usize) {
        let index = usize::from(y) * usize::from(GRID_W) + usize::from(x);
        self.grid[index] = u8::try_from(player + 1).unwrap_or(u8::MAX);
    }

    /// Out-of-bounds counts as occupied — a wall behaves exactly like a
    /// trail for collision purposes.
    pub(crate) fn occupied(&self, x: i16, y: i16) -> bool {
        if x < 0 || y < 0 || x >= i16::from(GRID_W) || y >= i16::from(GRID_H) {
            return true;
        }
        let index =
            usize::try_from(y).unwrap_or(0) * usize::from(GRID_W) + usize::try_from(x).unwrap_or(0);
        self.grid[index] != 0
    }
}
