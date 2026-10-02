//! What a consuming game has to tell the session about itself.

use std::fmt::Debug;
use std::hash::Hash;

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The three types a rollback session is generic over.
///
/// Implement this on a zero-sized marker type; it is a type-level bundle, not
/// something you construct.
///
/// ```ignore
/// struct MyGame;
/// impl Config for MyGame {
///     type Input = MyInput;   // one player's input for one frame
///     type State = MyWorld;   // everything the simulation needs to resume
///     type Address = String;  // how a peer is addressed on the wire
/// }
/// ```
///
/// # The determinism contract
///
/// Rollback works by every peer re-running the *same* simulation over the
/// *same* inputs and getting bit-identical results. If two peers ever diverge,
/// they are playing different games and nothing downstream can recover it. So
/// [`Self::State`] and the `advance_frame` that produces it must be
/// deterministic **across machines and across targets** — this crate is built
/// for native and `wasm32` simultaneously. In practice:
///
/// - **No floating point.** IEEE 754 agrees on `+`/`-`/`*`/`/`, but `sin`,
///   `cos`, `exp` and friends come from whichever libm the target links, and
///   those differ. Use integers or fixed point.
/// - **No iteration over `HashMap`/`HashSet`.** `std`'s default hasher is
///   randomly seeded per process. Use `BTreeMap`/`BTreeSet`, or sort first.
/// - **No `rand` seeded from entropy**, no system clock, no thread scheduling
///   in the simulation path. Seed any PRNG from data every peer agrees on and
///   use a portable algorithm.
/// - **No dependence on collection *insertion* order** where peers may have
///   inserted in different orders.
///
/// None of this is checked by the compiler. It *is* checkable at runtime:
/// [`crate::SyncTestSession`] re-simulates every frame and compares state
/// checksums, which catches most violations locally, before they ever desync a
/// real match. Run it in your test suite.
pub trait Config: 'static {
    /// One player's input for one frame.
    ///
    /// This is *state, not events*: "which direction is held right now",
    /// not "the player turned". Rollback predicts a missing input by
    /// repeating the last one, which is only sensible for the former.
    ///
    /// Keep it small — it goes on the wire every frame, several frames'
    /// worth per packet for redundancy.
    ///
    /// `Send + Sync` because inbound frames are decoded on the engine's
    /// event loop and read by the game's frame loop, which are not the same
    /// thread on native. Plain data satisfies this for free.
    type Input: Copy
        + Clone
        + PartialEq
        + Default
        + Debug
        + Send
        + Sync
        + Serialize
        + DeserializeOwned;

    /// Everything the simulation needs to resume from a frame.
    ///
    /// Saved every frame and restored on rollback, so cloning it should be
    /// cheap. If your world is large, save a compact snapshot rather than the
    /// live representation.
    type State: Clone;

    /// How a remote peer is addressed.
    ///
    /// Must be stable for the whole session and unique per player — this is
    /// the key inputs are filed under. Over a habilis-network mesh this is the peer's
    /// signed public key, never its nickname (nicknames are cosmetic and
    /// explicitly non-unique).
    type Address: Clone + PartialEq + Eq + Hash + Debug;
}
