//! GGPO-style rollback netcode for peer-to-peer games on a habilis-network mesh.
//!
//! This is an implementation of a **named, well-documented algorithm**, not a
//! bespoke one: [GGPO](https://github.com/pond3r/ggpo), the model behind most
//! modern fighting games, whose Rust reference implementation is
//! [GGRS](https://github.com/gschup/ggrs). If you know how rollback behaves
//! there, you know how it behaves here — including what it costs.
//!
//! # How it works, in one paragraph
//!
//! Only inputs cross the network, never game state. Each peer simulates
//! immediately, guessing any remote input that has not arrived yet by
//! repeating that player's last one. When the real input turns up and
//! contradicts the guess, the session rolls the simulation back to the frame
//! it went wrong at and re-simulates forward with the truth. Because every
//! peer runs the same deterministic simulation over the same inputs, they all
//! arrive at the same state without anyone being authoritative.
//!
//! # What you are signing up for
//!
//! | Property | Consequence |
//! |---|---|
//! | Strict determinism required | Integer or fixed-point only; no floats, no `HashMap` iteration, no clocks in the simulation. See [`Config`]. |
//! | State snapshotted every frame | [`Config::State`] must be cheap to clone. |
//! | Bounded rollback | Past `max_prediction` frames the session stalls instead of guessing further. |
//! | Inputs only on the wire | Bandwidth scales with players, not world size. |
//! | No authoritative peer | Nobody arbitrates, so there is also no anti-cheat. |
//! | Small player counts | Fan-out is O(n²) mesh-wide. Built for 2–8. |
//!
//! Delay-based deterministic lockstep — the classic RTS model — is the same
//! algorithm with `max_prediction` set to zero, so it is a configuration
//! rather than a separate code path.
//!
//! # What it is not for
//!
//! Large persistent worlds where each peer only observes nearby players.
//! Rollback requires every peer to simulate the *whole* world; interest
//! management is the direct opposite. That needs replication with dead
//! reckoning, which is a different algorithm and would be a different crate.
//!
//! Turn-based games get nothing from rollback either — the mesh's ordinary
//! message delivery is a better fit.
//!
//! # Verifying determinism
//!
//! Nothing here can check the determinism contract at compile time, and a
//! violation surfaces as a desync over a real network rather than a local
//! failure. [`SyncTestSession`] turns that into a unit test: it re-simulates
//! every frame and compares state checksums. Use it.

#[cfg(test)]
mod testutil;

mod config;
mod error;
mod frame;
mod input_queue;
mod mesh;
mod protocol;
mod request;
mod saved_states;
mod session;
mod sync;
mod sync_test;
mod time_sync;
mod transport;

pub use config::Config;
pub use error::RollbackError;
pub use frame::{Frame, InputStatus, NULL_FRAME};
pub use mesh::{
    LOBBY_TAG, Lobby, LobbyError, MeshTransport, Outbound, ROLLBACK_TAG, RollbackDriver,
    StartedMatch,
};
pub use protocol::PeerState;
pub use request::{Request, StateCell};
pub use session::{Event, P2PSession, SessionState};
pub use sync_test::SyncTestSession;
pub use transport::{Body, InputPacket, Message, Transport};
