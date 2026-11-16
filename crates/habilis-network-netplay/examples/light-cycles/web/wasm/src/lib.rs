//! The web `light-cycles` client's wasm half: game logic, the
//! `habilis-network-netplay` embedding (`app`), and the deterministic
//! `grid`/`round`/`sim` machinery — all this crate's own copy,
//! independent of `native/game`'s (see the plan's "Workspace layout").
//!
//! This file is the one thing with no native counterpart to mirror: the
//! wasm-bindgen JS API a `requestAnimationFrame` loop drives —
//! [`LightCyclesPeer::join`], [`LightCyclesPeer::turn`],
//! [`LightCyclesPeer::frame`], [`LightCyclesPeer::hud`],
//! [`LightCyclesPeer::drain_events`].
//!
//! `frame()` is also where the simulation is *paced*, and that is
//! load-bearing rather than a convenience. A rollback session advances
//! exactly one simulation tick per `Game::tick`, so driving it straight
//! off rAF would run this client at the display's refresh rate — 60 Hz
//! against the terminal client's 20 — and the two would not be playing
//! the same game. The accumulator below decouples the two: render as
//! often as the browser likes, simulate at [`grid::TICK_MS`].

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

mod cycle;
mod cycle_dto;
mod dir;
mod frame_dto;
mod game;
mod game_event;
mod grid;
mod hud_dto;
mod input;
mod js_error;
mod light_cycles;
mod light_cycles_peer;
mod outcome;
mod outcome_dto;
mod parse_dir;
mod roster_entry_dto;
mod round;
mod round_descriptor;
mod sim;
mod snapshot;
mod spawn;
mod split_mix64;
mod world;

use habilis_network::protocol::{MeshName, Nickname};
use wasm_bindgen::prelude::wasm_bindgen;

/// The most simulation ticks one `frame()` will run to catch up.
///
/// A browser suspends rAF entirely while a tab is backgrounded, so the
/// first frame after the player comes back can be minutes of owed time.
/// Replaying all of it would freeze the tab and, worse, race far ahead of
/// the other players. Capping it means a returning tab simply resumes and
/// lets the session's own pacing pull it back into line.
pub(crate) const MAX_CATCH_UP_TICKS: u32 = 4;

/// A fresh `word-word` room code, from the same curated wordlist the
/// native CLI's `MeshName::random()` draws on — 1024 words, so ~1M pairs.
/// Exposed here rather than reimplemented on the frontend: a second,
/// shorter word list would give browser-minted codes a far higher chance
/// of colliding with an unrelated room than CLI-minted ones, on a topic
/// string that is the room's whole identity.
#[wasm_bindgen]
#[must_use]
pub fn random_room_code() -> String {
    MeshName::random().to_string()
}

/// A fresh `word-word` nickname, from that same wordlist — what
/// `native/game`'s CLI defaults to.
#[wasm_bindgen]
#[must_use]
pub fn random_nick() -> String {
    Nickname::random().to_string()
}
