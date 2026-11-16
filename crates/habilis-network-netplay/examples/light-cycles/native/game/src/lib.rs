//! The native `light-cycles` client, as a library: game logic, the
//! `habilis-network-netplay` embedding, and terminal rendering. Split out from
//! `main.rs` (a thin CLI shell around this) specifically so the
//! `tests/` integration tests can drive `Game` directly — for a
//! binary-only crate, an integration test would have no way to reach any
//! of this at all.

#![cfg_attr(target_family = "wasm", deny(clippy::disallowed_methods))]

pub mod cycle;
pub mod dir;
pub mod game;
pub mod grid;
pub mod input;
pub mod light_cycles;
pub mod outcome;
pub mod round;
pub mod round_descriptor;
pub mod sim;
pub mod snapshot;
pub mod spawn;
pub mod split_mix64;
pub mod ui;
pub mod ui_component;
pub mod world;
