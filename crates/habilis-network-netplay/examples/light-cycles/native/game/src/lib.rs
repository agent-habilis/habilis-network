//! The native `light-cycles` client, as a library: game logic, the
//! `habilis-network-netplay` embedding, and terminal rendering. Split out from
//! `main.rs` (a thin CLI shell around this) specifically so the
//! `tests/` integration tests can drive `Game` directly — for a
//! binary-only crate, an integration test would have no way to reach any
//! of this at all.
//!
//! The unstable-feature gate lives here, not in `main.rs`: only `ui.rs`
//! writes components with the bare `yield` keyword, and that code lives
//! in this library. See `native/rust-toolchain.toml` for why `native/` is
//! pinned to a specific nightly.
#![feature(coroutines, yield_expr)]

pub mod app;
pub mod grid;
pub mod round;
pub mod sim;
pub mod ui;
