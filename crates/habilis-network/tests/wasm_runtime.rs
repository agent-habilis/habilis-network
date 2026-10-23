//! The wasm runtime guard: the things that compile fine and then panic.
//!
//! ```sh
//! CC=$(brew --prefix llvm)/bin/clang \
//! CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang \
//!   cargo test -p habilis-network --no-default-features \
//!     --target wasm32-unknown-unknown
//! ```
//!
//! Every wasm breakage this crate has had was invisible to `cargo check`:
//!
//! - `std::time::Instant::now()` and `SystemTime::now()` do not fail to
//!   compile on `wasm32-unknown-unknown`. They compile, and then `panic!`
//!   ("time not implemented on this platform") — and `UnixSecs::now` stamps every
//!   `Message`, so a browser peer could not author a single frame.
//! - `tokio::time` compiles and panics the same way: there is no timer driver.
//! - `tokio::spawn` compiles and panics with "there is no reactor running".
//!   This one shipped: the browser mesh peer died on it at `setup.rs:115`
//!   *after* the wasm CI check was green.
//!
//! So this file's job is not to test logic. It is to **execute** the handful of
//! primitives whose failure mode is a runtime panic, so the next one is caught
//! by CI rather than by a blank browser tab. Keep it cheap and keep it boring;
//! its value is that it runs at all.

#[cfg(target_arch = "wasm32")]
#[path = "wasm_runtime/cases.rs"]
mod cases;
