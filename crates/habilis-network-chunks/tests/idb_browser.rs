//! The browser backend, in a real browser.
//!
//! `IndexedDB` needs a browser, so this cannot ride the native conformance
//! suite — but it is held to the same contract, and the cases below are
//! transcribed from it rather than invented. The predecessor crate shipped its
//! `IndexedDB` backend with **no test coverage at all**, which is exactly the
//! sort of gap that only shows up as a user losing a download.
//!
//! Run with:
//!
//! ```text
//! wasm-pack test --headless --chrome crates/habilis-network-chunks
//! wasm-pack test --headless --safari crates/habilis-network-chunks
//! ```

#[cfg(target_arch = "wasm32")]
#[path = "idb_browser/cases.rs"]
mod cases;
