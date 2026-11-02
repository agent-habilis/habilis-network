//! The conformance suite every backend must pass.
//!
//! Written once against the traits, run per backend. That is the whole reason
//! [`ChunkSource`] and [`ChunkStore`] are traits at all: an in-memory map, a
//! directory of files and an `IndexedDB` database differ in every way except the
//! behaviour asserted here — and the expensive failures are behaviour, not
//! implementation. Storing bytes that address something else. Reporting
//! coverage for chunks that are gone. Sweeping away live data.
//!
//! Add a backend by implementing [`Harness`] and adding one `backends!` line.
//! Anything that only passes for one backend is in the wrong file.

// Host-only: these backends are `std::fs`-bound, and a wasm build simply does
// not have them. The browser backend is exercised in `idb_browser.rs`, which
// needs a real browser and a real executor that this suite has neither of.

#[cfg(not(target_arch = "wasm32"))]
#[path = "conformance/cases.rs"]
mod cases;
