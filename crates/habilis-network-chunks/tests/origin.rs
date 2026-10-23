//! The non-owning half: serving the user's own files where they already sit.
//!
//! [`FsOrigin`] is the reason this crate exists rather than reaching for an
//! ordinary content-addressed store. It answers a bare chunk address — no file,
//! no offset, because that is all a peer sends — by resolving it back to a place
//! on disk and reading through. Nothing is copied, so publishing a large tree
//! costs a `stat` walk plus one read per file anyone actually asks about.
//!
//! The cases below are the ones where "read through to a file we do not own"
//! differs from "keep a copy", which is where the bugs live.

// Host-only: these backends are `std::fs`-bound, and a wasm build simply does
// not have them. The browser backend is exercised in `idb_browser.rs`, which
// needs a real browser and a real executor that this suite has neither of.

#[cfg(not(target_arch = "wasm32"))]
#[path = "origin/cases.rs"]
mod cases;
