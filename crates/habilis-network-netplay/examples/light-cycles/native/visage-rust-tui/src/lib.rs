//! A Rust port, for `light-cycles`' native client, of `visage-dom`'s
//! generator/signal reactive core and `visage-tui`'s terminal diffing —
//! see the plan's `visage-rust-tui` section for scope and provenance.
//!
//! Uses native Rust generators (nightly-only; see `native/rust-toolchain.toml`)
//! rather than a stable-Rust emulation crate — a component is written
//! directly with the `yield` keyword:
//!
//! ```ignore
//! use visage_rust_tui::component::{Instance, Yield};
//! use visage_rust_tui::reactive::Signal;
//! use visage_rust_tui::view::View;
//!
//! let count = Signal::new(0);
//! let count_in_component = count.clone();
//! let mut instance = Instance::new(0, #[coroutine] move || {
//!     loop {
//!         let n = count_in_component.get();
//!         yield Yield::View(View::text(format!("count is {n}")));
//!     }
//! });
//! ```
//!
//! Module map:
//! - [`reactive`] — `Signal<T>`, tracked reads, the update queue.
//! - [`component`] — the coroutine-driven `Instance`, thunk/loop
//!   classification.
//! - [`view`] — the declarative `View` tree a component yields.
//! - [`host`] — the `Host` trait a reconciler patches.
//! - [`reconcile`] — a non-keyed `View -> Host` patcher (v1 scope; see its
//!   doc comment for what's deliberately not a fiber/LIS port).
//! - [`tui`] — the terminal `Host`: node arena, layout, paint, diff.
//! - [`runtime`] — wires the above together for a single-root app.

#![feature(coroutines, coroutine_trait)]
// This crate's `HashSet<SignalId>`/`HashSet<SubscriberId>` never take a
// custom hasher anywhere, so generalizing every dependency-set-taking
// function over `BuildHasher` (clippy's default suggestion) would be
// genericity with no real caller.
#![allow(clippy::implicit_hasher)]

pub mod component;
pub mod host;
pub mod reactive;
pub mod reconcile;
pub mod runtime;
pub mod tui;
pub mod view;

pub use component::{Instance, Yield};
pub use host::Host;
pub use reactive::Signal;
pub use runtime::Runtime;
pub use view::View;
