//! A //! signal reactive core and `visage-tui`'s terminal diffing —
//! see the plan's `visage-rust-tui` section for scope and provenance.
//!
//! A component is a type that implements [`component::Component`], stepped by
//! the runtime on each render. It is plain stable Rust:
//!
//! ```ignore
//! use visage_rust_tui::component::{Component, Instance, Step};
//! use visage_rust_tui::reactive::Signal;
//! use visage_rust_tui::view::View;
//!
//! struct Count(Signal<i32>);
//!
//! impl Component for Count {
//!     fn step(&mut self) -> Option<Step> {
//!         Some(Step::View(View::text(format!("count is {}", self.0.get()))))
//!     }
//! }
//!
//! let count = Signal::new(0);
//! let mut instance = Instance::new(Count(count.clone()));
//! ```
//!
//! Module map:
//! - [`reactive`] — `Signal<T>`, tracked reads, the update queue.
//! - [`component`] — the `Component` trait, the `Instance` that steps it, and
//!   thunk/loop classification.
//! - [`view`] — the declarative `View` tree a component produces.
//! - [`host`] — the `Host` trait a reconciler patches.
//! - [`reconcile`] — a non-keyed `View -> Host` patcher (v1 scope; see its
//!   doc comment for what's deliberately not a fiber/LIS port).
//! - [`tui`] — the terminal `Host`: node arena, layout, paint, diff.
//! - [`runtime`] — wires the above together for a single-root app.

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

pub use component::{Component, Instance, Step};
pub use host::Host;
pub use reactive::Signal;
pub use runtime::Runtime;
pub use view::View;
