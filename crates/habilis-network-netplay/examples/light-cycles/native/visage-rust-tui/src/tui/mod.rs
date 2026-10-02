//! The terminal `Host`: node arena, layout, paint, color, width, and the
//! diff that turns two painted frames into minimal ANSI. See the crate's
//! top-level docs and the plan's `visage-rust-tui` section for what's
//! ported from `visage-tui` and what's deliberately scoped down for v1.

pub mod color;
pub mod diff;
pub mod host_impl;
pub mod layout;
pub mod node;
pub mod paint;
pub mod width;
