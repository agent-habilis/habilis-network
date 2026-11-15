//! The terminal `Host`: node arena, layout, paint, color, width, and the
//! diff that turns two painted frames into minimal ANSI. See the crate's
//! top-level docs and the plan's `visage-rust-tui` section for what's
//! ported from `visage-tui` and what's deliberately scoped down for v1.

pub mod arena;
pub mod clip;
pub mod color;
pub mod diff;
pub mod layout;
pub mod layout_state;
pub mod node;
pub mod node_id;
pub mod paint;
pub mod screen_buffer;
pub mod style;
pub mod tag;
pub mod text_align;
pub mod truncate;
pub mod tui_host;
pub mod tui_node;
pub mod width;
pub mod wrap;
