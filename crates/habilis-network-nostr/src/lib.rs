//! A small Nostr relay client: signed ephemeral events on public relays, one
//! shared socket per relay, and a pool that keeps the healthiest few open.
//!
//! The crate knows nothing about meshes. A caller picks the tags, ranks the
//! relays, and seals its own payload into each event's `content`.

mod conn;
mod event;
mod pool;
mod wire;
#[cfg(not(target_arch = "wasm32"))]
mod ws;
#[cfg(target_arch = "wasm32")]
#[path = "ws_web.rs"]
mod ws;

#[cfg(all(feature = "test-relay", not(target_arch = "wasm32")))]
pub mod test_relay;

pub use event::{Event, Keys, TAG, kind_for};
pub use pool::Pool;

/// Seconds since the Unix epoch, on the portable clock (std on a host,
/// `Date.now()` in a browser, where `std::time::SystemTime::now` panics).
pub(crate) fn unix_now() -> u64 {
    n0_future::time::SystemTime::now()
        .duration_since(n0_future::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
