//! A small Nostr relay client: signed ephemeral events on public relays, one
//! shared socket per relay, and a pool that keeps the healthiest few open.
//!
//! The crate knows nothing about meshes. A caller picks the tags, ranks the
//! relays, and seals its own payload into each event's `content`.
//!
//! # Examples
//!
//! A pool opens one relay, publishes an event under a tag, and reads what
//! members of that tag publish. The doc test compiles it but does not run it.
//!
//! ```no_run
//! use habilis_network_iroh_nostr_address_lookup::{Lane, Pool};
//!
//! # async fn demo() {
//! let relays = vec!["wss://relay.example".parse().expect("a relay URL")];
//! let tag = [7u8; 32];
//! let (pool, mut events) = Pool::open(Lane::Signal, relays, 1, &[tag]);
//! pool.publish(&tag, "hello".to_owned());
//! if let Some(event) = events.recv().await {
//!     println!("{}", event.content);
//! }
//! # }
//! ```

use n0_future::time;
mod event;
mod event_error;
mod hub;
mod lane;
mod pool;
mod wire;
#[cfg(not(target_arch = "wasm32"))]
#[path = "native/sender.rs"]
mod ws;
#[cfg(target_arch = "wasm32")]
#[path = "web/sender.rs"]
mod ws;

#[cfg(all(feature = "test-relay", not(target_arch = "wasm32")))]
pub mod test_relay;

pub use event::{Event, Keys, TAG, kind_for};
pub use event_error::EventError;
pub use lane::{DATA_KIND_START, LANE_KIND_SPAN, Lane, SIGNAL_KIND_START};
pub use pool::Pool;

/// Seconds since the Unix epoch, on the portable clock (std on a host,
/// `Date.now()` in a browser, where `std::time::SystemTime::now` panics).
pub(crate) fn unix_now() -> u64 {
    time::SystemTime::now()
        .duration_since(time::SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
