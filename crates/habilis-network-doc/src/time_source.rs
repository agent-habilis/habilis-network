//! Where a document reads the wall clock.

use std::fmt;
use std::sync::Arc;

use habilis_network_util::clock;

/// The wall clock of a state document, in milliseconds since the Unix epoch. The document bounds
/// the time of a change by it (see `DOC_CLOCK_WINDOW`), so a test can set the clock without
/// sleeping.
///
/// # Examples
///
/// A test gives the document the time that it wants.
///
/// ```
/// use habilis_network_doc::TimeSource;
///
/// let source = TimeSource::new(|| 42);
/// assert_eq!(source.now(), 42);
/// ```
#[derive(Clone)]
pub struct TimeSource(
    // Shared: a document clones its source, and a test keeps a handle to the clock that it moves.
    Arc<dyn Fn() -> u64 + Send + Sync>,
);

impl TimeSource {
    /// A source that reads `read`.
    #[must_use]
    pub fn new(read: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        // The shared handle: a document clones its source and the clones read one clock.
        Self(Arc::new(read))
    }

    /// The clock of this machine.
    #[must_use]
    pub fn wall_clock() -> Self {
        Self::new(clock::unix_millis)
    }

    /// The time now, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn now(&self) -> u64 {
        (self.0)()
    }
}

impl Default for TimeSource {
    /// The unit tests of this crate read a clock that stays at 0, so their small Lamport times
    /// stay small. A build for anything else reads the wall clock.
    fn default() -> Self {
        if cfg!(test) {
            Self::new(|| 0)
        } else {
            Self::wall_clock()
        }
    }
}

impl fmt::Debug for TimeSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TimeSource")
    }
}
