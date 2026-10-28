use std::time::{Duration, Instant};

/// Poll `probe` until it yields a value, or give up.
///
/// Used for everything that comes up asynchronously — the harness server's
/// socket, a driver's `/status`, the page's `#matrix-done` — so each of them
/// gets a bounded wait instead of an unbounded one.
pub(crate) fn wait_for<T>(
    timeout: Duration,
    interval: Duration,
    mut probe: impl FnMut() -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = probe() {
            return Some(value);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(interval);
    }
}
