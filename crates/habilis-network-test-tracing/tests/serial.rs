//! The guards of one binary do not overlap, so an event from a runtime worker
//! belongs to exactly one test. Each probe fails if another probe holds a
//! guard at the same time.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::Duration;

use habilis_network_test_tracing::init;

static HOLDING: AtomicUsize = AtomicUsize::new(0);

fn probe() {
    let _log = init();
    let others = HOLDING.fetch_add(1, Ordering::SeqCst);
    sleep(Duration::from_millis(300));
    HOLDING.fetch_sub(1, Ordering::SeqCst);
    assert_eq!(others, 0, "another test held a guard at the same time");
}

#[test]
fn the_first_probe_holds_the_only_guard() {
    probe();
}

#[test]
fn the_second_probe_holds_the_only_guard() {
    probe();
}

#[test]
fn the_third_probe_holds_the_only_guard() {
    probe();
}
