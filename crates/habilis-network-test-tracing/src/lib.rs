//! A tracing subscriber for tests that fails the test when a WARN or ERROR
//! event is logged.
//!
//! Start each test with `let _log = habilis_network_test_tracing::init();`.
//! The guard must be the first local of the test, so that it drops last and
//! sees the events of every value that the test drops before it.
//!
//! A panic inside the subscriber does not fail a test when a spawned task logs
//! the event, so the subscriber records the event and [`Guard`] panics on the
//! test thread when it drops.

use std::fmt::{self, Write as _};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{Layer, fmt as tracing_fmt};

static INSTALLED: OnceLock<bool> = OnceLock::new();
static LIVE: Mutex<Vec<Arc<Slot>>> = Mutex::new(Vec::new());
static CAPTURED: Mutex<String> = Mutex::new(String::new());

/// Installs the subscriber on the first call and returns the guard of the
/// calling test.
///
/// The events print to stderr as they do with `tracing_subscriber::fmt()`,
/// filtered by `RUST_LOG`. The guard sees every WARN and ERROR event, whatever
/// `RUST_LOG` says.
///
/// # Panics
///
/// Panics if another global subscriber is already installed, because the
/// guard would never see an event. Panics if an earlier call in this binary
/// was [`init_capturing`].
#[must_use = "the guard fails the test when it drops; bind it to a local"]
pub fn init() -> Guard {
    install(false, "");
    new_guard()
}

/// Like [`init`], but the events go to a buffer that [`captured_logs`] returns,
/// for a test that asserts on a log line. `RUST_LOG` wins; without it the
/// filter is `default_directives`. The buffer is shared by the tests of the
/// binary.
///
/// # Panics
///
/// Panics under the same conditions as [`init`], and if an earlier call in
/// this binary was [`init`].
#[must_use = "the guard fails the test when it drops; bind it to a local"]
pub fn init_capturing(default_directives: &str) -> Guard {
    install(true, default_directives);
    new_guard()
}

/// The log text that [`init_capturing`] collected, for the whole binary. Empty
/// after [`init`].
#[must_use]
pub fn captured_logs() -> String {
    lock(&CAPTURED).clone()
}

fn install(capturing: bool, default_directives: &str) {
    let installed = *INSTALLED.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default_directives));
        let result = if capturing {
            let print = tracing_fmt::layer()
                .with_ansi(false)
                .with_writer(Capture)
                .with_filter(filter);
            tracing_subscriber::registry()
                .with(print)
                .with(Catch.with_filter(LevelFilter::WARN))
                .try_init()
        } else {
            let print = tracing_fmt::layer().with_filter(filter);
            tracing_subscriber::registry()
                .with(print)
                .with(Catch.with_filter(LevelFilter::WARN))
                .try_init()
        };
        result.expect("another global tracing subscriber is installed");
        capturing
    });
    assert_eq!(
        installed, capturing,
        "init and init_capturing in the same test binary"
    );
}

fn new_guard() -> Guard {
    let slot = Arc::new(Slot {
        thread: thread::current().name().unwrap_or_default().to_owned(),
        events: Mutex::new(Vec::new()),
        expected: Mutex::new(Vec::new()),
    });
    lock(&LIVE).push(Arc::clone(&slot));
    Guard { slot }
}

struct Capture;

impl<'writer> MakeWriter<'writer> for Capture {
    type Writer = CaptureWriter;

    fn make_writer(&'writer self) -> CaptureWriter {
        CaptureWriter
    }
}

struct CaptureWriter;

impl io::Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        lock(&CAPTURED).push_str(&String::from_utf8_lossy(bytes));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Fails the test, when it drops, if the test logged a WARN or ERROR event
/// that it did not expect, or did not log a WARN event that it expected.
#[derive(Debug)]
pub struct Guard {
    slot: Arc<Slot>,
}

impl Guard {
    /// Asserts that the test logs a WARN event from `target` (a module path
    /// prefix) whose message contains `text`. Use it only where the warning
    /// is the subject of the test; fix the code for every other warning.
    pub fn expect_warn(&self, target: &str, text: &str) {
        lock(&self.slot.expected).push(Expectation {
            target: target.to_owned(),
            text: text.to_owned(),
            seen: false,
        });
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        lock(&LIVE).retain(|slot| !Arc::ptr_eq(slot, &self.slot));
        if thread::panicking() {
            return;
        }
        let problems = self.slot.problems();
        assert!(
            problems.is_empty(),
            "the test logged:\n{}",
            problems.join("\n")
        );
    }
}

#[derive(Debug)]
struct Slot {
    thread: String,
    events: Mutex<Vec<Logged>>,
    expected: Mutex<Vec<Expectation>>,
}

impl Slot {
    fn problems(&self) -> Vec<String> {
        let mut expected = lock(&self.expected);
        let mut problems = Vec::new();
        for logged in lock(&self.events).iter() {
            let hit = expected
                .iter_mut()
                .find(|want| logged.level == Level::WARN && want.matches(logged));
            match hit {
                Some(want) => want.seen = true,
                None => problems.push(format!(
                    "  unexpected {} {}: {} (thread {})",
                    logged.level, logged.target, logged.text, logged.thread
                )),
            }
        }
        for want in expected.iter().filter(|want| !want.seen) {
            problems.push(format!(
                "  expected WARN {} containing {:?}, and it was not logged",
                want.target, want.text
            ));
        }
        problems
    }
}

#[derive(Debug)]
struct Expectation {
    target: String,
    text: String,
    seen: bool,
}

impl Expectation {
    fn matches(&self, logged: &Logged) -> bool {
        logged.target.starts_with(&self.target) && logged.text.contains(&self.text)
    }
}

#[derive(Debug)]
struct Logged {
    level: Level,
    target: String,
    text: String,
    thread: String,
}

/// A thread that is the thread of a live test files the event under that test.
/// Any other thread (a runtime worker, a thread of iroh) files it under every
/// live test, because the layer cannot tell which test the thread works for.
struct Catch;

impl<S: Subscriber> Layer<S> for Catch {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let current = thread::current();
        let thread = current.name().unwrap_or("unnamed");
        let logged = || Logged {
            level: *event.metadata().level(),
            target: event.metadata().target().to_owned(),
            text: fields.text.clone(),
            thread: thread.to_owned(),
        };
        let live = lock(&LIVE);
        let own: Vec<_> = live.iter().filter(|slot| slot.thread == thread).collect();
        let owners = if own.is_empty() {
            live.iter().collect()
        } else {
            own
        };
        for slot in owners {
            lock(&slot.events).push(logged());
        }
    }
}

#[derive(Default)]
struct Fields {
    text: String,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if !self.text.is_empty() {
            self.text.push(' ');
        }
        let _ = if field.name() == "message" {
            write!(self.text, "{value:?}")
        } else {
            write!(self.text, "{}={value:?}", field.name())
        };
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
