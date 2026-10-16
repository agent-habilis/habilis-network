//! A tracing subscriber for tests that fails the test when a WARN or ERROR
//! event is logged.
//!
//! Start each test with `let _log = habilis_network_test_tracing::init();`.
//! The guard must be the first local of the test, so that it drops last and
//! sees the events of every value that the test drops before it.
//!
//! The guards of one binary do not overlap: a guard waits until the thread of
//! the test that held the lock before it has ended, so every event belongs to
//! exactly one test. An event that arrives between the drop of a guard and the
//! end of its thread, for example when a runtime drops its endpoints after the
//! test body, fails the next test with the name of the test that ended.
//!
//! A panic inside the subscriber does not fail a test when a spawned task logs
//! the event, so the subscriber records the event and [`Guard`] panics on the
//! test thread when it drops.

use std::cell::RefCell;
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

static INSTALLED: OnceLock<Mode> = OnceLock::new();
static LIVE: Mutex<Vec<Arc<Slot>>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());
static LATE: Mutex<Late> = Mutex::new(Late {
    ended: None,
    events: Vec::new(),
});
static CAPTURED: Mutex<String> = Mutex::new(String::new());

thread_local! {
    static HELD: RefCell<Option<MutexGuard<'static, ()>>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Stderr,
    Capture,
    Writer,
}

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
/// was [`init_capturing`] or [`init_with_writer`].
#[must_use = "the guard fails the test when it drops; bind it to a local"]
pub fn init() -> Guard {
    install(Mode::Stderr, "", io::stderr);
    new_guard()
}

/// Like [`init`], but the events go to a buffer that [`captured_logs`] returns,
/// for a test that asserts on a log line. `RUST_LOG` wins; without it the
/// filter is `default_directives`. The buffer is shared by the tests of the
/// binary.
///
/// # Panics
///
/// Panics under the same conditions as [`init`].
#[must_use = "the guard fails the test when it drops; bind it to a local"]
pub fn init_capturing(default_directives: &str) -> Guard {
    install(Mode::Capture, default_directives, Capture);
    new_guard()
}

/// Like [`init_capturing`], but the events go to `writer`, for a test that
/// keeps its log in a place of its own. Only the first call of the binary
/// installs `writer`.
///
/// # Panics
///
/// Panics under the same conditions as [`init`].
#[must_use = "the guard fails the test when it drops; bind it to a local"]
pub fn init_with_writer<W>(default_directives: &str, writer: W) -> Guard
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    install(Mode::Writer, default_directives, writer);
    new_guard()
}

/// The log text that [`init_capturing`] collected, for the whole binary. Empty
/// after the other entry points.
#[must_use]
pub fn captured_logs() -> String {
    lock(&CAPTURED).clone()
}

/// Empties the text that [`captured_logs`] returns, for a test that reads the
/// log of its own run when the tests of the binary run one after the other.
pub fn clear_captured_logs() {
    lock(&CAPTURED).clear();
}

fn install<W>(mode: Mode, default_directives: &str, writer: W)
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let installed = *INSTALLED.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default_directives));
        let print = tracing_fmt::layer()
            .with_ansi(mode == Mode::Stderr)
            .with_writer(writer)
            .with_filter(filter);
        tracing_subscriber::registry()
            .with(print)
            .with(Catch.with_filter(LevelFilter::WARN))
            .try_init()
            .expect("another global tracing subscriber is installed");
        mode
    });
    assert_eq!(
        installed, mode,
        "two of init, init_capturing and init_with_writer in the same test binary"
    );
}

fn new_guard() -> Guard {
    let serial = HELD
        .try_with(|held| held.borrow_mut().take())
        .ok()
        .flatten()
        .unwrap_or_else(|| lock(&SERIAL));
    let slot = Arc::new(Slot {
        thread: thread::current().name().unwrap_or_default().to_owned(),
        events: Mutex::new(Vec::new()),
        expected: Mutex::new(Vec::new()),
    });
    let mut live = lock(&LIVE);
    lock(&slot.events).append(&mut lock(&LATE).events);
    live.push(Arc::clone(&slot));
    Guard {
        slot,
        serial: Some(serial),
    }
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
    serial: Option<MutexGuard<'static, ()>>,
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
        {
            let mut live = lock(&LIVE);
            live.retain(|slot| !Arc::ptr_eq(slot, &self.slot));
            lock(&LATE).ended = Some(self.slot.thread.clone());
        }
        if let Some(serial) = self.serial.take() {
            // The lock stays until the thread of the test ends, so the
            // runtime that the test drops after its body still logs to this test.
            let _ = HELD.try_with(|held| *held.borrow_mut() = Some(serial));
        }
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
                Some(want) if logged.after.is_none() => want.seen = true,
                _ if logged.after.is_some() => problems.push(format!(
                    "  logged after test {} ended: {} {}: {} (thread {})",
                    logged.after.as_deref().unwrap_or_default(),
                    logged.level,
                    logged.target,
                    logged.text,
                    logged.thread
                )),
                Some(_) => {}
                None => problems.push(format!(
                    "  unexpected {} {}: {} (thread {}{})",
                    logged.level,
                    logged.target,
                    logged.text,
                    logged.thread,
                    if logged.shared {
                        ", from a worker thread"
                    } else {
                        ""
                    }
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
    shared: bool,
    after: Option<String>,
}

#[derive(Debug)]
struct Late {
    ended: Option<String>,
    events: Vec<Logged>,
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
        let live = lock(&LIVE);
        let own: Vec<_> = live.iter().filter(|slot| slot.thread == thread).collect();
        let shared = own.is_empty();
        let logged = || Logged {
            level: *event.metadata().level(),
            target: event.metadata().target().to_owned(),
            text: fields.text.clone(),
            thread: thread.to_owned(),
            shared,
            after: None,
        };
        if live.is_empty() {
            let mut late = lock(&LATE);
            if let Some(ended) = late.ended.clone() {
                late.events.push(Logged {
                    after: Some(ended),
                    ..logged()
                });
            }
            return;
        }
        let owners = if shared { live.iter().collect() } else { own };
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
