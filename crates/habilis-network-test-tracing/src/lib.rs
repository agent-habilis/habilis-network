//! A tracing subscriber for tests that fails the test when a WARN or ERROR
//! event is logged.
//!
//! Start each test with `let _log = habilis_network_test_tracing::init();`.
//! The guard must be the first local of the test, so that it drops last and
//! sees the events of every value that the test drops before it.
//!
//! Tests run side by side. An event belongs to the test whose thread logs it,
//! or whose runtime logs it: the worker threads of a runtime that [`run`] or
//! [`run_multi_thread`] build carry the name of their test. They replace
//! `#[tokio::test]`, and they drop the runtime before the guard, so the events
//! of the endpoints that the runtime drops belong to the test too. An event of
//! a thread that no test owns is filed under every live test, and the failure
//! text names them all.
//!
//! An event of the worker of a test that ended, or an event that comes while no
//! test is live, is kept and fails the next guard with the name of the test that
//! ended. A binary that logs such an event after its last guard has nobody to
//! fail, so it exits with 101.
//!
//! A panic inside the subscriber does not fail a test when a spawned task logs
//! the event, so the subscriber records the event and [`Guard`] panics on the
//! test thread when it drops.

use std::fmt::{self, Write as _};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;

pub use habilis_network_test_tracing_macros::test;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{Layer, fmt as tracing_fmt};

static INSTALLED: OnceLock<Mode> = OnceLock::new();
static LIVE: Mutex<Vec<Arc<Slot>>> = Mutex::new(Vec::new());
static LATE: Mutex<Late> = Mutex::new(Late {
    ended: None,
    events: Vec::new(),
});
static CAPTURED: Mutex<String> = Mutex::new(String::new());

/// The end of the name of a thread that a runtime of this crate starts for a test.
const WORKER: &str = "/worker";

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

/// Like [`Guard::expect_warn`], for the test of the calling thread, which the
/// `test` attribute guards: the guard is out of its reach.
///
/// # Panics
///
/// Panics if the calling thread is not the thread of a live guard.
pub fn expect_warn(target: &str, text: &str) {
    let current = thread::current();
    let name = current.name().unwrap_or_default();
    let live = lock(&LIVE);
    let slot = live
        .iter()
        .find(|slot| slot.thread == name)
        .unwrap_or_else(|| panic!("expect_warn outside a guarded test (thread {name})"));
    lock(&slot.expected).push(Expectation {
        target: target.to_owned(),
        text: text.to_owned(),
        seen: false,
    });
}

/// Whether the test of the calling thread has logged a WARN from `target` (a
/// module path prefix) whose message contains `text`. A test that expects the
/// WARN with [`Guard::expect_warn`] polls it to wait until the WARN came.
#[must_use]
pub fn saw_warn(target: &str, text: &str) -> bool {
    let current = thread::current();
    let name = current.name().unwrap_or_default();
    lock(&LIVE)
        .iter()
        .filter(|slot| slot.thread == name)
        .any(|slot| {
            lock(&slot.events).iter().any(|logged| {
                logged.level == Level::WARN
                    && logged.target.starts_with(target)
                    && logged.text.contains(text)
            })
        })
}

/// Runs `future` to its end on a current-thread runtime, drops the runtime,
/// then drops `guard`. Use it in place of `#[tokio::test]`.
///
/// # Panics
///
/// Panics if the runtime cannot be built.
#[cfg(not(target_arch = "wasm32"))]
pub fn run<F: Future>(guard: Guard, future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .thread_name(worker_name())
        .enable_all()
        .build()
        .expect("runtime");
    let output = runtime.block_on(future);
    drop(runtime);
    drop(guard);
    output
}

/// Like [`run`], on a multi-thread runtime with `worker_threads` workers. Use it
/// in place of `#[tokio::test(flavor = "multi_thread", worker_threads = N)]`.
///
/// # Panics
///
/// Panics if the runtime cannot be built.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_multi_thread<F: Future>(guard: Guard, worker_threads: usize, future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name(worker_name())
        .enable_all()
        .build()
        .expect("runtime");
    let output = runtime.block_on(future);
    drop(runtime);
    drop(guard);
    output
}

/// The name of the threads of a runtime that a test starts: its own name and `WORKER`.
#[cfg(not(target_arch = "wasm32"))]
fn worker_name() -> String {
    format!("{}{WORKER}", thread::current().name().unwrap_or_default())
}

#[cfg(not(target_arch = "wasm32"))]
#[expect(unsafe_code, reason = "libc::atexit and libc::_exit are FFI calls")]
fn fail_the_binary_on_a_late_event_at_exit() {
    static REGISTERED: std::sync::Once = std::sync::Once::new();
    extern "C" fn at_exit() {
        let Ok(late) = LATE.try_lock() else { return };
        if late.events.is_empty() {
            return;
        }
        for logged in &late.events {
            eprintln!("{}", late_line(logged));
        }
        // SAFETY: `_exit` ends the process at once and runs no Rust code.
        unsafe { libc::_exit(101) }
    }
    REGISTERED.call_once(|| {
        // SAFETY: `at_exit` is an `extern "C" fn` that takes no argument.
        unsafe {
            libc::atexit(at_exit);
        }
    });
}

fn install<W>(mode: Mode, default_directives: &str, writer: W)
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    #[cfg(not(target_arch = "wasm32"))]
    fail_the_binary_on_a_late_event_at_exit();
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
    let thread = thread::current().name().unwrap_or_default().to_owned();
    assert!(
        thread.is_empty() || !lock(&LIVE).iter().any(|slot| slot.thread == thread),
        "init() twice in one test (thread {thread}): a test has one guard"
    );
    let slot = Arc::new(Slot {
        thread,
        events: Mutex::new(Vec::new()),
        expected: Mutex::new(Vec::new()),
    });
    let mut live = lock(&LIVE);
    lock(&slot.events).append(&mut lock(&LATE).events);
    live.push(Arc::clone(&slot));
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
        {
            let mut live = lock(&LIVE);
            live.retain(|slot| !Arc::ptr_eq(slot, &self.slot));
            lock(&LATE).ended = Some(self.slot.thread.clone());
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
                _ if logged.after.is_some() => problems.push(late_line(logged)),
                Some(_) => {}
                None => problems.push(format!(
                    "  unexpected {} {}: {} (thread {}{})",
                    logged.level,
                    logged.target,
                    logged.text,
                    logged.thread,
                    worker_note(logged)
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
    /// The live tests that the event is filed under, when there is more than one.
    shared_with: Vec<String>,
    after: Option<String>,
}

fn worker_note(logged: &Logged) -> String {
    if !logged.shared {
        String::new()
    } else if logged.shared_with.is_empty() {
        ", from a worker thread".to_owned()
    } else {
        format!(
            ", from a worker thread, while these tests ran: {}",
            logged.shared_with.join(", ")
        )
    }
}

fn late_line(logged: &Logged) -> String {
    format!(
        "  logged after test {} ended: {} {}: {} (thread {})",
        logged.after.as_deref().unwrap_or_default(),
        logged.level,
        logged.target,
        logged.text,
        logged.thread
    )
}

#[derive(Debug)]
struct Late {
    ended: Option<String>,
    events: Vec<Logged>,
}

/// An event of the thread of a live test, or of a worker of its runtime, is filed
/// under that test. An event of a worker of a test that ended is kept as late.
/// Any other thread (a thread of iroh) is filed under every live test, because
/// the layer cannot tell which test the thread works for.
struct Catch;

impl<S: Subscriber> Layer<S> for Catch {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let current = thread::current();
        let thread = current.name().unwrap_or("unnamed");
        let test = thread.strip_suffix(WORKER).unwrap_or(thread);
        let live = lock(&LIVE);
        let own: Vec<_> = live.iter().filter(|slot| slot.thread == test).collect();
        let shared = own.is_empty();
        let logged = || Logged {
            level: *event.metadata().level(),
            target: event.metadata().target().to_owned(),
            text: fields.text.clone(),
            thread: thread.to_owned(),
            shared,
            shared_with: Vec::new(),
            after: None,
        };
        let ended_worker = shared && test != thread;
        if live.is_empty() || ended_worker {
            let mut late = lock(&LATE);
            let ended = if ended_worker {
                Some(test.to_owned())
            } else {
                late.ended.clone()
            };
            if let Some(ended) = ended {
                late.events.push(Logged {
                    after: Some(ended),
                    ..logged()
                });
            }
            return;
        }
        if !shared {
            for slot in own {
                lock(&slot.events).push(logged());
            }
            return;
        }
        let mut shared_with: Vec<String> = if live.len() > 1 {
            live.iter().map(|slot| slot.thread.clone()).collect()
        } else {
            Vec::new()
        };
        shared_with.sort();
        for slot in live.iter() {
            lock(&slot.events).push(Logged {
                shared_with: shared_with.clone(),
                ..logged()
            });
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
