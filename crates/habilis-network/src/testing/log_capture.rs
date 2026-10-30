#[cfg(feature = "multihop")]
use std::sync::Arc;

#[cfg(feature = "multihop")]
#[cfg(feature = "multihop")]
use std::io;
#[cfg(feature = "multihop")]
#[cfg(feature = "multihop")]
use std::sync;
#[cfg(feature = "multihop")]
#[cfg(feature = "multihop")]
use tracing::subscriber;
/// The logs that a test captured from its own thread, see [`LogCapture::start`].
#[cfg(feature = "multihop")]
#[derive(Clone, Default)]
// the capture and its writer share one buffer, which the test reads
pub(crate) struct LogCapture(Arc<sync::Mutex<Vec<u8>>>);

#[cfg(feature = "multihop")]
impl LogCapture {
    /// Capture every event up to `level` that the calling thread logs, until the guard drops.
    pub(crate) fn start(level: tracing::Level) -> (Self, subscriber::DefaultGuard) {
        // While one dispatcher is the only one registered, `tracing` answers the interest of a
        // callsite from the default of the thread that hits it first. A parallel test thread
        // with no default of its own then caches "never" on a callsite that this capture
        // needs, and the event is dropped. A second dispatcher, kept for the whole process,
        // makes `tracing` ask every registered dispatcher instead.
        static SECOND_DISPATCHER: sync::OnceLock<tracing::Dispatch> = sync::OnceLock::new();
        SECOND_DISPATCHER
            .get_or_init(|| tracing::Dispatch::new(subscriber::NoSubscriber::default()));
        let capture = Self::default();
        let writer = capture.clone();
        let make_writer = move || writer.clone();
        let builder = tracing_subscriber::fmt().with_writer(make_writer);
        let subscriber = builder.with_ansi(false).with_max_level(level).finish();
        let guard = subscriber::set_default(subscriber);
        (capture, guard)
    }

    /// Everything that was captured so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log buffer")).into_owned()
    }
}

#[cfg(feature = "multihop")]
impl io::Write for LogCapture {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
