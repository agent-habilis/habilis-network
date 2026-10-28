use wasm_bindgen::prelude::wasm_bindgen;

/// Route the engine's `tracing` lines — the mesh census, `relay-only path
/// refused`, per-peer path readings — to the browser console. `filter` is an
/// `EnvFilter` string (`habilis_network=info,habilis_network::lifecycle=debug`); an invalid
/// one falls back to `info`. One-shot: a second call is a no-op, so a page
/// can call it unconditionally.
#[wasm_bindgen(js_name = initTracing)]
pub fn init_tracing(filter: &str) {
    use tracing_subscriber::fmt::format::FmtSpan;
    let env_filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // The default fmt timer reads `std::time::SystemTime`, which panics on
    // wasm32-unknown; `without_time` sidesteps it.
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_span_events(FmtSpan::NONE)
        .with_writer(console_writer::MakeConsoleWriter)
        .with_env_filter(env_filter)
        .try_init();
}

/// A `MakeWriter` that hands each formatted line to `console.log`.
mod console_writer {
    use std::io;

    pub(crate) struct MakeConsoleWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeConsoleWriter {
        type Writer = ConsoleWriter;

        fn make_writer(&'a self) -> Self::Writer {
            ConsoleWriter(Vec::new())
        }
    }

    /// Buffers one event's bytes; the flush on drop is what reaches the
    /// console, because `fmt` writes an event in several small writes.
    pub(crate) struct ConsoleWriter(Vec<u8>);

    impl io::Write for ConsoleWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.0.is_empty() {
                return Ok(());
            }
            let text = String::from_utf8_lossy(&self.0);
            web_sys::console::log_1(&text.trim_end().into());
            self.0.clear();
            Ok(())
        }
    }

    impl Drop for ConsoleWriter {
        fn drop(&mut self) {
            let _ = io::Write::flush(self);
        }
    }
}
