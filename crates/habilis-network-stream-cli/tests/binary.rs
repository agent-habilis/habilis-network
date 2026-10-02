//! The `habilis-network-stream` binary end to end, with no browser: one process streams
//! its stdin, a second reads the hash to its stdout, and both meet on an
//! in-process relay. This is the end-to-end test CI runs on every change; the
//! browser suite (`cargo task e2e --suite stream`) runs in its own workflow.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_habilis-network-stream");
/// A relay dial, a direct path and the whole payload on one machine.
const BUDGET: Duration = Duration::from_mins(1);

/// Bytes that are not text, so a lossy decode anywhere would show.
fn payload(len: usize) -> Vec<u8> {
    let mut state: u32 = 0x9E37_79B9;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// A producer on `relay`, with `--robot` notes on stderr, sent line by line.
fn producer(relay: &str) -> (Child, mpsc::Receiver<serde_json::Value>) {
    let mut child = Command::new(BINARY)
        .args(["--lookup", "relay", "--relay-url", relay, "--robot"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the producer");
    let stderr = child.stderr.take().expect("stderr");
    let (notes, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Ok(note) = serde_json::from_str(&line)
                && notes.send(note).is_err()
            {
                break;
            }
        }
    });
    (child, received)
}

/// The first note of `kind`, within the budget.
fn note(notes: &mpsc::Receiver<serde_json::Value>, kind: &str, text: &str) -> serde_json::Value {
    let deadline = Instant::now() + BUDGET;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let note = notes.recv_timeout(left).expect("the note in time");
        if note["kind"] == kind && (text.is_empty() || note["text"] == text) {
            return note;
        }
    }
}

/// The exit code, within the budget.
fn exit_code(child: &mut Child) -> Option<i32> {
    let deadline = Instant::now() + BUDGET;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("wait") {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("the process did not exit in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bytes_piped_in_come_out_of_another_binary_byte_exact() {
    let (url, _relay) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("relay");
    let url = url.to_string();
    tokio::task::spawn_blocking(move || {
        let sent = payload(8 * 1024 * 1024);
        let (mut producer, notes) = producer(&url);
        // Written now, before any reader exists, and closed: the producer, not
        // the caller, waits for the reader.
        let mut stdin = producer.stdin.take().expect("stdin");
        let input = sent.clone();
        std::thread::spawn(move || stdin.write_all(&input));

        let ready = note(&notes, "ready", "");
        let hash = ready["hash"].as_str().expect("a hash").to_owned();
        let mut reader = Command::new(BINARY)
            .arg(&hash)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the reader");
        let mut got = Vec::new();
        reader
            .stdout
            .take()
            .expect("stdout")
            .read_to_end(&mut got)
            .expect("read");

        assert_eq!(got.len(), sent.len(), "every byte arrives");
        assert!(got == sent, "the bytes arrive unchanged and in order");
        assert_eq!(exit_code(&mut reader), Some(0), "the reader sees the end");
        assert_eq!(
            exit_code(&mut producer),
            Some(0),
            "the producer closes clean"
        );
    })
    .await
    .expect("the test body");
}

/// A stopped producer tells its reader at once: the reader gets "abandoned"
/// and exits 1, instead of waiting out the idle timeout for a lost link.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_producer_stopped_by_sigterm_abandons_its_reader_at_once() {
    let (url, _relay) = habilis_network::net::test_relay::spawn_plain()
        .await
        .expect("relay");
    let url = url.to_string();
    tokio::task::spawn_blocking(move || {
        let (mut producer, notes) = producer(&url);
        // Held open: the input never ends by itself.
        let _stdin = producer.stdin.take().expect("stdin");
        let hash = note(&notes, "ready", "")["hash"]
            .as_str()
            .expect("a hash")
            .to_owned();
        let mut reader = Command::new(BINARY)
            .arg(&hash)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the reader");
        note(&notes, "note", "a reader attached; streaming stdin");

        let stopped = Instant::now();
        let killed = Command::new("kill")
            .args(["-TERM", &producer.id().to_string()])
            .status()
            .expect("kill");
        assert!(killed.success());
        assert_eq!(exit_code(&mut producer), Some(143), "the SIGTERM exit code");
        assert_eq!(exit_code(&mut reader), Some(1), "the reader fails");
        let waited = stopped.elapsed();
        let mut error = String::new();
        reader
            .stderr
            .take()
            .expect("stderr")
            .read_to_string(&mut error)
            .expect("stderr");
        assert!(
            error.contains("the producer abandoned the stream"),
            "{error}"
        );
        // Well under the ~34 s idle timeout a lost link would take, with room
        // for a cold runner.
        assert!(waited < Duration::from_secs(20), "took {waited:?}");
    })
    .await
    .expect("the test body");
}
