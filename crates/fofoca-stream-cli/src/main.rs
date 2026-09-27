//! `fofoca-stream`: stdin to one reader, or a stream's bytes to stdout.
//!
//! ```text
//! cat lorem.txt | fofoca-stream --web-url http://127.0.0.1:3020/
//! fofoca-stream <hash> > received.txt
//! ```
//!
//! Stdout is the byte stream and nothing else: every word this binary has to
//! say — the hash, the URL to open — goes to stderr, as prose or (`--robot`)
//! as one JSON object per line.
//!
//! With a hash it reads that stream to stdout and exits at its end. Without
//! one, stdin must be a pipe or a file: it creates a stream, prints its hash,
//! waits for the one reader, streams stdin to it, and ends the stream at EOF.
//! The bytes ride a direct path by default (the relay only with
//! `--transport p2p,relay`), never gossip, and the reader paces the writer.

mod args;

use std::io::{IsTerminal as _, Write as _};

use anyhow::{Context as _, Result, bail};
use clap::Parser as _;
use fofoca_stream::{Producer, StreamHash, StreamNode};
use tokio::sync::mpsc;

use crate::args::Args;

/// How much of stdin one write carries.
const CHUNK: usize = 64 * 1024;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fofoca=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    run(&Args::parse()).await
}

/// The node outlives the stream work, and is closed after it however it
/// ended, a stop signal included: closing is what gets a dropped stream's
/// `ABANDONED` to the peer. Exiting straight from the signal lost that race
/// about one time in five on Ctrl-C and every time on SIGTERM, and the peer
/// then waited out the idle timeout.
async fn run(args: &Args) -> Result<()> {
    let (node, outcome) = if let Some(hash) = &args.hash {
        let hash: StreamHash = hash.parse()?;
        let node = StreamNode::bind_for(&hash).await?;
        let outcome = until_stopped(read(args, &node, &hash)).await;
        (node, outcome)
    } else {
        if std::io::stdin().is_terminal() {
            bail!("pipe data in to stream it, or pass a hash to read one");
        }
        let node = StreamNode::bind(&args.opts()).await?;
        let outcome = until_stopped(produce(args, &node)).await;
        (node, outcome)
    };
    if let Err(code) = outcome {
        note(args, &format!("stopped by a signal (exit {code})"));
    }
    // A second signal during the close means leave now, flush or not.
    tokio::select! {
        () = node.close() => {}
        _ = stop_signal() => {}
    }
    outcome.unwrap_or_else(|code| std::process::exit(code))
}

/// `work`'s outcome, or the exit code of the signal that stopped it. Either
/// way `work` is dropped by the time this returns.
async fn until_stopped(work: impl Future<Output = Result<()>>) -> Result<Result<()>, i32> {
    tokio::select! {
        outcome = work => Ok(outcome),
        code = stop_signal() => Err(code),
    }
}

/// Resolves at Ctrl-C, SIGTERM or SIGHUP (a closed terminal, or `kill -HUP`),
/// with the exit code a shell gives each: 128 plus the signal number. SIGHUP
/// is left alone when the process inherited it ignored, as under `nohup`;
/// Ctrl-C is not, even when inherited ignored as in a background job, and
/// `examples/tail/tail.sh` relies on that. A handler that cannot be installed
/// never fires, as the default action then still applies.
async fn stop_signal() -> i32 {
    let interrupt = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => 130,
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(unix)]
    let others = async {
        use tokio::signal::unix::SignalKind;
        let hangup = async {
            if hangup_ignored() {
                std::future::pending().await
            } else {
                unix_signal(SignalKind::hangup(), 129).await
            }
        };
        tokio::select! {
            code = unix_signal(SignalKind::terminate(), 143) => code,
            code = hangup => code,
        }
    };
    #[cfg(not(unix))]
    let others = std::future::pending::<i32>();
    tokio::select! {
        code = interrupt => code,
        code = others => code,
    }
}

/// Whether this process started with SIGHUP ignored, as under `nohup`. Then
/// a closed terminal must not stop it, so no handler is installed: tokio's
/// would replace the inherited ignore.
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "libc::sigaction read; std has no way to query a signal's disposition"
)]
fn hangup_ignored() -> bool {
    // SAFETY: `sigaction` is plain data, and all-zero is a valid value of it.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a null new action only reads the current one into `old`.
    let read = unsafe { libc::sigaction(libc::SIGHUP, std::ptr::null(), &raw mut old) } == 0;
    read && old.sa_sigaction == libc::SIG_IGN
}

/// Resolves with `code` at the first `kind` signal.
#[cfg(unix)]
async fn unix_signal(kind: tokio::signal::unix::SignalKind, code: i32) -> i32 {
    match tokio::signal::unix::signal(kind) {
        Ok(mut signals) => {
            signals.recv().await;
            code
        }
        Err(_) => std::future::pending().await,
    }
}

/// Read the stream behind `hash` to stdout.
async fn read(args: &Args, node: &StreamNode, hash: &StreamHash) -> Result<()> {
    let mut reader = node.open(hash).await?;
    note(args, "reading");
    let mut stdout = std::io::stdout().lock();
    while let Some(chunk) = reader.read().await? {
        let written = stdout.write_all(&chunk).and_then(|()| stdout.flush());
        // Whoever reads our stdout stopped (`| head`). Rust ignores SIGPIPE,
        // so the EPIPE lands here instead of killing us, and the read ends
        // with exit 0 (ripgrep's choice, not the 141 a killed `cat` gets).
        // The producer then sees its reader leave.
        if let Err(error) = &written
            && error.kind() == std::io::ErrorKind::BrokenPipe
        {
            note(args, "stdout closed; leaving the stream");
            return Ok(());
        }
        written.context("writing to stdout")?;
    }
    drop(stdout);
    note(args, "end of stream");
    Ok(())
}

/// Stream stdin to the one reader of a new stream.
async fn produce(args: &Args, node: &StreamNode) -> Result<()> {
    let mut producer = node.create().await;
    report_ready(args, producer.hash());
    producer.attached().await?;
    note(args, "a reader attached; streaming stdin");
    pump(&mut producer, spawn_stdin()).await?;
    producer.close().await?;
    note(args, "stream closed");
    Ok(())
}

async fn pump(
    producer: &mut Producer,
    mut stdin: mpsc::Receiver<std::io::Result<Vec<u8>>>,
) -> Result<()> {
    while let Some(chunk) = stdin.recv().await {
        producer.write(&chunk.context("reading stdin")?).await?;
    }
    Ok(())
}

/// Stdin on its own thread, since tokio's `io-std` stays off. A small bounded
/// channel, so a slow reader holds stdin back instead of the process holding
/// the whole input.
fn spawn_stdin() -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (tx, rx) = mpsc::channel(4);
    std::thread::spawn(move || forward(std::io::stdin().lock(), &tx));
    rx
}

/// Send `input` down `tx` in chunks until its end, or its first error. An
/// `Interrupted` read is retried, not sent.
fn forward(mut input: impl std::io::Read, tx: &mpsc::Sender<std::io::Result<Vec<u8>>>) {
    let mut buf = vec![0_u8; CHUNK];
    loop {
        let chunk = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => Ok(buf[..len].to_vec()),
            // A signal landed mid-read; nothing was lost, so read again.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => Err(error),
        };
        let failed = chunk.is_err();
        if tx.blocking_send(chunk).is_err() || failed {
            break;
        }
    }
}

fn report_ready(args: &Args, hash: &StreamHash) {
    let hash = hash.encode();
    let url = args.page_url(&hash);
    if args.robot {
        say(format_args!(
            "{}",
            serde_json::json!({ "kind": "ready", "hash": hash, "url": url })
        ));
        return;
    }
    say(format_args!("hash {hash}"));
    match url {
        Some(url) => say(format_args!("open {url}")),
        None => say(format_args!("read it with: fofoca-stream {hash}")),
    }
    say(format_args!("* waiting for a reader"));
}

fn note(args: &Args, text: &str) {
    if args.robot {
        say(format_args!(
            "{}",
            serde_json::json!({ "kind": "note", "text": text })
        ));
    } else {
        say(format_args!("* {text}"));
    }
}

/// One line to stderr. Best effort: once the terminal is gone the write
/// fails, and `eprintln!` would panic there, skipping the node close that
/// tells the peer the stream was abandoned.
fn say(line: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind, Read};

    use tokio::sync::mpsc;

    /// Returns `Interrupted` once, then `data`, then the end.
    struct InterruptedOnce {
        interrupted: bool,
        data: &'static [u8],
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(Error::from(ErrorKind::Interrupted));
            }
            let len = self.data.len().min(buf.len());
            buf[..len].copy_from_slice(&self.data[..len]);
            self.data = &self.data[len..];
            Ok(len)
        }
    }

    /// `Interrupted` means "try again" (a signal landed mid-read), not a
    /// failed input: the stream must carry on, not end in an error.
    #[test]
    fn an_interrupted_read_is_retried() {
        let (tx, mut rx) = mpsc::channel(4);
        let input = InterruptedOnce {
            interrupted: false,
            data: b"after the signal",
        };
        std::thread::spawn(move || super::forward(input, &tx));
        let mut got = Vec::new();
        while let Some(chunk) = rx.blocking_recv() {
            got.extend(chunk.expect("an interrupted read is not an error"));
        }
        assert_eq!(got, b"after the signal");
    }

    /// Any other failure is sent once and ends the input: the producer then
    /// fails, and never closes the stream as if the input had ended.
    #[test]
    fn a_failed_read_ends_the_stream_as_an_error() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(Error::other("the disk went away"))
            }
        }
        let (tx, mut rx) = mpsc::channel(4);
        std::thread::spawn(move || super::forward(Failing, &tx));
        let first = rx.blocking_recv().expect("the error is sent");
        assert_eq!(
            first.expect_err("a failed read is an error").to_string(),
            "the disk went away"
        );
        assert!(rx.blocking_recv().is_none(), "nothing follows the error");
    }
}
