//! Which node driver a process runs: the mode of the event loop.

use tokio::sync::{broadcast, mpsc};

use crate::protocol::message::Authored;

use crate::daemon::node::SignalHandling;

/// Who drives the event loop. The variants make illegal channel
/// combinations unrepresentable and let the loop *derive* both "exit the
/// process on quit?" and "spawn the unix-socket listener?" instead of
/// carrying them as independent, drift-prone bools.
///
/// # Examples
///
/// A command-line driver ends its loop when the command ends.
///
/// ```
/// use habilis_network::runtime::DriverMode;
///
/// let mode = DriverMode::Cli;
/// assert!(matches!(mode, DriverMode::Cli));
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum DriverMode {
    /// A long-running CLI daemon. Owns the unix-socket IPC listener
    /// (for `msg` / `poll`); ctrl-c / SIGTERM `std::process::exit`s.
    Cli,
    /// Fully in-process, driven by a [`Node`](crate::daemon::node::Node). Outbound sends +
    /// polls arrive **typed** on the `session_rx` that [`run`](crate::daemon::run) takes
    /// alongside this; `msg_tx` fans inbound out to the consumer's broadcast, or
    /// is `None` when the consumer drains frames some other way (a poll-only
    /// session, or an app that consumes every frame inside the loop). Never
    /// exits the process and binds no socket; shutdown on `quit_rx`.
    InProcess {
        /// Where the messages go.
        msg_tx: Option<broadcast::Sender<Authored>>,
        /// Where the quit signal comes from.
        quit_rx: mpsc::Receiver<()>,
        /// Whether this session registers the process-wide
        /// ctrl-c/SIGTERM/SIGHUP/SIGQUIT listeners for a graceful leave.
        /// Registering any tokio signal handler suppresses the OS
        /// default-terminate for the *whole process, permanently* — so a
        /// session living inside a foreground command that owns its own
        /// lifetime (a `--advertise` transfer's directory session, a
        /// directory browse) must pass `false`, or ctrl-c stops killing
        /// the host command.
        handle_signals: SignalHandling,
    },
}
