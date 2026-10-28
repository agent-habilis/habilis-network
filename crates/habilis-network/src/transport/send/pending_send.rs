//! A send that has not yet been delivered.

use anyhow::Result;
use tokio::sync::oneshot;

/// The outcome of a send that runs on a task. A caller that needs the verdict awaits it off its
/// event loop. Dropping it does not cancel the send: a failure is then only logged.
pub type PendingSend = oneshot::Receiver<Result<()>>;
