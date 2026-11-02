//! A send that has not yet been delivered.

use anyhow::Result;
use tokio::sync::oneshot;

/// The outcome of a send that runs on a task. A caller that needs the verdict awaits it off its
/// event loop. Dropping it does not cancel the send: a failure is then only logged.
///
/// # Examples
///
/// A pending send is a channel that receives the outcome of a send that is not done yet. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::PendingSend;
///
/// # fn demo(pending: PendingSend) {
/// drop(pending);
/// # }
/// ```
pub type PendingSend = oneshot::Receiver<Result<()>>;
