use iroh::{Endpoint, EndpointId};
use n0_future::task::JoinHandle;
use tokio::sync::{mpsc, oneshot};

use crate::util::clock::Instant;
use crate::util::tuning::RENDEZVOUS_CLOSE;

use super::{Dependents, rung_of};

/// A live co-hosted rendezvous endpoint. Dropping it aborts both tasks,
/// releasing the endpoint + router (and, private, freeing the
/// deterministic port for the next member to claim).
pub(crate) struct Rendezvous {
    /// The gossip co-host: subscribes, bridges the rendezvous into the
    /// mesh, and re-asserts the peer link each heal tick.
    pub(crate) task: JoinHandle<()>,
    /// The relay-rung liveness/discovery monitor (`spawn_relay_monitor`).
    /// `None` for private / relay-disabled meshes (nothing to monitor).
    pub(crate) monitor: Option<crate::lookup::StoppableTask>,
    /// The co-hosted endpoint itself, retained so [`Self::shed`] and
    /// [`Self::shed_and_wait`] can close it gracefully — a plain drop (task
    /// abort) skips the orderly QUIC close, and the peer's link to its own
    /// dead beacon lingers as a zombie until the idle timeout, stalling the
    /// post-shed re-graft.
    pub(crate) endpoint: Endpoint,
    /// The beacon's own `WebRTC` answerer: the handle a tab's session to the
    /// rendezvous attaches to, and the admission its negotiations hold a
    /// slot in. The peer endpoint has its own pair, which says nothing about
    /// who depends on the beacon. `None` where the beacon carries no lane.
    pub(crate) lane: RendezvousLane,
    /// The members that linked to this beacon, as its gossip task saw them come up. The holder
    /// reads them: a member that it does not know is a sign that another group may exist.
    pub(crate) arrivals: mpsc::Receiver<EndpointId>,
    /// Set by the release paths, which close the endpoint themselves. A drop with it unset is a
    /// beacon that nobody released, and closes the endpoint on its own.
    pub(crate) released: bool,
}

/// A beacon's `WebRTC` answerer and the table that admits its sessions.
pub(crate) type RendezvousLane = Option<(
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    crate::transport::SignalAdmission,
)>;

impl Rendezvous {
    /// How many peers depend on this beacon's data channel: sessions attached
    /// to its answerer, plus rounds still negotiating one. `peer` is our own
    /// member endpoint. `in_flight` does not name its peers, so a round counts
    /// whoever it is with.
    pub(crate) fn dependents(&self, peer: EndpointId) -> Dependents {
        self.lane
            .as_ref()
            .map_or_else(Dependents::default, |(handle, admission)| Dependents {
                live: handle.live_peer_ids().collect(),
                own: vec![peer, self.endpoint.id()],
                in_flight: admission.in_flight(),
            })
    }

    /// The index of the rung in `ladder` that this beacon is bound on: `0` is the first rung that a
    /// joiner tries. `None` when it is bound on none of them (a public beacon).
    pub(crate) fn rung_in(&self, ladder: &[u16]) -> Option<usize> {
        rung_of(&self.endpoint, ladder)
    }

    /// Tests only: make this beacon stop answering and keep its rung. The endpoint stays bound and
    /// the co-host task stays alive, as a stopped process or a wedged accept loop leaves them;
    /// no connection of the gossip ALPN is taken any more.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) fn stall(&self) {
        self.endpoint.set_alpns(Vec::new());
    }

    /// The members that linked to this beacon since the last call.
    pub(crate) fn take_arrivals(&mut self) -> Vec<EndpointId> {
        let mut arrived = Vec::new();
        while let Ok(id) = self.arrivals.try_recv() {
            arrived.push(id);
        }
        arrived
    }

    /// A beacon holding `endpoint` whose answerer is `lane`, for a test that
    /// needs a held beacon without a claim.
    #[cfg(test)]
    pub(crate) fn for_test(endpoint: Endpoint, lane: RendezvousLane) -> Self {
        Self {
            task: n0_future::task::spawn(std::future::pending()),
            monitor: None,
            endpoint,
            lane,
            arrivals: mpsc::channel(1).1,
            released: false,
        }
    }

    /// Release the beacon *gracefully*: abort the tasks, then close the
    /// endpoint off-loop so every peer holding a link to it (including our
    /// own peer) sees an immediate `NeighborDown` instead of a
    /// zombie link that only dies at the QUIC idle timeout.
    pub(crate) fn shed(self) {
        drop(self.shed_then());
    }

    /// [`Self::shed`], and a receiver that resolves when the close of the endpoint is done. The
    /// event loop waits on it to re-probe the id at once: the wait that the reclaim tick used to
    /// give is the close, and the close is an event, not a time.
    pub(crate) fn shed_then(mut self) -> oneshot::Receiver<()> {
        self.released = true;
        let endpoint = self.endpoint.clone();
        let (done, closed) = oneshot::channel();
        let shed_at = Instant::now();
        n0_future::task::spawn(async move {
            endpoint.close().await;
            tracing::debug!(
                target: "habilis_network::beacon",
                age_ms = u64::try_from(shed_at.elapsed().as_millis()).unwrap_or(u64::MAX),
                "beacon closed"
            );
            // The last handle of the endpoint goes before the event does, so that whoever waits sees
            // the id free of it.
            drop(endpoint);
            let _ = done.send(());
        });
        // `self` drops here, aborting the co-host task and stopping the monitor.
        closed
    }

    /// The same graceful release, *awaited* — for the event loop's teardown.
    ///
    /// [`Self::shed`] hands the close to a spawned task, which is right
    /// mid-run and useless on the way out: the runtime is about to go away, so
    /// a detached close is never polled and the endpoint reaches its `Drop`
    /// still open. iroh says so — `Endpoint dropped without calling
    /// Endpoint::close. Aborting ungracefully.` — on every departure of every
    /// co-hosting member, which is all of them.
    ///
    /// Bounded, because winding down must not hang on a relay that stopped
    /// answering. See `RENDEZVOUS_CLOSE`. Past the bound we are no worse
    /// off than before this existed.
    ///
    /// The monitor is stopped and waited for in the same budget, not aborted:
    /// mid re-walk it holds a probe endpoint of its own, which an abort drops
    /// open.
    pub(crate) async fn shed_and_wait(mut self) {
        let endpoint = self.endpoint.clone();
        let monitor = self.monitor.take();
        self.released = true;
        // Abort the co-host task first, so it is not still driving the
        // endpoint while it closes.
        drop(self);
        tokio::join!(
            async {
                if n0_future::time::timeout(RENDEZVOUS_CLOSE, endpoint.close())
                    .await
                    .is_err()
                {
                    tracing::debug!(target: "habilis_network::beacon", "rendezvous endpoint close timed out; abandoning it");
                }
            },
            async {
                if let Some(monitor) = monitor {
                    monitor.stop_and_wait().await;
                }
            },
        );
    }
}

/// Aborts the co-host task and stops the monitor (dropping it signals the
/// stop, and the monitor then closes any probe endpoint of its own). A beacon
/// that was not released through [`Rendezvous::shed`] or
/// [`Rendezvous::shed_and_wait`] hands its endpoint to a detached close, because
/// closing is async and `Drop` is not.
///
/// A drop is what a crash leaves, when the daemon task is aborted with the
/// beacon in its slot. Without the close, iroh logs `Endpoint dropped without
/// calling Endpoint::close. Aborting ungracefully.` and every peer linked to
/// that beacon waits out the QUIC idle timeout instead of seeing a
/// `NeighborDown`. The close runs only where a runtime is there to run it. The
/// release sites stay the way to wait for the close.
impl Drop for Rendezvous {
    fn drop(&mut self) {
        self.task.abort();
        if !self.released {
            close_detached(self.endpoint.clone());
        }
    }
}

/// Close `endpoint` on a task of its own, for a `Drop` that cannot wait. Outside a runtime there
/// is nothing to run the close, and the endpoint is dropped as before.
fn close_detached(endpoint: Endpoint) {
    #[cfg(not(target_arch = "wasm32"))]
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    drop(n0_future::task::spawn(async move {
        endpoint.close().await;
    }));
}
