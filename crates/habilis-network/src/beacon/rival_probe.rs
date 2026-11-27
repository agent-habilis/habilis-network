use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::future as future_util;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use n0_future::task::JoinHandle;
use tokio::sync::{oneshot, watch};

use crate::lookup::{ProbeAnswer, TransportHandles, build_endpoint, probe_answer};
use crate::protocol::meshes::LookupOpts;
use crate::util::tuning::{HEAL_PROBE, RENDEZVOUS_CLOSE, heal_interval};

use super::{RendezvousParams, WhoAnswer, ask_who, beacon_lookups, rendezvous_addr, rung_is_busy};

use n0_future::{task, time};
use std::future;
/// A public probe-before-claim running **off** the event loop.
///
/// The probe answers one question — does a beacon already serve this
/// rendezvous? — and it answers it slowly: a free rendezvous is only
/// provably free once the dial has exhausted its budget, so the common
/// "nobody is home, claim it" case costs the full [`HEAL_PROBE`].
/// Paid inline that was ~5s per heal tick during which the sole event loop
/// polled nothing at all: no gossip, no IPC, and — the reason this exists —
/// no quit. A departure landing in that window missed `Node::leave`'s
/// budget entirely, the caller tore the endpoint down underneath the
/// still-running loop, and the graceful `Left` never went out.
///
/// So the probe rides its own task and publishes its verdict through a
/// channel the loop selects on, exactly as the relay-rung walk does
/// through [`RendezvousParams::rung_tx`]. What stays on the loop is only
/// the bind, which is milliseconds.
#[derive(Debug)]
#[must_use]
pub(crate) struct RivalProbe {
    /// The verdict: `true` ⇒ a beacon already answers, stay a peer.
    /// A dropped sender (the task died) reads as `true` — see
    /// [`probe_verdict`].
    pub(crate) rx: oneshot::Receiver<bool>,
    pub(crate) task: JoinHandle<()>,
    /// The throwaway prober endpoints, retained for the same reason `Rendezvous` retains its own:
    /// aborting the task drops the endpoints open, and iroh tears an unclosed endpoint down
    /// ungracefully. The task closes them on the happy path; this is for the departure that cancels
    /// it first. A public probe dials with one endpoint. A private ladder has one endpoint for each
    /// busy rung ([`spawn_ladder_probe`]). Empty when the probe never dialed: an unanswerable target
    /// pre-resolves the verdict without an endpoint, and a ladder with no busy rung is free.
    pub(crate) endpoints: Vec<Endpoint>,
    /// Tells the task to stop dialing and go straight to its own close.
    /// `None` when there is no dial to stop.
    pub(crate) cancel: Option<oneshot::Sender<()>>,
}

impl RivalProbe {
    /// Stop the probe and wait for its endpoint to close gracefully — the
    /// departure counterpart to letting the task finish, and the same bounded
    /// shape as `Rendezvous::shed_and_wait` for the same reason.
    ///
    /// The task closes its own endpoint, so this cancels the dial and waits for
    /// the task rather than aborting it. An abort could land while the task is
    /// already inside `close()`, which cuts that close short, and a second
    /// `close()` returns at once while one is in flight, so nothing would
    /// finish it.
    pub(crate) async fn abort_and_close(mut self) {
        if self.endpoints.is_empty() {
            // Never dialed, nothing to close.
            return;
        }
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if time::timeout(RENDEZVOUS_CLOSE, &mut self.task)
            .await
            .is_err()
        {
            tracing::debug!(target: "habilis_network::beacon", "rival-probe endpoint close timed out; abandoning it");
        }
    }
}

/// A drop that no one asked to close (the daemon task was aborted, as a crash does) cancels the
/// dial and leaves the task to run its own close. An abort would drop the last handle of the
/// prober open. A probe with no dial to cancel has no endpoint, so its task is aborted.
impl Drop for RivalProbe {
    fn drop(&mut self) {
        match self.cancel.take() {
            Some(_cancel) => {}
            None => self.task.abort(),
        }
    }
}

/// Await the outstanding rival probe's verdict, or pend forever when none
/// is running — the [`recv_opt`] shape, so the event loop can give this its
/// own `select!` arm.
///
/// Consumes the probe: one verdict per probe, and clearing the slot is what
/// lets the next tick start a fresh one. A dropped sender (the task was
/// aborted, or panicked) reads as "a rival is there": we could not tell, and
/// claiming blind is the one outcome the probe exists to prevent.
///
/// [`recv_opt`]: crate::daemon::event_loop
pub(crate) async fn probe_verdict(probe: &mut Option<RivalProbe>) -> bool {
    let Some(active) = probe.as_mut() else {
        return future::pending().await;
    };
    // `&mut Receiver` so a losing `select!` arm drops this future without
    // dropping the receiver — the verdict survives to the next poll.
    let found_rival = verdict_of((&mut active.rx).await);
    *probe = None;
    found_rival
}

/// Whether the answer of the ask says that a holder serves the id. A node that holds nothing reads
/// `Rival`, and also `Reached`: a connection that came up is proof that a holder is there, even
/// when it sent no valid frame (a slow beacon), and a claim on the other reading stands up a
/// second holder. Only `Unknown`, where nothing was reached, reads the id as free.
fn holder_is_there(answer: WhoAnswer) -> bool {
    matches!(answer, WhoAnswer::Rival(_) | WhoAnswer::Reached(_))
}

/// Read a probe task's outcome. A dropped sender — the task was aborted, or
/// panicked — means we never learned the answer, and "a rival is there" is
/// the safe reading: claiming blind is the duplicate-id collision the probe
/// exists to prevent, while a needless extra tick costs one heal interval.
pub(crate) fn verdict_of(result: Result<bool, oneshot::error::RecvError>) -> bool {
    result.unwrap_or(true)
}

/// Start the probe-before-claim on its own task.
///
/// The prober dials from a **throwaway endpoint**, not the member's `peer`:
/// an ex-holder re-probing after a rival re-check shed carries stale
/// per-id connection state for the shared `rendezvous_id` (the link to its
/// own just-dropped beacon — the reused-endpoint-id pathology of
/// iroh-gossip#10), and a dial from it joins that dead state and times out
/// even while the rival's live addresses sit in the address book. A fresh
/// endpoint has no history to get stuck on.
///
/// Which is exactly why it must be handed [`rendezvous_addr`] rather than a
/// bare id. A throwaway endpoint has no address book, and nothing else will
/// fill the gap: endpoints are built on `presets::Minimal`, which wires **no
/// N0 pkarr/DNS** on purpose (see `lookup::build_endpoint`), and mDNS/DHT are
/// `host`-only. So a bare `EndpointAddr::new(id)` is unresolvable in a browser
/// and in any relay-only mesh — the dial times out, the verdict reads "free",
/// and every surviving member claims a duplicate same-id beacon that captures
/// its own bootstrap dial. Probe-before-claim was a no-op exactly where it
/// mattered most; naming the address is what makes it answer its question.
///
/// When there is nothing to name *and* no lookup that could resolve the bare
/// id, the probe cannot answer its question at all, so it does not dial: it
/// pre-resolves the verdict to "held". `gossip::recv::arms_reclaim`'s widened
/// gate leans on the probe never reading "free" blind, and this branch is
/// what makes that structural rather than configurational.
///
/// The endpoint is built here, on the loop, rather than inside the task:
/// it costs milliseconds, and holding it lets a departure close it (see
/// [`RivalProbe::abort_and_close`]). `None` ⇒ the build failed, so we
/// cannot tell and must not claim blind; the next tick retries.
pub(crate) async fn spawn_rival_probe(
    params: &RendezvousParams,
    node: EndpointId,
) -> Option<RivalProbe> {
    use tracing::Instrument as _;
    if !params.bind_ports.is_empty() {
        return spawn_ladder_probe(params, node).await;
    }
    let target = match rendezvous_addr(params) {
        Some(address) => address,
        // Nothing to name (relay disabled, no ladder). The bare id is a
        // dialable target only while a lookup can resolve it — mDNS/DHT,
        // when the mesh carries them and this build wires them.
        None if bare_id_resolvable(&params.lookups) => EndpointAddr::new(params.id),
        None => {
            tracing::info!(target: "habilis_network::beacon", node = %node.fmt_short(),
                "rival probe has nothing to dial and no lookup to resolve the id; reading the rendezvous as held");
            let (tx, rx) = oneshot::channel();
            // The receiver is held below; this send cannot fail.
            let _ = tx.send(true);
            return Some(RivalProbe {
                rx,
                task: task::spawn(async {}),
                endpoints: Vec::new(),
                cancel: None,
            });
        }
    };
    let lookups = beacon_lookups(params);
    let prober = match build_endpoint(
        &lookups,
        None,
        None,
        Vec::new(),
        TransportHandles {
            options: params.bind_options,
            ..TransportHandles::default()
        },
    )
    .await
    {
        Ok(prober) => prober,
        Err(error) => {
            tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), %error, "rival probe endpoint build failed; next tick retries");
            return None;
        }
    };
    tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), "rival probe endpoint built");
    // Clamped so at most one probe is outstanding per heal tick even when
    // tests shorten the cadence below the probe cap.
    let budget = HEAL_PROBE.min(heal_interval());
    let (tx, rx) = oneshot::channel();
    let endpoint = prober.clone();
    let (cancel, cancelled) = oneshot::channel();
    // The span names the member that probes, so the `connect-probe finished` line of `lookup`,
    // which knows only the throwaway prober, carries it too.
    let probe_span = tracing::info_span!(
        target: "habilis_network::beacon",
        "rival_probe",
        node = %node.fmt_short()
    );
    let task = task::spawn(
        async move {
            let found_rival = tokio::select! {
                answer = ask_who(&prober, target, node, budget) => holder_is_there(answer),
                // A departure: no one will read the verdict, but the endpoint
                // must still close below.
                _ = cancelled => true,
            };
            prober.close().await;
            // A closed receiver means the loop moved on (departure, or the
            // beacon arrived another way); the verdict is simply stale.
            let _ = tx.send(found_rival);
        }
        .instrument(probe_span),
    );
    Some(RivalProbe {
        rx,
        task,
        endpoints: vec![endpoint],
        cancel: Some(cancel),
    })
}

/// The probe of a private ladder: one throwaway prober for each busy rung, and a rung that answers
/// as the rendezvous id is a rival. A prober that dials the whole ladder takes the first answer for
/// the answer of the id: another mesh whose ladder shares a rung answers with its own identity, the
/// dial ends on it, and the verdict says "free" while the beacon of this mesh is live on another
/// rung. A rung that nobody holds has no listener to ask, so a ladder with no busy rung is free at
/// once.
async fn spawn_ladder_probe(params: &RendezvousParams, node: EndpointId) -> Option<RivalProbe> {
    use tracing::Instrument as _;
    let rungs: Vec<u16> = params
        .bind_ports
        .iter()
        .copied()
        .filter(|&port| rung_is_busy(port))
        .collect();
    let (tx, rx) = oneshot::channel();
    if rungs.is_empty() {
        let _ = tx.send(false);
        return Some(RivalProbe {
            rx,
            task: task::spawn(async {}),
            endpoints: Vec::new(),
            cancel: None,
        });
    }
    let lookups = beacon_lookups(params);
    let mut probers = Vec::with_capacity(rungs.len());
    for _ in &rungs {
        match build_endpoint(
            &lookups,
            None,
            None,
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        {
            Ok(prober) => probers.push(prober),
            Err(error) => {
                tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), %error, "rival probe endpoint build failed; next tick retries");
                for built in probers {
                    built.close().await;
                }
                return None;
            }
        }
    }
    tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), rungs = rungs.len(), "rival probe endpoints built");
    let budget = HEAL_PROBE.min(heal_interval());
    let endpoints = probers.clone();
    let id = params.id;
    let (cancel, cancelled) = oneshot::channel();
    let (stop, stopped) = watch::channel(false);
    let probe_span = tracing::info_span!(
        target: "habilis_network::beacon",
        "rival_probe",
        node = %node.fmt_short()
    );
    let task = task::spawn(
        async move {
            let mut rung_reads = Vec::new();
            let paired = probers.into_iter().zip(rungs);
            for (prober, port) in paired {
                rung_reads.push(read_rung(prober, id, port, budget, stopped.clone()));
            }
            let reads = future_util::join_all(rung_reads);
            tokio::pin!(reads);
            let found_rival = tokio::select! {
                answers = &mut reads => answers.contains(&ProbeAnswer::Ours),
                // A departure: no one will read the verdict, but every prober must still close.
                _ = cancelled => {
                    let _ = stop.send(true);
                    reads.await;
                    true
                }
            };
            let _ = tx.send(found_rival);
        }
        .instrument(probe_span),
    );
    Some(RivalProbe {
        rx,
        task,
        endpoints,
        cancel: Some(cancel),
    })
}

/// What one rung of a private ladder answers to a prober of its own, and the close of the prober.
/// A stop ends the dial and goes straight to the close.
async fn read_rung(
    prober: Endpoint,
    id: EndpointId,
    port: u16,
    budget: Duration,
    mut stopped: watch::Receiver<bool>,
) -> ProbeAnswer {
    let address = EndpointAddr::new(id).with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    let answer = tokio::select! {
        answer = probe_answer(&prober, address, budget) => answer,
        _ = stopped.wait_for(|stop| *stop) => ProbeAnswer::NoAnswer,
    };
    prober.close().await;
    answer
}

/// Whether this build can resolve a bare endpoint id under `lookups` — the
/// only condition a probe may dial one. mDNS and DHT are compile-time
/// features and `host`-only, so a browser or a feature-trimmed build
/// resolves nothing regardless of what the mesh id asks for.
fn bare_id_resolvable(lookups: &LookupOpts) -> bool {
    (cfg!(all(feature = "host", feature = "mdns")) && lookups.mdns)
        || (cfg!(all(feature = "host", feature = "dht")) && lookups.dht)
}
