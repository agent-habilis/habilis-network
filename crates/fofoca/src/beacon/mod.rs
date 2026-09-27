//! The **beacon role**: the runtime that co-hosts the rendezvous
//! endpoint — the creator-independent bootstrap anchor.
//!
//! Concept split (see the Concept Glossary in AGENTS.md): *rendezvous*
//! is the seed-derived **identity** (`protocol::crypto`); *beacon*
//! is the **role** a live member plays by binding and serving that
//! identity. This module owns the role; it never derives the identity.
//!
//! A co-hosting member binds a second iroh endpoint to the shared
//! `rendezvous_secret` and glues it into the local mesh via this
//! process's own peer endpoint, so a cold joiner that dials the
//! seed-derived `rendezvous_id` is shuffled into the full mesh.
//!
//! - **Public:** ephemeral port, discoverable by node id via N0 pkarr.
//!   Every member co-hosts permanently; pkarr is last-writer-wins, so
//!   the record always resolves to a recently-live member. Two
//!   `EagerProbed` members can still claim inside each other's probe
//!   window and bind duplicate same-id copies (each capturing its own
//!   bootstrap dial); the event loop's periodic rival re-check shed
//!   (`daemon::event_loop::shed_rival_beacon_if_due`) re-arbitrates, so
//!   the single-co-host invariant holds *eventually*, not at claim time.
//! - **Private:** a deterministic loopback port *ladder* (no
//!   pkarr/DNS). Exactly one member per mesh is the beacon: a member
//!   binds the first free rung; on `AddrInUse` it probes the rung's
//!   node id — *ours* ⇒ the beacon already exists, stay a peer;
//!   *foreign* (an unrelated mesh that derived the same port) ⇒ skip
//!   to the next rung. So independent private meshes on one host never
//!   hijack each other, and there is no second same-identity co-host
//!   for a joiner to mis-connect to. On the beacon's death its rung
//!   frees and the next heal/reclaim tick re-elects.
//!
//! The rendezvous endpoint never authors app messages; its node id is
//! filtered out of peer-side neighbor handling.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use iroh_gossip::proto::TopicId;
use n0_future::task::JoinHandle;
use tokio::sync::{oneshot, watch};

use crate::lookup::{TransportHandles, add_peer_addr, build_endpoint, build_mesh, probe_connect};
use crate::protocol::mesh::{LookupOpts, RelayChoice};
use crate::util::tuning::{
    HEAL_PROBE_SECS, RENDEZVOUS_CLOSE_SECS, RENDEZVOUS_PROBE_ATTEMPTS, RENDEZVOUS_PROBE_RETRY_MS,
    RENDEZVOUS_PROBE_SECS, heal_interval_secs,
};

/// Everything [`ensure`] needs to (re)build the rendezvous endpoint.
/// Cheap to clone-hold for the event loop's lifetime.
#[derive(Debug)]
pub(crate) struct RendezvousParams {
    pub(crate) topic_id: TopicId,
    /// `rendezvous_secret(seed)` — the shared identity every co-host binds.
    pub(crate) secret: SecretKey,
    /// Empty when the mesh has lookups (ephemeral, address-lookup
    /// discoverable). Non-empty for a loopback-only mesh: the
    /// deterministic loopback port *ladder* in preference order. The
    /// beacon binds the first free rung; an independent mesh squatting a
    /// rung (seed collision) is skipped instead of mistaken for our own
    /// beacon.
    pub(crate) bind_ports: Vec<u16>,
    /// `rendezvous_id`, memoized for neighbor filtering / bootstrap seeding.
    pub(crate) id: EndpointId,
    /// The peer's resolved lookup config. The beacon
    /// endpoint must publish `rendezvous_id` to the *same*
    /// address-lookups (or a joiner using only mDNS/DHT could never
    /// resolve it) — see `beacon_lookups`.
    pub(crate) lookups: LookupOpts,
    /// The mesh's `transport.relay_transport`. With it off, the beacon holds every
    /// inbound gossip connection — a joiner's first link — until iroh selects
    /// a direct path on it, so no frame ever crosses the relay.
    pub(crate) relay_transport: bool,
    /// The single relay **rung** the beacon homes on — initialized to
    /// the first ladder rung (optimistic, unprobed) at setup and
    /// corrected off the event loop: a backgrounded startup probe and
    /// the beacon's own liveness self-monitor publish a new rung through
    /// [`Self::rung_tx`], which the event loop applies back here. The
    /// joiner pre-registers `rendezvous_id` at this exact rung
    /// (`daemon::setup::register_rendezvous`), so the beacon must home
    /// here or that relay-direct dial finds nothing. `None` ⇒ no
    /// reachable relay (private mode, relay disabled, or every rung
    /// down) — joiners fall back to mDNS/DHT.
    pub(crate) bootstrap_relay: Option<RelayUrl>,
    /// How the off-loop rung selectors (the backgrounded startup probe
    /// and the beacon co-host's liveness self-monitor) publish a freshly
    /// chosen rung. The event loop holds the matching receiver and, on a
    /// change, updates [`Self::bootstrap_relay`], re-registers the
    /// rendezvous, and re-homes the beacon — so the heavy ladder walk
    /// never runs on the sole event loop.
    pub(crate) rung_tx: watch::Sender<Option<RelayUrl>>,
}

/// A live co-hosted rendezvous endpoint. Dropping it aborts both tasks,
/// releasing the endpoint + router (and, private, freeing the
/// deterministic port for the next member to claim).
pub(crate) struct Rendezvous {
    /// The gossip co-host: subscribes, bridges the rendezvous into the
    /// mesh, and re-asserts the peer link each heal tick.
    task: JoinHandle<()>,
    /// The relay-rung liveness/discovery monitor (`spawn_relay_monitor`).
    /// `None` for private / relay-disabled meshes (nothing to monitor).
    monitor: Option<crate::lookup::StoppableTask>,
    /// The co-hosted endpoint itself, retained so [`Self::shed`] and
    /// [`Self::shed_and_wait`] can close it gracefully — a plain drop (task
    /// abort) skips the orderly QUIC close, and the peer's link to its own
    /// dead beacon lingers as a zombie until the idle timeout, stalling the
    /// post-shed re-graft.
    endpoint: Endpoint,
    /// The beacon's own `WebRTC` answerer: the handle a tab's session to the
    /// rendezvous attaches to, and the admission its negotiations hold a
    /// slot in. The peer endpoint has its own pair, which says nothing about
    /// who depends on the beacon. `None` where the beacon carries no lane.
    lane: Option<(
        fofoca_iroh_webrtc_transport::WebRtcHandle,
        crate::transport::SignalAdmission,
    )>,
}

impl Rendezvous {
    /// How many peers depend on this beacon's data channel: sessions attached
    /// to its answerer, plus rounds still negotiating one.
    pub(crate) fn dependents(&self) -> usize {
        self.lane.as_ref().map_or(0, |(handle, admission)| {
            handle.session_count() + admission.in_flight()
        })
    }

    /// A beacon holding `endpoint` whose answerer is `lane`, for a test that
    /// needs a held beacon without a claim.
    #[cfg(test)]
    pub(crate) fn for_test(
        endpoint: Endpoint,
        lane: Option<(
            fofoca_iroh_webrtc_transport::WebRtcHandle,
            crate::transport::SignalAdmission,
        )>,
    ) -> Self {
        Self {
            task: n0_future::task::spawn(std::future::pending()),
            monitor: None,
            endpoint,
            lane,
        }
    }

    /// Release the beacon *gracefully*: abort the tasks, then close the
    /// endpoint off-loop so every peer holding a link to it (including our
    /// own peer) sees an immediate `NeighborDown` instead of a
    /// zombie link that only dies at the QUIC idle timeout.
    pub(crate) fn shed(self) {
        let endpoint = self.endpoint.clone();
        n0_future::task::spawn(async move {
            endpoint.close().await;
        });
        // `self` drops here, aborting the co-host task and stopping the monitor.
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
    /// answering. See `RENDEZVOUS_CLOSE_SECS`. Past the bound we are no worse
    /// off than before this existed.
    ///
    /// The monitor is stopped and waited for in the same budget, not aborted:
    /// mid re-walk it holds a probe endpoint of its own, which an abort drops
    /// open.
    pub(crate) async fn shed_and_wait(mut self) {
        let endpoint = self.endpoint.clone();
        let monitor = self.monitor.take();
        // Abort the co-host task first, so it is not still driving the
        // endpoint while it closes.
        drop(self);
        tokio::join!(
            async {
                if n0_future::time::timeout(
                    Duration::from_secs(RENDEZVOUS_CLOSE_SECS),
                    endpoint.close(),
                )
                .await
                .is_err()
                {
                    tracing::debug!(target: "fofoca::beacon", "rendezvous endpoint close timed out; abandoning it");
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
/// stop, and the monitor then closes any probe endpoint of its own) — and
/// **does not close the endpoint**, because it cannot: closing is async and
/// `Drop` is not.
///
/// So a bare `drop` (or `*slot = None`, which is the same thing wearing a
/// disguise) abandons a live, still-registered socket: iroh logs `Endpoint
/// dropped without calling Endpoint::close. Aborting ungracefully.` and every
/// peer linked to that beacon waits out the QUIC idle timeout instead of
/// seeing a `NeighborDown`. Every release site must go through
/// [`Rendezvous::shed`] (mid-run) or [`Rendezvous::shed_and_wait`] (on the way
/// out) — the two plain drops that predated this note are the whole reason it
/// is here.
impl Drop for Rendezvous {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The rendezvous's **dialable** address: the id plus somewhere to reach it.
///
/// One construction, two callers that must not drift — the hint a joiner
/// pre-registers on its peer endpoint (`daemon::setup::register_rendezvous`)
/// and the target [`spawn_rival_probe`] dials. They are the same address by
/// definition: the probe asks "is anyone serving the identity a joiner would
/// reach?", so asking it anywhere else answers a different question.
///
/// - Private (a non-empty ladder): every loopback rung, because iroh's
///   node-id dial reaches whichever rung our beacon actually bound.
/// - Public: `bootstrap_relay`, the single rung the beacon homes on
///   ([`beacon_lookups`]) — a relay-direct dial with no lookup round-trip.
/// - `None`: relay disabled and no ladder, so there is nothing to name and
///   only mDNS/DHT can resolve the id.
pub(crate) fn rendezvous_addr(params: &RendezvousParams) -> Option<EndpointAddr> {
    let mut addr = EndpointAddr::new(params.id);
    if !params.bind_ports.is_empty() {
        for &port in &params.bind_ports {
            addr = addr.with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
        return Some(addr);
    }
    Some(addr.with_relay_url(params.bootstrap_relay.clone()?))
}

/// A public probe-before-claim running **off** the event loop.
///
/// The probe answers one question — does a beacon already serve this
/// rendezvous? — and it answers it slowly: a free rendezvous is only
/// provably free once the dial has exhausted its budget, so the common
/// "nobody is home, claim it" case costs the full [`HEAL_PROBE_SECS`].
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
pub(crate) struct RivalProbe {
    /// The verdict: `true` ⇒ a beacon already answers, stay a peer.
    /// A dropped sender (the task died) reads as `true` — see
    /// [`probe_verdict`].
    rx: oneshot::Receiver<bool>,
    task: JoinHandle<()>,
    /// The throwaway prober endpoint, retained for the same reason
    /// [`Rendezvous`] retains its own: aborting the task drops the endpoint
    /// open, and iroh tears an unclosed endpoint down ungracefully. The
    /// task closes it on the happy path; this is for the departure that
    /// cancels it first. `None` when the probe never dialed — an
    /// unanswerable target pre-resolves the verdict without an endpoint.
    endpoint: Option<Endpoint>,
    /// Tells the task to stop dialing and go straight to its own close.
    /// `None` when there is no dial to stop.
    cancel: Option<oneshot::Sender<()>>,
}

impl RivalProbe {
    /// Stop the probe and wait for its endpoint to close gracefully — the
    /// departure counterpart to letting the task finish, and the same bounded
    /// shape as [`Rendezvous::shed_and_wait`] for the same reason.
    ///
    /// The task closes its own endpoint, so this cancels the dial and waits for
    /// the task rather than aborting it. An abort could land while the task is
    /// already inside `close()`, which cuts that close short, and a second
    /// `close()` returns at once while one is in flight, so nothing would
    /// finish it.
    pub(crate) async fn abort_and_close(mut self) {
        if self.endpoint.is_none() {
            // Never dialed, nothing to close.
            return;
        }
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if n0_future::time::timeout(Duration::from_secs(RENDEZVOUS_CLOSE_SECS), &mut self.task)
            .await
            .is_err()
        {
            tracing::debug!(target: "fofoca::beacon", "rival-probe endpoint close timed out; abandoning it");
        }
    }
}

impl Drop for RivalProbe {
    fn drop(&mut self) {
        self.task.abort();
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
        return std::future::pending().await;
    };
    // `&mut Receiver` so a losing `select!` arm drops this future without
    // dropping the receiver — the verdict survives to the next poll.
    let found_rival = verdict_of((&mut active.rx).await);
    *probe = None;
    found_rival
}

/// Read a probe task's outcome. A dropped sender — the task was aborted, or
/// panicked — means we never learned the answer, and "a rival is there" is
/// the safe reading: claiming blind is the duplicate-id collision the probe
/// exists to prevent, while a needless extra tick costs one heal interval.
fn verdict_of(result: Result<bool, oneshot::error::RecvError>) -> bool {
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
async fn spawn_rival_probe(params: &RendezvousParams) -> Option<RivalProbe> {
    let target = match rendezvous_addr(params) {
        Some(addr) => addr,
        // Nothing to name (relay disabled, no ladder). The bare id is a
        // dialable target only while a lookup can resolve it — mDNS/DHT,
        // when the mesh carries them and this build wires them.
        None if bare_id_resolvable(&params.lookups) => EndpointAddr::new(params.id),
        None => {
            tracing::info!(target: "fofoca::beacon",
                "rival probe has nothing to dial and no lookup to resolve the id; reading the rendezvous as held");
            let (tx, rx) = oneshot::channel();
            // The receiver is held below; this send cannot fail.
            let _ = tx.send(true);
            return Some(RivalProbe {
                rx,
                task: n0_future::task::spawn(async {}),
                endpoint: None,
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
        TransportHandles::default(),
    )
    .await
    {
        Ok(prober) => prober,
        Err(error) => {
            tracing::debug!(target: "fofoca::beacon", %error, "rival probe endpoint build failed; next tick retries");
            return None;
        }
    };
    // Clamped so at most one probe is outstanding per heal tick even when
    // tests shorten the cadence below the probe cap.
    let budget = Duration::from_secs(HEAL_PROBE_SECS.min(heal_interval_secs()));
    let (tx, rx) = oneshot::channel();
    let endpoint = prober.clone();
    let (cancel, cancelled) = oneshot::channel();
    let task = n0_future::task::spawn(async move {
        let found_rival = tokio::select! {
            found = probe_connect(&prober, target, budget) => found,
            // A departure: no one will read the verdict, but the endpoint
            // must still close below.
            _ = cancelled => true,
        };
        prober.close().await;
        // A closed receiver means the loop moved on (departure, or the
        // beacon arrived another way); the verdict is simply stale.
        let _ = tx.send(found_rival);
    });
    Some(RivalProbe {
        rx,
        task,
        endpoint: Some(endpoint),
        cancel: Some(cancel),
    })
}

/// Whether this build can resolve a bare endpoint id under `lookups` — the
/// only condition a probe may dial one. mDNS and DHT are compile-time
/// features and `host`-only, so a browser or a feature-trimmed build
/// resolves nothing regardless of what the mesh id asks for.
fn bare_id_resolvable(lookups: &LookupOpts) -> bool {
    (cfg!(all(feature = "host", feature = "mdns")) && lookups.mdns)
        || (cfg!(all(feature = "host", feature = "dht")) && lookups.dht)
}

/// Probe a `AddrInUse` private rung: is the listener *our* mesh's
/// rendezvous, or an unrelated mesh that happened to derive the same
/// port? A loopback `connect` to `rendezvous_id` succeeds only if the
/// listener presents that exact node id (iroh validates it during the
/// TLS handshake) — a foreign rendezvous (different key) is rejected,
/// a dead socket times out. Resolves in milliseconds against a live
/// loopback listener; the timeout only guards a pathological socket.
///
/// `prober` must be a **throwaway** endpoint, never this member's peer
/// endpoint, and that is a correctness requirement rather than hygiene.
/// The dial goes out on `GOSSIP_ALPN`, which is exactly what the beacon's
/// gossip accepts and adopts as a peer connection. Dialed from our own
/// endpoint it arrives as a second connection *from us*, and
/// `PeerState::accept_conn` promotes the newcomer to our **active**
/// connection, superseding the real one. Closing the probe then reads to
/// the beacon as our active connection dropping: it marks us
/// disconnected and emits `NeighborDown`. The probe would tear down the
/// very link whose existence it is asking about — and on a ticker, kill
/// it again every time it was re-established. From a throwaway identity
/// the beacon sees a stranger arrive and leave, which costs it nothing.
/// [`spawn_rival_probe`] takes the same precaution for the public path.
async fn rung_serves_our_mesh(prober: &Endpoint, rendezvous_id: EndpointId, port: u16) -> bool {
    let addr = EndpointAddr::new(rendezvous_id)
        .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    // Retried, and *spaced*: a `false` here is read by the caller as a
    // positive "foreign" finding and authorizes an irreversible bind, so
    // it has to be worth believing, and the miss worth covering is a rung
    // whose owner won the bind race microseconds ago and is not yet
    // accepting — which refuses instantly, so unspaced attempts would all
    // land inside that same gap. See `RENDEZVOUS_PROBE_ATTEMPTS` and
    // `RENDEZVOUS_PROBE_RETRY_MS`. Both common cases still cost one
    // attempt — a live listener answers, a foreign squat rejects.
    for attempt in 1..=RENDEZVOUS_PROBE_ATTEMPTS {
        if attempt > 1 {
            n0_future::time::sleep(Duration::from_millis(RENDEZVOUS_PROBE_RETRY_MS)).await;
        }
        let ours = probe_connect(
            prober,
            addr.clone(),
            Duration::from_secs(RENDEZVOUS_PROBE_SECS),
        )
        .await;
        if ours {
            tracing::trace!(target: "fofoca::beacon", port, attempt, "private rung identity-probe: ours");
            return true;
        }
        tracing::trace!(
            target: "fofoca::beacon",
            port,
            attempt,
            attempts = RENDEZVOUS_PROBE_ATTEMPTS,
            "private rung identity-probe: no answer"
        );
    }
    false
}

/// The beacon mirrors the peer's *address-lookups* (so a joiner
/// resolves `rendezvous_id` via whichever it enabled) but homes on a
/// **single** relay rung — `params.bootstrap_relay`, the first
/// reachable rung of the ladder. Unlike a peer (which spreads
/// across the whole multi-relay set for resilience), the beacon must be
/// at the one deterministic rung the joiner pre-registers
/// (`daemon::setup::register_rendezvous`), or the relay-direct dial
/// finds nothing. A `None` rung ⇒ relay off for the beacon (joiners use
/// mDNS/DHT).
fn beacon_lookups(params: &RendezvousParams) -> LookupOpts {
    LookupOpts {
        mdns: params.lookups.mdns,
        dht: params.lookups.dht,
        relay_lookup: params
            .bootstrap_relay
            .clone()
            .map_or(RelayChoice::Disabled, |rung| {
                RelayChoice::Custom(vec![rung])
            }),
    }
}

/// Build the rendezvous endpoint (see module docs for the one-beacon /
/// claim-if-free / identity-probe rationale). Public: one
/// ephemeral-port endpoint. Private: bind the first **free** ladder
/// rung; on `AddrInUse`, probe — *ours* ⇒ `None` (stay a peer),
/// *foreign* ⇒ next rung. `None` also covers public build failure /
/// every rung foreign-squatted (≈0); the next tick retries.
async fn build_rendezvous_endpoint(
    params: &RendezvousParams,
) -> Option<(Endpoint, Option<fofoca_iroh_webrtc_transport::WebRtcHandle>)> {
    let lookups = beacon_lookups(params);
    if params.bind_ports.is_empty() {
        // The public probe-before-claim that used to run here — the analog
        // of the private rung identity-probe below — now runs off the loop
        // (`spawn_rival_probe`), and `ensure` only reaches this point once
        // its verdict says the rendezvous is free. Everything left is a
        // bind.
        //
        // A public rendezvous carries the `WebRTC` transport and answers
        // JSEP: a browser-shaped peer has no IP to punch with, so on a mesh
        // whose relay is lookup only the data channel is the only path its
        // rendezvous link can ever be admitted on.
        let webrtc = crate::lookup::new_webrtc_handle(params.secret.public());
        let endpoint = build_endpoint(
            &lookups,
            Some(params.secret.clone()),
            None,
            Vec::new(),
            TransportHandles {
                webrtc: Some(webrtc.clone()),
                ..TransportHandles::default()
            },
        )
        .await
        .ok();
        if endpoint.is_some() {
            tracing::info!(target: "fofoca::beacon", "beacon assumed: bound public rendezvous endpoint (ephemeral port)");
        } else {
            tracing::debug!(target: "fofoca::beacon", "public beacon endpoint build failed; next tick retries");
        }
        return endpoint.map(|endpoint| (endpoint, Some(webrtc)));
    }
    // Built on the first contended rung and reused for the rest of the
    // walk, then closed. A throwaway identity, for the reason
    // `rung_serves_our_mesh` gives at length: probing from `peer` would
    // make the beacon mistake the probe for this member's own gossip
    // connection and drop the real one when the probe closes.
    let mut prober: Option<Endpoint> = None;
    let mut verdict: Option<(Endpoint, Option<fofoca_iroh_webrtc_transport::WebRtcHandle>)> = None;
    for &port in &params.bind_ports {
        if let Ok(endpoint) = build_endpoint(
            &lookups,
            Some(params.secret.clone()),
            Some(port),
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        {
            tracing::info!(target: "fofoca::beacon", port, "beacon assumed: bound rendezvous ladder rung");
            // No `WebRTC` on the ladder: a loopback mesh has no browsers.
            verdict = Some((endpoint, None));
            break;
        }
        // build failed (AddrInUse): is it our beacon, or a foreign squat?
        if prober.is_none() {
            prober = build_endpoint(
                &lookups,
                None,
                None,
                Vec::new(),
                TransportHandles::default(),
            )
            .await
            .ok();
        }
        let Some(prober) = prober.as_ref() else {
            tracing::debug!(target: "fofoca::beacon", "rung probe endpoint build failed; staying peer this tick");
            break;
        };
        if rung_serves_our_mesh(prober, params.id, port).await {
            tracing::debug!(target: "fofoca::beacon", port, "rung already serves our beacon; staying peer");
            break;
        }
        tracing::debug!(target: "fofoca::beacon", port, "rung squatted by a foreign mesh; trying next rung");
    }
    if let Some(prober) = prober {
        // Closed, not dropped: a dropped endpoint reaches `Drop` open and
        // iroh says so loudly, and the orderly close also retires the
        // stranger the beacon just saw instead of leaving it to time out.
        prober.close().await;
    }
    if verdict.is_none() {
        tracing::debug!(target: "fofoca::beacon", "no rendezvous ladder rung taken; staying peer");
    }
    verdict
}

/// Idempotent: a no-op while we co-host and the task is alive;
/// otherwise (never started, or the task died) try to (re)stand-up the
/// rendezvous. All outcomes are quiet — the next heal/reclaim tick retries.
///
/// **Nothing slow happens on the caller's task.** A public member that must
/// probe before claiming starts the probe (`spawn_rival_probe`) and returns
/// immediately; the verdict lands on the event loop's own arm, which calls
/// [`claim_after_probe`]. The bind that follows is milliseconds, and
/// `subscribe_and_join` runs inside the spawned co-host task. The private
/// ladder walk stays inline: against a live loopback listener a rung
/// identity-probe answers on its first attempt, in milliseconds. Its
/// *bound* is not milliseconds though — an unresponsive rung costs
/// `RENDEZVOUS_PROBE_SECS * RENDEZVOUS_PROBE_ATTEMPTS` before the walk
/// moves on, on this task. That is deliberate (see
/// [`RENDEZVOUS_PROBE_ATTEMPTS`] on why the answer has to be worth
/// believing) but it is the one inline cost here that is not trivially
/// short.
///
/// Returns whether this call stood up a **new** rendezvous (a
/// `None`/dead → live transition) — the edge the event loop's rival
/// re-check scheduling keys on. Starting a probe is not that edge, so a
/// probing call returns `false`.
pub(crate) async fn ensure(
    params: &RendezvousParams,
    peer: &Endpoint,
    current: &mut Option<Rendezvous>,
    probe_first: bool,
    probe: &mut Option<RivalProbe>,
) -> bool {
    if !releasable(current) {
        return false;
    }
    // Public probe-before-claim. Skipped for the eager origin
    // (`probe_first == false`): it has no peers to collide with and must be
    // the beacon from t=0. One probe at a time — a second would answer the
    // same question at the same cost.
    if params.bind_ports.is_empty() && probe_first {
        if probe.is_none() {
            *probe = spawn_rival_probe(params).await;
        }
        return false;
    }
    claim(params, peer, current).await
}

/// Apply an off-loop probe's verdict: claim the rendezvous if it is free.
///
/// Re-checks the beacon slot first, because up to [`HEAL_PROBE_SECS`] passed
/// while the probe ran and the loop kept moving — a reclaim tick or a
/// re-stand-up may have taken the role in the meantime, and claiming twice
/// binds the duplicate same-id copy the probe exists to prevent.
pub(crate) async fn claim_after_probe(
    params: &RendezvousParams,
    peer: &Endpoint,
    current: &mut Option<Rendezvous>,
    found_rival: bool,
) -> bool {
    if found_rival {
        tracing::debug!(target: "fofoca::beacon", "public rendezvous already served by a beacon; staying peer");
        return false;
    }
    if !releasable(current) {
        return false;
    }
    claim(params, peer, current).await
}

/// Whether the beacon slot is free to (re)claim: empty, or holding a
/// rendezvous whose co-host task has ended.
///
/// A dead one is [`Rendezvous::shed`], never dropped: the co-host *task*
/// ending says nothing about the endpoint, which is still open and still
/// registered under `rendezvous_id`. Dropping it there abandons a live socket
/// — iroh logs `Endpoint dropped without calling Endpoint::close` and joiners
/// keep resolving to a corpse until the QUIC idle timeout.
fn releasable(current: &mut Option<Rendezvous>) -> bool {
    if current
        .as_ref()
        .is_some_and(|rendezvous| !rendezvous.task.is_finished())
    {
        return false;
    }
    if let Some(dead) = current.take() {
        tracing::info!(target: "fofoca::beacon", "beacon released (co-host task ended); attempting re-stand-up");
        dead.shed();
    }
    true
}

/// Bind the rendezvous endpoint and stand the beacon up on it. The rival
/// question is already settled by the time this runs — either it never
/// applied (private ladder, eager origin) or [`claim_after_probe`] answered
/// it.
async fn claim(
    params: &RendezvousParams,
    peer: &Endpoint,
    current: &mut Option<Rendezvous>,
) -> bool {
    let Some((endpoint, webrtc)) = build_rendezvous_endpoint(params).await else {
        // Public: endpoint build failed. Private: every ladder rung is
        // occupied — our mesh's beacon(s) already exist on the ladder
        // (joiners reach them by identity-checked dial). Either way,
        // nothing to do; the next tick retries.
        return false;
    };

    // The rendezvous pseudo-node's active view is overlay plumbing, not the
    // member peer cap, so it stays at the shipped default rather than
    // tracking `--max-peers`.
    // The rendezvous pseudo-node accepts no unicast — it is not a peer.
    // A *public* rendezvous answers JSEP (`build_rendezvous_endpoint` put
    // the transport on the endpoint): a browser-shaped peer has no other
    // way onto a mesh whose relay is lookup only.
    let lane = webrtc.map(|handle| {
        (
            handle,
            crate::transport::SignalAdmission::new(crate::transport::MAX_DIRECT_PEERS),
        )
    });
    let (gossip, router) = build_mesh(
        endpoint.clone(),
        crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
        None,
        lane.clone().map(|(handle, admission)| {
            (
                handle,
                admission,
                crate::transport::IceProfile { host_only: false },
            )
        }),
        // The rendezvous serves no caller protocol either — it is a meeting
        // point, not somewhere an application is reachable.
        Vec::new(),
        params.relay_transport,
    );

    // Register the peer's address so the rendezvous can dial it
    // in private mode (no lookup); a harmless direct hint in public.
    let _ = add_peer_addr(&endpoint, peer.addr());
    // And the other way: our peer is the one that dials the rendezvous, and a
    // public mesh without a relay rung gives it no lookup to find the id by.
    let _ = add_peer_addr(peer, endpoint.addr());
    let topic_id = params.topic_id;

    // Relay-monitor inputs. The monitor runs as its **own** task (below),
    // off both the event loop and this gossip task, so relay probes never
    // stall rendezvous bridging. Spawned whenever relay is enabled
    // (public + a non-empty ladder) — *not* gated on currently holding a
    // rung, so a relay-less beacon keeps probing to rediscover one.
    let ladder = crate::lookup::relay_ladder(&params.lookups.relay_lookup);
    let monitors_relay = !params.lookups.is_loopback() && !ladder.is_empty();
    let monitor_endpoint = endpoint.clone();
    let monitor_homed = params.bootstrap_relay.is_some();
    let monitor_rung_tx = params.rung_tx.clone();
    let rendezvous_endpoint = endpoint.clone();

    let task = n0_future::task::spawn(async move {
        use futures_util::StreamExt as _;

        // Keep the gossip frontend + the Router's accept loop alive
        // for the task's lifetime so the rendezvous stays reachable by
        // cold joiners.
        let _endpoint = endpoint;
        let _router = router;

        // *Inside the task*, not in `ensure`, so `daemon::run` never blocks
        // here — blocking it stalls in-process two-session setups whose
        // runtime must also drive the peer. No bootstrap: our own peer dials
        // us, and dialing it back races that dial (see
        // `a_rendezvous_does_not_dial_its_own_peer`).
        let Ok(topic) = gossip.subscribe(topic_id, Vec::new()).await else {
            return;
        };
        // Retain the gossip frontend for the task's lifetime.
        let _gossip = gossip;
        let (_sender, mut receiver) = topic.split();
        // App payloads are discarded — this node only relays the gossip
        // overlay. Ends when the topic terminally closes.
        while receiver.next().await.is_some() {}
    });

    // Relay liveness/discovery, off this gossip task: never stops
    // probing, backs off while relay-less. `None` when relay is disabled
    // (private / empty ladder).
    let monitor = monitors_relay.then(|| {
        crate::lookup::spawn_relay_monitor(monitor_endpoint, ladder, monitor_rung_tx, monitor_homed)
    });

    tracing::info!(target: "fofoca::beacon", "beacon role active: serving the rendezvous");
    *current = Some(Rendezvous {
        task,
        monitor,
        endpoint: rendezvous_endpoint,
        lane,
    });
    true
}

#[cfg(test)]
mod tests {
    use super::{
        Endpoint, LookupOpts, Rendezvous, RendezvousParams, RivalProbe, SecretKey, TopicId, ensure,
        oneshot, probe_verdict, releasable, rendezvous_addr, spawn_rival_probe, verdict_of, watch,
    };

    /// A real endpoint that touches nothing: `LookupOpts::loopback` binds
    /// 127.0.0.1 with relay, mDNS, DHT and the portmapper all off, so these
    /// tests make zero external network calls.
    async fn loopback_endpoint() -> Endpoint {
        crate::lookup::build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            crate::lookup::TransportHandles::default(),
        )
        .await
        .expect("loopback endpoint")
    }

    /// A probe wrapped around a channel we drive by hand. The endpoint is
    /// real but inert, because `RivalProbe` retains one so a departure can
    /// close it, and these tests are about the slot, not the dial.
    async fn probe_for(rx: oneshot::Receiver<bool>) -> RivalProbe {
        RivalProbe {
            rx,
            task: n0_future::task::spawn(std::future::pending()),
            endpoint: Some(loopback_endpoint().await),
            cancel: None,
        }
    }

    /// A beacon holding `endpoint`, whose co-host task is already finished —
    /// the "dead beacon" `releasable` is meant to clear.
    async fn dead_beacon(endpoint: Endpoint) -> Rendezvous {
        let task = n0_future::task::spawn(async {});
        // Let it finish, so `task.is_finished()` is true below.
        for _ in 0..100 {
            if task.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(task.is_finished(), "the co-host task should have ended");
        Rendezvous {
            task,
            monitor: None,
            endpoint,
            lane: None,
        }
    }

    /// Params for the public probe-before-claim path: no `bind_ports` (so
    /// `ensure` takes the public branch) and all-off lookups (so nothing
    /// leaves the machine).
    fn public_params() -> RendezvousParams {
        let secret = SecretKey::generate();
        let id = secret.public();
        RendezvousParams {
            topic_id: TopicId::from_bytes([7u8; 32]),
            secret,
            bind_ports: Vec::new(),
            id,
            lookups: LookupOpts::loopback(),
            relay_transport: false,
            bootstrap_relay: None,
            rung_tx: watch::channel(None).0,
        }
    }

    /// Give a spawned close a chance to run, without pinning a duration the
    /// scheduler has to honour.
    async fn settle(endpoint: &Endpoint) {
        for _ in 0..200 {
            if endpoint.is_closed() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Regression for `Endpoint dropped without calling Endpoint::close` on
    /// every Ctrl-C that landed mid-probe. A probe still in its handshake has
    /// sent a close frame nobody will acknowledge, so iroh's close waits out
    /// the QUIC drain (about 3s) before it finishes. A budget shorter than that
    /// abandoned the endpoint half-closed, and its drop logged the error.
    #[tokio::test]
    async fn abort_and_close_waits_out_a_probe_mid_handshake() {
        // Bound and never read: the handshake's packets vanish without an
        // answer, as they do into a relay rung nobody serves.
        let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a silent loopback socket");
        let mut params = public_params();
        params.bind_ports = vec![silent.local_addr().expect("its address").port()];
        let probe = spawn_rival_probe(&params)
            .await
            .expect("a probe with a rung to dial");
        let prober = probe.endpoint.clone().expect("the probe dials");
        // Let the handshake start, so there is a connection to drain.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        probe.abort_and_close().await;

        assert!(
            prober.is_closed(),
            "abort_and_close returned with the probe endpoint still open; its drop logs the ungraceful-abort error"
        );
    }

    /// The other half of the same error: the probe's dial ran out on its own
    /// and its task was already closing the endpoint when the departure came.
    /// Aborting the task there cut that close short, and a second `close()`
    /// returns at once while one is in flight, so nothing finished it.
    #[tokio::test]
    async fn abort_and_close_lets_a_probe_finish_closing_its_own_endpoint() {
        let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a silent loopback socket");
        let target = super::EndpointAddr::new(SecretKey::generate().public())
            .with_ip_addr(silent.local_addr().expect("its address"));
        let prober = loopback_endpoint().await;
        let dialer = prober.clone();
        let task = n0_future::task::spawn(async move {
            // The dial gives up almost at once, leaving a handshake to drain,
            // and the task moves on to its own close, as the real one does.
            super::probe_connect(&dialer, target, std::time::Duration::from_millis(200)).await;
            dialer.close().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let probe = RivalProbe {
            rx: oneshot::channel().1,
            task,
            endpoint: Some(prober.clone()),
            cancel: None,
        };

        probe.abort_and_close().await;

        assert!(
            prober.is_closed(),
            "abort_and_close cut the probe's own close short; its drop logs the ungraceful-abort error"
        );
    }

    /// Regression for `Endpoint dropped without calling Endpoint::close` on a
    /// departure while the relay monitor re-walks the ladder: the walk probes
    /// each rung on an endpoint of its own, and aborting the monitor mid-walk
    /// dropped that endpoint open. Relay-less, the monitor walks at once.
    #[cfg(feature = "host")]
    #[test]
    fn shed_and_wait_mid_rewalk_closes_the_monitor_probe_endpoint() {
        let (_silent, rung) = crate::testing::silent_relay_rung();

        let errors = crate::testing::errors_through_runtime_drop(async {
            let endpoint = loopback_endpoint().await;
            let monitor = crate::lookup::spawn_relay_monitor(
                endpoint.clone(),
                vec![rung],
                watch::channel(None).0,
                false,
            );
            // Let the walk bind its probe and start waiting for the relay.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let rendezvous = Rendezvous {
                task: n0_future::task::spawn(std::future::pending()),
                monitor: Some(monitor),
                endpoint,
                lane: None,
            };

            rendezvous.shed_and_wait().await;
        });

        assert!(
            !errors.contains("Endpoint dropped without calling"),
            "the relay monitor's probe endpoint reached its drop open:\n{errors}"
        );
    }

    #[test]
    fn a_public_rendezvous_is_named_at_its_relay_rung() {
        let mut params = public_params();
        params.bootstrap_relay = Some("https://relay.example/".parse().expect("relay url"));

        let addr = rendezvous_addr(&params).expect("a public rendezvous has a rung to name");

        assert_eq!(addr.id, params.id);
        assert!(
            addr.addrs
                .iter()
                .any(|addr| matches!(addr, iroh::TransportAddr::Relay(_))),
            "the probe must dial the rung the beacon homes on, not a bare id"
        );
    }

    #[test]
    fn a_private_rendezvous_is_named_at_every_ladder_rung() {
        let mut params = public_params();
        params.bind_ports = vec![4001, 4002, 4003];

        let addr = rendezvous_addr(&params).expect("a ladder is always nameable");

        let rungs = addr
            .addrs
            .iter()
            .filter(|addr| matches!(addr, iroh::TransportAddr::Ip(_)))
            .count();
        assert_eq!(
            rungs, 3,
            "iroh's node-id dial reaches whichever rung the beacon bound, so name them all"
        );
    }

    #[test]
    fn nothing_to_name_is_none_not_a_bare_id() {
        // Relay disabled and no ladder: mDNS/DHT are the only resolution
        // channel, and handing back a bare id would look like an address the
        // caller could dial when it is not one.
        let params = public_params();
        assert!(params.bootstrap_relay.is_none() && params.bind_ports.is_empty());

        assert!(rendezvous_addr(&params).is_none());
    }

    #[test]
    fn an_answered_probe_is_taken_at_its_word() {
        assert!(verdict_of(Ok(true)), "a rival answered");
        assert!(!verdict_of(Ok(false)), "nobody answered; the id is free");
        // `RecvError` cannot be constructed here, so the unanswered case is
        // covered end-to-end by `a_probe_whose_task_dies_frees_the_slot_too`.
    }

    #[tokio::test]
    async fn a_verdict_is_delivered_once_and_frees_the_slot() {
        let (tx, rx) = oneshot::channel();
        let mut slot = Some(probe_for(rx).await);
        tx.send(false).expect("verdict accepted");

        assert!(!probe_verdict(&mut slot).await, "the rendezvous is free");
        // Cleared, or the loop's arm would re-fire on the closed channel
        // forever and no later tick could ever start a fresh probe.
        assert!(slot.is_none(), "the slot is free for the next probe");
    }

    #[tokio::test]
    async fn an_unanswerable_probe_reads_held_not_free() {
        // Relay disabled, no ladder, and no mDNS/DHT on the mesh: the probe
        // has no dialable address (`nothing_to_name_is_none_not_a_bare_id`
        // pins that half) and no lookup that could resolve the bare id. A
        // dial would only ever time out, and a timeout must not read as
        // "free" — claiming blind is the duplicate-beacon collision the
        // probe exists to prevent, and `gossip::recv::arms_reclaim`'s
        // widened gate leans on exactly this.
        let params = public_params();
        let mut slot = spawn_rival_probe(&params).await;
        assert!(
            slot.is_some(),
            "the probe reports a verdict, it does not vanish"
        );
        assert!(
            probe_verdict(&mut slot).await,
            "an unanswerable probe reads as held, never as free"
        );
    }

    #[tokio::test]
    async fn a_probe_whose_task_dies_frees_the_slot_too() {
        let (tx, rx) = oneshot::channel::<bool>();
        let mut slot = Some(probe_for(rx).await);
        drop(tx);

        assert!(
            probe_verdict(&mut slot).await,
            "could not tell; stay a peer"
        );
        assert!(slot.is_none(), "a dead probe must not wedge the slot");
    }

    #[tokio::test]
    async fn no_probe_means_the_arm_never_fires() {
        let mut slot: Option<RivalProbe> = None;
        let pending = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            probe_verdict(&mut slot),
        )
        .await;
        assert!(pending.is_err(), "an empty slot pends instead of firing");
    }

    #[tokio::test]
    async fn shedding_a_beacon_closes_its_endpoint() {
        let endpoint = loopback_endpoint().await;
        let beacon = dead_beacon(endpoint.clone()).await;

        beacon.shed();

        settle(&endpoint).await;
        assert!(endpoint.is_closed(), "`shed` must close, not just abort");
    }

    #[tokio::test]
    async fn shed_and_wait_closes_before_it_returns() {
        let endpoint = loopback_endpoint().await;
        let beacon = dead_beacon(endpoint.clone()).await;

        beacon.shed_and_wait().await;

        // No settling: the whole point of the awaited form is that the close
        // has happened by the time the departure path moves on.
        assert!(
            endpoint.is_closed(),
            "the awaited shed must finish the close"
        );
    }

    #[tokio::test]
    async fn clearing_a_dead_beacon_closes_its_endpoint() {
        // Regression: this slot used to be cleared with `*current = None`.
        // The co-host task ending says nothing about the endpoint, so the
        // plain drop abandoned a live socket — iroh's `Endpoint dropped
        // without calling Endpoint::close`, and peers linked to a corpse
        // until the QUIC idle timeout.
        let endpoint = loopback_endpoint().await;
        let mut slot = Some(dead_beacon(endpoint.clone()).await);

        assert!(releasable(&mut slot), "a dead beacon frees the slot");
        assert!(slot.is_none(), "and is cleared out of it");

        settle(&endpoint).await;
        assert!(
            endpoint.is_closed(),
            "the dead beacon's endpoint must be closed, not dropped"
        );
    }

    #[tokio::test]
    async fn a_live_beacon_keeps_the_slot_and_its_endpoint() {
        let endpoint = loopback_endpoint().await;
        let mut slot = Some(Rendezvous {
            task: n0_future::task::spawn(std::future::pending()),
            monitor: None,
            endpoint: endpoint.clone(),
            lane: None,
        });

        assert!(!releasable(&mut slot), "a live beacon is not releasable");
        assert!(slot.is_some(), "and is left alone");
        assert!(!endpoint.is_closed(), "its endpoint stays open");
    }

    /// The peer dials its co-hosted rendezvous (its bootstrap, or a re-graft),
    /// so the rendezvous must not dial back. Two dials open two connections;
    /// iroh-gossip keeps the newer one and stops reading the older, and a
    /// `Join` or `Neighbor` already sent on the older one is lost. Only one
    /// side then lists the other as a neighbor, and the rendezvous forwards
    /// nothing to its own peer. Here the peer never dials, so any link can
    /// only be the rendezvous dialing it.
    #[tokio::test]
    async fn a_rendezvous_does_not_dial_its_own_peer() {
        use futures_util::StreamExt as _;
        use iroh_gossip::api::Event;

        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let mut params = public_params();
        params.bind_ports = vec![port];

        let peer = loopback_endpoint().await;
        let (gossip, router) = crate::lookup::build_mesh(
            peer.clone(),
            crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
            None,
            None,
            Vec::new(),
            false,
        );
        let (_sender, mut receiver) = gossip
            .subscribe(params.topic_id, Vec::new())
            .await
            .expect("subscribe without a bootstrap")
            .split();

        let mut beacon = None;
        let mut probe = None;
        assert!(
            ensure(&params, &peer, &mut beacon, false, &mut probe).await,
            "a free ladder rung is claimed"
        );

        let first_neighbor = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match receiver.next().await {
                    Some(Ok(Event::NeighborUp(id))) => return id,
                    Some(_) => {}
                    None => std::future::pending::<()>().await,
                }
            }
        })
        .await;

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        let _ = router.shutdown().await;
        assert!(
            first_neighbor.is_err(),
            "the rendezvous dialed its own peer (neighbor {}); with the peer dialing it too, the pair opens two connections and one side's Join is lost",
            first_neighbor.map_or_else(|_| String::new(), |id| id.fmt_short().to_string())
        );
    }

    /// On a public mesh with no relay rung nothing names the rendezvous for a
    /// lookup to find, yet the holder's own peer is the one that must dial it
    /// (the rendezvous never dials its peer). With every lookup off, only the
    /// address the claim hands the peer lets the holder's re-graft reach it.
    #[tokio::test]
    async fn a_holder_reaches_its_own_public_rendezvous_without_lookups() {
        use futures_util::StreamExt as _;
        use iroh_gossip::api::Event;

        let params = public_params();
        let peer = loopback_endpoint().await;
        let (gossip, router) = crate::lookup::build_mesh(
            peer.clone(),
            crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
            None,
            None,
            Vec::new(),
            false,
        );
        let (sender, mut receiver) = gossip
            .subscribe(params.topic_id, Vec::new())
            .await
            .expect("subscribe without a bootstrap")
            .split();

        let mut beacon = None;
        let mut probe = None;
        assert!(
            ensure(&params, &peer, &mut beacon, false, &mut probe).await,
            "a public rendezvous is claimed when no probe is asked for"
        );
        sender
            .join_peers(vec![params.id])
            .await
            .expect("ask the gossip to join the rendezvous");
        let linked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match receiver.next().await {
                    Some(Ok(Event::NeighborUp(id))) if id == params.id => return,
                    Some(_) => {}
                    None => std::future::pending::<()>().await,
                }
            }
        })
        .await
        .is_ok();

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        let _ = router.shutdown().await;
        assert!(
            linked,
            "the holder never reached its own rendezvous: nothing registered its address, and with every lookup off nothing can resolve it"
        );
    }

    #[tokio::test]
    async fn ensure_starts_the_probe_instead_of_waiting_for_it() {
        // The invariant the departure bug came down to: `ensure` runs on the
        // sole event loop, so it must not block on the probe. It used to,
        // for the full `HEAL_PROBE_SECS` — long enough that `Node::leave`'s
        // 3s budget expired and the graceful `Left` was never sent.
        let params = public_params();
        let peer = loopback_endpoint().await;
        let mut beacon = None;
        let mut probe = None;

        let started = std::time::Instant::now();
        let claimed = ensure(&params, &peer, &mut beacon, true, &mut probe).await;
        let elapsed = started.elapsed();

        // The structural assertion, not the clock, is what pins this: a call
        // that *waited* would have consumed the verdict and left the slot
        // empty. The timing bound below is only a coarse backstop — on
        // loopback the dial fails fast, so a blocking `ensure` would still
        // return quickly here.
        assert!(
            probe.is_some(),
            "ensure must leave the probe running, not await it"
        );
        assert!(
            !claimed,
            "and claim nothing on the strength of a probe it never read"
        );
        assert!(beacon.is_none(), "and stand no beacon up");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "ensure must return without waiting out the probe, took {elapsed:?}"
        );

        // A second call must not stack a second probe answering the same
        // question at the same cost.
        let before = std::time::Instant::now();
        assert!(!ensure(&params, &peer, &mut beacon, true, &mut probe).await);
        assert!(
            before.elapsed() < std::time::Duration::from_secs(1),
            "and neither must the next tick"
        );

        if let Some(probe) = probe.take() {
            probe.abort_and_close().await;
        }
    }
}
