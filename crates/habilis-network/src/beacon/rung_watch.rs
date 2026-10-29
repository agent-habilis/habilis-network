use std::collections::{BTreeMap, BTreeSet};

use iroh::EndpointId;
use n0_future::task::JoinHandle;
use tokio::sync::mpsc;

use crate::lookup::{ProbeAnswer, TransportHandles, build_endpoint};
use crate::protocol::mesh::LookupOpts;
use crate::util::clock::Instant;
use crate::util::tuning::{RECLAIM_WINDOW, RENDEZVOUS_CLOSE, RENDEZVOUS_PROBE, heal_interval};

use super::{RendezvousParams, rung_answer, rung_is_busy, rung_probes_are_blind};

/// What a busy rung said when it was last asked.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RungReading {
    pub(crate) answer: ProbeAnswer,
    pub(crate) read_at: Instant,
    /// Since when the rung has said nothing, and not answered since. Kept across probes: a rung
    /// that stays silent is bound once it has been silent for the whole reclaim window.
    pub(crate) silent_since: Option<Instant>,
    /// The ask that this reading answers.
    pub(crate) generation: u64,
}

/// A probe task that is out for a rung, and since when.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InFlight {
    pub(crate) generation: u64,
    pub(crate) since: Instant,
}

/// What a probe task found out about one rung. The event loop notes it in its [`RungWatch`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct RungReport {
    pub(crate) port: u16,
    pub(crate) answer: ProbeAnswer,
    /// Which ask of the rung this answers: a task that was given up can still report, and its
    /// report is not the answer that the loop waits for.
    pub(crate) generation: u64,
}

/// How a walk reads a rung that is bound by somebody else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RungRead {
    /// It answered as the beacon of our own mesh.
    Ours,
    /// It answered, and was not ours.
    Foreign,
    /// It has said nothing for the whole reclaim window: read as foreign.
    SilentLongEnough,
    /// It said nothing, and not for long enough yet: the walk waits.
    Silent,
    /// No fresh reading: somebody has to ask.
    Unknown,
}

/// What the event loop knows of the busy rungs of a private ladder, and the probe tasks that find
/// out more.
///
/// The ladder walk is instant: it binds a free rung, reads what is here, and asks for what it does
/// not know by spawning a probe task, as the public path does with `spawn_rival_probe`. It never
/// waits for a rung. The report of a probe task arrives on the loop, which notes it here and walks
/// again at once. A reading is fresh for one heal tick; a silent rung keeps the time it was first
/// read silent until it answers.
#[derive(Debug)]
pub(crate) struct RungWatch {
    pub(crate) readings: BTreeMap<u16, RungReading>,
    /// The rungs that a probe task is out for, and since when. A task that has not reported for
    /// longer than one heal tick is dead (the loop that would have noted it, or the runtime, is
    /// gone) and the rung is asked again.
    pub(crate) in_flight: BTreeMap<u16, InFlight>,
    /// The generation of the next ask. A report of an ask that is no longer the one in flight, or
    /// that is older than the stored reading or than the last clear, is ignored.
    pub(crate) next_generation: u64,
    /// The asks below this generation were made before the last clear of the readings.
    pub(crate) generation_floor: u64,
    /// How many consecutive checks of our own rung did not answer as ours, and the reading that
    /// was counted last, so that one reading is one check however often a tick reads it.
    pub(crate) own_misses: u32,
    pub(crate) own_counted: Option<Instant>,
    /// The rungs that the walk read as held by a foreign listener, and has not read as ours since.
    /// A reading expires after a heal tick, this does not: the book must not take such a rung
    /// back each time the rendezvous is registered again.
    pub(crate) foreign: BTreeSet<u16>,
    /// The rungs whose last probe was answered and ended without an identity: a refusal, a close,
    /// an alert that is not about the key. A busy, closing or starting beacon of our own mesh does
    /// that, and so does a listener of another program, so the answer cannot tell them apart. A
    /// dial of the rendezvous id tries every address of the id, and such a listener fails the dial
    /// as a whole, so the rung stays out of the book until it answers as ours. Silence is not
    /// here: a host too loaded to answer reads the same, and its beacon is found by the dial.
    pub(crate) refused: BTreeSet<u16>,
    pub(crate) reports: mpsc::UnboundedSender<RungReport>,
    /// The probe tasks that are out. A task reports before it closes its prober, so the loop that
    /// ends has to wait for them: [`Self::finish`].
    pub(crate) tasks: Vec<JoinHandle<()>>,
}

impl RungWatch {
    pub(crate) fn new(reports: mpsc::UnboundedSender<RungReport>) -> Self {
        Self {
            readings: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            next_generation: 1,
            generation_floor: 0,
            own_misses: 0,
            own_counted: None,
            foreign: BTreeSet::new(),
            refused: BTreeSet::new(),
            reports,
            tasks: Vec::new(),
        }
    }

    /// A watch whose reports go nowhere: for a state that no loop drives.
    pub(crate) fn detached() -> Self {
        Self::new(mpsc::unbounded_channel().0)
    }

    /// The walk read `port` as serving our beacon.
    pub(crate) fn clear_foreign(&mut self, port: u16) {
        self.foreign.remove(&port);
        self.refused.remove(&port);
    }

    /// The walk read `port` as held by a foreign listener.
    pub(crate) fn mark_foreign(&mut self, port: u16) {
        self.foreign.insert(port);
    }

    /// The rungs that stay out of the book: those that the walk read as held by a foreign listener,
    /// and those that answered the last probe without an identity ([`Self::refused`]).
    pub(crate) fn withheld_rungs(&self) -> Vec<u16> {
        self.foreign.union(&self.refused).copied().collect()
    }

    /// Whether the last probe of `port` was answered without an identity.
    pub(crate) fn refused(&self, port: u16) -> bool {
        self.refused.contains(&port)
    }

    /// Whether a probe task is out, and not dead.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> bool {
        let now = Instant::now();
        self.in_flight
            .values()
            .any(|probe| Self::alive(probe.since, now))
    }

    /// Whether a probe that was asked at `since` is still waited for. After one heal tick it is
    /// given up: the task, or the loop that would note its report, is gone.
    fn alive(since: Instant, now: Instant) -> bool {
        now.saturating_duration_since(since) < heal_interval()
    }

    /// Note what a probe task found.
    ///
    /// A probe that was given up can still report. Its report is ignored when the rung was asked
    /// again since, when a newer ask has been noted, and when the readings were cleared after the
    /// ask: it would end the wait for the probe in flight and put an old answer in as fresh.
    pub(crate) fn note(&mut self, report: RungReport, now: Instant) {
        match self.in_flight.get(&report.port) {
            Some(probe) if probe.generation != report.generation => return,
            Some(_) => {
                self.in_flight.remove(&report.port);
            }
            None => {}
        }
        if report.generation < self.generation_floor
            || self
                .readings
                .get(&report.port)
                .is_some_and(|stored| report.generation < stored.generation)
        {
            return;
        }
        let gap = heal_interval().saturating_mul(3);
        let silent_since: Option<Instant> = match report.answer {
            ProbeAnswer::NoAnswer | ProbeAnswer::Refused => Some(
                self.readings
                    .get(&report.port)
                    .filter(|before| now.saturating_duration_since(before.read_at) < gap)
                    .and_then(|before| before.silent_since)
                    .unwrap_or(now),
            ),
            ProbeAnswer::Ours | ProbeAnswer::Foreign => None,
        };
        if report.answer == ProbeAnswer::Refused {
            self.refused.insert(report.port);
        } else {
            self.refused.remove(&report.port);
        }
        self.readings.insert(
            report.port,
            RungReading {
                answer: report.answer,
                read_at: now,
                silent_since,
                generation: report.generation,
            },
        );
    }

    /// Forget every reading: the ladder is ours now. The asks made so far are over, and the late
    /// report of one of them is ignored.
    pub(crate) fn forget(&mut self) {
        self.readings.clear();
        self.refused.clear();
        self.generation_floor = self.next_generation;
        self.own_misses = 0;
        self.own_counted = None;
    }

    /// Whether the holder of the beacon on `own_port` should shed it: its own rung did not answer
    /// as ours at two consecutive checks, and never at one, so that a busy moment does not take a
    /// healthy beacon from the members that joined through it. A check is a probe task dialing
    /// the rung from a throwaway endpoint, one attempt, never blind; a reading that says ours
    /// resets the count.
    ///
    /// What it does not see: a beacon whose endpoint answers while its gossip is wedged.
    pub(crate) fn own_rung_failed(
        &mut self,
        params: &RendezvousParams,
        node: EndpointId,
        own_port: u16,
    ) -> bool {
        match self.reading(own_port, Instant::now()) {
            RungRead::Ours => {
                self.own_misses = 0;
                self.own_counted = None;
                false
            }
            RungRead::Unknown => {
                self.ask(params, node, own_port, false);
                false
            }
            RungRead::Foreign | RungRead::SilentLongEnough | RungRead::Silent => {
                let read_at = self.readings.get(&own_port).map(|reading| reading.read_at);
                if read_at != self.own_counted {
                    self.own_misses = self.own_misses.saturating_add(1);
                    self.own_counted = read_at;
                }
                self.own_misses >= 2
            }
        }
    }

    /// The count of the checks of our own rung is over: the beacon was shed.
    pub(crate) fn own_check_done(&mut self) {
        self.own_misses = 0;
        self.own_counted = None;
    }

    /// Tests only: every probe task that is out has been out for longer than a heal tick, as when
    /// one has passed: the task is given up and the rung is asked again.
    #[cfg(all(test, feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) fn expire_probes_in_flight(&mut self) {
        let long_ago = heal_interval().saturating_mul(2);
        for probe in self.in_flight.values_mut() {
            probe.since = probe.since.checked_sub(long_ago).unwrap_or(probe.since);
        }
    }

    /// Tests only: every reading is older than a heal tick, as when one has passed.
    #[cfg(test)]
    pub(crate) fn expire_readings(&mut self) {
        let long_ago = heal_interval().saturating_mul(2);
        for reading in self.readings.values_mut() {
            reading.read_at = reading
                .read_at
                .checked_sub(long_ago)
                .unwrap_or(reading.read_at);
        }
    }

    /// How a walk reads `port` now. A reading older than a heal tick is `Unknown` and asks again.
    /// `Ours` and `Foreign` act at once. A silent or refusing rung stays `Silent` until two
    /// reports of silence are a window apart, and then it is `SilentLongEnough`.
    pub(crate) fn reading(&self, port: u16, now: Instant) -> RungRead {
        let Some(reading) = self.readings.get(&port) else {
            return RungRead::Unknown;
        };
        if now.saturating_duration_since(reading.read_at) >= heal_interval() {
            return RungRead::Unknown;
        }
        match reading.answer {
            ProbeAnswer::Ours => RungRead::Ours,
            ProbeAnswer::Foreign => RungRead::Foreign,
            // The window is measured between two reports, not up to now: the reading is fresh
            // for a heal tick, and one report read a window later is still one sample.
            ProbeAnswer::NoAnswer | ProbeAnswer::Refused => match reading.silent_since {
                Some(since)
                    if reading.read_at.saturating_duration_since(since) >= RECLAIM_WINDOW =>
                {
                    RungRead::SilentLongEnough
                }
                _ => RungRead::Silent,
            },
        }
    }

    /// Spawn one probe of `port`, if none is out. `blindable`: the claim walk's probes are the
    /// ones that a test makes read silence; the check of the lower rungs is not.
    pub(crate) fn ask(
        &mut self,
        params: &RendezvousParams,
        node: EndpointId,
        port: u16,
        blindable: bool,
    ) {
        let now = Instant::now();
        if self
            .in_flight
            .get(&port)
            .is_some_and(|probe| Self::alive(probe.since, now))
        {
            return;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        self.in_flight.insert(
            port,
            InFlight {
                generation,
                since: now,
            },
        );
        let reports = self.reports.clone();
        let id = params.id;
        let blind = blindable && rung_probes_are_blind(node);
        self.tasks.retain(|task| !task.is_finished());
        self.tasks.push(n0_future::task::spawn(async move {
            // A throwaway identity, for the reason `rung_answer` gives, and with no address
            // lookup: the dial carries the one address that it asks about, and a lookup could
            // hand it another path of the id, which would answer for the id and not the rung.
            let prober = if blind {
                None
            } else {
                build_endpoint(
                    &LookupOpts::loopback(),
                    None,
                    None,
                    Vec::new(),
                    TransportHandles::default(),
                )
                .await
                .ok()
            };
            let answer = match &prober {
                Some(prober) => rung_answer(prober, id, port).await,
                None => ProbeAnswer::NoAnswer,
            };
            // The report goes before the close: closing an endpoint that dialed a silent rung
            // takes about 3 s, and the silence of a rung is timed from the arrival of the report.
            // A closed channel means the loop is gone: the report is stale.
            let _ = reports.send(RungReport {
                port,
                answer,
                generation,
            });
            if let Some(prober) = prober {
                prober.close().await;
            }
        }));
    }

    /// Waits for the probe tasks that are out, so that every prober has closed its endpoint when
    /// this returns. A prober that dials a silent rung gives up after [`RENDEZVOUS_PROBE`] and
    /// then takes about 3 s to close, and the departure of a node would otherwise drop it open.
    /// The bound is the dial and the close, which `NODE_LEAVE` leaves room for.
    pub(crate) async fn finish(&mut self) {
        let tasks = std::mem::take(&mut self.tasks);
        let _ = n0_future::time::timeout(RENDEZVOUS_PROBE + RENDEZVOUS_CLOSE, async {
            for task in tasks {
                let _ = task.await;
            }
        })
        .await;
    }

    /// The port of a rung below `own` that answered as the beacon of our own mesh, if one did.
    /// The busy rungs that have no fresh reading are asked, and the answer comes with a later
    /// call. A rung that said nothing, or refused, or that nobody holds is not an answer: a
    /// holder never gives up its bind on an unknown. A lower rung is asked only when the std
    /// socket check (`rung_is_busy`) reads it busy. If iroh binds a family that the check does
    /// not see, the holder never asks and never sheds. The C, CP and D cases on the fix tree
    /// are the proof of that assumption.
    pub(crate) fn lower_rung_that_answers(
        &mut self,
        params: &RendezvousParams,
        node: EndpointId,
        own: usize,
    ) -> Option<u16> {
        let now = Instant::now();
        let mut answered = None;
        for &port in params.bind_ports.iter().take(own) {
            match self.reading(port, now) {
                RungRead::Ours => {
                    tracing::info!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "a lower rung answers as the beacon of our mesh");
                    answered = Some(port);
                    break;
                }
                RungRead::Unknown if rung_is_busy(port) => self.ask(params, node, port, false),
                RungRead::Foreign
                | RungRead::SilentLongEnough
                | RungRead::Silent
                | RungRead::Unknown => {}
            }
        }
        answered
    }

    /// Tests only: say that `port` has been silent for `by` already.
    #[cfg(test)]
    pub(crate) fn age_silence(&mut self, port: u16, by: std::time::Duration) {
        if let Some(reading) = self.readings.get_mut(&port) {
            reading.silent_since = Instant::now().checked_sub(by);
        }
    }
}
