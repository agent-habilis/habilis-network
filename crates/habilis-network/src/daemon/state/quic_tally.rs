//! The QUIC counters of the live connections, as a delta per census window.

use std::collections::HashMap;
use std::fmt;

use iroh::endpoint::ConnectionStats;
use iroh_gossip::net::GOSSIP_ALPN;

use crate::transport::UNICAST_ALPN;

/// What a connection carries, by its ALPN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnKind {
    Gossip,
    Unicast,
    /// Every other protocol: the blob channel, the signalling and the nudge.
    Other,
}

pub(crate) const KIND_COUNT: usize = 3;

impl ConnKind {
    const ALL: [Self; KIND_COUNT] = [Self::Gossip, Self::Unicast, Self::Other];

    pub(crate) fn of_alpn(alpn: &[u8]) -> Self {
        if alpn == GOSSIP_ALPN {
            Self::Gossip
        } else if alpn == UNICAST_ALPN {
            Self::Unicast
        } else {
            Self::Other
        }
    }

    /// The text that a reader of the census line gets: a rename breaks the reader.
    fn name(self) -> &'static str {
        match self {
            Self::Gossip => "gossip",
            Self::Unicast => "unicast",
            Self::Other => "other",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// What one connection counted since it began, or what a set of them counted in a window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct QuicCounts {
    /// The PING frames sent: the keep-alive, and also the probes of the path MTU and of the
    /// loss timer, so this is an upper bound for the keep-alive.
    pub(crate) ping_tx: u64,
    /// The PING frames received, with the same reach as `ping_tx`.
    pub(crate) ping_rx: u64,
    /// The ACK frames sent, those of a path included.
    pub(crate) ack_tx: u64,
    pub(crate) dgram_tx: u64,
    pub(crate) dgram_rx: u64,
    pub(crate) bytes_tx: u64,
    pub(crate) bytes_rx: u64,
}

impl QuicCounts {
    /// Whether a counter of `self` is below the same counter of `mark`. A counter of one
    /// connection never goes down, so this says that `mark` is the mark of another connection.
    fn is_below(self, mark: Self) -> bool {
        self.ping_tx < mark.ping_tx
            || self.ping_rx < mark.ping_rx
            || self.ack_tx < mark.ack_tx
            || self.dgram_tx < mark.dgram_tx
            || self.dgram_rx < mark.dgram_rx
            || self.bytes_tx < mark.bytes_tx
            || self.bytes_rx < mark.bytes_rx
    }

    /// What `self` counted after `mark`.
    fn since(self, mark: Self) -> Self {
        let diff = |now: u64, then: u64| now.saturating_sub(then);
        Self {
            ping_tx: diff(self.ping_tx, mark.ping_tx),
            ping_rx: diff(self.ping_rx, mark.ping_rx),
            ack_tx: diff(self.ack_tx, mark.ack_tx),
            dgram_tx: diff(self.dgram_tx, mark.dgram_tx),
            dgram_rx: diff(self.dgram_rx, mark.dgram_rx),
            bytes_tx: diff(self.bytes_tx, mark.bytes_tx),
            bytes_rx: diff(self.bytes_rx, mark.bytes_rx),
        }
    }

    fn add(&mut self, other: Self) {
        self.ping_tx = self.ping_tx.saturating_add(other.ping_tx);
        self.ping_rx = self.ping_rx.saturating_add(other.ping_rx);
        self.ack_tx = self.ack_tx.saturating_add(other.ack_tx);
        self.dgram_tx = self.dgram_tx.saturating_add(other.dgram_tx);
        self.dgram_rx = self.dgram_rx.saturating_add(other.dgram_rx);
        self.bytes_tx = self.bytes_tx.saturating_add(other.bytes_tx);
        self.bytes_rx = self.bytes_rx.saturating_add(other.bytes_rx);
    }

    pub(crate) fn of(stats: &ConnectionStats) -> Self {
        Self {
            ping_tx: stats.frame_tx.ping,
            ping_rx: stats.frame_rx.ping,
            ack_tx: stats.frame_tx.acks.saturating_add(stats.frame_tx.path_acks),
            dgram_tx: stats.udp_tx.datagrams,
            dgram_rx: stats.udp_rx.datagrams,
            bytes_tx: stats.udp_tx.bytes,
            bytes_rx: stats.udp_rx.bytes,
        }
    }
}

/// One live connection as a census reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QuicReading {
    pub(crate) id: usize,
    pub(crate) kind: ConnKind,
    pub(crate) counts: QuicCounts,
}

/// The census line of a window. It reads as `name=kind:value,kind:value` words, one per field,
/// divided by spaces. `live` is a gauge at the end of the window and the others are deltas.
#[derive(Debug)]
pub(crate) struct QuicLine {
    pub(crate) live: String,
    pub(crate) ping_tx: String,
    pub(crate) ping_rx: String,
    pub(crate) ack_tx: String,
    pub(crate) dgram_tx: String,
    pub(crate) dgram_rx: String,
    pub(crate) bytes_tx: String,
    pub(crate) bytes_rx: String,
}

impl fmt::Display for QuicLine {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "live={} ping_tx={} ping_rx={} ack_tx={} dgram_tx={} dgram_rx={} bytes_tx={} bytes_rx={}",
            self.live,
            self.ping_tx,
            self.ping_rx,
            self.ack_tx,
            self.dgram_tx,
            self.dgram_rx,
            self.bytes_tx,
            self.bytes_rx
        )
    }
}

/// What the live connections did in one window, by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct QuicWindow {
    pub(crate) live: [u64; KIND_COUNT],
    pub(crate) moved: [QuicCounts; KIND_COUNT],
}

impl QuicWindow {
    /// One field of the window as `kind:value` pairs, for a census line.
    pub(crate) fn pairs(&self, pick: impl Fn(&Self, ConnKind) -> u64) -> String {
        let pair = |kind: ConnKind| format!("{}:{}", kind.name(), pick(self, kind));
        let pairs: Vec<String> = ConnKind::ALL.into_iter().map(pair).collect();
        pairs.join(",")
    }

    /// The fields of the census line.
    pub(crate) fn line(&self) -> QuicLine {
        let moved = |pick: fn(&QuicCounts) -> u64| {
            self.pairs(move |window, kind| pick(&window.moved_of(kind)))
        };
        QuicLine {
            live: self.pairs(Self::live_of),
            ping_tx: moved(|counts| counts.ping_tx),
            ping_rx: moved(|counts| counts.ping_rx),
            ack_tx: moved(|counts| counts.ack_tx),
            dgram_tx: moved(|counts| counts.dgram_tx),
            dgram_rx: moved(|counts| counts.dgram_rx),
            bytes_tx: moved(|counts| counts.bytes_tx),
            bytes_rx: moved(|counts| counts.bytes_rx),
        }
    }

    pub(crate) fn live_of(&self, kind: ConnKind) -> u64 {
        self.live[kind.index()]
    }

    pub(crate) fn moved_of(&self, kind: ConnKind) -> QuicCounts {
        self.moved[kind.index()]
    }
}

/// The reading of each live connection at the last census.
///
/// At most one mark per live connection: `take` drops the marks of the connections that are gone.
#[derive(Clone, Debug, Default)]
pub(crate) struct QuicTally {
    marks: HashMap<usize, QuicCounts>,
    started: bool,
}

impl QuicTally {
    /// What the live connections did since the last call. The first call only reads the marks, so
    /// it reports no movement: a connection that is older than the census has no window yet.
    /// What a connection did between the last call and its close is not counted. An id whose
    /// counters went down is a new connection, which counts from zero.
    pub(crate) fn take(&mut self, readings: &[QuicReading]) -> QuicWindow {
        let mut window = QuicWindow::default();
        let mut marks: HashMap<usize, QuicCounts> = HashMap::with_capacity(readings.len());
        for reading in readings {
            let index = reading.kind.index();
            window.live[index] += 1;
            if self.started {
                let seen = self.marks.get(&reading.id).copied().unwrap_or_default();
                let mark = if reading.counts.is_below(seen) {
                    QuicCounts::default()
                } else {
                    seen
                };
                window.moved[index].add(reading.counts.since(mark));
            }
            marks.insert(reading.id, reading.counts);
        }
        self.marks = marks;
        self.started = true;
        window
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnKind, QuicCounts, QuicReading, QuicTally, QuicWindow};
    use iroh::endpoint::ConnectionStats;

    /// Counts of `unit` times a weight that is different for each field (1, 2, 4, 8, 16, 32, 64),
    /// so that a test sees a field read from another field, and no two fields hold one value.
    fn counts(unit: u64) -> QuicCounts {
        QuicCounts {
            ping_tx: unit,
            ping_rx: 2 * unit,
            ack_tx: 4 * unit,
            dgram_tx: 8 * unit,
            dgram_rx: 16 * unit,
            bytes_tx: 32 * unit,
            bytes_rx: 64 * unit,
        }
    }

    fn reading(id: usize, kind: ConnKind, unit: u64) -> QuicReading {
        QuicReading {
            id,
            kind,
            counts: counts(unit),
        }
    }

    /// The first call reads the marks and reports no movement. The next calls report the delta of
    /// each connection in every field, a connection born in the window counts from zero, and a
    /// connection that is gone leaves no mark.
    #[test]
    fn a_window_is_the_delta_of_each_live_connection_since_the_last_call() {
        let mut tally = QuicTally::default();

        let first_readings = [
            reading(1, ConnKind::Gossip, 10),
            reading(2, ConnKind::Unicast, 20),
        ];
        let first = tally.take(&first_readings);
        assert_eq!(first.live_of(ConnKind::Gossip), 1, "live is a gauge");
        assert_eq!(first.live_of(ConnKind::Unicast), 1, "live is a gauge");
        assert_eq!(
            first.moved_of(ConnKind::Gossip),
            QuicCounts::default(),
            "the first call has no window"
        );

        let second_readings = [
            reading(1, ConnKind::Gossip, 13),
            reading(2, ConnKind::Unicast, 27),
            reading(3, ConnKind::Gossip, 2),
        ];
        let second = tally.take(&second_readings);
        assert_eq!(second.live_of(ConnKind::Gossip), 2, "1 old and 1 new");
        assert_eq!(
            second.moved_of(ConnKind::Gossip),
            counts(3 + 2),
            "3 more units on the old connection, and the 2 of the new one, in every field"
        );
        assert_eq!(
            second.moved_of(ConnKind::Unicast),
            counts(7),
            "7 more units, in every field"
        );
        assert_eq!(
            second.moved_of(ConnKind::Other),
            QuicCounts::default(),
            "no such connection"
        );

        let third = tally.take(&[reading(3, ConnKind::Gossip, 2)]);
        assert_eq!(
            third.live_of(ConnKind::Unicast),
            0,
            "the connection is gone"
        );
        assert_eq!(
            third.moved_of(ConnKind::Gossip),
            QuicCounts::default(),
            "3 did nothing"
        );

        let fourth = tally.take(&[reading(1, ConnKind::Gossip, 1)]);
        assert_eq!(
            fourth.moved_of(ConnKind::Gossip),
            counts(1),
            "an id that came back counts from zero: its old mark was dropped"
        );
    }

    /// An id can be reused: the stable id is the address of the connection, so a new connection
    /// can take the id of one that is gone between two calls. QUIC counters never go down, so a
    /// counter below its mark says that the connection is new, and it counts from zero. One
    /// counter below is enough.
    #[test]
    fn a_reused_id_with_a_lower_counter_counts_from_zero() {
        let mut tally = QuicTally::default();
        let old = [reading(1, ConnKind::Gossip, 10)];
        tally.take(&old);

        let reused = [reading(1, ConnKind::Gossip, 2)];
        let reused_window = tally.take(&reused);
        assert_eq!(
            reused_window.moved_of(ConnKind::Gossip),
            counts(2),
            "the new connection counts all it has, not 0"
        );

        let one_down = QuicCounts {
            bytes_rx: 1,
            ..counts(30)
        };
        let one_down_readings = [QuicReading {
            id: 1,
            kind: ConnKind::Gossip,
            counts: one_down,
        }];
        let one_down_window = tally.take(&one_down_readings);
        assert_eq!(
            one_down_window.moved_of(ConnKind::Gossip),
            one_down,
            "1 counter below its mark is enough: the others count from zero too"
        );
    }

    /// The text of one field: one pair per kind, in the order of the kinds.
    #[test]
    fn a_field_reads_as_one_pair_per_kind() {
        let mut tally = QuicTally::default();
        tally.take(&[reading(1, ConnKind::Gossip, 0)]);
        let readings = [
            reading(1, ConnKind::Gossip, 4),
            reading(2, ConnKind::Other, 6),
        ];
        let window = tally.take(&readings);
        let pings = window.pairs(|window, kind| window.moved_of(kind).ping_tx);
        let live = window.pairs(QuicWindow::live_of);

        assert_eq!(
            pings, "gossip:4,unicast:0,other:6",
            "the pings of the window"
        );
        assert_eq!(live, "gossip:1,unicast:0,other:1", "the live connections");
    }

    /// The census line holds every field once, with its own value, with the live gauge first.
    #[test]
    fn the_census_line_names_each_field_once() {
        let mut tally = QuicTally::default();
        tally.take(&[reading(1, ConnKind::Unicast, 0)]);
        let readings = [reading(1, ConnKind::Unicast, 2)];
        let line = tally.take(&readings).line().to_string();

        assert_eq!(
            line,
            "live=gossip:0,unicast:1,other:0 ping_tx=gossip:0,unicast:2,other:0 \
             ping_rx=gossip:0,unicast:4,other:0 ack_tx=gossip:0,unicast:8,other:0 \
             dgram_tx=gossip:0,unicast:16,other:0 dgram_rx=gossip:0,unicast:32,other:0 \
             bytes_tx=gossip:0,unicast:64,other:0 bytes_rx=gossip:0,unicast:128,other:0",
            "the line of one unicast connection that moved 2 units: each field has its weight"
        );
    }

    /// The counters of a connection come from the stats of QUIC: the ACK frames of a path are
    /// ACK frames. Each stat has a value of its own, so no field reads another one.
    #[test]
    fn the_counts_read_the_stats_of_a_connection() {
        let mut stats = ConnectionStats::default();
        stats.frame_tx.ping = 1;
        stats.frame_rx.ping = 2;
        stats.frame_tx.acks = 4;
        stats.frame_tx.path_acks = 8;
        stats.udp_tx.datagrams = 16;
        stats.udp_rx.datagrams = 32;
        stats.udp_tx.bytes = 64;
        stats.udp_rx.bytes = 128;

        assert_eq!(
            QuicCounts::of(&stats),
            QuicCounts {
                ping_tx: 1,
                ping_rx: 2,
                ack_tx: 12,
                dgram_tx: 16,
                dgram_rx: 32,
                bytes_tx: 64,
                bytes_rx: 128,
            },
            "each stat lands in its field, and the 2 kinds of ACK add up to 12"
        );
    }
}
