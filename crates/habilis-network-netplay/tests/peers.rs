//! Two and four peers over a deliberately hostile in-memory transport.
//!
//! The point is not that the happy path works — it is that the protocol
//! survives what a real network does: dropping packets, delivering them out
//! of order, delivering them twice, and delaying them. Each of those is
//! injectable here and deterministic, so a failure reproduces exactly rather
//! than once a week on someone's flaky wifi.
//!
//! Every peer runs in the same process against a shared mailbox. That is the
//! *only* thing faked; the protocol, the rollback engine and the session are
//! the real ones.

use std::collections::HashMap;
use std::rc::Rc;

use habilis_network_netplay::{
    Config, Event, Message, P2PSession, Request, RollbackError, SessionState, Transport,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
struct Input(i32);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    value: i64,
    frame: i32,
}

#[derive(Debug)]
struct Game;

impl Config for Game {
    type Input = Input;
    type State = State;
    type Address = String;
}

/// A deterministic pseudo-random source, so "random" loss is reproducible.
/// Portable by construction — the same reason the light-cycles example rolls
/// its own rather than using `rand`.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut word = self.0;
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^ (word >> 31)
    }

    /// True with probability `percent`/100.
    fn chance(&mut self, percent: u64) -> bool {
        percent > 0 && self.next() % 100 < percent
    }
}

/// How badly the network should misbehave.
#[derive(Clone, Copy, Default)]
struct Impairment {
    /// Percent chance a packet is thrown away outright.
    drop: u64,
    /// Percent chance a packet is delivered twice.
    duplicate: u64,
    /// Percent chance a packet is held back and released later, arriving
    /// after packets sent behind it.
    reorder: u64,
}

/// One shared mailbox every peer sends into and reads out of.
#[derive(Default)]
struct Network {
    /// Addressee -> packets waiting.
    inboxes: HashMap<String, Vec<(String, Message<Input>)>>,
    /// Packets held back to be delivered later, out of order.
    delayed: Vec<(String, String, Message<Input>)>,
    impairment: Impairment,
    rng_state: u64,
}

impl Network {
    fn deliver(&mut self, from: &str, to: &str, message: Message<Input>) {
        let mut rng = Rng(self.rng_state);
        let dropped = rng.chance(self.impairment.drop);
        let duplicated = rng.chance(self.impairment.duplicate);
        let delayed = rng.chance(self.impairment.reorder);
        self.rng_state = rng.0;

        if dropped {
            return;
        }
        if delayed {
            self.delayed.push((from.to_owned(), to.to_owned(), message));
            return;
        }
        let inbox = self.inboxes.entry(to.to_owned()).or_default();
        inbox.push((from.to_owned(), message.clone()));
        if duplicated {
            inbox.push((from.to_owned(), message));
        }
    }

    /// Release everything held back, ahead of anything sent since — which is
    /// what makes the delivery order wrong.
    fn flush_delayed(&mut self) {
        for (from, to, message) in std::mem::take(&mut self.delayed) {
            self.inboxes.entry(to).or_default().push((from, message));
        }
    }

    fn take(&mut self, addr: &str) -> Vec<(String, Message<Input>)> {
        self.inboxes.remove(addr).unwrap_or_default()
    }
}

/// One peer's view of the shared network.
struct Wire {
    addr: String,
    net: Rc<std::cell::RefCell<Network>>,
}

impl Transport<Game> for Wire {
    fn send_to(&mut self, message: &Message<Input>, addr: &String) {
        self.net
            .borrow_mut()
            .deliver(&self.addr, addr, message.clone());
    }

    fn receive_all(&mut self) -> Vec<(String, Message<Input>)> {
        self.net.borrow_mut().take(&self.addr)
    }
}

/// A peer: its session plus the state its requests drive.
struct Peer {
    session: P2PSession<Game, Wire>,
    state: State,
    desynced: bool,
}

impl Peer {
    fn checksum(state: &State) -> u128 {
        u128::from(state.value.cast_unsigned()) ^ (u128::from(state.frame.cast_unsigned()) << 64)
    }

    fn handle(&mut self, request: Request<Game>) {
        match request {
            Request::SaveState { cell, frame } => {
                cell.save(frame, self.state.clone(), Some(Self::checksum(&self.state)));
            }
            Request::LoadState { cell } => {
                self.state = cell.load().expect("the session only loads frames it saved");
            }
            Request::AdvanceFrame { inputs } => {
                let sum: i64 = inputs.iter().map(|(input, _)| i64::from(input.0)).sum();
                self.state.value += sum;
                self.state.frame += 1;
            }
        }
    }
}

/// Build `count` peers on one network, with the given impairment.
fn build(count: usize, impairment: Impairment) -> (Rc<std::cell::RefCell<Network>>, Vec<Peer>) {
    let net = Rc::new(std::cell::RefCell::new(Network {
        impairment,
        rng_state: 0x1234_5678,
        ..Network::default()
    }));
    let addrs: Vec<String> = (0..count).map(|index| format!("peer-{index}")).collect();

    let peers = (0..count)
        .map(|handle| {
            let wire = Wire {
                addr: addrs[handle].clone(),
                net: Rc::clone(&net),
            };
            Peer {
                session: P2PSession::new(
                    addrs.clone(),
                    handle,
                    wire,
                    8,
                    0,
                    // A distinct nonce per peer, as a real session would.
                    0xA000 + u32::try_from(handle).expect("handle fits"),
                )
                .expect("handle is in range"),
                state: State::default(),
                desynced: false,
            }
        })
        .collect();
    (net, peers)
}

/// Run `ticks` of the frame loop across every peer.
fn run(net: &Rc<std::cell::RefCell<Network>>, peers: &mut [Peer], ticks: usize) {
    for tick in 0..ticks {
        for (handle, peer) in peers.iter_mut().enumerate() {
            peer.session.poll_remote_peers();
            for event in peer.session.drain_events() {
                if let Event::Desync { .. } = event {
                    peer.desynced = true;
                }
            }
            if peer.session.state() != SessionState::Running {
                continue;
            }
            // A distinct, frame-varying input per player so a misattributed
            // packet shows up as a wrong total rather than passing by luck.
            let value =
                i32::try_from(tick % 7).expect("small") + i32::try_from(handle).expect("small");
            if peer.session.add_local_input(Input(value)).is_err() {
                continue;
            }
            match peer.session.advance_frame() {
                Ok(requests) => {
                    for request in requests {
                        peer.handle(request);
                    }
                    peer.session.publish_checksum();
                }
                // The peer is behind, or we are deliberately yielding.
                Err(RollbackError::PredictionLimit) => {}
                Err(other) => panic!("unexpected session error: {other}"),
            }
        }
        net.borrow_mut().flush_delayed();
    }
}

#[test]
fn two_peers_synchronize_before_either_starts() {
    let (net, mut peers) = build(2, Impairment::default());
    assert!(
        peers
            .iter()
            .all(|peer| peer.session.state() == SessionState::Synchronizing)
    );

    run(&net, &mut peers, 40);

    assert!(
        peers
            .iter()
            .all(|peer| peer.session.state() == SessionState::Running),
        "the handshake must complete on both sides"
    );
    assert!(
        peers.iter().all(|peer| peer.state.frame > 0),
        "and only then does anyone simulate"
    );
}

#[test]
fn two_peers_converge_on_a_clean_link() {
    let (net, mut peers) = build(2, Impairment::default());
    run(&net, &mut peers, 200);
    assert_converged(&peers);
}

#[test]
fn two_peers_converge_through_packet_loss() {
    let (net, mut peers) = build(
        2,
        Impairment {
            drop: 30,
            ..Impairment::default()
        },
    );
    run(&net, &mut peers, 400);
    assert_converged(&peers);
}

#[test]
fn two_peers_converge_through_duplication_and_reordering() {
    let (net, mut peers) = build(
        2,
        Impairment {
            duplicate: 25,
            reorder: 25,
            ..Impairment::default()
        },
    );
    run(&net, &mut peers, 400);
    assert_converged(&peers);
}

#[test]
fn four_peers_converge_under_everything_at_once() {
    let (net, mut peers) = build(
        4,
        Impairment {
            drop: 20,
            duplicate: 20,
            reorder: 20,
        },
    );
    run(&net, &mut peers, 500);
    assert_converged(&peers);
}

/// Every peer that got as far as frame N must agree about frame N.
///
/// Comparing final states directly would be wrong — peers legitimately sit
/// at different frames, since one may be mid-stall while another advances.
/// What must hold is that nobody reported a desync and the peers' progress
/// is within the prediction window of each other.
fn assert_converged(peers: &[Peer]) {
    assert!(
        peers.iter().all(|peer| !peer.desynced),
        "a peer reported a checksum mismatch"
    );
    assert!(
        peers
            .iter()
            .all(|peer| peer.session.state() == SessionState::Running),
        "every peer should still be connected"
    );

    let frames: Vec<i32> = peers.iter().map(|peer| peer.state.frame).collect();
    let lowest = *frames.iter().min().expect("at least one peer");
    let highest = *frames.iter().max().expect("at least one peer");
    assert!(lowest > 0, "no peer made progress; frames were {frames:?}");
    assert!(
        highest - lowest <= 16,
        "peers drifted apart instead of pacing together: {frames:?}"
    );
}
