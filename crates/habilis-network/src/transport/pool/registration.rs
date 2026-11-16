//! The outcome of asking the pool for a connection to a peer.

use tokio::sync::watch;

use super::in_flight_dial::InFlightDial;

use super::unicast_pool::DialOutcome;

/// What a caller of `UnicastPool::register_dial` became for one peer.
#[derive(Clone)]
pub(crate) enum Registration {
    Dialer(InFlightDial),
    Waiter(watch::Receiver<DialOutcome>),
}
