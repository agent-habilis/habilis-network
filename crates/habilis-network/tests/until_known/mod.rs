//! What the tests that name a member in a request share: wait until the node knows the member.

use std::time::{Duration, Instant};

use habilis_network::membership::{Membership, Request, UnknownPeer};
use tokio::sync::oneshot;

/// How long a node may take to learn a member from its `PeerInfo`. It is the time the test waits for
/// a fact, not a sleep of a guessed length: the request is sent again every 250 ms and the wait
/// ends at the first answer that applied.
const PEER_KNOWN_DEADLINE: Duration = Duration::from_secs(30);

/// Send the request that `build` makes until the node knows the member that it names. A request on
/// a member the node does not know yet does nothing, and the node says so; the test then waits for
/// the `PeerInfo` instead of going on as if the cut, the deny or the offer had been made.
///
/// # Panics
/// The event loop stopped, or the node does not know the member after [`PEER_KNOWN_DEADLINE`].
pub(crate) async fn until_peer_known(
    membership: &Membership,
    peer: &str,
    build: impl Fn(oneshot::Sender<Result<(), UnknownPeer>>) -> Request,
) {
    let deadline = Instant::now() + PEER_KNOWN_DEADLINE;
    loop {
        match membership.request(&build).await.expect("the loop answers") {
            Ok(()) => return,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(unknown) => panic!(
                "{unknown} after {PEER_KNOWN_DEADLINE:?}: the request on {peer:?} did not apply"
            ),
        }
    }
}
