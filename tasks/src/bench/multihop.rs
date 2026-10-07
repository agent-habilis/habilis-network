//! The multihop cells: real multihop nodes on loopback, the application
//! endpoints sharing only the multihop transport, so the bytes cross the
//! underlay hop by hop.

use std::net::SocketAddr;

use habilis_network_iroh_multihop_transport::{HandleConfig, MultihopHandle, underlay_secret};
use habilis_network_iroh_webrtc_transport::bench::{BENCH_ALPN, Bench};
use habilis_network_iroh_webrtc_transport::iroh::endpoint::presets;
use habilis_network_iroh_webrtc_transport::iroh::protocol::Router;
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
};

use super::Args;
use super::native::ladder_measure;
use super::run::Outcome;

/// Uniform link cost. With one route the value does not matter.
const COST: u32 = 10;

/// An application endpoint whose only transport is multihop, with its
/// routing handle.
struct Node {
    app: Endpoint,
    handle: MultihopHandle,
    id: EndpointId,
}

/// The loopback underlay of a node, on the key derived from the node's own.
async fn underlay(secret: &SecretKey) -> Result<Endpoint, String> {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("a literal loopback address");
    Endpoint::builder(presets::Minimal)
        .secret_key(underlay_secret(secret))
        .relay_mode(RelayMode::Disabled)
        .bind_addr(loopback)
        .map_err(|error| format!("bind address refused: {error:#}"))?
        .bind()
        .await
        .map_err(|error| format!("underlay bind failed: {error:#}"))
}

async fn node(secret: SecretKey) -> Result<Node, String> {
    let handle = hop(&secret).await?;
    let app = Endpoint::builder(presets::Minimal)
        .secret_key(secret.clone())
        .relay_mode(RelayMode::Disabled)
        .preset(handle.clone())
        .clear_ip_transports()
        .clear_relay_transports()
        .bind()
        .await
        .map_err(|error| format!("app bind failed: {error:#}"))?;
    Ok(Node {
        app,
        handle,
        id: secret.public(),
    })
}

/// A member that only forwards: an underlay and a routing handle, with no
/// application endpoint.
async fn hop(secret: &SecretKey) -> Result<MultihopHandle, String> {
    MultihopHandle::new(secret, underlay(secret).await?, HandleConfig::default())
        .map_err(|error| format!("multihop handle failed: {error:#}"))
}

fn secret(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn require_forwarded(cells: u64) -> Result<(), String> {
    if cells == 0 {
        return Err(
            "the third member forwarded no cells: this is not a three-node path".to_owned(),
        );
    }
    Ok(())
}

/// Two nodes with a direct underlay link between them.
pub(crate) async fn ladder_multihop_direct(args: &Args) -> Outcome {
    let run = async {
        let alice = node(secret(1)).await?;
        let bob = node(secret(2)).await?;
        alice
            .handle
            .feed_topology(alice.handle.link_vector(vec![(bob.id, COST)]));
        alice
            .handle
            .feed_topology(bob.handle.link_vector(vec![(alice.id, COST)]));
        let _router = Router::builder(bob.app.clone())
            .accept(BENCH_ALPN, Bench)
            .spawn();
        ladder_measure(&alice.app, EndpointAddr::from(bob.id), args, 0.0).await
    };
    Box::pin(run).await.into()
}

/// Two nodes with a third member between them: every cell crosses the third.
pub(crate) async fn ladder_multihop_third(args: &Args) -> Outcome {
    let run = async {
        let alice = node(secret(11)).await?;
        let third = hop(&secret(12)).await?;
        let third_id = secret(12).public();
        let bob = node(secret(13)).await?;
        alice
            .handle
            .feed_topology(alice.handle.link_vector(vec![(third_id, COST)]));
        alice
            .handle
            .feed_topology(third.link_vector(vec![(alice.id, COST), (bob.id, COST)]));
        alice
            .handle
            .feed_topology(bob.handle.link_vector(vec![(third_id, COST)]));
        let _router = Router::builder(bob.app.clone())
            .accept(BENCH_ALPN, Bench)
            .spawn();
        let measured = ladder_measure(&alice.app, EndpointAddr::from(bob.id), args, 0.0).await?;
        require_forwarded(third.forwarded_cells())?;
        Ok(measured)
    };
    Box::pin(run).await.into()
}

#[cfg(test)]
mod tests {
    use super::{Args, Outcome, ladder_multihop_direct, ladder_multihop_third, require_forwarded};
    use crate::bench::Direction;

    fn small_args() -> Args {
        Args {
            only: None,
            bytes: 64 * 1024,
            rounds: 2,
            direction: Direction::Down,
            list: false,
            json: None,
        }
    }

    #[tokio::test]
    async fn the_direct_multihop_cell_is_on_the_multihop_path_with_round_trips() {
        let Outcome::Ok(measured) = ladder_multihop_direct(&small_args()).await else {
            panic!("the direct multihop cell did not measure");
        };

        assert_eq!(measured.path, "multihop");
        assert!(measured.rtt.is_some());
    }

    #[tokio::test]
    async fn the_third_member_cell_is_on_the_multihop_path_through_the_third() {
        let Outcome::Ok(measured) = ladder_multihop_third(&small_args()).await else {
            panic!("the third-member multihop cell did not measure");
        };

        assert_eq!(measured.path, "multihop");
        assert!(measured.rtt.is_some());
    }

    /// A "via a third member" number from a run where the third forwarded
    /// nothing would be a direct number with the wrong name.
    #[test]
    fn a_third_member_that_forwarded_nothing_is_an_error() {
        assert!(require_forwarded(0).is_err());
        assert!(require_forwarded(1).is_ok());
    }
}
