use std::time::Duration;

use iroh::Endpoint;

use tokio::time;
/// Best-effort wait (≤5s) for the endpoint to publish reachable addresses, so a
/// freshly-minted ticket resolves immediately. Never blocks forever.
pub(crate) async fn wait_online(endpoint: &Endpoint) {
    let _ = time::timeout(Duration::from_secs(5), endpoint.online()).await;
}
