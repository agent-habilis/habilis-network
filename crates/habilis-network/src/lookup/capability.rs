mod network_capability;

use std::time::Duration;

use anyhow::Result;
use iroh::Watcher;

use crate::protocol::mesh::LookupOpts;
use crate::util::clock;

pub use network_capability::NetworkCapability;

/// Build a public peer endpoint and read iroh's net-report, bounded by
/// `timeout`. Bind failure is the only hard error; a net-report that never
/// completes (offline) still yields a `NetworkCapability` with the local bind
/// info and `report_obtained = false`.
///
/// # Errors
/// The endpoint fails to bind (the local network stack is broken).
pub async fn probe(timeout: Duration) -> Result<NetworkCapability, super::EndpointError> {
    probe_checked(timeout)
        .await
        .map_err(super::EndpointError::internal)
}

async fn probe_checked(timeout: Duration) -> Result<NetworkCapability> {
    let endpoint = super::build_peer_endpoint(&LookupOpts::public_preset()).await?;
    let node_id = endpoint.id().to_string();
    let local_addrs = endpoint.bound_sockets();

    // The endpoint runs net-report continuously; `initialized()` resolves on
    // the first completed report. Offline, it never resolves → we time out and
    // report only the local bind.
    let mut watcher = endpoint.net_report();
    let report = tokio::time::timeout(timeout, watcher.initialized())
        .await
        .ok();

    let capability = match report {
        Some(report) => {
            let preferred = report.preferred_relay.clone();
            let preferred_relay_latency_ms: Option<u64> = preferred.as_ref().and_then(|url| {
                report
                    .relay_latency
                    .iter()
                    .filter(|(_, relay, _)| *relay == url)
                    .map(|(_, _, latency)| latency)
                    .min()
                    .map(clock::millis_saturating)
            });
            NetworkCapability {
                node_id,
                local_addrs,
                report_obtained: true,
                udp_v4: Some(report.udp_v4),
                udp_v6: Some(report.udp_v6),
                mapping_varies_by_dest: report.mapping_varies_by_dest(),
                public_v4: report.global_v4.map(|address| address.to_string()),
                public_v6: report.global_v6.map(|address| address.to_string()),
                preferred_relay: preferred.map(|url| url.to_string()),
                preferred_relay_latency_ms,
                captive_portal: report.captive_portal,
            }
        }
        None => NetworkCapability {
            node_id,
            local_addrs,
            report_obtained: false,
            udp_v4: None,
            udp_v6: None,
            mapping_varies_by_dest: None,
            public_v4: None,
            public_v6: None,
            preferred_relay: None,
            preferred_relay_latency_ms: None,
            captive_portal: None,
        },
    };
    endpoint.close().await;
    Ok(capability)
}
