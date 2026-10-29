//! The mDNS leg of the lookup layer: same-LAN multicast publish/resolve
//! of the seed-derived `rendezvous_id`. Wired only when `--mdns` is in
//! the allowlist; it accelerates same-LAN bootstrap and is one of the
//! independently-sufficient reliability layers (see the lookup glossary
//! in AGENTS.md).

use anyhow::{Context, Result};
use std::collections::HashMap;

use futures_util::{Stream, StreamExt as _};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use tokio::sync::mpsc;

use super::LanEvent;

/// Wire the LAN mDNS address-lookup onto a bound endpoint. In iroh 1.0 the
/// provider is a companion crate built from the endpoint id and added to the
/// endpoint's address-lookup services.
pub(super) fn wire(endpoint: &Endpoint) -> Result<MdnsAddressLookup> {
    let lookup = MdnsAddressLookup::builder()
        .build(endpoint.id())
        .context("building mDNS address-lookup")?;
    let services = endpoint
        .address_lookup()
        .map_err(|err| anyhow::anyhow!("{err:?}"))
        .context("endpoint has no address-lookup services for mDNS")?;
    services.add(lookup.clone());
    tracing::debug!("mDNS address-lookup wired (LAN multicast publish + resolve)");
    Ok(lookup)
}

/// Whether a record's user data is our mesh's member tag.
pub(crate) fn is_member_tag(user_data: Option<&iroh::endpoint_info::UserData>, tag: &str) -> bool {
    user_data.is_some_and(|data| data.to_string() == tag)
}

/// The members of our mesh that the LAN announces, other than `own`: the records whose user data is
/// `tag`. Beacons, probes and endpoints of other meshes carry no tag, or another one.
pub(crate) async fn lan_events(
    lookup: &MdnsAddressLookup,
    tag: String,
    own: EndpointId,
) -> impl Stream<Item = LanEvent> + Unpin + use<> {
    lookup.subscribe().await.filter_map(move |event| {
        std::future::ready(match event {
            DiscoveryEvent::Discovered { endpoint_info, .. }
                if endpoint_info.endpoint_id != own
                    && is_member_tag(endpoint_info.data.user_data(), &tag) =>
            {
                Some(LanEvent::Seen(endpoint_info.into_endpoint_addr()))
            }
            DiscoveryEvent::Expired { endpoint_id } if endpoint_id != own => {
                Some(LanEvent::Gone(endpoint_id))
            }
            DiscoveryEvent::Discovered { .. } | DiscoveryEvent::Expired { .. } | _ => None,
        })
    })
}

/// Drop what the loop already knows. A `Seen` passes when the id is new or its addresses changed
/// (a repeat of the same record is the mDNS refresh, not news); a `Gone` passes only for an id that
/// was passed before, so an `Expired` for any other endpoint of the LAN ends here.
pub(crate) fn news_only(
    event: LanEvent,
    known: &mut HashMap<EndpointId, EndpointAddr>,
) -> Option<LanEvent> {
    match event {
        LanEvent::Seen(address) => {
            if known.get(&address.id) == Some(&address) {
                return None;
            }
            known.insert(address.id, address.clone());
            Some(LanEvent::Seen(address))
        }
        LanEvent::Gone(id) => known.remove(&id).map(|_| LanEvent::Gone(id)),
    }
}

/// The members of our mesh that the LAN announces, as a small channel that the event loop reads.
/// The raw subscribe channel of the lookup holds 20 events and drops when it is full, with no
/// replay, and one peer makes dozens of events: so a task of its own owns the subscribe stream from
/// the moment of the call, filters by tag, drops what is no news, and forwards the rest. The loop
/// never reads the raw stream.
pub(crate) async fn spawn_lan_contacts(
    lookup: &MdnsAddressLookup,
    tag: String,
    own: EndpointId,
) -> mpsc::Receiver<LanEvent> {
    let mut events = lan_events(lookup, tag, own).await;
    let (sender, receiver) = mpsc::channel(32);
    n0_future::task::spawn(async move {
        let mut known = HashMap::new();
        while let Some(event) = events.next().await {
            let Some(event) = news_only(event, &mut known) else {
                continue;
            };
            if sender.send(event).await.is_err() {
                break;
            }
        }
    });
    receiver
}
