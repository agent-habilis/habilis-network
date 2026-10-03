//! The pkarr leg of the lookup layer: signed address records on HTTPS pkarr
//! relays. It is the one lookup other than the relay that a browser can use,
//! because it needs only `fetch`.
//!
//! The publisher and the resolver are ours, not iroh's `PkarrPublisher` and
//! `PkarrResolver`, for three reasons that each broke a promise the mesh makes:
//!
//! - iroh's publisher publishes whatever the endpoint reports, so a record
//!   with no relay address (the endpoint is not home yet, or lost its relay)
//!   would replace the last good one. For the shared rendezvous key that can
//!   leave a bare-id dial with no address to try. This publisher skips such a
//!   record.
//! - iroh puts no deadline on a request, so a relay that accepts the
//!   connection and never answers stalls that publisher for good. Every
//!   request here runs under a timeout, and each relay has its own task, so a
//!   slow relay delays no other.
//! - iroh builds one HTTP client for the publisher and another for the
//!   resolver. Here one client serves both for each URL.

use std::fmt;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use iroh::address_lookup::{
    AddrFilter, AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, DEFAULT_PKARR_TTL,
    DEFAULT_REPUBLISH_INTERVAL, EndpointData, EndpointInfo, Error as LookupError, Item,
    PkarrRelayClient,
};
use iroh::endpoint::Builder;
use iroh::{Endpoint, EndpointId, SecretKey};
use n0_future::boxed::BoxStream;
use n0_future::task::AbortOnDropHandle;
use n0_future::time::{self, Duration};
use tokio::sync::watch;
use tracing::{Instrument as _, debug, info, info_span, warn};

use habilis_network_protocol::is_loopback;

use crate::protocol::{PkarrChoice, RelayChoice, Url};

/// The pinned list. The public relays form two groups that do not share
/// records: n0's server, and the Pubky relays, which share theirs through the
/// mainline DHT. One entry from each group makes each a fallback for the
/// other; the second Pubky entry covers an outage of the first.
///
/// `Pinned` is what the mesh id carries, not this list, like the pinned relay
/// ladder. A change here splits the members of one pinned mesh between two
/// lists until all of them upgrade, with no error, so keep an old entry until
/// no live build uses it.
const DEFAULT_PKARR_URLS: [&str; 3] = [
    "https://dns.iroh.link/pkarr",
    "https://pkarr.pubky.app/",
    "https://pkarr.pubky.org/",
];

static DEFAULT_PKARR_URL_LIST: LazyLock<Vec<Url>> = LazyLock::new(|| {
    DEFAULT_PKARR_URLS
        .iter()
        .map(|raw| {
            raw.parse()
                .expect("DEFAULT_PKARR_URLS entries are valid URLs")
        })
        .collect()
});

/// The clocks of one pkarr leg.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// The deadline of one request, a publish or a resolve.
    request: Duration,
    /// How often an unchanged record is published again.
    republish: Duration,
    /// After a failed publish the wait grows by this much per failure.
    retry_step: Duration,
    /// The longest wait after a failure.
    retry_cap: Duration,
}

impl Timing {
    const DEFAULT: Self = Self {
        request: Duration::from_secs(10),
        republish: DEFAULT_REPUBLISH_INTERVAL,
        retry_step: Duration::from_secs(1),
        retry_cap: Duration::from_mins(1),
    };

    /// The wait before the next try, after `failed` failures in a row.
    fn backoff(self, failed: u32) -> Duration {
        self.retry_step.saturating_mul(failed).min(self.retry_cap)
    }
}

/// One pkarr relay, as the lookup uses it. A trait so a test can stand in a
/// relay that hangs or refuses without a network.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
trait Relay: fmt::Debug + Send + Sync + 'static {
    /// Sign `info` and put it on the relay.
    async fn publish(&self, info: &EndpointInfo) -> Result<(), LookupError>;
    /// Get and verify the record of `id`.
    async fn resolve(&self, id: EndpointId) -> Result<EndpointInfo, LookupError>;
}

/// A real pkarr relay over HTTP.
#[derive(Debug)]
struct HttpRelay {
    client: PkarrRelayClient,
    secret_key: SecretKey,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Relay for HttpRelay {
    async fn publish(&self, info: &EndpointInfo) -> Result<(), LookupError> {
        let packet = info
            .to_pkarr_signed_packet(&self.secret_key, DEFAULT_PKARR_TTL)
            .map_err(|err| LookupError::from_err_any("pkarr", err))?;
        self.client
            .publish(&packet)
            .await
            .map_err(LookupError::from)
    }

    async fn resolve(&self, id: EndpointId) -> Result<EndpointInfo, LookupError> {
        let packet = self.client.resolve(id).await?;
        EndpointInfo::from_pkarr_signed_packet(&packet)
            .map_err(|err| LookupError::from_err_any("pkarr", err))
    }
}

/// The lookup for one pkarr relay: it publishes this endpoint's record there
/// and resolves other endpoints from there.
struct PkarrLookup {
    relay: Arc<dyn Relay>,
    endpoint_id: EndpointId,
    timing: Timing,
    /// The record to publish. The task reads it on every change and on every
    /// republish; `None` until the endpoint reports an address with a relay.
    record: watch::Sender<Option<EndpointInfo>>,
    _publisher: AbortOnDropHandle<()>,
}

impl fmt::Debug for PkarrLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkarrLookup")
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

impl PkarrLookup {
    fn new(relay: Arc<dyn Relay>, endpoint_id: EndpointId, timing: Timing) -> Self {
        let (record, watcher) = watch::channel(None);
        let task = n0_future::task::spawn(
            publish_loop(Arc::clone(&relay), watcher, timing)
                .instrument(info_span!("pkarr_publish")),
        );
        Self {
            relay,
            endpoint_id,
            timing,
            record,
            _publisher: AbortOnDropHandle::new(task),
        }
    }
}

impl AddressLookup for PkarrLookup {
    /// The record names the home relay and never an IP address, the same as
    /// the DHT leg, and it is never published without one.
    fn publish(&self, data: &EndpointData) {
        let data = data.apply_filter(&AddrFilter::relay_only());
        if data.relay_urls().next().is_none() {
            debug!("no relay address yet; the last published pkarr record stays");
            return;
        }
        let info = EndpointInfo::from_parts(self.endpoint_id, data.into_owned());
        // Wake the task only when the record differs. The endpoint reports
        // every change of its direct addresses, and after the relay-only
        // filter most of them leave the record as it was: a PUT for each
        // would be a write to a public relay that says nothing new.
        self.record.send_if_modified(|current| {
            if current.as_ref() == Some(&info) {
                false
            } else {
                *current = Some(info);
                true
            }
        });
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, LookupError>>> {
        let relay = Arc::clone(&self.relay);
        let request = self.timing.request;
        let lookup = async move {
            let info = time::timeout(request, relay.resolve(endpoint_id))
                .await
                .map_err(|elapsed| LookupError::from_err("pkarr", elapsed))??;
            Ok(Item::new(info, "pkarr", None))
        };
        Some(Box::pin(n0_future::stream::once_future(lookup)))
    }
}

/// How a publish outcome is logged. A relay that stays down fails on every
/// retry for as long as it is down, so only the first failure and the recovery
/// are worth a warning; the failures between are debug.
#[derive(Debug, PartialEq, Eq)]
enum Report {
    Warn,
    Debug,
    Recovered,
    Quiet,
}

impl Report {
    /// What to log, given whether the relay was already failing.
    fn after(was_failing: bool, succeeded: bool) -> Self {
        match (was_failing, succeeded) {
            (false, false) => Self::Warn,
            (true, false) => Self::Debug,
            (true, true) => Self::Recovered,
            (false, true) => Self::Quiet,
        }
    }
}

/// Publish the record when it changes and every `republish` period, and again
/// after a failure with a wait that grows to a cap.
async fn publish_loop(
    relay: Arc<dyn Relay>,
    mut record: watch::Receiver<Option<EndpointInfo>>,
    timing: Timing,
) {
    let mut failed: u32 = 0;
    loop {
        let info = record.borrow_and_update().clone();
        let wait = match info {
            None => timing.republish,
            Some(info) => match time::timeout(timing.request, relay.publish(&info)).await {
                Ok(Ok(())) => {
                    if Report::after(failed > 0, true) == Report::Recovered {
                        info!(failed, "pkarr publish recovered");
                    }
                    failed = 0;
                    timing.republish
                }
                outcome => {
                    let report = Report::after(failed > 0, false);
                    failed = failed.saturating_add(1);
                    let wait = timing.backoff(failed);
                    let error = match outcome {
                        Ok(Err(err)) => format!("{err:#}"),
                        _ => "timed out".to_owned(),
                    };
                    if report == Report::Warn {
                        warn!(%error, ?wait, "pkarr publish failed; retrying, and logging the retries at debug");
                    } else {
                        debug!(%error, ?wait, failed, "pkarr publish failed again");
                    }
                    wait
                }
            },
        };
        tokio::select! {
            changed = record.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = time::sleep(wait) => {}
        }
    }
}

/// Builds the lookup of one relay URL once the endpoint exists, because the
/// HTTP client takes the endpoint's TLS config and DNS resolver.
#[derive(Debug)]
struct PkarrBuilder {
    url: Url,
}

impl AddressLookupBuilder for PkarrBuilder {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        #[cfg(not(target_arch = "wasm32"))]
        let client = PkarrRelayClient::new(
            self.url,
            endpoint.tls_config().clone(),
            endpoint.dns_resolver()?.clone(),
        );
        #[cfg(target_arch = "wasm32")]
        let client = PkarrRelayClient::new(self.url);
        let relay = HttpRelay {
            client,
            secret_key: endpoint.secret_key().clone(),
        };
        Ok(PkarrLookup::new(
            Arc::new(relay),
            endpoint.id(),
            Timing::DEFAULT,
        ))
    }
}

/// The pkarr relays a mesh publishes to and resolves from.
///
/// The pinned list is skipped when every relay rung is on this machine: such
/// a mesh is local by construction (a test, a chat over a local relay), and
/// its members would otherwise write to n0's server and the Pubky relays a
/// record that names a relay no one else can reach, and a test run would
/// depend on those servers. A custom list is what the mesh asked for, so it
/// always applies.
fn urls_for<'a>(choice: &'a PkarrChoice, relay: &RelayChoice) -> &'a [Url] {
    match choice {
        PkarrChoice::Disabled => &[],
        PkarrChoice::Pinned => match relay {
            RelayChoice::Custom(ladder)
                if !ladder.is_empty() && ladder.iter().all(|rung| is_loopback(rung)) =>
            {
                &[]
            }
            RelayChoice::Disabled | RelayChoice::Pinned | RelayChoice::Custom(_) => {
                &DEFAULT_PKARR_URL_LIST
            }
        },
        PkarrChoice::Custom(urls) => urls,
    }
}

/// Add a lookup for every URL [`urls_for`] names. A member publishes to all of
/// them, so a peer that can reach any one resolves it.
pub(super) fn wire(mut builder: Builder, choice: &PkarrChoice, relay: &RelayChoice) -> Builder {
    let urls = urls_for(choice, relay);
    if urls.is_empty() && *choice == PkarrChoice::Pinned {
        debug!("pinned pkarr list skipped: every relay rung is local");
    }
    for url in urls {
        builder = builder.address_lookup(PkarrBuilder { url: url.clone() });
    }
    builder
}

/// A live check of the public relays, for `cargo task e2e --suite pkarr-live`.
/// Behind `iroh-test-utils` like [`test_pkarr`](super::test_pkarr), so none of
/// it is in a shipped build.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(super) mod probe {
    use super::{
        DEFAULT_PKARR_TTL, Endpoint, EndpointData, EndpointId, EndpointInfo, HttpRelay,
        PkarrRelayClient, Relay as _, SecretKey, Timing, Url, time,
    };

    /// The pinned list of public pkarr relays, as text.
    pub const DEFAULT_PKARR_URLS: [&str; 3] = super::DEFAULT_PKARR_URLS;

    /// A throwaway record for probing a pkarr relay: a fresh key, so no relay holds
    /// an older record of it, and the signed payload a `PUT` carries.
    #[derive(Debug, Clone)]
    pub struct ProbeRecord {
        /// The key as the relay path spells it (z-base-32).
        pub key: String,
        /// The signature, the timestamp and the DNS packet.
        pub payload: Vec<u8>,
    }

    /// A fresh [`ProbeRecord`]. It names a relay that does not exist, so a peer
    /// that resolves it can reach nothing.
    #[must_use]
    pub fn probe_record() -> ProbeRecord {
        let secret = SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let info = probe_info(secret.public());
        ProbeRecord {
            key: secret.public().to_z32(),
            payload: sign_probe(&info, &secret),
        }
    }

    /// The probe record of `id`. A fixed record, so building it cannot fail.
    fn probe_info(id: EndpointId) -> EndpointInfo {
        let relay = "https://pkarr-probe.invalid./"
            .parse()
            .expect("a fixed relay URL");
        let data = EndpointData::new(vec![iroh::TransportAddr::Relay(relay)]);
        EndpointInfo::from_parts(id, data)
    }

    fn sign_probe(info: &EndpointInfo, secret: &SecretKey) -> Vec<u8> {
        info.to_pkarr_signed_packet(secret, DEFAULT_PKARR_TTL)
            .expect("the probe record encodes")
            .to_relay_payload()
    }

    /// What the lookup's own client did against one relay.
    #[derive(Debug)]
    pub struct Probe {
        /// A signed record went out and the relay took it.
        pub published: Result<(), String>,
        /// The same record came back, signed by the same key.
        pub resolved: Result<(), String>,
    }

    /// Publish a throwaway record to `url` and resolve it back, through the same
    /// client and the same deadline as the lookup. Meant for a live check of a
    /// public relay; it reaches the network.
    pub async fn probe(url: &Url) -> Probe {
        let endpoint = match Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                let failed = Err(format!("no endpoint to probe from: {error:#}"));
                return Probe {
                    published: failed.clone(),
                    resolved: failed,
                };
            }
        };
        let relay = match endpoint.dns_resolver() {
            Ok(dns) => HttpRelay {
                client: PkarrRelayClient::new(
                    url.clone(),
                    endpoint.tls_config().clone(),
                    dns.clone(),
                ),
                secret_key: SecretKey::from_bytes(&rand::random::<[u8; 32]>()),
            },
            Err(error) => {
                let failed = Err(format!("no resolver to probe with: {error:#}"));
                return Probe {
                    published: failed.clone(),
                    resolved: failed,
                };
            }
        };
        let id = relay.secret_key.public();
        let info = probe_info(id);
        let published = match time::timeout(Timing::DEFAULT.request, relay.publish(&info)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("{error:#}")),
            Err(_) => Err("no answer before the deadline".to_owned()),
        };
        let resolved = match time::timeout(Timing::DEFAULT.request, relay.resolve(id)).await {
            Ok(Ok(found)) if found.endpoint_id == id && found.data == info.data => Ok(()),
            Ok(Ok(_)) => Err("the relay returned a different record".to_owned()),
            Ok(Err(error)) => Err(format!("{error:#}")),
            Err(_) => Err("no answer before the deadline".to_owned()),
        };
        endpoint.close().await;
        Probe {
            published,
            resolved,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use iroh::TransportAddr;

    use super::*;

    const FAST: Timing = Timing {
        request: Duration::from_millis(100),
        republish: Duration::from_mins(5),
        retry_step: Duration::from_millis(50),
        retry_cap: Duration::from_millis(400),
    };

    #[derive(Debug, Clone, Copy)]
    enum Mode {
        Accept,
        /// Like a relay that refuses a write that is not newer.
        Refuse,
        /// The first publish never answers; the later ones are accepted.
        HangFirst,
    }

    #[derive(Debug)]
    struct Fake {
        mode: Mode,
        calls: AtomicUsize,
        stored: Mutex<Vec<EndpointInfo>>,
    }

    impl Fake {
        fn new(mode: Mode) -> Arc<Self> {
            Arc::new(Self {
                mode,
                calls: AtomicUsize::new(0),
                stored: Mutex::default(),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn stored(&self) -> Vec<EndpointInfo> {
            self.stored.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Relay for Arc<Fake> {
        async fn publish(&self, info: &EndpointInfo) -> Result<(), LookupError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            match self.mode {
                Mode::Refuse => {
                    return Err(LookupError::from_err_any(
                        "test",
                        std::io::Error::other("409 not newer"),
                    ));
                }
                Mode::HangFirst if call == 0 => std::future::pending().await,
                Mode::Accept | Mode::HangFirst => {}
            }
            self.stored.lock().unwrap().push(info.clone());
            Ok(())
        }

        async fn resolve(&self, _id: EndpointId) -> Result<EndpointInfo, LookupError> {
            std::future::pending().await
        }
    }

    fn lookup(fake: &Arc<Fake>) -> PkarrLookup {
        let id = SecretKey::from_bytes(&[7; 32]).public();
        PkarrLookup::new(Arc::new(Arc::clone(fake)), id, FAST)
    }

    fn with_relay(port: u16) -> EndpointData {
        let relay = format!("http://127.0.0.1:{port}/")
            .parse()
            .expect("a relay url");
        EndpointData::new(vec![TransportAddr::Relay(relay)])
    }

    fn without_relay() -> EndpointData {
        EndpointData::new(vec![TransportAddr::Ip("127.0.0.1:9".parse().unwrap())])
    }

    async fn settle() {
        time::sleep(Duration::from_millis(300)).await;
    }

    #[tokio::test]
    async fn a_record_with_no_relay_is_never_published() {
        let fake = Fake::new(Mode::Accept);
        let lookup = lookup(&fake);
        lookup.publish(&without_relay());
        lookup.publish(&EndpointData::new(vec![]));
        settle().await;
        assert_eq!(fake.calls(), 0, "an empty record would replace a good one");
    }

    #[tokio::test]
    async fn a_record_that_loses_its_relay_leaves_the_last_good_one() {
        let fake = Fake::new(Mode::Accept);
        let lookup = lookup(&fake);
        lookup.publish(&with_relay(1));
        settle().await;
        lookup.publish(&without_relay());
        settle().await;
        let stored = fake.stored();
        assert_eq!(stored.len(), 1, "only the record with a relay goes out");
        assert!(stored[0].data.relay_urls().next().is_some());
    }

    #[tokio::test]
    async fn a_direct_address_is_not_published() {
        let fake = Fake::new(Mode::Accept);
        let lookup = lookup(&fake);
        let mut data = with_relay(1);
        data.add_ip_addrs(vec!["127.0.0.1:9".parse().unwrap()]);
        lookup.publish(&data);
        settle().await;
        let stored = fake.stored();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].data.ip_addrs().count(), 0);
    }

    #[tokio::test]
    async fn a_relay_that_never_answers_does_not_stall_a_later_publish() {
        let fake = Fake::new(Mode::HangFirst);
        let lookup = lookup(&fake);
        lookup.publish(&with_relay(1));
        time::sleep(Duration::from_millis(20)).await;
        lookup.publish(&with_relay(2));
        time::sleep(Duration::from_millis(600)).await;
        let stored = fake.stored();
        assert_eq!(stored.len(), 1, "the later publish got through");
        let relay = stored[0].data.relay_urls().next().unwrap().to_string();
        assert!(relay.contains(":2/"), "it is the newer record: {relay}");
    }

    #[tokio::test]
    async fn a_hung_relay_does_not_delay_another_relay() {
        let hung = Fake::new(Mode::HangFirst);
        let live = Fake::new(Mode::Accept);
        let hung_lookup = lookup(&hung);
        let live_lookup = lookup(&live);
        hung_lookup.publish(&with_relay(1));
        live_lookup.publish(&with_relay(1));
        time::sleep(Duration::from_millis(50)).await;
        assert_eq!(live.stored().len(), 1, "the live relay did not wait");
    }

    #[tokio::test]
    async fn a_refused_write_backs_off_instead_of_looping_hot() {
        let fake = Fake::new(Mode::Refuse);
        let lookup = lookup(&fake);
        lookup.publish(&with_relay(1));
        time::sleep(Duration::from_secs(1)).await;
        let calls = fake.calls();
        assert!(calls >= 2, "it retries: {calls}");
        assert!(calls <= 8, "it does not loop hot: {calls}");
    }

    #[tokio::test]
    async fn a_resolve_that_never_answers_ends_at_the_deadline() {
        use n0_future::StreamExt as _;

        let fake = Fake::new(Mode::Accept);
        let lookup = lookup(&fake);
        let id = SecretKey::from_bytes(&[9; 32]).public();
        let mut stream = lookup.resolve(id).expect("a stream");
        let started = time::Instant::now();
        let item = stream.next().await.expect("one item");
        assert!(item.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_direct_address_change_that_leaves_the_record_the_same_sends_no_put() {
        let fake = Fake::new(Mode::Accept);
        let lookup = lookup(&fake);
        let mut first = with_relay(1);
        first.add_ip_addrs(vec!["127.0.0.1:9".parse().unwrap()]);
        lookup.publish(&first);
        settle().await;
        assert_eq!(fake.calls(), 1);

        let mut moved = with_relay(1);
        moved.add_ip_addrs(vec!["127.0.0.1:10".parse().unwrap()]);
        lookup.publish(&moved);
        lookup.publish(&with_relay(1));
        settle().await;
        assert_eq!(fake.calls(), 1, "the relay-only record did not change");

        lookup.publish(&with_relay(2));
        settle().await;
        assert_eq!(fake.calls(), 2, "a new home relay is a new record");
    }

    fn rung(url: &str) -> iroh::RelayUrl {
        url.parse().expect("a relay url")
    }

    #[test]
    fn the_pinned_list_applies_beside_a_public_relay() {
        let public = RelayChoice::Custom(vec![rung("https://relay.example/")]);
        for relay in [RelayChoice::Pinned, RelayChoice::Disabled, public] {
            assert_eq!(urls_for(&PkarrChoice::Pinned, &relay).len(), 3, "{relay:?}");
        }
    }

    #[test]
    fn the_pinned_list_is_skipped_when_every_relay_rung_is_local() {
        for ladder in [
            vec![rung("http://127.0.0.1:3340/")],
            vec![rung("http://localhost:3340/"), rung("http://[::1]:3340/")],
        ] {
            assert!(urls_for(&PkarrChoice::Pinned, &RelayChoice::Custom(ladder)).is_empty());
        }
    }

    #[test]
    fn one_public_rung_among_local_ones_keeps_the_pinned_list() {
        let ladder = vec![
            rung("http://127.0.0.1:3340/"),
            rung("https://relay.example/"),
        ];
        let urls = urls_for(&PkarrChoice::Pinned, &RelayChoice::Custom(ladder));
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn a_custom_list_applies_beside_a_local_relay() {
        let custom = PkarrChoice::Custom(vec!["http://127.0.0.1:4000/pkarr".parse().unwrap()]);
        let local = RelayChoice::Custom(vec![rung("http://127.0.0.1:3340/")]);
        assert_eq!(urls_for(&custom, &local).len(), 1);
        assert!(urls_for(&PkarrChoice::Disabled, &local).is_empty());
    }

    #[test]
    fn only_the_first_failure_and_the_recovery_are_warnings() {
        assert_eq!(Report::after(false, false), Report::Warn);
        assert_eq!(Report::after(true, false), Report::Debug);
        assert_eq!(Report::after(true, true), Report::Recovered);
        assert_eq!(Report::after(false, true), Report::Quiet);
    }
}
