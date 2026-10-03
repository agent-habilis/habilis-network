//! The pkarr leg of the lookup layer: signed address records on HTTPS pkarr
//! relays. It is the one lookup other than the relay that a browser can use,
//! because it needs only `fetch`.
//!
//! The publisher and the resolver are ours, not iroh's `PkarrPublisher` and
//! `PkarrResolver`, for three reasons that each broke a promise the mesh makes:
//!
//! - iroh's publisher publishes whatever the endpoint reports, so a record
//!   with no relay address (the endpoint is not home yet, or lost its relay)
//!   would replace the last good one. For the shared rendezvous key that
//!   locks every joiner out. This publisher skips such a record.
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
use tracing::{Instrument as _, debug, info_span, warn};

use crate::protocol::{PkarrChoice, Url};

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
        retry_cap: Duration::from_secs(60),
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
        self.record.send_replace(Some(info));
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
                    failed = 0;
                    timing.republish
                }
                outcome => {
                    failed = failed.saturating_add(1);
                    let wait = timing.backoff(failed);
                    match outcome {
                        Ok(Err(err)) => {
                            warn!(error = %format!("{err:#}"), ?wait, failed, "pkarr publish failed");
                        }
                        _ => warn!(?wait, failed, "pkarr publish timed out"),
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

/// Add a lookup for every URL of `choice`. A member publishes to all of them,
/// so a peer that can reach any one resolves it.
pub(super) fn wire(mut builder: Builder, choice: &PkarrChoice) -> Builder {
    let urls: &[Url] = match choice {
        PkarrChoice::Disabled => return builder,
        PkarrChoice::Pinned => &DEFAULT_PKARR_URL_LIST,
        PkarrChoice::Custom(urls) => urls,
    };
    for url in urls {
        builder = builder.address_lookup(PkarrBuilder { url: url.clone() });
    }
    builder
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
                Mode::Accept => {}
                Mode::Refuse => {
                    return Err(LookupError::from_err_any(
                        "test",
                        std::io::Error::other("409 not newer"),
                    ));
                }
                Mode::HangFirst if call == 0 => std::future::pending().await,
                Mode::HangFirst => {}
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
}
