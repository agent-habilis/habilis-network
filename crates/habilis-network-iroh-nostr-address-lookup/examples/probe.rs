//! Probe public Nostr relays for what the lookup needs: do they forward an
//! ephemeral event between two subscribers, and how fast?
//!
//! ```text
//! cargo run -p habilis-network-iroh-nostr-address-lookup --example probe             # every candidate
//! cargo run -p habilis-network-iroh-nostr-address-lookup --example probe -- cadence wss://relay.example
//! ```
//!
//! `cadence` runs ten pools on one relay and one tag with the engine's announce
//! schedule for 30 s, and counts what each pool received.
//! Set `RUST_LOG=habilis_network::lookup=debug` to see each relay's refusal reason.
//!
//! The run ends with the list to pin: the fastest forwarding relay of each
//! operator, found by apex domain, and no test host. A pinned list that holds
//! several relays of one operator spends its slots on one point of failure.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use habilis_network_iroh_nostr_address_lookup::Pool;
use url::Url;

use futures_util::future;
use std::env;
use tokio::time;
/// Trystero's pinned list (2026-09) plus a few large public relays.
const CANDIDATES: &[&str] = &[
    "basspistol.org",
    "bucket.coracle.social",
    "chorus.pjv.me",
    "koru.bitcointxoko.org",
    "nos.lol",
    "nostr-01.uid.ovh",
    "nostr-01.yakihonne.com",
    "nostr-relay.corb.net",
    "nostr.data.haus",
    "nostr.islandarea.net",
    "nostr.sathoarder.com",
    "nostr.tegila.com.br",
    "nostr.vulpem.com",
    "purplerelay.com",
    "relay-can.zombi.cloudrodion.com",
    "relay-rpi.edufeed.org",
    "relay.agorist.space",
    "relay.artio.inf.unibe.ch",
    "relay.mostr.pub",
    "relay.mostro.network",
    "relay.sigit.io",
    "relay02.lnfi.network",
    "schnorr.me",
    "social.amanah.eblessing.co",
    "staging.yabu.me",
    "strfry.shock.network",
    "top.testrelay.top",
    "yabu.me/v2",
    "relay.damus.io",
    "relay.primal.net",
    "relay.nostr.band",
    "offchain.pub",
];

const CONNECT_BUDGET: Duration = Duration::from_secs(8);
const ECHO_BUDGET: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("cadence") {
        let url: Url = args
            .get(1)
            .expect("cadence needs a relay URL")
            .parse()
            .expect("a valid URL");
        cadence(url).await;
        return;
    }

    let probes = CANDIDATES.iter().map(|host| {
        let url: Url = format!("wss://{host}").parse().expect("a valid URL");
        async move { (url.clone(), probe(url).await) }
    });
    let mut results = future::join_all(probes).await;
    results.sort_by_key(|(_, outcome)| match outcome {
        Outcome::Forwards(rtt) => (0, *rtt),
        Outcome::Swallows => (1, Duration::ZERO),
        Outcome::NoConnect => (2, Duration::ZERO),
    });
    for (url, outcome) in &results {
        match outcome {
            Outcome::Forwards(rtt) => println!("ok      {:>5} ms  {url}", rtt.as_millis()),
            Outcome::Swallows => println!("no-echo           {url}"),
            Outcome::NoConnect => println!("down              {url}"),
        }
    }
    let ok = results
        .iter()
        .filter(|(_, outcome)| matches!(outcome, Outcome::Forwards(_)))
        .count();
    println!("{ok} of {} forward ephemeral events", results.len());

    // The results are sorted fastest first, so the first relay of an operator
    // is its fastest.
    let mut operators = HashSet::new();
    println!("\npin (the fastest forwarding relay per operator, no test host):");
    for (url, outcome) in &results {
        let (Outcome::Forwards(rtt), Some(host)) = (outcome, url.host_str()) else {
            continue;
        };
        if is_test_host(host) {
            println!("  skip {url}: a test host");
        } else if operators.insert(apex(host)) {
            println!(
                "  \"{}\",  // {} ms",
                url.as_str().trim_end_matches('/'),
                rtt.as_millis()
            );
        } else {
            println!("  skip {url}: {} has a faster relay above", apex(host));
        }
    }
}

/// The registrable domain of `host`: its last two labels, or the last three
/// when the last two are a country-code suffix such as `com.br`. A short rule
/// in place of the public suffix list, enough for a probe's candidate list.
fn apex(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    let suffix_labels = match labels.as_slice() {
        [.., second, last]
            if last.len() == 2 && ["com", "co", "org", "net", "ac", "gov"].contains(second) =>
        {
            3
        }
        _ => 2,
    };
    labels[labels.len().saturating_sub(suffix_labels)..].join(".")
}

/// A host that names itself a staging or test relay.
fn is_test_host(host: &str) -> bool {
    host.split('.')
        .any(|label| label == "staging" || label.starts_with("test"))
}

enum Outcome {
    Forwards(Duration),
    /// Connected, but our event never came back: refused, rate-limited, or
    /// ephemeral kinds dropped.
    Swallows,
    NoConnect,
}

async fn probe(url: Url) -> Outcome {
    let tag: [u8; 32] = rand::random();
    let (sender, _sender_rx) = Pool::open(vec![url.clone()], 1, &[tag]);
    let (_receiver, mut receiver_rx) = Pool::open(vec![url], 1, &[tag]);
    let connected = time::timeout(CONNECT_BUDGET, async {
        while sender.connected().is_empty() {
            time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if connected.is_err() {
        return Outcome::NoConnect;
    }
    // The shared socket sends our REQ before it reports `Up`, so one publish
    // is enough; a second one a second later covers a slow REQ install.
    let started = Instant::now();
    sender.publish(&tag, "probe".to_owned());
    let echo = time::timeout(ECHO_BUDGET, async {
        let retry = time::sleep(Duration::from_secs(1));
        tokio::pin!(retry);
        let mut retried = false;
        loop {
            tokio::select! {
                event = receiver_rx.recv() => return event,
                () = &mut retry, if !retried => {
                    retried = true;
                    sender.publish(&tag, "probe".to_owned());
                }
            }
        }
    })
    .await;
    match echo {
        Ok(Some(_)) => Outcome::Forwards(started.elapsed()),
        _ => Outcome::Swallows,
    }
}

/// The announce schedule the discovery service will use: 0, 1 and 3 s, then
/// every 5 s up to 30 s.
const SCHEDULE_SECS: &[u64] = &[0, 1, 3, 5, 10, 15, 20, 25, 30];
const NODES: usize = 10;

async fn cadence(url: Url) {
    let tag: [u8; 32] = rand::random();
    let mut pools = Vec::new();
    for _ in 0..NODES {
        pools.push(Pool::open(vec![url.clone()], 1, &[tag]));
    }
    // One process shares one socket per relay, which is not what ten real
    // nodes look like to the relay's per-connection limits, but it is what
    // they look like to its per-IP limits, and those are the ones that bite.
    time::sleep(Duration::from_secs(3)).await;
    let started = Instant::now();
    for &at in SCHEDULE_SECS {
        let target = Duration::from_secs(at);
        if let Some(wait) = target.checked_sub(started.elapsed()) {
            time::sleep(wait).await;
        }
        for (pool, _) in &pools {
            pool.publish(&tag, format!("hello {}", rand::random::<u64>()));
        }
    }
    time::sleep(Duration::from_secs(3)).await;
    let sent = SCHEDULE_SECS.len() * NODES;
    let expected_each = SCHEDULE_SECS.len() * (NODES - 1);
    println!("published {sent} events on {url}; each node expects {expected_each}");
    for (index, (_, receiver)) in pools.iter_mut().enumerate() {
        let mut got = 0;
        while receiver.try_recv().is_ok() {
            got += 1;
        }
        println!("node {index}: received {got}");
    }
}
