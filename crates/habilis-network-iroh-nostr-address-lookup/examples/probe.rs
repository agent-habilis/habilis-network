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
//! Set `RUST_LOG=habilis_network::nostr=debug` to see each relay's refusal reason.

use std::time::{Duration, Instant};

use habilis_network_iroh_nostr_address_lookup::Pool;
use url::Url;

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
    let args: Vec<String> = std::env::args().skip(1).collect();
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
    let mut results = futures_util::future::join_all(probes).await;
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
    let connected = tokio::time::timeout(CONNECT_BUDGET, async {
        while sender.connected().is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
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
    let echo = tokio::time::timeout(ECHO_BUDGET, async {
        let retry = tokio::time::sleep(Duration::from_secs(1));
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
    tokio::time::sleep(Duration::from_secs(3)).await;
    let started = Instant::now();
    for &at in SCHEDULE_SECS {
        let target = Duration::from_secs(at);
        if let Some(wait) = target.checked_sub(started.elapsed()) {
            tokio::time::sleep(wait).await;
        }
        for (pool, _) in &pools {
            pool.publish(&tag, format!("hello {}", rand::random::<u64>()));
        }
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
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
