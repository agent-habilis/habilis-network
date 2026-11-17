//! Serve the test relay on one port until something kills the process, so a browser test has a relay to
//! reach. A browser cannot run the relay itself.
//!
//! ```text
//! cargo run -p habilis-network-iroh-nostr-address-lookup --features test-relay \
//!     --example serve_relay -- 127.0.0.1:7447
//! ```
//!
//! It prints `listening ws://ADDRESS` once the port is open.

use std::process::ExitCode;
use std::{env, future};

use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;

#[tokio::main]
async fn main() -> ExitCode {
    let Some(address) = env::args().nth(1) else {
        eprintln!("usage: serve_relay ADDRESS (for example 127.0.0.1:7447)");
        return ExitCode::from(2);
    };
    let relay = match TestRelay::spawn_on(&address).await {
        Ok(relay) => relay,
        Err(error) => {
            eprintln!("cannot listen on {address}: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("listening {}", relay.url());
    // Kill the process to stop the relay.
    let forever: future::Pending<()> = future::pending();
    forever.await;
    ExitCode::SUCCESS
}
