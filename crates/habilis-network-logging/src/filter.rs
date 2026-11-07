#[cfg(feature = "host")]
// One literal for each directive, joined by `concat!`: a string with continuation lines loses a
// directive when a line lacks its backslash, and rustfmt can rewrite such a string. A test parses
// every directive.
const SUBSYSTEMS: &str = concat!(
    "habilis_network::gossip=info,",
    "habilis_network::lookup=info,",
    "habilis_network::beacon=info,",
    "habilis_network::lifecycle=info,",
    "habilis_network::directory=info,",
    "habilis_network::messages=info,",
    "habilis_network::blob=info",
);

/// Default tracing directives when `RUST_LOG` is unset (`RUST_LOG`
/// wins). Quiets benign `noq_proto::connection`; release also drops the
/// env-dependent `mainline::rpc` DHT-bootstrap ERROR; the `messages`
/// target is pinned on so it lands at any base level. See AGENTS.md.
///
/// Our own operational subsystems (gossip/lookup/beacon/lifecycle/directory)
/// are pinned to `info` in BOTH profiles so the always-on log file
/// carries the connectivity/lifecycle story even in a release build
/// (whose `error` base would otherwise drop every diagnostic) — the
/// same rationale as the `messages=info` pin. tracing writes only to
/// the file sink; `--output json` (stdout) is a separate path, so this
/// never affects the event stream.
#[cfg(feature = "host")]
#[must_use]
pub fn log_filter(consumer_pins: &str) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let base = if cfg!(debug_assertions) {
            "info,noq_proto::connection=off"
        } else {
            "error,noq_proto::connection=off,mainline::rpc=off"
        };
        let mut directives = format!("{base},{SUBSYSTEMS}");
        if !consumer_pins.is_empty() {
            directives.push(',');
            directives.push_str(consumer_pins);
        }
        EnvFilter::new(directives)
    })
}

#[cfg(all(test, feature = "host"))]
mod tests {
    /// A release build drops every line below `error` unless its target is pinned, so the blob
    /// eviction warning is pinned like the other subsystems.
    #[test]
    fn the_blob_target_is_pinned_at_every_base_level() {
        assert!(
            super::SUBSYSTEMS.contains("habilis_network::blob=info"),
            "habilis_network::blob is not pinned: {}",
            super::SUBSYSTEMS
        );
    }

    /// The list is one string with continuation lines. A line that lacks its backslash leaves a
    /// newline and spaces inside the string: `EnvFilter` drops that directive (the pin of the target
    /// that follows does not work in a release build), and the launcher prints a parse error on
    /// stderr. `contains` does not see it, so every directive is parsed here, each one alone and the
    /// whole list, and the list is exactly the pinned targets, each at `info`.
    #[test]
    fn every_directive_of_the_pinned_list_is_clean_and_parses() {
        use tracing_subscriber::EnvFilter;
        let pinned = [
            "habilis_network::gossip=info",
            "habilis_network::lookup=info",
            "habilis_network::beacon=info",
            "habilis_network::lifecycle=info",
            "habilis_network::directory=info",
            "habilis_network::messages=info",
            "habilis_network::blob=info",
        ];
        let directives: Vec<&str> = super::SUBSYSTEMS.split(',').collect();

        assert_eq!(
            directives, pinned,
            "the list holds exactly the pinned targets, with no whitespace inside a directive"
        );
        for directive in &directives {
            EnvFilter::try_new(directive)
                .unwrap_or_else(|error| panic!("{directive:?} does not parse: {error}"));
        }
        EnvFilter::try_new(super::SUBSYSTEMS)
            .unwrap_or_else(|error| panic!("the whole list does not parse: {error}"));
    }
}
