//! The command line, and what it resolves to.

use clap::Parser;
use fofoca::protocol::{Lookup, Transport};
use fofoca_stream::StreamOpts;

/// Stream stdin to one reader, or a stream's bytes to stdout.
#[derive(Debug, Parser)]
#[command(name = "fofoca-stream", version)]
pub(crate) struct Args {
    /// A stream hash to read to stdout. Without one, stdin is streamed and the
    /// new stream's hash is printed.
    pub hash: Option<String>,
    /// How peers find the producer, any of `mdns,dht,relay`. All three when
    /// none is named. Ignored when reading: the hash carries its own.
    #[arg(long, value_delimiter = ',')]
    pub lookup: Vec<Lookup>,
    /// What may carry the bytes: `p2p`, or `p2p,relay` to let them fall back
    /// to the relay. Ignored when reading: the hash carries it.
    #[arg(long, value_delimiter = ',')]
    pub transport: Vec<Transport>,
    /// A custom relay ladder, first preferred. Ignored when reading.
    #[arg(long = "relay-url", value_name = "URL")]
    pub relay_urls: Vec<String>,
    /// The web page's address, printed with the hash in its fragment as the
    /// URL a browser reads the stream from.
    #[arg(long, env = "FOFOCA_STREAM_WEB", value_name = "URL")]
    pub web_url: Option<String>,
    /// One JSON object per line on stderr instead of prose.
    #[arg(long)]
    pub robot: bool,
}

impl Args {
    /// The producing node's options. Every lookup when none is named: the
    /// hash is useless to a reader that cannot find the producer.
    pub(crate) fn opts(&self) -> StreamOpts {
        let lookup = if self.lookup.is_empty() {
            vec![Lookup::Mdns, Lookup::Dht, Lookup::Relay]
        } else {
            self.lookup.clone()
        };
        StreamOpts {
            lookup,
            transport: self.transport.clone(),
            relay_urls: self.relay_urls.clone(),
            ..StreamOpts::default()
        }
    }

    /// The page URL for `hash`, when a web address is known. The hash rides in
    /// the fragment, which a browser never sends to the server.
    pub(crate) fn page_url(&self, hash: &str) -> Option<String> {
        self.web_url.as_deref().map(|base| format!("{base}#{hash}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("fofoca-stream").chain(args.iter().copied()))
            .expect("valid args")
    }

    #[test]
    fn a_bare_producer_uses_every_lookup_and_a_named_one_replaces_them() {
        assert_eq!(
            parse(&[]).opts().lookup,
            vec![Lookup::Mdns, Lookup::Dht, Lookup::Relay]
        );
        assert_eq!(
            parse(&["--lookup", "mdns,relay"]).opts().lookup,
            vec![Lookup::Mdns, Lookup::Relay]
        );
    }

    #[test]
    fn transport_is_a_comma_list_of_known_names() {
        assert_eq!(
            parse(&["--transport", "p2p,relay"]).opts().transport,
            vec![Transport::P2p, Transport::Relay]
        );
        assert!(Args::try_parse_from(["fofoca-stream", "--lookup", "public"]).is_err());
    }

    #[test]
    fn a_positional_argument_is_the_hash_to_read() {
        assert_eq!(parse(&["abc"]).hash.as_deref(), Some("abc"));
        assert_eq!(parse(&[]).hash, None);
    }

    #[test]
    fn the_page_url_carries_the_hash_in_the_fragment() {
        let args = parse(&["--web-url", "http://127.0.0.1:3020/"]);
        assert_eq!(
            args.page_url("abc").as_deref(),
            Some("http://127.0.0.1:3020/#abc")
        );
        assert_eq!(parse(&[]).page_url("abc"), None);
    }
}
