//! The mesh-wide config carried in the mesh id — the lookup allowlist
//! (`mdns`/`dht`/`relay`/`pkarr`) and the relay ladder and pkarr relay list it
//! may carry — plus its byte
//! codec and the `--advertise` directory selection. A mesh's network reach is
//! fully described by its lookups: no lookups means loopback-only; any lookup
//! means reachable across machines. The transport policy the id also carries
//! is `transport.rs`; [`MeshConfig`] is where the two meet.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use iroh_base::RelayUrl;
use serde::Deserialize;
use url::Url;

use super::transport::{Transport, TransportPolicy};
use super::{ChoiceError, MeshName};
use crate::crypto::PASSWORD_VERIFIER_LEN;

/// The connectivity relay. `Disabled` ⇒ no relay at all
/// (`RelayMode::Disabled`); `Pinned` ⇒ the lookup-layer pinned default
/// *ladder* (the n0 prod set); `Custom` ⇒ an operator-supplied **ordered
/// ladder** (`--relay a,b,c`). Relay is an allowlist member like
/// mdns/dht, not an always-on URL — the lookup layer turns
/// `Pinned`/`Custom` into an ordered relay ladder, and the beacon homes
/// on the first reachable rung (see `lookup::relay_ladder` /
/// `lookup::select_bootstrap_rung`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayChoice {
    Disabled,
    Pinned,
    Custom(Vec<RelayUrl>),
}

/// The pkarr relays a mesh publishes to and resolves from. `Pinned` ⇒ the
/// lookup layer's default list; `Custom` ⇒ an operator-supplied list. Every
/// member publishes to *every* URL, because the public relays form groups
/// that do not share records with each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkarrChoice {
    Disabled,
    Pinned,
    Custom(Vec<Url>),
}

/// The lookup allowlist baked into the mesh id. `mdns`/`dht`/`pkarr` are the
/// enabled iroh address-lookups (all resolve the same seed-derived
/// `rendezvous_id`); `relay_lookup` is the connectivity relay (see
/// [`RelayChoice`]). An all-off set is a loopback-only mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupOpts {
    pub mdns: bool,
    pub dht: bool,
    pub relay_lookup: RelayChoice,
    pub pkarr: PkarrChoice,
}

/// Wire ceiling on a custom relay ladder, so a forged id can't blow up
/// allocation. Far above any real ladder.
pub(super) const MAX_RELAY_LADDER: usize = 16;
/// Wire ceiling on a single relay URL's byte length.
pub(super) const MAX_RELAY_URL_BYTES: usize = 512;
/// Wire ceiling on a custom pkarr relay list.
const MAX_PKARR_URLS: usize = 16;

const FLAG_MDNS: u8 = 0b0001;
const FLAG_DHT: u8 = 0b0010;
const FLAG_RELAY: u8 = 0b0100;
const FLAG_RELAY_CUSTOM: u8 = 0b1000;
/// Pkarr is on; the pinned list unless [`FLAG_PKARR_CUSTOM`] is also set.
/// `0x10`/`0x20` are left for the Nostr lookup.
const FLAG_PKARR: u8 = 0b100_0000;
const FLAG_PKARR_CUSTOM: u8 = 0b1000_0000;
const KNOWN_LOOKUP_FLAGS: u8 =
    FLAG_MDNS | FLAG_DHT | FLAG_RELAY | FLAG_RELAY_CUSTOM | FLAG_PKARR | FLAG_PKARR_CUSTOM;

impl LookupOpts {
    /// Loopback-only: no address-lookups, no relay (the seed-derived
    /// port ladder bootstraps everything on one machine).
    #[must_use]
    pub fn loopback() -> Self {
        LookupOpts {
            mdns: false,
            dht: false,
            relay_lookup: RelayChoice::Disabled,
            pkarr: PkarrChoice::Disabled,
        }
    }

    /// The all-on default for a mesh reachable across machines: both
    /// address-lookups plus the pinned default relay ladder.
    #[must_use]
    pub fn public_preset() -> Self {
        LookupOpts {
            mdns: true,
            dht: true,
            relay_lookup: RelayChoice::Pinned,
            pkarr: PkarrChoice::Disabled,
        }
    }

    /// True when nothing reaches off-machine — the mesh is loopback-only.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        !self.mdns
            && !self.dht
            && self.relay_lookup == RelayChoice::Disabled
            && self.pkarr == PkarrChoice::Disabled
    }

    /// Human/JSON label for the mesh's reach. Derived from the lookups —
    /// there is no stored network mode.
    #[must_use]
    pub fn network_label(&self) -> &'static str {
        if self.is_loopback() {
            "private"
        } else {
            "public"
        }
    }

    /// The wire ceilings [`encode_into`](Self::encode_into) relies on. A
    /// caller-supplied ladder (`--relay-url`, `relayUrls`, the `relay_urls` C
    /// field) reaches the encoder unbounded otherwise: past
    /// [`MAX_RELAY_LADDER`] it mints an id [`decode_from`](Self::decode_from)
    /// rejects, and past 255 the count no longer fits its `u8`.
    ///
    /// # Errors
    /// The custom ladder is longer than [`MAX_RELAY_LADDER`], one of its
    /// URLs is longer than [`MAX_RELAY_URL_BYTES`], or the pkarr list fails
    /// [`validate_pkarr_urls`].
    pub fn validate(&self) -> Result<()> {
        if let PkarrChoice::Custom(urls) = &self.pkarr {
            validate_pkarr_urls(urls)?;
        }
        let RelayChoice::Custom(ladder) = &self.relay_lookup else {
            return Ok(());
        };
        if ladder.len() > MAX_RELAY_LADDER {
            bail!(
                "relay ladder too long: {} rungs, the wire ceiling is {MAX_RELAY_LADDER}",
                ladder.len()
            );
        }
        for url in ladder {
            let len = url.to_string().len();
            if len > MAX_RELAY_URL_BYTES {
                bail!("relay URL too long: {len} bytes, the wire ceiling is {MAX_RELAY_URL_BYTES}");
            }
        }
        Ok(())
    }

    /// Append the canonical wire encoding to `buf`:
    /// `[flags u8][if custom relay: list][if custom pkarr: list]`, each list
    /// `[count u8] ([len u16 LE] url)*`.
    ///
    /// # Panics
    /// If a relay ladder longer than `MAX_RELAY_LADDER`, a pkarr list longer
    /// than `MAX_PKARR_URLS`, or a URL longer than `MAX_RELAY_URL_BYTES`,
    /// reaches here — [`validate`](Self::validate) rejects all three, and
    /// every mint runs it, so this is a broken invariant rather than bad
    /// input.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        let mut flags: u8 = 0;
        if self.mdns {
            flags |= FLAG_MDNS;
        }
        if self.dht {
            flags |= FLAG_DHT;
        }
        match &self.relay_lookup {
            RelayChoice::Disabled => {}
            RelayChoice::Pinned => flags |= FLAG_RELAY,
            RelayChoice::Custom(_) => flags |= FLAG_RELAY | FLAG_RELAY_CUSTOM,
        }
        match &self.pkarr {
            PkarrChoice::Disabled => {}
            PkarrChoice::Pinned => flags |= FLAG_PKARR,
            PkarrChoice::Custom(_) => flags |= FLAG_PKARR | FLAG_PKARR_CUSTOM,
        }
        buf.push(flags);
        if let RelayChoice::Custom(ladder) = &self.relay_lookup {
            encode_urls(buf, ladder.iter().map(ToString::to_string));
        }
        if let PkarrChoice::Custom(urls) = &self.pkarr {
            encode_urls(buf, urls.iter().map(|url| url.as_str().to_owned()));
        }
    }

    /// Decode from a cursor over the config region, advancing `pos`.
    /// # Errors
    /// The buffer is truncated, the encoded length exceeds what remains, or a
    /// lookup bit is unknown to this build.
    pub fn decode_from(bytes: &[u8], pos: &mut usize) -> Result<Self> {
        let flags = *bytes.get(*pos).context("truncated lookup flags")?;
        *pos += 1;
        if flags & !KNOWN_LOOKUP_FLAGS != 0 {
            bail!("unsupported lookup flags {flags:#04x}: upgrade to a newer build");
        }
        let mdns = flags & FLAG_MDNS != 0;
        let dht = flags & FLAG_DHT != 0;
        let relay_enabled = flags & FLAG_RELAY != 0;
        let relay_custom = flags & FLAG_RELAY_CUSTOM != 0;
        if relay_custom && !relay_enabled {
            bail!("custom-relay bit set without relay-enabled bit");
        }
        let relay_lookup = if !relay_enabled {
            RelayChoice::Disabled
        } else if !relay_custom {
            RelayChoice::Pinned
        } else {
            let count = *bytes.get(*pos).context("truncated relay ladder count")? as usize;
            *pos += 1;
            if count == 0 {
                bail!("custom relay ladder is empty");
            }
            if count > MAX_RELAY_LADDER {
                bail!("relay ladder too long: {count}");
            }
            RelayChoice::Custom(decode_relay_ladder(bytes, pos, count)?)
        };
        let pkarr = match (flags & FLAG_PKARR != 0, flags & FLAG_PKARR_CUSTOM != 0) {
            (false, true) => bail!("custom-pkarr bit set without pkarr-enabled bit"),
            (false, false) => PkarrChoice::Disabled,
            (true, false) => PkarrChoice::Pinned,
            (true, true) => PkarrChoice::Custom(decode_pkarr_urls(bytes, pos)?),
        };
        let opts = LookupOpts {
            mdns,
            dht,
            relay_lookup,
            pkarr,
        };
        opts.validate()?;
        Ok(opts)
    }
}

/// `[count u8] ([len u16 LE] url)*`. The lists are created locally and bounded
/// by [`LookupOpts::validate`], which every mint runs, so the casts always fit.
fn encode_urls(buf: &mut Vec<u8>, urls: impl ExactSizeIterator<Item = String>) {
    buf.push(u8::try_from(urls.len()).expect("URL list bounded by validate"));
    for text in urls {
        let len = u16::try_from(text.len()).expect("URL bounded by MAX_RELAY_URL_BYTES");
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(text.as_bytes());
    }
}

/// Decode a pkarr list. A URL must come back in the exact text it was
/// encoded from: `Url` normalizes, and a normalized copy would re-encode to
/// other config bytes and so to another topic.
fn decode_pkarr_urls(bytes: &[u8], pos: &mut usize) -> Result<Vec<Url>> {
    let count = *bytes.get(*pos).context("truncated pkarr list count")? as usize;
    *pos += 1;
    if count > MAX_PKARR_URLS {
        bail!("pkarr list too long: {count}");
    }
    let mut urls = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u16(bytes, pos).context("truncated pkarr URL length")? as usize;
        if len > MAX_RELAY_URL_BYTES {
            bail!("pkarr URL too long: {len}");
        }
        let end = pos.checked_add(len).context("pkarr URL length overflow")?;
        let raw = bytes.get(*pos..end).context("truncated pkarr URL")?;
        *pos = end;
        let text = std::str::from_utf8(raw).context("pkarr URL is not UTF-8")?;
        let url = Url::parse(text).context("invalid pkarr URL")?;
        if url.as_str() != text {
            bail!("non-canonical pkarr URL {text:?}");
        }
        urls.push(url);
    }
    Ok(urls)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Parse the pkarr relay list a surface passes as strings (`pkarrUrls`, the
/// `pkarr_urls` C field, `--pkarr-url`). Empty ⇒ `None`, the pinned default.
///
/// # Errors
/// An entry is not a URL, or the list fails [`validate_pkarr_urls`].
pub fn parse_pkarr_urls(texts: &[String]) -> Result<Option<Vec<Url>>> {
    if texts.is_empty() {
        return Ok(None);
    }
    let urls = texts
        .iter()
        .map(|text| Url::parse(text.trim()).with_context(|| format!("invalid pkarr URL {text:?}")))
        .collect::<Result<Vec<_>>>()?;
    validate_pkarr_urls(&urls)?;
    Ok(Some(urls))
}

/// The rules a pkarr list must meet: not empty, at most [`MAX_PKARR_URLS`]
/// entries, no entry twice, and each one a bare base iroh can append a key
/// to: `https` (or `http` on a loopback host), no credentials, query or
/// fragment, no trailing slash on a path, and at most
/// [`MAX_RELAY_URL_BYTES`] long.
///
/// # Errors
/// The list breaks one of the rules above.
pub fn validate_pkarr_urls(urls: &[Url]) -> Result<()> {
    if urls.is_empty() {
        bail!("a pkarr list needs at least one URL");
    }
    if urls.len() > MAX_PKARR_URLS {
        bail!(
            "pkarr list too long: {} URLs, the wire ceiling is {MAX_PKARR_URLS}",
            urls.len()
        );
    }
    for (index, url) in urls.iter().enumerate() {
        match url.scheme() {
            "https" => {}
            "http" if is_loopback(url) => {}
            "http" => bail!("pkarr URL {url} is plain http off this machine: use https"),
            _ => bail!("pkarr URL {url} is not https"),
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!("pkarr URL {url} carries credentials, which every member would get");
        }
        if url.query().is_some() || url.fragment().is_some() {
            bail!("pkarr URL {url} has a query or a fragment");
        }
        if url.path() != "/" && url.path().ends_with('/') {
            bail!("pkarr URL {url} ends in a slash: the key would follow an empty segment");
        }
        if urls[..index].contains(url) {
            bail!("pkarr URL {url} is in the list twice");
        }
        let len = url.as_str().len();
        if len > MAX_RELAY_URL_BYTES {
            bail!("pkarr URL too long: {len} bytes, the wire ceiling is {MAX_RELAY_URL_BYTES}");
        }
    }
    Ok(())
}

/// Decode `count` length-prefixed relay URLs from the cursor, advancing `pos`.
fn decode_relay_ladder(bytes: &[u8], pos: &mut usize, count: usize) -> Result<Vec<RelayUrl>> {
    let mut ladder = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u16(bytes, pos).context("truncated relay URL length")? as usize;
        if len > MAX_RELAY_URL_BYTES {
            bail!("relay URL too long: {len}");
        }
        let end = pos.checked_add(len).context("relay URL length overflow")?;
        let raw = bytes.get(*pos..end).context("truncated relay URL")?;
        *pos = end;
        let text = std::str::from_utf8(raw).context("relay URL is not UTF-8")?;
        ladder.push(text.parse::<RelayUrl>().context("invalid relay URL")?);
    }
    Ok(ladder)
}

pub(super) fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16> {
    let end = pos.checked_add(2).context("u16 length overflow")?;
    let slice = bytes.get(*pos..end).context("truncated u16")?;
    *pos = end;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Feature byte appended after the lookups when a mesh carries a password
/// and/or is invite-only. Appended — not a spare lookup-flags bit — because
/// binaries older than the pkarr lookup ignored unknown flag bits (they would
/// silently decode a featured id and sit in an empty topic) but hard-error on
/// trailing config bytes. Decode now rejects an unknown lookup bit too. One
/// feature byte gates both features; their fields follow in a fixed
/// order (password verifier, then issuer pubkey).
const FEATURE_PASSWORD: u8 = 0b0001;

/// Feature bit marking an invite-only mesh: joining needs a creator-minted
/// an invite, not the bare hash. The issuer public key (below) follows the
/// password verifier when both bits are set.
const FEATURE_INVITE_ONLY: u8 = 0b0010;

/// Feature bit marking a mesh whose relay may carry **payload**
/// ([`TransportPolicy::relay_transport`] is `true`). Absent — the default, and every id
/// minted before the policy existed — the relay is lookup only: members carry
/// payload (gossip, unicast, blobs) over a direct path alone, UDP or a
/// `WebRTC` session, and the relay serves the bootstrap dial, JSEP
/// signalling and NAT-traversal frames. No field follows the bit. In the mesh
/// id rather than per node, because one relaying member would undo the saving
/// for everyone it links. The bit spells the *permissive* case so that
/// existing ids keep their bytes and topic and read as lookup only.
const FEATURE_RELAY_TRANSPORT: u8 = 0b0100;

/// Feature bits marking a mesh that leaves `udp` or `webrtc` out of its
/// transport list ([`TransportPolicy::udp`], [`TransportPolicy::webrtc`]). No
/// field follows either. Each spells the *restrictive* case, the reverse of
/// the relay bit, for the same reason: the default `udp,webrtc` sets neither,
/// so every id minted before the list had these entries keeps its bytes and
/// topic.
const FEATURE_NO_UDP: u8 = 0b1000;
const FEATURE_NO_WEBRTC: u8 = 0b1_0000;

const KNOWN_FEATURES: u8 = FEATURE_PASSWORD
    | FEATURE_INVITE_ONLY
    | FEATURE_RELAY_TRANSPORT
    | FEATURE_NO_UDP
    | FEATURE_NO_WEBRTC;

/// Byte length of the Ed25519 issuer public key an invite-only mesh carries.
const ISSUER_PUBKEY_LEN: usize = 32;

/// The mesh-wide configuration carried in the id and mixed into the
/// gossip topic, so every member that joins behaves identically. A
/// different config is a different mesh (different topic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshConfig {
    pub lookups: LookupOpts,
    /// The password verifier — a one-way check value derived from the
    /// Argon2id-stretched password (`crypto::password_verifier`), never the
    /// password itself. `None` ⇒ passwordless. Carried in the id so `join`
    /// can verify a candidate password locally before any network.
    pub password: Option<[u8; PASSWORD_VERIFIER_LEN]>,
    /// The Ed25519 issuer public key of an **invite-only** mesh — the mint
    /// authority. `Some` ⇒ invite-only: the bare hash reaches nothing (the
    /// derivation secret lives only in creator-minted invites), and a redeemer
    /// verifies each invite's signature against this key. `None` ⇒ open join.
    pub issuer_pubkey: Option<[u8; ISSUER_PUBKEY_LEN]>,
    /// Which transports may carry payload. See [`TransportPolicy`].
    pub transport: TransportPolicy,
}

impl MeshConfig {
    /// Default loopback-only config: no lookups. Test-only since the
    /// directory now builds its config from explicit lookups and `create`
    /// constructs `MeshConfig` directly.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn loopback() -> Self {
        MeshConfig {
            lookups: LookupOpts::loopback(),
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy::default(),
        }
    }

    /// Default reachable-across-machines config: the all-on lookup preset.
    /// Test-only (see [`MeshConfig::loopback`]).
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn public_preset() -> Self {
        MeshConfig {
            lookups: LookupOpts::public_preset(),
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy::default(),
        }
    }

    /// Everything a minted config must satisfy before it becomes an id:
    /// [`LookupOpts::validate`]'s wire ceilings, plus the transport rules: a
    /// direct path must exist, and the relay must exist as a lookup both to
    /// carry payload and to signal a mesh without `udp`.
    /// Checked on decode and at `setup_mesh`, the choke point every minted
    /// config passes before any network.
    ///
    /// # Errors
    /// The lookups fail [`LookupOpts::validate`], the transports name neither
    /// `udp` nor `webrtc`, or `relay_transport` or a missing `udp` needs the
    /// relay lookup while `lookups.relay_lookup` is `Disabled`.
    pub fn validate(&self) -> Result<()> {
        self.lookups.validate()?;
        let transport = &self.transport;
        if !transport.udp && !transport.webrtc {
            bail!("a mesh needs a direct path: transport `udp`, `webrtc`, or both");
        }
        let no_relay = self.lookups.relay_lookup == RelayChoice::Disabled;
        if transport.relay_transport && no_relay {
            bail!(
                "transport `relay` needs lookup `relay`: with the relay disabled there is none to carry payload"
            );
        }
        // The pkarr publisher keeps iroh's `relay_only` filter, so a record
        // names the home relay and nothing else: without one it is empty.
        if self.lookups.pkarr != PkarrChoice::Disabled && no_relay {
            bail!(
                "lookup `pkarr` needs lookup `relay`: a pkarr record names the home relay and nothing else"
            );
        }
        // A native member without UDP has no address a peer could reach, so the
        // JSEP exchange that opens its data channel can only cross the relay.
        if !transport.udp && no_relay {
            bail!(
                "a mesh without transport `udp` needs lookup `relay`: the relay is the only path its WebRTC offers can take"
            );
        }
        Ok(())
    }

    /// The config a create names, from its three independent choices: the
    /// lookups, the relay ladder, and the transports. Password and invite
    /// stay unset; a caller that wants them fills those fields in.
    ///
    /// This is the one place that knows all three, so the rules that need two
    /// of them live here and nowhere else: a ladder needs `relay` among the
    /// lookups (through [`LookupSet::from_lookups`]), and so does letting the
    /// relay carry payload (through [`MeshConfig::validate`]).
    ///
    /// # Errors
    /// `relay_urls` is given without [`Lookup::Relay`], `pkarr_urls` without
    /// [`Lookup::Pkarr`], `transports` leaves neither [`Transport::Udp`] nor
    /// [`Transport::WebRtc`], or needs a relay lookup (see
    /// [`MeshConfig::validate`]) while none is on.
    pub fn resolve(
        lookups: &[Lookup],
        relay_urls: Option<RelayLadder>,
        pkarr_urls: Option<Vec<Url>>,
        transports: &[Transport],
    ) -> Result<Self> {
        let config = MeshConfig {
            lookups: resolve_lookups(LookupSet::from_lookups(lookups, relay_urls, pkarr_urls)?),
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy::from_transports(transports)?,
        };
        config.validate()?;
        Ok(config)
    }

    /// Canonical wire bytes: `[lookups…][if password: feature-flags u8 ‖
    /// verifier]`. This exact byte string is what the id carries and what
    /// the topic derivation mixes in, so it must be deterministic — the
    /// feature byte is emitted only when nonzero (a passwordless config
    /// stays byte-for-byte what it was before features existed).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2);
        self.lookups.encode_into(&mut buf);
        let mut features = 0u8;
        if self.password.is_some() {
            features |= FEATURE_PASSWORD;
        }
        if self.issuer_pubkey.is_some() {
            features |= FEATURE_INVITE_ONLY;
        }
        if self.transport.relay_transport {
            features |= FEATURE_RELAY_TRANSPORT;
        }
        if !self.transport.udp {
            features |= FEATURE_NO_UDP;
        }
        if !self.transport.webrtc {
            features |= FEATURE_NO_WEBRTC;
        }
        if features != 0 {
            buf.push(features);
            // Fixed field order so the encoding is canonical: password verifier
            // then issuer pubkey, each present iff its bit is set.
            if let Some(verifier) = &self.password {
                buf.extend_from_slice(verifier);
            }
            if let Some(pubkey) = &self.issuer_pubkey {
                buf.extend_from_slice(pubkey);
            }
        }
        buf
    }

    /// Decode a config region, requiring it to consume `bytes` exactly
    /// (no trailing slack within the length-delimited region we were given).
    ///
    /// # Errors
    /// The bytes are malformed or do not decode to a valid config region.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let lookups = LookupOpts::decode_from(bytes, &mut pos)?;
        let (password, issuer_pubkey, transport) = if pos == bytes.len() {
            (None, None, TransportPolicy::default())
        } else {
            let features = bytes[pos];
            pos += 1;
            if features & !KNOWN_FEATURES != 0 {
                bail!("unsupported mesh feature flags {features:#04x} — upgrade to a newer build");
            }
            if features == 0 {
                // A zero feature byte re-encodes without itself, silently
                // changing the topic-derivation bytes — reject the
                // non-canonical form outright.
                bail!("non-canonical mesh config: zero feature flags");
            }
            let password = if features & FEATURE_PASSWORD != 0 {
                let end = pos
                    .checked_add(PASSWORD_VERIFIER_LEN)
                    .context("password verifier length overflow")?;
                let raw = bytes.get(pos..end).context("truncated password verifier")?;
                pos = end;
                let mut verifier = [0u8; PASSWORD_VERIFIER_LEN];
                verifier.copy_from_slice(raw);
                Some(verifier)
            } else {
                None
            };
            let issuer_pubkey = if features & FEATURE_INVITE_ONLY != 0 {
                let end = pos
                    .checked_add(ISSUER_PUBKEY_LEN)
                    .context("issuer pubkey length overflow")?;
                let raw = bytes.get(pos..end).context("truncated issuer pubkey")?;
                pos = end;
                let mut pubkey = [0u8; ISSUER_PUBKEY_LEN];
                pubkey.copy_from_slice(raw);
                Some(pubkey)
            } else {
                None
            };
            let transport = TransportPolicy {
                udp: features & FEATURE_NO_UDP == 0,
                webrtc: features & FEATURE_NO_WEBRTC == 0,
                relay_transport: features & FEATURE_RELAY_TRANSPORT != 0,
            };
            (password, issuer_pubkey, transport)
        };
        if pos != bytes.len() {
            bail!("trailing bytes in mesh config");
        }
        let config = MeshConfig {
            lookups,
            password,
            issuer_pubkey,
            transport,
        };
        config.validate()?;
        Ok(config)
    }
}

/// A three-state optional-value CLI flag: absent, passed bare, or passed with
/// a value.
///
/// One type for what were two identical enums — relay intent and directory
/// intent — each with the same three variants and the same private `is_set`.
/// The duplicate admitted it in a doc comment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OptFlag<T> {
    /// The flag was absent.
    #[default]
    Unset,
    /// The flag was passed bare, selecting the well-known default.
    Default,
    /// The flag was passed with a value.
    Named(T),
}

impl<T> OptFlag<T> {
    /// Whether the flag was given at all, bare or valued.
    #[must_use]
    pub fn is_set(&self) -> bool {
        !matches!(self, Self::Unset)
    }
}

/// Relay intent in a [`LookupSet`]: absent / default / custom ladder.
/// Resolved into a `RelayChoice` by `resolve_lookups`. [`OptFlag::Named`]
/// carries the ordered [`RelayLadder`] (iroh-free), so this is part of the
/// public library API surface.
pub type RelaySelection = OptFlag<RelayLadder>;

impl FromStr for OptFlag<RelayLadder> {
    type Err = RelayLadderError;

    /// Parse a `--relay` optional-value flag. The bare form resolves via the
    /// `"default"` `default_missing_value` (the same token the MCP / library API
    /// surface uses) to [`RelaySelection::Default`]; any other value is a
    /// custom ladder. `Unset` comes from the *absent* flag (`Option::None`),
    /// not from this parser.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "default" {
            Ok(RelaySelection::Default)
        } else {
            text.parse::<RelayLadder>().map(RelaySelection::Named)
        }
    }
}

/// CLI `--advertise` intent. `Unset` ⇒ the mesh is not listed in any
/// directory; `Default` ⇒ the well-known `global` directory; `Named` ⇒ a
/// custom one. The directory name is itself a [`MeshName`] (same charset),
/// since the directory derives its mesh from it.
pub type DirectorySelection = OptFlag<MeshName>;

/// The well-known default directory — used when `--advertise` is passed
/// bare (no value).
pub const DEFAULT_DIRECTORY: &str = "global";

impl OptFlag<MeshName> {
    /// Resolve a clap three-state `--advertise` optional-value flag
    /// (absent / bare / valued) — the one converter shared by every
    /// command that advertises (`create`, `pipe listen`, `file send`,
    /// `port listen`).
    /// Resolve a clap `--advertise` optional-value flag into a
    /// [`DirectorySelection`]. The bare form resolves via the `"global"`
    /// [`DEFAULT_DIRECTORY`] `default_missing_value`, so it arrives here as
    /// `Some(global)` — behaviorally identical to [`DirectorySelection::Default`]
    /// (both advertise into the well-known directory). `Unset` comes from the
    /// *absent* flag.
    #[must_use]
    pub fn from_flag(flag: Option<MeshName>) -> Self {
        match flag {
            None => DirectorySelection::Unset,
            Some(directory) => DirectorySelection::Named(directory),
        }
    }

    /// The directory to advertise into, or `None` when not advertising.
    /// Bare ⇒ the [`DEFAULT_DIRECTORY`]; valued ⇒ the given name.
    ///
    /// # Panics
    /// If [`DEFAULT_DIRECTORY`] is not a valid mesh name. It is a constant, so
    /// this is a compile-time-checkable fact that only a bad edit can break.
    #[must_use]
    pub fn directory(&self) -> Option<MeshName> {
        match self {
            DirectorySelection::Unset => None,
            DirectorySelection::Default => Some(
                MeshName::new(DEFAULT_DIRECTORY).expect("DEFAULT_DIRECTORY is a valid mesh name"),
            ),
            DirectorySelection::Named(name) => Some(name.clone()),
        }
    }
}

/// Advertise was requested on a loopback-only mesh. A directory listing
/// requires a mesh reachable across machines, so this is a hard error
/// (never a silent no-op). Typed so callers can classify it — the MCP
/// server maps it to `invalid_params`, the CLI to an `anyhow` bail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertiseRequiresReachable;

impl fmt::Display for AdvertiseRequiresReachable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("advertise needs a reachable mesh; enable a lookup (e.g. public)")
    }
}

impl std::error::Error for AdvertiseRequiresReachable {}

/// `--advertise` lists the mesh in a public directory, so it requires a
/// mesh that is actually reachable across machines.
/// # Errors
/// The mesh advertises to a directory but is not reachable from one.
pub fn validate_advertise(
    advertise: &DirectorySelection,
    lookups: &LookupOpts,
) -> Result<(), AdvertiseRequiresReachable> {
    if advertise.is_set()
        && lookups.is_loopback()
        && !habilis_network_util::tuning::directory_private_for_test()
    {
        return Err(AdvertiseRequiresReachable);
    }
    Ok(())
}

/// One way a mesh's members find each other — an entry of the `lookup` list
/// a create names. Naming any restricts the mesh to exactly those; naming
/// none is a loopback-only mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lookup {
    /// LAN mDNS multicast.
    Mdns,
    /// The mainline `BitTorrent` DHT.
    Dht,
    /// Rendezvous through a relay server. A lookup only: whether the relay
    /// may also carry payload is the transport policy's call.
    Relay,
    /// Signed address records on HTTPS pkarr relays.
    Pkarr,
}

impl Lookup {
    const NAMES: &[&str] = &["mdns", "dht", "relay", "pkarr"];

    /// The name the list spells this lookup by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mdns => "mdns",
            Self::Dht => "dht",
            Self::Relay => "relay",
            Self::Pkarr => "pkarr",
        }
    }
}

impl FromStr for Lookup {
    type Err = ChoiceError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "mdns" => Ok(Self::Mdns),
            "dht" => Ok(Self::Dht),
            "relay" => Ok(Self::Relay),
            "pkarr" => Ok(Self::Pkarr),
            other => Err(ChoiceError::new("lookup", other, Self::NAMES)),
        }
    }
}

impl fmt::Display for Lookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The lookups a create selected, before they become the [`LookupOpts`] in
/// the id. `mdns`/`dht` are address-lookups; `relay_lookup` is the
/// rendezvous through a relay, bare or with a custom ladder; `pkarr` is the
/// pkarr lookup, bare or with a custom relay list.
#[derive(Debug, Clone, Default)]
pub struct LookupSet {
    pub mdns: bool,
    pub dht: bool,
    pub relay_lookup: RelaySelection,
    pub pkarr: OptFlag<Vec<Url>>,
}

impl LookupSet {
    /// The set a `lookup` list names, with `relay_urls` as the ladder the
    /// relay lookup homes on and `pkarr_urls` as the pkarr relays (`None` ⇒
    /// the pinned default for each).
    ///
    /// # Errors
    /// `relay_urls` is given but `lookups` does not name [`Lookup::Relay`],
    /// or `pkarr_urls` is given but `lookups` does not name
    /// [`Lookup::Pkarr`]: a list says *which* server, and only its lookup
    /// uses one.
    pub fn from_lookups(
        lookups: &[Lookup],
        relay_urls: Option<RelayLadder>,
        pkarr_urls: Option<Vec<Url>>,
    ) -> Result<Self> {
        let relay = lookups.contains(&Lookup::Relay);
        if relay_urls.is_some() && !relay {
            bail!("a relay ladder needs lookup `relay`");
        }
        let relay_lookup = if relay {
            relay_urls.map_or(RelaySelection::Default, RelaySelection::Named)
        } else {
            RelaySelection::Unset
        };
        let pkarr_on = lookups.contains(&Lookup::Pkarr);
        if pkarr_urls.is_some() && !pkarr_on {
            bail!("a pkarr relay list needs lookup `pkarr`");
        }
        let pkarr = if pkarr_on {
            pkarr_urls.map_or(OptFlag::Default, OptFlag::Named)
        } else {
            OptFlag::Unset
        };
        Ok(Self {
            mdns: lookups.contains(&Lookup::Mdns),
            dht: lookups.contains(&Lookup::Dht),
            relay_lookup,
            pkarr,
        })
    }

    fn any(&self) -> bool {
        self.mdns || self.dht || self.relay_lookup.is_set() || self.pkarr.is_set()
    }
}

/// Resolve a selection into the effective [`LookupOpts`] baked into the mesh
/// id. Naming **any** lookup uses *only* those named (so `mdns` alone is
/// mDNS-only, relay/dht off); naming none is a loopback-only mesh. A bare
/// relay ⇒ the pinned default ladder, a named one ⇒ that custom ladder.
#[must_use]
pub fn resolve_lookups(lookups: LookupSet) -> LookupOpts {
    if !lookups.any() {
        return LookupOpts::loopback();
    }
    let relay_lookup = match lookups.relay_lookup {
        RelaySelection::Unset => RelayChoice::Disabled,
        RelaySelection::Default => RelayChoice::Pinned,
        RelaySelection::Named(ladder) => RelayChoice::Custom(ladder.as_urls().to_vec()),
    };
    let pkarr = match lookups.pkarr {
        OptFlag::Unset => PkarrChoice::Disabled,
        OptFlag::Default => PkarrChoice::Pinned,
        OptFlag::Named(urls) => PkarrChoice::Custom(urls),
    };
    LookupOpts {
        mdns: lookups.mdns,
        dht: lookups.dht,
        relay_lookup,
        pkarr,
    }
}

/// Parse a comma-separated, ordered relay **ladder** (`a,b,c`) — order
/// preserved (the beacon homes on the first reachable rung); an empty or
/// whitespace-only entry is a hard error so a typo never silently
/// shrinks the ladder. The single source of truth for `--relay` syntax,
/// shared by the CLI value-parser and `RelayLadder` (the MCP / library API
/// string path); `String` error so clap can surface it directly.
pub(crate) fn parse_relay_ladder(raw: &str) -> Result<Vec<RelayUrl>, String> {
    raw.split(',')
        .map(|entry| {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                return Err(format!("empty entry in relay ladder {raw:?}"));
            }
            trimmed
                .parse::<RelayUrl>()
                .map_err(|error| format!("invalid relay URL {trimmed:?}: {error}"))
        })
        .collect()
}

/// An ordered, non-empty relay ladder (`a,b,c` in preference order),
/// validated at construction. Public + **iroh-free**: the wrapped
/// `Vec<RelayUrl>` stays private, so embedders (`CreateConfig`) name a
/// ladder without depending on the `iroh` type. Parsing reuses
/// `parse_relay_ladder` — the same source of truth as the CLI value
/// parser — and rejects empty entries, so a `RelayLadder` is never empty;
/// "no custom ladder" is the `Option::None` case at the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLadder(Vec<RelayUrl>);

/// A relay ladder that couldn't be parsed (empty entry / invalid URL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLadderError(String);

impl fmt::Display for RelayLadderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RelayLadderError {}

impl FromStr for RelayLadder {
    type Err = RelayLadderError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_relay_ladder(input)
            .map(RelayLadder)
            .map_err(RelayLadderError)
    }
}

impl RelayLadder {
    /// The ordered rungs, for internal consumers — keeps `RelayUrl` off
    /// the public surface.
    pub(crate) fn as_urls(&self) -> &[RelayUrl] {
        &self.0
    }

    /// The number of rungs (always >= 1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false` — a `RelayLadder` is constructed non-empty. Present
    /// for API completeness (and `clippy::len_without_is_empty`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for RelayLadder {
    /// The canonical `a,b,c` text form — round-trips through [`FromStr`].
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, url) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{url}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod lookup_tests {
    use super::{
        Lookup, LookupOpts, LookupSet, MeshConfig, PkarrChoice, RelayChoice, RelayLadder,
        RelaySelection, Transport, TransportPolicy, resolve_lookups,
    };

    fn lookups(mdns: bool, dht: bool, relay_lookup: RelaySelection) -> LookupSet {
        LookupSet {
            mdns,
            dht,
            relay_lookup,
            ..LookupSet::default()
        }
    }

    #[test]
    fn relay_ladder_parses_ordered_rungs() {
        let one: RelayLadder = "https://a.example".parse().unwrap();
        assert_eq!(one.len(), 1);
        assert!(!one.is_empty());

        let two: RelayLadder = "https://a.example,https://b.example".parse().unwrap();
        assert_eq!(two.len(), 2);
        // Display round-trips through FromStr (canonical `a,b` text form).
        let rendered = two.to_string();
        assert_eq!(rendered.parse::<RelayLadder>().unwrap(), two);
        assert_eq!(two.as_urls().len(), 2);
    }

    #[test]
    fn relay_ladder_rejects_empty_and_empty_entries() {
        assert!("".parse::<RelayLadder>().is_err());
        assert!(
            "https://a.example,,https://b.example"
                .parse::<RelayLadder>()
                .is_err(),
            "an empty entry must be rejected so a typo never shrinks the ladder"
        );
    }

    #[test]
    fn naming_relay_alone_is_reachable() {
        // Naming any lookup uses only those. A relay alone yields a reachable
        // (non-loopback) mesh.
        let ladder: RelayLadder = "https://a.example".parse().unwrap();
        let opts = resolve_lookups(lookups(false, false, RelaySelection::Named(ladder)));
        assert!(!opts.mdns && !opts.dht);
        assert!(
            !opts.is_loopback(),
            "a named relay makes the mesh reachable"
        );
        assert!(matches!(opts.relay_lookup, RelayChoice::Custom(_)));
    }

    #[test]
    fn mdns_alone_disables_dht_and_relay() {
        let opts = resolve_lookups(lookups(true, false, RelaySelection::Unset));
        assert!(opts.mdns && !opts.dht);
        assert_eq!(
            opts.relay_lookup,
            RelayChoice::Disabled,
            "--mdns alone ⇒ relay off"
        );
        assert!(!opts.is_loopback(), "any lookup ⇒ reachable");
    }

    #[test]
    fn bare_relay_is_pinned_and_suppresses_lookups() {
        let opts = resolve_lookups(lookups(false, false, RelaySelection::Default));
        assert!(!opts.mdns && !opts.dht);
        assert_eq!(opts.relay_lookup, RelayChoice::Pinned);
    }

    #[test]
    fn valued_relay_preserves_ladder_order() {
        let rung0: iroh_base::RelayUrl = "https://a.example".parse().unwrap();
        let rung1: iroh_base::RelayUrl = "https://b.example".parse().unwrap();
        let ladder: RelayLadder = "https://a.example,https://b.example".parse().unwrap();
        let opts = resolve_lookups(lookups(false, false, RelaySelection::Named(ladder)));
        assert_eq!(opts.relay_lookup, RelayChoice::Custom(vec![rung0, rung1]));
    }

    #[test]
    fn config_round_trips_loopback() {
        let config = MeshConfig::loopback();
        let decoded = MeshConfig::from_bytes(&config.to_bytes()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn config_round_trips_public_preset() {
        let config = MeshConfig::public_preset();
        let decoded = MeshConfig::from_bytes(&config.to_bytes()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn config_round_trips_custom_relay_ladder() {
        let config = MeshConfig {
            lookups: LookupOpts {
                mdns: true,
                dht: false,
                relay_lookup: RelayChoice::Custom(vec![
                    "https://a.example".parse().unwrap(),
                    "https://b.example".parse().unwrap(),
                ]),
                pkarr: PkarrChoice::Disabled,
            },
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy::default(),
        };
        let decoded = MeshConfig::from_bytes(&config.to_bytes()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn config_rejects_trailing_bytes() {
        // A lone trailing 0x00 is now the non-canonical zero feature byte;
        // either way it must be rejected, never silently absorbed.
        let mut bytes = MeshConfig::loopback().to_bytes();
        bytes.push(0);
        assert!(MeshConfig::from_bytes(&bytes).is_err());
    }

    #[test]
    fn config_rejects_custom_flag_without_enabled() {
        // flags with custom(0b1000) but not enabled(0b0100).
        let bytes = [0b1000];
        assert!(MeshConfig::from_bytes(&bytes).is_err());
    }

    #[test]
    fn config_round_trips_password_verifier() {
        let config = MeshConfig {
            lookups: LookupOpts::public_preset(),
            password: Some([0xA5u8; 16]),
            issuer_pubkey: None,
            transport: TransportPolicy::default(),
        };
        let decoded = MeshConfig::from_bytes(&config.to_bytes()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn passwordless_encoding_is_byte_identical_to_pre_feature_format() {
        // Live meshes depend on this: a config without a password must not
        // grow a feature byte (it feeds the topic derivation).
        assert_eq!(MeshConfig::loopback().to_bytes(), vec![0b0000]);
        assert_eq!(MeshConfig::public_preset().to_bytes(), vec![0b0111]);
    }

    #[test]
    fn config_rejects_unknown_feature_flags() {
        let mut bytes = MeshConfig::public_preset().to_bytes();
        bytes.push(0b10_0000); // an undefined feature bit (1 to 16 are taken)
        bytes.extend_from_slice(&[0u8; 16]);
        let error = MeshConfig::from_bytes(&bytes).unwrap_err();
        assert!(
            error.to_string().contains("upgrade to a newer build"),
            "got: {error}"
        );
    }

    #[test]
    fn config_round_trips_relay_as_transport() {
        let config = MeshConfig {
            transport: TransportPolicy {
                relay_transport: true,
                ..TransportPolicy::default()
            },
            ..MeshConfig::public_preset()
        };
        let bytes = config.to_bytes();
        // Lookups byte, then the feature byte with only this bit: the feature
        // carries no field of its own.
        assert_eq!(bytes, vec![0b0111, super::FEATURE_RELAY_TRANSPORT]);
        assert_eq!(MeshConfig::from_bytes(&bytes).unwrap(), config);
        assert_ne!(
            bytes,
            MeshConfig::public_preset().to_bytes(),
            "letting the relay carry payload derives a different topic"
        );
    }

    #[test]
    fn relay_is_lookup_only_by_default_and_on_every_pre_policy_id() {
        // An id minted before the policy existed has no feature byte; it now
        // reads as lookup only, the default, with its bytes and topic intact.
        assert!(!MeshConfig::public_preset().transport.relay_transport);
        assert!(
            !MeshConfig::from_bytes(&[0b0111])
                .unwrap()
                .transport
                .relay_transport
        );
    }

    #[test]
    fn udp_and_webrtc_are_on_by_default_and_on_every_older_id() {
        let default = TransportPolicy::default();
        assert!(default.udp && default.webrtc && !default.relay_transport);
        assert_eq!(MeshConfig::public_preset().to_bytes(), vec![0b0111]);
        let old = MeshConfig::from_bytes(&[0b0111]).unwrap().transport;
        assert!(old.udp && old.webrtc && !old.relay_transport);
        let old_relay = MeshConfig::from_bytes(&[0b0111, super::FEATURE_RELAY_TRANSPORT])
            .unwrap()
            .transport;
        assert!(old_relay.udp && old_relay.webrtc && old_relay.relay_transport);
    }

    #[test]
    fn a_transport_list_turns_on_exactly_the_paths_it_names() {
        let policy = |list: &[Transport]| TransportPolicy::from_transports(list).unwrap();
        assert_eq!(policy(&[]), TransportPolicy::default());
        let udp = policy(&[Transport::Udp]);
        assert!(udp.udp && !udp.webrtc && !udp.relay_transport);
        let webrtc = policy(&[Transport::WebRtc]);
        assert!(!webrtc.udp && webrtc.webrtc && !webrtc.relay_transport);
        let all = policy(&[Transport::Udp, Transport::WebRtc, Transport::Relay]);
        assert!(all.udp && all.webrtc && all.relay_transport);
    }

    #[test]
    fn config_round_trips_every_transport_list() {
        let lists: [&[Transport]; 5] = [
            &[Transport::Udp],
            &[Transport::WebRtc],
            &[Transport::Udp, Transport::WebRtc],
            &[Transport::WebRtc, Transport::Relay],
            &[Transport::Udp, Transport::Relay],
        ];
        let mut seen = Vec::new();
        for list in lists {
            let config = MeshConfig::resolve(&[Lookup::Relay], None, None, list).unwrap();
            let bytes = config.to_bytes();
            assert_eq!(MeshConfig::from_bytes(&bytes).unwrap(), config, "{list:?}");
            assert!(!seen.contains(&bytes), "{list:?} shares its bytes");
            seen.push(bytes);
        }
    }

    #[test]
    fn a_mesh_without_udp_needs_the_relay_lookup() {
        let error = MeshConfig::resolve(&[Lookup::Mdns], None, None, &[Transport::WebRtc])
            .unwrap_err()
            .to_string();
        assert!(error.contains("relay"), "{error}");
        assert!(MeshConfig::resolve(&[Lookup::Relay], None, None, &[Transport::WebRtc]).is_ok());
        assert!(MeshConfig::resolve(&[Lookup::Mdns], None, None, &[Transport::Udp]).is_ok());
    }

    #[test]
    fn an_id_with_neither_udp_nor_webrtc_is_refused() {
        let bytes = vec![0b0111, super::FEATURE_NO_UDP | super::FEATURE_NO_WEBRTC];
        assert!(MeshConfig::from_bytes(&bytes).is_err());
    }

    #[test]
    fn config_round_trips_relay_as_transport_with_password() {
        let config = MeshConfig {
            lookups: LookupOpts::public_preset(),
            password: Some([0xA5u8; 16]),
            issuer_pubkey: None,
            transport: TransportPolicy {
                relay_transport: true,
                ..TransportPolicy::default()
            },
        };
        let decoded = MeshConfig::from_bytes(&config.to_bytes()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn config_rejects_relay_transport_on_without_a_relay_lookup() {
        let config = MeshConfig {
            transport: TransportPolicy {
                relay_transport: true,
                ..TransportPolicy::default()
            },
            ..MeshConfig::loopback()
        };
        assert!(config.validate().is_err(), "no relay to carry payload");
        // The same shape on the wire is refused on decode too.
        let bytes = vec![0b0000, super::FEATURE_RELAY_TRANSPORT];
        assert!(MeshConfig::from_bytes(&bytes).is_err());
    }

    #[test]
    fn config_round_trips_issuer_pubkey() {
        let config = MeshConfig {
            lookups: LookupOpts::public_preset(),
            password: None,
            issuer_pubkey: Some([0x3Cu8; 32]),
            transport: TransportPolicy::default(),
        };
        let decoded = MeshConfig::from_bytes(&config.to_bytes()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn config_round_trips_password_and_invite_together() {
        // Both feature bits set: the fixed field order (verifier, then issuer
        // pubkey) must round-trip.
        let config = MeshConfig {
            lookups: LookupOpts::loopback(),
            password: Some([0xA5u8; 16]),
            issuer_pubkey: Some([0x3Cu8; 32]),
            transport: TransportPolicy::default(),
        };
        let decoded = MeshConfig::from_bytes(&config.to_bytes()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn config_rejects_truncated_issuer_pubkey() {
        let mut bytes = MeshConfig::public_preset().to_bytes();
        bytes.push(0b0010); // invite-only bit
        bytes.extend_from_slice(&[0u8; 16]); // half a pubkey
        assert!(MeshConfig::from_bytes(&bytes).is_err());
    }

    #[test]
    fn config_rejects_truncated_verifier() {
        let mut bytes = MeshConfig::public_preset().to_bytes();
        bytes.push(0b0001);
        bytes.extend_from_slice(&[0u8; 8]); // half a verifier
        assert!(MeshConfig::from_bytes(&bytes).is_err());
    }

    #[test]
    fn config_rejects_verifier_with_trailing_slack() {
        let mut bytes = MeshConfig::public_preset().to_bytes();
        bytes.push(0b0001);
        bytes.extend_from_slice(&[0u8; 17]); // verifier + one extra byte
        assert!(MeshConfig::from_bytes(&bytes).is_err());
    }
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod directory_selection_tests;

#[cfg(test)]
mod choice_tests {
    use super::{
        Lookup, LookupSet, MeshConfig, PkarrChoice, RelayChoice, RelayLadder, RelaySelection,
        Transport, TransportPolicy, resolve_lookups,
    };
    use url::Url;

    #[test]
    fn a_lookup_and_a_transport_parse_from_their_names() {
        assert_eq!("mdns".parse::<Lookup>().unwrap(), Lookup::Mdns);
        assert_eq!("dht".parse::<Lookup>().unwrap(), Lookup::Dht);
        assert_eq!("relay".parse::<Lookup>().unwrap(), Lookup::Relay);
        assert_eq!("udp".parse::<Transport>().unwrap(), Transport::Udp);
        assert_eq!("webrtc".parse::<Transport>().unwrap(), Transport::WebRtc);
        assert_eq!("relay".parse::<Transport>().unwrap(), Transport::Relay);
        for (name, lookup) in [
            ("mdns", Lookup::Mdns),
            ("dht", Lookup::Dht),
            ("relay", Lookup::Relay),
        ] {
            assert_eq!(lookup.to_string(), name);
        }
        assert_eq!(Transport::Udp.to_string(), "udp");
    }

    #[test]
    fn the_direct_transport_is_named_udp_not_p2p() {
        let udp = "udp".parse::<Transport>().unwrap();
        assert_eq!(udp.to_string(), "udp");
        assert!("p2p".parse::<Transport>().is_err());
    }

    #[test]
    fn an_unknown_name_is_an_error_that_lists_the_choices() {
        let error = "relai".parse::<Lookup>().unwrap_err().to_string();
        assert!(
            error.contains("relai") && error.contains("mdns, dht, relay, pkarr"),
            "{error}"
        );
        let transport_error = "tcp".parse::<Transport>().unwrap_err().to_string();
        assert!(
            transport_error.contains("tcp") && transport_error.contains("udp, webrtc, relay"),
            "{transport_error}"
        );
    }

    #[test]
    fn the_lists_deserialize_from_json_names() {
        let lookups: Vec<Lookup> = serde_json::from_str(r#"["mdns","relay"]"#).unwrap();
        assert_eq!(lookups, vec![Lookup::Mdns, Lookup::Relay]);
        let transports: Vec<Transport> = serde_json::from_str(r#"["udp","relay"]"#).unwrap();
        assert_eq!(transports, vec![Transport::Udp, Transport::Relay]);
        assert!(serde_json::from_str::<Vec<Lookup>>(r#"["public"]"#).is_err());
    }

    #[test]
    fn a_lookup_list_becomes_the_set_of_exactly_those() {
        let set = LookupSet::from_lookups(&[Lookup::Mdns], None, None).unwrap();
        assert!(set.mdns && !set.dht);
        assert_eq!(set.relay_lookup, RelaySelection::Unset);
        let opts = resolve_lookups(set);
        assert!(opts.mdns && !opts.dht);
        assert_eq!(opts.relay_lookup, RelayChoice::Disabled);
    }

    #[test]
    fn naming_relay_takes_the_default_ladder_unless_one_is_given() {
        let bare = LookupSet::from_lookups(&[Lookup::Relay], None, None).unwrap();
        assert_eq!(bare.relay_lookup, RelaySelection::Default);
        let ladder: RelayLadder = "https://a.example,https://b.example".parse().unwrap();
        let custom = LookupSet::from_lookups(&[Lookup::Relay], Some(ladder.clone()), None).unwrap();
        assert_eq!(custom.relay_lookup, RelaySelection::Named(ladder));
    }

    #[test]
    fn a_ladder_without_the_relay_lookup_is_an_error() {
        let ladder: RelayLadder = "https://a.example".parse().unwrap();
        let error = LookupSet::from_lookups(&[Lookup::Mdns], Some(ladder), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("relay"), "{error}");
    }

    #[test]
    fn an_empty_transport_list_and_udp_alone_keep_the_relay_off_payload() {
        assert_eq!(
            TransportPolicy::from_transports(&[]).unwrap(),
            TransportPolicy::default()
        );
        assert!(
            !TransportPolicy::from_transports(&[Transport::Udp])
                .unwrap()
                .relay_transport
        );
        assert!(
            TransportPolicy::from_transports(&[Transport::Udp, Transport::Relay])
                .unwrap()
                .relay_transport
        );
    }

    #[test]
    fn udp_cannot_be_disabled() {
        let error = TransportPolicy::from_transports(&[Transport::Relay])
            .unwrap_err()
            .to_string();
        assert!(error.contains("udp"), "{error}");
    }

    #[test]
    fn a_config_resolves_from_the_three_choices() {
        let config = MeshConfig::resolve(
            &[Lookup::Relay],
            None,
            None,
            &[Transport::Udp, Transport::Relay],
        )
        .unwrap();
        assert!(config.transport.relay_transport);
        assert_eq!(config.lookups.relay_lookup, RelayChoice::Pinned);
        assert!(config.password.is_none() && config.issuer_pubkey.is_none());

        let bare = MeshConfig::resolve(&[], None, None, &[]).unwrap();
        assert!(bare.lookups.is_loopback());
        assert!(!bare.transport.relay_transport);
    }

    /// The relay's two roles are two lists, so the relay can serve lookup
    /// alone: named in `lookup` and not in `transport`, it is the rendezvous
    /// and carries no payload. That is also what an empty `transport` means.
    #[test]
    fn relay_can_be_a_lookup_and_nothing_more() {
        for transports in [&[][..], &[Transport::Udp][..]] {
            let config = MeshConfig::resolve(&[Lookup::Relay], None, None, transports).unwrap();
            assert_eq!(config.lookups.relay_lookup, RelayChoice::Pinned);
            assert!(!config.transport.relay_transport, "{transports:?}");
            assert_eq!(config, MeshConfig::from_bytes(&config.to_bytes()).unwrap());
        }
    }

    #[test]
    fn relay_transport_needs_the_relay_lookup() {
        let error = MeshConfig::resolve(
            &[Lookup::Mdns],
            None,
            None,
            &[Transport::Udp, Transport::Relay],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("relay"), "{error}");
    }

    #[test]
    fn no_lookups_is_loopback_without_a_preset_switch() {
        let opts = resolve_lookups(LookupSet::default());
        assert!(opts.is_loopback());
        assert_eq!(opts.network_label(), "private");
    }

    fn pkarr_urls(texts: &[&str]) -> Vec<Url> {
        texts.iter().map(|text| text.parse().unwrap()).collect()
    }

    #[test]
    fn pkarr_parses_from_its_name() {
        assert_eq!("pkarr".parse::<Lookup>().unwrap(), Lookup::Pkarr);
        assert_eq!(Lookup::Pkarr.to_string(), "pkarr");
        let lookups: Vec<Lookup> = serde_json::from_str(r#"["pkarr"]"#).unwrap();
        assert_eq!(lookups, vec![Lookup::Pkarr]);
    }

    /// A pkarr mesh: pkarr with the relay it needs.
    fn with_pkarr(urls: Option<Vec<Url>>) -> anyhow::Result<MeshConfig> {
        MeshConfig::resolve(&[Lookup::Relay, Lookup::Pkarr], None, urls, &[])
    }

    #[test]
    fn naming_pkarr_takes_the_default_list_unless_one_is_given() {
        let bare = with_pkarr(None).unwrap();
        assert_eq!(bare.lookups.pkarr, PkarrChoice::Pinned);

        let urls = pkarr_urls(&["https://a.example/pkarr", "https://b.example/"]);
        let custom = with_pkarr(Some(urls.clone())).unwrap();
        assert_eq!(custom.lookups.pkarr, PkarrChoice::Custom(urls));
    }

    /// A record names the home relay and nothing else, so without a relay
    /// it holds no address a peer could dial.
    #[test]
    fn pkarr_without_the_relay_lookup_is_an_error() {
        for lookups in [
            &[Lookup::Pkarr][..],
            &[Lookup::Pkarr, Lookup::Mdns, Lookup::Dht][..],
        ] {
            let error = MeshConfig::resolve(lookups, None, None, &[])
                .unwrap_err()
                .to_string();
            assert!(error.contains("relay"), "{error}");
        }
    }

    #[test]
    fn a_pkarr_list_without_the_pkarr_lookup_is_an_error() {
        let urls = pkarr_urls(&["https://a.example/pkarr"]);
        let error = MeshConfig::resolve(&[Lookup::Mdns], None, Some(urls), &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("pkarr"), "{error}");
    }

    #[test]
    fn a_pkarr_config_round_trips_and_its_list_is_in_the_bytes() {
        let pinned = with_pkarr(None).unwrap();
        let urls = pkarr_urls(&["https://a.example/pkarr", "https://b.example/"]);
        let custom = MeshConfig::resolve(
            &[Lookup::Relay, Lookup::Pkarr],
            Some("https://relay.example".parse().unwrap()),
            Some(urls),
            &[],
        )
        .unwrap();
        for config in [&pinned, &custom] {
            assert_eq!(*config, MeshConfig::from_bytes(&config.to_bytes()).unwrap());
        }
        assert_ne!(pinned.to_bytes(), custom.to_bytes());
    }

    #[test]
    fn an_unknown_lookup_bit_is_rejected() {
        let error = MeshConfig::from_bytes(&[0b1_0000]).unwrap_err().to_string();
        assert!(error.contains("lookup"), "{error}");
    }

    #[test]
    fn a_pkarr_list_is_bounded_and_http_only() {
        let too_many = (0..17)
            .map(|index| format!("https://a{index}.example/").parse().unwrap())
            .collect();
        assert!(with_pkarr(Some(too_many)).is_err());
        assert!(with_pkarr(Some(pkarr_urls(&["wss://a.example/"]))).is_err());
        assert!(with_pkarr(Some(Vec::new())).is_err());
    }

    /// iroh appends the key as a path segment, so a URL must be a bare base:
    /// a trailing slash on a path makes `/pkarr//KEY`, and credentials, a
    /// query or a fragment would ride into every member's copy of the id.
    #[test]
    fn a_pkarr_url_is_a_bare_base() {
        for good in ["https://a.example/", "https://a.example/pkarr"] {
            assert!(with_pkarr(Some(pkarr_urls(&[good]))).is_ok(), "{good}");
        }
        for bad in [
            "https://a.example/pkarr/",
            "https://user:pass@a.example/pkarr",
            "https://user@a.example/pkarr",
            "https://a.example/pkarr?x=1",
            "https://a.example/pkarr#top",
        ] {
            assert!(with_pkarr(Some(pkarr_urls(&[bad]))).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_pkarr_list_names_each_relay_once() {
        let twice = pkarr_urls(&["https://a.example/pkarr", "https://a.example/pkarr"]);
        let error = with_pkarr(Some(twice)).unwrap_err().to_string();
        assert!(error.contains("twice"), "{error}");
    }

    /// A page served over HTTPS cannot fetch plain HTTP, so `http` is for a
    /// relay on this machine only, which is what tests run.
    #[test]
    fn plain_http_is_for_a_loopback_relay_only() {
        for good in [
            "http://127.0.0.1:1/pkarr",
            "http://localhost/pkarr",
            "http://[::1]/pkarr",
        ] {
            assert!(with_pkarr(Some(pkarr_urls(&[good]))).is_ok(), "{good}");
        }
        assert!(with_pkarr(Some(pkarr_urls(&["http://a.example/pkarr"]))).is_err());
    }
}
