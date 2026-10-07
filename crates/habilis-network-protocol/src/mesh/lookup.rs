//! The mesh-wide config carried in the mesh id — the lookup allowlist
//! (`mdns`/`dht`/`relay`) and the relay ladder it may carry — plus its byte
//! codec and the `--advertise` directory selection. A mesh's network reach is
//! fully described by its lookups: no lookups means loopback-only; any lookup
//! means reachable across machines. The transport policy the id also carries
//! is `transport.rs`; [`MeshConfig`] is where the two meet.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use iroh_base::RelayUrl;
use serde::Deserialize;

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

/// The lookup allowlist baked into the mesh id. `mdns`/`dht` are the
/// enabled iroh address-lookups (both resolve the same seed-derived
/// `rendezvous_id`); `relay_lookup` is the connectivity relay (see
/// [`RelayChoice`]). An all-off set is a loopback-only mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupOpts {
    pub mdns: bool,
    pub dht: bool,
    pub relay_lookup: RelayChoice,
}

/// Wire ceiling on a custom relay ladder, so a forged id can't blow up
/// allocation. Far above any real ladder.
pub(super) const MAX_RELAY_LADDER: usize = 16;
/// Wire ceiling on a single relay URL's byte length.
pub(super) const MAX_RELAY_URL_BYTES: usize = 512;

impl LookupOpts {
    /// Loopback-only: no address-lookups, no relay (the seed-derived
    /// port ladder bootstraps everything on one machine).
    #[must_use]
    pub fn loopback() -> Self {
        LookupOpts {
            mdns: false,
            dht: false,
            relay_lookup: RelayChoice::Disabled,
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
        }
    }

    /// True when nothing reaches off-machine — the mesh is loopback-only.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        !self.mdns && !self.dht && self.relay_lookup == RelayChoice::Disabled
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
    /// The custom ladder is longer than [`MAX_RELAY_LADDER`], or one of its
    /// URLs is longer than [`MAX_RELAY_URL_BYTES`].
    pub fn validate(&self) -> Result<()> {
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
    /// `[flags u8][if custom: [count u8] ([len u16 LE] url)*]`.
    ///
    /// # Panics
    /// If a relay ladder longer than `MAX_RELAY_LADDER`, or a relay URL longer
    /// than `MAX_RELAY_URL_BYTES`, reaches here — [`validate`](Self::validate)
    /// rejects both, and every mint runs it, so this is a broken invariant
    /// rather than bad input.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        let mut flags: u8 = 0;
        if self.mdns {
            flags |= 0b0001;
        }
        if self.dht {
            flags |= 0b0010;
        }
        match &self.relay_lookup {
            RelayChoice::Disabled => {}
            RelayChoice::Pinned => flags |= 0b0100,
            RelayChoice::Custom(_) => flags |= 0b0100 | 0b1000,
        }
        buf.push(flags);
        if let RelayChoice::Custom(ladder) = &self.relay_lookup {
            // The ladder is created locally and bounded by the CLI / library API,
            // so this cast and the lengths below always fit.
            buf.push(u8::try_from(ladder.len()).expect("relay ladder bounded by MAX_RELAY_LADDER"));
            for url in ladder {
                let text = url.to_string();
                let len =
                    u16::try_from(text.len()).expect("relay URL bounded by MAX_RELAY_URL_BYTES");
                buf.extend_from_slice(&len.to_le_bytes());
                buf.extend_from_slice(text.as_bytes());
            }
        }
    }

    /// Decode from a cursor over the config region, advancing `pos`.
    /// # Errors
    /// The buffer is truncated, or the encoded length exceeds what remains.
    pub fn decode_from(bytes: &[u8], pos: &mut usize) -> Result<Self> {
        let flags = *bytes.get(*pos).context("truncated lookup flags")?;
        *pos += 1;
        let mdns = flags & 0b0001 != 0;
        let dht = flags & 0b0010 != 0;
        let relay_enabled = flags & 0b0100 != 0;
        let relay_custom = flags & 0b1000 != 0;
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
        Ok(LookupOpts {
            mdns,
            dht,
            relay_lookup,
        })
    }
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
/// old binaries ignore unknown flag bits (they would silently decode a
/// featured id and sit in an empty topic) but hard-error on trailing config
/// bytes. One feature byte gates both features; their fields follow in a fixed
/// order (password verifier, then issuer pubkey).
const FEATURE_PASSWORD: u8 = 0b0001;

/// Feature bit marking an invite-only mesh: joining needs a creator-minted
/// an invite, not the bare hash. The issuer public key (below) follows the
/// password verifier when both bits are set.
const FEATURE_INVITE_ONLY: u8 = 0b0010;

/// The transport policy is always written, as one byte right after the
/// lookups, so no id leaves a path to an implicit default. Each bit spells a
/// path that is **on**.
pub(super) const TRANSPORT_UDP: u8 = 0b0001;
pub(super) const TRANSPORT_WEBRTC: u8 = 0b0010;
pub(super) const TRANSPORT_MULTIHOP: u8 = 0b0100;
/// The relay may carry payload ([`TransportPolicy::relay_transport`]). Off, the
/// relay serves the bootstrap dial, JSEP signalling and NAT-traversal frames
/// only. In the mesh id rather than per node, because one relaying member
/// would undo the saving for everyone it links.
pub(super) const TRANSPORT_RELAY: u8 = 0b1000;
pub(super) const KNOWN_TRANSPORT_BITS: u8 =
    TRANSPORT_UDP | TRANSPORT_WEBRTC | TRANSPORT_MULTIHOP | TRANSPORT_RELAY;

const KNOWN_FEATURES: u8 = FEATURE_PASSWORD | FEATURE_INVITE_ONLY;

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
        if transport.multihop_has_no_direct_path() {
            bail!(super::transport::MULTIHOP_ALONE);
        }
        if !transport.udp && !transport.webrtc {
            bail!("a mesh needs a direct path: transport `udp`, `webrtc`, or both");
        }
        let no_relay = self.lookups.relay_lookup == RelayChoice::Disabled;
        if transport.relay_transport && no_relay {
            bail!(
                "transport `relay` needs lookup `relay`: with the relay disabled there is none to carry payload"
            );
        }
        if transport.multihop && !transport.udp {
            bail!("transport `multihop` needs `udp`: its underlay is a UDP endpoint");
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
    /// `relay_urls` is given without [`Lookup::Relay`], `transports` leaves
    /// neither [`Transport::Udp`] nor [`Transport::WebRtc`], or needs a relay
    /// lookup (see [`MeshConfig::validate`]) while none is on.
    pub fn resolve(
        lookups: &[Lookup],
        relay_urls: Option<RelayLadder>,
        transports: &[Transport],
    ) -> Result<Self> {
        let config = MeshConfig {
            lookups: resolve_lookups(LookupSet::from_lookups(lookups, relay_urls)?),
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
        buf.push(self.transport.to_byte());
        let mut features = 0u8;
        if self.password.is_some() {
            features |= FEATURE_PASSWORD;
        }
        if self.issuer_pubkey.is_some() {
            features |= FEATURE_INVITE_ONLY;
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
        let transport_byte = *bytes.get(pos).context(
            "missing transport policy byte: upgrade, this mesh id is from an older build",
        )?;
        pos += 1;
        let transport = TransportPolicy::from_byte(transport_byte)?;
        let (password, issuer_pubkey) = if pos == bytes.len() {
            (None, None)
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
            (password, issuer_pubkey)
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
}

impl Lookup {
    const NAMES: &[&str] = &["mdns", "dht", "relay"];

    /// The name the list spells this lookup by.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mdns => "mdns",
            Self::Dht => "dht",
            Self::Relay => "relay",
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
/// rendezvous through a relay, bare or with a custom ladder.
#[derive(Debug, Clone, Default)]
pub struct LookupSet {
    pub mdns: bool,
    pub dht: bool,
    pub relay_lookup: RelaySelection,
}

impl LookupSet {
    /// The set a `lookup` list names, with `relay_urls` as the ladder the
    /// relay lookup homes on (`None` ⇒ the pinned default).
    ///
    /// # Errors
    /// `relay_urls` is given but `lookups` does not name [`Lookup::Relay`]:
    /// a ladder says *which* relay, and only a relay lookup uses one.
    pub fn from_lookups(lookups: &[Lookup], relay_urls: Option<RelayLadder>) -> Result<Self> {
        let relay = lookups.contains(&Lookup::Relay);
        if relay_urls.is_some() && !relay {
            bail!("a relay ladder needs lookup `relay`");
        }
        let relay_lookup = if relay {
            relay_urls.map_or(RelaySelection::Default, RelaySelection::Named)
        } else {
            RelaySelection::Unset
        };
        Ok(Self {
            mdns: lookups.contains(&Lookup::Mdns),
            dht: lookups.contains(&Lookup::Dht),
            relay_lookup,
        })
    }

    fn any(&self) -> bool {
        self.mdns || self.dht || self.relay_lookup.is_set()
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
    LookupOpts {
        mdns: lookups.mdns,
        dht: lookups.dht,
        relay_lookup,
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
        Lookup, LookupOpts, LookupSet, MeshConfig, RelayChoice, RelayLadder, RelaySelection,
        Transport, TransportPolicy, resolve_lookups,
    };

    fn lookups(mdns: bool, dht: bool, relay_lookup: RelaySelection) -> LookupSet {
        LookupSet {
            mdns,
            dht,
            relay_lookup,
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
    fn a_passwordless_config_has_no_feature_byte() {
        // The lookups byte, the policy byte, and nothing else: the feature
        // byte only exists for a password or an invite.
        assert_eq!(MeshConfig::loopback().to_bytes(), vec![0b0000, 0b0111]);
        assert_eq!(MeshConfig::public_preset().to_bytes(), vec![0b0111, 0b0111]);
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
        // Lookups byte, then the policy byte with every path on, the relay
        // included. No feature byte: no password and no invite.
        assert_eq!(bytes, vec![0b0111, 0b1111]);
        assert_eq!(MeshConfig::from_bytes(&bytes).unwrap(), config);
        assert_ne!(
            bytes,
            MeshConfig::public_preset().to_bytes(),
            "letting the relay carry payload derives a different topic"
        );
    }

    #[test]
    fn relay_is_lookup_only_by_default() {
        assert!(!MeshConfig::public_preset().transport.relay_transport);
        assert!(
            !MeshConfig::from_bytes(&[0b0111, 0b0111])
                .unwrap()
                .transport
                .relay_transport
        );
    }

    #[test]
    fn udp_webrtc_and_multihop_are_on_by_default() {
        let default = TransportPolicy::default();
        assert!(default.udp && default.webrtc && default.multihop && !default.relay_transport);
        assert_eq!(MeshConfig::public_preset().to_bytes(), vec![0b0111, 0b0111]);
        let decoded = MeshConfig::from_bytes(&[0b0111, 0b0111]).unwrap().transport;
        assert_eq!(decoded, default);
        let with_relay = MeshConfig::from_bytes(&[0b0111, 0b1111]).unwrap().transport;
        assert!(
            with_relay.udp
                && with_relay.webrtc
                && with_relay.multihop
                && with_relay.relay_transport
        );
    }

    #[test]
    fn the_transport_policy_is_always_one_explicit_byte() {
        // Lookups byte, then the policy byte. Nothing is left implicit: a
        // config without the policy byte is not a version 2 config.
        assert_eq!(MeshConfig::public_preset().to_bytes().len(), 2);
        assert!(MeshConfig::from_bytes(&[0b0111]).is_err());
    }

    #[test]
    fn a_transport_list_turns_on_exactly_the_paths_it_names() {
        let policy = |list: &[Transport]| TransportPolicy::from_transports(list).unwrap();
        assert_eq!(policy(&[]), TransportPolicy::default());
        let udp = policy(&[Transport::Udp]);
        assert!(udp.udp && !udp.webrtc && !udp.multihop && !udp.relay_transport);
        let webrtc = policy(&[Transport::WebRtc]);
        assert!(!webrtc.udp && webrtc.webrtc && !webrtc.multihop && !webrtc.relay_transport);
        let multihop = policy(&[Transport::Udp, Transport::Multihop]);
        assert!(multihop.udp && !multihop.webrtc && multihop.multihop && !multihop.relay_transport);
        let all = policy(&[
            Transport::Udp,
            Transport::WebRtc,
            Transport::Multihop,
            Transport::Relay,
        ]);
        assert!(all.udp && all.webrtc && all.multihop && all.relay_transport);
    }

    #[test]
    fn config_round_trips_every_transport_list() {
        let lists: [&[Transport]; 8] = [
            &[Transport::Udp],
            &[Transport::WebRtc],
            &[Transport::Udp, Transport::WebRtc],
            &[Transport::WebRtc, Transport::Relay],
            &[Transport::Udp, Transport::Relay],
            &[Transport::Udp, Transport::Multihop],
            &[Transport::Udp, Transport::WebRtc, Transport::Multihop],
            &[Transport::Udp, Transport::Multihop, Transport::Relay],
        ];
        let mut seen = Vec::new();
        for list in lists {
            let config = MeshConfig::resolve(&[Lookup::Relay], None, list).unwrap();
            let bytes = config.to_bytes();
            assert_eq!(MeshConfig::from_bytes(&bytes).unwrap(), config, "{list:?}");
            assert!(!seen.contains(&bytes), "{list:?} shares its bytes");
            seen.push(bytes);
        }
    }

    #[test]
    fn a_mesh_without_udp_needs_the_relay_lookup() {
        let error = MeshConfig::resolve(&[Lookup::Mdns], None, &[Transport::WebRtc])
            .unwrap_err()
            .to_string();
        assert!(error.contains("relay"), "{error}");
        assert!(MeshConfig::resolve(&[Lookup::Relay], None, &[Transport::WebRtc]).is_ok());
        assert!(MeshConfig::resolve(&[Lookup::Mdns], None, &[Transport::Udp]).is_ok());
    }

    #[test]
    fn multihop_needs_udp() {
        let error = MeshConfig::resolve(
            &[Lookup::Relay],
            None,
            &[Transport::WebRtc, Transport::Multihop],
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("multihop") && error.contains("udp"),
            "{error}"
        );
        let bytes = vec![0b0111, super::TRANSPORT_WEBRTC | super::TRANSPORT_MULTIHOP];
        assert!(MeshConfig::from_bytes(&bytes).is_err());
    }

    const NEEDS_A_DIRECT_PATH: &str =
        "a transport list needs a direct path: name `udp`, `webrtc`, or both";
    const MULTIHOP_ALONE: &str = "transport `multihop` cannot be the only transport: it forwards over a direct path, name `udp`";
    const MULTIHOP_NEEDS_UDP: &str =
        "transport `multihop` needs `udp`: its underlay is a UDP endpoint";

    /// Every subset of the four transports, each with its result: `Ok`, or the
    /// exact error. A relay lookup is on, so the relay rules do not speak here.
    #[test]
    fn every_subset_of_the_transports_resolves_or_names_its_error() {
        use Transport::{Multihop, Relay, Udp, WebRtc};
        let rows: [(&[Transport], Result<(), &str>); 16] = [
            (&[], Ok(())),
            (&[Udp], Ok(())),
            (&[WebRtc], Ok(())),
            (&[Multihop], Err(MULTIHOP_ALONE)),
            (&[Relay], Err(NEEDS_A_DIRECT_PATH)),
            (&[Udp, WebRtc], Ok(())),
            (&[Udp, Multihop], Ok(())),
            (&[Udp, Relay], Ok(())),
            (&[WebRtc, Multihop], Err(MULTIHOP_NEEDS_UDP)),
            (&[WebRtc, Relay], Ok(())),
            (&[Multihop, Relay], Err(MULTIHOP_ALONE)),
            (&[Udp, WebRtc, Multihop], Ok(())),
            (&[Udp, WebRtc, Relay], Ok(())),
            (&[Udp, Multihop, Relay], Ok(())),
            (&[WebRtc, Multihop, Relay], Err(MULTIHOP_NEEDS_UDP)),
            (&[Udp, WebRtc, Multihop, Relay], Ok(())),
        ];
        let mask = |list: &[Transport]| {
            [Udp, WebRtc, Multihop, Relay]
                .iter()
                .enumerate()
                .filter(|(_, transport)| list.contains(transport))
                .fold(0u8, |mask, (bit, _)| mask | 1 << bit)
        };
        let covered: std::collections::HashSet<u8> =
            rows.iter().map(|(list, _)| mask(list)).collect();
        assert_eq!(covered.len(), 16, "the table names every subset once");
        for (list, expected) in rows {
            let got = MeshConfig::resolve(&[Lookup::Relay], None, list)
                .map(|_| ())
                .map_err(|error| error.to_string());
            assert_eq!(
                got,
                expected.map_err(str::to_owned),
                "the transport list {list:?}"
            );
        }
    }

    /// A mesh id that is decoded passes `validate` and not `from_transports`, so
    /// `validate` names the same mistake.
    #[test]
    fn an_id_with_multihop_alone_names_that_mistake() {
        let alone = MeshConfig::from_bytes(&[0b0111, super::TRANSPORT_MULTIHOP])
            .unwrap_err()
            .to_string();
        assert_eq!(alone, MULTIHOP_ALONE);
        let with_relay = super::TRANSPORT_MULTIHOP | super::TRANSPORT_RELAY;
        let with_relay_error = MeshConfig::from_bytes(&[0b0111, with_relay])
            .unwrap_err()
            .to_string();
        assert_eq!(with_relay_error, MULTIHOP_ALONE);
    }

    /// One rule, not one per caller: a list that names `multihop` twice is
    /// still multihop with no direct transport, and says so as a list of one.
    #[test]
    fn multihop_named_twice_is_still_multihop_alone() {
        for list in [
            &[Transport::Multihop, Transport::Multihop][..],
            &[Transport::Multihop, Transport::Relay, Transport::Multihop][..],
        ] {
            let error = MeshConfig::resolve(&[Lookup::Relay], None, list)
                .unwrap_err()
                .to_string();
            assert_eq!(error, MULTIHOP_ALONE, "{list:?}");
        }
    }

    #[test]
    fn a_policy_byte_with_an_unknown_bit_asks_for_an_upgrade() {
        let error = MeshConfig::from_bytes(&[0b0111, 0b1_0111])
            .unwrap_err()
            .to_string();
        assert!(error.contains("upgrade"), "{error}");
    }

    #[test]
    fn an_id_with_neither_udp_nor_webrtc_is_refused() {
        for byte in [0b0000, super::TRANSPORT_MULTIHOP, super::TRANSPORT_RELAY] {
            assert!(
                MeshConfig::from_bytes(&[0b0111, byte]).is_err(),
                "{byte:#06b}"
            );
        }
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
        let bytes = vec![0b0000, super::TRANSPORT_UDP | super::TRANSPORT_RELAY];
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
        Lookup, LookupSet, MeshConfig, RelayChoice, RelayLadder, RelaySelection, Transport,
        TransportPolicy, resolve_lookups,
    };

    #[test]
    fn a_lookup_and_a_transport_parse_from_their_names() {
        assert_eq!("mdns".parse::<Lookup>().unwrap(), Lookup::Mdns);
        assert_eq!("dht".parse::<Lookup>().unwrap(), Lookup::Dht);
        assert_eq!("relay".parse::<Lookup>().unwrap(), Lookup::Relay);
        assert_eq!("udp".parse::<Transport>().unwrap(), Transport::Udp);
        assert_eq!("webrtc".parse::<Transport>().unwrap(), Transport::WebRtc);
        assert_eq!("relay".parse::<Transport>().unwrap(), Transport::Relay);
        assert_eq!(
            "multihop".parse::<Transport>().unwrap(),
            Transport::Multihop
        );
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
            error.contains("relai") && error.contains("mdns, dht, relay"),
            "{error}"
        );
        let transport_error = "tcp".parse::<Transport>().unwrap_err().to_string();
        assert!(
            transport_error.contains("tcp")
                && transport_error.contains("udp, webrtc, multihop, relay"),
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
        let set = LookupSet::from_lookups(&[Lookup::Mdns], None).unwrap();
        assert!(set.mdns && !set.dht);
        assert_eq!(set.relay_lookup, RelaySelection::Unset);
        let opts = resolve_lookups(set);
        assert!(opts.mdns && !opts.dht);
        assert_eq!(opts.relay_lookup, RelayChoice::Disabled);
    }

    #[test]
    fn naming_relay_takes_the_default_ladder_unless_one_is_given() {
        let bare = LookupSet::from_lookups(&[Lookup::Relay], None).unwrap();
        assert_eq!(bare.relay_lookup, RelaySelection::Default);
        let ladder: RelayLadder = "https://a.example,https://b.example".parse().unwrap();
        let custom = LookupSet::from_lookups(&[Lookup::Relay], Some(ladder.clone())).unwrap();
        assert_eq!(custom.relay_lookup, RelaySelection::Named(ladder));
    }

    #[test]
    fn a_ladder_without_the_relay_lookup_is_an_error() {
        let ladder: RelayLadder = "https://a.example".parse().unwrap();
        let error = LookupSet::from_lookups(&[Lookup::Mdns], Some(ladder))
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
        let config =
            MeshConfig::resolve(&[Lookup::Relay], None, &[Transport::Udp, Transport::Relay])
                .unwrap();
        assert!(config.transport.relay_transport);
        assert_eq!(config.lookups.relay_lookup, RelayChoice::Pinned);
        assert!(config.password.is_none() && config.issuer_pubkey.is_none());

        let bare = MeshConfig::resolve(&[], None, &[]).unwrap();
        assert!(bare.lookups.is_loopback());
        assert!(!bare.transport.relay_transport);
    }

    /// The relay's two roles are two lists, so the relay can serve lookup
    /// alone: named in `lookup` and not in `transport`, it is the rendezvous
    /// and carries no payload. That is also what an empty `transport` means.
    #[test]
    fn relay_can_be_a_lookup_and_nothing_more() {
        for transports in [&[][..], &[Transport::Udp][..]] {
            let config = MeshConfig::resolve(&[Lookup::Relay], None, transports).unwrap();
            assert_eq!(config.lookups.relay_lookup, RelayChoice::Pinned);
            assert!(!config.transport.relay_transport, "{transports:?}");
            assert_eq!(config, MeshConfig::from_bytes(&config.to_bytes()).unwrap());
        }
    }

    #[test]
    fn relay_transport_needs_the_relay_lookup() {
        let error = MeshConfig::resolve(&[Lookup::Mdns], None, &[Transport::Udp, Transport::Relay])
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
}
