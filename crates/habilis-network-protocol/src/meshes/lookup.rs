//! The mesh-wide config carried in the mesh id — the lookup allowlist
//! (`mdns`/`dht`/`relay`) and the relay ladder it may carry — plus its byte
//! codec and the `--advertise` directory selection. A mesh's network reach is
//! fully described by its lookups: no lookups means loopback-only; any lookup
//! means reachable across machines. The transport policy the id also carries
//! is `transport.rs`; [`MeshConfig`] is where the two meet.

use std::fmt;
use std::str::FromStr;

use iroh_base::RelayUrl;
use serde::Deserialize;

use super::transport::{Transport, TransportPolicy};
use super::{ChoiceError, ConfigError, MeshName};
use crate::crypto::PASSWORD_VERIFIER_LEN;

use habilis_network_util::tuning;
use std::{error, str};
/// The connectivity relay. `Disabled` ⇒ no relay at all
/// (`RelayMode::Disabled`); `Pinned` ⇒ the lookup-layer pinned default
/// *ladder* (the n0 prod set); `Custom` ⇒ an operator-supplied **ordered
/// ladder** (`--relay a,b,c`). Relay is an allowlist member like
/// mdns/dht, not an always-on URL — the lookup layer turns
/// `Pinned`/`Custom` into an ordered relay ladder, and the beacon homes
/// on the first reachable rung (see `lookup::relay_ladder` /
/// `lookup::select_bootstrap_rung`).
///
/// # Examples
///
/// A relay choice sets how the relay finds peers, and a lookup set can have none of them.
///
/// ```
/// use habilis_network_protocol::meshes::{LookupOpts, RelayChoice};
///
/// let opts = LookupOpts::new(RelayChoice::Disabled);
/// assert!(opts.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayChoice {
    /// No relay lookup.
    Disabled,
    /// The pinned relay of the mesh.
    Pinned,
    /// The relays that the caller names.
    Custom(Vec<RelayUrl>),
}

/// The lookup allowlist baked into the mesh id. `mdns`/`dht` are the
/// enabled iroh address-lookups (both resolve the same seed-derived
/// `rendezvous_id`); `relay_lookup` is the connectivity relay (see
/// [`RelayChoice`]). An all-off set is a loopback-only mesh.
///
/// # Examples
///
/// A loopback preset is local only, and the public preset is not.
///
/// ```
/// use habilis_network_protocol::meshes::LookupOpts;
///
/// assert!(LookupOpts::loopback().is_loopback());
/// assert!(!LookupOpts::public_preset().is_loopback());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LookupOpts {
    /// Whether peers are found on the local network.
    pub mdns: bool,
    /// Whether peers are found on the mainline DHT.
    pub dht: bool,
    /// How the relay is used to find peers.
    pub relay_lookup: RelayChoice,
}

/// Wire ceiling on a custom relay ladder, so a forged id can't blow up
/// allocation. Far above any real ladder.
pub(super) const MAX_RELAY_LADDER: usize = 16;
/// Wire ceiling on a single relay URL's byte length.
pub(super) const MAX_RELAY_URL_BYTES: usize = 512;

impl Default for LookupOpts {
    /// Loopback: nothing reaches off the machine until a caller asks for it.
    fn default() -> Self {
        Self::loopback()
    }
}

impl LookupOpts {
    /// Every lookup off, with the relay choice given. Turn one on with its `with_` method.
    #[must_use]
    pub fn new(relay_lookup: RelayChoice) -> Self {
        Self {
            mdns: false,
            dht: false,
            relay_lookup,
        }
    }

    /// Turn the mDNS lookup on or off.
    #[must_use]
    pub fn mdns(
        mut self,
        // true turns the mDNS lookup on
        mdns: bool,
    ) -> Self {
        self.mdns = mdns;
        self
    }

    /// Turn the DHT lookup on or off.
    #[must_use]
    pub fn dht(
        mut self,
        // true turns the DHT lookup on
        dht: bool,
    ) -> Self {
        self.dht = dht;
        self
    }

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
    /// `MAX_RELAY_LADDER` it mints an id [`decode_from`](Self::decode_from)
    /// rejects, and past 255 the count no longer fits its `u8`.
    ///
    /// # Errors
    /// # Errors
    /// A [`ConfigError::Invalid`] when the custom ladder has more than
    /// `MAX_RELAY_LADDER` rungs, or one of its URLs is longer than
    /// `MAX_RELAY_URL_BYTES`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let RelayChoice::Custom(ladder) = &self.relay_lookup else {
            return Ok(());
        };
        if ladder.len() > MAX_RELAY_LADDER {
            return Err(ConfigError::Invalid(format!(
                "relay ladder too long: {} rungs, the wire ceiling is {MAX_RELAY_LADDER}",
                ladder.len()
            )));
        }
        for url in ladder {
            let len = url.to_string().len();
            if len > MAX_RELAY_URL_BYTES {
                return Err(ConfigError::Invalid(format!(
                    "relay URL too long: {len} bytes, the wire ceiling is {MAX_RELAY_URL_BYTES}"
                )));
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
    pub fn encode_into(&self, buffer: &mut Vec<u8>) {
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
        buffer.push(flags);
        if let RelayChoice::Custom(ladder) = &self.relay_lookup {
            // The ladder is created locally and bounded by the CLI / library API,
            // so this cast and the lengths below always fit.
            buffer.push(
                u8::try_from(ladder.len()).expect("relay ladder bounded by MAX_RELAY_LADDER"),
            );
            for url in ladder {
                let text = url.to_string();
                let len =
                    u16::try_from(text.len()).expect("relay URL bounded by MAX_RELAY_URL_BYTES");
                buffer.extend_from_slice(&len.to_le_bytes());
                buffer.extend_from_slice(text.as_bytes());
            }
        }
    }

    /// Decode from a cursor over the config region, advancing `pos`.
    /// # Errors
    /// # Errors
    /// A [`ConfigError::Truncated`] when the buffer ends before a field, or a
    /// [`ConfigError::Invalid`] for a flag set without its enabling bit, an empty
    /// ladder, or one longer than `MAX_RELAY_LADDER`. A [`ConfigError::Source`] when a
    /// relay URL does not parse.
    pub fn decode_from(bytes: &[u8], position: &mut usize) -> Result<Self, ConfigError> {
        let flags = *bytes
            .get(*position)
            .ok_or(ConfigError::Truncated("truncated lookup flags"))?;
        *position += 1;
        let mdns = flags & 0b0001 != 0;
        let dht = flags & 0b0010 != 0;
        let relay_enabled = flags & 0b0100 != 0;
        let relay_custom = flags & 0b1000 != 0;
        if relay_custom && !relay_enabled {
            return Err(ConfigError::Invalid(
                "custom-relay bit set without relay-enabled bit".to_owned(),
            ));
        }
        let relay_lookup = if !relay_enabled {
            RelayChoice::Disabled
        } else if !relay_custom {
            RelayChoice::Pinned
        } else {
            let count = *bytes
                .get(*position)
                .ok_or(ConfigError::Truncated("truncated relay ladder count"))?
                as usize;
            *position += 1;
            if count == 0 {
                return Err(ConfigError::Invalid(
                    "custom relay ladder is empty".to_owned(),
                ));
            }
            if count > MAX_RELAY_LADDER {
                return Err(ConfigError::Invalid(format!(
                    "relay ladder too long: {count}"
                )));
            }
            RelayChoice::Custom(decode_relay_ladder(bytes, position, count)?)
        };
        Ok(LookupOpts {
            mdns,
            dht,
            relay_lookup,
        })
    }
}

/// Decode `count` length-prefixed relay URLs from the cursor, advancing `pos`.
fn decode_relay_ladder(
    bytes: &[u8],
    position: &mut usize,
    count: usize,
) -> Result<Vec<RelayUrl>, ConfigError> {
    let mut ladder = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u16(bytes, position)
            .map_err(ConfigError::with_step("truncated relay URL length"))?
            as usize;
        if len > MAX_RELAY_URL_BYTES {
            return Err(ConfigError::Invalid(format!("relay URL too long: {len}")));
        }
        let end = position
            .checked_add(len)
            .ok_or(ConfigError::Truncated("relay URL length overflow"))?;
        let raw = bytes
            .get(*position..end)
            .ok_or(ConfigError::Truncated("truncated relay URL"))?;
        *position = end;
        let text = str::from_utf8(raw).map_err(ConfigError::with_step("relay URL is not UTF-8"))?;
        let url: RelayUrl = text
            .parse()
            .map_err(ConfigError::with_step("invalid relay URL"))?;
        ladder.push(url);
    }
    Ok(ladder)
}

pub(super) fn read_u16(bytes: &[u8], position: &mut usize) -> Result<u16, ConfigError> {
    let end = position
        .checked_add(2)
        .ok_or(ConfigError::Truncated("u16 length overflow"))?;
    let slice = bytes
        .get(*position..end)
        .ok_or(ConfigError::Truncated("truncated u16"))?;
    *position = end;
    let pair: [u8; 2] = slice
        .try_into()
        .map_err(|_| ConfigError::Truncated("truncated u16"))?;
    Ok(u16::from_le_bytes(pair))
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
/// The relay may carry payload ([`Transport::Relay`]). Off, the
/// relay serves the bootstrap dial, JSEP signalling and NAT-traversal frames
/// only. In the mesh id rather than per node, because one relaying member
/// would undo the saving for everyone it links.
pub(super) const TRANSPORT_RELAY: u8 = 0b1000;
/// Gossip as a path ([`Transport::Gossip`]). Written after the relay's bit, so an id that
/// an older build made reads as gossip off and keeps its bytes.
pub(super) const TRANSPORT_GOSSIP: u8 = 0b1_0000;
pub(super) const KNOWN_TRANSPORT_BITS: u8 =
    TRANSPORT_UDP | TRANSPORT_WEBRTC | TRANSPORT_MULTIHOP | TRANSPORT_RELAY | TRANSPORT_GOSSIP;

const KNOWN_FEATURES: u8 = FEATURE_PASSWORD | FEATURE_INVITE_ONLY;

/// Byte length of the Ed25519 issuer public key an invite-only mesh carries.
const ISSUER_PUBKEY_LEN: usize = 32;

/// The mesh-wide configuration carried in the id and mixed into the
/// gossip topic, so every member that joins behaves identically. A
/// different config is a different mesh (different topic).
///
/// # Examples
///
/// A config with no lookup named resolves to the loopback lookups.
///
/// ```
/// use habilis_network_protocol::meshes::MeshConfig;
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
/// assert!(config.lookups.is_loopback());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct MeshConfig {
    /// The lookups that find the mesh.
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

impl<const N: usize> TryFrom<&[u8; N]> for MeshConfig {
    type Error = ConfigError;

    fn try_from(bytes: &[u8; N]) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl MeshConfig {
    /// The mesh config from its four parts.
    #[must_use]
    pub fn new(
        lookups: LookupOpts,
        password: Option<[u8; PASSWORD_VERIFIER_LEN]>,
        issuer_pubkey: Option<[u8; ISSUER_PUBKEY_LEN]>,
        transport: TransportPolicy,
    ) -> Self {
        Self {
            lookups,
            password,
            issuer_pubkey,
            transport,
        }
    }

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
    /// # Errors
    /// A [`ConfigError::Invalid`] when the lookups fail [`LookupOpts::validate`], the
    /// transports name neither `udp` nor `webrtc`, or `relay_transport` or a missing
    /// `udp` needs the relay lookup while `lookups.relay_lookup` is `Disabled`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.lookups.validate()?;
        let transport = &self.transport;
        if transport.multihop_has_no_direct_path() {
            return Err(ConfigError::Invalid(
                super::transport::MULTIHOP_ALONE.to_owned(),
            ));
        }
        if !transport.allows(Transport::Udp) && !transport.allows(Transport::WebRtc) {
            return Err(ConfigError::Invalid(
                "a mesh needs a direct path: transport `udp`, `webrtc`, or both".to_owned(),
            ));
        }
        let no_relay = self.lookups.relay_lookup == RelayChoice::Disabled;
        if transport.allows(Transport::Relay) && no_relay {
            return Err(ConfigError::Invalid("transport `relay` needs lookup `relay`: with the relay disabled there is none to carry payload".to_owned()));
        }
        // A native member without UDP has no address a peer could reach, so the
        // JSEP exchange that opens its data channel can only cross the relay.
        if !transport.allows(Transport::Udp) && no_relay {
            return Err(ConfigError::Invalid("a mesh without transport `udp` needs lookup `relay`: the relay is the only path its WebRTC offers can take".to_owned()));
        }
        Ok(())
    }

    /// The config a create names, from its three independent choices: the
    /// lookups, the relay ladder, and the transports. Password and invite
    /// stay unset; a caller that wants them fills those fields in.
    ///
    /// This is the one place that knows all three, so the rules that need two
    /// of them live here and nowhere else: a ladder needs `relay` among the
    /// lookups (through [`LookupSet::choose`]), and so does letting the
    /// relay carry payload (through [`MeshConfig::validate`]).
    ///
    /// # Errors
    /// # Errors
    /// A [`ConfigError::Invalid`] when `relay_urls` is given without [`Lookup::Relay`],
    /// when `transports` leaves neither [`Transport::Udp`] nor [`Transport::WebRtc`], or
    /// when the config needs a relay lookup (see [`MeshConfig::validate`]) while none is on.
    /// A [`ConfigError::Invalid`] also from [`TransportPolicy`]'s `TryFrom` list conversion.
    pub fn resolve(
        lookups: &[Lookup],
        relay_urls: Option<RelayLadder>,
        transports: &[Transport],
    ) -> Result<Self, ConfigError> {
        let config = MeshConfig {
            lookups: resolve_lookups(LookupSet::choose(lookups, relay_urls)?),
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy::try_from(transports)?,
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
        let mut buffer = Vec::with_capacity(2);
        self.lookups.encode_into(&mut buffer);
        buffer.push(self.transport.to_byte());
        let mut features = 0u8;
        if self.password.is_some() {
            features |= FEATURE_PASSWORD;
        }
        if self.issuer_pubkey.is_some() {
            features |= FEATURE_INVITE_ONLY;
        }
        if features != 0 {
            buffer.push(features);
            // Fixed field order so the encoding is canonical: password verifier
            // then issuer pubkey, each present iff its bit is set.
            if let Some(verifier) = &self.password {
                buffer.extend_from_slice(verifier);
            }
            if let Some(pubkey) = &self.issuer_pubkey {
                buffer.extend_from_slice(pubkey);
            }
        }
        buffer
    }
}

impl TryFrom<&[u8]> for MeshConfig {
    type Error = ConfigError;

    /// Decode a config region, requiring it to consume `bytes` exactly
    /// (no trailing slack within the length-delimited region we were given).
    ///
    /// # Errors
    /// # Errors
    /// A [`ConfigError::Truncated`] when the bytes end before a field, or
    /// [`ConfigError::Invalid`] for a non-canonical or unknown feature byte or trailing
    /// bytes. A [`ConfigError::Source`] when a nested field does not decode.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut position = 0;
        let lookups = LookupOpts::decode_from(bytes, &mut position)?;
        let transport_byte = *bytes.get(position).ok_or(ConfigError::Truncated(
            "missing transport policy byte: upgrade, this mesh id is from an older build",
        ))?;
        position += 1;
        let transport = TransportPolicy::try_from(transport_byte)?;
        let (password, issuer_pubkey) = if position == bytes.len() {
            (None, None)
        } else {
            let features = bytes[position];
            position += 1;
            if features & !KNOWN_FEATURES != 0 {
                return Err(ConfigError::Invalid(format!(
                    "unsupported mesh feature flags {features:#04x} — upgrade to a newer build"
                )));
            }
            if features == 0 {
                // A zero feature byte re-encodes without itself, silently
                // changing the topic-derivation bytes — reject the
                // non-canonical form outright.
                return Err(ConfigError::Invalid(
                    "non-canonical mesh config: zero feature flags".to_owned(),
                ));
            }
            let password = if features & FEATURE_PASSWORD != 0 {
                let end = position
                    .checked_add(PASSWORD_VERIFIER_LEN)
                    .ok_or(ConfigError::Truncated("password verifier length overflow"))?;
                let raw = bytes
                    .get(position..end)
                    .ok_or(ConfigError::Truncated("truncated password verifier"))?;
                position = end;
                let mut verifier = [0u8; PASSWORD_VERIFIER_LEN];
                verifier.copy_from_slice(raw);
                Some(verifier)
            } else {
                None
            };
            let issuer_pubkey = if features & FEATURE_INVITE_ONLY != 0 {
                let end = position
                    .checked_add(ISSUER_PUBKEY_LEN)
                    .ok_or(ConfigError::Truncated("issuer pubkey length overflow"))?;
                let raw = bytes
                    .get(position..end)
                    .ok_or(ConfigError::Truncated("truncated issuer pubkey"))?;
                position = end;
                let mut pubkey = [0u8; ISSUER_PUBKEY_LEN];
                pubkey.copy_from_slice(raw);
                Some(pubkey)
            } else {
                None
            };
            (password, issuer_pubkey)
        };
        if position != bytes.len() {
            return Err(ConfigError::Invalid(
                "trailing bytes in mesh config".to_owned(),
            ));
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
///
/// # Examples
///
/// A flag that is named or bare is set, and an absent flag is not.
///
/// ```
/// use habilis_network_protocol::meshes::OptFlag;
///
/// assert!(OptFlag::Named(3).is_set());
/// assert!(!OptFlag::<u8>::Unset.is_set());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Copy)]
#[non_exhaustive]
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
///
/// # Examples
///
/// An absent relay selection is not set.
///
/// ```
/// use habilis_network_protocol::meshes::RelaySelection;
///
/// let flag: RelaySelection = RelaySelection::Unset;
/// assert!(!flag.is_set());
/// ```
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
            let ladder: Result<RelayLadder, _> = text.parse();
            ladder.map(RelaySelection::Named)
        }
    }
}

/// CLI `--advertise` intent. `Unset` ⇒ the mesh is not listed in any
/// directory; `Default` ⇒ the well-known `global` directory; `Named` ⇒ a
/// custom one. The directory name is itself a [`MeshName`] (same charset),
/// since the directory derives its mesh from it.
///
/// # Examples
///
/// A named directory selection gives back the name it was given.
///
/// ```
/// use habilis_network_protocol::MeshName;
/// use habilis_network_protocol::meshes::DirectorySelection;
///
/// let flag = DirectorySelection::from(Some(MeshName::try_new("directory-chat").expect("a name")));
/// assert!(flag.is_set());
/// assert_eq!(flag.directory().expect("a named directory").as_str(), "directory-chat");
/// ```
pub type DirectorySelection = OptFlag<MeshName>;

/// The well-known default directory — used when `--advertise` is passed
/// bare (no value).
pub const DEFAULT_DIRECTORY: &str = "global";

impl OptFlag<MeshName> {
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
                MeshName::try_new(DEFAULT_DIRECTORY)
                    .expect("DEFAULT_DIRECTORY is a valid mesh name"),
            ),
            DirectorySelection::Named(name) => Some(name.clone()),
        }
    }

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
    pub fn from_option(flag: Option<MeshName>) -> Self {
        match flag {
            None => DirectorySelection::Unset,
            Some(directory) => DirectorySelection::Named(directory),
        }
    }
}

impl From<Option<MeshName>> for OptFlag<MeshName> {
    fn from(flag: Option<MeshName>) -> Self {
        Self::from_option(flag)
    }
}

/// Advertise was requested on a loopback-only mesh. A directory listing
/// requires a mesh reachable across machines, so this is a hard error
/// (never a silent no-op). Typed so callers can classify it — the MCP
/// server maps it to `invalid_params`, the CLI to an `anyhow` bail.
///
/// # Examples
///
/// A mesh that advertises on a loopback lookup set is refused, and this is the error.
///
/// ```
/// use habilis_network_protocol::meshes::{DirectorySelection, LookupOpts, validate_advertise};
///
/// let error = validate_advertise(&DirectorySelection::Default, &LookupOpts::loopback()).unwrap_err();
/// assert!(!error.to_string().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[non_exhaustive]
pub struct AdvertiseRequiresReachable;

impl fmt::Display for AdvertiseRequiresReachable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("advertise needs a reachable mesh; enable a lookup (e.g. public)")
    }
}

impl error::Error for AdvertiseRequiresReachable {}

/// `--advertise` lists the mesh in a public directory, so it requires a
/// mesh that is actually reachable across machines.
/// # Errors
/// The mesh advertises to a directory but is not reachable from one.
///
/// # Examples
///
/// Advertising is allowed only when the lookups can reach peers from outside the loopback.
///
/// ```
/// use habilis_network_protocol::meshes::{DirectorySelection, LookupOpts, validate_advertise};
///
/// assert!(validate_advertise(&DirectorySelection::Unset, &LookupOpts::loopback()).is_ok());
/// assert!(validate_advertise(&DirectorySelection::Default, &LookupOpts::loopback()).is_err());
/// ```
pub fn validate_advertise(
    advertise: &DirectorySelection,
    lookups: &LookupOpts,
) -> Result<(), AdvertiseRequiresReachable> {
    if advertise.is_set() && lookups.is_loopback() && !tuning::directory_private_for_test() {
        return Err(AdvertiseRequiresReachable);
    }
    Ok(())
}

/// One way a mesh's members find each other — an entry of the `lookup` list
/// a create names. Naming any restricts the mesh to exactly those; naming
/// none is a loopback-only mesh.
///
/// # Examples
///
/// Each lookup has a name that parses back to the same lookup.
///
/// ```
/// use habilis_network_protocol::meshes::Lookup;
///
/// let parsed: Lookup = Lookup::Dht.as_str().parse().expect("a lookup name parses");
/// assert_eq!(parsed.as_str(), Lookup::Dht.as_str());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
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
///
/// # Examples
///
/// A set with a lookup in it resolves to lookups that are not loopback.
///
/// ```
/// use habilis_network_protocol::meshes::{Lookup, LookupSet, resolve_lookups};
///
/// let set = LookupSet::choose(&[Lookup::Mdns], None).expect("a lookup set");
/// assert!(set.any());
/// assert!(!resolve_lookups(set).is_loopback());
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LookupSet {
    /// Whether peers are found on the local network.
    pub mdns: bool,
    /// Whether peers are found on the mainline DHT.
    pub dht: bool,
    /// How the relay is used to find peers.
    pub relay_lookup: RelaySelection,
}

impl LookupSet {
    /// The set a `lookup` list names, with `relay_urls` as the ladder the
    /// relay lookup homes on (`None` ⇒ the pinned default).
    ///
    /// # Errors
    /// # Errors
    /// A [`ConfigError::Invalid`] when `relay_urls` is given but `lookups` does not
    /// name [`Lookup::Relay`]: a ladder says *which* relay, and only a relay lookup uses one.
    pub fn choose(
        lookups: &[Lookup],
        relay_urls: Option<RelayLadder>,
    ) -> Result<Self, ConfigError> {
        let relay = lookups.contains(&Lookup::Relay);
        if relay_urls.is_some() && !relay {
            return Err(ConfigError::Invalid(
                "a relay ladder needs lookup `relay`".to_owned(),
            ));
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

    /// Whether the set names at least one lookup. A set that names none
    /// resolves to a loopback-only mesh in [`resolve_lookups`], so a consumer
    /// that wants another default for that case asks this, not its own copy
    /// of the rule.
    #[must_use]
    pub fn any(&self) -> bool {
        self.mdns || self.dht || self.relay_lookup.is_set()
    }
}

/// Resolve a selection into the effective [`LookupOpts`] baked into the mesh
/// id. Naming **any** lookup uses *only* those named (so `mdns` alone is
/// mDNS-only, relay/dht off); naming none is a loopback-only mesh. A bare
/// relay ⇒ the pinned default ladder, a named one ⇒ that custom ladder.
///
/// # Examples
///
/// An empty lookup set resolves to the loopback lookups.
///
/// ```
/// use habilis_network_protocol::meshes::{LookupSet, resolve_lookups};
///
/// let set = LookupSet::choose(&[], None).expect("an empty lookup set");
/// assert!(resolve_lookups(set).is_loopback());
/// ```
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
            let url: RelayUrl = trimmed
                .parse()
                .map_err(|error| format!("invalid relay URL {trimmed:?}: {error}"))?;
            Ok(url)
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
///
/// # Examples
///
/// A relay ladder holds the relay URLs that it is given, in order.
///
/// ```
/// use habilis_network_protocol::meshes::RelayLadder;
///
/// let ladder: RelayLadder = "https://relay.example.com".parse().expect("a relay ladder");
/// assert_eq!(ladder.len(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLadder(Vec<RelayUrl>);

/// A relay ladder that couldn't be parsed (empty entry / invalid URL).
///
/// # Examples
///
/// Text that is not a relay URL returns an error that says why.
///
/// ```
/// use habilis_network_protocol::meshes::RelayLadder;
///
/// let error = "not a relay".parse::<RelayLadder>().unwrap_err();
/// assert!(!error.to_string().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct RelayLadderError(String);

impl fmt::Display for RelayLadderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl error::Error for RelayLadderError {}

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
        let mut separator = "";
        for url in &self.0 {
            formatter.write_str(separator)?;
            write!(formatter, "{url}")?;
            separator = ",";
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
    use std::collections::HashSet;

    fn lookups(mdns: bool, dht: bool, relay_lookup: RelaySelection) -> LookupSet {
        LookupSet {
            mdns,
            dht,
            relay_lookup,
        }
    }

    #[test]
    fn relay_ladder_parses_ordered_rungs() {
        let _guard = ::habilis_network_test_tracing::init();
        let one: RelayLadder = "https://a.example"
            .parse()
            .expect("the literal is a valid relay URL");
        assert_eq!(one.len(), 1, "a single rung parses to one rung");
        assert!(!one.is_empty(), "a single rung is not an empty ladder");

        let two: RelayLadder = "https://a.example,https://b.example"
            .parse()
            .expect("the literal is a list of valid relay URLs");
        assert_eq!(two.len(), 2, "two rungs parse to two rungs");
        // Display round-trips through FromStr (canonical `a,b` text form).
        let rendered = two.to_string();
        let reparsed: RelayLadder = rendered
            .parse()
            .expect("the text was rendered from a valid relay ladder");
        assert_eq!(reparsed, two, "the ladder re-parses to the same rungs");
        assert_eq!(two.as_urls().len(), 2, "the ladder lists its two urls");
    }

    #[test]
    fn relay_ladder_rejects_empty_and_empty_entries() {
        let _guard = ::habilis_network_test_tracing::init();
        let empty: Result<RelayLadder, _> = "".parse();
        assert!(
            empty.is_err(),
            "an empty ladder and an empty entry are refused"
        );
        let doubled: Result<RelayLadder, _> = "https://a.example,,https://b.example".parse();
        assert!(
            doubled.is_err(),
            "an empty entry must be rejected so a typo never shrinks the ladder"
        );
    }

    #[test]
    fn naming_relay_alone_is_reachable() {
        let _guard = ::habilis_network_test_tracing::init();
        // Naming any lookup uses only those. A relay alone yields a reachable
        // (non-loopback) mesh.
        let ladder: RelayLadder = "https://a.example"
            .parse()
            .expect("the literal is a valid relay URL");
        let options = resolve_lookups(lookups(false, false, RelaySelection::Named(ladder)));
        assert!(
            !options.mdns && !options.dht,
            "naming relay alone leaves mdns and dht off"
        );
        assert!(
            !options.is_loopback(),
            "a named relay makes the mesh reachable"
        );
        assert!(
            matches!(options.relay_lookup, RelayChoice::Custom(_)),
            "naming relay alone selects a custom relay lookup"
        );
    }

    #[test]
    fn mdns_alone_disables_dht_and_relay() {
        let _guard = ::habilis_network_test_tracing::init();
        let options = resolve_lookups(lookups(true, false, RelaySelection::Unset));
        assert!(
            options.mdns && !options.dht,
            "naming mdns alone turns dht off"
        );
        assert_eq!(
            options.relay_lookup,
            RelayChoice::Disabled,
            "--mdns alone ⇒ relay off"
        );
        assert!(!options.is_loopback(), "any lookup ⇒ reachable");
    }

    #[test]
    fn bare_relay_is_pinned_and_suppresses_lookups() {
        let _guard = ::habilis_network_test_tracing::init();
        let options = resolve_lookups(lookups(false, false, RelaySelection::Default));
        assert!(
            !options.mdns && !options.dht,
            "a bare relay is off for mdns and dht"
        );
        assert_eq!(
            options.relay_lookup,
            RelayChoice::Pinned,
            "a bare relay pins the relay lookup"
        );
    }

    #[test]
    fn valued_relay_preserves_ladder_order() {
        let _guard = ::habilis_network_test_tracing::init();
        let rung0: iroh_base::RelayUrl = "https://a.example"
            .parse()
            .expect("the literal is a valid relay URL");
        let rung1: iroh_base::RelayUrl = "https://b.example"
            .parse()
            .expect("the literal is a valid relay URL");
        let ladder: RelayLadder = "https://a.example,https://b.example"
            .parse()
            .expect("the literal is a list of valid relay URLs");
        let options = resolve_lookups(lookups(false, false, RelaySelection::Named(ladder)));
        assert_eq!(
            options.relay_lookup,
            RelayChoice::Custom(vec![rung0, rung1]),
            "a valued relay keeps the order of its ladder"
        );
    }

    #[test]
    fn config_round_trips_loopback() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = MeshConfig::loopback();
        let decoded = MeshConfig::try_from(config.to_bytes().as_slice())
            .expect("the config was just encoded by to_bytes, so it decodes");
        assert_eq!(decoded, config, "a loopback config survives a round trip");
    }

    #[test]
    fn config_round_trips_public_preset() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = MeshConfig::public_preset();
        let decoded = MeshConfig::try_from(config.to_bytes().as_slice())
            .expect("the config was just encoded by to_bytes, so it decodes");
        assert_eq!(
            decoded, config,
            "a public preset config survives a round trip"
        );
    }

    #[test]
    fn config_round_trips_custom_relay_ladder() {
        let _guard = ::habilis_network_test_tracing::init();
        let config: MeshConfig = MeshConfig {
            lookups: LookupOpts {
                mdns: true,
                dht: false,
                relay_lookup: RelayChoice::Custom(vec![
                    "https://a.example"
                        .parse()
                        .expect("the literal is a valid relay URL"),
                    "https://b.example"
                        .parse()
                        .expect("the literal is a valid relay URL"),
                ]),
            },
            password: None,
            issuer_pubkey: None,
            transport: TransportPolicy::default(),
        };
        let decoded = MeshConfig::try_from(config.to_bytes().as_slice())
            .expect("the config was just encoded by to_bytes, so it decodes");
        assert_eq!(
            decoded, config,
            "a custom relay ladder survives a round trip"
        );
    }

    #[test]
    fn config_rejects_trailing_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        // A lone trailing 0x00 is now the non-canonical zero feature byte;
        // either way it must be rejected, never silently absorbed.
        let mut bytes = MeshConfig::loopback().to_bytes();
        bytes.push(0);
        assert!(
            MeshConfig::try_from(&bytes[..]).is_err(),
            "trailing bytes after a config are refused"
        );
    }

    #[test]
    fn config_rejects_custom_flag_without_enabled() {
        let _guard = ::habilis_network_test_tracing::init();
        // flags with custom(0b1000) but not enabled(0b0100).
        let bytes = [0b1000];
        assert!(
            MeshConfig::try_from(&bytes[..]).is_err(),
            "a custom flag without its enabled flag is refused"
        );
    }

    #[test]
    fn config_round_trips_password_verifier() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = MeshConfig {
            lookups: LookupOpts::public_preset(),
            password: Some([0xa5u8; 16]),
            issuer_pubkey: None,
            transport: TransportPolicy::default(),
        };
        let decoded = MeshConfig::try_from(config.to_bytes().as_slice())
            .expect("the config was just encoded by to_bytes, so it decodes");
        assert_eq!(decoded, config, "a password verifier survives a round trip");
    }

    #[test]
    fn a_passwordless_config_has_no_feature_byte() {
        let _guard = ::habilis_network_test_tracing::init();
        // The lookups byte, the policy byte, and nothing else: the feature
        // byte only exists for a password or an invite.
        assert_eq!(
            MeshConfig::loopback().to_bytes(),
            vec![0b0000, 0b1_0111],
            "a loopback config without a password encodes no feature byte"
        );
        assert_eq!(
            MeshConfig::public_preset().to_bytes(),
            vec![0b0111, 0b1_0111],
            "a public preset without a password encodes no feature byte"
        );
    }

    #[test]
    fn config_rejects_unknown_feature_flags() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut bytes = MeshConfig::public_preset().to_bytes();
        bytes.push(0b10_0000); // an undefined feature bit (1 to 16 are taken)
        bytes.extend_from_slice(&[0u8; 16]);
        let error = MeshConfig::try_from(&bytes[..]).expect_err(
            "the bytes in this test carry an unknown transport bit, so decoding is refused",
        );
        assert!(
            error.to_string().contains("upgrade to a newer build"),
            "got: {error}"
        );
    }

    #[test]
    fn config_round_trips_relay_as_transport() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = MeshConfig {
            transport: TransportPolicy::default().relay_transport(true),
            ..MeshConfig::public_preset()
        };
        let bytes = config.to_bytes();
        // Lookups byte, then the policy byte with every path on, the relay and gossip
        // included. No feature byte: no password and no invite.
        assert_eq!(
            bytes,
            vec![0b0111, 0b1_1111],
            "a relay transport encodes as the expected bytes"
        );
        assert_eq!(
            MeshConfig::try_from(&bytes[..])
                .expect("the bytes in this test are a valid encoded config"),
            config,
            "a relay transport decodes back to the same config"
        );
        assert_ne!(
            bytes,
            MeshConfig::public_preset().to_bytes(),
            "letting the relay carry payload derives a different topic"
        );
    }

    #[test]
    fn relay_is_lookup_only_by_default() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !MeshConfig::public_preset()
                .transport
                .allows(Transport::Relay),
            "the public preset keeps the relay lookup only"
        );
        assert!(
            !MeshConfig::try_from(&[0b0111, 0b0111])
                .expect("the bytes in this test are a valid encoded config")
                .transport
                .allows(Transport::Relay),
            "the relay stays lookup-only when the flag is not set"
        );
    }

    #[test]
    fn udp_webrtc_multihop_and_gossip_are_on_by_default() {
        let _guard = ::habilis_network_test_tracing::init();
        let default = TransportPolicy::default();
        assert!(
            default.allows(Transport::Udp)
                && default.allows(Transport::WebRtc)
                && default.allows(Transport::Multihop)
                && !default.allows(Transport::Relay),
            "udp, webrtc, multihop and gossip are on by default"
        );
        assert!(default.allows(Transport::Gossip), "gossip is on by default");
        assert_eq!(
            MeshConfig::public_preset().to_bytes(),
            vec![0b0111, 0b1_0111],
            "the public preset encodes the default transport policy"
        );
        let decoded = MeshConfig::try_from(&[0b0111, 0b1_0111])
            .expect("the bits in this test name a valid transport set")
            .transport;
        assert_eq!(
            decoded, default,
            "the default transport policy survives a round trip"
        );
        let with_relay = MeshConfig::try_from(&[0b0111, 0b1111])
            .expect("the bits in this test name a valid transport set")
            .transport;
        assert!(
            with_relay.allows(Transport::Udp)
                && with_relay.allows(Transport::WebRtc)
                && with_relay.allows(Transport::Multihop)
                && with_relay.allows(Transport::Relay),
            "the relayed policy keeps the default paths on"
        );
    }

    #[test]
    fn the_transport_policy_is_always_one_explicit_byte() {
        let _guard = ::habilis_network_test_tracing::init();
        // Lookups byte, then the policy byte. Nothing is left implicit: a
        // config without the policy byte is not a version 2 config.
        assert_eq!(
            MeshConfig::public_preset().to_bytes().len(),
            2,
            "the transport policy is one explicit byte"
        );
        assert!(
            MeshConfig::try_from(&[0b0111]).is_err(),
            "a transport policy of one byte with no lookup is refused"
        );
    }

    #[test]
    fn a_transport_list_turns_on_exactly_the_paths_it_names() {
        let _guard = ::habilis_network_test_tracing::init();
        let policy = |list: &[Transport]| {
            TransportPolicy::try_from(list)
                .expect("the list in this test names only known transports")
        };
        assert_eq!(
            policy(&[]),
            TransportPolicy::default(),
            "an empty transport list gives the default policy"
        );
        let udp = policy(&[Transport::Udp]);
        assert!(
            udp.allows(Transport::Udp)
                && !udp.allows(Transport::WebRtc)
                && !udp.allows(Transport::Multihop)
                && !udp.allows(Transport::Relay),
            "a udp list turns on udp alone"
        );
        let webrtc = policy(&[Transport::WebRtc]);
        assert!(
            !webrtc.allows(Transport::Udp)
                && webrtc.allows(Transport::WebRtc)
                && !webrtc.allows(Transport::Multihop)
                && !webrtc.allows(Transport::Relay),
            "a webrtc list turns on webrtc alone"
        );
        let multihop = policy(&[Transport::Udp, Transport::Multihop]);
        assert!(
            multihop.allows(Transport::Udp)
                && !multihop.allows(Transport::WebRtc)
                && multihop.allows(Transport::Multihop)
                && !multihop.allows(Transport::Relay),
            "a multihop list turns on multihop alone"
        );
        let all = policy(&[
            Transport::Udp,
            Transport::WebRtc,
            Transport::Multihop,
            Transport::Relay,
        ]);
        assert!(
            all.allows(Transport::Udp)
                && all.allows(Transport::WebRtc)
                && all.allows(Transport::Multihop)
                && all.allows(Transport::Relay),
            "the full list turns on every path"
        );
    }

    #[test]
    fn config_round_trips_every_transport_list() {
        let _guard = ::habilis_network_test_tracing::init();
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
            let config = MeshConfig::resolve(&[Lookup::Relay], None, list)
                .expect("the lookup and transport list in this test resolve to a valid config");
            let bytes = config.to_bytes();
            assert_eq!(
                MeshConfig::try_from(&bytes[..])
                    .expect("the bytes in this test are a valid encoded config"),
                config,
                "{list:?}"
            );
            assert!(!seen.contains(&bytes), "{list:?} shares its bytes");
            seen.push(bytes);
        }
    }

    #[test]
    fn a_mesh_without_udp_needs_the_relay_lookup() {
        let _guard = ::habilis_network_test_tracing::init();
        let error = MeshConfig::resolve(&[Lookup::Mdns], None, &[Transport::WebRtc])
            .expect_err("a relay-only lookup with no relay ladder is refused by resolve")
            .to_string();
        assert!(error.contains("relay"), "{error}");
        assert!(
            MeshConfig::resolve(&[Lookup::Relay], None, &[Transport::WebRtc]).is_ok(),
            "a mesh without udp needs the relay lookup for webrtc"
        );
        assert!(
            MeshConfig::resolve(&[Lookup::Mdns], None, &[Transport::Udp]).is_ok(),
            "a mesh with mdns and udp needs no relay lookup"
        );
    }

    /// `webrtc` is a direct path, so `webrtc,multihop` is a list that multihop can forward
    /// over, with no `udp`: the case of a browser, and of a native member run without IP.
    #[test]
    fn multihop_with_webrtc_and_no_udp_resolves() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            MeshConfig::resolve(
                &[Lookup::Relay],
                None,
                &[Transport::WebRtc, Transport::Multihop],
            )
            .is_ok(),
            "multihop with webrtc and no udp resolves"
        );
        let bytes = [0b0111, super::TRANSPORT_WEBRTC | super::TRANSPORT_MULTIHOP];
        assert!(
            MeshConfig::try_from(&bytes[..]).is_ok(),
            "the multihop config decodes"
        );
    }

    const NEEDS_A_DIRECT_PATH: &str =
        "a transport list needs a direct path: name `udp`, `webrtc`, or both";
    const MULTIHOP_ALONE: &str = "transport `multihop` cannot be the only transport: it forwards over a direct path, name `udp` or `webrtc`";

    /// The gossip bit is the fifth: an id that an older build made has it clear, reads as gossip
    /// off, and keeps its bytes, so its id and its topic do not move. The default has the bit,
    /// so a default mesh made now has another id than one made before.
    #[test]
    fn the_gossip_bit_is_the_fifth_and_an_older_id_reads_as_gossip_off() {
        let _guard = ::habilis_network_test_tracing::init();
        let default = MeshConfig::public_preset();
        let bytes = default.to_bytes();
        assert_eq!(
            bytes,
            vec![0b0111, 0b1_0111],
            "the gossip bit encodes as the expected bytes"
        );
        assert_eq!(
            MeshConfig::try_from(&bytes[..])
                .expect("the bytes in this test are a valid encoded config"),
            default,
            "an older id decodes with gossip off"
        );
        let without_gossip = MeshConfig {
            transport: TransportPolicy::default().gossip(false),
            ..MeshConfig::public_preset()
        };
        assert_eq!(
            without_gossip.to_bytes(),
            vec![0b0111, 0b0111],
            "a config without gossip encodes the expected bytes"
        );
        assert_ne!(
            bytes,
            without_gossip.to_bytes(),
            "gossip on derives another id and another topic"
        );
        let older = [0b0111, 0b0111];
        let decoded = MeshConfig::try_from(&older)
            .expect("the older encoding in this test is a valid config");
        assert!(
            !decoded.transport.allows(Transport::Gossip),
            "an older id has gossip off after decoding"
        );
        assert_eq!(
            decoded, without_gossip,
            "the decoded config without gossip equals the original"
        );
        assert_eq!(decoded.to_bytes(), older, "an older id keeps its bytes");
    }

    /// A decoded id passes `validate` and not `from_transports`: gossip with no `udp` or `webrtc`
    /// is refused the same way, whatever else the byte names.
    #[test]
    fn an_id_with_gossip_and_no_direct_path_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        let gossip_only = MeshConfig::try_from(&[0b0111, super::TRANSPORT_GOSSIP])
            .expect_err("the transport list with gossip only is refused by try_from")
            .to_string();
        assert!(gossip_only.contains("needs a direct path"), "{gossip_only}");
        let with_multihop =
            MeshConfig::try_from(&[0b0111, super::TRANSPORT_GOSSIP | super::TRANSPORT_MULTIHOP])
                .expect_err("the transport list with gossip and multihop is refused by try_from")
                .to_string();
        assert_eq!(
            with_multihop, MULTIHOP_ALONE,
            "an id with gossip and no direct path is refused as multihop alone"
        );
    }

    /// Every subset of the five transports, each with its result: `Ok`, or the
    /// exact error. A relay lookup is on, so the relay rules do not speak here.
    #[test]
    fn every_subset_of_the_transports_resolves_or_names_its_error() {
        use Transport::{Gossip, Multihop, Relay, Udp, WebRtc};
        let _guard = ::habilis_network_test_tracing::init();
        let rows: [(&[Transport], Result<(), &str>); 32] = [
            (&[], Ok(())),
            (&[Udp], Ok(())),
            (&[WebRtc], Ok(())),
            (&[Multihop], Err(MULTIHOP_ALONE)),
            (&[Relay], Err(NEEDS_A_DIRECT_PATH)),
            (&[Udp, WebRtc], Ok(())),
            (&[Udp, Multihop], Ok(())),
            (&[Udp, Relay], Ok(())),
            (&[WebRtc, Multihop], Ok(())),
            (&[WebRtc, Relay], Ok(())),
            (&[Multihop, Relay], Err(MULTIHOP_ALONE)),
            (&[Udp, WebRtc, Multihop], Ok(())),
            (&[Udp, WebRtc, Relay], Ok(())),
            (&[Udp, Multihop, Relay], Ok(())),
            (&[WebRtc, Multihop, Relay], Ok(())),
            (&[Udp, WebRtc, Multihop, Relay], Ok(())),
            // Gossip rides the links of a direct path: it adds nothing on its own.
            (&[Gossip], Err(NEEDS_A_DIRECT_PATH)),
            (&[Udp, Gossip], Ok(())),
            (&[WebRtc, Gossip], Ok(())),
            (&[Multihop, Gossip], Err(MULTIHOP_ALONE)),
            (&[Relay, Gossip], Err(NEEDS_A_DIRECT_PATH)),
            (&[Udp, WebRtc, Gossip], Ok(())),
            (&[Udp, Multihop, Gossip], Ok(())),
            (&[Udp, Relay, Gossip], Ok(())),
            (&[WebRtc, Multihop, Gossip], Ok(())),
            (&[WebRtc, Relay, Gossip], Ok(())),
            (&[Multihop, Relay, Gossip], Err(MULTIHOP_ALONE)),
            (&[Udp, WebRtc, Multihop, Gossip], Ok(())),
            (&[Udp, WebRtc, Relay, Gossip], Ok(())),
            (&[Udp, Multihop, Relay, Gossip], Ok(())),
            (&[WebRtc, Multihop, Relay, Gossip], Ok(())),
            (&[Udp, WebRtc, Multihop, Relay, Gossip], Ok(())),
        ];
        let mask: fn(&[Transport]) -> u8 = |list| {
            let transports = [Udp, WebRtc, Multihop, Gossip, Relay];
            let bits = transports.iter().enumerate();
            let present = bits.filter(|(_, transport)| list.contains(transport));
            present.fold(0u8, |mask, (bit, _)| mask | 1 << bit)
        };
        let covered: HashSet<u8> = rows.iter().map(|(list, _)| mask(list)).collect();
        assert_eq!(covered.len(), 32, "the table names every subset once");
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
        let _guard = ::habilis_network_test_tracing::init();
        let alone = MeshConfig::try_from(&[0b0111, super::TRANSPORT_MULTIHOP])
            .expect_err("the bits name multihop alone, which is refused")
            .to_string();
        assert_eq!(
            alone, MULTIHOP_ALONE,
            "an id with multihop alone names the multihop mistake"
        );
        let with_relay = super::TRANSPORT_MULTIHOP | super::TRANSPORT_RELAY;
        let with_relay_error = MeshConfig::try_from(&[0b0111, with_relay])
            .expect_err("the bits name multihop with a relay, which is refused")
            .to_string();
        assert_eq!(
            with_relay_error, MULTIHOP_ALONE,
            "an id with multihop and a relay error names the multihop mistake"
        );
    }

    /// One rule, not one per caller: a list that names `multihop` twice is
    /// still multihop with no direct transport, and says so as a list of one.
    #[test]
    fn multihop_named_twice_is_still_multihop_alone() {
        let _guard = ::habilis_network_test_tracing::init();
        for list in [
            &[Transport::Multihop, Transport::Multihop][..],
            &[Transport::Multihop, Transport::Relay, Transport::Multihop][..],
        ] {
            let error = MeshConfig::resolve(&[Lookup::Relay], None, list)
                .expect_err("MeshConfig::resolve refuses a list that names multihop with no direct transport")
                .to_string();
            assert_eq!(error, MULTIHOP_ALONE, "{list:?}");
        }
    }

    #[test]
    fn a_policy_byte_with_an_unknown_bit_asks_for_an_upgrade() {
        let _guard = ::habilis_network_test_tracing::init();
        // Bit 4 is gossip now: the next one is the first unknown.
        let error = MeshConfig::try_from(&[0b0111, 0b10_0111])
            .expect_err("a bit past the known transports is refused by MeshConfig::try_from")
            .to_string();
        assert!(error.contains("upgrade"), "{error}");
    }

    #[test]
    fn an_id_with_neither_udp_nor_webrtc_is_refused() {
        let _guard = ::habilis_network_test_tracing::init();
        for byte in [0b0000, super::TRANSPORT_MULTIHOP, super::TRANSPORT_RELAY] {
            assert!(
                MeshConfig::try_from(&[0b0111, byte]).is_err(),
                "{byte:#06b}"
            );
        }
    }

    #[test]
    fn config_round_trips_relay_as_transport_with_password() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = MeshConfig {
            lookups: LookupOpts::public_preset(),
            password: Some([0xa5u8; 16]),
            issuer_pubkey: None,
            transport: TransportPolicy::default().relay_transport(true),
        };
        let decoded = MeshConfig::try_from(config.to_bytes().as_slice())
            .expect("the config was just encoded by to_bytes, so it decodes");
        assert_eq!(
            decoded, config,
            "a relay transport with a password survives a round trip"
        );
    }

    #[test]
    fn config_rejects_relay_transport_on_without_a_relay_lookup() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = MeshConfig {
            transport: TransportPolicy::default().relay_transport(true),
            ..MeshConfig::loopback()
        };
        assert!(config.validate().is_err(), "no relay to carry payload");
        // The same shape on the wire is refused on decode too.
        let bytes = [0b0000, super::TRANSPORT_UDP | super::TRANSPORT_RELAY];
        assert!(
            MeshConfig::try_from(&bytes[..]).is_err(),
            "relay transport on without a relay lookup is refused"
        );
    }

    #[test]
    fn config_round_trips_issuer_pubkey() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = MeshConfig {
            lookups: LookupOpts::public_preset(),
            password: None,
            issuer_pubkey: Some([0x3cu8; 32]),
            transport: TransportPolicy::default(),
        };
        let decoded = MeshConfig::try_from(config.to_bytes().as_slice())
            .expect("the config was just encoded by to_bytes, so it decodes");
        assert_eq!(
            decoded, config,
            "an issuer public key survives a round trip"
        );
    }

    #[test]
    fn config_round_trips_password_and_invite_together() {
        let _guard = ::habilis_network_test_tracing::init();
        // Both feature bits set: the fixed field order (verifier, then issuer
        // pubkey) must round-trip.
        let config = MeshConfig {
            lookups: LookupOpts::loopback(),
            password: Some([0xa5u8; 16]),
            issuer_pubkey: Some([0x3cu8; 32]),
            transport: TransportPolicy::default(),
        };
        let decoded = MeshConfig::try_from(config.to_bytes().as_slice())
            .expect("the config was just encoded by to_bytes, so it decodes");
        assert_eq!(
            decoded, config,
            "a password and an invite survive a round trip together"
        );
    }

    #[test]
    fn config_rejects_truncated_issuer_pubkey() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut bytes = MeshConfig::public_preset().to_bytes();
        bytes.push(0b0010); // invite-only bit
        bytes.extend_from_slice(&[0u8; 16]); // half a pubkey
        assert!(
            MeshConfig::try_from(&bytes[..]).is_err(),
            "a truncated issuer public key is refused"
        );
    }

    #[test]
    fn config_rejects_truncated_verifier() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut bytes = MeshConfig::public_preset().to_bytes();
        bytes.push(0b0001);
        bytes.extend_from_slice(&[0u8; 8]); // half a verifier
        assert!(
            MeshConfig::try_from(&bytes[..]).is_err(),
            "a truncated verifier is refused"
        );
    }

    #[test]
    fn config_rejects_verifier_with_trailing_slack() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut bytes = MeshConfig::public_preset().to_bytes();
        bytes.push(0b0001);
        bytes.extend_from_slice(&[0u8; 17]); // verifier + one extra byte
        assert!(
            MeshConfig::try_from(&bytes[..]).is_err(),
            "a verifier with trailing slack is refused"
        );
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
        let _guard = ::habilis_network_test_tracing::init();
        let mdns: Lookup = "mdns"
            .parse()
            .expect("the literal \"mdns\" is a known lookup name");
        assert_eq!(
            mdns,
            Lookup::Mdns,
            "the mdns name parses to the mdns lookup"
        );
        let dht: Lookup = "dht"
            .parse()
            .expect("the literal \"dht\" is a known lookup name");
        assert_eq!(dht, Lookup::Dht, "the dht name parses to the dht lookup");
        let relay: Lookup = "relay"
            .parse()
            .expect("the literal \"relay\" is a known lookup name");
        assert_eq!(
            relay,
            Lookup::Relay,
            "the relay name parses to the relay lookup"
        );
        let udp: Transport = "udp"
            .parse()
            .expect("the literal \"udp\" is a known transport name");
        assert_eq!(
            udp,
            Transport::Udp,
            "the udp name parses to the udp transport"
        );
        let webrtc: Transport = "webrtc"
            .parse()
            .expect("the literal \"webrtc\" is a known transport name");
        assert_eq!(
            webrtc,
            Transport::WebRtc,
            "the webrtc name parses to the webrtc transport"
        );
        let relay_transport: Transport = "relay"
            .parse()
            .expect("the literal \"relay\" is a known lookup name");
        assert_eq!(
            relay_transport,
            Transport::Relay,
            "the relay name parses to the relay transport"
        );
        let multihop: Transport = "multihop"
            .parse()
            .expect("the literal \"multihop\" is a known transport name");
        assert_eq!(
            multihop,
            Transport::Multihop,
            "the multihop name parses to the multihop transport"
        );
        let gossip: Transport = "gossip"
            .parse()
            .expect("the literal \"gossip\" is a known transport name");
        assert_eq!(
            gossip,
            Transport::Gossip,
            "the gossip name parses to the gossip transport"
        );
        assert_eq!(
            Transport::Gossip.to_string(),
            "gossip",
            "the gossip transport displays as gossip"
        );
        for (name, lookup) in [
            ("mdns", Lookup::Mdns),
            ("dht", Lookup::Dht),
            ("relay", Lookup::Relay),
        ] {
            assert_eq!(lookup.to_string(), name, "the lookup displays as its name");
        }
        assert_eq!(
            Transport::Udp.to_string(),
            "udp",
            "the udp transport displays as udp"
        );
    }

    #[test]
    fn the_direct_transport_is_named_udp_not_p2p() {
        let _guard = ::habilis_network_test_tracing::init();
        let udp: Transport = "udp"
            .parse()
            .expect("the literal \"udp\" is a known transport name");
        assert_eq!(udp.to_string(), "udp", "the direct transport is named udp");
        let p2p: Result<Transport, _> = "p2p".parse();
        assert!(p2p.is_err(), "the name p2p is not a transport");
    }

    #[test]
    fn an_unknown_name_is_an_error_that_lists_the_choices() {
        let _guard = ::habilis_network_test_tracing::init();
        let misspelt: Result<Lookup, _> = "relai".parse();
        let error = misspelt
            .expect_err("the misspelt name is not a known transport, so parsing refuses it")
            .to_string();
        assert!(
            error.contains("relai") && error.contains("mdns, dht, relay"),
            "{error}"
        );
        let unknown_transport: Result<Transport, _> = "tcp".parse();
        let transport_error = unknown_transport
            .expect_err("the unknown transport name is refused by parsing")
            .to_string();
        assert!(
            transport_error.contains("tcp")
                && transport_error.contains("udp, webrtc, multihop, gossip, relay"),
            "{transport_error}"
        );
    }

    #[test]
    fn the_lists_deserialize_from_json_names() {
        let _guard = ::habilis_network_test_tracing::init();
        let lookups: Vec<Lookup> = serde_json::from_str(r#"["mdns","relay"]"#)
            .expect("the JSON literal is a list of known lookup names");
        assert_eq!(
            lookups,
            vec![Lookup::Mdns, Lookup::Relay],
            "the lookup list deserializes from its json names"
        );
        let transports: Vec<Transport> = serde_json::from_str(r#"["udp","relay"]"#)
            .expect("the JSON literal is a list of known transport names");
        assert_eq!(
            transports,
            vec![Transport::Udp, Transport::Relay],
            "the transport list deserializes from its json names"
        );
        let unknown: Result<Vec<Lookup>, _> = serde_json::from_str(r#"["public"]"#);
        assert!(unknown.is_err(), "an unknown json lookup name is refused");
    }

    #[test]
    fn a_lookup_list_becomes_the_set_of_exactly_those() {
        let _guard = ::habilis_network_test_tracing::init();
        let set = LookupSet::choose(&[Lookup::Mdns], None)
            .expect("a mDNS-only lookup set has a valid choice with no ladder");
        assert!(
            set.mdns && !set.dht,
            "a lookup list sets mdns and leaves dht off"
        );
        assert_eq!(
            set.relay_lookup,
            RelaySelection::Unset,
            "a lookup list leaves the relay lookup unset"
        );
        let options = resolve_lookups(set);
        assert!(
            options.mdns && !options.dht,
            "a lookup list gives the options mdns and no dht"
        );
        assert_eq!(
            options.relay_lookup,
            RelayChoice::Disabled,
            "a lookup list leaves the relay lookup disabled"
        );
    }

    #[test]
    fn a_set_names_a_lookup_when_any_field_is_set() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            !LookupSet::default().any(),
            "an empty lookup set names no lookup"
        );
        for lookup in [Lookup::Mdns, Lookup::Dht, Lookup::Relay] {
            let set = LookupSet::choose(&[lookup], None)
                .expect("the lookup set in this test has a valid choice with no ladder");
            assert!(set.any(), "{lookup:?} alone is a lookup");
        }
    }

    #[test]
    fn naming_relay_takes_the_default_ladder_unless_one_is_given() {
        let _guard = ::habilis_network_test_tracing::init();
        let bare = LookupSet::choose(&[Lookup::Relay], None)
            .expect("a relay lookup with no ladder has a valid choice");
        assert_eq!(
            bare.relay_lookup,
            RelaySelection::Default,
            "naming relay takes the default ladder when none is given"
        );
        let ladder: RelayLadder = "https://a.example,https://b.example"
            .parse()
            .expect("the literal is a list of valid relay URLs");
        let custom = LookupSet::choose(&[Lookup::Relay], Some(ladder.clone()))
            .expect("the relay lookup with this ladder is a valid choice");
        assert_eq!(
            custom.relay_lookup,
            RelaySelection::Named(ladder),
            "naming relay with a ladder keeps the named ladder"
        );
    }

    #[test]
    fn a_ladder_without_the_relay_lookup_is_an_error() {
        let _guard = ::habilis_network_test_tracing::init();
        let ladder: RelayLadder = "https://a.example"
            .parse()
            .expect("the literal is a valid relay URL");
        let error = LookupSet::choose(&[Lookup::Mdns], Some(ladder))
            .expect_err("LookupSet::choose refuses the mDNS lookup when the relay ladder is set")
            .to_string();
        assert!(error.contains("relay"), "{error}");
    }

    #[test]
    fn an_empty_transport_list_and_udp_alone_keep_the_relay_off_payload() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            TransportPolicy::try_from(&[]).expect("an empty list is a valid transport policy"),
            TransportPolicy::default(),
            "an empty transport list keeps the relay off the payload path"
        );
        assert!(
            !TransportPolicy::try_from(&[Transport::Udp])
                .expect("the udp-only list is a valid transport policy")
                .allows(Transport::Relay),
            "udp alone keeps the relay off the payload path"
        );
        assert!(
            TransportPolicy::try_from(&[Transport::Udp, Transport::Relay])
                .expect("the udp and relay list is a valid transport policy")
                .allows(Transport::Relay),
            "a transport list with relay turns the relay on"
        );
    }

    #[test]
    fn udp_cannot_be_disabled() {
        let _guard = ::habilis_network_test_tracing::init();
        let error = TransportPolicy::try_from(&[Transport::Relay])
            .expect_err("TransportPolicy::try_from refuses a policy with the relay and no udp")
            .to_string();
        assert!(error.contains("udp"), "{error}");
    }

    #[test]
    fn a_config_resolves_from_the_three_choices() {
        let _guard = ::habilis_network_test_tracing::init();
        let config =
            MeshConfig::resolve(&[Lookup::Relay], None, &[Transport::Udp, Transport::Relay])
                .expect("the lookup and transport list in this test resolve to a valid config");
        assert!(
            config.transport.allows(Transport::Relay),
            "the three choices resolve to a relay transport"
        );
        assert_eq!(
            config.lookups.relay_lookup,
            RelayChoice::Pinned,
            "the three choices resolve to a pinned relay lookup"
        );
        assert!(
            config.password.is_none() && config.issuer_pubkey.is_none(),
            "the three choices leave the password and issuer unset"
        );

        let bare = MeshConfig::resolve(&[], None, &[])
            .expect("an empty lookup list with no transports resolves to the default config");
        assert!(bare.lookups.is_loopback(), "the bare config is loopback");
        assert!(
            !bare.transport.allows(Transport::Relay),
            "the bare config has the relay transport off"
        );
    }

    /// The relay's two roles are two lists, so the relay can serve lookup
    /// alone: named in `lookup` and not in `transport`, it is the rendezvous
    /// and carries no payload. That is also what an empty `transport` means.
    #[test]
    fn relay_can_be_a_lookup_and_nothing_more() {
        let _guard = ::habilis_network_test_tracing::init();
        for transports in [&[][..], &[Transport::Udp][..]] {
            let config = MeshConfig::resolve(&[Lookup::Relay], None, transports)
                .expect("the lookup and transport list in this test resolve to a valid config");
            assert_eq!(
                config.lookups.relay_lookup,
                RelayChoice::Pinned,
                "a relay can be a lookup and nothing more"
            );
            assert!(!config.transport.allows(Transport::Relay), "{transports:?}");
            assert_eq!(
                config,
                MeshConfig::try_from(config.to_bytes().as_slice())
                    .expect("the config was just encoded by to_bytes, so it decodes"),
                "the relay-only config survives a round trip"
            );
        }
    }

    #[test]
    fn relay_transport_needs_the_relay_lookup() {
        let _guard = ::habilis_network_test_tracing::init();
        let error = MeshConfig::resolve(&[Lookup::Mdns], None, &[Transport::Udp, Transport::Relay])
            .expect_err("MeshConfig::resolve refuses the relay transport without the relay lookup")
            .to_string();
        assert!(error.contains("relay"), "{error}");
    }

    #[test]
    fn no_lookups_is_loopback_without_a_preset_switch() {
        let _guard = ::habilis_network_test_tracing::init();
        let options = resolve_lookups(LookupSet::default());
        assert!(
            options.is_loopback(),
            "no lookups is loopback without a preset switch"
        );
        assert_eq!(
            options.network_label(),
            "private",
            "no lookups labels the network as private"
        );
    }
}
