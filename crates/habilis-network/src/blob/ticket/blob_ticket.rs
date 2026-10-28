use super::{KIND, PASSWORD_BIT, RELAY_TRANSPORT_BIT, VERSION};
use anyhow::{Context, Result, bail};
use iroh::EndpointAddr;

use crate::protocol::base58check::{self, take_array};
use crate::protocol::crypto::TicketSecret;
use crate::protocol::mesh::LookupOpts;
use crate::protocol::peer_addr_error::{endpoint_addr_from_json, endpoint_addr_to_json};
use crate::transport::PayloadPath;

use crate::blob::{BlobDigest, HASH_LEN, SECRET_LEN};

/// A decoded blob ticket.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BlobTicket {
    /// The endpoint address of the producer that serves the blob.
    pub addr: EndpointAddr,
    /// The bearer secret of the ticket.
    pub secret: TicketSecret,
    /// The SHA-256 of the blob.
    pub sha256: BlobDigest,
    /// The size of the blob, in bytes.
    pub size: u64,
    /// The lookups that find the producer's endpoint.
    pub lookups: LookupOpts,
    /// Password-protected: the consumer must present the Argon2id stretch of the
    /// password (salted by `secret`) in the stream header instead of the raw
    /// secret, so the ticket no longer redeems alone.
    pub password: bool,
    /// Whether the relay may carry the transfer (the producer mesh's
    /// `TransportPolicy::relay`). `false` ⇒ the consumer refuses to fetch over
    /// a relayed path, as the producer refuses to serve one.
    pub relay_transport: PayloadPath,
}

impl BlobTicket {
    /// Encode as a bare base58 blob ticket.
    #[must_use]
    /// # Panics
    /// Panics if an internal invariant is violated.
    pub fn encode(&self) -> String {
        let mut payload = Vec::with_capacity(SECRET_LEN + 1 + HASH_LEN + 8 + 64);
        payload.extend_from_slice(self.secret.as_bytes());
        let mut flags = 0u8;
        if self.password {
            flags |= PASSWORD_BIT;
        }
        if self.relay_transport.relay_allowed() {
            flags |= RELAY_TRANSPORT_BIT;
        }
        payload.push(flags);
        payload.extend_from_slice(self.sha256.as_bytes());
        payload.extend_from_slice(&self.size.to_le_bytes());
        self.lookups.encode_into(&mut payload);
        let addr_json = serde_json::to_vec(&endpoint_addr_to_json(&self.addr))
            .expect("EndpointAddr JSON always serializes");
        payload.extend_from_slice(&addr_json);
        let mut framed = Vec::with_capacity(2 + payload.len());
        framed.push(VERSION);
        framed.push(KIND);
        framed.extend_from_slice(&payload);
        base58check::encode(&framed)
    }

    /// The blob's content hash as lowercase hex — the content-addressed name to
    /// land the fetched bytes under, mirroring the producer's spool filename
    /// (`src/blob/store.rs`).
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256.to_string()
    }

    /// Decode a bare base58 blob ticket.
    ///
    /// # Errors
    /// Bad Base58/checksum, the wrong ticket kind, a bad version, or a
    /// malformed payload.
    pub fn decode(ticket: &str) -> Result<Self, crate::blob::BlobError> {
        Self::decode_checked(ticket).map_err(crate::blob::BlobError::internal)
    }

    fn decode_checked(ticket: &str) -> Result<Self> {
        let framed = base58check::decode(ticket.trim(), "blob ticket")?;
        let version = *framed.first().context("ticket too short")?;
        if version != VERSION {
            bail!("unsupported blob ticket version: {version}");
        }
        let kind = *framed.get(1).context("ticket too short")?;
        if kind != KIND {
            bail!("not a blob ticket: wrong ticket kind");
        }
        let payload = &framed[2..];
        let mut position = 0;
        let secret = TicketSecret::from_bytes(
            take_array::<SECRET_LEN>(payload, &mut position).context("ticket missing secret")?,
        );
        let flags = *payload.get(position).context("ticket missing flags")?;
        position += 1;
        let password = flags & PASSWORD_BIT != 0;
        let relay_transport = PayloadPath::from(flags & RELAY_TRANSPORT_BIT != 0);
        let sha256 = BlobDigest::from_bytes(
            take_array::<HASH_LEN>(payload, &mut position).context("ticket missing hash")?,
        );
        let size_bytes = take_array::<8>(payload, &mut position).context("ticket missing size")?;
        let size = u64::from_le_bytes(size_bytes);
        let lookups = LookupOpts::decode_from(payload, &mut position)?;
        let addr_json = payload.get(position..).context("ticket missing address")?;
        let value: serde_json::Value =
            serde_json::from_slice(addr_json).context("invalid ticket address json")?;
        let (_id, addr) = endpoint_addr_from_json(&value)?;
        Ok(Self {
            addr,
            secret,
            sha256,
            size,
            lookups,
            password,
            relay_transport,
        })
    }
}
