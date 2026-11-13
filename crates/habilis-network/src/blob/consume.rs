//! The blob consumer: redeem a bare base58 ticket by dialing the producer's blob
//! endpoint, presenting the bearer secret, and streaming the content-addressed
//! bytes to a writer while verifying them against the ticket's SHA-256. Constant
//! memory — nothing is buffered whole. Standalone: it builds its own peer
//! endpoint and never touches the daemon.

use std::time::{Duration, Instant};

use std::error::Error;
use std::fmt;
use std::future::Future;

use anyhow::{Result, anyhow, bail};
use iroh::Endpoint;
use iroh::endpoint::Connection;
use sha2::Sha256;
use tokio::io::AsyncWrite;

use crate::lookup::{add_peer_addr, address_book, build_peer_endpoint};
use crate::protocol::crypto::{Password, TicketAuth, TicketSecret};
use crate::util::consts::MAX_BLOB_BYTES;

use super::close_on_drop::CloseOnDrop;
use super::dialed::Dialed;
use super::error::BlobError;
use super::ticket::BlobTicket;
use super::{BLOB_ALPN, HASH_LEN, SECRET_LEN};

use crate::transport;
use tokio::time;
/// How long the first dial keeps retrying while the producer's address
/// propagates through the lookups (mirrors the application's bridge ticket).
const DISCOVERY_DEADLINE: Duration = Duration::from_secs(90);
const RETRY_DELAY: Duration = Duration::from_secs(3);
/// How long a dial waits alone for the handshake before a second dial starts from a new endpoint.
/// A handshake takes milliseconds, so a dial with no reply after 2 s is already abnormal. On a LAN
/// the reply flight of the producer to one consumer socket is sometimes dropped for 30 s or more,
/// while a new socket gets through at once. The second dial costs nothing in the good case: it is
/// bound only after this delay.
pub(super) const HEDGE_DELAY: Duration = Duration::from_secs(2);
/// How long each dial attempt waits for the handshake. A handshake takes milliseconds. On a LAN
/// with two interfaces, the reply flight of the producer to one endpoint is sometimes lost for
/// good, and iroh waits 30 s before it gives up on the attempt. A slow link needs more than 5 s,
/// so each attempt waits longer than the one before, and the last cap repeats.
pub(super) const DIAL_CAPS: Caps = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(20),
];
type Caps = [Duration; 3];

/// The cap of attempt number `attempt`, counted from 0.
pub(super) fn cap_of(caps: &Caps, attempt: usize) -> Duration {
    caps[attempt.min(caps.len() - 1)]
}

/// A dial attempt that got no handshake within its cap. The wait was the delay, so the retry
/// follows at once.
#[derive(Debug)]
struct Stalled(Duration);

impl fmt::Display for Stalled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "no handshake within {:?}", self.0)
    }
}

impl Error for Stalled {}
const CHUNK: usize = 64 * 1024;

/// Fetch the blob named by `ticket`, streaming its bytes to `out` and verifying
/// the SHA-256 as they arrive. On a hash mismatch this returns an error *after*
/// bytes have already been written — the caller (e.g. a `fetch` command) must
/// treat a non-zero result as "discard what landed".
///
/// # Errors
/// A password mismatch with the ticket, dial/handshake failure, the producer
/// refusing (bad secret / unknown blob), a size disagreement, a truncated
/// stream, or a final digest that does not match the ticket.
///
/// # Examples
///
/// It fetches a blob from its ticket and writes its bytes to the output. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::blob::{BlobTicket, fetch};
/// use tokio::io::AsyncWrite;
///
/// # async fn demo<Writer: AsyncWrite + Unpin>(ticket: &BlobTicket, out: &mut Writer) {
/// let _ = fetch(ticket, out, None).await;
/// # }
/// ```
pub async fn fetch<Writer>(
    ticket: &BlobTicket,
    out: &mut Writer,
    password: Option<Password>,
) -> Result<(), BlobError>
where
    Writer: AsyncWrite + Unpin,
{
    let token = auth_token(ticket, password.as_ref())?;
    // `fetch` owns its endpoints, so a stall is not for the caller to act on.
    fetch_with_token(ticket, out, &token)
        .await
        .map_err(BlobError::internal)
}

/// [`fetch`] over an endpoint the caller already holds, so a caller that fetches
/// often does not bind a cold endpoint for each blob. The endpoint is left open:
/// the caller owns it and closes it.
///
/// `ticket.lookups` is not applied to the endpoint. Build it with
/// `habilis_network::net::build_peer_endpoint(&ticket.lookups)`, or with the same
/// relay ladder as the producer, so that both sides can reach a common relay. The
/// dial carries the ticket address, so this adds nothing to the lookup services of
/// the endpoint. An endpoint with no lookup services reaches only the exact ticket
/// address: it does not resolve the producer again if that address changes.
///
/// # Errors
/// The same as [`fetch`].
///
/// # Examples
///
/// It fetches a blob over an endpoint that the caller keeps. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::iroh::Endpoint;
/// use habilis_network::ops::blob::{BlobTicket, fetch_with_endpoint};
/// use tokio::io::AsyncWrite;
///
/// # async fn demo<Writer: AsyncWrite + Unpin>(endpoint: &Endpoint, ticket: &BlobTicket, out: &mut Writer) {
/// let _ = fetch_with_endpoint(endpoint, ticket, out, None).await;
/// # }
/// ```
pub async fn fetch_with_endpoint<Writer>(
    endpoint: &Endpoint,
    ticket: &BlobTicket,
    out: &mut Writer,
    password: Option<Password>,
) -> Result<(), BlobError>
where
    Writer: AsyncWrite + Unpin,
{
    fetch_with_endpoint_caps(endpoint, ticket, out, password, &DIAL_CAPS).await
}

/// [`fetch_with_endpoint`] that does not wait out a dial the producer cannot answer. A dial
/// with no handshake after `HEDGE_DELAY` is hedged: `build` binds one more endpoint, the fetch
/// dials from it too, and the first dial to connect wins. The loser is cancelled, and the
/// endpoint that `build` bound is closed. A handshake that completes in time binds nothing.
///
/// `build` must return the endpoint as its last step: the fetch cancels a build that is still
/// running when the first dial connects, and a cancelled build drops an endpoint it bound but did
/// not return, which iroh logs as an error. The error of `build` must implement `std::error::Error`,
/// so a builder that returns `anyhow::Error` maps it first. A build that fails or is slow costs the
/// hedge only: the first dial keeps waiting until its cap.
///
/// The endpoint of the caller is only dialed from and never closed. If every attempt stalls, this
/// returns [`BlobError::HandshakeStalled`], as [`fetch_with_endpoint`] does, and the caller builds
/// a new endpoint.
///
/// # Errors
/// The same as [`fetch_with_endpoint`]. An error of `build` is not an error of the fetch: it
/// drops the hedge, and the fetch goes on with the first dial.
///
/// # Examples
///
/// It fetches a blob over the endpoint of the caller, and binds a second one for a stalled dial.
/// The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::iroh::Endpoint;
/// use habilis_network::net::build_peer_endpoint;
/// use habilis_network::ops::blob::{BlobTicket, fetch_hedged};
/// use tokio::io::AsyncWrite;
///
/// # async fn demo<Writer: AsyncWrite + Unpin>(endpoint: &Endpoint, ticket: &BlobTicket, out: &mut Writer) {
/// let build = || build_peer_endpoint(&ticket.lookups);
/// let _ = fetch_hedged(endpoint, build, ticket, out, None).await;
/// # }
/// ```
pub async fn fetch_hedged<Writer, Build, Built, BuildError>(
    endpoint: &Endpoint,
    build: Build,
    ticket: &BlobTicket,
    out: &mut Writer,
    password: Option<Password>,
) -> Result<(), BlobError>
where
    Writer: AsyncWrite + Unpin,
    Build: Fn() -> Built,
    Built: Future<Output = Result<Endpoint, BuildError>>,
    BuildError: Error + Send + Sync + 'static,
{
    fetch_hedged_caps(
        endpoint,
        build,
        ticket,
        out,
        password,
        &DIAL_CAPS,
        Some(HEDGE_DELAY),
    )
    .await
}

/// [`fetch_hedged`] with the caps and the hedge delay as parameters, so that a test does not wait
/// for the real ones.
pub(super) async fn fetch_hedged_caps<Writer, Build, Built, BuildError>(
    endpoint: &Endpoint,
    build: Build,
    ticket: &BlobTicket,
    out: &mut Writer,
    password: Option<Password>,
    caps: &Caps,
    hedge: Option<Duration>,
) -> Result<(), BlobError>
where
    Writer: AsyncWrite + Unpin,
    Build: Fn() -> Built,
    Built: Future<Output = Result<Endpoint, BuildError>>,
    BuildError: Error + Send + Sync + 'static,
{
    let token = auth_token(ticket, password.as_ref())?;
    let build = || async { Ok(build().await?) };
    fetch_over(endpoint, ticket, &token, out, caps, hedge, &build)
        .await
        .map_err(blob_error)
}

/// [`fetch_with_endpoint`] with the caps of the dial attempts as a parameter, so that a test does
/// not wait for the real ones.
pub(super) async fn fetch_with_endpoint_caps<Writer>(
    endpoint: &Endpoint,
    ticket: &BlobTicket,
    out: &mut Writer,
    password: Option<Password>,
    caps: &Caps,
) -> Result<(), BlobError>
where
    Writer: AsyncWrite + Unpin,
{
    let token = auth_token(ticket, password.as_ref())?;
    fetch_over(
        endpoint,
        ticket,
        &token,
        out,
        caps,
        None,
        &no_endpoint_to_build,
    )
    .await
    .map_err(blob_error)
}

/// The builder of a fetch that never hedges.
async fn no_endpoint_to_build() -> Result<Endpoint> {
    bail!("this fetch has no builder for a second endpoint")
}

/// Whether an error is a dial attempt that got no handshake within its cap.
fn is_stalled(error: &anyhow::Error) -> bool {
    let stalled: Option<&Stalled> = error.downcast_ref();
    stalled.is_some()
}

/// A stalled handshake is a cause the caller acts on, so it keeps its own variant.
fn blob_error(error: anyhow::Error) -> BlobError {
    if is_stalled(&error) {
        BlobError::HandshakeStalled
    } else {
        BlobError::internal(error)
    }
}

async fn fetch_with_token<Writer>(
    ticket: &BlobTicket,
    out: &mut Writer,
    token: &TicketSecret,
) -> Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    let build = || async { Ok(build_peer_endpoint(&ticket.lookups).await?) };
    fetch_building(ticket, out, token, &DIAL_CAPS, Some(HEDGE_DELAY), build).await
}

/// [`fetch_with_token`] with the endpoint builder as a parameter, so that a test sees the
/// endpoints it binds. Every attempt binds a new endpoint: a retry from the endpoint that
/// stalled stalls again.
pub(super) async fn fetch_building<Writer, Build, Built>(
    ticket: &BlobTicket,
    out: &mut Writer,
    token: &TicketSecret,
    caps: &Caps,
    hedge: Option<Duration>,
    build: Build,
) -> Result<()>
where
    Writer: AsyncWrite + Unpin,
    Build: Fn() -> Built,
    Built: Future<Output = Result<Endpoint>>,
{
    let started = Instant::now();
    let mut attempt = 0;
    let (endpoint, dialed) = loop {
        let endpoint = CloseOnDrop::new(build().await?);
        add_peer_addr(&address_book(&endpoint.endpoint), ticket.address.clone());
        match dial_once(
            &endpoint.endpoint,
            ticket,
            cap_of(caps, attempt),
            hedge,
            &build,
        )
        .await
        {
            Ok(dialed) => break (endpoint, dialed),
            Err(error) => {
                endpoint.close().await;
                if started.elapsed() >= DISCOVERY_DEADLINE {
                    if is_stalled(&error) {
                        return Err(error);
                    }
                    bail!("connecting to the blob producer failed: {error}");
                }
                tracing::debug!(target: "habilis_network::blob", %error, "blob dial retrying on a new endpoint");
                if !is_stalled(&error) {
                    time::sleep(RETRY_DELAY).await;
                }
                attempt += 1;
            }
        }
    };
    let result = transfer(&dialed.connection, ticket, token, out).await;
    dialed.close().await;
    endpoint.close().await;
    result
}

async fn fetch_over<Writer, Build, Built>(
    endpoint: &Endpoint,
    ticket: &BlobTicket,
    token: &TicketSecret,
    out: &mut Writer,
    caps: &Caps,
    hedge: Option<Duration>,
    build: &Build,
) -> Result<()>
where
    Writer: AsyncWrite + Unpin,
    Build: Fn() -> Built,
    Built: Future<Output = Result<Endpoint>>,
{
    let dialed = dial(endpoint, ticket, caps, hedge, build).await?;
    let result = transfer(&dialed.connection, ticket, token, out).await;
    dialed.close().await;
    result
}

/// The transfer, with the cause of a failure in the log. The error that a caller sees says only
/// "connection lost". The close reason says who ended the connection and why.
async fn transfer<Writer>(
    connection: &Connection,
    ticket: &BlobTicket,
    token: &TicketSecret,
    out: &mut Writer,
) -> Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    let result = transfer_stream(connection, ticket, token, out).await;
    if let Err(error) = &result {
        let cause = format!("{error:#}");
        tracing::debug!(target: "habilis_network::blob", %cause, close = ?connection.close_reason(), "blob transfer failed");
    }
    result
}

async fn transfer_stream<Writer>(
    connection: &Connection,
    ticket: &BlobTicket,
    token: &TicketSecret,
    out: &mut Writer,
) -> Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    use sha2::Digest;
    use tokio::io::AsyncWriteExt as _;
    // A fresh connection to a peer behind NAT starts on the relay and punches
    // inside it, so this waits rather than refusing at once. The producer
    // waits too; refusing here first spares the round trip and names the
    // cause.
    transport::refuse_relayed(
        connection,
        ticket.relay_transport,
        transport::PROBE_DEADLINE,
        super::RELAY_REFUSED_CODE,
    )
    .await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    // Request: sha256 ‖ secret, then done sending.
    send.write_all(ticket.sha256.as_bytes()).await?;
    send.write_all(token.as_bytes()).await?;
    let _ = send.finish();

    // Response: size(u64) ‖ <size bytes>. A refusal closes the connection with a
    // coded reason before the size arrives.
    let mut size_buf = [0u8; 8];
    if recv.read_exact(&mut size_buf).await.is_err() {
        return Err(refusal(connection));
    }
    let size = u64::from_le_bytes(size_buf);
    if size != ticket.size {
        bail!(
            "producer offered {size} bytes but the ticket promises {}",
            ticket.size
        );
    }
    if size > MAX_BLOB_BYTES {
        bail!("blob size {size} exceeds the maximum");
    }

    let mut hasher = Sha256::new();
    let mut remaining = size;
    let mut buffer = vec![0u8; CHUNK];
    while remaining > 0 {
        let capacity = buffer.len();
        let want = usize::try_from(remaining.min(capacity as u64)).unwrap_or(capacity);
        let read = match recv.read(&mut buffer[..want]).await? {
            Some(read) if read > 0 => read,
            _ => bail!("blob stream ended {remaining} bytes early"),
        };
        hasher.update(&buffer[..read]);
        out.write_all(&buffer[..read]).await?;
        remaining -= read as u64;
    }
    out.flush().await?;

    let digest = hasher.finalize();
    if digest.as_slice() != ticket.sha256.as_bytes() {
        bail!("content hash mismatch — the fetched bytes are not what the ticket promised");
    }
    Ok(())
}

/// The 32-byte auth token opening the fetch stream: the raw secret, or its
/// Argon2id stretch when the ticket is password-protected.
fn auth_token(ticket: &BlobTicket, password: Option<&Password>) -> Result<TicketSecret, BlobError> {
    match (ticket.password, password) {
        (true, Some(pw)) => Ok(TicketAuth::blob(&ticket.secret, Some(pw)).token),
        (true, None) => Err(BlobError::PasswordRequired),
        (false, Some(_)) => Err(BlobError::PasswordNotNeeded),
        (false, None) => Ok(ticket.secret.clone()),
    }
}

/// Dial the producer's blob endpoint, retrying until [`DISCOVERY_DEADLINE`] so a
/// producer whose address is still propagating is waited for, not failed on. A retry from the
/// endpoint that stalled can stall again, and the caller owns the endpoint: after one attempt of
/// each cap, all stalled, this returns the stall and the caller decides. A stall does not check the
/// deadline: after it, at most 2 more attempts run, 20 s each.
async fn dial<Build, Built>(
    endpoint: &Endpoint,
    ticket: &BlobTicket,
    caps: &Caps,
    hedge: Option<Duration>,
    build: &Build,
) -> Result<Dialed>
where
    Build: Fn() -> Built,
    Built: Future<Output = Result<Endpoint>>,
{
    let started = Instant::now();
    let mut attempt = 0;
    let mut stalls = 0;
    loop {
        match dial_once(endpoint, ticket, cap_of(caps, attempt), hedge, build).await {
            Ok(dialed) => return Ok(dialed),
            Err(error) if is_stalled(&error) => {
                stalls += 1;
                if stalls >= caps.len() {
                    return Err(error);
                }
                tracing::debug!(%error, "blob dial retrying after a stalled handshake");
                attempt += 1;
            }
            Err(error) if started.elapsed() < DISCOVERY_DEADLINE => {
                tracing::debug!(%error, "blob dial retrying while the address propagates");
                stalls = 0;
                time::sleep(RETRY_DELAY).await;
                attempt += 1;
            }
            Err(error) => bail!("connecting to the blob producer failed: {error}"),
        }
    }
}

async fn connect(endpoint: &Endpoint, ticket: &BlobTicket) -> Result<Connection> {
    Ok(endpoint.connect(ticket.address.clone(), BLOB_ALPN).await?)
}

/// One dial attempt, cut off after `cap`. With `hedge`, a dial with no handshake after that delay
/// binds a new endpoint with `build` and dials from it too. The first dial to connect wins, and
/// the other is dropped: a dropped `CloseOnDrop` closes its endpoint.
pub(super) async fn dial_once<Build, Built>(
    endpoint: &Endpoint,
    ticket: &BlobTicket,
    cap: Duration,
    hedge: Option<Duration>,
    build: &Build,
) -> Result<Dialed>
where
    Build: Fn() -> Built,
    Built: Future<Output = Result<Endpoint>>,
{
    let deadline = time::sleep(cap);
    tokio::pin!(deadline);
    let first = connect(endpoint, ticket);
    tokio::pin!(first);
    let Some(delay) = hedge.filter(|delay| *delay < cap) else {
        return tokio::select! {
            biased;
            connected = &mut first => Ok(Dialed { connection: connected?, hedge: None }),
            () = &mut deadline => Err(Stalled(cap).into()),
        };
    };
    tokio::select! {
        biased;
        connected = &mut first => return Ok(Dialed { connection: connected?, hedge: None }),
        () = &mut deadline => return Err(Stalled(cap).into()),
        () = time::sleep(delay) => {}
    }
    tracing::debug!(target: "habilis_network::blob", after = ?delay, "hedge started: no handshake yet, dialing from a new endpoint");
    // The cap applies while the second endpoint builds: a slow builder must not hold the dial.
    let second_build = tokio::select! {
        biased;
        connected = &mut first => return Ok(Dialed { connection: connected?, hedge: None }),
        () = &mut deadline => return Err(Stalled(cap).into()),
        result = build() => result,
    };
    let second = match second_build {
        Ok(fresh) => CloseOnDrop::new(fresh),
        Err(error) => {
            // No hedge for this attempt: the first dial keeps its chance until the cap.
            tracing::debug!(target: "habilis_network::blob", %error, "no hedge: the second endpoint did not build");
            return tokio::select! {
                biased;
                connected = &mut first => Ok(Dialed { connection: connected?, hedge: None }),
                () = &mut deadline => Err(Stalled(cap).into()),
            };
        }
    };
    add_peer_addr(&address_book(&second.endpoint), ticket.address.clone());
    // The dial borrows the endpoint of the hedge, so it ends before the endpoint moves.
    let outcome = {
        let second_dial = connect(&second.endpoint, ticket);
        tokio::pin!(second_dial);
        tokio::select! {
            biased;
            connected = &mut first => match connected {
                Ok(connection) => Outcome::First(connection),
                // A fresh socket is the point of the hedge: it keeps its chance until the cap.
                Err(error) => tokio::select! {
                    biased;
                    hedged = &mut second_dial => hedged.map_or(Outcome::Failed(error), Outcome::Hedge),
                    // Neither dial got a handshake by the cap: that is a stall, whatever the first error was.
                    () = &mut deadline => {
                        tracing::debug!(target: "habilis_network::blob", %error, "the first dial failed and the hedge got no handshake by the cap");
                        Outcome::Deadline
                    }
                },
            },
            connected = &mut second_dial => match connected {
                Ok(connection) => Outcome::Hedge(connection),
                Err(error) => {
                    tracing::debug!(target: "habilis_network::blob", %error, "the hedge dial failed; the first dial keeps waiting");
                    tokio::select! {
                        biased;
                        retried = &mut first => retried.map_or_else(Outcome::Failed, Outcome::First),
                        () = &mut deadline => Outcome::Deadline,
                    }
                }
            },
            () = &mut deadline => Outcome::Deadline,
        }
    };
    match outcome {
        Outcome::First(connection) => Ok(Dialed {
            connection,
            hedge: None,
        }),
        Outcome::Hedge(connection) => {
            tracing::debug!(target: "habilis_network::blob", "the hedge connected first");
            Ok(Dialed {
                connection,
                hedge: Some(second),
            })
        }
        Outcome::Failed(error) => Err(error),
        Outcome::Deadline => Err(Stalled(cap).into()),
    }
}

/// How a hedged attempt ended.
enum Outcome {
    First(Connection),
    Hedge(Connection),
    Failed(anyhow::Error),
    Deadline,
}

/// Turn a producer-side connection close into a readable error — the coded
/// close (`bad secret` / `unknown blob`) is surfaced to the user.
fn refusal(connection: &Connection) -> anyhow::Error {
    match connection.close_reason() {
        Some(reason) => anyhow!("the blob producer refused the fetch: {reason}"),
        None => anyhow!("the blob fetch ended before any data arrived"),
    }
}

/// Assert at compile time that the request header the producer reads
/// (`HASH_LEN + SECRET_LEN`) matches what this side writes.
const _: () = assert!(
    HASH_LEN + SECRET_LEN == 64,
    "the hash and the secret fill exactly 64 bytes"
);
