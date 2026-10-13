//! The resident memory that one WebRTC session costs the process that holds it.
//!
//! An underlay session and an application session are the same object: a session made by
//! `offer_with` and `answer_with`, and attached to a `WebRtcTransport`. This example measures
//! that object and nothing else: no endpoint, no relay, no gossip. Two processes hold the two
//! ends, so each reading counts exactly one end.
//!
//! ```text
//! session_cost measure --role offerer|answerer --k <sessions> [--settle 5] [--hold 60]
//! session_cost fit < lines-of-measure-output
//! ```
//!
//! The sessions are IDLE: no datagram crosses them and no QUIC connection rides on them, so the
//! slope is the idle floor of a session. The send path of the transport cannot be driven from
//! here (`Transmit` has no public constructor), so a reading under traffic needs real iroh
//! endpoints on top of the sessions, which this example does not do.
//!
//! `measure` starts a peer process (this binary, `peer`), opens one warm-up session, which stays open, to take
//! the start-up cost of the libraries out of the slope, reads the resident memory, opens `k`
//! sessions, reads it again after `settle` seconds, once more after `hold` seconds with the
//! sessions alive, and a last time after closing them. It prints one JSON line. `fit` reads
//! such lines and prints the slope per role, with its standard error and the noise floor
//! (the spread of the `k = 0` runs).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use habilis_network_iroh_webrtc_transport::iroh_base::{EndpointId, SecretKey};
use habilis_network_iroh_webrtc_transport::{
    IceConfig, SignalEnvelope, WebRtcTransport, answer_with, offer_with,
};
use habilis_network_util::resident_memory::current_resident_memory_bytes;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};

const JSEP_DEADLINE: Duration = Duration::from_secs(30);
const MIB: f64 = 1_048_576.0;

/// The median of a set of readings. The mean of the two middle ones if their number is even.
fn median(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[middle]
    } else {
        sorted[middle - 1].midpoint(sorted[middle])
    }
}

/// A least-squares line through `(x, y)` points.
#[derive(Debug, PartialEq)]
struct Fit {
    slope: f64,
    intercept: f64,
    /// The standard error of the slope, `None` with fewer than three points.
    slope_stderr: Option<f64>,
}

#[expect(clippy::cast_precision_loss, reason = "a handful of points")]
fn fit(points: &[(f64, f64)]) -> Option<Fit> {
    if points.len() < 2 {
        return None;
    }
    let count = points.len() as f64;
    let mean_x = points.iter().map(|&(px, _)| px).sum::<f64>() / count;
    let mean_y = points.iter().map(|&(_, py)| py).sum::<f64>() / count;
    let sxx: f64 = points.iter().map(|&(px, _)| (px - mean_x).powi(2)).sum();
    if sxx <= f64::EPSILON {
        return None;
    }
    let sxy: f64 = points
        .iter()
        .map(|&(px, py)| (px - mean_x) * (py - mean_y))
        .sum();
    let slope = sxy / sxx;
    let intercept = mean_y - slope * mean_x;
    let slope_stderr = (points.len() >= 3).then(|| {
        let sse: f64 = points
            .iter()
            .map(|&(px, py)| (py - (intercept + slope * px)).powi(2))
            .sum();
        (sse / (count - 2.0) / sxx).sqrt()
    });
    Some(Fit {
        slope,
        intercept,
        slope_stderr,
    })
}

/// The sample standard deviation, `None` with fewer than two values.
#[expect(clippy::cast_precision_loss, reason = "a handful of values")]
fn std_dev(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let count = values.len() as f64;
    let mean = values.iter().sum::<f64>() / count;
    let squares: f64 = values.iter().map(|value| (value - mean).powi(2)).sum();
    Some((squares / (count - 1.0)).sqrt())
}

/// A line on the pipe between the two processes.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum Msg {
    /// The measured process answers: the peer is to make an offer.
    Go,
    Offer {
        env: SignalEnvelope,
    },
    Answer {
        env: SignalEnvelope,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Offerer,
    Answerer,
}

async fn send(out: &mut ChildStdin, message: &Msg) -> anyhow::Result<()> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    out.write_all(&line).await?;
    out.flush().await?;
    Ok(())
}

type Lines = tokio::io::Lines<BufReader<ChildStdout>>;

async fn receive(lines: &mut Lines) -> anyhow::Result<Msg> {
    let line = lines
        .next_line()
        .await?
        .context("the peer closed the pipe")?;
    Ok(serde_json::from_str(&line)?)
}

/// Opens one session from the measured side and returns the id of the far end.
async fn open_one(
    role: Role,
    transport: &WebRtcTransport,
    local: EndpointId,
    to_peer: &mut ChildStdin,
    from_peer: &mut Lines,
) -> anyhow::Result<EndpointId> {
    let ice = IceConfig::host_only();
    match role {
        Role::Offerer => {
            let (pending, env) = offer_with(local, &ice).await?;
            send(to_peer, &Msg::Offer { env }).await?;
            let Msg::Answer { env: answer } = receive(from_peer).await? else {
                bail!("the peer did not answer");
            };
            let session = Box::pin(pending.complete(&answer, JSEP_DEADLINE)).await?;
            let remote = answer.claimed_endpoint()?;
            transport.attach(remote, session)?;
            Ok(remote)
        }
        Role::Answerer => {
            send(to_peer, &Msg::Go).await?;
            let Msg::Offer { env: offer } = receive(from_peer).await? else {
                bail!("the peer did not offer");
            };
            let (pending, env) = answer_with(local, &offer, &ice).await?;
            send(to_peer, &Msg::Answer { env }).await?;
            let session = Box::pin(pending.complete(JSEP_DEADLINE)).await?;
            let remote = offer.claimed_endpoint()?;
            transport.attach(remote, session)?;
            Ok(remote)
        }
    }
}

fn resident() -> u64 {
    current_resident_memory_bytes().unwrap_or(0)
}

/// Waits `settle` seconds, then the median of five readings one second apart.
async fn settled(settle: u64) -> u64 {
    tokio::time::sleep(Duration::from_secs(settle)).await;
    let mut readings = Vec::new();
    for _ in 0..5 {
        readings.push(resident());
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    median(&readings)
}

/// The load average of the last minute, `None` where it cannot be read.
fn load1() -> Option<f64> {
    if let Ok(text) = std::fs::read_to_string("/proc/loadavg") {
        return text.split_whitespace().next()?.parse().ok();
    }
    let output = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok()?;
    String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .find_map(|word| word.parse().ok())
}

async fn measure(role: Role, sessions: usize, settle: u64, hold: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        current_resident_memory_bytes().is_some(),
        "the resident memory of this process cannot be read on this platform"
    );
    let mut child = Command::new(std::env::current_exe()?)
        .arg("peer")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut to_peer = child.stdin.take().context("no stdin")?;
    let mut from_peer = BufReader::new(child.stdout.take().context("no stdout")?).lines();
    let local = SecretKey::generate().public();
    let transport = WebRtcTransport::new(local);

    // One warm-up session takes the start-up of the libraries out of the slope. It stays open: a
    // session that is closed gives back part of its memory late, after the baseline reading, and
    // that fell into the later readings (the K = 0 runs lost 0.5 to 1.0 MiB over the hold).
    let at_start = resident();
    let _warm = Box::pin(open_one(
        role,
        &transport,
        local,
        &mut to_peer,
        &mut from_peer,
    ))
    .await?;
    let before = settled(settle).await;

    let mut remotes = Vec::with_capacity(sessions);
    for _ in 0..sessions {
        remotes.push(
            Box::pin(open_one(
                role,
                &transport,
                local,
                &mut to_peer,
                &mut from_peer,
            ))
            .await?,
        );
    }
    anyhow::ensure!(
        transport.session_count() == sessions + 1,
        "{} sessions are live, not {} (the warm-up session and {sessions})",
        transport.session_count(),
        sessions + 1
    );
    let after_open = settled(settle).await;
    let after_hold = if hold > 0 {
        settled(hold).await
    } else {
        after_open
    };
    for remote in &remotes {
        transport.detach(remote);
    }
    let after_close = settled(settle).await;

    println!(
        "{}",
        serde_json::json!({
            "role": if role == Role::Offerer { "offerer" } else { "answerer" },
            "k": sessions,
            "at_start": at_start,
            "r0": before,
            "rk": after_open,
            "rk_hold": after_hold,
            "r_close": after_close,
            "load1": load1(),
            "settle": settle,
            "hold": hold,
        })
    );
    Ok(())
}

/// The peer: answers or offers on request, with a fresh endpoint id for every session, and
/// keeps its end of every session open until its stdin closes.
async fn run_peer() -> anyhow::Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    let mut held: Vec<Arc<WebRtcTransport>> = Vec::new();
    let ice = IceConfig::host_only();
    while let Some(line) = lines.next_line().await? {
        let id = SecretKey::generate().public();
        let transport = WebRtcTransport::new(id);
        match serde_json::from_str::<Msg>(&line)? {
            Msg::Offer { env: offer } => {
                let (pending, env) = answer_with(id, &offer, &ice).await?;
                reply(&mut out, &Msg::Answer { env }).await?;
                let session = Box::pin(pending.complete(JSEP_DEADLINE)).await?;
                transport.attach(offer.claimed_endpoint()?, session)?;
            }
            Msg::Go => {
                let (pending, env) = offer_with(id, &ice).await?;
                reply(&mut out, &Msg::Offer { env }).await?;
                let reply_line = lines.next_line().await?.context("no answer")?;
                let Msg::Answer { env: answer } = serde_json::from_str(&reply_line)? else {
                    bail!("expected an answer");
                };
                let session = Box::pin(pending.complete(&answer, JSEP_DEADLINE)).await?;
                transport.attach(answer.claimed_endpoint()?, session)?;
            }
            Msg::Answer { .. } => bail!("an answer out of turn"),
        }
        held.push(transport);
    }
    Ok(())
}

async fn reply(out: &mut tokio::io::Stdout, message: &Msg) -> anyhow::Result<()> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    out.write_all(&line).await?;
    out.flush().await?;
    Ok(())
}

/// A number of a JSON row, `None` if the field is missing or is not a number.
fn field(row: &serde_json::Value, name: &str) -> Option<f64> {
    row[name].as_f64()
}

/// Reads the lines of `measure` from stdin and prints the slope per role and per reading.
fn run_fit() -> anyhow::Result<()> {
    let mut rows: Vec<serde_json::Value> = Vec::new();
    for line in std::io::stdin().lines() {
        let line = line?;
        if line.trim_start().starts_with('{') {
            rows.push(serde_json::from_str(&line)?);
        }
    }
    println!("cost of an IDLE session: no traffic, no QUIC connection on top (the idle floor)");
    for role in ["offerer", "answerer"] {
        let of_role: Vec<&serde_json::Value> =
            rows.iter().filter(|row| row["role"] == role).collect();
        if of_role.is_empty() {
            continue;
        }
        println!("{role}: {} runs", of_role.len());
        let mut effect = None;
        for (name, label) in [
            ("rk", "after open"),
            ("rk_hold", "after hold"),
            ("r_close", "after close"),
        ] {
            let mut skipped = 0_usize;
            let mut points: Vec<(f64, f64)> = Vec::new();
            for row in &of_role {
                match (field(row, "k"), field(row, "r0"), field(row, name)) {
                    (Some(count), Some(before), Some(after)) => {
                        points.push((count, (after - before) / MIB));
                    }
                    _ => skipped += 1,
                }
            }
            let note = if skipped > 0 {
                format!(" ({skipped} rows skipped: a field is missing)")
            } else {
                String::new()
            };
            match fit(&points) {
                Some(line) => {
                    println!(
                        "  {label:11}: {:+.3} MiB per session, standard error {}, intercept {:+.2} MiB{note}",
                        line.slope,
                        line.slope_stderr
                            .map_or_else(|| "n/a".to_owned(), |error| format!("{error:.3}")),
                        line.intercept
                    );
                    if name == "rk" {
                        effect = Some((line.slope, line.slope_stderr));
                    }
                }
                None => println!("  {label:11}: no fit (needs two different values of k){note}"),
            }
        }
        let noise: Vec<f64> = of_role
            .iter()
            .filter(|row| field(row, "k") == Some(0.0))
            .filter_map(|row| Some((field(row, "rk")? - field(row, "r0")?) / MIB))
            .collect();
        let floor = std_dev(&noise);
        println!(
            "  noise floor (spread of the k = 0 runs, {} runs): {} MiB",
            noise.len(),
            floor.map_or_else(|| "n/a".to_owned(), |value| format!("{value:.3}"))
        );
        println!("  verdict: {}", verdict(floor, effect));
    }
    Ok(())
}

/// A number only if the slope is positive, and the noise floor and the standard error of the
/// slope are both below 10 percent of what they are measured against.
fn verdict(floor: Option<f64>, effect: Option<(f64, Option<f64>)>) -> &'static str {
    match (floor, effect) {
        (Some(floor), Some((slope, Some(error))))
            if slope > 0.0 && floor < 0.10 * slope * 32.0 && error < 0.10 * slope =>
        {
            "a result: the noise floor is below 10 percent of the effect at k = 32 and the standard error is below 10 percent of the slope"
        }
        _ => {
            "NO RESULT: the noise floor must be below 10 percent of the effect at k = 32 AND the standard error below 10 percent of the slope"
        }
    }
}

fn argument(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("peer") => Box::pin(run_peer()).await,
        Some("fit") => run_fit(),
        Some("measure") => {
            let role = match argument(&args, "--role").as_deref() {
                Some("offerer") => Role::Offerer,
                Some("answerer") => Role::Answerer,
                _ => bail!("--role offerer|answerer"),
            };
            let sessions = argument(&args, "--k").context("--k")?.parse()?;
            let settle = argument(&args, "--settle").map_or(Ok(5), |value| value.parse())?;
            let hold = argument(&args, "--hold").map_or(Ok(60), |value| value.parse())?;
            measure(role, sessions, settle, hold).await
        }
        _ => bail!(
            "usage: session_cost measure --role offerer|answerer --k N [--settle S] [--hold H] | fit | peer"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{fit, median, std_dev, verdict};

    #[test]
    fn the_median_of_an_odd_set_is_its_middle_value() {
        assert_eq!(median(&[9, 1, 5]), 5);
    }

    #[test]
    fn the_median_of_an_even_set_is_the_mean_of_the_two_middle_values() {
        assert_eq!(median(&[10, 2, 8, 4]), 6);
    }

    #[test]
    fn the_median_of_nothing_is_zero() {
        assert_eq!(median(&[]), 0);
    }

    #[test]
    fn a_fit_through_points_on_a_line_finds_its_slope_and_intercept() {
        let points: Vec<(f64, f64)> = [0.0, 1.0, 8.0, 32.0]
            .iter()
            .map(|x| (*x, 3.0 + 0.25 * x))
            .collect();
        let line = fit(&points).expect("a line");
        assert!((line.slope - 0.25).abs() < 1e-9, "{line:?}");
        assert!((line.intercept - 3.0).abs() < 1e-9, "{line:?}");
        assert!(line.slope_stderr.expect("a stderr") < 1e-9);
    }

    #[test]
    fn a_fit_with_noise_reports_a_standard_error_that_grows_with_the_noise() {
        let quiet = [(0.0, 0.0), (1.0, 1.1), (8.0, 7.9), (32.0, 32.2)];
        let loud = [(0.0, 5.0), (1.0, -4.0), (8.0, 14.0), (32.0, 25.0)];
        let quiet_error = fit(&quiet)
            .and_then(|line| line.slope_stderr)
            .expect("quiet");
        let loud_error = fit(&loud).and_then(|line| line.slope_stderr).expect("loud");
        assert!(
            loud_error > 10.0 * quiet_error,
            "{quiet_error} against {loud_error}"
        );
    }

    #[test]
    fn a_fit_needs_two_different_x_values() {
        assert_eq!(fit(&[(3.0, 1.0), (3.0, 2.0)]), None);
        assert_eq!(fit(&[(3.0, 1.0)]), None);
    }

    #[test]
    fn the_standard_deviation_is_the_sample_one() {
        let spread = std_dev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]).expect("a spread");
        assert!((spread - 2.138_089_935).abs() < 1e-6, "{spread}");
        assert_eq!(std_dev(&[1.0]), None);
    }

    #[test]
    fn a_verdict_needs_both_the_noise_floor_and_the_standard_error_to_be_small() {
        // The effect at k = 32 is 6.4 MiB (slope 0.2). A floor of 0.5 and an error of 0.01 pass.
        assert!(verdict(Some(0.5), Some((0.2, Some(0.01)))).starts_with("a result"));
        // A floor of 1.0 is over 10 percent of 6.4.
        assert!(verdict(Some(1.0), Some((0.2, Some(0.01)))).starts_with("NO RESULT"));
        // An error of 0.05 is over 10 percent of the slope.
        assert!(verdict(Some(0.5), Some((0.2, Some(0.05)))).starts_with("NO RESULT"));
        // Nothing to compare: no result.
        assert!(verdict(None, Some((0.2, Some(0.01)))).starts_with("NO RESULT"));
        assert!(verdict(Some(0.5), Some((0.2, None))).starts_with("NO RESULT"));
        assert!(verdict(Some(0.5), None).starts_with("NO RESULT"));
    }

    #[test]
    fn a_negative_slope_is_never_a_result() {
        // A session that frees memory is a flaw of the run, not a cost, however small the noise.
        assert!(verdict(Some(0.5), Some((-0.2, Some(0.01)))).starts_with("NO RESULT"));
        assert!(verdict(Some(0.0), Some((0.0, Some(0.0)))).starts_with("NO RESULT"));
    }
}
