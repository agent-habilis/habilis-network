//! A terminal chat on a habilis-network mesh — the chat example's native half
//! (`examples/chat/` holds the browser half and the README).
//!
//! ```text
//! cargo run -p chat -- --topic room
//! cargo run -p chat -- --topic room --nick ana --relay-url http://127.0.0.1:3340/
//! cargo run -p chat -- --topic room --transport udp,webrtc,relay
//! cargo run -p chat -- --lookup relay,pkarr --pkarr-url https://pkarr.example/pkarr   # create; share the printed id
//! ```
//!
//! Type to broadcast; `/msg <nick> <text>` sends directed; `/peers` prints
//! the roster; `/quit` leaves. `--robot` swaps the prose for one JSON object
//! per line — the engine's own events pass through verbatim, messages become
//! `{"kind":"msg",...}` — which is what `cargo task e2e --suite chat`
//! reads. Tracing goes to stderr either way, so stdout *is* the chat.

use anyhow::{Context as _, Result, bail};
use habilis_network::membership::{
    Inbound, Membership, Opts, Request, depart, join, json_sink, msg_body, parse_to,
};
use tokio::sync::oneshot;

struct Args {
    opts: Opts,
    robot: bool,
}

fn parse_args() -> Result<Args> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(args: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut opts = Opts::default();
    let mut robot = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().with_context(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--topic" => opts.topic = Some(value("--topic")?),
            "--mesh" => opts.mesh = Some(value("--mesh")?),
            "--nick" => opts.nick = Some(value("--nick")?),
            // `--relay-url`, not `--relay`: which relay, nothing about its
            // role. Spelled as the bun-ffi client spells it.
            "--relay-url" => opts.relay_urls.push(value("--relay-url")?),
            // Which pkarr relays, instead of the default list. Repeatable.
            // A create-only choice, like the browser and bun-ffi surfaces: a
            // topic always uses the default list, so a tab and a terminal
            // derive the same mesh from the same string.
            "--pkarr-url" => opts.pkarr_urls.push(value("--pkarr-url")?),
            // How a created mesh's members find each other; a topic always
            // uses all four and an id carries its own.
            "--lookup" => {
                opts.lookup = value("--lookup")?
                    .split(',')
                    .filter(|name| !name.is_empty())
                    .map(|name| name.parse().map_err(|error| anyhow::anyhow!("{error}")))
                    .collect::<Result<_>>()?;
            }
            "--transport" => {
                opts.transport = value("--transport")?
                    .split(',')
                    .map(|name| name.parse().map_err(|error| anyhow::anyhow!("{error}")))
                    .collect::<Result<_>>()?;
            }
            "--robot" => robot = true,
            other => bail!(
                "unknown argument {other}\nusage: chat --topic <t> | --mesh <id> \
                 [--nick <n>] [--relay-url <url>]... [--pkarr-url <url>]... \
                 [--lookup mdns,dht,relay,pkarr] [--transport udp,webrtc,relay] [--robot]"
            ),
        }
    }
    let creating = opts.topic.is_none() && opts.mesh.is_none();
    if !creating && !opts.lookup.is_empty() {
        bail!("--lookup only applies when creating, with neither --topic nor --mesh");
    }
    if !creating && !opts.pkarr_urls.is_empty() {
        bail!(
            "--pkarr-url only applies when creating: a topic uses the default pkarr list and an id carries its own"
        );
    }
    Ok(Args { opts, robot })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // Stderr, so stdout stays the chat surface (and the robot protocol).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "habilis_network=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args()?;
    let (sink, mut events) = json_sink();
    let mut membership = join(&args.opts, sink).await?;

    // Stdin on its own thread: the engine owns no stdio, and tokio's own stdin
    // wants the `io-std` feature this crate deliberately leaves off.
    let (lines_tx, mut lines) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            maybe = lines.recv() => {
                let Some(line) = maybe else { break };
                if !handle_line(&membership, line.trim(), args.robot).await? {
                    break;
                }
            }
            maybe = membership.inbound.recv() => {
                let Some(msg) = maybe else { break };
                show_msg(&msg, args.robot);
            }
            maybe = events.recv() => {
                let Some(event) = maybe else { break };
                show_event(&event, args.robot);
            }
        }
    }
    depart(membership.node).await
}

/// One line of input. `false` ends the chat.
async fn handle_line(membership: &Membership, line: &str, robot: bool) -> Result<bool> {
    if line.is_empty() {
        return Ok(true);
    }
    if line == "/quit" {
        return Ok(false);
    }
    if line == "/peers" {
        let roster = request(membership, |reply| Request::Peers { reply }).await?;
        println!("{roster}");
        return Ok(true);
    }
    let (to, text) = if let Some(rest) = line.strip_prefix("/msg ") {
        let Some((nick, text)) = rest.split_once(' ') else {
            report_error(robot, "usage: /msg <nick> <text>");
            return Ok(true);
        };
        (Some(nick), text)
    } else {
        (None, line)
    };
    let to = parse_to(to)?;
    let body = match msg_body(text) {
        Ok(body) => body,
        Err(error) => {
            report_error(robot, &format!("send failed: {error}"));
            return Ok(true);
        }
    };
    let sent = request(membership, |reply| Request::Send { to, body, reply }).await?;
    if let Err(refusal) = sent {
        report_error(robot, &format!("send failed: {refusal}"));
    }
    Ok(true)
}

async fn request<T>(
    membership: &Membership,
    build: impl FnOnce(oneshot::Sender<T>) -> Request,
) -> Result<T> {
    membership
        .request(build)
        .await
        .map_err(|error| anyhow::anyhow!(error))
}

fn show_msg(msg: &Inbound, robot: bool) {
    if robot {
        println!(
            "{}",
            serde_json::json!({
                "kind": "msg",
                "from": msg.nick,
                "text": msg.text,
                "directed": msg.directed,
            })
        );
        return;
    }
    let mark = if msg.directed { " (direct)" } else { "" };
    println!("{}{mark}: {}", msg.nick, msg.text);
}

/// Engine events arrive as JSON already; the robot passes them through and
/// the human reading gets the two that matter as prose.
fn show_event(event: &str, robot: bool) {
    if robot {
        println!("{event}");
        return;
    }
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(event) else {
        return;
    };
    match (
        parsed.get("kind").and_then(serde_json::Value::as_str),
        parsed.get("nick").and_then(serde_json::Value::as_str),
    ) {
        (Some("ready"), _) => println!("* connected — type to chat, /quit to leave"),
        (Some(kind @ ("joined" | "left" | "returned")), Some(nick)) => {
            println!("* {nick} {kind}");
        }
        _ => {}
    }
}

fn report_error(robot: bool, message: &str) {
    if robot {
        println!(
            "{}",
            serde_json::json!({ "kind": "error", "text": message })
        );
    } else {
        println!("! {message}");
    }
}

#[cfg(test)]
mod tests {
    use habilis_network::protocol::Lookup;

    use super::*;

    fn parse(args: &[&str]) -> Result<Args> {
        parse_args_from(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn a_create_takes_a_pkarr_list() {
        let args = parse(&[
            "--lookup",
            "relay,pkarr",
            "--pkarr-url",
            "https://a.example/pkarr",
            "--pkarr-url",
            "https://b.example/pkarr",
        ])
        .expect("parses");
        assert_eq!(
            args.opts.pkarr_urls,
            ["https://a.example/pkarr", "https://b.example/pkarr"]
        );
    }

    #[test]
    fn a_create_takes_a_lookup_list() {
        let args = parse(&["--lookup", "relay,pkarr"]).expect("parses");
        assert_eq!(args.opts.lookup, [Lookup::Relay, Lookup::Pkarr]);
    }

    #[test]
    fn an_unknown_lookup_names_the_choices() {
        let error = parse(&["--lookup", "carrier-pigeon"])
            .err()
            .expect("refused");
        assert!(format!("{error:#}").contains("pkarr"), "{error:#}");
    }

    #[test]
    fn a_topic_or_an_id_refuses_a_lookup_list() {
        assert!(parse(&["--topic", "room", "--lookup", "relay"]).is_err());
        assert!(parse(&["--mesh", "abc", "--lookup", "relay"]).is_err());
    }

    #[test]
    fn a_topic_or_an_id_refuses_a_pkarr_list() {
        assert!(parse(&["--topic", "room", "--pkarr-url", "https://a.example/pkarr"]).is_err());
        assert!(parse(&["--mesh", "abc", "--pkarr-url", "https://a.example/pkarr"]).is_err());
    }
}
