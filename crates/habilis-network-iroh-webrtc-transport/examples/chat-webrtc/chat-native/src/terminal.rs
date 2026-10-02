//! Stdin in, room out.
//!
//! Shared by both roles, because both are ordinary members: the host types into
//! the same loop a joined peer does. What differs is only where the two ends
//! are plumbed — the host's messages arrive from a [`Membership`] and its lines
//! go straight into the [`Room`](crate::room::Room); a joiner's arrive off a
//! QUIC stream and its lines go back out over one. Both are reduced to the same
//! pair here: a receiver of [`ServerMsg`], and a closure that sends a line.

use std::future::Future;

use anyhow::Result;
use chat_proto::{ClientMsg, ServerMsg};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::sync::mpsc;

use crate::room::Membership;

const CHANNEL_CAPACITY: usize = 64;

/// One line of a transcript.
#[must_use]
pub fn render(msg: &ServerMsg) -> String {
    match msg {
        ServerMsg::Welcome { you, roster } => {
            format!("* you are \"{you}\" — in the room: {}", roster.join(", "))
        }
        ServerMsg::Joined { nick } => format!("* {nick} joined"),
        ServerMsg::Left { nick } => format!("* {nick} left"),
        ServerMsg::Said { nick, text } => format!("{nick}: {text}"),
    }
}

/// Stdin, as a channel.
///
/// A task rather than a `select!` branch: an mpsc receiver is unambiguously
/// cancel-safe where a half-read line is not. The channel closes on EOF, which
/// is how ^D ends a session.
#[must_use]
pub fn lines() -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = stdin.next_line().await {
            if tx.send(line).await.is_err() {
                break;
            }
        }
    });
    rx
}

/// Drain a [`Membership`]'s fan-out into a channel [`participate`] can read.
///
/// The task owns the membership, so the member stays in the roster exactly as
/// long as this channel is alive and leaves when it is dropped.
#[must_use]
pub fn from_membership(mut membership: Membership) -> mpsc::Receiver<ServerMsg> {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    tokio::spawn(async move {
        while let Some(fanout) = membership.next_broadcast().await {
            if tx.send(fanout.msg).await.is_err() {
                break;
            }
        }
    });
    rx
}

/// Run a member's terminal until stdin ends or the room does.
///
/// Empty lines are dropped here so neither caller has to remember to — a stray
/// return should not broadcast.
pub async fn participate<F, Fut>(mut incoming: mpsc::Receiver<ServerMsg>, mut say: F) -> Result<()>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let mut stdin = lines();
    loop {
        tokio::select! {
            typed = stdin.recv() => {
                let Some(line) = typed else { return Ok(()) };
                let text = line.trim().to_owned();
                if text.is_empty() {
                    continue;
                }
                // Validated before it goes anywhere, so an over-long line is a
                // local complaint rather than a frame the room silently drops.
                if let Err(error) = (ClientMsg::Say { text: text.clone() }).validate() {
                    println!("* not sent: {error}");
                    continue;
                }
                say(text).await?;
            }
            received = incoming.recv() => {
                let Some(msg) = received else { return Ok(()) };
                println!("{}", render(&msg));
            }
        }
    }
}
