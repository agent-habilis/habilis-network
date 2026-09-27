//! Selecting a mesh, standing it up, and leaving it — the one ritual every
//! embedding runs.

use std::sync::Arc;

use crate::embed::NodeSink;
use crate::net::TransportOpts;
use crate::protocol::JoinTarget;
use crate::protocol::Nickname;
use crate::protocol::{DirectorySelection, Lookup, MeshConfig, MeshName, RelayLadder, Transport};
use crate::runtime::{CreateParams, JoinParams, Node, Resolved};
use crate::runtime::{SetupKind, SetupParams, derive_topic_mesh_config, setup_mesh};
use crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY;
use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::sync::mpsc;

use super::app::{DEPARTURE_GRACE, INBOUND_CAP, Inbound, MembershipApp, Request};
use crate::net::PathFlags;

/// How the caller selects a mesh — an id to join, a shared string to derive one
/// from, or a create over the choices below.
///
/// A create names three mesh-wide choices, kept apart because they are three
/// concepts: `lookup` says how members find each other, `transport` says what
/// payload may ride, `relay_urls` says which relay. `paths` is this node's own
/// and not in the id.
///
/// `Deserialize` so a browser tab can hand its constructor a plain object and
/// have it land here, which is what stops the browser and the C caller growing
/// two different option sets. `deny_unknown_fields` so a typo is an error rather
/// than a silently loopback mesh; `default` so every field stays optional.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Opts {
    /// A `mesh id` to join.
    pub mesh: Option<String>,
    /// A shared string both sides derive the same public mesh from.
    pub topic: Option<String>,
    /// Local nickname; `None` mints a random one.
    pub nick: Option<String>,
    /// Mesh name to create with; `None` falls back to `"fofoca"`. Ignored
    /// when joining (the name travels with the id/topic instead).
    pub name: Option<String>,
    /// How members find each other: any of `mdns`, `dht`, `relay`. Naming
    /// any uses only those; naming none is a loopback mesh. Ignored with a
    /// `topic` (always all three) or a `mesh` id (which carries its own).
    pub lookup: Vec<Lookup>,
    /// What may carry payload: `p2p`, and `relay` if named. Empty ⇒ `p2p`
    /// alone, so all data is peer to peer and the relay serves lookup only.
    /// `relay` needs `relay` in `lookup`. Part of the mesh id, so a joiner
    /// inherits it; ignored when joining by id.
    pub transport: Vec<Transport>,
    /// Which relay: an ordered ladder (first preferred) replacing the
    /// default. Needs `relay` in `lookup`. Part of the mesh id — with
    /// `topic`, every member must pass the same list or they derive
    /// different meshes. Empty ⇒ the default ladder. Ignored when joining
    /// by id.
    pub relay_urls: Vec<String>,
    /// Which of this node's paths may carry data. Per node, not in the id;
    /// the default is everything the target has.
    pub paths: PathFlags,
    /// Active-view cap; `0` takes the engine default.
    pub max_peers: usize,
}

/// The ladder these options name, or `None` for the default. Parsed as one
/// list, so an empty or bad entry is an error rather than a shrunk ladder.
fn relay_ladder(urls: &[String]) -> Result<Option<RelayLadder>> {
    if urls.is_empty() {
        return Ok(None);
    }
    urls.join(",")
        .parse::<RelayLadder>()
        .map(Some)
        .map_err(|error| anyhow::anyhow!("{error}"))
}

/// One live membership's moving parts.
#[expect(
    missing_debug_implementations,
    reason = "Node's Debug is manual and says nothing a caller wants; the identity a reader would look for is on `node` already"
)]
pub struct Membership {
    pub node: Node<MembershipApp>,
    /// Inbound `msg` frames in arrival order, bounded at [`INBOUND_CAP`].
    pub inbound: mpsc::Receiver<Inbound>,
}

/// Resolve `opts`, stand the mesh up, and spawn the event loop.
///
/// The single setup ritual every embedding runs. A browser and a terminal reach
/// each other only if they agree on the mesh id, the transports and the spawn
/// flags, so none of those is written twice. The one thing that differs is
/// `sink`: the C caller passes `SilentSink` because it can only poll, and the
/// browser passes [`json_sink`](super::json_sink)'s because it has a
/// callback.
///
/// # Errors
/// An unparseable id/topic/nickname, conflicting selectors, a mesh no peer on
/// this target could reach, or a failure standing up the endpoint and overlay.
pub async fn join(opts: &Opts, sink: Arc<dyn NodeSink>) -> Result<Membership> {
    let nickname = opts
        .nick
        .clone()
        .map(Nickname::new)
        .transpose()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let (kind, author) = resolve_kind(opts, nickname)?;
    let max_peers = if opts.max_peers == 0 {
        GOSSIP_ACTIVE_VIEW_CAPACITY
    } else {
        opts.max_peers
    };

    // A browser has no UDP socket, so the loopback ladder a selector-less create
    // resolves to is a mesh of exactly one, forever — and it fails *silently*:
    // the node comes up healthy, the roster stays empty, and nothing says why.
    // Refused where the target makes it impossible rather than where the caller
    // happens to be, the same reasoning that splits the WebRTC backend by target
    // rather than by feature.
    #[cfg(target_arch = "wasm32")]
    {
        let loopback = match &kind {
            SetupKind::Create { config, .. } => config.lookups.is_loopback(),
            SetupKind::Join { mesh, .. } | SetupKind::Topic { mesh, .. } => mesh.is_loopback(),
        };
        anyhow::ensure!(
            !loopback,
            "a browser peer cannot reach a loopback mesh: name a lookup (`relay`), or a topic / mesh id"
        );
    }

    let (inbound_tx, inbound) = mpsc::channel(INBOUND_CAP);
    let config = setup_mesh(
        kind,
        SetupParams {
            author,
            max_peers,
            // An embedded library writes no files and binds no control
            // socket, so it claims no /tmp root of its own.
            runtime_base: None,
            state_file: None,
            sink,
            // The engine binds its own endpoint and serves no extra
            // ALPNs here: injecting either is for a consumer that
            // already owns an iroh endpoint, which an embedded member does
            // not.
            endpoint: None,
            protocols: Vec::new(),
            // The caller's switches over everything this target has. In a
            // browser the WebRTC lane is the only one that exists, and the
            // engine attaches it per target.
            transports: TransportOpts::from(opts.paths),
            multihop: false,
            // An embedded member publishes no per-peer identity, so `meta`
            // stays free-form.
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .context("setting up the mesh")?;

    // `handle_signals: false` — this is a library inside somebody else's
    // process, unlike a CLI that owns its own: installing process-wide ctrl-c /
    // SIGTERM listeners would hijack the host's own handling. A foreign caller
    // traps signals itself and closes the handle.
    let node = Node::spawn(
        config,
        MembershipApp::new(inbound_tx),
        /* push */ None,
        /* handle_signals */ false,
    );

    Ok(Membership { node, inbound })
}

impl Membership {
    /// Push a request into the event loop and await its reply — the dance
    /// every embedding (the wasm peer, the C ABI, the task runner's native
    /// side, the chat example) had re-implemented on its own.
    ///
    /// # Errors
    /// The event loop stopped, or dropped the reply.
    pub async fn request<T>(
        &self,
        build: impl FnOnce(tokio::sync::oneshot::Sender<T>) -> Request,
    ) -> Result<T, String> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        self.node
            .sender()
            .send(build(reply))
            .await
            .map_err(|_| "the event loop stopped".to_owned())?;
        answer
            .await
            .map_err(|_| "the event loop dropped the reply".to_owned())
    }
}

/// Broadcast `Left` and wind the loop down, after a brief grace period: a gossip
/// broadcast is fire-and-forget, so leaving the instant after a send could race
/// the frames out of existence.
///
/// `n0_future::time::sleep`, not `tokio::time`: off wasm32 it *is*
/// `tokio::time::sleep` verbatim, and in a browser tokio has no timer driver and
/// panics. The grace is part of what a remote peer sees, so it belongs here
/// rather than in either consumer.
///
/// # Errors
/// The event loop returned an error or panicked.
pub async fn depart(node: Node<MembershipApp>) -> Result<()> {
    n0_future::time::sleep(DEPARTURE_GRACE).await;
    node.leave().await
}

/// Resolve the selectors into a [`SetupKind`] plus our nickname. Exactly one
/// source: an id, a topic string, or a create over the named lookups (no
/// selector and no lookup ⇒ a loopback create).
///
/// Public because it is the one function that decides *which mesh you land in*,
/// and a tab and a terminal meeting depends on both running it.
///
/// # Errors
/// Both `mesh` and `topic` set, an unparseable id or topic, an invalid mesh
/// name, or a create whose advertise target is unreachable.
pub fn resolve_kind(opts: &Opts, nickname: Option<Nickname>) -> Result<(SetupKind, Nickname)> {
    match (&opts.mesh, &opts.topic) {
        (Some(_), Some(_)) => anyhow::bail!("pass only one of mesh / topic"),
        (Some(id), None) => {
            let target: JoinTarget = id.parse().map_err(|error| anyhow::anyhow!("{error}"))?;
            let Resolved { kind, author, .. } = JoinParams {
                target,
                nickname,
                password: None,
            }
            .resolve()
            .context("resolving the mesh id")?;
            Ok((kind, author))
        }
        (None, Some(string)) => {
            // Note what this ignores: `lookup`. `TopicParams::resolve` always
            // derives through the all-on preset, so a topic mesh is always
            // mDNS + DHT + the relay. That is what lets a tab and a terminal
            // derive the same id from the same string — the lookups are mixed
            // into the derivation, so two reaches over one string are two
            // different meshes. `relay_urls` and `transport` are the two
            // choices that *do* change the id, and every member must pass the
            // same values.
            let config = MeshConfig::resolve(
                &[Lookup::Mdns, Lookup::Dht, Lookup::Relay],
                relay_ladder(&opts.relay_urls)?,
                &opts.transport,
            )?;
            let mesh =
                derive_topic_mesh_config(string, config).context("resolving the topic string")?;
            Ok((
                SetupKind::Topic {
                    mesh,
                    topic_string: string.clone(),
                },
                nickname.unwrap_or_else(Nickname::random),
            ))
        }
        (None, None) => {
            let config = MeshConfig::resolve(
                &opts.lookup,
                relay_ladder(&opts.relay_urls)?,
                &opts.transport,
            )?;
            let name = MeshName::new(opts.name.clone().unwrap_or_else(|| "fofoca".to_string()))
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let Resolved { kind, author, .. } = CreateParams {
                name,
                nickname,
                config,
                advertise: DirectorySelection::Unset,
                password: None,
                invite_only: false,
            }
            .resolve()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            Ok((kind, author))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{LookupOpts, RelayChoice};
    use crate::runtime::derive_topic_mesh_with;

    use super::*;

    fn opts() -> Opts {
        Opts::default()
    }

    fn all_lookups() -> Vec<Lookup> {
        vec![Lookup::Mdns, Lookup::Dht, Lookup::Relay]
    }

    fn create_config(opts: &Opts) -> MeshConfig {
        let (kind, _) = resolve_kind(opts, None).expect("a create resolves");
        match kind {
            SetupKind::Create { config, .. } => config,
            SetupKind::Join { .. } | SetupKind::Topic { .. } => {
                panic!("no selector must resolve to SetupKind::Create")
            }
        }
    }

    /// The JSON a browser tab hands over is this struct verbatim, so its
    /// shape is a contract: the three lists, the ladder, the per-node paths.
    /// A field from before the split is a typo now, not a silent no-op.
    #[test]
    fn the_json_shape_is_the_three_choices_and_the_paths() {
        let parsed: Opts = serde_json::from_str(
            r#"{"lookup":["mdns","relay"],"transport":["p2p","relay"],
                "relayUrls":["http://127.0.0.1:3340/"],"paths":{"webrtc":false}}"#,
        )
        .expect("the documented shape parses");
        assert_eq!(parsed.lookup, vec![Lookup::Mdns, Lookup::Relay]);
        assert_eq!(parsed.transport, vec![Transport::P2p, Transport::Relay]);
        assert_eq!(parsed.relay_urls, vec!["http://127.0.0.1:3340/".to_owned()]);
        assert!(parsed.paths.ip && !parsed.paths.webrtc);
        for stale in [
            r#"{"public":true}"#,
            r#"{"relayLookup":true}"#,
            r#"{"relayTransport":true}"#,
            r#"{"transports":{}}"#,
            r#"{"lookup":["public"]}"#,
        ] {
            assert!(serde_json::from_str::<Opts>(stale).is_err(), "{stale}");
        }
    }

    /// The interop assertion. A browser resolving `topic` and a terminal calling
    /// `derive_topic_mesh_with(s, public_preset())` must land on the same id:
    /// the derivation mixes the lookups in, so this is not a formality.
    #[test]
    fn a_topic_derives_the_public_preset_mesh() {
        let (kind, _author) = resolve_kind(
            &Opts {
                topic: Some("standup".to_owned()),
                ..opts()
            },
            None,
        )
        .expect("a plain topic string resolves");
        let expected = derive_topic_mesh_with("standup", LookupOpts::public_preset())
            .expect("the same string derives");
        match kind {
            SetupKind::Topic { mesh, topic_string } => {
                // Both, because they are what a peer meets another peer on: the
                // gossip topic it subscribes to, and the pseudo-node it dials to
                // find the swarm in the first place.
                assert_eq!(mesh.topic_id(), expected.topic_id());
                assert_eq!(mesh.rendezvous_id(), expected.rendezvous_id());
                assert_eq!(topic_string, "standup");
            }
            SetupKind::Create { .. } | SetupKind::Join { .. } => {
                panic!("a topic string must resolve to SetupKind::Topic")
            }
        }
    }

    #[test]
    fn naming_both_selectors_is_an_error_rather_than_a_precedence_rule() {
        let error = resolve_kind(
            &Opts {
                mesh: Some("whatever".to_owned()),
                topic: Some("standup".to_owned()),
                ..opts()
            },
            None,
        )
        .expect_err("mesh and topic together");
        assert!(error.to_string().contains("only one"), "{error}");
    }

    #[test]
    fn a_bare_create_is_loopback_and_naming_lookups_is_not() {
        assert!(create_config(&opts()).lookups.is_loopback());
        let all = create_config(&Opts {
            lookup: all_lookups(),
            ..opts()
        });
        assert!(!all.lookups.is_loopback());
        assert_eq!(all.lookups, LookupOpts::public_preset());
    }

    /// The relay's two roles are two lists: `relay` in `lookup` finds peers
    /// through it, `relay` in `transport` lets payload ride it. The second is
    /// off unless named, and meaningless without the first.
    #[test]
    fn relay_transport_is_off_unless_named_and_needs_the_relay_lookup() {
        let lookup_only = create_config(&Opts {
            lookup: all_lookups(),
            ..opts()
        });
        assert!(!lookup_only.transport.relay_transport);

        let relayed = create_config(&Opts {
            lookup: vec![Lookup::Relay],
            transport: vec![Transport::P2p, Transport::Relay],
            ..opts()
        });
        assert!(relayed.transport.relay_transport);

        assert!(
            resolve_kind(
                &Opts {
                    transport: vec![Transport::P2p, Transport::Relay],
                    ..opts()
                },
                None,
            )
            .is_err(),
            "relay transport without a relay lookup is an error, not a loopback mesh"
        );
    }

    /// Naming the relay as a lookup and not as a transport is a mesh whose
    /// relay is the meeting point and nothing more: payload never rides it.
    /// On a create, on a topic, and with a custom ladder alike.
    #[test]
    fn the_relay_can_serve_lookup_alone() {
        let create = create_config(&Opts {
            lookup: vec![Lookup::Relay],
            transport: vec![Transport::P2p],
            ..opts()
        });
        assert_eq!(create.lookups.relay_lookup, RelayChoice::Pinned);
        assert!(!create.transport.relay_transport);

        let (topic, _) = resolve_kind(
            &Opts {
                topic: Some("standup".to_owned()),
                transport: vec![Transport::P2p],
                relay_urls: vec!["http://127.0.0.1:3340/".to_owned()],
                ..opts()
            },
            None,
        )
        .expect("a lookup-only topic resolves");
        let SetupKind::Topic { mesh, .. } = topic else {
            panic!("a topic selector must resolve to SetupKind::Topic")
        };
        assert!(!mesh.transport().relay_transport);
        assert!(!mesh.is_loopback(), "the relay lookup is on");
    }

    #[test]
    fn p2p_cannot_be_left_out_of_the_transports() {
        let error = resolve_kind(
            &Opts {
                lookup: vec![Lookup::Relay],
                transport: vec![Transport::Relay],
                ..opts()
            },
            None,
        )
        .expect_err("relay alone is not a mode the engine has");
        assert!(format!("{error:#}").contains("p2p"), "{error:#}");
    }

    /// `relayUrls` swaps the default ladder for the caller's, on both the
    /// create path and the topic path — and on a topic it changes the id,
    /// because the lookups are mixed into the derivation. It says *which*
    /// relay and nothing more: it does not turn the relay lookup on.
    #[test]
    fn relay_urls_replace_the_ladder_and_change_a_topic_id() {
        let urls = vec!["http://127.0.0.1:3340/".to_owned()];
        let config = create_config(&Opts {
            lookup: vec![Lookup::Relay],
            relay_urls: urls.clone(),
            ..opts()
        });
        let RelayChoice::Custom(ladder) = &config.lookups.relay_lookup else {
            panic!("relayUrls must resolve to a custom ladder")
        };
        assert_eq!(ladder.len(), 1);
        assert!(
            resolve_kind(
                &Opts {
                    relay_urls: urls.clone(),
                    ..opts()
                },
                None,
            )
            .is_err(),
            "a ladder without the relay lookup is an error, not an implied lookup"
        );

        let (plain, _) = resolve_kind(
            &Opts {
                topic: Some("standup".to_owned()),
                ..opts()
            },
            None,
        )
        .expect("a plain topic resolves");
        let (laddered, _) = resolve_kind(
            &Opts {
                topic: Some("standup".to_owned()),
                relay_urls: urls,
                ..opts()
            },
            None,
        )
        .expect("a topic with a custom ladder resolves");
        let (SetupKind::Topic { mesh: plain, .. }, SetupKind::Topic { mesh: laddered, .. }) =
            (plain, laddered)
        else {
            panic!("a topic selector must resolve to SetupKind::Topic")
        };
        assert_ne!(
            plain.to_string(),
            laddered.to_string(),
            "the ladder is mixed into the id, so both sides must name the same one"
        );

        assert!(
            resolve_kind(
                &Opts {
                    lookup: vec![Lookup::Relay],
                    relay_urls: vec!["not a url".to_owned()],
                    ..opts()
                },
                None,
            )
            .is_err(),
            "a bad URL is an error, not a shrunk ladder"
        );
    }

    /// `relay_urls` is caller-supplied — the `relay_urls` C field splits an
    /// arbitrary string on `,` — so an oversize ladder must be an error here,
    /// at the boundary. Past 255 rungs the wire count no longer fits its `u8`
    /// and the encoder panics; a wasm or in-process caller has no guard to
    /// catch that, and an FFI caller gets a bare "a panic crossed the FFI
    /// boundary" instead of a diagnostic.
    #[test]
    fn an_oversize_relay_ladder_is_an_error_not_a_panic() {
        let urls: Vec<String> = (0..300)
            .map(|index| format!("https://r{index}.example"))
            .collect();
        for kind in [None, Some("standup".to_owned())] {
            let error = resolve_kind(
                &Opts {
                    topic: kind.clone(),
                    lookup: vec![Lookup::Relay],
                    relay_urls: urls.clone(),
                    ..opts()
                },
                None,
            )
            .expect_err("300 rungs must not reach the encoder");
            // `{:#}` so the topic path's context does not hide the cause.
            assert!(
                format!("{error:#}").contains("relay ladder too long"),
                "got: {error:#}"
            );
        }
    }

    /// A topic with the relay allowed as transport derives a different mesh
    /// than the plain public-preset topic — and inherits the policy.
    #[test]
    fn relay_transport_changes_a_topic_id() {
        let (plain, _) = resolve_kind(
            &Opts {
                topic: Some("standup".to_owned()),
                ..opts()
            },
            None,
        )
        .expect("a plain topic resolves");
        let (relayed, _) = resolve_kind(
            &Opts {
                topic: Some("standup".to_owned()),
                transport: vec![Transport::P2p, Transport::Relay],
                ..opts()
            },
            None,
        )
        .expect("a relay-transport topic resolves");
        let (SetupKind::Topic { mesh: plain, .. }, SetupKind::Topic { mesh: relayed, .. }) =
            (plain, relayed)
        else {
            panic!("a topic selector must resolve to SetupKind::Topic")
        };
        assert_ne!(plain.to_string(), relayed.to_string());
        assert!(relayed.transport().relay_transport);
        assert!(!plain.transport().relay_transport);
    }

    #[test]
    fn naming_one_lookup_selects_only_that_one() {
        let config = create_config(&Opts {
            lookup: vec![Lookup::Mdns],
            ..opts()
        });
        assert!(config.lookups.mdns);
        assert!(!config.lookups.dht);
        assert_eq!(config.lookups.relay_lookup, RelayChoice::Disabled);
        assert!(!config.lookups.is_loopback());
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::runtime::TopicParams;

    /// The collapse of the bare-topic early return rests on this identity: a
    /// tab and a terminal meet only if the no-override arm keeps deriving the
    /// exact id `TopicParams::resolve` always produced.
    #[test]
    fn a_bare_topic_still_derives_the_public_preset_mesh() {
        let opts = Opts {
            topic: Some("standup".to_owned()),
            ..Opts::default()
        };
        let (kind, _author) = resolve_kind(&opts, None).expect("resolve");
        let SetupKind::Topic { mesh, .. } = kind else {
            panic!("a topic resolves to a topic kind");
        };
        let Resolved { kind: baseline, .. } = TopicParams {
            string: "standup".to_owned(),
            nickname: None,
        }
        .resolve()
        .expect("baseline");
        let SetupKind::Topic { mesh: expected, .. } = baseline else {
            panic!("the baseline is a topic kind");
        };
        assert_eq!(mesh.to_string(), expected.to_string());
    }
}
