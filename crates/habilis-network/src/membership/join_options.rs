//! Selecting a mesh, standing it up, and leaving it — the one ritual every
//! embedding runs.

use crate::daemon::SetupError;
use std::sync::Arc;

use crate::embed::NodeSink;
use crate::protocol::{
    DirectorySelection, JoinTarget, Lookup, MeshConfig, MeshName, Nickname, RelayLadder, Transport,
};
use crate::runtime::{
    CreateParams, JoinParams, Node, Resolved, SetupKind, SetupParams, SignalHandling,
    derive_topic_mesh_config, setup_mesh,
};
use crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY;
use anyhow::Result;
use serde::Deserialize;
use tokio::sync::mpsc;

use super::membership_app::{DEPARTURE_GRACE, INBOUND_CAP, Inbound, MembershipApp, Request};

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::beacon;
use n0_future::time;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use std::sync::atomic;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use std::sync::atomic::Ordering;
use tokio::sync::oneshot;
/// How the caller selects a mesh — an id to join, a shared string to derive one
/// from, or a create over the choices below.
///
/// A create names three mesh-wide choices, kept apart because they are three
/// concepts: `lookup` says how members find each other, `transport` says what
/// payload may ride, `relay_urls` says which relay.
///
/// `Deserialize` so a browser tab can hand its constructor a plain object and
/// have it land here, which is what stops the browser and the C caller growing
/// two different option sets. `deny_unknown_fields` so a typo is an error rather
/// than a silently loopback mesh; `default` so every field stays optional.
///
/// # Examples
///
/// A mesh and a topic cannot both name the mesh to join.
///
/// ```
/// use habilis_network::membership::{JoinOptions, resolve_kind};
///
/// let options = JoinOptions::default().mesh(Some("a".to_owned())).topic(Some("b".to_owned()));
/// assert!(resolve_kind(&options, None).is_err());
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[non_exhaustive]
pub struct JoinOptions {
    /// A `mesh id` to join.
    pub mesh: Option<String>,
    /// A shared string both sides derive the same public mesh from.
    pub topic: Option<String>,
    /// Local nickname; `None` mints a random one.
    pub nick: Option<String>,
    /// Mesh name to create with; `None` falls back to `"habilis-network"`. Ignored
    /// when joining (the name travels with the id/topic instead).
    pub name: Option<String>,
    /// How members find each other: any of `mdns`, `dht`, `relay`. Naming
    /// any uses only those; naming none is a loopback mesh. Ignored with a
    /// `topic` (always all three) or a `mesh` id (which carries its own).
    pub lookup: Vec<Lookup>,
    /// What may carry payload: any of `udp`, `webrtc`, `multihop`, `gossip`, `relay`, with
    /// `udp` or `webrtc` among them, and `udp` with `multihop`. Empty ⇒
    /// `udp,webrtc,multihop,gossip`, so all data is peer to peer (through other members
    /// when no direct path exists, and through the mesh topic when no member routes) and the
    /// relay serves lookup only. A list names what it carries: without `gossip` there is none.
    /// `relay`, or
    /// a list without `udp`,
    /// needs `relay` in `lookup`. Part of the mesh id, so a joiner inherits
    /// it; ignored when joining by id.
    pub transport: Vec<Transport>,
    /// Which relay: an ordered ladder (first preferred) replacing the
    /// default. Needs `relay` in `lookup`. Part of the mesh id — with
    /// `topic`, every member must pass the same list or they derive
    /// different meshes. Empty ⇒ the default ladder. Ignored when joining
    /// by id.
    pub relay_urls: Vec<String>,
    /// Active-view cap (G); `0` takes the engine default.
    pub max_peers: usize,
    /// Ceiling of direct connections (C); `0` takes the engine default.
    pub max_direct: usize,
}

impl JoinOptions {
    /// Set the topic that derives the mesh.
    #[must_use]
    pub fn topic(mut self, topic: Option<String>) -> Self {
        self.topic = topic;
        self
    }

    /// Set the nickname.
    #[must_use]
    pub fn nick(mut self, nick: Option<String>) -> Self {
        self.nick = nick;
        self
    }

    /// Set the mesh name.
    #[must_use]
    pub fn mesh(mut self, mesh: Option<String>) -> Self {
        self.mesh = mesh;
        self
    }

    /// Set the name to create the mesh with.
    #[must_use]
    pub fn name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Set the lookups.
    #[must_use]
    pub fn lookup(mut self, lookup: impl IntoIterator<Item = Lookup>) -> Self {
        self.lookup = lookup.into_iter().collect();
        self
    }

    /// Set the transports.
    #[must_use]
    pub fn transport(mut self, transport: impl IntoIterator<Item = Transport>) -> Self {
        self.transport = transport.into_iter().collect();
        self
    }

    /// The relay URLs to dial, in the order given.
    #[must_use]
    pub fn relay_urls(mut self, relay_urls: impl IntoIterator<Item = String>) -> Self {
        self.relay_urls = relay_urls.into_iter().collect();
        self
    }

    /// Set the peer cap.
    #[must_use]
    pub fn max_peers(mut self, max_peers: usize) -> Self {
        self.max_peers = max_peers;
        self
    }

    /// Set the direct-session cap.
    #[must_use]
    pub fn max_direct(mut self, max_direct: usize) -> Self {
        self.max_direct = max_direct;
        self
    }
}

/// The ladder these options name, or `None` for the default. Parsed as one
/// list, so an empty or bad entry is an error rather than a shrunk ladder.
fn relay_ladder(urls: &[String]) -> Result<Option<RelayLadder>> {
    if urls.is_empty() {
        return Ok(None);
    }
    let ladder: Result<RelayLadder, _> = urls.join(",").parse();
    ladder.map(Some).map_err(|error| anyhow::anyhow!("{error}"))
}

/// One live membership's moving parts.
///
/// # Examples
///
/// A membership is one member of a mesh, and it leaves the mesh when it departs. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::membership::{JoinOptions, Membership, depart, join, json_sink};
///
/// # async fn demo() {
/// let (sink, _events) = json_sink();
/// let member: Membership = join(&JoinOptions::default(), sink).await.expect("a member");
/// depart(member.node).await.expect("depart");
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct Membership {
    /// The running node that this membership drives.
    pub node: Node<MembershipApp>,
    /// Inbound `msg` frames in arrival order, bounded at [`INBOUND_CAP`].
    pub inbound: mpsc::Receiver<Inbound>,
}

/// Tests only: whether a member that is set up now has its rung probes blind from its first walk.
/// [`Request::BlindRungProbes`] can only reach a member that is up, after its startup walk ran.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
static NEW_MEMBERS_ARE_BLIND: atomic::AtomicBool = atomic::AtomicBool::new(false);

/// Tests only: make every member that [`join`] sets up from now on blind (`blind`), or not. The
/// dial is process-wide, so a test turns it on around the opens that it means and off again.
///
/// # Examples
///
/// It sets whether the members that join from now on are blind.
///
/// ```
/// use habilis_network::membership::blind_new_members;
///
/// blind_new_members(true);
/// blind_new_members(false);
/// ```
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub fn blind_new_members(
    // true makes every member that join sets up from now on blind
    blind: bool,
) {
    NEW_MEMBERS_ARE_BLIND.store(blind, Ordering::SeqCst);
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
///
/// # Examples
///
/// It joins a mesh with the given options and a sink for its events. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::membership::{JoinOptions, join, json_sink};
///
/// # async fn demo() {
/// let (sink, _events) = json_sink();
/// let options = JoinOptions::default().nick(Some("alice".to_owned()));
/// let member = join(&options, sink).await.expect("a member");
/// # let _ = member;
/// # }
/// ```
pub async fn join<S: NodeSink + 'static>(
    options: &JoinOptions,
    // join takes a shared sink, which the event loop keeps
    sink: Arc<S>,
) -> Result<Membership, SetupError> {
    let nick_text = options.nick.as_deref();
    let nickname = nick_text
        .map(Nickname::try_new)
        .transpose()
        .map_err(|error| SetupError::internal(anyhow::anyhow!("{error}")))?;
    let (kind, author) = resolve_kind(options, nickname)?;
    let max_peers = if options.max_peers == 0 {
        GOSSIP_ACTIVE_VIEW_CAPACITY
    } else {
        options.max_peers
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
        if loopback {
            return Err(SetupError::internal(anyhow::anyhow!(
                "a browser peer cannot reach a loopback mesh: name a lookup (`relay`), or a topic / mesh id"
            )));
        }
    }

    let (inbound_tx, inbound) = mpsc::channel(INBOUND_CAP);
    let config = setup_mesh(
        kind,
        SetupParams::new(author, sink)
            .max_peers(max_peers)
            .max_direct(options.max_direct),
    )
    .await?;

    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    if NEW_MEMBERS_ARE_BLIND.load(Ordering::SeqCst) {
        // Before the loop is spawned, so that the startup walk is blind too.
        beacon::set_blind_rung_probes(config.endpoint.id(), true);
    }

    // `SignalHandling::Leave` — this is a library inside somebody else's
    // process, unlike a CLI that owns its own: installing process-wide ctrl-c /
    // SIGTERM listeners would hijack the host's own handling. A foreign caller
    // traps signals itself and closes the handle.
    let node = Node::spawn(
        config,
        MembershipApp::new(inbound_tx),
        /* push */ None,
        SignalHandling::Leave,
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
        build: impl FnOnce(oneshot::Sender<T>) -> Request,
    ) -> Result<T, String> {
        let (reply, answer) = oneshot::channel();
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
///
/// # Examples
///
/// It leaves the mesh of a membership. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::membership::{Membership, depart};
///
/// # async fn demo(member: Membership) {
/// depart(member.node).await.expect("depart");
/// # }
/// ```
pub async fn depart(node: Node<MembershipApp>) -> Result<(), SetupError> {
    time::sleep(DEPARTURE_GRACE).await;
    node.leave()
        .await
        .map_err(|error| SetupError::Internal(error.into()))
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
///
/// # Examples
///
/// Naming both a mesh and a topic is refused.
///
/// ```
/// use habilis_network::membership::{JoinOptions, resolve_kind};
///
/// let options = JoinOptions::default().mesh(Some("a".to_owned())).topic(Some("b".to_owned()));
/// assert!(resolve_kind(&options, None).is_err());
/// ```
pub fn resolve_kind(
    options: &JoinOptions,
    nickname: Option<Nickname>,
) -> Result<(SetupKind, Nickname), SetupError> {
    match (&options.mesh, &options.topic) {
        (Some(_), Some(_)) => Err(SetupError::MeshAndTopic),
        (Some(id), None) => {
            let target: JoinTarget = id
                .parse()
                .map_err(|error| SetupError::internal(anyhow::anyhow!("{error}")))?;
            let Resolved { kind, author, .. } =
                JoinParams::new(target, nickname, None).resolve()?;
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
                relay_ladder(&options.relay_urls).map_err(SetupError::internal)?,
                &options.transport,
            )
            .map_err(SetupError::Config)?;
            let mesh = derive_topic_mesh_config(string, config)?;
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
                &options.lookup,
                relay_ladder(&options.relay_urls).map_err(SetupError::internal)?,
                &options.transport,
            )
            .map_err(SetupError::Config)?;
            let name = MeshName::try_new(options.name.as_deref().unwrap_or("habilis-network"))
                .map_err(|error| SetupError::internal(anyhow::anyhow!("{error}")))?;
            let Resolved { kind, author, .. } =
                CreateParams::new(name, nickname, config, DirectorySelection::Unset)
                    .password(None)
                    .invite_only(false)
                    .resolve()
                    .map_err(|error| SetupError::internal(anyhow::Error::from(error)))?;
            Ok((kind, author))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{LookupOpts, RelayChoice};
    use crate::runtime;

    use super::{JoinOptions, Lookup, MeshConfig, SetupKind, Transport, resolve_kind};
    fn options() -> JoinOptions {
        JoinOptions::default()
    }

    fn all_lookups() -> Vec<Lookup> {
        vec![Lookup::Mdns, Lookup::Dht, Lookup::Relay]
    }

    fn create_config(options: &JoinOptions) -> MeshConfig {
        let (kind, _) = resolve_kind(options, None).expect("a create resolves");
        match kind {
            SetupKind::Create { config, .. } => config,
            SetupKind::Join { .. } | SetupKind::Topic { .. } => {
                panic!("no selector must resolve to SetupKind::Create")
            }
        }
    }

    /// The JSON a browser tab hands over is this struct verbatim, so its
    /// shape is a contract: the three lists and the ladder. A field from
    /// before the split is a typo now, not a silent no-op.
    #[test]
    fn the_json_shape_is_the_three_choices() {
        let _guard = ::habilis_network_test_tracing::init();
        let parsed: JoinOptions = serde_json::from_str(
            r#"{"lookup":["mdns","relay"],"transport":["webrtc","relay"],
                "relayUrls":["http://127.0.0.1:3340/"]}"#,
        )
        .expect("the documented shape parses");
        assert_eq!(
            parsed.lookup,
            vec![Lookup::Mdns, Lookup::Relay],
            "the lookup list keeps mdns and relay in order"
        );
        assert_eq!(
            parsed.transport,
            vec![Transport::WebRtc, Transport::Relay],
            "the transport list keeps webrtc and relay in order"
        );
        assert_eq!(
            parsed.relay_urls,
            vec!["http://127.0.0.1:3340/".to_owned()],
            "the relay urls keep the loopback relay address"
        );
        for stale in [
            r#"{"paths":{"webrtc":false}}"#,
            r#"{"public":true}"#,
            r#"{"relayLookup":true}"#,
            r#"{"relayTransport":true}"#,
            r#"{"transports":{}}"#,
            r#"{"lookup":["public"]}"#,
        ] {
            assert!(
                serde_json::from_str::<JoinOptions>(stale).is_err(),
                "{stale}"
            );
        }
    }

    /// The interop assertion. A browser resolving `topic` and a terminal calling
    /// `runtime::derive_topic_mesh_with(s, public_preset())` must land on the same id:
    /// the derivation mixes the lookups in, so this is not a formality.
    #[test]
    fn a_topic_derives_the_public_preset_mesh() {
        let _guard = ::habilis_network_test_tracing::init();
        let (kind, _author) = resolve_kind(
            &JoinOptions {
                topic: Some("standup".to_owned()),
                ..options()
            },
            None,
        )
        .expect("a plain topic string resolves");
        let expected = runtime::derive_topic_mesh_with("standup", LookupOpts::public_preset())
            .expect("the same string derives");
        match kind {
            SetupKind::Topic { mesh, topic_string } => {
                // Both, because they are what a peer meets another peer on: the
                // gossip topic it subscribes to, and the pseudo-node it dials to
                // find the swarm in the first place.
                assert_eq!(
                    mesh.topic_id(),
                    expected.topic_id(),
                    "a topic derives the same topic id as the public preset"
                );
                assert_eq!(
                    mesh.rendezvous_id(),
                    expected.rendezvous_id(),
                    "a topic derives the same rendezvous id as the public preset"
                );
                assert_eq!(topic_string, "standup", "the topic string is kept as given");
            }
            SetupKind::Create { .. } | SetupKind::Join { .. } => {
                panic!("a topic string must resolve to SetupKind::Topic")
            }
        }
    }

    #[test]
    fn naming_both_selectors_is_an_error_rather_than_a_precedence_rule() {
        let _guard = ::habilis_network_test_tracing::init();
        let conflicting = JoinOptions {
            mesh: Some("whatever".to_owned()),
            topic: Some("standup".to_owned()),
            ..options()
        };
        let error = resolve_kind(&conflicting, None).expect_err("mesh and topic together");
        assert!(error.to_string().contains("only one"), "{error}");
    }

    #[test]
    fn a_bare_create_is_loopback_and_naming_lookups_is_not() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            create_config(&options()).lookups.is_loopback(),
            "a bare create uses loopback lookups"
        );
        let all = create_config(&JoinOptions {
            lookup: all_lookups(),
            ..options()
        });
        assert!(!all.lookups.is_loopback(), "naming lookups is not loopback");
        assert_eq!(
            all.lookups,
            LookupOpts::public_preset(),
            "naming lookups selects the public preset"
        );
    }

    /// The relay's two roles are two lists: `relay` in `lookup` finds peers
    /// through it, `relay` in `transport` lets payload ride it. The second is
    /// off unless named, and meaningless without the first.
    #[test]
    fn relay_transport_is_off_unless_named_and_needs_the_relay_lookup() {
        let _guard = ::habilis_network_test_tracing::init();
        let lookup_only = create_config(&JoinOptions {
            lookup: all_lookups(),
            ..options()
        });
        assert!(
            !lookup_only.transport.relay_transport,
            "the relay transport stays off when only the relay lookup is named"
        );

        let relayed = create_config(&JoinOptions {
            lookup: vec![Lookup::Relay],
            transport: vec![Transport::Udp, Transport::Relay],
            ..options()
        });
        assert!(
            relayed.transport.relay_transport,
            "the relay transport is on when it is named"
        );

        assert!(
            resolve_kind(
                &JoinOptions {
                    transport: vec![Transport::Udp, Transport::Relay],
                    ..options()
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
        let _guard = ::habilis_network_test_tracing::init();
        let create = create_config(&JoinOptions {
            lookup: vec![Lookup::Relay],
            transport: vec![Transport::Udp],
            ..options()
        });
        assert_eq!(
            create.lookups.relay_lookup,
            RelayChoice::Pinned,
            "the relay serves lookup alone as a pinned relay"
        );
        assert!(
            !create.transport.relay_transport,
            "the relay lookup alone leaves the relay transport off"
        );

        let (topic, _) = resolve_kind(
            &JoinOptions {
                topic: Some("standup".to_owned()),
                transport: vec![Transport::Udp],
                relay_urls: vec!["http://127.0.0.1:3340/".to_owned()],
                ..options()
            },
            None,
        )
        .expect("a lookup-only topic resolves");
        let SetupKind::Topic { mesh, .. } = topic else {
            panic!("a topic selector must resolve to SetupKind::Topic")
        };
        assert!(
            !mesh.transport().relay_transport,
            "the mesh transport has the relay transport off"
        );
        assert!(!mesh.is_loopback(), "the relay lookup is on");
    }

    #[test]
    fn udp_cannot_be_left_out_of_the_transports() {
        let _guard = ::habilis_network_test_tracing::init();
        let error = resolve_kind(
            &JoinOptions {
                lookup: vec![Lookup::Relay],
                transport: vec![Transport::Relay],
                ..options()
            },
            None,
        )
        .expect_err("relay alone is not a mode the engine has");
        assert!(format!("{error:#}").contains("udp"), "{error:#}");
    }

    /// `relayUrls` swaps the default ladder for the caller's, on both the
    /// create path and the topic path — and on a topic it changes the id,
    /// because the lookups are mixed into the derivation. It says *which*
    /// relay and nothing more: it does not turn the relay lookup on.
    #[test]
    fn relay_urls_replace_the_ladder_and_change_a_topic_id() {
        let _guard = ::habilis_network_test_tracing::init();
        let urls = vec!["http://127.0.0.1:3340/".to_owned()];
        let config = create_config(&JoinOptions {
            lookup: vec![Lookup::Relay],
            relay_urls: urls.clone(),
            ..options()
        });
        let RelayChoice::Custom(ladder) = &config.lookups.relay_lookup else {
            panic!("relayUrls must resolve to a custom ladder")
        };
        assert_eq!(
            ladder.len(),
            1,
            "one relay url replaces the ladder with one rung"
        );
        assert!(
            resolve_kind(
                &JoinOptions {
                    relay_urls: urls.clone(),
                    ..options()
                },
                None,
            )
            .is_err(),
            "a ladder without the relay lookup is an error, not an implied lookup"
        );

        let (plain, _) = resolve_kind(
            &JoinOptions {
                topic: Some("standup".to_owned()),
                ..options()
            },
            None,
        )
        .expect("a plain topic resolves");
        let (laddered, _) = resolve_kind(
            &JoinOptions {
                topic: Some("standup".to_owned()),
                relay_urls: urls,
                ..options()
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
                &JoinOptions {
                    lookup: vec![Lookup::Relay],
                    relay_urls: vec!["not a url".to_owned()],
                    ..options()
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
        let _guard = ::habilis_network_test_tracing::init();
        let urls: Vec<String> = (0..300)
            .map(|index| format!("https://r{index}.example"))
            .collect();
        for kind in [None, Some("standup".to_owned())] {
            let oversize = JoinOptions {
                topic: kind.clone(),
                lookup: vec![Lookup::Relay],
                relay_urls: urls.clone(),
                ..options()
            };
            let error =
                resolve_kind(&oversize, None).expect_err("300 rungs must not reach the encoder");
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
        let _guard = ::habilis_network_test_tracing::init();
        let (plain, _) = resolve_kind(
            &JoinOptions {
                topic: Some("standup".to_owned()),
                ..options()
            },
            None,
        )
        .expect("a plain topic resolves");
        let (relayed, _) = resolve_kind(
            &JoinOptions {
                topic: Some("standup".to_owned()),
                transport: vec![Transport::Udp, Transport::Relay],
                ..options()
            },
            None,
        )
        .expect("a relay-transport topic resolves");
        let (SetupKind::Topic { mesh: plain, .. }, SetupKind::Topic { mesh: relayed, .. }) =
            (plain, relayed)
        else {
            panic!("a topic selector must resolve to SetupKind::Topic")
        };
        assert_ne!(
            plain.to_string(),
            relayed.to_string(),
            "the relay transport changes the topic string"
        );
        assert!(
            relayed.transport().relay_transport,
            "the relayed mesh has the relay transport on"
        );
        assert!(
            !plain.transport().relay_transport,
            "the plain mesh has the relay transport off"
        );
    }

    #[test]
    fn naming_one_lookup_selects_only_that_one() {
        let _guard = ::habilis_network_test_tracing::init();
        let config = create_config(&JoinOptions {
            lookup: vec![Lookup::Mdns],
            ..options()
        });
        assert!(config.lookups.mdns, "naming one lookup selects mdns");
        assert!(!config.lookups.dht, "naming one lookup leaves dht off");
        assert_eq!(
            config.lookups.relay_lookup,
            RelayChoice::Disabled,
            "naming one lookup leaves the relay lookup disabled"
        );
        assert!(
            !config.lookups.is_loopback(),
            "naming one lookup is not loopback"
        );
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::{JoinOptions, Resolved, SetupKind, resolve_kind};
    use crate::runtime::TopicParams;

    /// The collapse of the bare-topic early return rests on this identity: a
    /// tab and a terminal meet only if the no-override arm keeps deriving the
    /// exact id `TopicParams::resolve` always produced.
    #[test]
    fn a_bare_topic_still_derives_the_public_preset_mesh() {
        let _guard = ::habilis_network_test_tracing::init();
        let options = JoinOptions {
            topic: Some("standup".to_owned()),
            ..JoinOptions::default()
        };
        let (kind, _author) = resolve_kind(&options, None).expect("resolve");
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
        assert_eq!(
            mesh.to_string(),
            expected.to_string(),
            "a bare topic derives the same mesh as the public preset"
        );
    }
}
