use super::{
    AppFrameParams, AppTag, BuildMsgParams, ChainCtx, MeshId, Message, MessageBody, MessageKind,
    Nickname, PresenceSubtype, build_msg_bytes,
};

fn nick(name: &str) -> Nickname {
    Nickname::from(name)
}

fn sid() -> MeshId {
    MeshId::from("test")
}

#[test]
fn test_round_trip() {
    let msg = Message::new_app(
        &sid(),
        &nick("word-word"),
        AppFrameParams {
            tag: AppTag::from("app_msg"),
            to: None,
            corr: None,
            body: MessageBody::from("Hello, world!"),
        },
    );
    let bytes = msg.serialize().unwrap();
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(parsed.id, msg.id);
    assert_eq!(parsed.kind, MessageKind::app_broadcast("app_msg"));
    assert_eq!(parsed.body, msg.body);
}

#[test]
#[should_panic(expected = "invalid app tag")]
fn app_tag_constructor_rejects_an_invalid_value() {
    let _ = AppTag::from("not-valid!");
}

#[test]
#[should_panic(expected = "invalid correlation id")]
fn correlation_id_constructor_rejects_an_invalid_value() {
    let _ = super::CorrId::from("");
}

#[test]
fn test_alive_round_trip() {
    let msg = Message::new_alive(&sid(), &nick("word-word"));
    let bytes = msg.serialize().unwrap();
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(
        parsed.kind,
        MessageKind::Presence {
            subtype: PresenceSubtype::Alive
        }
    );
    assert_eq!(parsed.body.as_str(), "");
}

#[test]
fn test_ping_round_trip() {
    let msg = Message::new_ping(&sid(), &nick("word-word"));
    let bytes = msg.serialize().unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("\"type\":\"ping\""));
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(parsed.kind, MessageKind::Ping);
    assert_eq!(parsed.body.as_str(), "");
}

#[test]
fn test_pong_round_trip() {
    let target = nick("pinger-here");
    let msg = Message::new_pong(&sid(), &nick("word-word"), target.clone());
    let bytes = msg.serialize().unwrap();
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(parsed.kind, MessageKind::Pong { to: target });
    assert_eq!(parsed.body.as_str(), "");
}

#[test]
fn test_task_status_round_trip() {
    let target = nick("calm-otter");
    let msg = Message::new_app(
        &sid(),
        &nick("word-word"),
        AppFrameParams {
            tag: AppTag::from("app_status"),
            to: Some(target.clone()),
            corr: None,
            body: MessageBody::from(r#"{"kind":"status-update"}"#),
        },
    );
    let bytes = msg.serialize().unwrap();
    let wire = String::from_utf8_lossy(&bytes);
    assert!(wire.contains("\"type\":\"app\""));
    assert!(wire.contains("\"tag\":\"app_status\""));
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(parsed.kind, MessageKind::app_to("app_status", target, None));
    assert_eq!(parsed.body, msg.body);
}

#[test]
fn test_task_artifact_round_trip() {
    let target = nick("calm-otter");
    let msg = Message::new_frame(
        &sid(),
        &nick("word-word"),
        MessageKind::app_to("app_artifact", target.clone(), None),
        MessageBody::from(r#"{"kind":"artifact-update"}"#),
    );
    let bytes = msg.serialize().unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("\"tag\":\"app_artifact\""));
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(
        parsed.kind,
        MessageKind::app_to("app_artifact", target, None)
    );
}

#[test]
fn test_ext_round_trip() {
    let mut msg = Message::new_app(
        &sid(),
        &nick("word-word"),
        AppFrameParams {
            tag: AppTag::from("app_msg"),
            to: None,
            corr: None,
            body: MessageBody::from("With ext."),
        },
    );
    msg.ext = serde_json::json!({"tags": ["rust", "p2p"], "priority": 1});
    let bytes = msg.serialize().unwrap();
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(parsed.ext["tags"][0], "rust");
    assert_eq!(parsed.ext["priority"], 1);
}

/// A valid UUID for the hand-written wire-JSON fixtures below (the
/// validating `MessageId` deserialize rejects non-UUID ids).
const FIXTURE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const FIXTURE_MESH: &str = "2UXAThUkdBAbiJNXvCt4YeMGQ9myFg7gJJZSr3pG3MAGzUwWmmV7D2NgrWBn1";

#[test]
fn test_unknown_ext_fields_ignored() {
    let json = format!(
        r#"{{"v":"12.0","id":"{FIXTURE_ID}","type":"app","tag":"app_msg","mesh":"{FIXTURE_MESH}","author":"a-b","ts":0,"body":"hi","ext":{{"future_field":"value","another":42}}}}"#
    );
    let parsed = Message::parse(json.as_bytes()).unwrap();
    assert_eq!(parsed.body.as_str(), "hi");
    assert_eq!(parsed.ext["future_field"], "value");
}

#[test]
fn test_missing_ext_defaults_to_empty_object() {
    let json = format!(
        r#"{{"v":"12.0","id":"{FIXTURE_ID}","type":"app","tag":"app_msg","mesh":"{FIXTURE_MESH}","author":"a-b","ts":0,"body":"hi"}}"#
    );
    let parsed = Message::parse(json.as_bytes()).unwrap();
    assert_eq!(parsed.ext, serde_json::json!({}));
}

#[test]
fn test_version_mismatch_rejected() {
    // A `1.0` (pre-merge) message must be rejected by this `2.0` binary — the
    // rolling-upgrade guard: cross-version state never silently folds.
    let json = format!(
        r#"{{"v":"1.0","id":"{FIXTURE_ID}","type":"msg","mesh":"test","author":"a-b","ts":0,"body":"hi","ext":{{}}}}"#
    );
    assert!(Message::parse(json.as_bytes()).is_err());
}

// Crafted wire messages that a correct client never produces: the
// validating newtype `Deserialize` impls must reject them at `parse`, so a
// malicious peer cannot crash the daemon (bad id) or inject terminal
// escapes / spoof the `<nick>`/`#mesh` conventions (bad body/author).
#[test]
fn parse_rejects_non_uuid_id() {
    let json = r#"{"v":"12.0","id":"not-a-uuid","type":"app","tag":"app_msg","mesh":"test","author":"a-b","ts":0,"body":"hi","ext":{}}"#;
    assert!(Message::parse(json.as_bytes()).is_err());
}

#[test]
fn parse_rejects_control_char_body() {
    let json = format!(
        r#"{{"v":"12.0","id":"{FIXTURE_ID}","type":"app","tag":"app_msg","mesh":"test","author":"a-b","ts":0,"body":"evil\u0000body","ext":{{}}}}"#
    );
    assert!(Message::parse(json.as_bytes()).is_err());
}

#[test]
fn parse_rejects_unsafe_author_nickname() {
    let json = format!(
        r#"{{"v":"12.0","id":"{FIXTURE_ID}","type":"app","tag":"app_msg","mesh":"test","author":"a#b","ts":0,"body":"hi","ext":{{}}}}"#
    );
    assert!(Message::parse(json.as_bytes()).is_err());
}

#[test]
fn parse_rejects_malformed_integrity_fields() {
    // Each history-integrity field (pubkey / sig / prev / parents) must be
    // rejected at `parse` when present but not well-formed lowercase hex,
    // so a crafted value never reaches the fork/DAG indexes or sig verify.
    let base = |extra: &str| {
        format!(
            r#"{{"v":"12.0","id":"{FIXTURE_ID}","type":"app","tag":"app_msg","mesh":"{FIXTURE_MESH}","author":"a-b","ts":0,"body":"hi"{extra},"ext":{{}}}}"#
        )
    };
    // 3KB garbage pubkey, non-hex / wrong-length variants, and a bad hash.
    for extra in [
        format!(r#","pubkey":"{}""#, "z".repeat(3000)),
        r#","pubkey":"AABB""#.to_string(), // uppercase + too short
        r#","sig":"nothex""#.to_string(),
        r#","prev":"xyz""#.to_string(),
        r#","parents":["00"]"#.to_string(), // too short
    ] {
        assert!(
            Message::parse(base(&extra).as_bytes()).is_err(),
            "should reject: {extra}"
        );
    }
    // A well-formed (if unverifiable) 64-hex pubkey still parses — shape
    // only; the signature gate is a separate, later check.
    let ok = base(&format!(r#","pubkey":"{}""#, "ab".repeat(32)));
    assert!(Message::parse(ok.as_bytes()).is_ok());
}

#[test]
fn build_msg_bytes_message() {
    let alice = nick("alice");
    let identity = crate::identity::Identity::generate();
    let (bytes, built) = build_msg_bytes(
        BuildMsgParams {
            tag: AppTag::from("app_msg"),
            mesh: &sid(),
            author: &alice,
            body: MessageBody::from("hello"),
            chain: ChainCtx::genesis(),
        },
        &identity,
    )
    .unwrap();
    assert!(!built.id.as_str().is_empty());
    assert!(!bytes.is_empty());
    let msg = Message::parse(&bytes).unwrap();
    assert_eq!(msg.body.as_str(), "hello");
    assert_eq!(msg.author, alice);
}

mod signing {
    use super::super::{CorrId, Message, MessageKind};
    use crate::identity::Identity;

    fn identity() -> Identity {
        Identity::generate()
    }

    #[test]
    fn signed_message_verifies() {
        let msg =
            Message::fixture(MessageKind::app_broadcast("app_msg"), "hello").signed(&identity());
        assert!(!msg.pubkey.is_empty() && !msg.sig.is_empty());
        assert!(msg.verify_signature());
    }

    #[test]
    fn unsigned_message_does_not_verify() {
        let msg = Message::fixture(MessageKind::app_broadcast("app_msg"), "hello");
        assert!(!msg.verify_signature(), "empty pubkey/sig must not verify");
    }

    #[test]
    fn tampered_body_breaks_signature() {
        let mut msg =
            Message::fixture(MessageKind::app_broadcast("app_msg"), "hello").signed(&identity());
        msg.body = "tampered".into();
        assert!(!msg.verify_signature());
    }

    #[test]
    fn tampered_author_breaks_signature() {
        let mut msg =
            Message::fixture(MessageKind::app_broadcast("app_msg"), "hello").signed(&identity());
        msg.author = "impostor-bot".into();
        assert!(!msg.verify_signature());
    }

    #[test]
    fn tampered_task_target_breaks_signature() {
        let mut msg = Message::fixture(
            MessageKind::app_to("app_status", "calm-otter".into(), None),
            "{}",
        )
        .signed(&identity());
        assert!(msg.verify_signature());
        msg.kind = MessageKind::app_to("app_status", "evil-otter".into(), None);
        assert!(!msg.verify_signature(), "directed `to` is a signed field");
    }

    #[test]
    fn tampered_corr_breaks_signature() {
        let mut msg = Message::fixture(
            MessageKind::app_to("app_req", "calm-otter".into(), Some(CorrId::from("aaaa"))),
            "{}",
        )
        .signed(&identity());
        msg.kind = MessageKind::app_to("app_req", "calm-otter".into(), Some(CorrId::from("bbbb")));
        assert!(!msg.verify_signature(), "`corr` is a signed field");
    }

    #[test]
    fn signature_survives_wire_round_trip() {
        let msg = Message::fixture(MessageKind::app_broadcast("app_msg"), "hi").signed(&identity());
        let parsed = Message::parse(&msg.serialize().unwrap()).unwrap();
        assert!(parsed.verify_signature());
        assert_eq!(parsed.pubkey, msg.pubkey);
    }

    #[test]
    fn unsigned_wire_omits_signature_fields() {
        // The skip-if-empty fields keep an unsigned message byte-identical
        // to the v1 wire, so existing snapshots are unaffected.
        let bytes = Message::fixture(MessageKind::app_broadcast("app_msg"), "hi")
            .serialize()
            .unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert!(!wire.contains("pubkey"), "{wire}");
        assert!(!wire.contains("\"sig\""), "{wire}");
    }
}

mod chain {
    use super::super::{Message, MessageKind};
    use crate::identity::Identity;

    fn msg(body: &str) -> Message {
        Message::fixture(MessageKind::app_broadcast("app_msg"), body)
    }

    #[test]
    fn chained_message_carries_seq_prev_and_verifies() {
        let prev = "a".repeat(64);
        let signed = msg("hi")
            .with_chain(5, Some(prev.clone()))
            .signed(&Identity::generate());
        assert_eq!(signed.seq, Some(5));
        assert_eq!(signed.prev.as_deref(), Some(prev.as_str()));
        assert!(signed.verify_signature());
    }

    #[test]
    fn content_hash_is_stable_and_64_hex() {
        let stamped = msg("x").with_chain(0, None);
        assert_eq!(stamped.content_hash_hex(), stamped.content_hash_hex());
        assert_eq!(stamped.content_hash_hex().len(), 64);
    }

    #[test]
    fn fork_pair_hashes_differently() {
        // The equivocation primitive: two different messages at the same
        // seq hash differently, so a receiver can prove the fork.
        let alpha = msg("alpha").with_chain(1, None);
        let beta = msg("beta").with_chain(1, None);
        assert_ne!(alpha.content_hash_hex(), beta.content_hash_hex());
    }

    #[test]
    fn tampering_seq_breaks_signature() {
        let mut signed = msg("x").with_chain(3, None).signed(&Identity::generate());
        signed.seq = Some(4);
        assert!(!signed.verify_signature(), "seq is a signed field");
    }

    #[test]
    fn parents_are_signed_and_round_trip() {
        let parents = vec!["a".repeat(64), "b".repeat(64)];
        let signed = msg("hi")
            .with_chain(1, None)
            .with_parents(parents.clone())
            .signed(&Identity::generate());
        assert_eq!(signed.parents, parents);
        let parsed = Message::parse(&signed.serialize().unwrap()).unwrap();
        assert_eq!(parsed.parents, parents);
        assert!(parsed.verify_signature());
    }

    #[test]
    fn tampering_parents_breaks_signature() {
        let mut signed = msg("hi")
            .with_parents(vec!["a".repeat(64)])
            .signed(&Identity::generate());
        signed.parents.push("b".repeat(64));
        assert!(!signed.verify_signature(), "parents are signed");
    }
}

mod snapshots {
    use super::super::CorrId;
    use super::{Message, MessageKind, Nickname, PresenceSubtype};

    /// A deterministic broadcast app frame. The body is a JSON payload shaped
    /// like a real consumer's — nested object, unicode, an embedded mesh id —
    /// but belonging to no actual data model, because what this snapshot pins
    /// is the **envelope**: field order, the `tag`/`type` discriminators, and
    /// that a JSON body survives as an opaque string rather than being
    /// re-encoded.
    ///
    /// Pinning a real payload here would make the engine's test suite the
    /// keeper of an application's wire contract. That contract belongs to the
    /// application, whose own suite owns it.
    fn chat_fixture(text: &str) -> Message {
        assert_eq!(text, "What is Rust?", "chat_fixture body is pinned");
        let body = concat!(
            "{\"id\":\"00000000-0000-0000-0000-000000000001\",",
            "\"role\":\"sender\",\"parts\":[{\"text\":\"What is Rust?\"}],",
            "\"scope\":\"test\"}"
        );
        Message::fixture(MessageKind::app_broadcast("app_msg"), body)
    }

    #[test]
    fn snap_wire_message() {
        let msg = chat_fixture("What is Rust?");
        let bytes = msg.serialize().unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        insta::assert_snapshot!(wire);
    }

    /// A **directed** app frame with no correlation id: pins that `to` is
    /// present and `corr` is absent. The body is a nested-object placeholder
    /// for the same reason as [`chat_fixture`]'s — the envelope is the subject.
    #[test]
    fn snap_wire_directed_uncorrelated() {
        let body = concat!(
            "{\"ref\":\"00000000-0000-0000-0000-000000000001\",",
            "\"scope\":\"test\",\"progress\":{\"phase\":\"running\"}}"
        );
        let msg = Message::fixture(
            MessageKind::app_to("app_status", Nickname::from("addressed-nick"), None),
            body,
        );
        let bytes = msg.serialize().unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        insta::assert_snapshot!(wire);
    }

    #[test]
    fn snap_wire_presence_joined() {
        let msg = Message::fixture(
            MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            },
            "",
        );
        let bytes = msg.serialize().unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        insta::assert_snapshot!(wire);
    }

    #[test]
    fn snap_wire_state_merge() {
        // A shared-state change rides `MessageKind::State`; its body is the
        // tagged merge envelope (`k:"merge"`) the reducer parses. Pinning the
        // wire bytes guards the discriminator + RFC 7386 merge shape.
        let msg = Message::fixture(MessageKind::State, r#"{"k":"merge","merge":{"turn":"b"}}"#);
        let bytes = msg.serialize().unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        insta::assert_snapshot!(wire);
    }

    /// A directed **request** frame: correlated by `rpc_id`,
    /// body = a JSON-RPC `{method, params}` envelope.
    #[test]
    fn snap_wire_app_directed_corr_req() {
        let msg = Message::fixture(
            MessageKind::app_to(
                "app_req",
                Nickname::from("addressed-nick"),
                Some(CorrId::from("00000000-0000-0000-0000-0000000000aa")),
            ),
            r#"{"op":"list","args":{}}"#,
        );
        let wire = String::from_utf8(msg.serialize().unwrap()).unwrap();
        insta::assert_snapshot!(wire);
    }

    /// A directed **response** frame, echoing the request's `rpc_id`.
    #[test]
    fn snap_wire_app_directed_corr_resp() {
        let msg = Message::fixture(
            MessageKind::app_to(
                "app_resp",
                Nickname::from("addressed-nick"),
                Some(CorrId::from("00000000-0000-0000-0000-0000000000aa")),
            ),
            r#"{"result":{"items":[]}}"#,
        );
        let wire = String::from_utf8(msg.serialize().unwrap()).unwrap();
        insta::assert_snapshot!(wire);
    }
}

mod prop {
    use proptest::{
        collection::vec as arb_vec, prelude::any, prop_assert, prop_assert_eq, proptest,
        strategy::Strategy,
    };

    use super::super::{
        AppFrameParams, AppTag, MAX_MESSAGE_SIZE, Message, MessageBody, MessageKind, Nickname,
        VERSION,
    };
    use super::sid;

    fn arb_ascii_body() -> impl Strategy<Value = String> {
        arb_vec(0x20u8..0x7Eu8, 0..200).prop_map(|bytes| String::from_utf8(bytes).unwrap())
    }

    fn arb_nickname() -> impl Strategy<Value = Nickname> {
        "[a-z]{3,8}-[a-z]{3,8}".prop_map(|raw| Nickname::new(raw).unwrap())
    }

    proptest! {
        #![proptest_config(crate::proptest_support::config())]
        #[test]
        fn prop_message_round_trip(
            body in arb_ascii_body(),
            author in arb_nickname(),
        ) {
            let body = MessageBody::new(body).unwrap();
            let msg = Message::new_app(&sid(), &author, AppFrameParams { tag: AppTag::from("app_msg"), to: None, corr: None, body });
            let bytes = msg.serialize().unwrap();
            let parsed = Message::parse(&bytes).unwrap();
            prop_assert_eq!(&parsed.body, &msg.body);
            prop_assert_eq!(&parsed.author, &msg.author);
            prop_assert_eq!(&parsed.version, VERSION);
            prop_assert_eq!(parsed.kind, MessageKind::app_broadcast("app_msg"));
        }

        #[test]
        fn prop_presence_round_trip(is_join in any::<bool>()) {
            let test_nick = Nickname::from("test-nick");
            let msg = if is_join {
                Message::new_joined(&sid(), &test_nick)
            } else {
                Message::new_left(&sid(), &test_nick)
            };
            let bytes = msg.serialize().unwrap();
            let parsed = Message::parse(&bytes).unwrap();
            prop_assert_eq!(parsed.kind, msg.kind);
        }

        #[test]
        fn prop_control_chars_rejected(
            // C0 controls excluding the allowed tab/newline/cr.
            body in "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]{1,10}",
        ) {
            prop_assert!(MessageBody::new(body).is_err());
        }

        #[test]
        fn prop_unicode_body_round_trip(
            // `\P{C}` excludes every category-C scalar (all
            // controls included), so `new` can't reject here and the
            // `.unwrap()` is safe. This fuzzes the multibyte round-trip.
            body in "\\P{C}{0,50}",
            author in arb_nickname(),
        ) {
            let body = MessageBody::new(body).unwrap();
            let expected = body.clone();
            let msg = Message::new_app(&sid(), &author, AppFrameParams { tag: AppTag::from("app_msg"), to: None, corr: None, body });
            let bytes = msg.serialize().unwrap();
            let parsed = Message::parse(&bytes).unwrap();
            prop_assert_eq!(&parsed.body, &expected);
        }

        #[test]
        fn prop_serialized_size_within_limit(
            body in arb_ascii_body(),
        ) {
            let msg = Message::new_app(
                &sid(),
                &Nickname::from("nick-name"),
                AppFrameParams {
                    tag: AppTag::from("app_msg"),
                    to: None,
                    corr: None,
                    body: MessageBody::new(body).unwrap(),
                },
            );
            if let Ok(bytes) = msg.serialize() {
                prop_assert!(bytes.len() <= MAX_MESSAGE_SIZE);
            }
        }
    }
}
