use super::{
    AppFrameParams, AppTag, AppTagError, BuildMsgParams, ChainCtx, CorrIdError, MeshId, Message,
    MessageBody, MessageId, MessageKind, Nickname, PresenceSubtype, build_msg_bytes,
};
use habilis_network_test_tracing::test;

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
            tag: AppTag::try_new("app_msg").expect("a valid app tag"),
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
fn app_tag_constructor_rejects_an_invalid_value() {
    assert_eq!(
        AppTag::try_new("not-valid!"),
        Err(AppTagError::Invalid),
        "a tag with a dash is refused"
    );
}

#[test]
fn correlation_id_constructor_rejects_an_invalid_value() {
    assert_eq!(
        super::CorrId::try_new(""),
        Err(CorrIdError::Invalid),
        "an empty id is refused"
    );
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

/// A browser builds and signs a link-state advertisement as a native node does: the builder
/// needs no operating system, so it must exist with the `host` feature off.
#[test]
fn a_link_state_message_is_built_signed_and_round_tripped_on_every_target() {
    let identity = crate::identity::Identity::generate();
    let msg = Message::new_link_state(&sid(), &nick("word-word"), MessageBody::from("{}"))
        .sign(&identity);
    assert!(msg.verify_signature());
    let parsed = Message::parse(msg.serialize().unwrap().as_bytes()).unwrap();
    assert_eq!(parsed.kind, MessageKind::LinkState);
    assert_eq!(parsed.body.as_str(), "{}");
}

#[test]
fn test_pong_round_trip() {
    let target = nick("pinger-here");
    let probe = MessageId::random();
    let msg = Message::new_pong(&sid(), &nick("word-word"), target.clone(), &probe);
    let bytes = msg.serialize().unwrap();
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(parsed.kind, MessageKind::Pong { to: target, probe });
    assert_eq!(parsed.body.as_str(), "");
}

#[test]
fn test_task_status_round_trip() {
    let target = nick("calm-otter");
    let msg = Message::new_app(
        &sid(),
        &nick("word-word"),
        AppFrameParams {
            tag: AppTag::try_new("app_status").expect("a valid app tag"),
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
            tag: AppTag::try_new("app_msg").expect("a valid app tag"),
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
const FIXTURE_MESH: &str = "DqrLWcbLaiVzMV2mvqefxWxWmgLCYmGWAK5jCxeTgFqc6dk1MQrfiqay2YxkRe";

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
    // Each malformed field comes with a well-formed partner, so that the pairing rule (a key
    // without a signature) cannot be the reason for the reject, and the error names the field.
    let good_sig = format!(r#","sig":"{}""#, "cd".repeat(64));
    let good_key = format!(r#","pubkey":"{}""#, "ab".repeat(32));
    for (extra, reason) in [
        // 3KB garbage pubkey, and an uppercase one that is also too short.
        (
            format!(r#","pubkey":"{}"{good_sig}"#, "z".repeat(3000)),
            "malformed pubkey",
        ),
        (format!(r#","pubkey":"AABB"{good_sig}"#), "malformed pubkey"),
        (
            format!(r#"{good_key},"sig":"nothex""#),
            "malformed signature",
        ),
        (
            format!(r#"{good_key},"sig":"{}""#, "CD".repeat(64)),
            "malformed signature",
        ),
        (r#","prev":"xyz""#.to_string(), "malformed prev hash"),
        // Too short.
        (r#","parents":["00"]"#.to_string(), "malformed parent hash"),
    ] {
        let error =
            Message::parse(base(&extra).as_bytes()).expect_err(&format!("should reject: {extra}"));
        assert_eq!(error.to_string(), reason, "for: {extra}");
    }
    // A well-formed (if unverifiable) 64-hex pubkey with a 128-hex signature still parses —
    // shape only; the signature gate is a separate, later check.
    let ok = base(&format!(
        r#","pubkey":"{}","sig":"{}""#,
        "ab".repeat(32),
        "cd".repeat(64)
    ));
    assert!(Message::parse(ok.as_bytes()).is_ok());
    // A pubkey alone no longer parses: a message holds a key and its signature, or neither.
    let key_only = base(&format!(r#","pubkey":"{}""#, "ab".repeat(32)));
    assert!(Message::parse(key_only.as_bytes()).is_err());
}

#[test]
fn build_msg_bytes_message() {
    let alice = nick("alice");
    let identity = crate::identity::Identity::generate();
    let (bytes, built) = build_msg_bytes(
        BuildMsgParams {
            tag: AppTag::try_new("app_msg").expect("a valid app tag"),
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
    let msg = Message::parse(bytes.as_bytes()).unwrap();
    assert_eq!(msg.body.as_str(), "hello");
    assert_eq!(msg.author, alice);
}

mod signing {
    use super::super::{CorrId, Message, MessageKind};
    use crate::identity::Identity;
    use habilis_network_test_tracing::test;

    fn identity() -> Identity {
        Identity::generate()
    }

    #[test]
    fn signed_message_verifies() {
        let msg =
            Message::fixture(MessageKind::app_broadcast("app_msg"), "hello").sign(&identity());
        assert!(msg.signer.is_some());
        assert!(msg.verify_signature());
    }

    #[test]
    fn unsigned_message_does_not_verify() {
        let msg = Message::fixture(MessageKind::app_broadcast("app_msg"), "hello");
        assert!(!msg.verify_signature(), "empty pubkey/sig must not verify");
    }

    #[test]
    fn tampered_body_breaks_signature() {
        let mut msg = Message::fixture(MessageKind::app_broadcast("app_msg"), "hello")
            .sign(&identity())
            .into_message();
        msg.body = "tampered".into();
        assert!(!msg.verify_signature());
    }

    #[test]
    fn tampered_author_breaks_signature() {
        let mut msg = Message::fixture(MessageKind::app_broadcast("app_msg"), "hello")
            .sign(&identity())
            .into_message();
        msg.author = "impostor-bot".into();
        assert!(!msg.verify_signature());
    }

    #[test]
    fn tampered_task_target_breaks_signature() {
        let mut msg = Message::fixture(
            MessageKind::app_to("app_status", "calm-otter".into(), None),
            "{}",
        )
        .sign(&identity())
        .into_message();
        assert!(msg.verify_signature());
        msg.kind = MessageKind::app_to("app_status", "evil-otter".into(), None);
        assert!(!msg.verify_signature(), "directed `to` is a signed field");
    }

    #[test]
    fn tampered_corr_breaks_signature() {
        let mut msg = Message::fixture(
            MessageKind::app_to(
                "app_req",
                "calm-otter".into(),
                Some(CorrId::try_new("aaaa").expect("a valid correlation id")),
            ),
            "{}",
        )
        .sign(&identity())
        .into_message();
        msg.kind = MessageKind::app_to(
            "app_req",
            "calm-otter".into(),
            Some(CorrId::try_new("bbbb").expect("a valid correlation id")),
        );
        assert!(!msg.verify_signature(), "`corr` is a signed field");
    }

    #[test]
    fn signature_survives_wire_round_trip() {
        let msg = Message::fixture(MessageKind::app_broadcast("app_msg"), "hi").sign(&identity());
        let parsed = Message::parse(msg.serialize().unwrap().as_bytes()).unwrap();
        assert!(parsed.verify_signature());
        assert_eq!(parsed.signer, msg.signer);
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
    use crate::ContentHash;
    use crate::identity::Identity;
    use habilis_network_test_tracing::test;

    fn msg(body: &str) -> Message {
        Message::fixture(MessageKind::app_broadcast("app_msg"), body)
    }

    #[test]
    fn chained_message_carries_seq_prev_and_verifies() {
        let prev = ContentHash::from_bytes([0xaa; 32]);
        let signed = msg("hi")
            .with_chain(5, Some(prev))
            .sign(&Identity::generate());
        assert_eq!(signed.seq, Some(5));
        assert_eq!(signed.prev, Some(prev));
        assert!(signed.verify_signature());
    }

    #[test]
    fn content_hash_is_stable_and_64_hex() {
        let stamped = msg("x").with_chain(0, None);
        assert_eq!(stamped.content_hash(), stamped.content_hash());
        assert_eq!(stamped.content_hash().to_string().len(), 64);
    }

    #[test]
    fn fork_pair_hashes_differently() {
        // The equivocation primitive: two different messages at the same
        // seq hash differently, so a receiver can prove the fork.
        let alpha = msg("alpha").with_chain(1, None);
        let beta = msg("beta").with_chain(1, None);
        assert_ne!(alpha.content_hash(), beta.content_hash());
    }

    #[test]
    fn tampering_seq_breaks_signature() {
        let mut signed = msg("x")
            .with_chain(3, None)
            .sign(&Identity::generate())
            .into_message();
        signed.seq = Some(4);
        assert!(!signed.verify_signature(), "seq is a signed field");
    }

    #[test]
    fn parents_are_signed_and_round_trip() {
        let parents = vec![
            ContentHash::from_bytes([0xaa; 32]),
            ContentHash::from_bytes([0xbb; 32]),
        ];
        let signed = msg("hi")
            .with_chain(1, None)
            .with_parents(parents.clone())
            .sign(&Identity::generate());
        assert_eq!(signed.parents, parents);
        let parsed = Message::parse(signed.serialize().unwrap().as_bytes()).unwrap();
        assert_eq!(parsed.parents, parents);
        assert!(parsed.verify_signature());
    }

    #[test]
    fn tampering_parents_breaks_signature() {
        let mut signed = msg("hi")
            .with_parents(vec![ContentHash::from_bytes([0xaa; 32])])
            .sign(&Identity::generate())
            .into_message();
        signed.parents.push(ContentHash::from_bytes([0xbb; 32]));
        assert!(!signed.verify_signature(), "parents are signed");
    }
}

mod snapshots {
    use super::super::CorrId;
    use super::{Message, MessageKind, Nickname, PresenceSubtype};
    use habilis_network_test_tracing::test;

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
                Some(
                    CorrId::try_new("00000000-0000-0000-0000-0000000000aa")
                        .expect("a valid correlation id"),
                ),
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
                Some(
                    CorrId::try_new("00000000-0000-0000-0000-0000000000aa")
                        .expect("a valid correlation id"),
                ),
            ),
            r#"{"result":{"items":[]}}"#,
        );
        let wire = String::from_utf8(msg.serialize().unwrap()).unwrap();
        insta::assert_snapshot!(wire);
    }
}

mod prop {
    use habilis_network_test_tracing::test;
    use proptest::collection::vec as arb_vec;
    use proptest::prelude::any;
    use proptest::strategy::Strategy;
    use proptest::{prop_assert, prop_assert_eq, proptest};

    use super::super::{
        AppFrameParams, AppTag, MAX_MESSAGE_SIZE, Message, MessageBody, MessageKind, Nickname,
        VERSION,
    };

    fn arb_ascii_body() -> impl Strategy<Value = String> {
        arb_vec(0x20u8..0x7Eu8, 0..200).prop_map(|bytes| String::from_utf8(bytes).unwrap())
    }

    fn arb_nickname() -> impl Strategy<Value = Nickname> {
        "[a-z]{3,8}-[a-z]{3,8}".prop_map(|raw| Nickname::try_new(raw).unwrap())
    }

    proptest! {
        #![proptest_config(crate::proptest_support::config())]
        #[test]
        fn prop_message_round_trip(
            body in arb_ascii_body(),
            author in arb_nickname(),
        ) {
            let body = MessageBody::try_new(body).unwrap();
            let msg = Message::new_app(&super::sid(), &author, AppFrameParams { tag: AppTag::try_new("app_msg").expect("a valid app tag"), to: None, corr: None, body });
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
                Message::new_joined(&super::sid(), &test_nick)
            } else {
                Message::new_left(&super::sid(), &test_nick)
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
            prop_assert!(MessageBody::try_new(body).is_err());
        }

        #[test]
        fn prop_unicode_body_round_trip(
            // `\P{C}` excludes every category-C scalar (all
            // controls included), so `new` can't reject here and the
            // `.unwrap()` is safe. This fuzzes the multibyte round-trip.
            body in "\\P{C}{0,50}",
            author in arb_nickname(),
        ) {
            let body = MessageBody::try_new(body).unwrap();
            let expected = body.clone();
            let msg = Message::new_app(&super::sid(), &author, AppFrameParams { tag: AppTag::try_new("app_msg").expect("a valid app tag"), to: None, corr: None, body });
            let bytes = msg.serialize().unwrap();
            let parsed = Message::parse(&bytes).unwrap();
            prop_assert_eq!(&parsed.body, &expected);
        }

        #[test]
        fn prop_serialized_size_within_limit(
            body in arb_ascii_body(),
        ) {
            let msg = Message::new_app(
                &super::sid(),
                &Nickname::from("nick-name"),
                AppFrameParams {
                    tag: AppTag::try_new("app_msg").expect("a valid app tag"),
                    to: None,
                    corr: None,
                    body: MessageBody::try_new(body).unwrap(),
                },
            );
            if let Ok(bytes) = msg.serialize() {
                prop_assert!(bytes.len() <= MAX_MESSAGE_SIZE);
            }
        }
    }
}

#[test]
fn a_resend_trailer_is_outside_the_frame_and_the_signature() {
    let identity = super::identity::Identity::generate();
    let msg = Message::new_app(
        &sid(),
        &nick("word-word"),
        AppFrameParams {
            tag: AppTag::try_new("app_msg").expect("a valid app tag"),
            to: None,
            corr: None,
            body: MessageBody::from("Hello, world!"),
        },
    )
    .sign(&identity);
    let frame = msg.serialize().unwrap().as_bytes().to_vec();

    let first = super::wire_with_resend_nonce(&frame, 7);
    let second = super::wire_with_resend_nonce(&frame, 8);

    assert_ne!(first, second, "each nonce gives the payload a new name");
    assert_ne!(first, frame);
    assert_eq!(first.len(), frame.len() + super::RESEND_TRAILER_LEN);
    let (parsed, nonce) = Message::parse_wire(&first).unwrap();
    assert_eq!(nonce, Some(7));
    assert_eq!(parsed.id, msg.id);
    assert!(
        parsed.verify_signature_with(&parsed.canonical_bytes()),
        "the signature does not cover the trailer"
    );
    let (plain, no_nonce) = Message::parse_wire(&frame).unwrap();
    assert_eq!(no_nonce, None);
    assert_eq!(plain.id, msg.id);
}

#[test]
fn a_reader_without_the_trailer_fails_closed_on_a_resend() {
    let msg = Message::new_alive(&sid(), &nick("word-word"));
    let frame = msg.serialize().unwrap();
    let wire = super::wire_with_resend_nonce(&frame, 1);
    assert!(
        Message::parse(&wire).is_err(),
        "Message::parse must reject the trailer, not skip it"
    );
}

#[test]
fn a_frame_of_the_largest_size_still_parses_with_the_trailer() {
    let msg = Message::new_alive(&sid(), &nick("word-word"));
    let mut frame = msg.serialize().unwrap();
    // JSON whitespace pads the frame up to the cap.
    frame.resize(habilis_network_util::consts::MAX_MESSAGE_SIZE, b' ');
    let wire = super::wire_with_resend_nonce(&frame, u64::MAX);
    assert_eq!(
        wire.len(),
        habilis_network_util::consts::MAX_MESSAGE_SIZE + super::RESEND_TRAILER_LEN
    );
    let (parsed, nonce) = Message::parse_wire(&wire).unwrap();
    assert_eq!(nonce, Some(u64::MAX));
    assert_eq!(parsed.id, msg.id);
}

/// The wire form of a signed message, captured from the code at the base commit with a fixed key
/// (`SecretKey::from_bytes(&[7; 32])`). A change that moves one byte of it is a wire change.
// The verified.rs doctests repeat this literal, so a change to it touches both files.
const SIGNED_WIRE: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;

/// The same message with no `pubkey` and no `sig` key: the canonical pre-signing form.
const UNSIGNED_WIRE: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;

/// [`UNSIGNED_WIRE`] with both keys present and empty.
const EMPTY_KEYS_WIRE: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"","sig":"","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;

/// [`SIGNED_WIRE`] with the `sig` key removed: a key and no signature.
const KEY_ONLY_WIRE: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;

const SIGNED_PUBKEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
/// The canonical bytes of [`SIGNED_WIRE`], hex, one line per piece: a 4-byte little-endian length,
/// then the field.
const SIGNED_CANONICAL_HEX: &str = concat!(
    "10000000",
    "686162696c69732d6d6573682f6d7367",
    "04000000",
    "31322e30",
    "24000000",
    "30303030303030302d303030302d303030302d303030302d303030303030303030303031",
    "1e000000",
    "7b2274797065223a22617070222c22746167223a226170705f6d7367227d",
    "3e000000",
    "4835473869554a66783555707258466d7053474c544c706a4b55354147686a5164347041616359334e535a36777937325039777641647375376b67774736",
    "09000000",
    "616c6963652d626f74",
    "08000000",
    "00f1536500000000",
    "0d000000",
    "68656c6c6f2c20676f6c64656e",
    "40000000",
    "65613461366336336532396335323061626566353530376231333265633566393935343737366165626562653762393234323165656136393134343664323263",
    "08000000",
    "0300000000000000",
    "40000000",
    "31313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131",
    "44000000",
    "5b2232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232225d",
    "04000000",
    "6e756c6c",
    "02000000",
    "7b7d"
);
/// The canonical bytes of [`UNSIGNED_WIRE`]. The `pubkey` field is the empty `00000000`.
const UNSIGNED_CANONICAL_HEX: &str = concat!(
    "10000000",
    "686162696c69732d6d6573682f6d7367",
    "04000000",
    "31322e30",
    "24000000",
    "30303030303030302d303030302d303030302d303030302d303030303030303030303031",
    "1e000000",
    "7b2274797065223a22617070222c22746167223a226170705f6d7367227d",
    "3e000000",
    "4835473869554a66783555707258466d7053474c544c706a4b55354147686a5164347041616359334e535a36777937325039777641647375376b67774736",
    "09000000",
    "616c6963652d626f74",
    "08000000",
    "00f1536500000000",
    "0d000000",
    "68656c6c6f2c20676f6c64656e",
    "00000000",
    "",
    "08000000",
    "0300000000000000",
    "40000000",
    "31313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131",
    "44000000",
    "5b2232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232225d",
    "04000000",
    "6e756c6c",
    "02000000",
    "7b7d"
);

fn hex(bytes: &[u8]) -> String {
    crate::identity::encode_hex(bytes)
}

/// Golden: the bytes of a signed message are fixed. The JSON text, the signed bytes, the content
/// hash, and the dedup key each equal a literal captured at the base commit.
#[test]
fn a_signed_message_keeps_its_wire_form() {
    let parsed = Message::parse(SIGNED_WIRE.as_bytes()).expect("the signed literal parses");
    assert!(
        parsed.verify_signature(),
        "the literal carries a valid signature"
    );
    assert_eq!(parsed.author_key().unwrap().to_string(), SIGNED_PUBKEY);
    assert_eq!(
        serde_json::to_string(&super::Wire(&parsed)).unwrap(),
        SIGNED_WIRE
    );
    assert_eq!(hex(&parsed.canonical_bytes()), SIGNED_CANONICAL_HEX);
    assert_eq!(
        parsed.content_hash().to_string(),
        "2e680fcb3a8d77ef027e722046200cf0b07c8d77d7572b7e0712556bfaf76e0e"
    );
    assert_eq!(
        hex(parsed.dedup_key().as_bytes()),
        "c7ba26a2ed0d21f0e8913dd8b4456086"
    );
}

/// Golden: a message with no `pubkey` key and no `sig` key parses, reads as unsigned, and does
/// not verify. Its JSON stays free of the two keys.
#[test]
fn a_message_with_no_key_fields_parses_as_unsigned() {
    let parsed = Message::parse(UNSIGNED_WIRE.as_bytes()).expect("the unsigned literal parses");
    assert!(parsed.signer.is_none());
    assert!(!parsed.verify_signature());
    assert_eq!(
        serde_json::to_string(&super::Wire(&parsed)).unwrap(),
        UNSIGNED_WIRE
    );
    assert_eq!(hex(&parsed.canonical_bytes()), UNSIGNED_CANONICAL_HEX);
    assert_eq!(
        parsed.content_hash().to_string(),
        "7c4c2cb3f17ce751fec8a53c2d01198b424ce71aad8f5eb5747541222bd4c263"
    );
}

/// Golden: `"pubkey": ""` and `"sig": ""` parse as the unsigned form. The keys do not come back on
/// serialize, and the signed bytes equal those of a message with no key fields.
#[test]
fn empty_key_fields_parse_as_unsigned_and_serialize_without_the_keys() {
    let parsed = Message::parse(EMPTY_KEYS_WIRE.as_bytes()).expect("empty key fields parse");
    assert!(parsed.signer.is_none());
    assert!(!parsed.verify_signature());
    assert_eq!(
        serde_json::to_string(&super::Wire(&parsed)).unwrap(),
        UNSIGNED_WIRE
    );
    assert_eq!(hex(&parsed.canonical_bytes()), UNSIGNED_CANONICAL_HEX);
}

/// A key with no signature is a parse error, and so is a signature with no key: a message holds
/// both or neither. This is a decision of wave 2 (the parser only: no sender emits either, so
/// no emitted byte moves). Before it, the key-only literal parsed, kept the key, and did not
/// verify.
#[test]
fn a_key_with_no_signature_is_rejected_and_so_is_a_signature_with_no_key() {
    let no_sig = Message::parse(KEY_ONLY_WIRE.as_bytes()).expect_err("a key with no signature");
    assert_eq!(no_sig.to_string(), "pubkey without a signature");

    let sig_only = SIGNED_WIRE.replace(&format!(r#""pubkey":"{SIGNED_PUBKEY}","#), "");
    assert!(!sig_only.contains("pubkey"));
    let no_key = Message::parse(sig_only.as_bytes()).expect_err("a signature with no key");
    assert_eq!(no_key.to_string(), "signature without a pubkey");
}

mod verified {
    use super::super::{Message, MessageKind, Verified};
    use super::SIGNED_WIRE;
    use crate::identity::Identity;

    fn msg(body: &str) -> Message {
        Message::fixture(MessageKind::app_broadcast("app_msg"), body)
    }

    #[test]
    fn a_signed_message_verifies_and_keeps_its_key() {
        let identity = Identity::generate();
        let key = identity.author_key();
        let verified = msg("hello").sign(&identity);
        assert_eq!(verified.key(), key);
        let back = verified
            .into_message()
            .verify()
            .expect("a signed message verifies");
        assert_eq!(back.author_key(), Some(key));
    }

    #[test]
    fn an_unsigned_message_is_given_back_by_verify() {
        let unsigned = msg("hello");
        let back = unsigned
            .clone()
            .verify()
            .expect_err("an unsigned message does not verify");
        assert_eq!(back.body.as_str(), unsigned.body.as_str());
        assert!(back.signer.is_none());
    }

    #[test]
    fn a_tampered_body_fails_verify_and_is_given_back() {
        let mut tampered = msg("hello").sign(&Identity::generate()).into_message();
        tampered.body = "tampered".into();
        let back = tampered
            .verify()
            .expect_err("a tampered body does not verify");
        assert_eq!(back.body.as_str(), "tampered");
    }

    #[test]
    fn a_fixture_keeps_the_signature_as_parsed() {
        let signed = msg("hello").sign(&Identity::generate());
        let wire = signed.serialize().expect("serialize");
        let parsed = Message::parse(wire.as_bytes()).expect("parses");

        let unmodified = Verified::fixture_with_signature(parsed.clone());
        assert_eq!(
            unmodified.serialize().expect("serialize").as_bytes(),
            wire.as_bytes(),
            "the original signature is kept"
        );
        assert!(unmodified.into_message().verify().is_ok());

        let mut tampered = parsed;
        tampered.body = "tampered".into();
        let forged = Verified::fixture_with_signature(tampered);
        let replayed =
            Message::parse(forged.serialize().expect("serialize").as_bytes()).expect("parses");
        assert!(
            replayed.verify().is_err(),
            "a body edited after signing does not verify at the receiver"
        );
    }

    #[test]
    fn verify_canonical_refuses_an_edited_clone() {
        let original = msg("hello").sign(&Identity::generate()).into_message();
        let (_, canonical) = original
            .clone()
            .verify_canonical()
            .expect("the original verifies");
        assert_eq!(canonical, original.canonical_bytes());

        let mut edited = original;
        edited.body = "edited".into();
        assert!(
            edited.clone().verify_canonical().is_err(),
            "an edited clone does not verify, so no proof is made over its bytes"
        );
        assert_ne!(edited.canonical_bytes(), canonical);
    }

    #[test]
    fn verified_serializes_to_the_same_bytes_as_its_message() {
        let parsed = Message::parse(SIGNED_WIRE.as_bytes()).expect("the signed literal parses");
        let verified = parsed.verify().expect("the golden signature verifies");
        assert_eq!(serde_json::to_string(&verified).unwrap(), SIGNED_WIRE);
    }
}
