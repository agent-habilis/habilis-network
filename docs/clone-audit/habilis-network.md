# Clone and Arc audit: habilis-network

Record for B1 (`Arc`/`Rc` use) and B3 (`.clone()` and `.cloned()` use) in the `habilis-network` crate.

- Date: 2026-10-30
- Count method (B3): non-test `.clone()` and `.cloned()` lines in `crates/habilis-network/src`, counted up to the first `cfg(test)` or `#[test]` line of each file. Test modules and `tests.rs` files are not counted.
- Count method (B1): `Arc` or `Rc` followed by `<`, `::new` or `::clone`, outside comments and test regions.
- Read in full: yes. Every B3 site in the counts below was read with its whole enclosing function in this audit. The `setup.rs` and `recv.rs` sites were read in full in earlier rounds of this audit and checked again when they changed.
- B1: the 65 sites were reviewed by declaration in an earlier round of this audit. None was removed. They are not re-read here.

## Result

- B3: 241 sites before this audit, 213 after. Changes landed as commits on `tracker-tarn-10`, one per file or one per signature change. 
- Removals, by kind:
  - the source is borrowed and the callee takes an owned value, so the callee or caller changed to borrow or move;
  - the value's last use comes before a `&mut` call, so a shared borrow of a field works;
  - the value is moved into a task or closure at its last use;
  - a clone of the whole collection before iterating was replaced with a borrow.
- Kept sites are reasoned per file below. Reason kinds are listed with no line numbers, so this file does not drift when code moves.

## B3, per file (sites kept, after the audit)

Reason kinds: **two owners** (the value is read again after the copy, or is returned), **moved into a task** (a spawned task or FnMut closure needs an owned copy), **borrowed input** (the source is `&T` and the owned field needs a copy), **owned argument** (the callee takes an owned value and the caller keeps the borrow), **lock release** (a copy taken so a lock is not held while work runs), **owned return** (a public accessor or helper returns an owned value).

| File | Sites | Reason kinds |
| --- | ---: | --- |
| daemon/event_loop.rs | 18 | two owners; moved into a task; borrowed setup input consumed later; owned event fields |
| gossip/recv.rs | 15 | owned keys from borrowed messages; two owners; owned constructor argument; moved into a task |
| lookup/peer.rs | 14 | handles returned to the caller; shared underlay legs; borrowed admission copied for an owned table |
| daemon/setup.rs | 13 | two owners (rung sender, rendezvous params, returned name and password); borrowed build fields copied into owned params |
| lookup/relay.rs | 10 | owned iterator from a static or borrowed ladder; owned receiver for `stopped()` (needs `&mut`); owned probe argument |
| gossip/merge_ctx.rs | 8 | two owners (frame, bytes, probe id, proof); moved into a task; owned key from a borrowed probe |
| transport/admission/signal_admission.rs | 8 | lock release; returned hook or guard owns the table; trait object (hub); moved into the eviction task |
| transport/probe/watchers.rs | 7 | moved into a watcher or nudge task; owned address for `negotiate_session` while state is `&mut`; borrowed route copied |
| membership/membership_app.rs | 7 | moved into spawned tasks (nudges, cold send, rung read); owned address while state is mutated |
| daemon/state/event_loop_state.rs | 7 | owned records from borrowed nicknames; owned keys in two maps; state mutated after the copy |
| transport/webrtc/offer.rs | 5 | moved into one offer task |
| transport/underlay_webrtc/tick.rs | 5 | dial task owns its copies; dialed address owned for the task |
| transport/probe/regraft.rs | 5 | owned addresses from borrowed state; state mutated after the copy |
| lookup/build_mesh.rs | 5 | returned gossip and book; endpoint copy for the acceptor; session gate copies a borrow consumed later |
| daemon/state_file.rs | 5 | owned JSON values from borrowed fields |
| daemon/node.rs | 5 | config moved into the daemon task after the copies; owned sender from `&self` |
| blob/store/blob_store.rs | 5 | owned entry fields from borrowed secrets |
| lifecycle/observed.rs | 4 | owned set keys and events from a borrowed message |
| daemon/setup/injected_endpoint.rs | 4 | `transports` consumed by the endpoint build; `InjectedEndpoint` keeps the handles |
| beacon/bind.rs | 4 | handles read again in the returned walk |
| transport/send/deliver.rs | 3 | bytes read on the cold path; pool moved into a task |
| transport/probe/grafts.rs | 3 | borrowed address copied for an owned argument; pool and sender moved into the probe task |
| testing/lane_node.rs | 3 | copies from `&self`; endpoint moved into the struct |
| lifecycle/heartbeat.rs | 3 | owned keys in two sets |
| daemon/heal.rs | 3 | attach copy and replace; handle shared with state; owned rung from a watch borrow |
| blob/consume.rs | 3 | borrowed ticket copied for owned arguments |
| beacon/rung_ladder.rs | 3 | borrowed params; owned relay URL; holder copied for two owners |
| transport/webrtc/rendezvous.rs | 2 | handle by value to a call that takes `&mut state` |
| transport/webrtc/negotiate_session.rs | 2 | handle moved into the offer round while state is `&mut`; endpoint moved into a nudge task |
| testing/log_capture.rs | 2 | writer copied per call in a closure that runs more than once |
| net.rs | 2 | copies from borrowed endpoint info into an owned list |
| lookup/mdns.rs | 2 | two owners (returned lookup; known map and event) |
| lifecycle/membership_update.rs | 2 | owned keys from a borrowed author |
| gossip/lan/lan_grafts.rs | 2 | record and `ask` both need the address; owned list from borrowed records |
| gossip/antientropy.rs | 2 | owned keys; frames read again by the fallback |
| daemon/shutdown.rs | 2 | one sender per signal task |
| daemon/config/event_loop_config.rs | 2 | public accessors return owned handles (`router()` has no caller in this repo) |
| transport/webrtc/retry.rs | 1 | owned list from borrowed addresses |
| transport/probe/pair_to_climb.rs | 1 | route needed by the step input and by the dial map |
| transport/mesh_sender.rs | 1 | owned copy out of a lock guard |
| transport/ipc/listener.rs | 1 | one sender per connection task |
| transport/ipc/client.rs | 1 | owned error field from a borrowed nickname |
| transport/admission/connection_hook.rs | 1 | task owns the admission handle |
| membership/join_options.rs | 1 | borrowed string copied for an owned topic |
| lookup/probe_answer.rs | 1 | address needed by `connect` and by the log |
| lookup/address_book.rs | 1 | book added to the endpoint and returned |
| lifecycle/presence_event.rs | 1 | owned set key from a borrowed message |
| gossip/heal.rs | 1 | task owns an endpoint copy |
| daemon/state/ping_round.rs | 1 | owned map key from a borrowed probe |
| daemon/params/create_params.rs | 1 | value read again |
| blob/produce.rs | 1 | endpoint read again |
| blob/offload_request.rs | 1 | borrowed lookups for an owned argument |
| beacon/rival_probe.rs | 1 | prober used by the probe task |
| beacon/lookups.rs | 1 | borrowed params; the choice owns its rung |

Files changed by this audit and now at zero clones: `transport/admission/inner.rs`, `transport/webrtc/session_policy.rs`, `lookup/endpoint.rs`, `lookup/capability.rs`, `transport/underlay_webrtc/plan.rs`, `gossip/recv.rs` (one removed; the file still has 15 kept sites above), `daemon/event_loop.rs` (three removed), `lookup/peer.rs` (two removed), `gossip/merge_ctx.rs` (two removed), `daemon/setup.rs` (six removed), `membership/membership_app.rs` (one removed), `lifecycle/heartbeat.rs` (one removed).

## B1, per file (`Arc` and `Rc` sites, kept)

Status: the 65 sites were reviewed by declaration in an earlier round of this audit, and none was removed. This pass did not re-read them, so no reason kinds are given per file here. The counts are from the `Arc`/`Rc` site script on the current tree.

| File | Sites |
| --- | ---: |
| daemon/event_loop.rs | 13 |
| transport/admission/signal_admission.rs | 9 |
| transport/admission.rs | 5 |
| lookup/tests.rs | 4 |
| daemon/setup/setup_params.rs | 4 |
| blob/produce.rs | 4 |
| gossip/split/mesh_receiver.rs | 3 |
| transport/outbox/resend_outbox.rs | 2 |
| transport/mesh_sender.rs | 2 |
| transport/admission/inner.rs | 2 |
| membership/membership_event.rs | 2 |
| gossip/split.rs | 2 |
| daemon/config/event_loop_config.rs | 2 |
| blob/produce/blob_server.rs | 2 |
| transport/underlay_webrtc/allowed.rs | 1 |
| transport/ipc/listener.rs | 1 |
| transport/admission/victims.rs | 1 |
| testing/log_capture.rs | 1 |
| testing.rs | 1 |
| membership/join_options.rs | 1 |
| daemon/state/state_init.rs | 1 |
| daemon/state/event_loop_state.rs | 1 |
| daemon/setup.rs | 1 |

## B1 second pass (2026-10-30)

Every `Arc`/`Rc` site was read again with its enclosing function. Struct field declarations are the type of the shared value, not a copy, so they are not counted as removals.

- Removed: 1 (the event loop's `identity` clone, below).
- Kept, with the reason per site type:
  - Shared between an owner and a spawned task or a closure that outlives the borrow: the IPC accept loop's sink (`spawn_ipc_rx`), the outbox's dropped counter, the split's high-water gauge, the mesh sender's gossip handle, the `SetupParams` sink, the loop's identity (held across `&mut state`, as the loop's comment says).
  - Owned value that outlives a lock or a call: the victims' hub copy (`take_victims`, used after the lock is dropped), the slot-freed and route-wake notifiers (the loop's `select!` holds them across state mutation).
  - Returned to a caller that needs an owned handle: `join`'s sink, `json_sink`, `high_water_gauge`, the multihop route-wake handle.
  - Trait objects the API takes as `Arc`: the signal admission's hub, the sink of `SetupParams`.
- Removed: the event loop's `identity` clone (`daemon/event_loop.rs`, `initial_state`). `initial_state` now takes the identity and the secrets by value, and `run_checked` moves them out of the mesh. The split that keeps `run_checked` under its 120-line limit: the control socket and the quit channel are named helpers (`control_socket`, `quit_channel`), each with a host and a browser variant.
- Test sites (`lookup/tests.rs`, the `admission.rs` test module) are outside the non-test rule and are kept.
