//! The **beacon role**: the runtime that co-hosts the rendezvous
//! endpoint — the creator-independent bootstrap anchor.
//!
//! Concept split (see the Concept Glossary in AGENTS.md): *rendezvous*
//! is the seed-derived **identity** (`protocol::crypto`); *beacon*
//! is the **role** a live member plays by binding and serving that
//! identity. This module owns the role; it never derives the identity.
//!
//! A co-hosting member binds a second iroh endpoint to the shared
//! `rendezvous_secret` and glues it into the local mesh via this
//! process's own peer endpoint, so a cold joiner that dials the
//! seed-derived `rendezvous_id` is shuffled into the full mesh.
//!
//! - **Public:** ephemeral port, discoverable by node id via N0 pkarr.
//!   Every member co-hosts permanently; pkarr is last-writer-wins, so
//!   the record always resolves to a recently-live member. Two
//!   `EagerProbed` members can still claim inside each other's probe
//!   window and bind duplicate same-id copies (each capturing its own
//!   bootstrap dial); the event loop's periodic rival re-check shed
//!   (`daemon::event_loop::shed_rival_beacon_if_due`) re-arbitrates, so
//!   the single-co-host invariant holds *eventually*, not at claim time.
//! - **Private:** a deterministic loopback port *ladder* (no
//!   pkarr/DNS). One member per mesh is the beacon, the holder of the
//!   lowest live rung. A member binds the first free rung; on
//!   `AddrInUse` it reads the rung from the answer of a probe task —
//!   *ours* ⇒ the beacon already exists, stay a peer; *foreign* (an
//!   unrelated mesh that derived the same port) ⇒ skip to the next
//!   rung; *no answer* ⇒ wait, and bind the rung only once it has been
//!   silent for the whole reclaim window. A listener that refuses,
//!   closes or fails before a certificate (a busy or starting beacon of
//!   the same mesh) is read as no answer: only a key that the verifier
//!   rejects, or an identity that iroh reads as another, is *foreign*.
//!   So independent private meshes
//!   on one host never hijack each other. A second same-identity
//!   co-host can still stand up when a host is too loaded to answer: a
//!   holder above the first rung yields it on a positive answer of a
//!   lower rung, at the next heal tick, and a holder whose own rung
//!   stops answering sheds it. On the beacon's death its rung frees and
//!   the next heal/reclaim tick re-elects.
//!
//! The rendezvous endpoint never authors app messages; its node id is
//! filtered out of peer-side neighbor handling.

mod bind;
pub(crate) mod claim;
mod contest;
mod dependents;
mod held;
mod lookups;
mod rendezvous;
mod rendezvous_params;
mod rival_probe;
mod rung_ladder;
mod rung_probe;
mod rung_watch;
pub(crate) use contest::{Contest, claim_after_probe, releasable};
pub(crate) use dependents::Dependents;
pub(crate) use held::{Held, Walk, read_busy_rungs, read_ladder, walk_ladder};
pub(crate) use lookups::beacon_lookups;
pub(crate) use rendezvous::{Rendezvous, RendezvousLane};
pub(crate) use rendezvous_params::RendezvousParams;
pub(crate) use rival_probe::{RivalProbe, probe_verdict, spawn_rival_probe};
pub(crate) use rung_ladder::{
    busy_rungs, refresh_holder_rung, rendezvous_addr, rendezvous_addr_without, rung_of,
};
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(crate) use rung_probe::set_blind_rung_probes;
pub(crate) use rung_probe::{rung_answer, rung_is_busy, rung_probes_are_blind};
pub(crate) use rung_watch::{RungRead, RungReport, RungWatch};

#[cfg(test)]
mod tests;
