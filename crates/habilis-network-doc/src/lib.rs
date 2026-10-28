//! The shared-document engine backing the `state` and `meta` channels.
//!
//! Each channel is an [`automerge`] CRDT. A local write is expressed as an
//! RFC 7386-style JSON merge (the unchanged `state|meta merge` surface),
//! translated into one automerge change; peers exchange those changes and
//! automerge merges them conflict-free — so we no longer own an ordered-log
//! fold. Convergence is automerge's job; ours is authenticity.
//!
//! Every change is carried inside a signed [`Message`](habilis_network_protocol::Message),
//! and every change is authorized before it touches the live doc. A channel
//! configured with a [`SelfWriteGate`] holds a per-peer map keyed by nickname in
//! which one field belongs to the peer it names: [`MeshDoc::ingest`] applies the
//! change to a throwaway fork first and rejects it if it would alter any *other*
//! peer's field. That field carries the peer's cryptographic identity, so a
//! forgery must converge nowhere — and because every honest member runs the same
//! gate before applying, it does.
//!
//! The engine needs the gate's *shape* and *rule*, never its meaning: it plants a
//! byte-identical genesis change so every replica agrees on the map's object
//! identity, and it compares before/after. What the guarded field represents is
//! the application's business.
//!
//! Changes arriving before their causal dependencies (out-of-order backfill) are
//! held in `pending` and drained — through the same gate — once their deps land,
//! so the gate is never bypassed by dependency buffering.

//! # Example
//!
//! ```
//! use habilis_network_doc::MeshDoc;
//!
//! let doc = MeshDoc::new_ungated();
//! assert!(doc.to_json().is_object());
//! ```

pub mod wire;

mod doc_error;

pub use doc_error::DocError;

mod mesh_doc;

pub use mesh_doc::{Ingested, MeshDoc, SelfWriteGate};
