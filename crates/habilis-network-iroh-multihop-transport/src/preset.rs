//! One-call wiring of the multihop transport onto an iroh endpoint builder.
//!
//! Implementing [`Preset`] lets a caller write
//! `Endpoint::builder(presets::N0).preset(handle)` to register the custom
//! transport, its address lookup, and the path selector together — the
//! same ergonomic shape iroh's own `test_transport` uses.

use iroh::endpoint::Builder;
use iroh::endpoint::presets::Preset;

use crate::MultihopHandle;

impl Preset for MultihopHandle {
    fn apply(self, builder: Builder) -> Builder {
        let transport = self.custom_transport();
        let lookup = self.address_lookup();
        let selector = self.path_selector();
        builder
            .add_custom_transport(transport)
            .address_lookup(lookup)
            .path_selector(selector)
    }
}
