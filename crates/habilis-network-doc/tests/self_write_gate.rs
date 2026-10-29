//! A gate is built from outside the crate: the type is `#[non_exhaustive]`, so a struct literal is refused there.

use habilis_network_doc::SelfWriteGate;

#[test]
fn a_gate_is_built_from_outside_the_crate() {
    let _guard = ::habilis_network_test_tracing::init();
    let gate = SelfWriteGate::new("peers".to_owned(), "card");
    assert_eq!(gate.map, "peers", "the first argument is the map");
    assert_eq!(gate.field, "card", "the second argument is the field");
}
