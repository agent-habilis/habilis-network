use super::{DEFAULT_DIRECTORY, DirectorySelection, LookupOpts, MeshName, validate_advertise};

#[test]
fn unset_is_not_advertising() {
    let _guard = ::habilis_network_test_tracing::init();
    let sel = DirectorySelection::Unset;
    assert!(!sel.is_set(), "an unset selection is not advertising");
    assert!(
        sel.directory().is_none(),
        "an unset selection has no directory"
    );
}

#[test]
fn bare_resolves_to_default_directory() {
    let _guard = ::habilis_network_test_tracing::init();
    let sel = DirectorySelection::Default;
    assert!(
        sel.is_set(),
        "a bare selection resolves to the default directory"
    );
    assert_eq!(
        sel.directory().unwrap().as_str(),
        DEFAULT_DIRECTORY,
        "the default directory is named as the default"
    );
}

#[test]
fn named_resolves_to_that_directory() {
    let _guard = ::habilis_network_test_tracing::init();
    let sel = DirectorySelection::Named(MeshName::try_new("gamedev").unwrap());
    assert_eq!(
        sel.directory().unwrap().as_str(),
        "gamedev",
        "a named selection resolves to that directory"
    );
}

#[test]
fn advertise_requires_reachable_mesh() {
    let _guard = ::habilis_network_test_tracing::init();
    // Loopback-only + advertising is rejected.
    let error =
        validate_advertise(&DirectorySelection::Default, &LookupOpts::loopback()).unwrap_err();
    assert!(error.to_string().contains("reachable"), "got: {error}");
    // Reachable + advertising, and loopback + not advertising, are fine.
    assert!(
        validate_advertise(&DirectorySelection::Default, &LookupOpts::public_preset()).is_ok(),
        "advertising a default directory requires a reachable mesh"
    );
    assert!(
        validate_advertise(&DirectorySelection::Unset, &LookupOpts::loopback()).is_ok(),
        "advertising an unset selection requires a reachable mesh"
    );
}
