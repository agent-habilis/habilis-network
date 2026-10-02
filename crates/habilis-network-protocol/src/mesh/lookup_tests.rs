use super::{DEFAULT_DIRECTORY, DirectorySelection, LookupOpts, MeshName, validate_advertise};

#[test]
fn unset_is_not_advertising() {
    let sel = DirectorySelection::Unset;
    assert!(!sel.is_set());
    assert!(sel.directory().is_none());
}

#[test]
fn bare_resolves_to_default_directory() {
    let sel = DirectorySelection::Default;
    assert!(sel.is_set());
    assert_eq!(sel.directory().unwrap().as_str(), DEFAULT_DIRECTORY);
}

#[test]
fn named_resolves_to_that_directory() {
    let sel = DirectorySelection::Named(MeshName::new("gamedev").unwrap());
    assert_eq!(sel.directory().unwrap().as_str(), "gamedev");
}

#[test]
fn advertise_requires_reachable_mesh() {
    // Loopback-only + advertising is rejected.
    let error =
        validate_advertise(&DirectorySelection::Default, &LookupOpts::loopback()).unwrap_err();
    assert!(error.to_string().contains("reachable"), "got: {error}");
    // Reachable + advertising, and loopback + not advertising, are fine.
    assert!(validate_advertise(&DirectorySelection::Default, &LookupOpts::public_preset()).is_ok());
    assert!(validate_advertise(&DirectorySelection::Unset, &LookupOpts::loopback()).is_ok());
}
