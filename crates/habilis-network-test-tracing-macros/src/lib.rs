//! The `test` attribute of `habilis-network-test-tracing`. Import it by name,
//! `use habilis_network_test_tracing::test;`, and every `#[test]` of the module
//! gets a guard that fails the test on a WARN or ERROR event.

use proc_macro::TokenStream;
use syn::{ItemFn, parse_macro_input};

mod expand;

/// A `#[test]` with a guard. A sync test runs its body after the guard starts.
/// An async test runs on a runtime that drops before the guard: a current-thread
/// one, or, with `flavor = "multi_thread"`, one of `worker_threads` workers
/// (the number of cores without it), like `#[tokio::test]`.
#[proc_macro_attribute]
pub fn test(args: TokenStream, item: TokenStream) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);
    match expand::expand(args.into(), function) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}
