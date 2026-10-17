//! The `test` attribute of `habilis-network-test-tracing`. Import it by name,
//! `use habilis_network_test_tracing::test;`, and every `#[test]` of the module
//! gets a guard that fails the test on a WARN or ERROR event.

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser as _;
use syn::punctuated::Punctuated;
use syn::{Expr, ExprLit, ItemFn, Lit, Meta, Token, parse_macro_input};

/// A `#[test]` with a guard. A sync test runs its body after the guard starts.
/// An async test runs on a runtime that drops before the guard: a current-thread
/// one, or, with `flavor = "multi_thread"`, one of `worker_threads` workers
/// (the number of cores without it), like `#[tokio::test]`.
#[proc_macro_attribute]
pub fn test(args: TokenStream, item: TokenStream) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);
    match expand(args.into(), function) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn expand(
    args: proc_macro2::TokenStream,
    mut function: ItemFn,
) -> syn::Result<proc_macro2::TokenStream> {
    let options = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(args)?;
    let mut multi_thread = false;
    let mut workers = None;
    for option in &options {
        let Meta::NameValue(pair) = option else {
            return Err(syn::Error::new_spanned(option, "expected `name = value`"));
        };
        let Expr::Lit(ExprLit { lit, .. }) = &pair.value else {
            return Err(syn::Error::new_spanned(&pair.value, "expected a literal"));
        };
        match (
            pair.path.get_ident().map(ToString::to_string).as_deref(),
            lit,
        ) {
            (Some("flavor"), Lit::Str(flavor)) if flavor.value() == "multi_thread" => {
                multi_thread = true;
            }
            (Some("flavor"), Lit::Str(flavor)) if flavor.value() == "current_thread" => {}
            (Some("worker_threads"), Lit::Int(count)) => workers = Some(count.clone()),
            _ => {
                return Err(syn::Error::new_spanned(
                    option,
                    "expected `flavor = \"multi_thread\"` or `worker_threads = N`",
                ));
            }
        }
    }
    let block = &function.block;
    let body = if function.sig.asyncness.take().is_some() {
        if multi_thread {
            let workers = workers.map_or_else(
                || quote!(::std::thread::available_parallelism().map_or(1, usize::from)),
                |count| quote!(#count),
            );
            quote!({
                let guard = ::habilis_network_test_tracing::init();
                ::habilis_network_test_tracing::run_multi_thread(guard, #workers, async #block)
            })
        } else {
            quote!({
                let guard = ::habilis_network_test_tracing::init();
                ::habilis_network_test_tracing::run(guard, async #block)
            })
        }
    } else if multi_thread || workers.is_some() {
        return Err(syn::Error::new_spanned(
            &function.sig,
            "`flavor` and `worker_threads` need an async test",
        ));
    } else {
        quote!({
            let _guard = ::habilis_network_test_tracing::__sync_guard();
            #block
        })
    };
    function.block = syn::parse2(body)?;
    function
        .attrs
        .insert(0, syn::parse_quote!(#[::core::prelude::v1::test]));
    Ok(quote!(#function))
}
