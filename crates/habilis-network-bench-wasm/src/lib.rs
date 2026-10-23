//! One browser endpoint of the transport benchmark, as free functions a page
//! puts on `window.bench`.
//!
//! Everything crosses the JS boundary as a string: the JSEP envelopes as JSON
//! (the runner ferries them between two tabs verbatim), ids as hex, and each
//! result as a JSON object. The runner cannot await a promise through CDP, so
//! the page wraps every call in a completion flag; nothing here knows that.
//!
//! One endpoint per page, held in a thread-local: the browser is
//! single-threaded and the JSEP handles are `JsValue`s, which are neither
//! `Send` nor `Sync`.

#[cfg(target_arch = "wasm32")]
pub mod browser;
