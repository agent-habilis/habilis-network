/**
 * `Symbol.asyncDispose`, guaranteed to exist.
 *
 * The one global this package mutates, and it is unavoidable: `Mesh` is an
 * `AsyncDisposable`, so `await using` has to find the symbol at the moment the
 * object literal is built. Without it `Symbol.asyncDispose` is `undefined` and
 * the computed key silently becomes the string `"undefined"` — an object that
 * type-checks as disposable and disposes of nothing.
 *
 * Bun, Deno and Node all define it. This is for a browser that does not yet.
 * `Symbol.for` rather than `Symbol()` so two copies of this module on one page
 * agree on the same symbol.
 *
 * Import this module for its side effect before building anything disposable.
 */
const wellKnown = Symbol as { asyncDispose?: symbol; dispose?: symbol }
wellKnown.asyncDispose ??= Symbol.for('Symbol.asyncDispose')
wellKnown.dispose ??= Symbol.for('Symbol.dispose')

export {}
