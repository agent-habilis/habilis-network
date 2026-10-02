# habilis-network-ffi (package)

habilis-network on Bun, Deno, and Node: `dlopen` over the C ABI of
[`crates/habilis-network-ffi`](../../crates/habilis-network-ffi), with mDNS, the mainline
DHT, and the relay ladder.

The `join` / `create` entry point lives in `src/index.ts`. The mesh
handle is owned by one worker thread (`src/worker.ts` driving
`src/engine.ts`), because every C call is blocking and thread-confined.
The three loaders are in `src/dlopen/`.

Build the library first, then the smoke test unlocks:

```sh
cargo build --release -p habilis-network-ffi
bun test
```

`koffi` is an optional peer dependency; Node needs it, Bun and Deno use
their built-in FFI.

See [`../README.md`](../README.md) for the workspace rules.
