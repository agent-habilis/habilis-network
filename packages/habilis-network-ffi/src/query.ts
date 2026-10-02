/**
 * The length-query convention `habilis_network_state_json` and `habilis_network_peers_json` share.
 */

const utf8 = new TextDecoder('utf-8', { fatal: true })

/** The buffer a first attempt uses. Big enough that a small mesh never retries. */
export const SCRATCH_BYTES = 4096

/**
 * One `habilis_network_*_json` call, retried until the document fits.
 *
 * The `+ 1` below is the entire reason this function exists. `copy_out` in
 * `crates/habilis-network-ffi/src/ffi.rs` writes only when `needed < cap` — strictly,
 * because it reserves room for the NUL — and otherwise writes *nothing* and
 * returns `needed` anyway. So `cap === needed` looks exactly like a fit to a
 * caller checking `returned <= cap`, and hands back whatever the buffer held
 * before. Asking for `needed + 1` is what makes the second attempt succeed.
 *
 * @param call invokes the C function with a buffer and its capacity, returning
 * the needed length excluding the NUL, or -1 on failure.
 * @param fail raises the thread-local error; must run before any other call.
 */
export function readDocument(
  name: string,
  call: (buffer: Uint8Array, cap: bigint) => bigint,
  fail: (call: string) => never,
): string {
  let buffer = new Uint8Array(SCRATCH_BYTES)
  // Twice is always enough: the first attempt learns the length, the second
  // asks for exactly that plus the NUL. The loop is a guard against a document
  // that grew between the two, not an unbounded retry.
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const needed = call(buffer, BigInt(buffer.byteLength))
    if (needed < 0n) {
      fail(name)
    }
    const length = Number(needed)
    if (length < buffer.byteLength) {
      return utf8.decode(buffer.subarray(0, length))
    }
    buffer = new Uint8Array(length + 1)
  }
  throw new Error(`${name} kept outgrowing its buffer`)
}
