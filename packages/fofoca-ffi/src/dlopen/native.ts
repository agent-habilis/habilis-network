/**
 * The runtime-neutral shape of a loaded `libfofoca_ffi`.
 *
 * One interface, three loaders. `bun:ffi`, `Deno.dlopen` and koffi spell the
 * same call three different ways; everything above this line (the worker
 * engine) speaks only this vocabulary, so a runtime difference can be wrong in
 * exactly one loader rather than smeared through the loop.
 */

import type { SymbolName } from '../abi.ts'
import type { WireOpts } from '../protocol.ts'

/**
 * A loader-specific address. Opaque on purpose: Bun hands out numbers, Deno
 * pointer objects, koffi its own wrappers, and nothing outside a loader may
 * assume any of them.
 */
export type NativePointer = unknown

/** What may cross the generic call boundary, per the `CType` of each slot. */
export type NativeValue = number | bigint | Uint8Array | string | null | NativePointer

export interface NativeLibrary {
  /**
   * Call one symbol from the `ABI` table. Arguments follow the table's types:
   * `i32` a number, `isize`/`usize` a bigint, `buf` a Uint8Array read or
   * written in place, `cstr` a string or null, `ptr` a `NativePointer`.
   * Returns a number for `i32`, a bigint for `isize`/`usize`, and a
   * `NativePointer` for `ptr`.
   */
  call(name: SymbolName, ...args: NativeValue[]): number | bigint | NativePointer

  /** Read the NUL-terminated string at `ptr`. Only valid for non-NULL pointers. */
  readCString(ptr: NativePointer): string

  isNull(ptr: NativePointer): boolean

  /**
   * `fofoca_mesh_open`, at loader level because it is the one struct-by-pointer
   * call: embedding string pointers into a byte-encoded struct is the single
   * thing the three runtimes cannot spell the same way. Returns the handle,
   * which is NULL on failure — check with [`isNull`].
   */
  open(opts: WireOpts): NativePointer

  /** Release the dlopen handle itself. The mesh handle is closed via `fofoca_mesh_close`. */
  close(): void
}

/**
 * Load the library with whichever FFI this runtime has.
 *
 * The loaders are imported dynamically so that a runtime never even parses the
 * module written for another one — `bun:ffi` does not exist off Bun, and koffi
 * is an optional dependency that Bun and Deno users never install.
 */
export async function loadNative(path: string): Promise<NativeLibrary> {
  const globals = globalThis as { Bun?: unknown; Deno?: unknown }
  if (globals.Bun !== undefined) {
    const { loadWithBun } = await import('./bun.ts')
    return loadWithBun(path)
  }
  if (globals.Deno !== undefined) {
    const { loadWithDeno } = await import('./deno.ts')
    return loadWithDeno(path)
  }
  const { loadWithKoffi } = await import('./node.ts')
  return loadWithKoffi(path)
}
