/**
 * The runtime-neutral shape of a loaded `libhabilis_network_ffi`.
 *
 * One interface, three loaders. `bun:ffi`, `Deno.dlopen` and koffi spell the
 * same call three different ways; everything above this line (the worker
 * engine) speaks only this vocabulary, so a runtime difference can be wrong in
 * exactly one loader rather than smeared through the loop.
 */

import { ABI_VERSION, type SymbolName } from '../abi.ts'
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
   * `habilis_network_mesh_open`, at loader level because it is the one struct-by-pointer
   * call: embedding string pointers into a byte-encoded struct is the single
   * thing the three runtimes cannot spell the same way. Returns the handle,
   * which is NULL on failure — check with [`isNull`].
   */
  open(opts: WireOpts): NativePointer

  /** Release the dlopen handle itself. The mesh handle is closed via `habilis_network_mesh_close`. */
  close(): void
}

/** The library and this package disagree about the C ABI, or the library cannot say. */
export class AbiMismatchError extends Error {
  override name = 'AbiMismatchError'
}

/**
 * Refuse a library whose `habilis_network_abi_version()` is not the one this
 * package speaks. `found` is what the probe returned: the version, or the
 * error that stopped it, which means the library has no such symbol, so it
 * predates the check.
 *
 * Both failures are the same hazard. A struct that gained a field is read at
 * the wrong size and offsets, and nothing downstream notices, so the loader
 * stops here, naming both versions and the way out.
 */
export function checkAbiVersion(path: string, found: number | Error, expected: number = ABI_VERSION): void {
  const rebuild = 'Rebuild the library from the same checkout as this package: cargo build --release -p habilis-network-ffi'
  if (found instanceof Error) {
    throw new AbiMismatchError(
      `${path} does not answer habilis_network_abi_version(), so it is older than the ABI check or is not a ` +
        `habilis-network library. This package speaks ABI version ${expected}. ${rebuild} (${found.message})`,
    )
  }
  if (found !== expected) {
    throw new AbiMismatchError(
      `${path} speaks ABI version ${found}, and this package speaks ABI version ${expected}. ` +
        `A library and a package built from different checkouts read each other's structs at the wrong ` +
        `offsets. ${rebuild}, or install the package release that matches the library.`,
    )
  }
}

/**
 * Load the library with whichever FFI this runtime has.
 *
 * The loaders are imported dynamically so that a runtime never even parses the
 * module written for another one — `bun:ffi` does not exist off Bun, and koffi
 * is an optional dependency that Bun and Deno users never install.
 *
 * The ABI version is asked first, with only that symbol bound, and a mismatch
 * or a missing symbol throws [`AbiMismatchError`] before anything else is
 * loaded.
 */
export async function loadNative(path: string): Promise<NativeLibrary> {
  const globals = globalThis as { Bun?: unknown; Deno?: unknown }
  if (globals.Bun !== undefined) {
    const { loadWithBun, probeAbiVersionWithBun } = await import('./bun.ts')
    checkAbiVersion(path, probeAbiVersionWithBun(path))
    return loadWithBun(path)
  }
  if (globals.Deno !== undefined) {
    const { loadWithDeno, probeAbiVersionWithDeno } = await import('./deno.ts')
    checkAbiVersion(path, probeAbiVersionWithDeno(path))
    return loadWithDeno(path)
  }
  const { loadWithKoffi, probeAbiVersionWithKoffi } = await import('./node.ts')
  checkAbiVersion(path, await probeAbiVersionWithKoffi(path))
  return loadWithKoffi(path)
}
