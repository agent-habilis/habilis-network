/**
 * The Bun loader: `bun:ffi` `dlopen`.
 *
 * Only ever imported on Bun — `loadNative` gates on `globalThis.Bun` — so the
 * `bun:ffi` import cannot fail at runtime elsewhere.
 */

import { CString, dlopen, FFIType, ptr, type Pointer } from 'bun:ffi'
import { ABI, type CType, type SymbolName } from '../abi.ts'
import type { WireOpts } from '../protocol.ts'
import type { NativeLibrary, NativePointer, NativeValue } from './native.ts'
import { encodeOpts } from './opts-struct.ts'

function ffiType(type: CType): FFIType {
  switch (type) {
    case 'i32':
      return FFIType.i32
    case 'isize':
      return FFIType.i64
    case 'usize':
      return FFIType.u64
    case 'u32':
      return FFIType.u32
    case 'ptr':
    case 'buf':
    case 'cstr':
      return FFIType.ptr
  }
}

const encoder = new TextEncoder()

function terminated(value: string): Uint8Array {
  const text = encoder.encode(value)
  const bytes = new Uint8Array(text.byteLength + 1)
  bytes.set(text, 0)
  return bytes
}

/**
 * `habilis_network_abi_version()` of the library at `path`, opened with that
 * one symbol and closed again, or the error that stopped it: the library has
 * no such symbol (an older build), or is not a library at all.
 */
export function probeAbiVersionWithBun(path: string): number | Error {
  let library: ReturnType<typeof dlopen>
  try {
    library = dlopen(path, {
      habilis_network_abi_version: { args: [], returns: ffiType(ABI.habilis_network_abi_version.returns) },
    })
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error))
  }
  try {
    return Number((library.symbols['habilis_network_abi_version'] as () => unknown)())
  } finally {
    library.close()
  }
}

export function loadWithBun(path: string): NativeLibrary {
  const signatures = Object.fromEntries(
    Object.entries(ABI).map(([name, signature]) => [
      name,
      {
        args: signature.args.map(ffiType),
        returns: ffiType(signature.returns),
      },
    ]),
  )
  const library = dlopen(path, signatures)

  const call = (name: SymbolName, ...args: NativeValue[]): number | bigint | NativePointer => {
    const signature = ABI[name]
    // `holds` roots every buffer minted for a `cstr` argument for the duration
    // of the (blocking) call, the same keep-alive rule `encodeOpts` states.
    const holds: Uint8Array[] = []
    const lowered = args.map((arg, index) => {
      // Widened: no ABI *argument* is an `isize` today, but the lowering is
      // written for the whole vocabulary so a header change cannot skew it.
      const type = signature.args[index] as CType | undefined
      switch (type) {
        case 'i32':
        case 'u32':
          return arg as number
        case 'isize':
        case 'usize':
          return arg as bigint
        case 'buf':
          return ptr(arg as Uint8Array)
        case 'cstr': {
          if (arg === null) {
            return null
          }
          const bytes = terminated(arg as string)
          holds.push(bytes)
          return ptr(bytes)
        }
        case 'ptr':
          return arg
        case undefined:
          throw new RangeError(`${name} takes ${signature.args.length} arguments`)
      }
    })
    const symbol = library.symbols[name] as (...lowered: unknown[]) => unknown
    const result = symbol(...lowered)
    holds.length = 0
    switch (signature.returns) {
      case 'i32':
      case 'u32':
        return Number(result)
      case 'isize':
      case 'usize':
        return BigInt(result as number | bigint)
      default:
        return result as NativePointer
    }
  }

  return {
    call,
    readCString: (pointer) => new CString(pointer as Pointer).toString(),
    isNull: (pointer) => pointer === null || pointer === 0,
    open: (opts: WireOpts) => {
      const encoded = encodeOpts(opts, (buffer) => BigInt(ptr(buffer)))
      const handle = call('habilis_network_mesh_open', ptr(encoded.struct))
      // Read after the call so the optimizer cannot collect the string
      // buffers while the engine is still reading their addresses.
      void encoded.keepAlive.length
      return handle
    },
    close: () => library.close(),
  }
}
