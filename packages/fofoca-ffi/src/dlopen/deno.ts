/**
 * The Deno loader: `Deno.dlopen`, which needs `--allow-ffi --unstable-ffi`.
 *
 * Typed structurally against `globalThis` rather than the Deno type
 * definitions: this package typechecks under Bun's types, and the whole
 * module is only ever imported when `globalThis.Deno` exists.
 */

import { ABI, type CType, type SymbolName } from '../abi.ts'
import type { WireOpts } from '../protocol.ts'
import type { NativeLibrary, NativePointer, NativeValue } from './native.ts'
import { encodeOpts } from './opts-struct.ts'

interface DenoPointerNamespace {
  of(buffer: Uint8Array): NativePointer
  value(pointer: NativePointer): bigint
}

interface DenoPointerViewConstructor {
  new (pointer: NativePointer): { getCString(): string }
}

interface DenoNamespace {
  dlopen(
    path: string,
    symbols: Record<string, { parameters: string[]; result: string }>,
  ): {
    symbols: Record<string, (...args: unknown[]) => unknown>
    close(): void
  }
  UnsafePointer: DenoPointerNamespace
  UnsafePointerView: DenoPointerViewConstructor
}

function denoNamespace(): DenoNamespace {
  const deno = (globalThis as { Deno?: DenoNamespace }).Deno
  if (deno === undefined) {
    throw new Error('the Deno loader was imported off Deno')
  }
  return deno
}

function ffiType(type: CType): string {
  switch (type) {
    case 'i32':
      return 'i32'
    case 'isize':
      return 'i64'
    case 'usize':
      return 'u64'
    case 'ptr':
      return 'pointer'
    // A `buf` and a `cstr` both cross as Deno's 'buffer': a Uint8Array whose
    // address the callee sees. The NUL for a cstr is this side's job.
    case 'buf':
    case 'cstr':
      return 'buffer'
  }
}

const encoder = new TextEncoder()

function terminated(value: string): Uint8Array {
  const text = encoder.encode(value)
  const bytes = new Uint8Array(text.byteLength + 1)
  bytes.set(text, 0)
  return bytes
}

export function loadWithDeno(path: string): NativeLibrary {
  const deno = denoNamespace()
  let library: ReturnType<DenoNamespace['dlopen']>
  try {
    library = deno.dlopen(
      path,
      Object.fromEntries(
        Object.entries(ABI).map(([name, signature]) => [
          name,
          {
            parameters: signature.args.map(ffiType),
            result: ffiType(signature.returns),
          },
        ]),
      ),
    )
  } catch (error) {
    throw new Error(
      `Deno.dlopen failed — run with --allow-ffi --unstable-ffi (${String(error)})`,
    )
  }

  const call = (name: SymbolName, ...args: NativeValue[]): number | bigint | NativePointer => {
    const signature = ABI[name]
    const lowered = args.map((arg, index) => {
      // Widened: no ABI *argument* is an `isize` today, but the lowering is
      // written for the whole vocabulary so a header change cannot skew it.
      const type = signature.args[index] as CType | undefined
      switch (type) {
        case 'i32':
          return arg as number
        case 'isize':
        case 'usize':
          return arg as bigint
        case 'buf':
          return arg as Uint8Array
        case 'cstr':
          return arg === null ? null : terminated(arg as string)
        case 'ptr':
          return arg
        case undefined:
          throw new RangeError(`${name} takes ${signature.args.length} arguments`)
      }
    })
    const symbol = library.symbols[name]
    if (symbol === undefined) {
      throw new Error(`${name} is not exported by the library`)
    }
    const result = symbol(...lowered)
    switch (signature.returns) {
      case 'i32':
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
    readCString: (pointer) => new deno.UnsafePointerView(pointer).getCString(),
    isNull: (pointer) => pointer === null,
    open: (opts: WireOpts) => {
      const encoded = encodeOpts(opts, (buffer) => deno.UnsafePointer.value(deno.UnsafePointer.of(buffer)))
      const handle = call('fofoca_mesh_open', deno.UnsafePointer.of(encoded.struct))
      void encoded.keepAlive.length
      return handle
    },
    close: () => library.close(),
  }
}
