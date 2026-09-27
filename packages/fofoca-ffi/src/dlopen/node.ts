/**
 * The Node loader: koffi, the one maintained FFI for Node with prebuilt
 * binaries. An optional peer dependency — Bun and Deno users never install
 * it — so the import failure message has to carry the fix.
 */

import { ABI, type CType, type SymbolName } from '../abi.ts'
import type { WireOpts } from '../protocol.ts'
import type { NativeLibrary, NativePointer, NativeValue } from './native.ts'

interface Koffi {
  load(path: string): {
    func(name: string, result: string, args: string[]): (...args: unknown[]) => unknown
    unload(): void
  }
  struct(name: string, fields: Record<string, string>): unknown
  decode(pointer: unknown, type: string): unknown
  types: Record<string, unknown>
}

function koffiType(type: CType): string {
  switch (type) {
    case 'i32':
      return 'int'
    case 'isize':
      return 'long'
    case 'usize':
      return 'size_t'
    case 'ptr':
      return 'void *'
    // In and out both: `fofoca_msg_recv` writes the text and the message struct
    // into caller buffers, and koffi only copies back what is marked out.
    case 'buf':
      return '_Inout_ uint8_t *'
    case 'cstr':
      return 'const char *'
  }
}

/** koffi registers struct names globally; a second registration throws. */
let optsRegistered = false

export async function loadWithKoffi(path: string): Promise<NativeLibrary> {
  let koffi: Koffi
  try {
    // Imported through a variable so the typechecker (which runs without the
    // optional dependency installed) does not resolve the module literally.
    const specifier = 'koffi'
    koffi = ((await import(specifier)) as { default: unknown }).default as Koffi
  } catch {
    throw new Error(
      [
        'fofoca-ffi on Node needs koffi, an optional peer dependency.',
        '',
        '  install it:  npm install koffi   (or bun add koffi / pnpm add koffi)',
        '',
        '  Bun and Deno need no extra install; they use their built-in FFI.',
      ].join('\n'),
    )
  }

  const library = koffi.load(path)

  if (!optsRegistered) {
    koffi.struct('fofoca_opts', {
      mesh: 'const char *',
      topic: 'const char *',
      nick: 'const char *',
      name: 'const char *',
      lookup: 'const char *',
      transport: 'const char *',
      relay_urls: 'const char *',
      disable_ip: 'int',
      disable_webrtc: 'int',
      max_peers: 'size_t',
    })
    optsRegistered = true
  }

  const functions = new Map<SymbolName, (...args: unknown[]) => unknown>()
  for (const [name, signature] of Object.entries(ABI)) {
    // `fofoca_mesh_open` is bound with the real struct type below, not as `void *`.
    if (name === 'fofoca_mesh_open') {
      continue
    }
    functions.set(
      name as SymbolName,
      library.func(name, koffiType(signature.returns), signature.args.map(koffiType)),
    )
  }
  const openFn = library.func('fofoca_mesh_open', 'void *', ['const fofoca_opts *'])

  const call = (name: SymbolName, ...args: NativeValue[]): number | bigint | NativePointer => {
    const symbol = functions.get(name)
    if (symbol === undefined) {
      throw new Error(`${name} is not callable through the generic table`)
    }
    const signature = ABI[name]
    const lowered = args.map((arg, index) => {
      switch (signature.args[index] as CType | undefined) {
        case 'isize':
        case 'usize':
          // koffi takes plain numbers for its integer types.
          return typeof arg === 'bigint' ? Number(arg) : arg
        case undefined:
          throw new RangeError(`${name} takes ${signature.args.length} arguments`)
        default:
          return arg
      }
    })
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
    readCString: (pointer) => koffi.decode(pointer, 'char *') as string,
    isNull: (pointer) => pointer === null || pointer === 0,
    open: (opts: WireOpts) =>
      openFn({
        mesh: opts.mesh,
        topic: opts.topic,
        nick: opts.nick,
        name: opts.name,
        lookup: opts.lookup,
        transport: opts.transport,
        relay_urls: opts.relayUrls,
        disable_ip: opts.disableIp ? 1 : 0,
        disable_webrtc: opts.disableWebrtc ? 1 : 0,
        max_peers: opts.maxPeers,
      }) as NativePointer,
    close: () => library.unload(),
  }
}
