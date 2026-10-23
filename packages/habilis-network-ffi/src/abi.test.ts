import { describe, expect, test } from 'bun:test'

import { ABI } from './abi.ts'

/**
 * Every `habilis_network_*` token in the header that is immediately followed by `(` and
 * not preceded by a word character — the same scrape `tasks/src/ffi.rs` does,
 * prose included. A name in a doc comment that no longer exists is drift worth
 * catching, and so is one this table has never heard of.
 */
function declared(header: string): Set<string> {
  return new Set(
    [...header.matchAll(/(?<![\w])habilis_network_[a-z_]*(?=\()/g)].map((match) => match[0]),
  )
}

const HEADER = '../../../crates/habilis-network-ffi/include/habilis_network.h'

/** The C return types of the header, in the vocabulary of `abi.ts`. */
const C_TYPES: Record<string, string> = { int: 'i32', int64_t: 'i64', size_t: 'usize' }

/**
 * The return type of each function that the header declares, in the
 * vocabulary of `abi.ts`: a pointer is `ptr`, and a C type that the table
 * cannot name, such as `long`, is reported by its own name. Comments go
 * first, so that prose ("longer", "longest") is not read as a type.
 */
function returns(header: string): Map<string, string> {
  const code = header.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/.*$/gm, '')
  const found = new Map<string, string>()
  for (const [, type, star, name] of code.matchAll(/^([A-Za-z_][\w ]*?)\s*(\*?)\s*(habilis_network_[a-z_]+)\(/gm)) {
    const ctype = (type ?? '').trim()
    found.set(name ?? '', star === '*' ? 'ptr' : (C_TYPES[ctype] ?? ctype))
  }
  return found
}

describe('the signature table and the header', () => {
  test('name the same symbols', async () => {
    const header = await Bun.file(new URL(HEADER, import.meta.url)).text()
    const fromHeader = [...declared(header)].sort()
    const fromTable = Object.keys(ABI).sort()

    expect(fromTable).toEqual(fromHeader)
  })

  test('the scrape finds something, so an empty match cannot pass as agreement', async () => {
    const header = await Bun.file(new URL(HEADER, import.meta.url)).text()

    expect(declared(header).size).toBeGreaterThan(10)
  })

  test('declare the same return types', async () => {
    const header = await Bun.file(new URL(HEADER, import.meta.url)).text()
    const fromHeader = Object.fromEntries(returns(header))
    const fromTable = Object.fromEntries(Object.entries(ABI).map(([name, signature]) => [name, signature.returns]))

    expect(fromHeader).toEqual(fromTable)
  })

  test('the return-type scrape reads code, not comments, and names a C type the table lacks', () => {
    const header = [
      '/* a longer text: long habilis_network_x(void); */',
      'int64_t habilis_network_y(void);',
      'long habilis_network_z(void);',
    ].join('\n')
    expect(returns(header)).toEqual(
      new Map([
        ['habilis_network_y', 'i64'],
        ['habilis_network_z', 'long'],
      ]),
    )
  })

  test('the scrape ignores a mention that is not a call', () => {
    expect(declared('see habilis_network_mesh_open for details')).toEqual(new Set())
    expect(declared('my_habilis_network_mesh_open(x)')).toEqual(new Set())
    expect(declared('habilis_network_mesh_open(const habilis_network_opts *o)')).toEqual(new Set(['habilis_network_mesh_open']))
  })
})

describe('the shape of each signature', () => {
  test('every handle-taking call takes the handle first', () => {
    const standalone = new Set(['habilis_network_last_error', 'habilis_network_version', 'habilis_network_max_msg'])
    // Opens a node from a hash alone: there is no handle yet to pass.
    const fromHash = new Set(['habilis_network_streams_bind_for'])
    for (const [name, signature] of Object.entries(ABI)) {
      if (standalone.has(name)) {
        expect(signature.args).toEqual([])
      } else if (fromHash.has(name)) {
        expect(signature.args).toEqual(['cstr'])
      } else {
        expect(signature.args[0]).toBe('ptr')
      }
    }
  })

  test('the three length-query calls agree on their shape', () => {
    for (const name of ['habilis_network_mesh_state_json', 'habilis_network_mesh_peers_json'] as const) {
      expect(ABI[name]).toEqual({ args: ['ptr', 'buf', 'usize'], returns: 'i64' })
    }
  })

  test('recv returns an int64_t, because 0, -1 and -2 are all meaningful', () => {
    expect(ABI.habilis_network_msg_recv.returns).toBe('i64')
  })
})
