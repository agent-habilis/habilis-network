import { describe, expect, test } from 'bun:test'

import { ABI } from './abi.ts'

/**
 * Every `fofoca_*` token in the header that is immediately followed by `(` and
 * not preceded by a word character — the same scrape `tasks/src/ffi.rs` does,
 * prose included. A name in a doc comment that no longer exists is drift worth
 * catching, and so is one this table has never heard of.
 */
function declared(header: string): Set<string> {
  return new Set(
    [...header.matchAll(/(?<![\w])fofoca_[a-z_]*(?=\()/g)].map((match) => match[0]),
  )
}

const HEADER = '../../../crates/fofoca-ffi/include/fofoca.h'

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

  test('the scrape ignores a mention that is not a call', () => {
    expect(declared('see fofoca_mesh_open for details')).toEqual(new Set())
    expect(declared('my_fofoca_mesh_open(x)')).toEqual(new Set())
    expect(declared('fofoca_mesh_open(const fofoca_opts *o)')).toEqual(new Set(['fofoca_mesh_open']))
  })
})

describe('the shape of each signature', () => {
  test('every handle-taking call takes the handle first', () => {
    const standalone = new Set(['fofoca_last_error', 'fofoca_version', 'fofoca_max_msg'])
    // Opens a node from a hash alone: there is no handle yet to pass.
    const fromHash = new Set(['fofoca_streams_bind_for'])
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
    for (const name of ['fofoca_mesh_state_json', 'fofoca_mesh_peers_json'] as const) {
      expect(ABI[name]).toEqual({ args: ['ptr', 'buf', 'usize'], returns: 'isize' })
    }
  })

  test('recv returns a long, because 0, -1 and -2 are all meaningful', () => {
    expect(ABI.fofoca_msg_recv.returns).toBe('isize')
  })
})
