import { describe, expect, test } from 'bun:test'

import { ABI, ABI_VERSION } from './abi.ts'

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
    expect(declared('see habilis_network_mesh_open for details')).toEqual(new Set())
    expect(declared('my_habilis_network_mesh_open(x)')).toEqual(new Set())
    expect(declared('habilis_network_mesh_open(const habilis_network_opts *o)')).toEqual(new Set(['habilis_network_mesh_open']))
  })
})

describe('the ABI version', () => {
  test('is the header macro, so the package and the header cannot drift', async () => {
    const header = await Bun.file(new URL(HEADER, import.meta.url)).text()
    const macro = /^#define HABILIS_NETWORK_ABI_VERSION (\d+)$/m.exec(header)

    expect(macro).not.toBeNull()
    expect(ABI_VERSION).toBe(Number(macro?.[1]))
  })

  test('is asked through a call that takes nothing and returns a u32', () => {
    expect(ABI.habilis_network_abi_version).toEqual({ args: [], returns: 'u32' })
  })
})

describe('the shape of each signature', () => {
  test('every handle-taking call takes the handle first', () => {
    const standalone = new Set([
      'habilis_network_abi_version',
      'habilis_network_last_error',
      'habilis_network_version',
      'habilis_network_max_msg',
    ])
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
      expect(ABI[name]).toEqual({ args: ['ptr', 'buf', 'usize'], returns: 'isize' })
    }
  })

  test('recv returns a long, because 0, -1 and -2 are all meaningful', () => {
    expect(ABI.habilis_network_msg_recv.returns).toBe('isize')
  })
})
