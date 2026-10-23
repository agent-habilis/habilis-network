/**
 * The one test that loads the real library. Skipped when it is not built —
 * `cargo build --release -p habilis-network-ffi` unlocks it.
 *
 * `create({})` with no discovery option is a loopback mesh, reachable only
 * from this machine, so this test is offline by design.
 */

import { describe, expect, test } from 'bun:test'
import { discover } from './discover.ts'
import { loadNative } from './dlopen/native.ts'
import { create } from './index.ts'

const library = discover()

describe.skipIf(library.path === null)('smoke over the built library', () => {
  test('loopback create: identity, merge read-back, leave', async () => {
    const mesh = await create({ nick: 'smoke' })
    try {
      expect(mesh.id.length).toBeGreaterThan(0)
      expect(mesh.name.length).toBeGreaterThan(0)
      expect(mesh.nick.length).toBeGreaterThan(0)
      expect(mesh.maxMsg).toBeGreaterThan(0)
      expect(mesh.peers).toEqual([])

      await mesh.state.merge({ lunch: 'yes' })
      expect(mesh.state.value['lunch']).toBe('yes')

      // A broadcast into an empty mesh must not error.
      await mesh.send('anyone?')
    } finally {
      await mesh.leave()
    }
  }, 30000)

  // A negative return is the case that a 32-bit `long` broke on Windows: the
  // low half of -1 read as 64 bits is 4294967295. A positive count read
  // right by luck, so it proves nothing about the width.
  test('a NULL handle gives -1 from a call that returns an int64_t', async () => {
    const native = await loadNative(library.path ?? '')
    try {
      expect(native.call('habilis_network_mesh_peer_count', null)).toBe(-1n)
    } finally {
      native.close()
    }
  })
})
