/**
 * The one test that loads the real library. Skipped when it is not built —
 * `cargo build --release -p fofoca-ffi` unlocks it.
 *
 * `create({})` with no discovery option is a loopback mesh, reachable only
 * from this machine, so this test is offline by design.
 */

import { describe, expect, test } from 'bun:test'
import { discover } from './discover.ts'
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
})
