/**
 * The one test that loads the real library. Skipped when it is not built —
 * `cargo build --release -p habilis-network-ffi` unlocks it.
 *
 * `create({})` with no discovery option is a loopback mesh, reachable only
 * from this machine, so this test is offline by design.
 */

import { describe, expect, test } from 'bun:test'
import { discover } from './discover.ts'
import type { Mesh } from 'habilis-network-api'
import { create, join } from './index.ts'

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

  test('a reply to the key of a message reaches its author', async () => {
    const alice = await create({ nick: 'smoke-a' })
    const bob = await join({ id: alice.id, nick: 'smoke-b' })
    try {
      await untilCompany(alice, bob)
      const signal = AbortSignal.timeout(30000)
      const atBob = bob.messages(signal)[Symbol.asyncIterator]()
      const atAlice = alice.messages(signal)[Symbol.asyncIterator]()

      await alice.send('hello bob')
      const heard = (await atBob.next()).value
      expect(heard?.from).toBe('smoke-a')
      expect(heard?.key).toMatch(/^[0-9a-f]{64}$/)
      expect(heard?.key).toBe(bob.peers.find((peer) => peer.nick === 'smoke-a')?.key)

      await bob.sendToKey(heard?.key ?? '', 'hello alice')
      const reply = (await atAlice.next()).value
      expect(reply).toMatchObject({ from: 'smoke-b', text: 'hello alice', directed: true })
      expect(reply?.key).toBe(alice.peers.find((peer) => peer.nick === 'smoke-b')?.key)

      await expect(bob.sendToKey('smoke-a', 'a nickname is not a key')).rejects.toThrow(/64 lowercase hex/)
    } finally {
      await bob.leave()
      await alice.leave()
    }
  }, 60000)
})

/** Wait until each mesh lists the other: the roster is re-read twice a second. */
async function untilCompany(first: Mesh, second: Mesh): Promise<void> {
  const deadline = Date.now() + 30000
  while (first.peers.length === 0 || second.peers.length === 0) {
    if (Date.now() > deadline) {
      throw new Error('the two meshes never saw each other')
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
}
