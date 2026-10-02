/**
 * Keyed reconciliation over a scene graph, fuzzed.
 *
 * The same shape as `../reconcile/fuzz.test.ts`, against the other host — and
 * the strongest single check that the `Host` seam did not break anything,
 * because it exercises the prefix/suffix scans, the key map, the LIS move
 * minimisation and the bulk-clear path against a child list whose invariants
 * are completely different from the DOM's.
 *
 * It asserts more than the DOM version can, cheaply: a doubly-linked list can
 * be correct forwards and corrupt backwards, so every check walks it both ways.
 */

import { expect, test } from 'bun:test'
import { component, signal } from 'visage-dom'
import { renderWith } from 'visage-dom/reconcile'
import { flushSync } from 'visage-dom/signal'
import type { Child } from 'visage-dom/types'
import { createCanvasHost, createSceneNode, type SceneNode } from './scene/index.ts'
import { shapes } from './shapes/index.ts'

const { group, circle } = shapes

function mulberry32(seed: number) {
  return () => {
    seed |= 0
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const Item = component<{ n: number }>(function* (props) {
  yield () => circle({ radius: props.n, fill: '#0f0' })
})

/**
 * A row whose root is a fragment, so it owns two scene nodes rather than one.
 * Odd ids use it, which puts multi-node fibers through the same keyed matching
 * and LIS ordering pass as single-node ones.
 */
const PairItem = component<{ n: number }>(function* (props) {
  yield () =>
    [circle({ radius: props.n, fill: '#a' }), circle({ radius: props.n, fill: '#b' })]
})

const rowFor = (n: number): Child =>
  n % 2 === 1 ? PairItem({ key: n, n }) : Item({ key: n, n })

const widthOf = (n: number) => (n % 2 === 1 ? 2 : 1)

test.each([0xc0ffee, 0x1234abc, 0xfeed, 0x5eed])(
  'keyed reorder fuzz over the scene graph (seed %p)',
  (seed) => {
    const rng = mulberry32(seed)
    const list = signal<number[]>([])
    const App = component(function* () {
      yield () => group(list.value.map(rowFor))
    })

    const scene = createSceneNode('#root')
    renderWith(App(), scene, createCanvasHost(() => {}))
    const holder = scene.firstChild as SceneNode

    let nextId = 0
    const identity = new Map<number, SceneNode[]>()

    const check = (label: string) => {
      const forwards: SceneNode[] = []
      for (let child = holder.firstChild; child !== null; child = child.next) {
        forwards.push(child)
      }
      const backwards: SceneNode[] = []
      for (let child = holder.lastChild; child !== null; child = child.prev) {
        backwards.push(child)
      }
      backwards.reverse()

      // A linked list can be right in one direction and corrupt in the other.
      expect(backwards, `${label}: both directions agree`).toEqual(forwards)
      expect(holder.childCount, `${label}: childCount`).toBe(forwards.length)
      for (const child of forwards) {
        expect(child.parent, `${label}: parent pointer`).toBe(holder)
      }

      const expected = list.peek()
      const width = expected.reduce((sum, n) => sum + widthOf(n), 0)
      expect(forwards.length, `${label}: node count`).toBe(width)

      let at = 0
      expected.forEach((n, i) => {
        const owned = forwards.slice(at, at + widthOf(n))
        at += widthOf(n)
        expect(
          owned.map((node) => node.radius),
          `${label}: row ${i} contents`,
        ).toEqual(owned.map(() => n))

        const known = identity.get(n)
        if (known) {
          known.forEach((node, j) => {
            expect(node === owned[j], `${label}: identity of ${n}[${j}]`).toBe(true)
          })
        } else {
          identity.set(n, owned)
        }
      })

      for (const [n, nodes] of identity) {
        if (!expected.includes(n)) {
          for (const node of nodes) {
            expect(node.parent, `${label}: ${n} detached`).toBe(null)
          }
          identity.delete(n)
        }
      }
    }

    for (let round = 0; round < 400; round++) {
      const cur = [...list.peek()]
      const op = Math.floor(rng() * 8)
      let next = cur

      if (op === 0) next = [...cur].reverse()
      else if (op === 1) {
        next = [...cur]
        for (let i = next.length - 1; i > 0; i--) {
          const j = Math.floor(rng() * (i + 1))
          ;[next[i], next[j]] = [next[j]!, next[i]!]
        }
      } else if (op === 2) {
        next = [...cur]
        const count = Math.floor(rng() * 6)
        for (let i = 0; i < count; i++) {
          next.splice(Math.floor(rng() * (next.length + 1)), 0, nextId++)
        }
      } else if (op === 3) {
        next = [...cur]
        const count = Math.min(next.length, Math.floor(rng() * 6))
        for (let i = 0; i < count; i++) next.splice(Math.floor(rng() * next.length), 1)
      } else if (op === 4 && cur.length > 1) {
        next = [...cur]
        const a = Math.floor(rng() * next.length)
        const b = Math.floor(rng() * next.length)
        ;[next[a], next[b]] = [next[b]!, next[a]!]
      } else if (op === 5) {
        next = cur.length > 1 ? [...cur.slice(1), cur[0]!] : cur
      } else if (op === 6) next = []
      else next = Array.from({ length: Math.floor(rng() * 12) }, () => nextId++)

      list.value = next
      flushSync()
      check(`seed ${seed} round ${round} op ${op}`)
    }
  },
)
