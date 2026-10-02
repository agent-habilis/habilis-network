/**
 * The reconciler, driven against a scene graph.
 *
 * This is the file that has to justify the whole design. The claim is not "a
 * canvas renderer exists" — it is that the *same* reconciler and the *same*
 * generator driver produce it, so every feature of the library arrives here
 * without being ported. So these tests are mostly the library's own behaviours,
 * re-asked with shapes instead of elements: signals, keyed lists, `yield*`
 * delegation, `try`/`catch` boundaries, context, disposal. If any of them
 * needed canvas-specific code, the seam would be in the wrong place.
 *
 * `renderCanvas` is bypassed deliberately: it wants a real 2d context, and none
 * of this is about painting.
 */

import { expect, test } from 'bun:test'
import { component, disposable, portal, signal } from 'visage-dom'
import { context } from 'visage-dom/context'
import { renderWith, type Root } from 'visage-dom/reconcile'
import { flushSync } from 'visage-dom/signal'
import type { Behavior, Child } from 'visage-dom/types'
import { createCanvasHost, createSceneNode, type SceneNode } from './scene/index.ts'
import { shapes } from './shapes/index.ts'

const { group, circle, rect, text } = shapes

function mountScene(view: Child): { scene: SceneNode; root: Root; commits: () => number } {
  const scene = createSceneNode('#root')
  let commits = 0
  const host = createCanvasHost(() => {
    commits += 1
  })
  const root = renderWith(view, scene, host)
  return { scene, root, commits: () => commits }
}

const kids = (node: SceneNode): SceneNode[] => {
  const out: SceneNode[] = []
  for (let child = node.firstChild; child !== null; child = child.next) out.push(child)
  return out
}

const tags = (node: SceneNode): string[] => kids(node).map((n) => n.tag)

test('a shape tree mounts into scene nodes', () => {
  const { scene } = mountScene(
    group({ x: 10 }, circle({ radius: 2, fill: '#0f0' }), rect({ width: 4, height: 4 })),
  )

  expect(tags(scene)).toEqual(['group'])
  const g = scene.firstChild as SceneNode
  expect(g.x).toBe(10)
  expect(tags(g)).toEqual(['circle', 'rect'])
  expect((g.firstChild as SceneNode).radius).toBe(2)
})

test('a string child becomes a text node the parent can read', () => {
  const { scene } = mountScene(text({ fill: '#a' }, 'count: ', 7))
  const label = scene.firstChild as SceneNode
  expect(kids(label).map((n) => n.data)).toEqual(['count: ', '7'])
})

test('a component drives the scene from a signal', () => {
  const n = signal(3)
  const Dot = component(function* () {
    yield () => circle({ radius: n.value, fill: '#0f0' })
  })

  const { scene } = mountScene(Dot())
  expect((scene.firstChild as SceneNode).radius).toBe(3)

  const node = scene.firstChild as SceneNode
  n.value = 9
  flushSync()
  expect(node.radius).toBe(9)
  // Patched in place, not rebuilt: same node, new field.
  expect(scene.firstChild).toBe(node)
})

test('props that stop being declared fall back to their defaults', () => {
  const on = signal(true)
  const Blink = component(function* () {
    yield () =>
      on.value ? circle({ radius: 2, fill: '#0f0' }) : circle({ radius: 2 })
  })

  const { scene } = mountScene(Blink())
  const node = scene.firstChild as SceneNode
  expect(node.fill).toBe('#0f0')

  on.value = false
  flushSync()
  expect(node.fill).toBe(null)
})

test('keyed reordering moves nodes and keeps their identity', () => {
  const list = signal([1, 2, 3])
  const App = component(function* () {
    yield () =>
      group(list.value.map((n): Child => circle({ key: n, radius: n, fill: '#0f0' })))
  })

  const { scene } = mountScene(App())
  const holder = scene.firstChild as SceneNode
  const before = kids(holder)
  expect(before.map((n) => n.radius)).toEqual([1, 2, 3])

  list.value = [3, 1, 2]
  flushSync()
  const after = kids(holder)
  expect(after.map((n) => n.radius)).toEqual([3, 1, 2])
  // The same three objects, reordered — not three new ones.
  expect(new Set(after)).toEqual(new Set(before))
  expect(after[0]).toBe(before[2] as SceneNode)
})

test('removals detach and additions splice in the right places', () => {
  const list = signal([1, 2, 3, 4])
  const App = component(function* () {
    yield () =>
      group(list.value.map((n): Child => circle({ key: n, radius: n, fill: '#0f0' })))
  })

  const { scene } = mountScene(App())
  const holder = scene.firstChild as SceneNode
  const two = kids(holder)[1] as SceneNode

  list.value = [1, 3, 4]
  flushSync()
  expect(kids(holder).map((n) => n.radius)).toEqual([1, 3, 4])
  expect(two.parent).toBe(null)

  list.value = [0, 1, 3, 9, 4]
  flushSync()
  expect(kids(holder).map((n) => n.radius)).toEqual([0, 1, 3, 9, 4])
  expect(holder.childCount).toBe(5)
})

test('emptying and refilling a list keeps the child list coherent', () => {
  const list = signal([1, 2, 3])
  const App = component(function* () {
    yield () =>
      group(list.value.map((n): Child => circle({ key: n, radius: n, fill: '#0f0' })))
  })

  const { scene } = mountScene(App())
  const holder = scene.firstChild as SceneNode

  list.value = []
  flushSync()
  expect(holder.childCount).toBe(0)
  expect(holder.firstChild).toBe(null)
  expect(holder.lastChild).toBe(null)

  list.value = [7, 8]
  flushSync()
  expect(kids(holder).map((n) => n.radius)).toEqual([7, 8])
})

test('a component whose root is a fragment owns several scene nodes', () => {
  const Pair = component(function* () {
    yield () => [circle({ radius: 1, fill: '#a' }), circle({ radius: 2, fill: '#b' })]
  })
  const { scene } = mountScene(group(Pair(), circle({ radius: 3, fill: '#c' })))

  const holder = scene.firstChild as SceneNode
  expect(kids(holder).map((n) => n.radius)).toEqual([1, 2, 3])
})

test('a null child becomes a hole that holds its siblings’ places', () => {
  const on = signal(false)
  const App = component(function* () {
    yield () =>
      group(
        circle({ radius: 1, fill: '#a' }),
        on.value ? circle({ radius: 2, fill: '#b' }) : null,
        circle({ radius: 3, fill: '#c' }),
      )
  })

  const { scene } = mountScene(App())
  const holder = scene.firstChild as SceneNode
  expect(tags(holder)).toEqual(['circle', '#hole', 'circle'])

  on.value = true
  flushSync()
  expect(kids(holder).map((n) => n.radius)).toEqual([1, 2, 3])
})

test('yield* delegates a view and a lifecycle, unchanged', () => {
  const disposed: string[] = []

  function* spinner(label: string): Behavior<unknown> {
    try {
      yield () => circle({ radius: 1, fill: '#0f0' })
    } finally {
      disposed.push(label)
    }
  }

  const App = component(function* () {
    yield* spinner('inner')
  })

  const { scene, root } = mountScene(App())
  expect(tags(scene)).toEqual(['circle'])
  root.unmount()
  expect(disposed).toEqual(['inner'])
})

test('try/catch around a yield is an error boundary here too', () => {
  const Boom = component(function* () {
    throw new Error('nope')
  })

  const Boundary = component(function* () {
    try {
      yield () => group(Boom())
    } catch {
      yield () => text({ fill: '#f00' }, 'caught')
    }
  })

  const { scene } = mountScene(Boundary())
  flushSync()
  const shown = scene.firstChild as SceneNode
  expect(shown.tag).toBe('text')
  expect(kids(shown).map((n) => n.data)).toEqual(['caught'])
})

test('context reaches descendants across the canvas host', () => {
  const Theme = context<string>('theme')

  const Leaf = component(function* () {
    const colour = this.inject(Theme)
    yield () => circle({ radius: 1, fill: colour })
  })

  const App = component(function* () {
    this.provide(Theme, '#abc')
    yield () => group(Leaf())
  })

  const { scene } = mountScene(App())
  const leaf = (scene.firstChild as SceneNode).firstChild as SceneNode
  expect(leaf.fill).toBe('#abc')
})

test('using scopes unwind on unmount under the canvas host', () => {
  const log: string[] = []
  const Leaf = component(function* () {
    using _cleanup = disposable(() => log.push('cleanup'))
    using _resource = {
      [Symbol.dispose]() {
        log.push('dispose')
      },
    }
    yield () => circle({ radius: 1, fill: '#0f0' })
  })

  const { root } = mountScene(Leaf())
  root.unmount()
  // Reverse registration order, same as the DOM path.
  expect(log).toEqual(['dispose', 'cleanup'])
})

test('ref hands back the scene node, which can then be driven imperatively', () => {
  const captured: SceneNode[] = []
  const { scene } = mountScene(
    circle({ radius: 2, fill: '#0f0', ref: (node) => captured.push(node) }),
  )

  expect(captured).toHaveLength(1)
  const node = captured[0] as SceneNode
  expect(node).toBe(scene.firstChild as SceneNode)

  // The control arm of the stress example depends on exactly this.
  node.x = 12.5
  expect((scene.firstChild as SceneNode).x).toBe(12.5)
})

test('one commit per settled reconcile, however many components resumed', () => {
  const a = signal(1)
  const b = signal(1)
  const Dot = component<{ n: number }>(function* (props) {
    yield () => circle({ radius: props.n, fill: '#0f0' })
  })
  const App = component(function* () {
    yield () => group(Dot({ n: a.value }), Dot({ n: b.value }))
  })

  const { commits } = mountScene(App())
  const afterMount = commits()
  expect(afterMount).toBe(1)

  // Two writes, two component resumes, one flush — and one repaint. This is
  // what keeps a fine-grained scene from repainting once per signal.
  a.value = 2
  b.value = 3
  flushSync()
  expect(commits()).toBe(afterMount + 1)
})

test('portals are refused rather than half-supported', () => {
  const target = createSceneNode('group')
  expect(() => mountScene(portal(target as unknown as Element, circle({ radius: 1 })))).toThrow(
    /no portals/,
  )
})

test('unmounting tears the scene down completely', () => {
  const Leaf = component(function* () {
    yield () => circle({ radius: 1, fill: '#0f0' })
  })
  const { scene, root } = mountScene(group(Leaf(), Leaf()))

  expect(scene.childCount).toBe(1)
  root.unmount()
  expect(scene.childCount).toBe(0)
  expect(scene.firstChild).toBe(null)
})

// ---------------------------------------------------------------------------
// Root lifecycle
// ---------------------------------------------------------------------------
