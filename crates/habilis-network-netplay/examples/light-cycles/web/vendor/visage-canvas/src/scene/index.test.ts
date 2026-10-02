import { expect, test } from 'bun:test'
import { createCanvasHost, createSceneNode, type SceneNode } from './index.ts'
import type { Host } from 'visage-dom/host'

const host: Host = createCanvasHost(() => {})

const node = (tag = 'circle'): SceneNode => createSceneNode(tag as SceneNode['tag'])

/** The child list, read forwards. */
const forwards = (parent: SceneNode): SceneNode[] => {
  const out: SceneNode[] = []
  for (let child = parent.firstChild; child !== null; child = child.next) out.push(child)
  return out
}

/**
 * The child list, read backwards. Every assertion below checks both, because a
 * doubly-linked list that is right in one direction and wrong in the other is
 * the failure mode — and `hitTest` walks it backwards.
 */
const backwards = (parent: SceneNode): SceneNode[] => {
  const out: SceneNode[] = []
  for (let child = parent.lastChild; child !== null; child = child.prev) out.push(child)
  return out.reverse()
}

function expectChildren(parent: SceneNode, expected: SceneNode[], label = ''): void {
  expect(forwards(parent), `${label} forwards`).toEqual(expected)
  expect(backwards(parent), `${label} backwards`).toEqual(expected)
  expect(parent.childCount, `${label} count`).toBe(expected.length)
  for (const child of expected) expect(child.parent).toBe(parent)
}

test('append builds the list in order', () => {
  const root = node('#root')
  const a = node()
  const b = node()
  const c = node()

  host.append(root, a)
  host.append(root, b)
  host.append(root, c)

  expectChildren(root, [a, b, c])
})

test('insert places a node before another, and at the front', () => {
  const root = node('#root')
  const a = node()
  const b = node()
  const c = node()

  host.insert(root, a, null)
  host.insert(root, c, null)
  host.insert(root, b, c) // middle
  expectChildren(root, [a, b, c], 'middle')

  const head = node()
  host.insert(root, head, a) // front
  expectChildren(root, [head, a, b, c], 'front')
})

test('insert doubles as a move: a node already in the tree leaves its old slot', () => {
  const root = node('#root')
  const a = node()
  const b = node()
  const c = node()
  for (const n of [a, b, c]) host.append(root, n)

  // This is exactly what `moveFiber` does, and the reason `insertBefore`
  // detaches first. Without it the list would corrupt rather than reorder.
  host.insert(root, c, a)
  expectChildren(root, [c, a, b], 'moved to front')

  host.insert(root, c, null)
  expectChildren(root, [a, b, c], 'moved to back')
})

test('remove unlinks from either end and from the middle', () => {
  const root = node('#root')
  const a = node()
  const b = node()
  const c = node()
  for (const n of [a, b, c]) host.append(root, n)

  host.remove(b)
  expectChildren(root, [a, c], 'middle gone')
  expect(b.parent).toBe(null)
  expect(b.prev).toBe(null)
  expect(b.next).toBe(null)

  host.remove(a)
  expectChildren(root, [c], 'head gone')
  host.remove(c)
  expectChildren(root, [], 'tail gone')
  expect(root.firstChild).toBe(null)
  expect(root.lastChild).toBe(null)
})

test('removing a detached node is a no-op, not a corruption', () => {
  const orphan = node()
  expect(() => host.remove(orphan)).not.toThrow()
  expect(orphan.parent).toBe(null)
})

test('nextSibling and childCount are what the reconciler reads', () => {
  const root = node('#root')
  const a = node()
  const b = node()
  host.append(root, a)
  host.append(root, b)

  expect(host.nextSibling(a)).toBe(b)
  expect(host.nextSibling(b)).toBe(null)
  expect(host.childCount(root)).toBe(2)
})

test('clear drops every child and orphans each one', () => {
  const root = node('#root')
  const kids = [node(), node(), node()]
  for (const n of kids) host.append(root, n)

  host.clear(root)
  expectChildren(root, [])
  // Orphaned properly, not merely unreachable from the parent — a child that
  // kept a stale `parent` would corrupt the list on its next insert.
  for (const child of kids) {
    expect(child.parent).toBe(null)
    expect(child.prev).toBe(null)
    expect(child.next).toBe(null)
  }
})

test('props land on flat fields', () => {
  const circle = node('circle')
  host.applyProps(circle, { x: 10, y: 20, radius: 4, fill: '#0f0', alpha: 0.5 })

  expect(circle.x).toBe(10)
  expect(circle.y).toBe(20)
  expect(circle.radius).toBe(4)
  expect(circle.fill).toBe('#0f0')
  expect(circle.alpha).toBe(0.5)
})

test('a prop that goes away is restored to its default, not left behind', () => {
  const circle = node('circle')
  const first = { x: 10, fill: '#0f0', alpha: 0.5, visible: false }
  host.applyProps(circle, first)
  expect(circle.fill).toBe('#0f0')

  // The scene node outlives its descriptors. Without the undefined branch in
  // setProp, a shape that stops declaring `fill` would keep painting the old
  // one forever — the bug this test exists for.
  host.applyProps(circle, { x: 10 }, first)
  expect(circle.x).toBe(10)
  expect(circle.fill).toBe(null)
  expect(circle.alpha).toBe(1)
  expect(circle.visible).toBe(true)
})

test('key, ref and children are the reconciler’s, not the node’s', () => {
  const circle = node('circle')
  expect(() =>
    host.applyProps(circle, { key: 3, ref: () => {}, children: [], radius: 1 }),
  ).not.toThrow()
  expect(circle.radius).toBe(1)
})

test('an unknown prop throws rather than vanishing', () => {
  const circle = node('circle')
  // The DOM host falls back to setAttribute; there is no such thing here, and
  // a silently dropped prop is how a typo becomes an afternoon.
  expect(() => host.applyProps(circle, { colour: 'red' })).toThrow(/no canvas prop "colour"/)
})

test('the host declines portals', () => {
  expect(host.supportsPortals).toBe(false)
})

test('the host declines the fragment fast path', () => {
  // An insertion here is four pointer writes, so staging would cost more than
  // it saves. `mountRange` takes its direct path instead.
  expect(host.createFragment()).toBe(null)
})

test('every node has the same shape, whatever its tag', () => {
  // The painter reads these fields ten thousand times a frame and wants them
  // monomorphic. Filling fields in lazily would give a circle and a text
  // different hidden classes.
  const keys = (n: SceneNode) => Object.keys(n).sort()
  expect(keys(node('circle'))).toEqual(keys(node('text')))
  expect(keys(node('circle'))).toEqual(keys(node('#hole')))
})
