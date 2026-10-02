import { expect, test } from 'bun:test'
import { hitTest } from './index.ts'
import { createSceneNode, insertBefore, type SceneNode } from '../scene/index.ts'

function shape(tag: SceneNode['tag'], props: Partial<SceneNode> = {}): SceneNode {
  return Object.assign(createSceneNode(tag), props)
}

function scene(...children: SceneNode[]): SceneNode {
  const root = createSceneNode('#root')
  for (const child of children) insertBefore(root, child, null)
  return root
}

test('a circle is hit inside its radius and missed outside', () => {
  const dot = shape('circle', { x: 50, y: 50, radius: 10, fill: '#a' })
  const root = scene(dot)

  expect(hitTest(root, 50, 50)).toBe(dot)
  expect(hitTest(root, 59, 50)).toBe(dot)
  expect(hitTest(root, 61, 50)).toBe(null)
})

test('a rect is hit within its box, measured from its top-left', () => {
  const box = shape('rect', { x: 10, y: 10, width: 20, height: 5, fill: '#a' })
  const root = scene(box)

  expect(hitTest(root, 10, 10)).toBe(box)
  expect(hitTest(root, 29, 14)).toBe(box)
  expect(hitTest(root, 31, 14)).toBe(null)
  expect(hitTest(root, 20, 16)).toBe(null)
})

test('the topmost shape wins, which is the last one painted', () => {
  const under = shape('rect', { width: 100, height: 100, fill: '#a' })
  const over = shape('circle', { x: 50, y: 50, radius: 10, fill: '#b' })
  const root = scene(under, over)

  // Reverse paint order, so the answer agrees with what is visible.
  expect(hitTest(root, 50, 50)).toBe(over)
  expect(hitTest(root, 5, 5)).toBe(under)
})

test('a group’s transform is undone before its children are tested', () => {
  const dot = shape('circle', { radius: 5, fill: '#a' })
  const holder = shape('group', { x: 100, y: 40 })
  insertBefore(holder, dot, null)
  const root = scene(holder)

  expect(hitTest(root, 100, 40)).toBe(dot)
  expect(hitTest(root, 0, 0)).toBe(null)
})

test('rotation and scale are undone too', () => {
  const box = shape('rect', { width: 10, height: 2, fill: '#a' })
  const holder = shape('group', { x: 50, y: 50, rotate: Math.PI / 2 })
  insertBefore(holder, box, null)
  const root = scene(holder)

  // Rotated a quarter turn: the box now runs downward from the group's origin.
  expect(hitTest(root, 50, 58)).toBe(box)
  expect(hitTest(root, 58, 50)).toBe(null)

  const scaled = shape('group', { scaleX: 2, scaleY: 2 })
  insertBefore(scaled, shape('circle', { radius: 5, fill: '#a' }), null)
  expect(hitTest(scene(scaled), 9, 0)).not.toBe(null)
  expect(hitTest(scene(scaled), 11, 0)).toBe(null)
})

test('an invisible or transparent subtree is not hittable', () => {
  const dot = shape('circle', { radius: 10, fill: '#a' })
  const hidden = shape('group', { visible: false })
  insertBefore(hidden, dot, null)
  expect(hitTest(scene(hidden), 0, 0)).toBe(null)

  const clear = shape('group', { alpha: 0 })
  insertBefore(clear, shape('circle', { radius: 10, fill: '#a' }), null)
  expect(hitTest(scene(clear), 0, 0)).toBe(null)
})

test('a clip bounds what can be hit inside it', () => {
  const dot = shape('circle', { x: 40, y: 0, radius: 5, fill: '#a' })
  const holder = shape('group', { clip: { x: 0, y: -10, width: 20, height: 20 } })
  insertBefore(holder, dot, null)
  const root = scene(holder)

  // Visually clipped away, so not hittable either.
  expect(hitTest(root, 40, 0)).toBe(null)
  expect(hitTest(root, 5, 0)).toBe(null)
})

test('a line is hit within half its stroke width', () => {
  const seg = shape('line', {
    x: 0,
    y: 0,
    x2: 100,
    y2: 0,
    stroke: '#a',
    lineWidth: 8,
  })
  const root = scene(seg)

  expect(hitTest(root, 50, 0)).toBe(seg)
  expect(hitTest(root, 50, 3)).toBe(seg)
  expect(hitTest(root, 50, 6)).toBe(null)
  // Past the end, not merely off to the side.
  expect(hitTest(root, 120, 0)).toBe(null)
})

test('groups, text and paths are not targets themselves', () => {
  const root = scene(
    shape('group', { x: 0, y: 0 }),
    shape('text', { text: 'hi', fill: '#a' }),
    shape('path', { path: 'M0 0 L10 10', fill: '#a' }),
  )
  // Documented: deciding a point is inside a Path2D needs a rendering context,
  // and this function deliberately has none.
  expect(hitTest(root, 0, 0)).toBe(null)
})
