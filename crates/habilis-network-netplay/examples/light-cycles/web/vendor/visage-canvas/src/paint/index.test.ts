/**
 * The painter, asserted against the draw-call sequence it emits.
 *
 * happy-dom's `getContext('2d')` returns null, so there is no context to paint
 * into headlessly — but a recorder is the right instrument anyway. A canvas
 * renderer's output *is* the call sequence; comparing pixels would be a slower,
 * blurrier way of asking the same question, and it would not catch the two
 * things most worth catching here: a `save` without its `restore`, and a style
 * setter issued ten thousand times when once would do.
 */

import { expect, test } from 'bun:test'
import { paint, type PaintContext } from './index.ts'
import { createSceneNode, insertBefore, type SceneNode } from '../scene/index.ts'

interface Call {
  op: string
  args: readonly unknown[]
}

const METHODS = new Set([
  'save', 'restore', 'setTransform', 'translate', 'rotate', 'scale',
  'clearRect', 'beginPath', 'closePath', 'moveTo', 'lineTo', 'rect', 'arc',
  'clip', 'fill', 'stroke', 'fillRect', 'strokeRect', 'fillText', 'drawImage',
  'roundRect',
])

interface Recorder {
  ctx: PaintContext
  calls: Call[]
  ops(): string[]
  count(op: string): number
}

function recorder(options: { roundRect?: boolean } = {}): Recorder {
  const calls: Call[] = []
  const store: Record<string, unknown> = {}

  const ctx = new Proxy(store, {
    get(_target, key) {
      if (typeof key !== 'string') return undefined
      if (key === 'roundRect' && options.roundRect !== true) return undefined
      if (METHODS.has(key)) {
        return (...args: unknown[]) => {
          calls.push({ op: key, args })
        }
      }
      return store[key]
    },
    set(_target, key, value) {
      if (typeof key === 'string') {
        calls.push({ op: `=${key}`, args: [value] })
        store[key] = value
      }
      return true
    },
  }) as unknown as PaintContext

  return {
    ctx,
    calls,
    ops: () => calls.map((c) => c.op),
    count: (op) => calls.filter((c) => c.op === op).length,
  }
}

const OPTIONS = { dpr: 2, width: 100, height: 50 }

function scene(...children: SceneNode[]): SceneNode {
  const root = createSceneNode('#root')
  for (const child of children) insertBefore(root, child, null)
  return root
}

function shape(tag: SceneNode['tag'], props: Partial<SceneNode> = {}): SceneNode {
  return Object.assign(createSceneNode(tag), props)
}

/** Only the calls after the frame preamble (transform + clear). */
function body(rec: Recorder): Call[] {
  return rec.calls.filter((c) => c.op !== 'setTransform' && c.op !== 'clearRect')
}

test('the frame opens by scaling to the device ratio and clearing', () => {
  const rec = recorder()
  paint(rec.ctx, scene(), OPTIONS)

  expect(rec.calls[0]).toEqual({ op: 'setTransform', args: [2, 0, 0, 2, 0, 0] })
  expect(rec.calls[1]).toEqual({ op: 'clearRect', args: [0, 0, 100, 50] })
})

test('a background is painted under the scene, in CSS pixels', () => {
  const rec = recorder()
  paint(rec.ctx, scene(), { ...OPTIONS, background: '#111' })

  expect(rec.ops()).toEqual([
    'setTransform', 'clearRect', '=globalAlpha', '=fillStyle', 'fillRect',
  ])
  expect(rec.calls.at(-1)).toEqual({ op: 'fillRect', args: [0, 0, 100, 50] })
})

test('paint order is tree order — later siblings land on top', () => {
  const rec = recorder()
  paint(
    rec.ctx,
    scene(
      shape('circle', { x: 1, y: 1, radius: 1, fill: '#a' }),
      shape('circle', { x: 2, y: 2, radius: 1, fill: '#b' }),
      shape('circle', { x: 3, y: 3, radius: 1, fill: '#c' }),
    ),
    OPTIONS,
  )

  const centres = rec.calls.filter((c) => c.op === 'arc').map((c) => c.args[0])
  expect(centres).toEqual([1, 2, 3])
})

test('a translation-only ancestor costs no context state at all', () => {
  const rec = recorder()
  const group = shape('group', { x: 10, y: 20 })
  insertBefore(group, shape('circle', { x: 5, y: 5, radius: 2, fill: '#0f0' }), null)
  paint(rec.ctx, scene(group), OPTIONS)

  // The whole point of folding the offset into the draw call: at ten thousand
  // shapes a save/restore pair per node is twenty thousand state pushes.
  expect(rec.count('save')).toBe(0)
  expect(rec.count('restore')).toBe(0)
  expect(rec.count('translate')).toBe(0)
  const arc = rec.calls.find((c) => c.op === 'arc')
  expect(arc?.args.slice(0, 2)).toEqual([15, 25])
})

test('rotation escalates to a real transform, and balances it', () => {
  const rec = recorder()
  const group = shape('group', { x: 10, y: 20, rotate: 0.5 })
  insertBefore(group, shape('circle', { x: 5, radius: 2, fill: '#0f0' }), null)
  paint(rec.ctx, scene(group), OPTIONS)

  const ops = body(rec).map((c) => c.op)
  expect(ops).toEqual([
    'save', 'translate', 'rotate',
    '=globalAlpha', 'beginPath', 'arc', '=fillStyle', 'fill',
    'restore',
  ])
  expect(rec.calls.find((c) => c.op === 'translate')?.args).toEqual([10, 20])
  // Inside the transform the child draws in local coordinates, not offset ones.
  expect(rec.calls.find((c) => c.op === 'arc')?.args.slice(0, 2)).toEqual([5, 0])
})

test('scale escalates too, and composes with the translation', () => {
  const rec = recorder()
  const group = shape('group', { x: 4, y: 4, scaleX: 2, scaleY: 3 })
  insertBefore(group, shape('rect', { width: 1, height: 1, fill: '#0f0' }), null)
  paint(rec.ctx, scene(group), OPTIONS)

  expect(rec.calls.find((c) => c.op === 'translate')?.args).toEqual([4, 4])
  expect(rec.calls.find((c) => c.op === 'scale')?.args).toEqual([2, 3])
  expect(rec.count('save')).toBe(1)
  expect(rec.count('restore')).toBe(1)
})

test('a clip saves, clips, and restores exactly once', () => {
  const rec = recorder()
  const group = shape('group', { clip: { x: 0, y: 0, width: 10, height: 10 } })
  insertBefore(group, shape('circle', { radius: 2, fill: '#0f0' }), null)
  paint(rec.ctx, scene(group), OPTIONS)

  const ops = body(rec).map((c) => c.op)
  expect(ops.filter((o) => o === 'save' || o === 'restore')).toEqual(['save', 'restore'])
  expect(ops).toContain('clip')
  expect(rec.calls.find((c) => c.op === 'rect')?.args).toEqual([0, 0, 10, 10])
})

test('visible: false paints nothing and skips the whole subtree', () => {
  const rec = recorder()
  const group = shape('group', { visible: false })
  insertBefore(group, shape('circle', { radius: 2, fill: '#0f0' }), null)
  insertBefore(group, shape('rect', { width: 2, height: 2, fill: '#0f0' }), null)
  paint(rec.ctx, scene(group, shape('circle', { radius: 1, fill: '#a' })), OPTIONS)

  // One arc: the visible sibling. Nothing from inside the hidden group.
  expect(rec.count('arc')).toBe(1)
  expect(rec.count('fillRect')).toBe(0)
})

test('alpha multiplies down the tree, the way opacity composites', () => {
  const rec = recorder()
  const group = shape('group', { alpha: 0.5 })
  insertBefore(group, shape('circle', { radius: 2, fill: '#0f0', alpha: 0.5 }), null)
  paint(rec.ctx, scene(group), OPTIONS)

  const alphas = rec.calls.filter((c) => c.op === '=globalAlpha').map((c) => c.args[0])
  expect(alphas).toEqual([0.25])
})

test('a fully transparent subtree is skipped before any work is done', () => {
  const rec = recorder()
  const group = shape('group', { alpha: 0 })
  insertBefore(group, shape('circle', { radius: 2, fill: '#0f0' }), null)
  paint(rec.ctx, scene(group), OPTIONS)

  expect(body(rec)).toEqual([])
})

test('style setters are issued once for a run of shapes that share them', () => {
  const rec = recorder()
  const kids = Array.from({ length: 50 }, (_, i) =>
    shape('circle', { x: i, radius: 1, fill: '#0f0', alpha: 1 }),
  )
  paint(rec.ctx, scene(...kids), OPTIONS)

  expect(rec.count('arc')).toBe(50)
  // Fifty circles, one fillStyle write. This is the difference between a
  // scene-graph painter and a naive one at ten thousand shapes.
  expect(rec.count('=fillStyle')).toBe(1)
  expect(rec.count('=globalAlpha')).toBe(1)
})

test('a restore invalidates the style cache rather than lying about it', () => {
  const rec = recorder()
  const rotated = shape('group', { rotate: 1 })
  insertBefore(rotated, shape('circle', { radius: 1, fill: '#0f0' }), null)
  paint(rec.ctx, scene(rotated, shape('circle', { radius: 1, fill: '#0f0' })), OPTIONS)

  // Same fill on both, but the restore between them puts the context back to
  // whatever it was at the save, so the cache must forget and re-set.
  expect(rec.count('=fillStyle')).toBe(2)
})

test('rect fills, strokes, and takes the rounded path only when asked and able', () => {
  const plain = recorder()
  paint(plain.ctx, scene(shape('rect', { width: 4, height: 3, fill: '#a' })), OPTIONS)
  expect(plain.calls.find((c) => c.op === 'fillRect')?.args).toEqual([0, 0, 4, 3])

  const rounded = recorder({ roundRect: true })
  paint(
    rounded.ctx,
    scene(shape('rect', { width: 4, height: 3, radius: 1, fill: '#a' })),
    OPTIONS,
  )
  expect(rounded.count('roundRect')).toBe(1)
  expect(rounded.count('fillRect')).toBe(0)

  // No roundRect in this context: fall back rather than throw.
  const fallback = recorder()
  paint(
    fallback.ctx,
    scene(shape('rect', { width: 4, height: 3, radius: 1, fill: '#a' })),
    OPTIONS,
  )
  expect(fallback.count('fillRect')).toBe(1)
})

test('a zero-sized or invisible shape emits nothing', () => {
  const rec = recorder()
  paint(
    rec.ctx,
    scene(
      shape('rect', { width: 0, height: 5, fill: '#a' }),
      shape('circle', { radius: 0, fill: '#a' }),
      shape('circle', { radius: 2 }), // no fill, no stroke
      shape('text', { fill: '#a' }), // no text
    ),
    OPTIONS,
  )
  expect(body(rec)).toEqual([])
})

test('line runs from (x, y) to (x2, y2) in the same space', () => {
  const rec = recorder()
  const group = shape('group', { x: 100, y: 100 })
  insertBefore(
    group,
    shape('line', { x: 1, y: 2, x2: 11, y2: 22, stroke: '#a', lineWidth: 3 }),
    null,
  )
  paint(rec.ctx, scene(group), OPTIONS)

  expect(rec.calls.find((c) => c.op === 'moveTo')?.args).toEqual([101, 102])
  expect(rec.calls.find((c) => c.op === 'lineTo')?.args).toEqual([111, 122])
  expect(rec.calls.find((c) => c.op === '=lineWidth')?.args).toEqual([3])
})

test('text draws its own prop, or its string children concatenated', () => {
  const own = recorder()
  paint(
    own.ctx,
    scene(shape('text', { text: 'hi', fill: '#a', font: '12px mono', x: 3, y: 4 })),
    OPTIONS,
  )
  expect(own.calls.find((c) => c.op === 'fillText')?.args).toEqual(['hi', 3, 4])
  expect(own.calls.find((c) => c.op === '=font')?.args).toEqual(['12px mono'])

  const fromChildren = recorder()
  const label = shape('text', { fill: '#a' })
  for (const part of ['count: ', '7']) {
    const t = createSceneNode('#text')
    t.data = part
    insertBefore(label, t, null)
  }
  paint(fromChildren.ctx, scene(label), OPTIONS)
  expect(fromChildren.calls.find((c) => c.op === 'fillText')?.args).toEqual([
    'count: 7',
    0,
    0,
  ])
})

test('maxWidth is passed only when set', () => {
  const without = recorder()
  paint(without.ctx, scene(shape('text', { text: 'a', fill: '#a' })), OPTIONS)
  expect(without.calls.find((c) => c.op === 'fillText')?.args).toHaveLength(3)

  const with_ = recorder()
  paint(with_.ctx, scene(shape('text', { text: 'a', fill: '#a', maxWidth: 40 })), OPTIONS)
  expect(with_.calls.find((c) => c.op === 'fillText')?.args).toEqual(['a', 0, 0, 40])
})

test('holes and text nodes paint nothing on their own', () => {
  const rec = recorder()
  const hole = createSceneNode('#hole')
  const text = createSceneNode('#text')
  text.data = 'orphan'
  paint(rec.ctx, scene(hole, text), OPTIONS)
  expect(body(rec)).toEqual([])
})
