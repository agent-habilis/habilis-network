/**
 * `renderCanvas`'s own lifecycle.
 *
 * Everything here is about the root rather than the reconciler: the rAF handle,
 * the resize observer, and the ordering of unmount. `reconcile.test.ts` drives
 * the host directly and so never exercises any of it.
 */

import { test, expect, beforeEach, afterEach } from 'bun:test'
import { component, flushSync, signal } from 'visage-dom'
import { renderCanvas } from './index.ts'
import { shapes } from './shapes/index.ts'
import { fakeRaf, makeCanvas, recorder } from './harness.test-util.ts'

const { circle, group } = shapes

let raf: ReturnType<typeof fakeRaf>

beforeEach(() => {
  document.body.innerHTML = ''
  raf = fakeRaf()
  raf.install()
})
afterEach(() => raf.restore())

test('commits in one flush coalesce into a single frame', () => {
  const { ctx } = recorder()
  const count = signal(1)
  const App = component(function* () {
    yield () => group({}, ...Array.from({ length: count.value }, () => circle({ radius: 1 })))
  })

  const root = renderCanvas(App(), makeCanvas(100, 50, ctx), { dpr: 2 })

  count.value = 2
  flushSync()
  count.value = 3
  flushSync()
  expect(raf.pending()).toBe(1)

  root.unmount()
})

test('update() after unmount throws rather than mounting an invisible tree', () => {
  const { ctx } = recorder()
  const root = renderCanvas(circle({ radius: 1 }), makeCanvas(100, 50, ctx))
  root.unmount()

  // It used to mount a live tree — generators running, timers started — whose
  // every commit was swallowed by the `disposed` guard, so nothing painted and
  // nothing complained. The DOM host throws outright in the same situation.
  expect(() => root.update(circle({ radius: 2 }))).toThrow(/unmounted/)
})

test('resize() after unmount leaves the backing store alone', () => {
  const { ctx } = recorder()
  const canvas = makeCanvas(100, 50, ctx)
  const root = renderCanvas(circle({ radius: 1 }), canvas, { dpr: 2 })
  const width = canvas.width
  root.unmount()

  Object.defineProperty(canvas, 'clientWidth', { get: () => 300, configurable: true })
  root.resize()

  // Writing `canvas.width` wipes the backing store, and `paintNow` is a no-op
  // by then — so this used to blank the canvas on a stray observer callback.
  expect(canvas.width).toBe(width)
})

test('unmount clears the canvas instead of freezing the last frame', () => {
  const { ctx, log } = recorder()
  const root = renderCanvas(circle({ radius: 1, fill: '#0f0' }), makeCanvas(100, 50, ctx))
  raf.flush()
  log.length = 0

  root.unmount()

  // The DOM host removes its nodes on unmount; the canvas equivalent is a final
  // paint of the emptied scene. Without it the last frame stays on screen with
  // no way to clear it, since `paint()` is a no-op once disposed.
  expect(log.some((call) => call.startsWith('clearRect'))).toBe(true)
  expect(log.some((call) => call.startsWith('arc'))).toBe(false)
})

test('unmount is idempotent and leaves no frame queued', () => {
  const { ctx } = recorder()
  const count = signal(1)
  const App = component(function* () {
    yield () => group({}, ...Array.from({ length: count.value }, () => circle({ radius: 1 })))
  })

  const root = renderCanvas(App(), makeCanvas(100, 50, ctx))
  count.value = 2
  flushSync()

  root.unmount()
  expect(raf.pending()).toBe(0)
  expect(() => root.unmount()).not.toThrow()
})

test('a throw during the initial mount leaves no frame queued', () => {
  const { ctx } = recorder()
  const Boom = component(function* () {
    throw new Error('mount boom')
    // eslint-disable-next-line no-unreachable
    yield () => circle({ radius: 1 })
  })

  expect(() => renderCanvas(Boom(), makeCanvas(100, 50, ctx))).toThrow(/mount boom/)

  // `renderWith`'s teardown still ran a commit, so a frame was queued even
  // though no root came back — it fired and painted a half-built scene.
  expect(raf.pending()).toBe(0)
})
