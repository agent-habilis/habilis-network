/**
 * The canvas backend — the same component concept, drawing instead of writing.
 *
 *     import { component, signal } from 'visage-dom'
 *     import { renderCanvas, shapes } from 'visage-canvas'
 *
 *     const { group, circle, text } = shapes
 *
 *     const Blip = component(function* () {
 *       const t = signal(0)
 *       using _spin = animation(() => { t.value += 0.02 })
 *       yield () =>
 *         group(
 *           { x: 100, y: 100, rotate: t.value },
 *           circle({ x: 40, radius: 8, fill: '#7dd3a0' }),
 *           text({ y: -20, fill: '#ddd', font: '12px mono' }, 'spin'),
 *         )
 *     })
 *
 *     renderCanvas(Blip(), document.querySelector('canvas')!)
 *
 * Nothing above is canvas-specific except the shape names. Generators, signals,
 * `yield*` delegation, `try`/`catch` boundaries, context, keyed lists and
 * `using` disposal all arrive unchanged, because the reconciler driving them
 * never knew what a DOM node was — see `../host/index.ts`.
 *
 * A deliberate exception: **portals throw here.** They exist to escape an
 * `overflow` or `z-index` context, and a scene graph has neither.
 *
 * This module is a separate entry point (`visage-canvas`) and
 * nothing in the default one imports it, so a DOM-only app pays nothing for it.
 */

import { renderWith, type Root } from 'visage-dom/reconcile'
import { observe } from 'visage-dom/resources'
import type { View } from 'visage-dom/types'
import { paint, type PaintContext } from './paint/index.ts'
import { createCanvasHost, createSceneNode, type SceneNode } from './scene/index.ts'

export interface CanvasRootOptions {
  /**
   * Backing-store scale. Defaults to `devicePixelRatio` clamped to 2 — a 3x
   * phone display costs 2.25x the fill rate of a 2x one for a difference
   * nothing in a 2D scene resolves.
   */
  dpr?: number
  /**
   * Painted under the scene each frame. Leave it out to keep the previous frame
   * underneath, which is how trails and motion blur are drawn.
   */
  background?: string
  /** Track the canvas's CSS box with a `ResizeObserver`. Default true. */
  autoResize?: boolean
}

export interface CanvasRoot extends Root {
  /**
   * Repaint now instead of on the next frame.
   *
   * Paint is normally scheduled on `requestAnimationFrame`, so any number of
   * commits in one frame collapse into one repaint. Force it when you are
   * measuring the paint, or driving the scene from your own frame loop.
   */
  paint(): void
  /** Re-read the CSS box and rebuild the backing store. Automatic by default. */
  resize(): void
  /** The scene graph's root, for `hitTest` and for `ref`-free inspection. */
  readonly scene: SceneNode
}

export function renderCanvas(
  view: View,
  canvas: HTMLCanvasElement,
  options: CanvasRootOptions = {},
): CanvasRoot {
  const ctx = canvas.getContext('2d') as PaintContext | null
  if (ctx === null) {
    throw new Error('view: renderCanvas needs a 2d context, and this canvas has none.')
  }

  const scene = createSceneNode('#root')
  let width = 0
  let height = 0
  let frame = 0
  let disposed = false

  const dpr = options.dpr ?? Math.min(globalThis.devicePixelRatio || 1, 2)

  function resize(): void {
    // After unmount the attributes must be left alone: writing `canvas.width`
    // wipes the backing store, and `paintNow` below is a no-op by then, so this
    // would blank whatever the last frame left on screen.
    if (disposed) return
    // The CSS box is the source of truth; the attributes follow it. Reading
    // clientWidth on a detached or `display: none` canvas gives 0, so fall back
    // to whatever the attributes already say rather than collapsing to nothing.
    const cssW = canvas.clientWidth || canvas.width / dpr || 0
    const cssH = canvas.clientHeight || canvas.height / dpr || 0
    if (cssW === width && cssH === height) return
    width = cssW
    height = cssH
    canvas.width = Math.round(cssW * dpr)
    canvas.height = Math.round(cssH * dpr)
    paintNow()
  }

  function paintNow(): void {
    if (disposed) return
    if (frame !== 0) {
      cancelAnimationFrame(frame)
      frame = 0
    }
    paint(ctx as PaintContext, scene, {
      dpr,
      width,
      height,
      background: options.background,
    })
  }

  /**
   * The host's end-of-commit hook. N generator resumes in one flush, and N
   * flushes in one frame, all coalesce here into a single repaint — which is
   * the right policy no matter how few shapes changed, because the repaint is
   * total either way.
   */
  function schedulePaint(): void {
    if (disposed || frame !== 0) return
    frame = requestAnimationFrame(() => {
      frame = 0
      paintNow()
    })
  }

  const host = createCanvasHost(schedulePaint)

  let root: ReturnType<typeof renderWith>
  try {
    root = renderWith(view, scene, host)
  } catch (error) {
    // The commit inside `renderWith`'s own teardown still ran `schedulePaint`,
    // so a frame is queued even though no root is coming back. Left alone it
    // fires and paints a half-built scene into a canvas nobody owns.
    disposed = true
    if (frame !== 0) cancelAnimationFrame(frame)
    frame = 0
    throw error
  }

  resize()

  const watcher =
    options.autoResize === false
      ? null
      : observe(new ResizeObserver(() => resize()), canvas)

  return {
    scene,
    update(next: View) {
      // Mounts a live tree that can never paint: generators run, timers start,
      // and every commit is swallowed by the `disposed` guard. The DOM host
      // throws outright here, and failing silently is worse.
      if (disposed) {
        throw new Error('visage-canvas: update() on an unmounted root.')
      }
      root.update(next)
    },
    unmount() {
      if (disposed) return
      if (frame !== 0) cancelAnimationFrame(frame)
      frame = 0
      watcher?.[Symbol.dispose]()
      root.unmount()
      // Painted *after* the tree is torn down, so the canvas ends up empty
      // rather than frozen on the last frame with no way to clear it. The DOM
      // host removes its nodes on unmount; this is the equivalent.
      paintNow()
      disposed = true
    },
    paint: paintNow,
    resize,
  }
}

export { shapes } from './shapes/index.ts'
export { hitTest } from './hit/index.ts'
export { paint, type PaintContext, type PaintOptions } from './paint/index.ts'
export type { SceneNode, SceneTag } from './scene/index.ts'
export type {
  Paintable,
  Rect,
  ShapeAttrs,
  ShapeAttrsMap,
  Shapes,
  ShapeTag,
  ShapeTagFn,
  Transform,
} from './types/index.ts'
