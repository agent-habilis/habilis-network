/**
 * Fakes for testing `renderCanvas` itself.
 *
 * `reconcile.test.ts` bypasses `renderCanvas` and drives the host directly,
 * because the real entry point wants a 2d context and happy-dom has none. That
 * left the root's own lifecycle — the rAF handle, the resize observer, the
 * unmount ordering — with no coverage at all. A recording context and a
 * controllable rAF are enough to close that.
 */

interface RecordingContext {
  [key: string]: unknown
}

export interface FakeRaf {
  install(): void
  restore(): void
  /** Frames queued but not yet run. */
  pending(): number
  flush(now?: number): void
  readonly calls: { req: number; cancel: number }
}

/** Replaces rAF with a queue the test drains by hand. */
export function fakeRaf(): FakeRaf {
  let next = 1
  const queue = new Map<number, FrameRequestCallback>()
  const calls = { req: 0, cancel: 0 }
  let originalRequest: typeof globalThis.requestAnimationFrame
  let originalCancel: typeof globalThis.cancelAnimationFrame

  return {
    calls,
    install() {
      originalRequest = globalThis.requestAnimationFrame
      originalCancel = globalThis.cancelAnimationFrame
      globalThis.requestAnimationFrame = (callback: FrameRequestCallback): number => {
        calls.req += 1
        const id = next++
        queue.set(id, callback)
        return id
      }
      globalThis.cancelAnimationFrame = (id: number): void => {
        calls.cancel += 1
        queue.delete(id)
      }
    },
    restore() {
      globalThis.requestAnimationFrame = originalRequest
      globalThis.cancelAnimationFrame = originalCancel
    },
    pending: () => queue.size,
    flush(now = 0) {
      const batch = [...queue.values()]
      queue.clear()
      for (const callback of batch) callback(now)
    },
  }
}

const METHODS = [
  'save', 'restore', 'setTransform', 'translate', 'rotate', 'scale',
  'clearRect', 'beginPath', 'closePath', 'moveTo', 'lineTo', 'rect', 'arc',
  'clip', 'fill', 'stroke', 'fillRect', 'strokeRect', 'fillText', 'drawImage',
  'roundRect',
] as const

/** A 2d context that records the calls made against it. */
export function recorder(): { ctx: unknown; log: string[] } {
  const log: string[] = []
  const ctx: RecordingContext = {
    fillStyle: '',
    strokeStyle: '',
    lineWidth: 1,
    lineCap: 'butt',
    lineJoin: 'miter',
    globalAlpha: 1,
    font: '',
    textAlign: 'start',
    textBaseline: 'alphabetic',
  }
  for (const name of METHODS) {
    ctx[name] = (...args: unknown[]): void => {
      log.push(`${name}(${args.map((arg) => String(arg)).join(',')})`)
    }
  }
  return { ctx, log }
}

/** A canvas with a fixed CSS box and a stubbed context. */
export function makeCanvas(cssWidth: number, cssHeight: number, ctx: unknown): HTMLCanvasElement {
  const canvas = document.createElement('canvas')
  Object.defineProperty(canvas, 'clientWidth', { get: () => cssWidth, configurable: true })
  Object.defineProperty(canvas, 'clientHeight', { get: () => cssHeight, configurable: true })
  ;(canvas as unknown as { getContext: () => unknown }).getContext = () => ctx
  document.body.appendChild(canvas)
  return canvas
}
