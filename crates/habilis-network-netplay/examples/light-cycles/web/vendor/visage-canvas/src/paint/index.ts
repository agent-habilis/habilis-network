/**
 * Scene graph in, `CanvasRenderingContext2D` calls out.
 *
 * Three rules, all of them consequences of the medium rather than choices:
 *
 * **Paint order is tree order.** Depth first, children in list order, later
 * siblings on top. There is no `z-index` because there is nothing to escape —
 * to raise a shape, move it later in the tree.
 *
 * **The repaint is total.** No damage tracking. Dirty-rect painting needs a
 * bounding box per shape and a rect-merging pass, and a bounding box that is
 * wrong by a pixel leaves visible litter on the screen. The whole scene is
 * cheaper to be right about, and it is why this backend wants a frame clock
 * (see C5 in docs/proposals.md) rather than the microtask flush.
 *
 * **`save()`/`restore()` are avoided.** At ten thousand shapes a save/restore
 * pair per node is twenty thousand context-state pushes for transforms that are
 * almost always a translation. So a translation-only node folds its offset into
 * the draw call and passes the running offset down, and only rotation, scale or
 * a clip escalates to the real thing. Style setters are likewise compared
 * against what was last set, because ten thousand circles usually share one
 * fill.
 */

import type { SceneNode } from '../scene/index.ts'

/**
 * What `paint` needs from a rendering context.
 *
 * Declared structurally rather than as `CanvasRenderingContext2D` so the tests
 * can pass a recorder — happy-dom's `getContext('2d')` returns null, so a fake
 * that logs its calls is the only way to assert a draw-call sequence headlessly,
 * and it is the right way regardless: the sequence *is* the output.
 */
export interface PaintContext {
  fillStyle: string | CanvasGradient | CanvasPattern
  strokeStyle: string | CanvasGradient | CanvasPattern
  lineWidth: number
  lineCap: CanvasLineCap
  lineJoin: CanvasLineJoin
  globalAlpha: number
  font: string
  textAlign: CanvasTextAlign
  textBaseline: CanvasTextBaseline

  save(): void
  restore(): void
  setTransform(a: number, b: number, c: number, d: number, e: number, f: number): void
  translate(x: number, y: number): void
  rotate(angle: number): void
  scale(x: number, y: number): void

  clearRect(x: number, y: number, w: number, h: number): void
  beginPath(): void
  closePath(): void
  moveTo(x: number, y: number): void
  lineTo(x: number, y: number): void
  rect(x: number, y: number, w: number, h: number): void
  arc(x: number, y: number, r: number, start: number, end: number): void
  clip(): void
  fill(path?: Path2D, rule?: CanvasFillRule): void
  stroke(path?: Path2D): void
  fillRect(x: number, y: number, w: number, h: number): void
  strokeRect(x: number, y: number, w: number, h: number): void
  fillText(text: string, x: number, y: number, maxWidth?: number): void
  drawImage(image: CanvasImageSource, x: number, y: number, w: number, h: number): void
  roundRect?(x: number, y: number, w: number, h: number, radii: number): void
}

export interface PaintOptions {
  /** Backing-store scale. Every coordinate below is in CSS pixels. */
  dpr: number
  width: number
  height: number
  /** Painted under the scene. Undefined leaves the previous frame in place. */
  background?: string | undefined
}

const TAU = Math.PI * 2

/**
 * `new Path2D(d)` per frame for an unchanging `d` is an allocation per shape per
 * frame. The string is the identity, and path strings are few and repeated.
 */
const pathCache = new Map<string, Path2D>()

function toPath2D(d: string): Path2D {
  const hit = pathCache.get(d)
  if (hit !== undefined) return hit
  if (typeof Path2D !== 'function') {
    throw new Error('view: <path> needs Path2D, which this environment does not have.')
  }
  const built = new Path2D(d)
  pathCache.set(d, built)
  return built
}

/**
 * The text a `text` node draws: its own `text` prop, or its string children
 * concatenated — so `text({ font }, 'hi ', name)` reads the way it looks.
 */
function textOf(node: SceneNode): string {
  if (node.text !== null) return node.text
  let out = ''
  for (let child = node.firstChild; child !== null; child = child.next) {
    if (child.tag === '#text') out += child.data
  }
  return out
}

/** Style setters, deduplicated against what the context was last given. */
class Painter {
  readonly ctx: PaintContext
  #fill: unknown = null
  #stroke: unknown = null
  #lineWidth = -1
  #lineCap: CanvasLineCap | null = null
  #lineJoin: CanvasLineJoin | null = null
  #alpha = -1
  #font: string | null = null
  #align: CanvasTextAlign | null = null
  #baseline: CanvasTextBaseline | null = null

  constructor(ctx: PaintContext) {
    this.ctx = ctx
  }

  /**
   * After a `restore()` the context's style state is whatever it was at the
   * matching `save()`, which is not what this cache believes. Rather than
   * mirror the stack, forget everything — clips are rare and the next few
   * setters are cheap.
   */
  invalidate(): void {
    this.#fill = null
    this.#stroke = null
    this.#lineWidth = -1
    this.#lineCap = null
    this.#lineJoin = null
    this.#alpha = -1
    this.#font = null
    this.#align = null
    this.#baseline = null
  }

  alpha(value: number): void {
    if (this.#alpha === value) return
    this.#alpha = value
    this.ctx.globalAlpha = value
  }

  fill(value: NonNullable<SceneNode['fill']>): void {
    if (this.#fill === value) return
    this.#fill = value
    this.ctx.fillStyle = value
  }

  stroke(node: SceneNode): void {
    const value = node.stroke as NonNullable<SceneNode['stroke']>
    if (this.#stroke !== value) {
      this.#stroke = value
      this.ctx.strokeStyle = value
    }
    if (this.#lineWidth !== node.lineWidth) {
      this.#lineWidth = node.lineWidth
      this.ctx.lineWidth = node.lineWidth
    }
    if (this.#lineCap !== node.lineCap) {
      this.#lineCap = node.lineCap
      this.ctx.lineCap = node.lineCap
    }
    if (this.#lineJoin !== node.lineJoin) {
      this.#lineJoin = node.lineJoin
      this.ctx.lineJoin = node.lineJoin
    }
  }

  text(node: SceneNode): void {
    if (node.font !== null && this.#font !== node.font) {
      this.#font = node.font
      this.ctx.font = node.font
    }
    if (this.#align !== node.align) {
      this.#align = node.align
      this.ctx.textAlign = node.align
    }
    if (this.#baseline !== node.baseline) {
      this.#baseline = node.baseline
      this.ctx.textBaseline = node.baseline
    }
  }
}

/** Repaint the whole scene. */
export function paint(ctx: PaintContext, root: SceneNode, options: PaintOptions): void {
  const { dpr, width, height, background } = options

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  if (background === undefined) {
    ctx.clearRect(0, 0, width, height)
  } else {
    ctx.clearRect(0, 0, width, height)
    ctx.globalAlpha = 1
    ctx.fillStyle = background
    ctx.fillRect(0, 0, width, height)
  }

  const painter = new Painter(ctx)
  painter.invalidate()
  walk(painter, root, 0, 0, 1, dpr)
}

/**
 * `ox`/`oy` is the translation accumulated from ancestors that has *not* been
 * pushed into the context — it is added to coordinates at the draw call
 * instead. `scale` is the base transform to restore to after a `save()`.
 */
function walk(
  painter: Painter,
  node: SceneNode,
  ox: number,
  oy: number,
  alpha: number,
  scale: number,
): void {
  if (!node.visible) return

  const own = alpha * node.alpha
  if (own <= 0) return

  const transformed =
    node.rotate !== 0 || node.scaleX !== 1 || node.scaleY !== 1 || node.clip !== null

  if (!transformed) {
    const px = ox + node.x
    const py = oy + node.y
    draw(painter, node, px, py, own)
    for (let child = node.firstChild; child !== null; child = child.next) {
      walk(painter, child, px, py, own, scale)
    }
    return
  }

  const ctx = painter.ctx
  ctx.save()
  ctx.translate(ox + node.x, oy + node.y)
  if (node.rotate !== 0) ctx.rotate(node.rotate)
  if (node.scaleX !== 1 || node.scaleY !== 1) ctx.scale(node.scaleX, node.scaleY)
  if (node.clip !== null) {
    const { x, y, width, height } = node.clip
    ctx.beginPath()
    ctx.rect(x, y, width, height)
    ctx.clip()
  }

  // Everything inside is now relative to the node's own origin.
  draw(painter, node, 0, 0, own)
  for (let child = node.firstChild; child !== null; child = child.next) {
    walk(painter, child, 0, 0, own, scale)
  }

  ctx.restore()
  painter.invalidate()
}

function draw(
  painter: Painter,
  node: SceneNode,
  px: number,
  py: number,
  alpha: number,
): void {
  const ctx = painter.ctx

  // A shape with neither a fill nor a stroke is invisible, and building its
  // path to then draw nothing is pure waste — which at ten thousand shapes is
  // ten thousand wasted `beginPath`/`arc` pairs.
  if (node.fill === null && node.stroke === null && node.tag !== 'image') return

  switch (node.tag) {
    case 'rect': {
      if (node.width === 0 || node.height === 0) return
      painter.alpha(alpha)
      if (node.radius > 0 && typeof ctx.roundRect === 'function') {
        ctx.beginPath()
        ctx.roundRect(px, py, node.width, node.height, node.radius)
        if (node.fill !== null) {
          painter.fill(node.fill)
          ctx.fill()
        }
        if (node.stroke !== null) {
          painter.stroke(node)
          ctx.stroke()
        }
        return
      }
      if (node.fill !== null) {
        painter.fill(node.fill)
        ctx.fillRect(px, py, node.width, node.height)
      }
      if (node.stroke !== null) {
        painter.stroke(node)
        ctx.strokeRect(px, py, node.width, node.height)
      }
      return
    }

    case 'circle': {
      if (node.radius <= 0) return
      painter.alpha(alpha)
      ctx.beginPath()
      ctx.arc(px, py, node.radius, 0, TAU)
      if (node.fill !== null) {
        painter.fill(node.fill)
        ctx.fill()
      }
      if (node.stroke !== null) {
        painter.stroke(node)
        ctx.stroke()
      }
      return
    }

    case 'line': {
      if (node.stroke === null) return
      painter.alpha(alpha)
      painter.stroke(node)
      ctx.beginPath()
      ctx.moveTo(px, py)
      // x2/y2 are the far end in the same space as x/y, not an offset from it.
      ctx.lineTo(px - node.x + node.x2, py - node.y + node.y2)
      ctx.stroke()
      return
    }

    case 'path': {
      if (node.path === null) return
      const path = typeof node.path === 'string' ? toPath2D(node.path) : node.path
      painter.alpha(alpha)
      // A Path2D's coordinates are its own, so the offset cannot be folded into
      // the call the way it is everywhere else. Paths are rare; pay for it here.
      const shifted = px !== 0 || py !== 0
      if (shifted) {
        ctx.save()
        ctx.translate(px, py)
      }
      if (node.fill !== null) {
        painter.fill(node.fill)
        ctx.fill(path, node.fillRule)
      }
      if (node.stroke !== null) {
        painter.stroke(node)
        ctx.stroke(path)
      }
      if (shifted) {
        ctx.restore()
        painter.invalidate()
      }
      return
    }

    case 'text': {
      const value = textOf(node)
      if (value === '' || node.fill === null) return
      painter.alpha(alpha)
      painter.text(node)
      painter.fill(node.fill)
      if (node.maxWidth > 0) ctx.fillText(value, px, py, node.maxWidth)
      else ctx.fillText(value, px, py)
      return
    }

    case 'image': {
      if (node.image === null || node.width === 0 || node.height === 0) return
      painter.alpha(alpha)
      ctx.drawImage(node.image, px, py, node.width, node.height)
      return
    }

    // group, #root, #text and #hole paint nothing of their own.
    default:
      return
  }
}
