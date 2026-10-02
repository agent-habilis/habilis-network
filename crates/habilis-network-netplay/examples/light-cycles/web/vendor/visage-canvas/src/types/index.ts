/**
 * The shape vocabulary, and the honest cost of a non-DOM backend.
 *
 * `Attrs<K>` in `../types/index.ts` is *derived*: it reads `HTMLElementTagNameMap`,
 * filters for writable non-method properties, and produces per-element attribute
 * types for every HTML tag without a single one being listed by hand. That is
 * the library's best trick and it does not transfer, because there is no
 * `CanvasElementTagNameMap` to read. A canvas has one API — `fillRect`,
 * `arc`, `fillText` — and no type describing "a circle".
 *
 * So this table is written by hand, and it is the irreducible price of the
 * second backend: seven tags, about forty-five props. Everything downstream
 * follows from it mechanically — the Proxy, the scene fields, the painter's
 * switch — but the table itself is prose.
 */

import type { BRAND, Child, ElementNode, Key } from 'visage-dom/types'
import type { SceneNode } from '../scene/index.ts'

/**
 * Placement in the parent's coordinate space.
 *
 * A node with only `x`/`y` set never touches the context's transform — the
 * translation is folded into the draw call instead, which at ten thousand
 * shapes is ten thousand `setTransform` calls not made. Rotation or scale
 * forces the matrix path.
 */
export interface Transform {
  x?: number
  y?: number
  /** Radians, clockwise, about the node's own origin. */
  rotate?: number
  scaleX?: number
  scaleY?: number
}

export interface Paintable extends Transform {
  fill?: string | CanvasGradient | CanvasPattern | null
  stroke?: string | CanvasGradient | CanvasPattern | null
  lineWidth?: number
  lineCap?: CanvasLineCap
  lineJoin?: CanvasLineJoin
  /** Multiplied into the inherited alpha, the way the DOM composites opacity. */
  alpha?: number
  /**
   * False paints nothing and skips the whole subtree, without unmounting it.
   * Cheaper than removing the children and rebuilding them, and it keeps their
   * component state — which is the canvas equivalent of `display: none`.
   */
  visible?: boolean
}

export interface Rect {
  x: number
  y: number
  width: number
  height: number
}

/**
 * Every tag, and what it takes.
 *
 * Deliberately small. Gradients and patterns are accepted as the raw
 * `CanvasGradient`/`CanvasPattern` objects rather than described declaratively:
 * they are created from the context, they are cacheable, and a descriptor
 * language for them is a second design that can wait until something needs it.
 */
export interface ShapeAttrsMap {
  /** A transform and an alpha, applied to everything inside. Paints nothing. */
  group: Transform & {
    alpha?: number
    visible?: boolean
    /** Clips the subtree to this rect, in the group's own space. */
    clip?: Rect
  }
  rect: Paintable & {
    width?: number
    height?: number
    /** Corner radius. Zero — the default — takes the straight `fillRect` path. */
    radius?: number
  }
  circle: Paintable & { radius?: number }
  /** From (x, y) to (x2, y2). Stroked only; `fill` is meaningless on a segment. */
  line: Paintable & { x2?: number; y2?: number }
  path: Paintable & {
    /** An SVG path string, or a `Path2D` built once and reused. */
    d?: string | Path2D
    fillRule?: CanvasFillRule
    /**
     * The path's extent from its own origin. Ignored by the 2D painter, which
     * asks the context to fill the path and needs no bounds to do it.
     *
     * `visage-webgpu` requires it. A GPU cannot fill an arbitrary path, so that
     * backend rasterises the path into a texture tile — and a `Path2D` has no
     * queryable bounds, so nothing but the author can say how large the tile
     * should be. A path without these draws on the 2D backend and is skipped on
     * the GPU one, which is a divergence worth knowing about and is recorded in
     * `docs/proposals/007-a-webgpu-render-target.md`.
     *
     * Declared here rather than in the GPU package's own table because the shape
     * vocabulary is shared: `visage-webgpu` re-exports these very types, and a
     * second table that was *nearly* this one is how two backends drift apart.
     */
    width?: number
    height?: number
  }
  text: Paintable & {
    /** Set this, or pass the string as a child: `text('hi')`. */
    text?: string
    font?: string
    align?: CanvasTextAlign
    baseline?: CanvasTextBaseline
    maxWidth?: number
  }
  image: Transform & {
    src?: CanvasImageSource | null
    width?: number
    height?: number
    alpha?: number
    visible?: boolean
  }
}

export type ShapeTag = keyof ShapeAttrsMap

/**
 * `[BRAND]?: never` is the load-bearing member: it is what lets the two
 * `ShapeTagFn` overloads tell a leading attributes object from a first child,
 * since an `ElementNode` carries the brand and an attrs object cannot. Same
 * mechanism `CommonAttrs` uses for DOM tags, established in
 * `spikes/02-tag-overloads.ts`.
 */
interface CommonShapeAttrs {
  readonly [BRAND]?: never
  key?: Key
  /** Runs on mount. Return a function to undo it on unmount. */
  ref?: (node: SceneNode) => void
}

export type ShapeAttrs<K extends ShapeTag> = ShapeAttrsMap[K] & CommonShapeAttrs

export interface ShapeTagFn<K extends ShapeTag> {
  (...children: Child[]): ElementNode<K>
  (attrs: ShapeAttrs<K>, ...children: Child[]): ElementNode<K>
}

export type Shapes = { [K in ShapeTag]: ShapeTagFn<K> }
