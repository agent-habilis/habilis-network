/**
 * The retained scene graph, and the canvas half of the `Host` interface.
 *
 * This is deliberately a mini-DOM that paints. Reading it next to
 * `../dom/index.ts` should feel like reading the same file twice, because the
 * reconciler asks both of them the same fifteen questions.
 *
 * Two decisions carry the whole file.
 *
 * **Children are a doubly-linked list, not an array.** `insert(parent, node,
 * before)` over an array needs `indexOf(before)` — O(n) per insert, O(n²) to
 * mount ten thousand particles, which is exactly the size this backend exists
 * to be measured at. A linked list makes `insert`, `remove`, `nextSibling` and
 * `clear` all O(1) given the node. This is why the DOM is one, and the reason
 * transfers unchanged.
 *
 * **Props land on flat scalar fields, not in a stored props object.** Three
 * reasons, in order of weight: the painter reads these fields ten thousand
 * times a frame and wants them monomorphic; a node collected by `ref` can be
 * driven imperatively with `node.x = 12.5`, which is what the example's control
 * arm needs; and the descriptor's `props` object is shared with the fiber for
 * the identity bail in `patch`, so it is not ours to mutate. The cost is the
 * `setProp` switch below, which is the same shape as the DOM's.
 */

import { DEV } from 'visage-dom/dev'
import type { Host, HostEl, HostNode } from 'visage-dom/host'
import type { Rect, ShapeTag } from '../types/index.ts'

/**
 * `#text` carries a string for a `text` parent to draw; `#hole` is the
 * placeholder the reconciler puts where a null or false child was, and paints
 * nothing. `#root` is the node a `CanvasRoot` renders into.
 */
export type SceneTag = ShapeTag | '#text' | '#hole' | '#root'

export interface SceneNode {
  readonly tag: SceneTag

  // --- Tree ----------------------------------------------------------------
  parent: SceneNode | null
  prev: SceneNode | null
  next: SceneNode | null
  firstChild: SceneNode | null
  lastChild: SceneNode | null
  childCount: number

  // --- Transform -----------------------------------------------------------
  x: number
  y: number
  rotate: number
  scaleX: number
  scaleY: number

  // --- Geometry ------------------------------------------------------------
  width: number
  height: number
  radius: number
  x2: number
  y2: number

  // --- Paint ---------------------------------------------------------------
  fill: string | CanvasGradient | CanvasPattern | null
  stroke: string | CanvasGradient | CanvasPattern | null
  lineWidth: number
  lineCap: CanvasLineCap
  lineJoin: CanvasLineJoin
  alpha: number
  visible: boolean

  // --- Text ----------------------------------------------------------------
  font: string | null
  align: CanvasTextAlign
  baseline: CanvasTextBaseline
  /** Zero means unset — `fillText` takes no maxWidth. */
  maxWidth: number
  text: string | null

  // --- Path, image, clip ---------------------------------------------------
  /** Kept as authored; the painter memoises the string form into a `Path2D`. */
  path: string | Path2D | null
  fillRule: CanvasFillRule
  image: CanvasImageSource | null
  clip: Rect | null

  /** `#text` only. */
  data: string
}

export function createSceneNode(tag: SceneTag): SceneNode {
  // One object literal with every field present, so every node has the same
  // hidden class and the painter's field reads stay monomorphic. Filling in
  // fields later would give a `circle` and a `text` different shapes.
  return {
    tag,
    parent: null,
    prev: null,
    next: null,
    firstChild: null,
    lastChild: null,
    childCount: 0,
    x: 0,
    y: 0,
    rotate: 0,
    scaleX: 1,
    scaleY: 1,
    width: 0,
    height: 0,
    radius: 0,
    x2: 0,
    y2: 0,
    fill: null,
    stroke: null,
    lineWidth: 1,
    lineCap: 'butt',
    lineJoin: 'miter',
    alpha: 1,
    visible: true,
    font: null,
    align: 'start',
    baseline: 'alphabetic',
    maxWidth: 0,
    text: null,
    path: null,
    fillRule: 'nonzero',
    image: null,
    clip: null,
    data: '',
  }
}

// ---------------------------------------------------------------------------
// Tree operations
// ---------------------------------------------------------------------------

/** Unlink from the current parent, leaving the node itself intact. */
export function detach(node: SceneNode): void {
  const parent = node.parent
  if (parent === null) return

  if (node.prev === null) parent.firstChild = node.next
  else node.prev.next = node.next

  if (node.next === null) parent.lastChild = node.prev
  else node.next.prev = node.prev

  parent.childCount -= 1
  node.parent = null
  node.prev = null
  node.next = null
}

/**
 * Insert before `before`, or append when it is null.
 *
 * Detaching first is what makes this double as a move: the reconciler's
 * `moveFiber` calls exactly this, and a node already in the tree has to leave
 * its old position before taking a new one.
 */
export function insertBefore(
  parent: SceneNode,
  node: SceneNode,
  before: SceneNode | null,
): void {
  // `insertBefore(p, n, n)` is a no-op in the DOM. Here `detach` would clear
  // the pointers and the branch below would then set `node.next = node` and
  // `node.prev = node`, so any later walk of the list never terminates. No
  // caller reaches this today; it is cheap insurance against one that does.
  if (before === node) return

  detach(node)
  node.parent = parent

  if (before === null) {
    node.prev = parent.lastChild
    node.next = null
    if (parent.lastChild === null) parent.firstChild = node
    else parent.lastChild.next = node
    parent.lastChild = node
  } else {
    node.prev = before.prev
    node.next = before
    if (before.prev === null) parent.firstChild = node
    else before.prev.next = node
    before.prev = node
  }

  parent.childCount += 1
}

/**
 * Drop every child at once.
 *
 * The DOM's analogue is `textContent = ''`, which still has to tear down N
 * nodes internally. Here it is four pointer writes, and the orphaned children
 * are collected because nothing references them — the one place this host is
 * unambiguously cheaper than the one it is modelled on.
 */
export function clearChildren(parent: SceneNode): void {
  for (let child = parent.firstChild; child !== null; ) {
    const next = child.next
    child.parent = null
    child.prev = null
    child.next = null
    child = next
  }
  parent.firstChild = null
  parent.lastChild = null
  parent.childCount = 0
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

/** Handled by the reconciler, never by the node. Mirrors the DOM host's set. */
const SKIP = new Set(['key', 'ref', 'children'])

/**
 * Apply one prop, or restore its default when `value` is undefined.
 *
 * The undefined branch is not decoration: `applyProps` calls it for every key
 * that was in the previous props and is not in the new ones, and a scene node
 * outlives its descriptors. Without the defaults a shape that stops declaring
 * `fill` would keep painting the old one forever.
 */
function setProp(node: SceneNode, key: string, value: unknown, prev: unknown): void {
  if (SKIP.has(key)) return
  if (Object.is(value, prev)) return

  switch (key) {
    // Transform
    case 'x': node.x = num(value, 0); return
    case 'y': node.y = num(value, 0); return
    case 'rotate': node.rotate = num(value, 0); return
    case 'scaleX': node.scaleX = num(value, 1); return
    case 'scaleY': node.scaleY = num(value, 1); return

    // Geometry
    case 'width': node.width = num(value, 0); return
    case 'height': node.height = num(value, 0); return
    case 'radius': node.radius = num(value, 0); return
    case 'x2': node.x2 = num(value, 0); return
    case 'y2': node.y2 = num(value, 0); return

    // Paint
    case 'fill': node.fill = (value ?? null) as SceneNode['fill']; return
    case 'stroke': node.stroke = (value ?? null) as SceneNode['stroke']; return
    case 'lineWidth': node.lineWidth = num(value, 1); return
    case 'lineCap': node.lineCap = (value ?? 'butt') as CanvasLineCap; return
    case 'lineJoin': node.lineJoin = (value ?? 'miter') as CanvasLineJoin; return
    case 'alpha': node.alpha = num(value, 1); return
    case 'visible': node.visible = value === undefined ? true : value !== false; return

    // Text
    case 'text': node.text = value === undefined ? null : String(value); return
    case 'font': node.font = value === undefined ? null : String(value); return
    case 'align': node.align = (value ?? 'start') as CanvasTextAlign; return
    case 'baseline': node.baseline = (value ?? 'alphabetic') as CanvasTextBaseline; return
    case 'maxWidth': node.maxWidth = num(value, 0); return

    // Path, image, clip
    case 'd': node.path = (value ?? null) as SceneNode['path']; return
    case 'fillRule': node.fillRule = (value ?? 'nonzero') as CanvasFillRule; return
    case 'src': node.image = (value ?? null) as CanvasImageSource | null; return
    case 'clip': node.clip = (value ?? null) as Rect | null; return
  }

  // Unknown prop. The DOM host has `setAttribute` to fall back on; there is no
  // such thing here, and silently dropping it is how a typo becomes an
  // afternoon. The shape table in `types.ts` makes this unreachable from typed
  // code, so anything arriving here came through a cast or from JavaScript.
  throw new Error(
    `view: <${node.tag}> has no canvas prop "${key}". The shape vocabulary is ` +
      'the ShapeAttrsMap in src/canvas/types.ts.',
  )
}

function num(value: unknown, fallback: number): number {
  if (value === undefined || value === null) return fallback
  const n = Number(value)
  // An unknown prop throws a page above; a non-numeric *value* used to sail
  // through as NaN and paint an invisible shape with no diagnostic at all.
  if (DEV && Number.isNaN(n)) {
    throw new Error(
      `view: expected a number but got ${JSON.stringify(value)}. Canvas ` +
        'geometry is numeric — a string like "10px" has no meaning here.',
    )
  }
  return n
}

function applyProps(
  node: SceneNode,
  next: Readonly<Record<string, unknown>>,
  prev?: Readonly<Record<string, unknown>>,
): void {
  if (prev === undefined) {
    for (const key in next) setProp(node, key, next[key], undefined)
    return
  }
  if (prev === next) return
  for (const key in prev) {
    if (!(key in next)) setProp(node, key, undefined, prev[key])
  }
  for (const key in next) setProp(node, key, next[key], prev[key])
}

// ---------------------------------------------------------------------------
// The host
// ---------------------------------------------------------------------------

/**
 * A `Host` bound to one canvas root.
 *
 * Per-root rather than a module singleton, and that is what makes `commit()`
 * work: the reconciler calls it once per settled reconcile, and it has to know
 * *which* canvas to repaint. One small object per `renderCanvas` call is a
 * price worth paying to avoid walking a node's parent chain on every mutation.
 */
export function createCanvasHost(onCommit: () => void): Host {
  return {
    createNode(tag: string): HostEl {
      return createSceneNode(tag as SceneTag)
    },
    createText(value: string): HostNode {
      const node = createSceneNode('#text')
      node.data = value
      return node
    },
    createHole(): HostNode {
      return createSceneNode('#hole')
    },

    setText(node: HostNode, value: string): void {
      ;(node as SceneNode).data = value
    },
    applyProps(node: HostEl, next, prev): void {
      applyProps(node as SceneNode, next, prev)
    },
    runRef(props, node: HostEl): (() => void) | void {
      const ref = props['ref']
      if (typeof ref !== 'function') return
      const detach = (ref as (n: SceneNode) => unknown)(node as SceneNode)
      if (typeof detach === 'function') return detach as () => void
    },

    insert(parent: HostEl, node: HostNode, before: HostNode | null): void {
      insertBefore(parent as SceneNode, node as SceneNode, before as SceneNode | null)
    },
    remove(node: HostNode): void {
      detach(node as SceneNode)
    },
    append(parent: HostEl, node: HostNode): void {
      insertBefore(parent as SceneNode, node as SceneNode, null)
    },

    nextSibling(node: HostNode): HostNode | null {
      return (node as SceneNode).next
    },
    childCount(parent: HostEl): number {
      return (parent as SceneNode).childCount
    },
    clear(parent: HostEl): void {
      clearChildren(parent as SceneNode)
    },

    /**
     * No staging container.
     *
     * The DOM stages a run of siblings in a `DocumentFragment` because every
     * live insertion is a layout invalidation. Here an insertion is four
     * pointer writes, so a fragment would add an allocation and a splice to
     * save nothing. `mountRange` takes its direct path instead.
     */
    createFragment(): null {
      return null
    },

    /**
     * Portals escape an `overflow` or `z-index` context. A scene graph has
     * neither — paint order is tree order — so there is nothing to escape and
     * the reconciler throws rather than half-working.
     */
    supportsPortals: false,

    commit: onCommit,
  }
}
