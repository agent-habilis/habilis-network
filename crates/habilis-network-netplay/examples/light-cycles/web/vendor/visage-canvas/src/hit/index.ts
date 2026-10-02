/**
 * Which shape is under a point.
 *
 * A canvas has no elements, so it has no events — there is nothing for a click
 * to land on. This is the minimum that makes the backend usable anyway: one
 * listener on the `<canvas>`, one call to this, and the shape you get back is
 * the one a `ref` handed you, so it can be compared by identity.
 *
 *     canvas.addEventListener('click', (e) => {
 *       const box = canvas.getBoundingClientRect()
 *       const hit = hitTest(root.scene, e.clientX - box.left, e.clientY - box.top)
 *       if (hit === closeButton) …
 *     })
 *
 * Per-shape `onclick` props are deliberately absent. They imply a synthetic
 * event system — bubbling, capture, `pointerenter`/`pointerleave` state kept
 * across frames — which is a larger thing than this whole renderer.
 */

import type { SceneNode } from '../scene/index.ts'

/**
 * The topmost shape containing (x, y), in the same CSS-pixel space the scene is
 * painted in, or null.
 *
 * Reverse paint order — last sibling first — because the last one painted is
 * the one on top, and the answer has to agree with what the user can see.
 *
 * `path` shapes never match: deciding whether a point is inside an arbitrary
 * `Path2D` needs `ctx.isPointInPath`, and this function deliberately has no
 * context. Test paths yourself, or wrap them in a `rect` you can hit.
 */
export function hitTest(node: SceneNode, x: number, y: number): SceneNode | null {
  if (!node.visible || node.alpha <= 0) return null

  // Into this node's own space: undo translate, then rotate, then scale — the
  // reverse of the order `paint` applies them.
  let lx = x - node.x
  let ly = y - node.y
  if (node.rotate !== 0) {
    const cos = Math.cos(-node.rotate)
    const sin = Math.sin(-node.rotate)
    const rx = lx * cos - ly * sin
    ly = lx * sin + ly * cos
    lx = rx
  }
  if (node.scaleX !== 1) lx /= node.scaleX
  if (node.scaleY !== 1) ly /= node.scaleY

  const clip = node.clip
  if (
    clip !== null &&
    (lx < clip.x || ly < clip.y || lx > clip.x + clip.width || ly > clip.y + clip.height)
  ) {
    return null
  }

  for (let child = node.lastChild; child !== null; child = child.prev) {
    const hit = hitTest(child, lx, ly)
    if (hit !== null) return hit
  }

  return contains(node, lx, ly) ? node : null
}

/** Whether the node's own geometry, anchored at the origin, covers (lx, ly). */
function contains(node: SceneNode, lx: number, ly: number): boolean {
  switch (node.tag) {
    case 'rect':
      return lx >= 0 && ly >= 0 && lx <= node.width && ly <= node.height

    case 'circle':
      return node.radius > 0 && lx * lx + ly * ly <= node.radius * node.radius

    case 'image':
      return (
        node.image !== null &&
        lx >= 0 &&
        ly >= 0 &&
        lx <= node.width &&
        ly <= node.height
      )

    case 'line': {
      // Distance from the point to the segment, against half the stroke width.
      const dx = node.x2 - node.x
      const dy = node.y2 - node.y
      const lengthSq = dx * dx + dy * dy
      const t = lengthSq === 0 ? 0 : Math.max(0, Math.min(1, (lx * dx + ly * dy) / lengthSq))
      const cx = lx - dx * t
      const cy = ly - dy * t
      const reach = Math.max(node.lineWidth, 1) / 2
      return cx * cx + cy * cy <= reach * reach
    }

    // `text` has no measured box without a context; `group`, `path`, `#root`,
    // `#text` and `#hole` are not targets. All fall through.
    default:
      return false
  }
}
