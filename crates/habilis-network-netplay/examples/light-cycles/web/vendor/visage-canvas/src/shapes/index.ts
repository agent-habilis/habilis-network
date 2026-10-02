/**
 * `shapes` is to the canvas what `tags` is to the DOM, and deliberately the
 * same three lines of machinery: a Proxy over a mapped type, one cached factory
 * per name, `fromArgs` deciding whether the first argument is attributes or a
 * child.
 *
 *     const { group, circle, text } = shapes
 *     group({ x: 40, y: 40 }, circle({ radius: 6, fill: '#0f0' }), text('hi'))
 *
 * The difference from `tags` is upstream, in `types.ts`: the DOM's factories are
 * typed by reading `HTMLElementTagNameMap`, and these are typed by a table
 * someone wrote.
 */

import { fromArgs } from 'visage-dom/element'
import type { ElementNode } from 'visage-dom/types'
import type { Shapes } from '../types/index.ts'

const cache = new Map<string, (...args: unknown[]) => ElementNode<string>>()

function makeShape(name: string) {
  const existing = cache.get(name)
  if (existing) return existing
  const fn = (...args: unknown[]): ElementNode<string> => fromArgs(name, args)
  cache.set(name, fn)
  return fn
}

export const shapes: Shapes = new Proxy(Object.create(null) as Shapes, {
  get(_target, prop: string | symbol) {
    if (typeof prop !== 'string') return undefined
    return makeShape(prop)
  },
  has() {
    return true
  },
})
