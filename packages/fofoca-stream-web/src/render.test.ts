import { describe, expect, test } from 'bun:test'

import type { ViewKey } from './render.ts'
import { Batcher, MAX_VIEW_CHARS, fit } from './render.ts'

const ana: ViewKey = { from: 'ana', directed: false, self: false }
const anaDirect: ViewKey = { from: 'ana', directed: true, self: false }
const mine: ViewKey = { from: 'ana', directed: false, self: true }

describe('Batcher', () => {
  test('a whole stream of chunks becomes one write', () => {
    const batcher = new Batcher()
    for (let i = 0; i < 500; i++) {
      batcher.push(ana, 'x'.repeat(2094))
    }

    const flushed = batcher.flush()
    expect(flushed).toHaveLength(1)
    expect(flushed[0]?.text.length).toBe(500 * 2094)
  })

  test('streams stay apart, including our own and the directed one', () => {
    const batcher = new Batcher()
    batcher.push(ana, 'broadcast')
    batcher.push(anaDirect, 'direct')
    batcher.push(mine, 'ours')

    expect(batcher.flush().map((pending) => [pending.key.from, pending.text])).toEqual([
      ['ana', 'broadcast'],
      ['ana', 'direct'],
      ['ana', 'ours'],
    ])
  })

  test('a flush consumes: the next one is empty', () => {
    const batcher = new Batcher()
    batcher.push(ana, 'a')
    expect(batcher.flush()).toHaveLength(1)
    expect(batcher.flush()).toEqual([])
    expect(batcher.size).toBe(0)
  })

  test('an eof rides with the text of its own batch', () => {
    const batcher = new Batcher()
    batcher.push(ana, 'tail')
    batcher.mark(ana, true)

    expect(batcher.flush()).toEqual([{ key: ana, text: 'tail', complete: true }])
  })

  test('a mark with no text still flushes, and only when it changed', () => {
    const batcher = new Batcher()
    batcher.mark(ana, true)
    expect(batcher.flush()).toEqual([{ key: ana, text: '', complete: true }])

    batcher.push(ana, 'more')
    expect(batcher.flush()).toEqual([{ key: ana, text: 'more' }])
  })

  test('what it holds is bounded, so a hidden tab cannot grow it', () => {
    const batcher = new Batcher(10)
    for (let i = 0; i < 100; i++) {
      batcher.push(ana, 'abcde')
    }

    const flushed = batcher.flush()
    expect(flushed).toHaveLength(1)
    expect(flushed[0]?.text.length).toBeLessThanOrEqual(10)
    expect(flushed[0]?.text).toBe('abcdeabcde')
  })

  test('a single chunk over the bound is kept whole for `fit` to trim', () => {
    const batcher = new Batcher(4)
    batcher.push(ana, 'abcdefgh')

    expect(batcher.flush()[0]?.text).toBe('abcdefgh')
  })

  test('an empty chunk queues nothing', () => {
    const batcher = new Batcher()
    batcher.push(ana, '')
    expect(batcher.size).toBe(0)
    expect(batcher.flush()).toEqual([])
  })
})

describe('fit', () => {
  test('under the cap nothing is dropped', () => {
    expect(fit(10, 'abc', 100)).toEqual({ append: 'abc', dropChars: 0 })
  })

  test('over the cap the oldest characters go', () => {
    expect(fit(98, 'abc', 100)).toEqual({ append: 'abc', dropChars: 1 })
    expect(fit(100, 'abcde', 100)).toEqual({ append: 'abcde', dropChars: 5 })
  })

  test('a batch larger than the cap keeps its own tail and clears the view', () => {
    expect(fit(500, 'abcdef', 4)).toEqual({ append: 'cdef', dropChars: 500 })
  })

  test('the default cap is above what the e2e streams', () => {
    expect(MAX_VIEW_CHARS).toBeGreaterThan(300_000)
  })
})
