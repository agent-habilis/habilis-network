import { describe, expect, test } from 'bun:test'

import { Fanout, MeshOverflowError } from './fanout.ts'

/** Take `count` values, so a test never hangs on an iterator that stalls. */
async function take<T>(iterator: AsyncIterableIterator<T>, count: number): Promise<T[]> {
  const taken: T[] = []
  for await (const value of iterator) {
    taken.push(value)
    if (taken.length === count) {
      break
    }
  }
  return taken
}

describe('Fanout', () => {
  test('every iterator sees every value, not a share of them', async () => {
    const fanout = new Fanout<number>()
    const first = fanout.iterate()
    const second = fanout.iterate()
    fanout.push(1)
    fanout.push(2)

    expect(await take(first, 2)).toEqual([1, 2])
    expect(await take(second, 2)).toEqual([1, 2])
  })

  test('an iterator sees nothing pushed before it existed', async () => {
    const fanout = new Fanout<number>()
    fanout.push(1)
    const late = fanout.iterate()
    fanout.push(2)

    expect(await take(late, 1)).toEqual([2])
  })

  test('a parked iterator wakes on the next push', async () => {
    const fanout = new Fanout<number>()
    const iterator = fanout.iterate()
    const parked = iterator.next()
    fanout.push(7)

    expect(await parked).toEqual({ value: 7, done: false })
  })

  test('a slow iterator overflows and a fast one carries on', async () => {
    const fanout = new Fanout<number>(4)
    const slow = fanout.iterate()
    const fast = fanout.iterate()

    // Drain `fast` as we go; leave `slow` parked on its buffer.
    for (let value = 0; value < 5; value += 1) {
      fanout.push(value)
      await fast.next()
    }

    await expect(slow.next()).rejects.toThrow(MeshOverflowError)
    fanout.push(99)
    expect(await fast.next()).toEqual({ value: 99, done: false })
  })

  test('an overflowed iterator stops costing anything', async () => {
    const fanout = new Fanout<number>(2)
    const slow = fanout.iterate()
    expect(fanout.size).toBe(1)
    for (let value = 0; value < 3; value += 1) {
      fanout.push(value)
    }
    expect(fanout.size).toBe(0)
    await expect(slow.next()).rejects.toThrow(MeshOverflowError)
  })

  test('breaking out of a for-await unsubscribes', async () => {
    const fanout = new Fanout<number>()
    const iterator = fanout.iterate()
    fanout.push(1)
    expect(fanout.size).toBe(1)

    await take(iterator, 1)

    expect(fanout.size).toBe(0)
  })

  test('end drains what is buffered, then completes', async () => {
    const fanout = new Fanout<number>()
    const iterator = fanout.iterate()
    fanout.push(1)
    fanout.push(2)
    fanout.end()

    const seen: number[] = []
    for await (const value of iterator) {
      seen.push(value)
    }
    expect(seen).toEqual([1, 2])
  })

  test('end wakes a parked iterator rather than leaving it hanging', async () => {
    const fanout = new Fanout<number>()
    const parked = fanout.iterate().next()
    fanout.end()

    expect(await parked).toEqual({ value: undefined, done: true })
  })

  test('an iterator created after end completes immediately', async () => {
    const fanout = new Fanout<number>()
    fanout.end()

    expect(await fanout.iterate().next()).toEqual({ value: undefined, done: true })
  })

  test('abort completes the iteration rather than throwing it', async () => {
    const fanout = new Fanout<number>()
    const stop = new AbortController()
    const iterator = fanout.iterate(stop.signal)
    fanout.push(1)

    const seen: number[] = []
    const draining = (async () => {
      for await (const value of iterator) {
        seen.push(value)
      }
    })()
    stop.abort()
    await draining

    expect(seen).toEqual([1])
    expect(fanout.size).toBe(0)
  })

  test('an already-aborted signal yields an iterator that is simply done', async () => {
    const fanout = new Fanout<number>()
    const signal = AbortSignal.abort()

    expect(await fanout.iterate(signal).next()).toEqual({ value: undefined, done: true })
    fanout.push(1)
    expect(fanout.size).toBe(0)
  })
})
