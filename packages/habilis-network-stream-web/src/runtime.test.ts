import { describe, expect, test } from 'bun:test'

import { fakeSink, fakeSource, settle } from './fake-stream.ts'
import type { Chunk } from './runtime.ts'
import { MAX_WAIT_MS, StreamRuntime } from './runtime.ts'

describe('a reading StreamRuntime', () => {
  test('chunks read back in order, merged into one item', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    fake.push('a')
    fake.push('b')
    fake.push('c')
    await settle()

    const { items } = await runtime.read({ waitMs: 0 })
    expect(items).toEqual([{ eof: false, text: 'abc' }])
  })

  test('a read takes nothing away: two readers see the same stream', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    fake.push('a')
    await settle()

    const first = await runtime.read({ waitMs: 0 })
    const second = await runtime.read({ waitMs: 0 })
    expect(first).toEqual(second)
  })

  test('a cursor reads only what came after it, and stays put at the end', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    fake.push('a')
    await settle()
    const { cursor } = await runtime.read({ waitMs: 0 })

    fake.push('b')
    await settle()
    const next = await runtime.read({ waitMs: 0, cursor })
    expect(next.items).toEqual([{ eof: false, text: 'b' }])
    const empty = await runtime.read({ waitMs: 0, cursor: next.cursor })
    expect(empty).toEqual({ items: [], cursor: next.cursor })
  })

  test('the end is its own item and the stream is complete', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source, { hash: 'h' })
    fake.push('a')
    fake.end()
    await settle()

    const { items } = await runtime.read({ waitMs: 0 })
    expect(items).toEqual([
      { eof: false, text: 'a' },
      { eof: true, text: '' },
    ])
    expect(runtime.status()).toMatchObject({ role: 'reader', hash: 'h', complete: true, bytes: 1 })
  })

  test('a multibyte character split across chunks decodes whole', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    const bytes = new TextEncoder().encode('é')
    fake.push(bytes.subarray(0, 1))
    fake.push(bytes.subarray(1))
    await settle()

    const { items } = await runtime.read({ waitMs: 0 })
    expect(items).toEqual([{ eof: false, text: 'é' }])
  })

  test('read waits for the first chunk, then returns it', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    const pending = runtime.read({ waitMs: 5_000 })
    setTimeout(() => fake.push('late'), 10)

    expect((await pending).items).toEqual([{ eof: false, text: 'late' }])
  })

  test('read gives up after waitMs, and returns early when its signal aborts', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    expect((await runtime.read({ waitMs: 10 })).items).toEqual([])

    const abort = new AbortController()
    const pending = runtime.read({ waitMs: MAX_WAIT_MS }, abort.signal)
    abort.abort()
    expect((await pending).items).toEqual([])
  })

  test('a stream that stopped early reports why and does not wait', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    fake.fail('the producer abandoned the stream')
    await settle()

    const started = Date.now()
    await runtime.read({ waitMs: MAX_WAIT_MS })
    expect(Date.now() - started).toBeLessThan(1_000)
    expect(runtime.status().error).toContain('abandoned')
  })

  test('the log drops its oldest past the byte cap, and an old cursor gets what is left', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source, { maxBytes: 2 })
    fake.push('a')
    fake.push('b')
    fake.push('c')
    await settle()

    const { items, cursor } = await runtime.read({ waitMs: 0, cursor: 0 })
    expect(items).toEqual([{ eof: false, text: 'bc' }])
    expect(cursor).toBe(3)
  })

  test('base64 carries bytes that are not text, joined before encoding', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    fake.push(new Uint8Array([0xff]))
    fake.push(new Uint8Array([0x00, 0xfe]))
    await settle()

    const { items } = await runtime.read({ waitMs: 0, encoding: 'base64' })
    expect(items).toEqual([{ eof: false, base64: btoa(String.fromCharCode(0xff, 0x00, 0xfe)) }])
  })

  test('onChunk sees every chunk as it lands, the end included', async () => {
    const fake = fakeSource()
    const runtime = StreamRuntime.reading(fake.source)
    const seen: Chunk[] = []
    runtime.onChunk = (chunk) => seen.push(chunk)
    fake.push('hi')
    fake.end()
    await settle()

    expect(seen).toEqual([
      { text: 'hi', eof: false },
      { text: '', eof: true },
    ])
  })

  test('a reading tab cannot write', async () => {
    const runtime = StreamRuntime.reading(fakeSource().source)
    await expect(runtime.write('x')).rejects.toThrow('cannot write')
  })
})

describe('a producing StreamRuntime', () => {
  test('writes wait for the reader, then land in order; close ends the stream', async () => {
    const fake = fakeSink('hash-1')
    const runtime = StreamRuntime.producing(fake.sink)
    const written: string[] = []
    runtime.onWritten = (text) => written.push(text)
    expect(runtime.status()).toMatchObject({ role: 'producer', hash: 'hash-1', attached: false })

    const first = runtime.write('a')
    fake.attach()
    await first
    await runtime.write('b')
    await runtime.close()

    expect(fake.writes).toEqual(['a', 'b'])
    expect(written).toEqual(['a', 'b'])
    expect(fake.closes).toBe(1)
    expect(runtime.status()).toMatchObject({ attached: true, complete: true, bytes: 2 })
  })

  test('a close with no reader ends the stream without an error', async () => {
    const runtime = StreamRuntime.producing(fakeSink().sink)
    await runtime.close()
    await settle()
    const status = runtime.status()
    expect(status.complete).toBe(true)
    expect(status.error).toBeUndefined()
  })

  test('a producing tab cannot read', async () => {
    const runtime = StreamRuntime.producing(fakeSink().sink)
    await expect(runtime.read({ waitMs: 0 })).rejects.toThrow('consumer reads it')
  })
})
