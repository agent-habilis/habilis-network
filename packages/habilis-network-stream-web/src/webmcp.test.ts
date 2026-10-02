import { describe, expect, test } from 'bun:test'

import { fakeSink, fakeSource, settle } from './fake-stream.ts'
import { StreamRuntime } from './runtime.ts'
import type { ModelContextLike, ToolDescriptor } from './webmcp.ts'
import { findModelContext, registerStreamTools, streamTools } from './webmcp.ts'

function tool(tools: ToolDescriptor[], name: string): ToolDescriptor {
  const found = tools.find((candidate) => candidate.name === name)
  if (!found) {
    throw new Error(`no tool ${name}`)
  }
  return found
}

async function call(tools: ToolDescriptor[], name: string, input?: unknown): Promise<unknown> {
  const result = await tool(tools, name).execute(input)
  const text = result.content[0]?.text
  if (result.content.length !== 1 || result.content[0]?.type !== 'text' || text === undefined) {
    throw new Error('a tool result is one text block')
  }
  return JSON.parse(text)
}

describe('streamTools', () => {
  test('registers the four tools, each with an object schema', () => {
    const tools = streamTools(StreamRuntime.reading(fakeSource().source))
    expect(tools.map((candidate) => candidate.name)).toEqual([
      'stream_write',
      'stream_close',
      'stream_read',
      'stream_status',
    ])
    for (const candidate of tools) {
      expect(candidate.inputSchema['type']).toBe('object')
      expect(candidate.description.length).toBeGreaterThan(20)
    }
  })

  test('stream_write and stream_close drive a producing tab', async () => {
    const fake = fakeSink()
    fake.attach()
    const tools = streamTools(StreamRuntime.producing(fake.sink))
    expect(await call(tools, 'stream_write', { text: 'hi' })).toEqual({ written: true })
    expect(await call(tools, 'stream_close')).toEqual({ closed: true })
    expect(fake.writes).toEqual(['hi'])
    expect(fake.closes).toBe(1)
  })

  test('stream_write refuses a missing or non-string text', async () => {
    const tools = streamTools(StreamRuntime.producing(fakeSink().sink))
    await expect(call(tools, 'stream_write', {})).rejects.toThrow('text must be a string')
    await expect(call(tools, 'stream_write', { text: 3 })).rejects.toThrow('text must be a string')
  })

  test('stream_read returns what arrived, in order, with a cursor to continue', async () => {
    const fake = fakeSource()
    const tools = streamTools(StreamRuntime.reading(fake.source))
    fake.push('ab')
    await settle()
    const first = (await call(tools, 'stream_read', { waitMs: 0 })) as { items: unknown[]; cursor: number }
    expect(first.items).toEqual([{ eof: false, text: 'ab' }])

    fake.push(new Uint8Array([0xff]))
    fake.end()
    await settle()
    const next = await call(tools, 'stream_read', { waitMs: 0, cursor: first.cursor, encoding: 'base64' })
    expect(next).toEqual({
      items: [
        { eof: false, base64: btoa(String.fromCharCode(0xff)) },
        { eof: true, base64: '' },
      ],
      cursor: first.cursor + 2,
    })
  })

  test('stream_read refuses bad input', async () => {
    const tools = streamTools(StreamRuntime.reading(fakeSource().source))
    await expect(call(tools, 'stream_read', { waitMs: 1.5 })).rejects.toThrow('waitMs must be an integer')
    await expect(call(tools, 'stream_read', { encoding: 'hex' })).rejects.toThrow('encoding must be')
  })

  test('stream_status reports the end this tab holds', async () => {
    const tools = streamTools(StreamRuntime.producing(fakeSink('h').sink))
    expect(await call(tools, 'stream_status')).toMatchObject({ role: 'producer', hash: 'h', attached: false })
  })

  // The hash is a bearer secret: whoever presents it first becomes the one
  // reader. A producer's agent needs it to hand the stream on; a reader's
  // has no use for it, so the tool does not hand it out.
  test('stream_status keeps the hash out of a reading tab', async () => {
    const tools = streamTools(StreamRuntime.reading(fakeSource().source, { hash: 'secret' }))
    const status = (await call(tools, 'stream_status')) as Record<string, unknown>
    expect(status['role']).toBe('reader')
    expect(status).not.toHaveProperty('hash')
  })

  test('stream_status says the hash is a secret', () => {
    const tools = streamTools(StreamRuntime.producing(fakeSink('h').sink))
    expect(tool(tools, 'stream_status').description).toContain('secret')
  })
})

describe('registerStreamTools', () => {
  test('registers every tool on the context it is given', () => {
    const registered: string[] = []
    const context: ModelContextLike = { registerTool: (candidate) => registered.push(candidate.name) }
    expect(registerStreamTools(StreamRuntime.reading(fakeSource().source), context)).toBe(true)
    expect(registered).toHaveLength(4)
  })

  test('is a no-op without a context', () => {
    expect(registerStreamTools(StreamRuntime.reading(fakeSource().source), undefined)).toBe(false)
  })
})

describe('findModelContext', () => {
  const context = { registerTool: () => undefined }

  test('prefers document.modelContext over navigator.modelContext', () => {
    const scope = {
      document: { modelContext: context },
      navigator: { modelContext: { registerTool: () => 'old' } },
    }
    expect(findModelContext(scope)).toBe(context)
  })

  test('falls back to navigator.modelContext', () => {
    expect(findModelContext({ document: {}, navigator: { modelContext: context } })).toBe(context)
  })

  test('finds nothing where neither exists, or where the shape is wrong', () => {
    expect(findModelContext({})).toBeUndefined()
    expect(findModelContext({ document: { modelContext: {} } })).toBeUndefined()
    expect(findModelContext({ navigator: null })).toBeUndefined()
  })
})
