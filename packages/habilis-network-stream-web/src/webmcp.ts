/**
 * The runtime as WebMCP tools.
 *
 * WebMCP (`document.modelContext`, earlier `navigator.modelContext`) lets a
 * page register schema-backed tools a browser agent can call. A tool is one
 * `execute` promise: the spec has no streaming or progress channel yet
 * (webmachinelearning/webmcp #82, #196), so the reading side is a
 * `stream_read` that long-polls for the first chunk.
 *
 * `streamTools` is pure so the tests can call each `execute` directly; the
 * registration is the only part that touches the browser, and it no-ops
 * where there is no model context.
 */

import type { StreamRuntime } from './runtime.ts'
import { MAX_WAIT_MS } from './runtime.ts'

export interface ToolResult {
  readonly content: { readonly type: 'text'; readonly text: string }[]
}

export interface ToolDescriptor {
  readonly name: string
  readonly description: string
  readonly inputSchema: Record<string, unknown>
  execute(input: unknown, options?: { signal?: AbortSignal }): Promise<ToolResult>
}

/** The slice of a model context this page uses. */
export interface ModelContextLike {
  registerTool(tool: ToolDescriptor): unknown
}

/** `document.modelContext`, else `navigator.modelContext`, else nothing. */
export function findModelContext(scope: object = globalThis): ModelContextLike | undefined {
  const holders = ['document', 'navigator'] as const
  for (const holder of holders) {
    const owner = (scope as Record<string, unknown>)[holder]
    if (owner === null || typeof owner !== 'object') {
      continue
    }
    const context = (owner as Record<string, unknown>)['modelContext']
    if (isModelContext(context)) {
      return context
    }
  }
  return undefined
}

function isModelContext(value: unknown): value is ModelContextLike {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as Record<string, unknown>)['registerTool'] === 'function'
  )
}

/** Register every stream tool. `false` when this browser has no model context. */
export function registerStreamTools(
  runtime: StreamRuntime,
  context: ModelContextLike | undefined = findModelContext(),
): boolean {
  if (context === undefined) {
    return false
  }
  for (const tool of streamTools(runtime)) {
    context.registerTool(tool)
  }
  return true
}

export function streamTools(runtime: StreamRuntime): ToolDescriptor[] {
  return [
    {
      name: 'stream_write',
      description:
        'Write text to the stream this tab produces. Waits until the one reader has attached, then until it has room: the reader paces the writer. Only a producing tab can write.',
      inputSchema: {
        type: 'object',
        properties: { text: { type: 'string', description: 'The text to write.' } },
        required: ['text'],
      },
      execute: async (input) => {
        const { text } = fields(input)
        await runtime.write(requireString(text, 'text'))
        return ok({ written: true })
      },
    },
    {
      name: 'stream_close',
      description:
        'End the stream this tab produces: the reader gets everything written, then the end of the stream. With no reader yet, the stream is abandoned and a later reader is refused. The stream cannot be written to afterwards.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => {
        await runtime.close()
        return ok({ closed: true })
      },
    },
    {
      name: 'stream_read',
      description: `Read what has arrived on the stream this tab reads, in order, and get back a cursor. Pass that cursor to the next call to continue where you stopped; omit it to read from the oldest entry still held. Reading takes nothing away, so another reader with its own cursor sees the same bytes. If there is nothing to read, wait up to waitMs (at most ${MAX_WAIT_MS}) for the first entry, then return what arrived, possibly nothing. Call it in a loop to follow the stream; an item with eof=true is its end. Ask for encoding "base64" to get bytes that are not text back exactly.`,
      inputSchema: {
        type: 'object',
        properties: {
          waitMs: {
            type: 'integer',
            minimum: 0,
            maximum: MAX_WAIT_MS,
            description: 'How long to wait for the first entry when there is nothing to read.',
          },
          cursor: {
            type: 'integer',
            minimum: 0,
            description: 'Where to read from, as returned by a previous call.',
          },
          encoding: {
            type: 'string',
            enum: ['text', 'base64'],
            description: 'How to render the bytes. Default text.',
          },
        },
      },
      execute: async (input, options) => {
        const { waitMs, cursor, encoding } = fields(input)
        return ok(
          await runtime.read(
            {
              ...(waitMs === undefined ? {} : { waitMs: requireInteger(waitMs, 'waitMs') }),
              ...(cursor === undefined ? {} : { cursor: requireInteger(cursor, 'cursor') }),
              ...(encoding === undefined ? {} : { encoding: requireEncoding(encoding) }),
            },
            options?.signal,
          ),
        )
      },
    },
    {
      name: 'stream_status',
      description:
        "This tab's end of the stream: whether it reads or produces, whether the reader has attached, whether the stream ended (or why it stopped early), the bytes so far, and the read log's cursors. A producing tab also gets the stream's hash. The hash is a secret: whoever presents it first becomes the stream's one reader, so give it only to the intended reader and never write it into a shared chat or log. Once `attached` is true the hash is spent and harmless.",
      inputSchema: { type: 'object', properties: {} },
      execute: async () => {
        // A reader's hash is spent and has no use to its agent; it is not
        // handed out where it could leak.
        const { hash, ...status } = runtime.status()
        return ok(status.role === 'producer' && hash !== undefined ? { ...status, hash } : status)
      },
    },
  ]
}

function ok(value: unknown): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value) }] }
}

function fields(input: unknown): Record<string, unknown> {
  if (input === undefined || input === null) {
    return {}
  }
  if (typeof input !== 'object') {
    throw new TypeError('tool input must be an object')
  }
  return input as Record<string, unknown>
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string') {
    throw new TypeError(`${name} must be a string`)
  }
  return value
}

function requireInteger(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new TypeError(`${name} must be an integer`)
  }
  return value
}

function requireEncoding(value: unknown): 'text' | 'base64' {
  if (value !== 'text' && value !== 'base64') {
    throw new TypeError('encoding must be "text" or "base64"')
  }
  return value
}

