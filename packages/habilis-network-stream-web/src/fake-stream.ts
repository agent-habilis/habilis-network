/** Fakes for the runtime's two ends: a byte source fed by `push`, a sink that records. */

import type { ByteSink, ByteSource } from './runtime.ts'

export interface FakeSource {
  readonly source: ByteSource
  push(bytes: Uint8Array | string): void
  end(): void
  fail(message: string): void
}

export function fakeSource(): FakeSource {
  const queue: (Uint8Array | null | Error)[] = []
  let wake: (() => void) | undefined
  const put = (item: Uint8Array | null | Error) => {
    queue.push(item)
    wake?.()
    wake = undefined
  }
  return {
    source: {
      read: async () => {
        while (queue.length === 0) {
          await new Promise<void>((resolve) => {
            wake = resolve
          })
        }
        const next = queue.shift()
        if (next instanceof Error) {
          throw next
        }
        return next ?? null
      },
    },
    push: (bytes) => put(typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes),
    end: () => put(null),
    fail: (message) => put(new Error(message)),
  }
}

export interface FakeSink {
  readonly sink: ByteSink
  readonly writes: string[]
  closes: number
  attach(): void
}

export function fakeSink(hash = 'the-hash'): FakeSink {
  let attach: () => void = () => {}
  let refuse: (error: Error) => void = () => {}
  const attached = new Promise<void>((resolve, reject) => {
    attach = resolve
    refuse = reject
  })
  // Unobserved until a caller waits on it, like the real handle's promise.
  attached.catch(() => {})
  const handle: FakeSink = {
    writes: [],
    closes: 0,
    attach: () => attach(),
    sink: {
      hash,
      attached: () => attached,
      write: async (data) => {
        await attached
        handle.writes.push(typeof data === 'string' ? data : new TextDecoder().decode(data))
      },
      // Like the wasm producer: a close ends any wait for the reader.
      close: async () => {
        handle.closes += 1
        refuse(new Error('this stream is closed'))
      },
    },
  }
  return handle
}

/** Let queued promise callbacks run. */
export function settle(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0))
}
