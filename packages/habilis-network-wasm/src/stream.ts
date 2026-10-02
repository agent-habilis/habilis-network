/**
 * Byte streams in the browser: 1-1, addressed by a hash, over a direct path by
 * default (a WebRTC data channel from a tab), over the relay only when the
 * stream's `transport` allows it, never over the mesh's gossip.
 *
 * ```ts
 * import { bindStreams, bindStreamsFor } from 'habilis-network-wasm'
 * const streams = await bindStreams({ lookup: ['relay'] })
 * const producer = await streams.create()
 * share(producer.hash)
 * await producer.write('hello')
 * await producer.close()
 *
 * const reader = await (await bindStreamsFor(hash)).open(hash)
 * for await (const chunk of reader) { … }
 * ```
 */

import type { Lookup, Transport } from 'habilis-network-api'

import { loadWasm } from './module.ts'
import type { ProducerHandle, ReaderHandle, StreamNodeHandle } from './module.ts'
import type { WasmOpts } from './index.ts'

/** How a stream node reaches peers: the same lists a mesh create takes. */
export interface StreamOpts {
  lookup?: Lookup[]
  transport?: Transport[]
  relayUrls?: string[]
}

export interface Producer {
  /** Hand this to the one consumer. Whoever holds it can take the stream. */
  readonly hash: string
  /** Resolves once the consumer is attached. */
  attached(): Promise<void>
  /** Waits for the consumer, then for room: the consumer paces the producer. */
  write(data: Uint8Array | string): Promise<void>
  /**
   * The consumer reads everything written, then the end of the stream. With
   * no consumer yet, the stream is abandoned at once instead.
   */
  close(): Promise<void>
  /** Give the stream up: the consumer reads an error, not the end. */
  abandon(): Promise<void>
}

export interface Reader extends AsyncIterable<Uint8Array> {
  /** The next bytes, or `null` at the end of the stream. Throws once closed. */
  read(): Promise<Uint8Array | null>
  close(): Promise<void>
}

export interface Streams extends AsyncDisposable {
  /** Resolves once the node has reached its relay, so the hash carries it. */
  create(): Promise<Producer>
  open(hash: string): Promise<Reader>
  close(): Promise<void>
}

const encoder = new TextEncoder()

function wrapProducer(handle: ProducerHandle): Producer {
  return {
    hash: handle.hash(),
    attached: () => handle.attached(),
    write: (data) => handle.write(typeof data === 'string' ? encoder.encode(data) : data),
    close: () => handle.close(),
    abandon: () => handle.abandon(),
  }
}

function wrapReader(handle: ReaderHandle): Reader {
  const read = async (): Promise<Uint8Array | null> => (await handle.read()) ?? null
  return {
    read,
    close: () => handle.close(),
    async *[Symbol.asyncIterator]() {
      for (;;) {
        const chunk = await read()
        if (chunk === null) {
          return
        }
        yield chunk
      }
    },
  }
}

function wrapNode(node: StreamNodeHandle): Streams {
  const streams: Streams = {
    create: async () => wrapProducer(await node.create()),
    open: async (hash) => wrapReader(await node.open(hash)),
    close: () => node.close(),
    [Symbol.asyncDispose]: () => streams.close(),
  }
  return streams
}

/** A node that creates and opens streams. A browser needs `lookup: ['relay']`. */
export async function bindStreams(opts: StreamOpts & WasmOpts = {}): Promise<Streams> {
  const module = await loadWasm(opts.glueUrl)
  module.initTracing(opts.log ?? 'info')
  const node = await module.StreamNode.bind(
    JSON.stringify({
      lookup: opts.lookup ?? [],
      transport: opts.transport ?? [],
      relayUrls: opts.relayUrls ?? [],
    }),
  )
  return wrapNode(node)
}

/** A node that can reach the producer of `hash`, with the hash's own lookups. */
export async function bindStreamsFor(hash: string, extras: WasmOpts = {}): Promise<Streams> {
  const module = await loadWasm(extras.glueUrl)
  module.initTracing(extras.log ?? 'info')
  return wrapNode(await module.StreamNode.forHash(hash))
}
