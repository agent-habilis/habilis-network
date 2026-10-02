/**
 * The worker entry: the only file on this side that touches globals.
 *
 * Everything with behavior worth testing lives in `engine.ts`; this file
 * wires it to a real message port and drives it. The loop below blocks this
 * thread for up to `RECV_TIMEOUT_MS` per pump — that is thread confinement
 * working as designed — and the macrotask yield between pumps is the only
 * point where queued `postMessage`s deliver.
 */

import { loadNative, type NativeLibrary } from './dlopen/native.ts'
import { createEngine, type Engine } from './engine.ts'
import type { Command, FromWorker } from './protocol.ts'

interface Port {
  post(message: FromWorker, transfer?: ArrayBuffer[]): void
  listen(handler: (command: Command) => void): void
}

async function portForThisRuntime(): Promise<Port> {
  const scope = globalThis as {
    postMessage?: (message: unknown, transfer?: unknown[]) => void
    onmessage?: ((event: { data: unknown }) => void) | null
  }
  // Bun and Deno workers speak the web worker API.
  if (typeof scope.postMessage === 'function') {
    return {
      post: (message, transfer) => scope.postMessage?.(message, transfer ?? []),
      listen: (handler) => {
        scope.onmessage = (event) => handler(event.data as Command)
      },
    }
  }
  // Node speaks worker_threads.
  const { parentPort } = await import('node:worker_threads')
  if (parentPort === null) {
    throw new Error('worker.ts must run inside a worker')
  }
  return {
    post: (message, transfer) => parentPort.postMessage(message, transfer ?? []),
    listen: (handler) => parentPort.on('message', (message) => handler(message as Command)),
  }
}

const port = await portForThisRuntime()

const queue: Command[] = []
let library: NativeLibrary | null = null
let engine: Engine | null = null
let spinning = false
let stopped = false

const stop = () => {
  stopped = true
  library?.close()
  library = null
}

const yieldMacrotask = () => new Promise<void>((resolve) => setTimeout(resolve, 0))

async function handleOne(command: Command): Promise<'idle' | 'closed'> {
  if (engine !== null) {
    return engine.handle(command)
  }
  if (command.t !== 'open') {
    port.post({ t: 'err', id: command.id, message: 'open the mesh first' })
    return 'idle'
  }
  try {
    library = await loadNative(command.lib)
  } catch (error) {
    port.post({
      t: 'err',
      id: command.id,
      message: error instanceof Error ? error.message : String(error),
    })
    return 'idle'
  }
  engine = createEngine(library, port)
  return engine.handle(command)
}

async function spin(): Promise<void> {
  spinning = true
  try {
    while (!stopped) {
      let command = queue.shift()
      while (command !== undefined) {
        if ((await handleOne(command)) === 'closed') {
          stop()
          return
        }
        command = queue.shift()
      }
      if (engine === null) {
        // Nothing open yet: go quiet until the next message restarts the spin.
        return
      }
      if (engine.pumpOnce() === 'closed') {
        stop()
        return
      }
      await yieldMacrotask()
    }
  } finally {
    spinning = false
  }
}

port.listen((command) => {
  queue.push(command)
  if (!spinning && !stopped) {
    void spin()
  }
})
