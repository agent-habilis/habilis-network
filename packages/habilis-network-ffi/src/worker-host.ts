/**
 * Spawning the worker that owns the handle, and talking to it — the main
 * thread's half of the `protocol.ts` contract, one small adapter per runtime.
 */

import type { Command, FromWorker } from './protocol.ts'

export interface WorkerHost {
  post(command: Command, transfer?: ArrayBuffer[]): void
  onMessage(handler: (message: FromWorker) => void): void
  terminate(): Promise<void>
}

const workerUrl = () => new URL('./worker.ts', import.meta.url)

export async function spawnWorker(): Promise<WorkerHost> {
  const globals = globalThis as { Bun?: unknown; Deno?: unknown }
  if (globals.Bun !== undefined || globals.Deno !== undefined) {
    // Bun ignores `type` (always a module); Deno requires it.
    const worker = new Worker(workerUrl(), { type: 'module' })
    return {
      post: (command, transfer) => worker.postMessage(command, transfer ?? []),
      onMessage: (handler) => {
        worker.onmessage = (event) => handler(event.data as FromWorker)
      },
      terminate: async () => {
        worker.terminate()
      },
    }
  }
  // Node. Runs the .ts entry directly, which needs type stripping (stock on
  // Node ≥ 23.6, `--experimental-strip-types` on 22.6+). The workspace keeps
  // this package outside node_modules by realpath, which is what makes
  // stripping legal there — the constraint `packages/README.md` documents.
  const { Worker: NodeWorker } = await import('node:worker_threads')
  const worker = new NodeWorker(workerUrl())
  return {
    post: (command, transfer) => worker.postMessage(command, transfer ?? []),
    onMessage: (handler) => {
      worker.on('message', (message) => handler(message as FromWorker))
    },
    terminate: async () => {
      await worker.terminate()
    },
  }
}
