/**
 * fofoca on Bun, Deno and Node: `join` / `create` over the C ABI.
 *
 * The mesh handle lives on a dedicated worker thread (the C ABI is blocking
 * and thread-confined); this side marshals every call to it and feeds what
 * comes back into `fofoca-api`'s `openMesh`, which owns everything a consumer
 * touches.
 */

import {
  type CreateOpts,
  type JoinOpts,
  type Mesh,
  type MeshBackend,
  type Opener,
  openMesh,
} from 'fofoca-api'
import { libraryPath } from './discover.ts'
import type { Command, OpenReply, Reply, WireOpts } from './protocol.ts'
import { spawnWorker, type WorkerHost } from './worker-host.ts'

export type { WireOpts } from './protocol.ts'

/** How long `leave()` waits for the worker's goodbye before pulling the plug. */
const CLOSE_TIMEOUT_MS = 2000

/** A `Command` minus the `id` this side mints — distributed over the union. */
type CommandBody = { [K in Command['t']]: Omit<Extract<Command, { t: K }>, 'id'> }[Command['t']]

/** Injection points for the tests; real callers never pass this. */
export interface OpenerDeps {
  spawn?: () => Promise<WorkerHost>
  lib?: string
}

export function ffiOpener(wire: WireOpts, deps: OpenerDeps = {}): Opener {
  return async (sink) => {
    // Resolved on the main thread on purpose: a discovery miss here is an
    // exception with a stack, where inside the worker it would be a
    // `postMessage` arriving before anything listens.
    const lib = deps.lib ?? libraryPath()
    const host = await (deps.spawn ?? spawnWorker)()

    let nextId = 1
    const pending = new Map<number, { resolve: (value: Reply) => void; reject: (error: Error) => void }>()
    let terminated = false
    const terminate = async () => {
      if (terminated) {
        return
      }
      terminated = true
      await host.terminate()
    }

    host.onMessage((message) => {
      switch (message.t) {
        case 'ok': {
          pending.get(message.id)?.resolve(message.value)
          pending.delete(message.id)
          break
        }
        case 'err': {
          pending.get(message.id)?.reject(new Error(message.message))
          pending.delete(message.id)
          break
        }
        case 'msg': {
          sink.msg({ from: message.from, directed: message.directed, text: message.text })
          break
        }
        case 'roster': {
          sink.roster(message.json)
          break
        }
        case 'state': {
          sink.state(message.json)
          break
        }
        case 'failed': {
          sink.failed(message.message)
          break
        }
        case 'closed': {
          sink.closed(message.reason)
          // The worker replies `ok` before it announces `closed`, so anything
          // still pending here will never be answered.
          for (const waiter of pending.values()) {
            waiter.reject(new Error(`the mesh closed: ${message.reason}`))
          }
          pending.clear()
          void terminate()
          break
        }
        default: {
          message satisfies never
        }
      }
    })

    const request = (command: CommandBody, transfer?: ArrayBuffer[]): Promise<Reply> => {
      const id = nextId
      nextId += 1
      return new Promise<Reply>((resolve, reject) => {
        pending.set(id, { resolve, reject })
        host.post({ ...command, id } as Command, transfer)
      })
    }

    let reply: OpenReply
    try {
      reply = (await request({ t: 'open', opts: wire, lib })) as OpenReply
    } catch (error) {
      await terminate()
      throw error
    }

    const backend: MeshBackend = {
      id: reply.id,
      name: reply.name,
      nick: reply.nick,
      maxMsg: reply.maxMsg,
      send: async (to, text) => {
        await request({ t: 'send', to, text })
      },
      stateMerge: async (json) => (await request({ t: 'stateMerge', json })) as string,
      close: async () => {
        try {
          await withTimeout(request({ t: 'close' }), CLOSE_TIMEOUT_MS)
        } finally {
          // A wedged engine must not be able to hang `leave()`.
          await terminate()
        }
      },
    }

    return {
      backend,
      rosterJson: reply.rosterJson,
      stateJson: reply.stateJson,
      // The C ABI has no presence callback; `openMesh` derives joined/left by
      // diffing the rosters the worker polls every 500 ms.
      pushesPresence: false,
    }
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms`)), ms)
    promise
      .then((value) => {
        clearTimeout(timer)
        resolve(value)
      })
      .catch((error: unknown) => {
        clearTimeout(timer)
        reject(error instanceof Error ? error : new Error(String(error)))
      })
  })
}

export function joinWire(opts: JoinOpts): WireOpts {
  const topic = opts.topic ?? null
  const mesh = opts.id ?? null
  if (topic === null && mesh === null) {
    // `fofoca_mesh_open` with neither selector *creates* a mesh — join({}) would
    // silently mint a loopback mesh of one and hear nobody, ever.
    throw new Error('join needs a topic or an id; to start a fresh mesh use create()')
  }
  if (topic !== null && mesh !== null) {
    throw new Error('join takes a topic or an id, not both')
  }
  return {
    mesh,
    topic,
    nick: opts.nick ?? null,
    name: null,
    lookup: null,
    transport: listWire(opts.transport),
    relayUrls: listWire(opts.relayUrls),
    disableIp: false,
    disableWebrtc: false,
    maxPeers: opts.maxPeers ?? 0,
  }
}

export function createWire(opts: CreateOpts): WireOpts {
  return {
    mesh: null,
    topic: null,
    nick: opts.nick ?? null,
    name: opts.name ?? null,
    lookup: listWire(opts.lookup),
    transport: listWire(opts.transport),
    relayUrls: listWire(opts.relayUrls),
    disableIp: opts.paths?.ip === false,
    disableWebrtc: opts.paths?.webrtc === false,
    maxPeers: opts.maxPeers ?? 0,
  }
}

/** The C ABI takes each list as one comma-separated string, NULL for empty. */
function listWire(items: readonly string[] | undefined): string | null {
  if (items === undefined || items.length === 0) {
    return null
  }
  return items.join(',')
}

export async function join(opts: JoinOpts = {}): Promise<Mesh> {
  return openMesh(ffiOpener(joinWire(opts)))
}

export async function create(opts: CreateOpts = {}): Promise<Mesh> {
  return openMesh(ffiOpener(createWire(opts)))
}

export { randomNick, randomTopic } from 'fofoca-api'
export type {
  CreateOpts,
  JoinOpts,
  Lane,
  Lookup,
  Mesh,
  MeshEvent,
  Message,
  Peer,
  Reach,
  StateDoc,
  Transport,
} from 'fofoca-api'
