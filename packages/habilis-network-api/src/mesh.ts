/**
 * The `Mesh` both backends hand out, built over the [`Opener`] seam.
 *
 * Everything a consumer touches lives here, so the browser and the terminal
 * cannot answer the same question two different ways.
 */

// Side effect only, and load-bearing: `mesh` below is an object literal with a
// `[Symbol.asyncDispose]` key, which needs the symbol to exist by then.
import './dispose.ts'
import type { BackendSink, MeshBackend, Opener } from './backend.ts'
import { Fanout } from './fanout.ts'
import { parseRoster, rosterPresence } from './roster.ts'
import type { Mesh, MeshEvent, Message, Peer, StateDoc } from './types.ts'

/** Freeze a parsed document all the way down, once per change. */
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const nested of Object.values(value)) {
      freeze(nested)
    }
    Object.freeze(value)
  }
  return value
}

export async function openMesh(open: Opener): Promise<Mesh> {
  const messages = new Fanout<Message>()
  const events = new Fanout<MeshEvent>()
  const changes = new Fanout<Record<string, unknown>>()

  let peers: Peer[] = []
  let rosterJson = ''
  let stateJson = ''
  let stateValue: Record<string, unknown> = {}
  // Sticky lifecycle: an `events()` iterator is always created *after* open, so
  // a live `ready` would be unobservable. Events that describe a state are
  // replayed per iterator; events that describe a transition are not.
  let closedReason: string | null = null
  // Off until the backend has told us whether it pushes presence itself, which
  // also gets the during-open case right: a roster that arrives before `open`
  // resolves is the baseline, and a baseline announces nobody.
  let announcePresence = false

  const applyRoster = (json: string, announce: boolean) => {
    if (json === rosterJson) {
      return
    }
    let next: Peer[]
    try {
      next = parseRoster(json)
    } catch (error) {
      // Keep the previous roster rather than blanking it: a consumer showing a
      // stale peer list is better off than one showing an empty mesh.
      events.push({ kind: 'error', message: `unreadable roster: ${String(error)}` })
      return
    }
    rosterJson = json
    const before = peers
    peers = next
    if (announce) {
      for (const event of rosterPresence(before, next)) {
        events.push(event)
      }
    }
  }

  const applyState = (json: string) => {
    if (json === stateJson) {
      return
    }
    let next: unknown
    try {
      next = JSON.parse(json)
    } catch (error) {
      events.push({ kind: 'error', message: `unreadable state document: ${String(error)}` })
      return
    }
    stateJson = json
    stateValue = freeze(next as Record<string, unknown>)
    changes.push(stateValue)
  }

  const close = (reason: string) => {
    if (closedReason !== null) {
      return
    }
    closedReason = reason
    events.push({ kind: 'closed', reason })
    messages.end()
    events.end()
    changes.end()
  }

  const sink: BackendSink = {
    msg: (msg) => messages.push({ from: msg.from, text: msg.text, directed: msg.directed }),
    roster: (json) => applyRoster(json, announcePresence),
    state: applyState,
    presence: (event) => events.push(event),
    failed: (message) => events.push({ kind: 'error', message }),
    event: (event) => events.push(event),
    closed: close,
  }

  const opened = await open(sink)
  const backend: MeshBackend = opened.backend
  // The opening roster is the baseline, never an arrival: every peer already
  // here would otherwise be announced as having just joined.
  applyRoster(opened.rosterJson, false)
  applyState(opened.stateJson)
  announcePresence = !opened.pushesPresence

  const refuseIfClosed = () => {
    if (closedReason !== null) {
      throw new Error('this mesh has been left; open a new one with join() or create()')
    }
  }

  const state: StateDoc = {
    get value() {
      return stateValue
    },
    merge: async (patch) => {
      refuseIfClosed()
      applyState(await backend.stateMerge(JSON.stringify(patch)))
    },
    changes: (signal) => changes.iterate(signal),
  }

  const mesh: Mesh = {
    id: backend.id,
    name: backend.name,
    nick: backend.nick,
    maxMsg: backend.maxMsg,
    get peers() {
      return peers
    },
    state,
    send: async (text, opts) => {
      refuseIfClosed()
      await backend.send(opts?.to ?? null, text)
    },
    messages: (signal) => messages.iterate(signal),
    events: (signal) => {
      const live = events.iterate(signal)
      return replay(closedReason === null ? { kind: 'ready' } : { kind: 'closed', reason: closedReason }, live)
    },
    leave: async () => {
      if (closedReason !== null) {
        return
      }
      await backend.close()
      close('left the mesh')
    },
    [Symbol.asyncDispose]: async () => {
      await mesh.leave()
    },
  }
  return mesh
}

/** Yield `first`, then everything `rest` has. */
async function* replay<T>(first: T, rest: AsyncIterableIterator<T>): AsyncIterableIterator<T> {
  yield first
  yield* rest
}
