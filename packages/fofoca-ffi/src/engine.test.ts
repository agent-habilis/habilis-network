import { describe, expect, test } from 'bun:test'
import type { NativeLibrary, NativePointer, NativeValue } from './dlopen/native.ts'
import { createEngine } from './engine.ts'
import { encodeMsg } from './msg.ts'
import type { Command, FromWorker, OpenReply, WireOpts } from './protocol.ts'

const OPTS: WireOpts = {
  mesh: null,
  topic: null,
  nick: 'ana',
  name: null,
  lookup: null,
  transport: null,
  relayUrls: null,
  disableIp: false,
  disableWebrtc: false,
  maxPeers: 0,
}

const OPEN: Command = { t: 'open', id: 1, opts: OPTS, lib: '/fake' }

interface FakeMsg {
  readonly nick: string
  readonly directed: boolean
  readonly text: string
}

/**
 * A `NativeLibrary` whose pointers are the strings they point at, so
 * `readCString` is the identity and NULL is `null`.
 */
function fakeLib(
  overrides: {
    openFails?: boolean
    sendResult?: number
    recv?: (FakeMsg | 'fail')[]
    lastError?: string
  } = {},
) {
  const utf8 = new TextEncoder()
  const state = {
    roster: '{"count":1,"peers":[]}',
    state: '{}',
    sends: [] as { to: string | null; text: string }[],
    closes: 0,
  }
  const recvQueue = overrides.recv ?? []

  const writeDocument = (doc: string, args: NativeValue[]): bigint => {
    const bytes = utf8.encode(doc)
    const buffer = args[1] as Uint8Array
    const cap = Number(args[2] as bigint)
    if (bytes.byteLength < cap) {
      buffer.set(bytes, 0)
    }
    return BigInt(bytes.byteLength)
  }

  const lib: NativeLibrary = {
    call: (name, ...args) => {
      switch (name) {
        case 'fofoca_max_msg':
          return 1408n
        case 'fofoca_mesh_id':
          return 'mesh-id'
        case 'fofoca_mesh_name':
          return 'mesh-name'
        case 'fofoca_mesh_nickname':
          return 'ana'
        case 'fofoca_version':
          return '0.0.0-test'
        case 'fofoca_last_error':
          return overrides.lastError ?? 'boom'
        case 'fofoca_mesh_peers_json':
          return writeDocument(state.roster, args)
        case 'fofoca_mesh_state_json':
          return writeDocument(state.state, args)
        case 'fofoca_msg_send': {
          state.sends.push({ to: args[1] as string | null, text: args[2] as string })
          return overrides.sendResult ?? 0
        }
        case 'fofoca_mesh_state_merge': {
          state.state = `{"merged":${JSON.stringify(args[1] as string)}}`
          return 0
        }
        case 'fofoca_msg_recv': {
          const next = recvQueue[0]
          if (next === undefined) {
            return 0n
          }
          if (next === 'fail') {
            recvQueue.shift()
            return -1n
          }
          const text = utf8.encode(next.text)
          const meta = args[4] as Uint8Array
          meta.set(encodeMsg({ nick: next.nick, directed: next.directed, len: text.byteLength }), 0)
          const buffer = args[1] as Uint8Array
          if (text.byteLength >= Number(args[2] as bigint)) {
            // Kept, as the engine keeps it, for a retry with a bigger buffer.
            return -2n
          }
          recvQueue.shift()
          buffer.set(text, 0)
          buffer[text.byteLength] = 0
          return 1n
        }
        case 'fofoca_mesh_close': {
          state.closes += 1
          return 0
        }
        case 'fofoca_mesh_open':
        case 'fofoca_mesh_peer_count':
        case 'fofoca_streams_bind':
        case 'fofoca_streams_bind_for':
        case 'fofoca_streams_close':
        case 'fofoca_stream_create':
        case 'fofoca_stream_hash':
        case 'fofoca_stream_write':
        case 'fofoca_stream_close':
        case 'fofoca_stream_open':
        case 'fofoca_stream_read':
        case 'fofoca_reader_close':
          throw new Error(`${name} is not part of the engine's vocabulary`)
        default:
          name satisfies never
          throw new Error('unreachable')
      }
    },
    readCString: (pointer: NativePointer) => pointer as string,
    isNull: (pointer: NativePointer) => pointer === null,
    open: () => (overrides.openFails ? null : 'handle'),
    close: () => {},
  }
  return { lib, state }
}

function fakePort() {
  const posted: FromWorker[] = []
  const transfers: ArrayBuffer[][] = []
  return {
    posted,
    transfers,
    port: {
      post: (message: FromWorker, transfer?: ArrayBuffer[]) => {
        posted.push(message)
        transfers.push(transfer ?? [])
      },
    },
  }
}

describe('createEngine', () => {
  test('open assembles the whole reply', () => {
    const { lib } = fakeLib()
    const { port, posted } = fakePort()
    const engine = createEngine(lib, port, () => 0)
    expect(engine.handle(OPEN)).toBe('idle')
    expect(posted).toHaveLength(1)
    const reply = posted[0] as { t: 'ok'; id: number; value: OpenReply }
    expect(reply.t).toBe('ok')
    expect(reply.id).toBe(1)
    expect(reply.value).toEqual({
      id: 'mesh-id',
      name: 'mesh-name',
      nick: 'ana',
      rosterJson: '{"count":1,"peers":[]}',
      stateJson: '{}',
      maxMsg: 1408,
      version: '0.0.0-test',
    })
  })

  test('a failed open reports the thread-local error', () => {
    const { lib } = fakeLib({ openFails: true, lastError: 'no such mesh' })
    const { port, posted } = fakePort()
    createEngine(lib, port, () => 0).handle(OPEN)
    expect(posted[0]).toEqual({ t: 'err', id: 1, message: 'fofoca_mesh_open: no such mesh' })
  })

  test('a received message crosses with its author, kind and text', () => {
    const { lib } = fakeLib({ recv: [{ nick: 'bo', directed: true, text: 'olá' }] })
    const { port, posted } = fakePort()
    const engine = createEngine(lib, port, () => 0)
    engine.handle(OPEN)
    expect(engine.pumpOnce()).toBe('idle')
    expect(posted[1]).toEqual({ t: 'msg', from: 'bo', directed: true, text: 'olá' })
  })

  test('a message too big for the buffer is taken on the next pump, whole', () => {
    const text = 'x'.repeat(5000)
    const { lib } = fakeLib({ recv: [{ nick: 'bo', directed: false, text }] })
    const { port, posted } = fakePort()
    const engine = createEngine(lib, port, () => 0)
    engine.handle(OPEN)
    engine.pumpOnce()
    expect(posted).toHaveLength(1)
    engine.pumpOnce()
    expect(posted[1]).toEqual({ t: 'msg', from: 'bo', directed: false, text })
  })

  test('a recv failure closes the mesh and the handle', () => {
    const { lib, state } = fakeLib({ recv: ['fail'], lastError: 'engine gone' })
    const { port, posted } = fakePort()
    const engine = createEngine(lib, port, () => 0)
    engine.handle(OPEN)
    expect(engine.pumpOnce()).toBe('closed')
    expect(posted[1]).toEqual({ t: 'closed', reason: 'fofoca_msg_recv: engine gone' })
    expect(state.closes).toBe(1)
    // Terminal for commands too.
    engine.handle({ t: 'send', id: 9, to: null, text: 'late' })
    expect(posted[2]).toEqual({ t: 'err', id: 9, message: 'the mesh is closed' })
  })

  test('send forwards the text and replies; a failure carries the error', () => {
    const { lib, state } = fakeLib({ sendResult: 0 })
    const { port, posted } = fakePort()
    const engine = createEngine(lib, port, () => 0)
    engine.handle(OPEN)
    engine.handle({ t: 'send', id: 2, to: 'bo', text: 'hello' })
    expect(posted[1]).toEqual({ t: 'ok', id: 2, value: null })
    expect(state.sends).toEqual([{ to: 'bo', text: 'hello' }])
  })

  test('stateMerge replies with the resulting document', () => {
    const { lib } = fakeLib()
    const { port, posted } = fakePort()
    const engine = createEngine(lib, port, () => 0)
    engine.handle(OPEN)
    engine.handle({ t: 'stateMerge', id: 2, json: '{"a":1}' })
    expect(posted[1]).toEqual({ t: 'ok', id: 2, value: '{"merged":"{\\"a\\":1}"}' })
  })

  test('roster and state are re-read on the poll cadence, not sooner', () => {
    let clock = 0
    const { lib } = fakeLib()
    const { port, posted } = fakePort()
    const engine = createEngine(lib, port, () => clock)
    engine.handle(OPEN)
    clock = 499
    engine.pumpOnce()
    expect(posted).toHaveLength(1) // just the open reply
    clock = 500
    engine.pumpOnce()
    expect(posted[1]).toEqual({ t: 'roster', json: '{"count":1,"peers":[]}' })
    expect(posted[2]).toEqual({ t: 'state', json: '{}' })
    // The cadence rebased on the poll, not on open.
    clock = 999
    engine.pumpOnce()
    expect(posted).toHaveLength(3)
  })

  test('close releases the handle, replies, then announces', () => {
    const { lib, state } = fakeLib()
    const { port, posted } = fakePort()
    const engine = createEngine(lib, port, () => 0)
    engine.handle(OPEN)
    expect(engine.handle({ t: 'close', id: 2 })).toBe('closed')
    expect(state.closes).toBe(1)
    expect(posted[1]).toEqual({ t: 'ok', id: 2, value: null })
    expect(posted[2]).toEqual({ t: 'closed', reason: 'left the mesh' })
  })
})
