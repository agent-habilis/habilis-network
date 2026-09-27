/**
 * The loop that owns the handle, as a pure object: a `NativeLibrary` in, a
 * port out, time injected. `worker.ts` is the thin file that gives it real
 * globals; the tests hand it fakes and a hand-cranked clock.
 *
 * Every `fofoca_*` call for the handle happens through this one object on one
 * thread — the C ABI's thread-confinement rule (`LAST_ERROR` is a
 * `thread_local!` in `crates/fofoca-ffi/src/ffi.rs`), which is why none of
 * this may ever run on a pool thread.
 */

import type { NativeLibrary, NativePointer } from './dlopen/native.ts'
import { MSG_BYTES, decodeMsg } from './msg.ts'
import {
  type Command,
  type FromWorker,
  type OpenReply,
  POLL_MS,
  RECV_TIMEOUT_MS,
} from './protocol.ts'
import { readDocument } from './query.ts'

export interface EnginePort {
  post(message: FromWorker, transfer?: ArrayBuffer[]): void
}

/** What the drive loop does next: keep spinning, or stop for good. */
export type EngineStatus = 'idle' | 'closed'

export interface Engine {
  handle(command: Command): EngineStatus
  pumpOnce(): EngineStatus
}

/**
 * The receive buffer's starting size: past the largest signed frame the engine
 * accepts, so a `-2` (buffer too small) is a surprise rather than the norm.
 * The engine keeps the message on `-2`, and the buffer grows for the retry.
 */
const RECV_BYTES = 4096

const utf8 = new TextDecoder()

export function createEngine(
  lib: NativeLibrary,
  port: EnginePort,
  now: () => number = Date.now,
): Engine {
  let handle: NativePointer | null = null
  let payload = new Uint8Array(RECV_BYTES)
  const meta = new Uint8Array(MSG_BYTES)
  let closed = false
  let lastPoll = 0

  const lastError = (call: string): string => {
    const pointer = lib.call('fofoca_last_error') as NativePointer
    return lib.isNull(pointer) ? `${call} failed` : `${call}: ${lib.readCString(pointer)}`
  }

  const raise = (call: string): never => {
    throw new Error(lastError(call))
  }

  const cstring = (
    call: 'fofoca_mesh_id' | 'fofoca_mesh_name' | 'fofoca_mesh_nickname' | 'fofoca_version',
  ) => {
    const pointer =
      call === 'fofoca_version'
        ? (lib.call(call) as NativePointer)
        : (lib.call(call, handle) as NativePointer)
    if (lib.isNull(pointer)) {
      raise(call)
    }
    return lib.readCString(pointer)
  }

  const readDoc = (name: 'fofoca_mesh_state_json' | 'fofoca_mesh_peers_json'): string =>
    readDocument(name, (buffer, cap) => lib.call(name, handle, buffer, cap) as bigint, raise)

  const ok = (id: number, value: OpenReply | string | null) => {
    port.post({ t: 'ok', id, value })
  }

  const err = (id: number, message: string) => {
    port.post({ t: 'err', id, message })
  }

  const status = (): EngineStatus => (closed ? 'closed' : 'idle')

  const open = (id: number, command: Command & { t: 'open' }) => {
    if (handle !== null) {
      err(id, 'this worker already owns a mesh')
      return
    }
    const opened = lib.open(command.opts)
    if (lib.isNull(opened)) {
      err(id, lastError('fofoca_mesh_open'))
      return
    }
    handle = opened
    lastPoll = now()
    ok(id, {
      id: cstring('fofoca_mesh_id'),
      name: cstring('fofoca_mesh_name'),
      nick: cstring('fofoca_mesh_nickname'),
      rosterJson: readDoc('fofoca_mesh_peers_json'),
      stateJson: readDoc('fofoca_mesh_state_json'),
      maxMsg: Number(lib.call('fofoca_max_msg') as bigint),
      version: cstring('fofoca_version'),
    })
  }

  const handleCommand = (command: Command): EngineStatus => {
    if (closed) {
      err(command.id, 'the mesh is closed')
      return 'closed'
    }
    try {
      switch (command.t) {
        case 'open': {
          open(command.id, command)
          break
        }
        case 'send': {
          if (handle === null) {
            err(command.id, 'no open mesh')
            break
          }
          const code = lib.call('fofoca_msg_send', handle, command.to, command.text) as number
          if (code === 0) {
            ok(command.id, null)
          } else {
            err(command.id, lastError('fofoca_msg_send'))
          }
          break
        }
        case 'stateMerge': {
          if (handle === null) {
            err(command.id, 'no open mesh')
            break
          }
          const code = lib.call('fofoca_mesh_state_merge', handle, command.json) as number
          if (code === 0) {
            // Reply with the *resulting* document: `MeshBackend.stateMerge`'s
            // read-your-write contract, which the next poll is up to half a
            // second too late for.
            ok(command.id, readDoc('fofoca_mesh_state_json'))
          } else {
            err(command.id, lastError('fofoca_mesh_state_merge'))
          }
          break
        }
        case 'close': {
          if (handle !== null) {
            lib.call('fofoca_mesh_close', handle)
            handle = null
          }
          closed = true
          ok(command.id, null)
          port.post({ t: 'closed', reason: 'left the mesh' })
          break
        }
        default: {
          command satisfies never
        }
      }
    } catch (error) {
      err(command.id, error instanceof Error ? error.message : String(error))
    }
    return status()
  }

  const pumpOnce = (): EngineStatus => {
    if (closed || handle === null) {
      return status()
    }
    const code = lib.call(
      'fofoca_msg_recv',
      handle,
      payload,
      BigInt(payload.byteLength),
      RECV_TIMEOUT_MS,
      meta,
    ) as bigint
    if (code === 1n || code === -2n) {
      let msg
      try {
        msg = decodeMsg(meta)
      } catch (error) {
        port.post({ t: 'failed', message: String(error) })
        return status()
      }
      if (code === -2n) {
        // Kept by the engine; the next pump takes it into the bigger buffer.
        payload = new Uint8Array(msg.len + 1)
        return status()
      }
      port.post({
        t: 'msg',
        from: msg.nick,
        directed: msg.directed,
        text: utf8.decode(payload.subarray(0, msg.len)),
      })
    } else if (code < 0n) {
      // A recv failure is terminal: the engine's inbound channel is gone, and
      // pretending otherwise would spin on the same error 20 times a second.
      const reason = lastError('fofoca_msg_recv')
      lib.call('fofoca_mesh_close', handle)
      handle = null
      closed = true
      port.post({ t: 'closed', reason })
      return 'closed'
    }

    if (now() - lastPoll >= POLL_MS) {
      lastPoll = now()
      try {
        port.post({ t: 'roster', json: readDoc('fofoca_mesh_peers_json') })
        port.post({ t: 'state', json: readDoc('fofoca_mesh_state_json') })
      } catch (error) {
        // A poll failure has no caller waiting on it. Surface and keep going.
        port.post({ t: 'failed', message: error instanceof Error ? error.message : String(error) })
      }
    }
    return status()
  }

  return { handle: handleCommand, pumpOnce }
}
