/**
 * The browser backend: a wasm [`MeshPeerHandle`] behind the `fofoca-api`
 * [`Opener`] seam. Two drain loops carry everything the engine surfaces —
 * messages and events — and a slow roster poll picks up what no event
 * announces (a peer's `transport` lane flipping from `relay-only` to
 * `unicast` once a path is proven, say).
 */

import type { BackendOpen, BackendSink, Opener } from 'fofoca-api'

import type { FofocaWasmModule, MeshPeerHandle } from './module.ts'

/** How often the roster is re-read between events. Dedup is upstream: an
 * identical document is discarded on a string compare before any parse. */
const ROSTER_POLL_MS = 500

interface WireMsg {
  nick: string
  directed: boolean
  text: string
}

type WireEvent =
  | { kind: 'ready' }
  | { kind: 'joined'; nick: string }
  | { kind: 'left'; nick: string }
  | { kind: 'quiet'; nick: string; last_seen_secs_ago: number }
  | { kind: 'returned'; nick: string }
  | { kind: 'fork'; nick: string; pubkey: string; seq: number }
  | { kind: 'state_changed'; channel: string; author: string; document: unknown; is_self: boolean }
  | { kind: 'info'; text: string }
  | { kind: 'error'; text: string }

/**
 * Build the [`Opener`] for one membership. `optsJson` is a JSON encoding of
 * `fofoca::membership::Opts` — the same object the C ABI takes.
 */
export function openWasm(module: FofocaWasmModule, optsJson: string): Opener {
  return async (sink: BackendSink): Promise<BackendOpen> => {
    const peer = await module.MeshPeer.open(optsJson)
    let closed = false

    const pushRoster = async () => {
      try {
        sink.roster(await peer.peersJson())
      } catch {
        // The loop is gone; the event drain reports it.
      }
    }

    const msgs = async () => {
      for (;;) {
        const json = await peer.nextMsg()
        if (json === undefined || json === null) {
          return
        }
        const msg = JSON.parse(json) as WireMsg
        sink.msg({ from: msg.nick, text: msg.text, directed: msg.directed })
      }
    }

    const events = async () => {
      for (;;) {
        const json = await peer.nextEvent()
        if (json === undefined || json === null) {
          if (!closed) {
            closed = true
            sink.closed('mesh event loop stopped')
          }
          return
        }
        const event = JSON.parse(json) as WireEvent
        switch (event.kind) {
          case 'ready':
            break
          case 'joined':
          case 'left':
            sink.presence({ kind: event.kind, nick: event.nick })
            await pushRoster()
            break
          case 'quiet':
          case 'returned':
            sink.event?.({ kind: event.kind, nick: event.nick })
            await pushRoster()
            break
          case 'fork':
            sink.event?.({ kind: 'fork', nick: event.nick, pubkey: event.pubkey, seq: event.seq })
            break
          case 'state_changed':
            sink.state(JSON.stringify(event.document))
            break
          case 'info':
            sink.event?.({ kind: 'info', message: event.text })
            break
          case 'error':
            sink.failed(event.text)
            break
          default: {
            const unhandled: never = event
            void unhandled
          }
        }
      }
    }

    void msgs()
    void events()
    const poll = setInterval(() => {
      if (!closed) {
        void pushRoster()
      }
    }, ROSTER_POLL_MS)

    const [rosterJson, stateJson] = await Promise.all([peer.peersJson(), peer.stateJson()])
    return {
      backend: {
        id: peer.id(),
        name: peer.name(),
        nick: peer.nick(),
        maxMsg: peer.maxMsg(),
        send: (to, text) => peer.send(to ?? undefined, text),
        stateMerge: (patchJson) => peer.stateMerge(patchJson),
        close: async () => {
          closed = true
          clearInterval(poll)
          await peer.close()
        },
      },
      rosterJson,
      stateJson,
      // The engine surfaces presence itself, join-horizon-gated and
      // exactly-once; a roster diff would announce backlog peers it
      // suppresses on purpose.
      pushesPresence: true,
    }
  }
}

export type { MeshPeerHandle }
