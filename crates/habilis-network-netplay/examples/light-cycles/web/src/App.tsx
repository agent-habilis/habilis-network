import { component, signal } from 'visage-dom'

import { Game } from './Game.tsx'
import { Lobby } from './Lobby.tsx'
import { loadWasm } from './wasm.ts'
import type { LightCyclesPeer } from '../wasm/dist/light_cycles_web.js'

export const App = component(function* () {
  const peer = signal<LightCyclesPeer | null>(null)
  const error = signal<string | null>(null)

  async function join(room: string, nick: string): Promise<void> {
    error.value = null
    try {
      const { LightCyclesPeer: PeerCtor } = await loadWasm()
      // Relay as lookup only: every input goes peer to peer.
      peer.value = await PeerCtor.join(room, nick, false)
    } catch (cause) {
      error.value = String(cause)
    }
  }

  yield () => (peer.value ? <Game peer={peer.value} /> : <Lobby onJoin={(room, nick) => void join(room, nick)} error={error.value} />)
})
