/**
 * Create/join screen. "Create" and "join" are the same `onJoin(room, nick)`
 * call — a topic-derived mesh converges regardless of who calls it first,
 * so "create" is just *generate a fresh code, then join it like anyone
 * else would* (see the plan's "Create / join screen" section).
 *
 * The room code round-trips through `location.hash`, mirroring
 * `chat-webrtc`'s ticket-in-fragment pattern: a `hashchange` listener
 * supports pasting a link mid-session, and the code never reaches a server.
 *
 * Room codes and default nicknames come from the wasm module
 * (`random_room_code`/`random_nick`), which draws on the same 1024-word
 * curated list `native/game`'s CLI uses — see their doc comments on why
 * this isn't a small JS word list instead.
 */
import { component, signal } from 'visage-dom'

import { loadWasm } from './wasm.ts'

function roomFromHash(): string {
  return decodeURIComponent(location.hash.slice(1))
}

export const Lobby = component<{ onJoin: (room: string, nick: string) => void; error: string | null }>(
  function* (props) {
    const nick = signal('')
    const room = signal(roomFromHash())
    const validationError = signal<string | null>(null)

    // `main.tsx` starts the wasm load on page load, so this normally
    // resolves well before anyone types. Until it does the field is empty
    // and shows its placeholder.
    void loadWasm().then((wasm) => {
      if (!nick.value) nick.value = wasm.random_nick()
    })

    window.addEventListener(
      'hashchange',
      () => {
        room.value = roomFromHash()
      },
      { signal: this.aborted },
    )

    async function chosenNick(): Promise<string> {
      const typed = nick.value.trim()
      if (typed) return typed
      return (await loadWasm()).random_nick()
    }

    async function create(): Promise<void> {
      const code = (await loadWasm()).random_room_code()
      location.hash = encodeURIComponent(code)
      room.value = code
      props.onJoin(code, await chosenNick())
    }

    async function join(): Promise<void> {
      const code = room.value.trim()
      if (!code) {
        validationError.value = 'enter a room code'
        return
      }
      validationError.value = null
      props.onJoin(code, await chosenNick())
    }

    yield () => (
      <section class="lobby">
        <h1>light-cycles</h1>
        <label>
          <span class="faint">nickname</span>
          <input
            value={nick.value}
            placeholder="picking one…"
            oninput={(event) => {
              nick.value = (event.target as HTMLInputElement).value
            }}
          />
        </label>
        <form
          onsubmit={(event: SubmitEvent) => {
            event.preventDefault()
            void join()
          }}
        >
          <label>
            <span class="faint">room code</span>
            <input
              value={room.value}
              placeholder="paste a room code"
              oninput={(event) => {
                room.value = (event.target as HTMLInputElement).value
              }}
            />
          </label>
          <button type="submit">join game</button>
        </form>
        <button onclick={() => void create()}>create game</button>
        {(validationError.value ?? props.error) && <p class="error">{validationError.value ?? props.error}</p>}
      </section>
    )
  },
)
