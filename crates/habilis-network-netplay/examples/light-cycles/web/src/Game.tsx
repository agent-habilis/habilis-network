/**
 * The joined-game view, laid out like the arcade cabinet it is imitating:
 * a full-bleed dark screen, the players' readouts flanking the top, and
 * the arena filling everything left over.
 *
 * Drives the `LightCyclesPeer` from a plain interval, and turns keyboard
 * input into `peer.turn(dir)` calls.
 *
 * An interval, deliberately, and not `requestAnimationFrame`: a browser
 * suspends rAF outright in a tab that is not visible, and this loop is not
 * only rendering — it is the whole peer. It announces presence, drains the
 * lobby, and advances the simulation. On rAF, a backgrounded tab stops
 * being a player at all: it never announces itself, so nobody in the room
 * ever sees it, and two tabs in one window can never find each other
 * because only one of them is ever running. A timer is throttled in the
 * background rather than stopped, so the peer stays in the room, and
 * `frame()` caps how much it will replay on the way back (see
 * `wasm/src/lib.rs`).
 *
 * There is nothing to gain from rAF here either: the simulation moves at
 * `TICK_MS`, so the board has nothing new to show between ticks.
 */
import { component, signal } from 'visage-dom'

import { Board } from './Board.tsx'
import { Hud } from './Hud.tsx'
import type { FrameDto, GameEvent, HudDto } from './types.ts'
import type { LightCyclesPeer } from '../wasm/dist/light_cycles_web.js'

/** Mirrors `wasm/src/grid.rs`'s `TICK_MS` — one tick is one frame of the
 * rollback session, and the arena only changes this often. */
const TICK_MS = 50

const KEY_TO_DIR: Record<string, string | undefined> = {
  ArrowUp: 'up',
  ArrowDown: 'down',
  ArrowLeft: 'left',
  ArrowRight: 'right',
  w: 'up',
  s: 'down',
  a: 'left',
  d: 'right',
  W: 'up',
  S: 'down',
  A: 'left',
  D: 'right',
}

export const Game = component<{ peer: LightCyclesPeer }>(function* (props) {
  const hud = signal<HudDto | null>(null)
  const events = signal<GameEvent[]>([])
  const frame = signal<FrameDto | null>(null)
  /** Last payloads as raw JSON — see the compares in the loop below. */
  let lastFrameJson = ''
  let lastHudJson = ''
  /** So a persistent fault logs once instead of sixty times a second. */
  let loggedError = false

  const loop = setInterval(() => {
    try {
      // Both compared as strings before parsing: a fresh object from
      // `JSON.parse` never equals the previous one, so assigning either
      // unconditionally would re-render its subtree every tick for content
      // that mostly has not changed — the HUD moves about once a match.
      const frameJson = props.peer.frame()
      if (frameJson !== lastFrameJson) {
        lastFrameJson = frameJson
        frame.value = JSON.parse(frameJson) as FrameDto
      }

      const hudJson = props.peer.hud()
      if (hudJson !== lastHudJson) {
        lastHudJson = hudJson
        hud.value = JSON.parse(hudJson) as HudDto
      }

      const drained = JSON.parse(props.peer.drain_events()) as GameEvent[]
      if (drained.length > 0) events.value = [...events.value, ...drained]
    } catch (error) {
      if (!loggedError) {
        loggedError = true
        console.error('light-cycles frame error (further errors suppressed):', error)
      }
    }
  }, TICK_MS)
  this.aborted.addEventListener('abort', () => {
    clearInterval(loop)
  })

  window.addEventListener(
    'keydown',
    (event) => {
      const dir = KEY_TO_DIR[event.key]
      if (!dir) return
      event.preventDefault()
      try {
        props.peer.turn(dir)
      } catch (error) {
        console.error('light-cycles turn error:', error)
      }
    },
    { signal: this.aborted },
  )

  yield () => (
    <section class="game">
      <Hud hud={hud} events={events} />
      <div class="arena">
        <Board frame={frame} />
        {hud.value?.waiting === true && (
          <div class="attract">
            <p class="attract__headline">
              {hud.value?.blocked != null
                ? 'cannot start'
                : (hud.value?.present ?? 1) > 1
                  ? 'get ready'
                  : 'waiting for a player'}
            </p>
            {hud.value?.blocked == null && (
              <p class="attract__hint">send this link to whoever is playing</p>
            )}
            {/* The whole URL, not just the code: the room round-trips
                through `location.hash` (see `Lobby.tsx`), so this link is
                all the other player needs — and it is the one thing on
                this screen worth selecting, hence the `pointer-events`
                exception in the stylesheet. */}
            <p class="attract__link">{location.href}</p>
          </div>
        )}
      </div>
      <footer class="controls">
        <p class="keys">
          <kbd>↑</kbd>
          <kbd>↓</kbd>
          <kbd>←</kbd>
          <kbd>→</kbd>
          <span class="faint">or</span>
          <kbd>wasd</kbd>
        </p>
        <p class="match">
          <span class="faint">match </span>
          {hud.value?.match_number ?? 0}
        </p>
        <p class="room">
          <span class="faint">room </span>
          {decodeURIComponent(location.hash.slice(1)) || '—'}
        </p>
      </footer>
    </section>
  )
})
