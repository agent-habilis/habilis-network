/**
 * The readouts above the arena, arranged the way the cabinet did it: the
 * players flanking the screen in their own colours, the match state
 * between them.
 *
 * With two players that puts one at each edge, which is the shape the
 * original had; with more it spreads them evenly rather than inventing a
 * second layout.
 *
 * The roster here is the *match* roster, so it is empty until a match
 * starts. That is why the latest lobby event is shown alongside it rather
 * than dropped with the rest of the scrolling log the arcade layout has no
 * room for: while waiting, it is the only thing that names who has turned
 * up.
 */
import { component, type Signal } from 'visage-dom'

import { colorFor } from './colors.ts'
import type { GameEvent, HudDto } from './types.ts'

/// Formats the outcome the wasm side already decided. Deliberately not
/// re-derived from `roster` here: `sim::outcome` is the game's central
/// rule, and the TypeScript copy that used to live here had already
/// drifted from it (it never reported the tick-cap draw).
function outcomeLabel(hud: HudDto | null): string {
  if (!hud) return ''
  if (hud.desynced) return 'desynced'
  // Ahead of the waiting states on purpose: a lobby that *cannot* start
  // must not keep reporting that it is about to.
  if (hud.blocked) return hud.blocked
  if (hud.waiting) return hud.present > 1 ? `${hud.present} players ready` : 'waiting'
  if (hud.syncing) return 'syncing'
  switch (hud.outcome.type) {
    case 'in_progress':
      return ''
    case 'draw':
      return 'draw'
    case 'winner':
      return `${hud.roster[hud.outcome.index]?.nick ?? '?'} wins`
  }
}

export const Hud = component<{ hud: Signal<HudDto | null>; events: Signal<GameEvent[]> }>(function* (props) {
  yield () => {
    const hud = props.hud.value
    const roster = hud?.roster ?? []
    const latest = props.events.value.at(-1)

    return (
      <header class="hud">
        <ul class="players">
          {roster.map((entry, index) => (
            <li
              key={entry.pubkey}
              class="player"
              attrs={{ 'data-alive': String(entry.alive) }}
              style={{ color: colorFor(index) }}
            >
              <span class="player__name">{entry.nick}</span>
              {entry.me && <span class="player__you">you</span>}
            </li>
          ))}
          {roster.length === 0 && latest && (
            <li class="player player--lobby">
              <span class="player__name">{latest.nick}</span>
              <span class="player__you">{latest.kind}</span>
            </li>
          )}
        </ul>
        <p class="status" attrs={{ 'data-desync': String((hud?.desynced ?? false) || hud?.blocked != null) }}>
          {outcomeLabel(hud)}
        </p>
      </header>
    )
  }
})
