/**
 * The arena, drawn as characters on the same `1ch` grid as the rest of the
 * UI — not a canvas.
 *
 * This is what keeps the two clients looking alike: `native/game`'s TUI
 * has only characters to draw with, so meeting it there means both render
 * the identical screen from the identical `grid` array, with the same
 * glyphs in the same colours. A canvas could draw a prettier arena, but it
 * could not draw *that* one, and it sat off the text grid besides.
 *
 * One `<span>` per contiguous same-colour run in a row, not one per cell —
 * the same run-length encoding `native/game`'s `ui.rs` (`flush_run`) uses,
 * for the same reason: a trail is usually a long straight line, so a row
 * is a handful of spans rather than 64 of them.
 */
import { component, type Signal } from 'visage-dom'

import { GRID_STEP, colorFor } from './colors.ts'
import type { FrameDto } from './types.ts'

/** A claimed cell. Full block, so trails read as solid light. */
const TRAIL = '█'
/** An empty cell on a ruled intersection — the arena's grid, which the
 * cabinet had and which a terminal can draw as well as a canvas can. */
const RULE = '·'
const EMPTY = ' '

interface Run {
  text: string
  /** `null` for the ruled grid, which is not any player's colour. */
  owner: number | null
}

/** Splits one row into runs of a single colour. */
function rowRuns(frame: FrameDto, y: number): Run[] {
  const runs: Run[] = []
  let current: Run | null = null
  for (let x = 0; x < frame.grid_w; x++) {
    const owner = frame.grid[y * frame.grid_w + x] ?? 0
    const ruled = x % GRID_STEP === 0 && y % GRID_STEP === 0
    const char = owner > 0 ? TRAIL : ruled ? RULE : EMPTY
    const key = owner > 0 ? owner - 1 : null
    if (current === null || current.owner !== key) {
      current = { text: char, owner: key }
      runs.push(current)
    } else {
      current.text += char
    }
  }
  return runs
}

export const Board = component<{ frame: Signal<FrameDto | null> }>(function* (props) {
  yield () => {
    const frame = props.frame.value
    if (!frame) return <pre class="board" />

    const rows = []
    for (let y = 0; y < frame.grid_h; y++) {
      rows.push(
        <div key={y} class="board__row">
          {rowRuns(frame, y).map((run, index) => (
            <span
              key={index}
              class={run.owner === null ? 'board__rule' : 'board__trail'}
              style={run.owner === null ? {} : { color: colorFor(run.owner) }}
            >
              {run.text}
            </span>
          ))}
        </div>,
      )
    }
    return <pre class="board">{rows}</pre>
  }
})
