/**
 * The palette — the same hues `agent-share/web/vendor/moonspace-theme`'s
 * `superstylin` theme uses (`themes/superstylin.ts`), transcribed rather
 * than pulled in through the full token/theme package: this example
 * doesn't vendor `moonspace-theme` (see `vendor/README.md` on why), so
 * this is the smallest way to still reuse the palette agent-share uses.
 *
 * This client is dark-only, so what is transcribed is `superstylinDark` —
 * its colour roles and its `hueDark` ramp, with no light variant to switch
 * to. An arena has to be a dark field or the light trails don't read as
 * light. `native/game`'s TUI reaches for named ANSI colors instead: a
 * terminal already has a user-chosen palette to respect, where a canvas
 * has nothing to defer to.
 */

/**
 * `superstylinDark`'s colour roles, under their own names.
 *
 * Kept in step with `style.css`'s `:root` block by hand — the DOM half
 * reads those custom properties, the canvas half reads these, and a canvas
 * has no cascade to inherit from. Change one, change the other.
 */
export const THEME = {
  /** The page. */
  bg: '#272727',
  /** One step below `bg`, for a surface that has to recede. */
  bgSunken: '#1e1d1e',
  bgRaised: '#343334',
  fg: '#ffffff',
  fgMuted: '#a6a5a6',
  fgSubtle: '#777677',
  /** Below every surface — and, here, the arena floor. */
  seam: '#000000',
  borderStrong: '#949394',
  accent: '#5aaafa',
  danger: '#ff7d87',
  warning: '#f5b455',
  /** The arena's neon edge. */
  info: '#5ad0e8',
} as const

/**
 * **The order and length are a cross-play contract**, not a local choice:
 * `native/game/src/ui.rs`'s `PLAYER_PALETTE` maps the same six hues to the
 * same roster indices (as named ANSI colors) and wraps at the same point,
 * so a given player is the same color to everyone regardless of which
 * client they are watching. Change one side and you change the other.
 *
 * These are `superstylin`'s `hueDark` ramp, in that fixed order.
 */
export const PLAYER_COLORS: readonly string[] = [
  '#5aaafa', // blue    — ANSI 4
  '#ff7d87', // red     — ANSI 1
  '#c99cf5', // purple  — ANSI 5 (magenta)
  '#6cd8a0', // green   — ANSI 2
  '#f5b455', // amber   — ANSI 3 (yellow)
  '#5ad0e8', // cyan    — ANSI 6
]

export function colorFor(rosterIndex: number): string {
  return PLAYER_COLORS[rosterIndex % PLAYER_COLORS.length] as string
}

/** How many cells apart the arena's ruled grid sits. 8 divides both 64 and
 * 48, so the field is ruled edge to edge with no partial square. Matches
 * `native/game/src/ui.rs`'s constant of the same name. */
export const GRID_STEP = 8
