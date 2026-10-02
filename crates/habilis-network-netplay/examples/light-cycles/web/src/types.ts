/**
 * The JSON shapes `light-cycles-web`'s wasm crate hands across the
 * wasm/JS boundary (`wasm/src/lib.rs`'s `FrameDto`/`HudDto`/`GameEvent`) —
 * hand-transcribed here since there is no shared schema between Rust and
 * TypeScript. Field names and casing must match `#[derive(Serialize)]`'s
 * output exactly (`serde`'s default: struct fields verbatim, enum variant
 * names bare unless a `#[serde(...)]` attribute says otherwise — see each
 * type's Rust counterpart for the attribute that applies).
 */

export interface CycleDto {
  x: number
  y: number
  alive: boolean
}

export type OutcomeDto =
  | { type: 'in_progress' }
  | { type: 'winner'; index: number }
  | { type: 'draw' }

export interface FrameDto {
  grid_w: number
  grid_h: number
  /** Row-major, `grid_w * grid_h`. `0` = empty, else roster index + 1. */
  grid: number[]
  cycles: CycleDto[]
}

export interface RosterEntryDto {
  pubkey: string
  nick: string
  alive: boolean
  me: boolean
}

export interface HudDto {
  /** Which match this is, counting from 1; `0` before the first. */
  match_number: number
  /** Peers in the lobby, us included. */
  present: number
  /** No match in progress — waiting for someone to play against. */
  waiting: boolean
  /** A peer's state checksum disagreed with ours. Should never happen. */
  desynced: boolean
  /** Why the lobby cannot start a match, when waiting will not fix it. */
  blocked: string | null
  /** The session is up but still aligning frame numbers with its peers. */
  syncing: boolean
  outcome: OutcomeDto
  roster: RosterEntryDto[]
}

export type GameEvent =
  | { kind: 'joined'; pubkey: string; nick: string }
  | { kind: 'left'; pubkey: string; nick: string }
