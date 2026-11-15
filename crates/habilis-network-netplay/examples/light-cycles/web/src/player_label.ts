import type { RosterEntryDto } from './types.ts'

/**
 * The name of the player at `slot`, or `?` for a slot that the roster does not hold.
 *
 * A nickname is a label that two live keys can share, so a nickname that the roster holds twice
 * carries the slot too. The roster is sorted, so the slot is the same on every peer, and it is
 * the slot that picks the colour. `native/game`'s `player_label` follows the same rule.
 */
export function playerLabel(roster: readonly RosterEntryDto[], slot: number): string {
  const entry = roster[slot]
  if (!entry) return '?'
  const users = roster.filter((other) => other.nick === entry.nick).length
  return users > 1 ? `${entry.nick} #${slot + 1}` : entry.nick
}
