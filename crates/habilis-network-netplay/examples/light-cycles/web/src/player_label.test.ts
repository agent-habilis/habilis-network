import { expect, test } from 'bun:test'

import { playerLabel } from './player_label.ts'
import type { RosterEntryDto } from './types.ts'

const entry = (pubkey: string, nick: string): RosterEntryDto => ({ pubkey, nick, alive: true, me: false })

// Two live keys can use one nickname, so a nickname alone does not say which of the two won.
test('a nickname that two players use carries the slot of the player', () => {
  const roster = [entry('k1', 'bob'), entry('k2', 'bob'), entry('k3', 'alice')]
  expect(playerLabel(roster, 0)).toBe('bob #1')
  expect(playerLabel(roster, 1)).toBe('bob #2')
})

test('a nickname that one player uses stays alone', () => {
  const roster = [entry('k1', 'bob'), entry('k2', 'bob'), entry('k3', 'alice')]
  expect(playerLabel(roster, 2)).toBe('alice')
})

test('a slot that the roster does not hold is a question mark', () => {
  expect(playerLabel([], 0)).toBe('?')
})
