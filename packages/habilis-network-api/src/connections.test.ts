import { describe, expect, test } from 'bun:test'

import { checkMaxConnections, DEFAULT_MAX_CONNECTIONS, maxConnectionsWire } from './connections.ts'

describe('max connections on the wire', () => {
  test('an absent cap is the default of 16', () => {
    expect(maxConnectionsWire(undefined)).toBe(DEFAULT_MAX_CONNECTIONS)
    expect(DEFAULT_MAX_CONNECTIONS).toBe(16)
  })

  test('0 and a whole number pass; the engine judges the minimum', () => {
    expect(checkMaxConnections(0)).toBe(0)
    expect(checkMaxConnections(8)).toBe(8)
    expect(maxConnectionsWire(3)).toBe(3)
  })

  test('a negative or fractional or non-finite cap throws with the value', () => {
    for (const bad of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => checkMaxConnections(bad)).toThrow(`max connections is ${bad}`)
    }
  })
})
