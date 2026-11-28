/**
 * The cap on the direct connections of a node when the caller gives none. It equals
 * `tuning::MAX_CONNECTIONS` of the engine: the C ABI takes a number, so the wire carries it.
 */
export const DEFAULT_MAX_CONNECTIONS = 16

/**
 * Refuse a cap that is not a whole number of 0 or more. The wire has an unsigned 64-bit
 * field, so `-1` would wrap to 2^64-1. A cap under the engine minimum is the engine's error.
 */
export function checkMaxConnections(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`max connections is ${value}: it must be a whole number of 0 or more`)
  }
  return value
}

/** The cap for the wire: the default when the caller gives none, else the checked value. */
export function maxConnectionsWire(value: number | undefined): number {
  return value === undefined ? DEFAULT_MAX_CONNECTIONS : checkMaxConnections(value)
}
