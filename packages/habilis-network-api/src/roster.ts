/**
 * The roster document, and the join/leave events a backend that cannot be told
 * about them has to derive.
 */

import type { Lane, MeshEvent, Peer, Reach } from './types.ts'

/**
 * `habilis_network::embed::RosterSnapshot`, as serde writes it: struct fields verbatim,
 * snake_case, enum variants lowercase.
 *
 * `count` is deliberately absent. It exists in the document and includes self,
 * where `habilis_network_peer_count` excludes self — reading either alongside
 * `peers.length` would be two sources of truth that disagree by one.
 */
interface RawEntry {
  nickname: string
  last_seen_secs_ago: number | null
  quiet: boolean
  reach: Reach
  transport: Lane
}

/**
 * Parse a roster document into the public shape.
 *
 * Frozen, array and entries both: the result is a cache handed to every caller
 * of `mesh.peers`, and one caller sorting it in place would corrupt it for the
 * rest.
 *
 * @throws if `json` is not a roster document.
 */
export function parseRoster(json: string): Peer[] {
  const parsed: unknown = JSON.parse(json)
  const peers = (parsed as { peers?: unknown }).peers
  if (!Array.isArray(peers)) {
    throw new TypeError('a roster document must have a `peers` array')
  }
  return Object.freeze(
    (peers as RawEntry[]).map((entry) =>
      Object.freeze({
        nick: entry.nickname,
        reach: entry.reach,
        transport: entry.transport,
        quiet: entry.quiet,
        // Omitted rather than set to `undefined`: `exactOptionalPropertyTypes`
        // draws a distinction between "absent" and "present and undefined", and
        // the engine's `None` means the peer's first heartbeat is not yet timed.
        ...(entry.last_seen_secs_ago === null
          ? {}
          : { lastSeenSecsAgo: entry.last_seen_secs_ago }),
      }),
    ),
  ) as Peer[]
}

/**
 * The arrivals and departures between two rosters.
 *
 * Sorted, so two peers watching the same mesh print the same transcript in the
 * same order. Leaves before joins, because a nickname that was released and
 * retaken in one interval reads as a departure followed by an arrival, not the
 * reverse.
 */
export function rosterPresence(before: readonly Peer[], after: readonly Peer[]): MeshEvent[] {
  const had = new Set(before.map((peer) => peer.nick))
  const has = new Set(after.map((peer) => peer.nick))
  const left = [...had].filter((nick) => !has.has(nick)).sort()
  const joined = [...has].filter((nick) => !had.has(nick)).sort()
  return [
    ...left.map((nick): MeshEvent => ({ kind: 'left', nick })),
    ...joined.map((nick): MeshEvent => ({ kind: 'joined', nick })),
  ]
}
