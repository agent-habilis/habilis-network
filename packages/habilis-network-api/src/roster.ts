/**
 * The roster document, and the join/leave events a backend that cannot be told
 * about them has to derive.
 */

import type { Lane, MeshEvent, Peer, Reach } from './types.ts'

/**
 * `habilis_network::embed::RosterSnapshot`, as serde writes it: struct fields verbatim,
 * snake_case, enum variants lowercase.
 *
 * `count` is deliberately absent. It exists in the document and includes self, as
 * `habilis_network_mesh_peer_count` does — reading either alongside `peers.length`
 * (the other members, quiet ones too) would be two sources of truth that disagree.
 */
interface RawEntry {
  nickname: string
  /** The author key, 64 lowercase hex digits. */
  key: string
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
        key: entry.key,
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
 * The arrivals and departures between two rosters, by key.
 *
 * A nickname is a label that two live peers can share, so a diff by nickname would give one
 * arrival for two keys. A key that changes its nickname is the same peer and gives no event.
 *
 * Sorted, so two peers watching the same mesh print the same transcript in the same order. Leaves
 * before joins, because a nickname that was released and retaken in one interval reads as a
 * departure followed by an arrival, not the reverse. Two events of one nickname are ordered by key.
 */
export function rosterPresence(before: readonly Peer[], after: readonly Peer[]): MeshEvent[] {
  const had = new Set(before.map((peer) => peer.key))
  const has = new Set(after.map((peer) => peer.key))
  // Code-unit order, as the default sort was: the same transcript on every locale.
  const order = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0)
  const byNickThenKey = (a: Peer, b: Peer) => order(a.nick, b.nick) || order(a.key, b.key)
  const left = before.filter((peer) => !has.has(peer.key)).sort(byNickThenKey)
  const joined = after.filter((peer) => !had.has(peer.key)).sort(byNickThenKey)
  return [
    ...left.map((peer): MeshEvent => ({ kind: 'left', nick: peer.nick, key: peer.key })),
    ...joined.map((peer): MeshEvent => ({ kind: 'joined', nick: peer.nick, key: peer.key })),
  ]
}
