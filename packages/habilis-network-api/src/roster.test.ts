import { describe, expect, test } from 'bun:test'

import { parseRoster, rosterPresence } from './roster.ts'

/** A roster document exactly as `habilis_network_peers_json` writes one. */
function roster(...peers: string[]): string {
  return JSON.stringify({
    peers: peers.map((nickname) => ({
      nickname,
      last_seen_secs_ago: 3,
      quiet: false,
      reach: 'direct',
      transport: 'unicast',
    })),
    count: peers.length + 1,
  })
}

describe('parseRoster', () => {
  test('maps the serde field names onto the public ones', () => {
    const [peer] = parseRoster(roster('ana'))
    expect(peer).toEqual({
      nick: 'ana',
      reach: 'direct',
      transport: 'unicast',
      quiet: false,
      lastSeenSecsAgo: 3,
    })
  })

  test('a null last_seen omits the property rather than setting it undefined', () => {
    const json = JSON.stringify({
      peers: [
        {
          nickname: 'ana',
          last_seen_secs_ago: null,
          quiet: true,
          reach: 'gossip',
          transport: 'multihop',
        },
      ],
      count: 2,
    })
    const [peer] = parseRoster(json)

    expect(peer).not.toHaveProperty('lastSeenSecsAgo')
    expect(peer?.quiet).toBe(true)
    expect(peer?.reach).toBe('gossip')
    expect(peer?.transport).toBe('multihop')
  })

  test('the result is frozen, so one caller cannot corrupt the cache', () => {
    const peers = parseRoster(roster('ana'))

    expect(Object.isFrozen(peers)).toBe(true)
    expect(Object.isFrozen(peers[0])).toBe(true)
  })

  test('a document with no peers array is an error, not an empty mesh', () => {
    expect(() => parseRoster('{"error":"the loop stopped"}')).toThrow(TypeError)
  })
})

describe('rosterPresence', () => {
  test('reports arrivals and departures', () => {
    const before = parseRoster(roster('ana', 'bo'))
    const after = parseRoster(roster('bo', 'cy'))

    expect(rosterPresence(before, after)).toEqual([
      { kind: 'left', nick: 'ana' },
      { kind: 'joined', nick: 'cy' },
    ])
  })

  test('an unchanged roster reports nothing', () => {
    const peers = parseRoster(roster('ana', 'bo'))

    expect(rosterPresence(peers, peers)).toEqual([])
  })

  test('leaves come before joins, and each group is sorted', () => {
    const before = parseRoster(roster('zoe', 'ana'))
    const after = parseRoster(roster('rex', 'bo'))

    expect(rosterPresence(before, after)).toEqual([
      { kind: 'left', nick: 'ana' },
      { kind: 'left', nick: 'zoe' },
      { kind: 'joined', nick: 'bo' },
      { kind: 'joined', nick: 'rex' },
    ])
  })

  test('a peer going quiet is not a departure', () => {
    const before = parseRoster(roster('ana'))
    const quiet = JSON.parse(roster('ana')) as {
      peers: { quiet: boolean }[]
    }
    quiet.peers[0]!.quiet = true
    const after = parseRoster(JSON.stringify(quiet))

    expect(rosterPresence(before, after)).toEqual([])
  })
})
