import { describe, expect, test } from 'bun:test'

import { parseRoster, rosterPresence } from './roster.ts'

/** The key of a nickname in a fixture: 64 lowercase hex digits, the same on every roster. */
function keyFor(nick: string): string {
  return Buffer.from(nick).toString('hex').padEnd(64, '0')
}

/** A roster document exactly as `habilis_network_peers_json` writes one, for the given rows. */
function rosterOf(...rows: { nickname: string; key: string }[]): string {
  return JSON.stringify({
    peers: rows.map(({ nickname, key }) => ({
      nickname,
      key,
      last_seen_secs_ago: 3,
      quiet: false,
      reach: 'direct',
      transport: 'unicast',
    })),
    count: rows.length + 1,
  })
}

/** A roster whose peers have the given nicknames, one key for each nickname. */
function roster(...peers: string[]): string {
  return rosterOf(...peers.map((nickname) => ({ nickname, key: keyFor(nickname) })))
}

describe('parseRoster', () => {
  test('maps the serde field names onto the public ones', () => {
    const [peer] = parseRoster(roster('ana'))
    expect(peer).toEqual({
      nick: 'ana',
      key: keyFor('ana'),
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
          key: keyFor('ana'),
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
      { kind: 'left', nick: 'ana', key: keyFor('ana') },
      { kind: 'joined', nick: 'cy', key: keyFor('cy') },
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
      { kind: 'left', nick: 'ana', key: keyFor('ana') },
      { kind: 'left', nick: 'zoe', key: keyFor('zoe') },
      { kind: 'joined', nick: 'bo', key: keyFor('bo') },
      { kind: 'joined', nick: 'rex', key: keyFor('rex') },
    ])
  })

  test('two keys of one nickname are two arrivals, and one of them leaving is one departure', () => {
    const first = { nickname: 'twin', key: keyFor('twin') }
    const second = { nickname: 'twin', key: 'cd'.repeat(32) }
    const alone = parseRoster(rosterOf(first))
    const both = parseRoster(rosterOf(first, second))

    expect(rosterPresence(alone, both)).toEqual([
      { kind: 'joined', nick: 'twin', key: second.key },
    ])
    expect(rosterPresence(both, alone)).toEqual([
      { kind: 'left', nick: 'twin', key: second.key },
    ])
  })

  test('a key that changes its nickname is neither a departure nor an arrival', () => {
    const key = keyFor('ana')
    const before = parseRoster(rosterOf({ nickname: 'ana', key }))
    const after = parseRoster(rosterOf({ nickname: 'ana-2', key }))

    expect(rosterPresence(before, after)).toEqual([])
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
