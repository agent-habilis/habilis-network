import { describe, expect, test } from 'bun:test'
import type { WireOpts } from '../protocol.ts'
import { encodeOpts, encodeStreamOpts, OPTS_BYTES, STREAM_OPTS_BYTES } from './opts-struct.ts'

const BASE: WireOpts = {
  mesh: null,
  topic: null,
  nick: null,
  name: null,
  lookup: null,
  transport: null,
  relayUrls: null,
  disableIp: false,
  disableWebrtc: false,
  maxPeers: 0,
}

/** Hands out a distinct fake address per buffer and remembers which was which. */
function fakePointers() {
  const buffers: Uint8Array[] = []
  return {
    buffers,
    pointerOf: (buffer: Uint8Array): bigint => {
      buffers.push(buffer)
      return 0x1000n + BigInt(buffers.length - 1) * 0x100n
    },
  }
}

describe('encodeOpts', () => {
  // The literal, not OPTS_BYTES against itself. The other side of this number
  // is the layout assert on `FofocaOpts` in crates/fofoca-ffi/src/ffi.rs; a
  // linked C consumer keeps passing the old struct when it moves, so both
  // sides must be edited together.
  test('the struct is the 72 bytes the C header lays out', () => {
    expect(OPTS_BYTES).toBe(72)
  })

  test('null selectors and empty lists encode as NULL pointers', () => {
    const { struct } = encodeOpts(BASE, fakePointers().pointerOf)
    expect(struct.byteLength).toBe(OPTS_BYTES)
    const view = new DataView(struct.buffer)
    for (const offset of [0, 8, 16, 24, 32, 40, 48]) {
      expect(view.getBigUint64(offset, true)).toBe(0n)
    }
  })

  test('string fields land at their offsets, NUL-terminated', () => {
    const pointers = fakePointers()
    const { struct, keepAlive } = encodeOpts(
      { ...BASE, mesh: 'M', topic: 'tea-time', nick: 'ana', name: 'salon' },
      pointers.pointerOf,
    )
    const view = new DataView(struct.buffer)
    // One buffer per string, in field order, each address embedded in order.
    expect(keepAlive.length).toBe(4)
    expect(view.getBigUint64(0, true)).toBe(0x1000n)
    expect(view.getBigUint64(8, true)).toBe(0x1100n)
    expect(view.getBigUint64(16, true)).toBe(0x1200n)
    expect(view.getBigUint64(24, true)).toBe(0x1300n)
    const topic = pointers.buffers[1]
    expect(topic).toBeDefined()
    expect(Array.from(topic ?? [])).toEqual([...new TextEncoder().encode('tea-time'), 0])
  })

  test('path switches and max_peers', () => {
    const { struct } = encodeOpts(
      { ...BASE, disableWebrtc: true, maxPeers: 12 },
      fakePointers().pointerOf,
    )
    const view = new DataView(struct.buffer)
    expect(view.getInt32(56, true)).toBe(0) // disable_ip
    expect(view.getInt32(60, true)).toBe(1) // disable_webrtc
    expect(view.getBigUint64(64, true)).toBe(12n)
  })

  test('the three lists land at their offsets as comma strings', () => {
    const pointers = fakePointers()
    const { struct, keepAlive } = encodeOpts(
      { ...BASE, lookup: 'mdns,relay', transport: 'p2p,relay', relayUrls: 'http://a/,http://b/' },
      pointers.pointerOf,
    )
    const view = new DataView(struct.buffer)
    expect(view.getBigUint64(32, true)).toBe(0x1000n) // lookup
    expect(view.getBigUint64(40, true)).toBe(0x1100n) // transport
    expect(view.getBigUint64(48, true)).toBe(0x1200n) // relay_urls
    expect(keepAlive.length).toBe(3)
    expect(Array.from(pointers.buffers[0] ?? [])).toEqual([...new TextEncoder().encode('mdns,relay'), 0])
    expect(Array.from(pointers.buffers[2] ?? [])).toEqual([
      ...new TextEncoder().encode('http://a/,http://b/'),
      0,
    ])
  })

  test('keepAlive roots every encoded string', () => {
    const { keepAlive } = encodeOpts({ ...BASE, nick: 'ana' }, fakePointers().pointerOf)
    expect(keepAlive.length).toBe(1)
    expect(keepAlive[0]?.at(-1)).toBe(0)
  })
})

describe('encodeStreamOpts', () => {
  // The literal, for the reason the 72 above is one: the other side is the
  // layout assert on `FofocaStreamOpts` in crates/fofoca-ffi/src/ffi.rs.
  test('the struct is the 32 bytes the C header lays out', () => {
    expect(STREAM_OPTS_BYTES).toBe(32)
  })

  test('the lists and the path switches land at their offsets', () => {
    const pointers = fakePointers()
    const { struct, keepAlive } = encodeStreamOpts(
      { lookup: 'relay', transport: null, relayUrls: 'http://a/', disableIp: true, disableWebrtc: false },
      pointers.pointerOf,
    )
    expect(struct.byteLength).toBe(STREAM_OPTS_BYTES)
    const view = new DataView(struct.buffer)
    expect(view.getBigUint64(0, true)).toBe(0x1000n) // lookup
    expect(view.getBigUint64(8, true)).toBe(0n) // transport
    expect(view.getBigUint64(16, true)).toBe(0x1100n) // relay_urls
    expect(view.getInt32(24, true)).toBe(1) // disable_ip
    expect(view.getInt32(28, true)).toBe(0) // disable_webrtc
    expect(keepAlive.length).toBe(2)
    expect(Array.from(pointers.buffers[0] ?? [])).toEqual([...new TextEncoder().encode('relay'), 0])
  })
})
