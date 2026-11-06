import { describe, expect, test } from 'bun:test'

import { MSG_BYTES, decodeMsg, encodeMsg } from './msg.ts'

const KEY = 'a'.repeat(64)

describe('decodeMsg', () => {
  test('round-trips both kinds', () => {
    for (const directed of [false, true]) {
      const meta = { nick: 'ana', key: KEY, directed, len: 17 }
      expect(decodeMsg(encodeMsg(meta))).toEqual(meta)
    }
  })

  test('reads a nick at the 63-byte limit `write_nick` truncates to', () => {
    const nick = 'n'.repeat(63)
    expect(decodeMsg(encodeMsg({ nick, key: KEY, directed: false, len: 1 })).nick).toBe(nick)
  })

  test('reads a len past the 32-bit line', () => {
    const len = 2 ** 40
    expect(decodeMsg(encodeMsg({ nick: 'ana', key: KEY, directed: false, len })).len).toBe(len)
  })

  test('stops at the NUL rather than trailing the rest of the field', () => {
    const bytes = encodeMsg({ nick: 'ana', key: KEY, directed: false, len: 3 })
    // Garbage after the terminator, as a reused buffer would hold. The nick starts at 8.
    bytes.set([0x7a, 0x7a], 16)

    expect(decodeMsg(bytes).nick).toBe('ana')
  })

  test('an unterminated nick is an error, not a read into the integers', () => {
    const bytes = encodeMsg({ nick: 'ana', key: KEY, directed: false, len: 3 })
    bytes.fill(0x61, 8, 72)

    expect(() => decodeMsg(bytes)).toThrow(/NUL-terminated/)
  })

  test('a short buffer is an error rather than a garbage message', () => {
    expect(() => decodeMsg(new Uint8Array(MSG_BYTES - 1))).toThrow(RangeError)
  })

  test('decodes at a non-zero byte offset, as a subarray of a scratch buffer is', () => {
    const scratch = new Uint8Array(MSG_BYTES * 2)
    const meta = { nick: 'bo', key: KEY, directed: true, len: 5 }
    scratch.set(encodeMsg(meta), MSG_BYTES)

    expect(decodeMsg(scratch.subarray(MSG_BYTES))).toEqual(meta)
  })

  test('reads the key of the author, 64 digits at offset 72', () => {
    const other = 'f'.repeat(64)

    expect(decodeMsg(encodeMsg({ nick: 'twin', key: other, directed: true, len: 2 })).key).toBe(other)
  })

  test('a key that is not 64 digits and a NUL is an error, not a read into the padding', () => {
    const bytes = encodeMsg({ nick: 'ana', key: KEY, directed: false, len: 3 })
    bytes.fill(0x61, 72, 137)

    expect(() => decodeMsg(bytes)).toThrow(/key is not 64 digits/)
  })

  test('the caller sets the size of the struct, which the engine checks', () => {
    const bytes = encodeMsg({ nick: 'ana', key: KEY, directed: false, len: 3 })

    expect(new DataView(bytes.buffer).getBigUint64(0, true)).toBe(152n)
  })

  test('the struct is 152 bytes, which is what the C layout says', () => {
    expect(MSG_BYTES).toBe(152)
    expect(encodeMsg({ nick: '', key: KEY, directed: false, len: 0 }).byteLength).toBe(152)
  })
})
