import { describe, expect, test } from 'bun:test'

import { SCRATCH_BYTES, readDocument } from './query.ts'

function refuse(name: string): never {
  throw new Error(`${name} failed`)
}

/**
 * `copy_out` from `crates/habilis-network-ffi/src/ffi.rs`, modelled exactly — including
 * the part that catches people out: the write happens only when
 * `needed < cap`, strictly, so `cap === needed` writes nothing and still
 * returns `needed`.
 */
function copyOut(document: string): {
  call: (buffer: Uint8Array, cap: bigint) => bigint
  attempts: number[]
} {
  const encoded = new TextEncoder().encode(document)
  const attempts: number[] = []
  return {
    attempts,
    call: (buffer, cap) => {
      attempts.push(Number(cap))
      const needed = encoded.byteLength
      if (needed < Number(cap)) {
        buffer.set(encoded)
        buffer[needed] = 0
      }
      return BigInt(needed)
    },
  }
}

describe('readDocument', () => {
  test('reads a document that fits the scratch buffer in one call', () => {
    const { call, attempts } = copyOut('{"a":1}')

    expect(readDocument('habilis_network_state_json', call, refuse)).toBe('{"a":1}')
    expect(attempts).toEqual([SCRATCH_BYTES])
  })

  test('grows once for a document larger than the scratch buffer', () => {
    const document = JSON.stringify({ blob: 'x'.repeat(SCRATCH_BYTES) })
    const { call, attempts } = copyOut(document)

    expect(readDocument('habilis_network_peers_json', call, refuse)).toBe(document)
    expect(attempts).toEqual([SCRATCH_BYTES, document.length + 1])
  })

  /**
   * The off-by-one this whole helper exists for. A document exactly as long as
   * the buffer writes nothing and returns its length, which a caller comparing
   * `returned <= cap` reads as success — and then decodes whatever the buffer
   * held before.
   */
  test('retries when the document is exactly the buffer length', () => {
    const document = 'x'.repeat(SCRATCH_BYTES)
    const { call, attempts } = copyOut(document)

    expect(readDocument('habilis_network_state_json', call, refuse)).toBe(document)
    expect(attempts).toEqual([SCRATCH_BYTES, SCRATCH_BYTES + 1])
  })

  test('an empty document is read, not mistaken for a failure', () => {
    const { call } = copyOut('')

    expect(readDocument('habilis_network_state_json', call, refuse)).toBe('')
  })

  test('a negative return raises the thread-local error', () => {
    expect(() => readDocument('habilis_network_peers_json', () => -1n, refuse)).toThrow(
      'habilis_network_peers_json failed',
    )
  })

  test('a document that keeps growing gives up instead of looping forever', () => {
    let size = SCRATCH_BYTES
    const call = (_buffer: Uint8Array, cap: bigint) => {
      size = Number(cap) + 1
      return BigInt(size)
    }

    expect(() => readDocument('habilis_network_state_json', call, refuse)).toThrow(/kept outgrowing/)
  })

  test('decodes multi-byte UTF-8 rather than cutting it', () => {
    const document = JSON.stringify({ nick: 'ana-café', note: '日本語' })
    const { call } = copyOut(document)

    expect(readDocument('habilis_network_state_json', call, refuse)).toBe(document)
  })
})
