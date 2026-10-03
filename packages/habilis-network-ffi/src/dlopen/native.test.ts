import { describe, expect, test } from 'bun:test'

import { ABI_VERSION } from '../abi.ts'
import { AbiMismatchError, checkAbiVersion, loadNative } from './native.ts'

describe('checkAbiVersion', () => {
  test('accepts the version this package speaks', () => {
    expect(() => checkAbiVersion('lib.so', ABI_VERSION)).not.toThrow()
  })

  test('refuses another version and names both', () => {
    const other = ABI_VERSION + 1
    expect(() => checkAbiVersion('/opt/lib.so', other)).toThrow(AbiMismatchError)
    expect(() => checkAbiVersion('/opt/lib.so', other)).toThrow(
      `/opt/lib.so speaks ABI version ${other}, and this package speaks ABI version ${ABI_VERSION}`,
    )
  })

  test('refuses an older library too', () => {
    expect(() => checkAbiVersion('lib.so', 0, 2)).toThrow('speaks ABI version 0, and this package speaks ABI version 2')
  })

  test('refuses a library with no version symbol, and says it is older', () => {
    const missing = new Error('Symbol "habilis_network_abi_version" not found')
    expect(() => checkAbiVersion('/opt/old.so', missing)).toThrow(AbiMismatchError)
    expect(() => checkAbiVersion('/opt/old.so', missing)).toThrow('does not answer habilis_network_abi_version()')
    // The way out and the loader's own reason both reach the reader.
    expect(() => checkAbiVersion('/opt/old.so', missing)).toThrow('cargo build --release -p habilis-network-ffi')
    expect(() => checkAbiVersion('/opt/old.so', missing)).toThrow('not found')
  })
})

/** A real shared library that exports no habilis-network symbol at all. */
const FOREIGN = process.platform === 'darwin' ? '/usr/lib/libSystem.B.dylib' : process.platform === 'linux' ? 'libc.so.6' : null

describe.skipIf(FOREIGN === null)('loadNative on a library without the version symbol', () => {
  test('throws the clear error before binding anything else', async () => {
    const error = await loadNative(FOREIGN as string).then(
      () => null,
      (caught: unknown) => caught,
    )

    expect(error).toBeInstanceOf(AbiMismatchError)
    expect((error as Error).message).toContain('habilis_network_abi_version')
    expect((error as Error).message).toContain(`ABI version ${ABI_VERSION}`)
  })
})
