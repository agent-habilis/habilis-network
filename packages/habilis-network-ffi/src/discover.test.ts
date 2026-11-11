import { describe, expect, test } from 'bun:test'
import { join, resolve, sep } from 'node:path'

import { discover, libraryName, libraryPath } from './discover.ts'

/** A filesystem that has exactly these paths. */
function only(...paths: string[]): (path: string) => boolean {
  const present = new Set(paths)
  return (path) => present.has(path)
}

/**
 * The path `discover` tries for `root` and `profile`, spelled as the OS spells it.
 * It uses the same `resolve` and `join` as `discover`: on Windows `resolve('/repo')` is
 * `C:\repo` and `join` uses `\`, so a literal POSIX string would never match.
 */
function candidate(root: string, profile: string): string {
  return join(resolve(root), 'target', profile, 'libhabilis_network_ffi.dylib')
}

describe('libraryName', () => {
  test('matches what cargo emits per platform', () => {
    expect(libraryName('darwin')).toBe('libhabilis_network_ffi.dylib')
    expect(libraryName('linux')).toBe('libhabilis_network_ffi.so')
    // Cargo drops the `lib` prefix here, and only here.
    expect(libraryName('win32')).toBe('habilis_network_ffi.dll')
  })
})

describe('discover', () => {
  test('finds a release build next to the walk', () => {
    const found = candidate('/repo', 'release')

    expect(
      discover({
        from: ['/repo/packages/habilis-network-ffi/src'],
        name: 'libhabilis_network_ffi.dylib',
        exists: only(found),
      }).path,
    ).toBe(found)
  })

  test('prefers release over a debug build sitting beside it', () => {
    expect(
      discover({
        from: ['/repo/packages/habilis-network-ffi/src'],
        name: 'libhabilis_network_ffi.dylib',
        exists: only(candidate('/repo', 'debug'), candidate('/repo', 'release')),
      }).path,
    ).toBe(candidate('/repo', 'release'))
  })

  test('takes a debug build when that is all there is', () => {
    expect(
      discover({
        from: ['/repo/packages/habilis-network-ffi/src'],
        name: 'libhabilis_network_ffi.dylib',
        exists: only(candidate('/repo', 'debug')),
      }).path,
    ).toBe(candidate('/repo', 'debug'))
  })

  test('walks up rather than looking only beside itself', () => {
    const { searched } = discover({
      from: ['/repo/packages/habilis-network-ffi/src'],
      name: 'libhabilis_network_ffi.dylib',
      exists: () => false,
    })

    expect(searched).toContain(candidate('/repo/packages/habilis-network-ffi/src', 'release'))
    expect(searched).toContain(candidate('/repo', 'release'))
    expect(searched).toContain(candidate('/', 'release'))
  })

  test('reports nothing found rather than guessing', () => {
    expect(
      discover({ from: ['/repo'], name: 'libhabilis_network_ffi.dylib', exists: () => false }).path,
    ).toBeNull()
  })

  test('does not search the same path twice when the roots overlap', () => {
    const { searched } = discover({
      from: ['/repo/a', '/repo/a'],
      name: 'libhabilis_network_ffi.dylib',
      exists: () => false,
    })

    expect(new Set(searched).size).toBe(searched.length)
  })
})

describe('libraryPath', () => {
  test('says how to build it, and where it looked', () => {
    let message = ''
    try {
      libraryPath({ from: ['/repo'], name: 'libhabilis_network_ffi.dylib', exists: () => false })
    } catch (error) {
      message = (error as Error).message
    }

    expect(message).toContain('cargo build --release -p habilis-network-ffi')
    expect(message).toContain('HABILIS_NETWORK_LIB=')
    expect(message).toContain(join(resolve('/repo'), 'target', 'release') + sep)
  })
})
