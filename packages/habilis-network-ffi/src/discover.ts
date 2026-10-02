/**
 * Finding `libhabilis_network_ffi` without being told where it is.
 */

import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * The cargo artifact name for this platform. Windows drops the `lib` prefix,
 * which is the kind of thing you discover from a support thread rather than
 * from a build log.
 */
export function libraryName(platform: string = process.platform): string {
  if (platform === 'win32') {
    return 'habilis_network_ffi.dll'
  }
  return platform === 'darwin' ? 'libhabilis_network_ffi.dylib' : 'libhabilis_network_ffi.so'
}

/**
 * Read an environment variable across three runtimes.
 *
 * Deno reaches it through `Deno.env`, and a process run without `--allow-env`
 * throws rather than returning undefined. A denied permission means "not set"
 * here — an override nobody asked for should not be able to crash the load.
 */
export function readEnv(name: string): string | undefined {
  const fromProcess = globalThis.process?.env?.[name]
  if (fromProcess !== undefined) {
    return fromProcess
  }
  const deno = (globalThis as { Deno?: { env?: { get(key: string): string | undefined } } }).Deno
  try {
    return deno?.env?.get(name)
  } catch {
    return undefined
  }
}

/** Every directory from `start` up to the filesystem root. */
function ancestors(start: string): string[] {
  const walked: string[] = []
  let current = resolve(start)
  for (;;) {
    walked.push(current)
    const parent = dirname(current)
    if (parent === current) {
      return walked
    }
    current = parent
  }
}

export interface Discovery {
  readonly path: string | null
  /** Every path tried, in order, for the error message. */
  readonly searched: string[]
}

/**
 * Where the built library is.
 *
 * `HABILIS_NETWORK_LIB` wins outright. Otherwise walk up from this module and from the
 * working directory, looking under `target/`. Release before debug at each
 * level, so a stale debug build left over from an afternoon of `cargo test`
 * never silently wins over the release build CI and the README both name.
 */
export function discover(
  options: { from?: string[]; name?: string; exists?: (path: string) => boolean } = {},
): Discovery {
  const override = readEnv('HABILIS_NETWORK_LIB')
  if (override !== undefined && override !== '') {
    return { path: override, searched: [override] }
  }

  const exists = options.exists ?? existsSync
  const name = options.name ?? libraryName()
  const roots =
    options.from ?? [dirname(fileURLToPath(import.meta.url)), globalThis.process?.cwd?.() ?? '.']

  const searched: string[] = []
  const seen = new Set<string>()
  for (const root of roots) {
    for (const directory of ancestors(root)) {
      for (const profile of ['release', 'debug']) {
        const candidate = join(directory, 'target', profile, name)
        if (seen.has(candidate)) {
          continue
        }
        seen.add(candidate)
        searched.push(candidate)
        if (exists(candidate)) {
          return { path: candidate, searched }
        }
      }
    }
  }
  return { path: null, searched }
}

/**
 * The library path, or an error that says what to do about it.
 *
 * @throws naming every directory tried and the exact command that builds it.
 * A "cannot find the library" message that does not include the build command
 * costs the reader a trip to the README.
 */
export function libraryPath(options?: Parameters<typeof discover>[0]): string {
  const { path, searched } = discover(options)
  if (path !== null) {
    return path
  }
  throw new Error(
    [
      `${libraryName()} not found.`,
      '',
      '  build it:  cargo build --release -p habilis-network-ffi',
      '  or set:    HABILIS_NETWORK_LIB=/path/to/' + libraryName(),
      '',
      '  looked in:',
      ...searched.map((candidate) => `    ${candidate}`),
    ].join('\n'),
  )
}
