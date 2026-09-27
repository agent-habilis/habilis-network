/**
 * `fofoca_opts`, encoded by hand for the loaders whose FFI cannot marshal a
 * struct (`bun:ffi` and Deno's). koffi marshals a plain object itself and
 * never touches this file.
 *
 * ```c
 * typedef struct {
 *   const char *mesh;        // offset  0
 *   const char *topic;       // offset  8
 *   const char *nick;        // offset 16
 *   const char *name;        // offset 24
 *   const char *lookup;      // offset 32
 *   const char *transport;   // offset 40
 *   const char *relay_urls;  // offset 48
 *   int disable_ip;          // offset 56
 *   int disable_webrtc;      // offset 60
 *   size_t max_peers;        // offset 64
 * } fofoca_opts;             // 72 bytes
 * ```
 *
 * 64-bit little-endian only, the same scope `msg.ts` claims for the same
 * reason.
 */

import type { WireOpts } from '../protocol.ts'

const MESH_OFFSET = 0
const TOPIC_OFFSET = 8
const NICK_OFFSET = 16
const NAME_OFFSET = 24
const LOOKUP_OFFSET = 32
const TRANSPORT_OFFSET = 40
const RELAY_URLS_OFFSET = 48
const DISABLE_IP_OFFSET = 56
const DISABLE_WEBRTC_OFFSET = 60
const MAX_PEERS_OFFSET = 64

export const OPTS_BYTES = 72

const LITTLE_ENDIAN = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1

const encoder = new TextEncoder()

export interface EncodedOpts {
  /** The struct itself, to pass as the `fofoca_mesh_open` argument. */
  readonly struct: Uint8Array
  /**
   * The NUL-terminated string buffers whose addresses the struct embeds.
   *
   * The caller MUST keep a reference to this array until `fofoca_mesh_open`
   * returns: nothing else roots these buffers, and a GC between encode and
   * call would leave the struct pointing at freed memory.
   */
  readonly keepAlive: readonly Uint8Array[]
}

function terminated(value: string): Uint8Array {
  const text = encoder.encode(value)
  const bytes = new Uint8Array(text.byteLength + 1)
  bytes.set(text, 0)
  return bytes
}

/** Writes a string's address at an offset (NULL for `null`), rooting its buffer. */
function stringField(
  view: DataView,
  keepAlive: Uint8Array[],
  pointerOf: (buffer: Uint8Array) => bigint,
): (offset: number, value: string | null) => void {
  return (offset, value) => {
    if (value === null) {
      view.setBigUint64(offset, 0n, LITTLE_ENDIAN)
      return
    }
    const bytes = terminated(value)
    keepAlive.push(bytes)
    view.setBigUint64(offset, pointerOf(bytes), LITTLE_ENDIAN)
  }
}

/**
 * Build the struct. `pointerOf` is injected because taking a buffer's address
 * is the one loader-specific step, and injecting it keeps the layout testable
 * without any FFI at all.
 */
export function encodeOpts(opts: WireOpts, pointerOf: (buffer: Uint8Array) => bigint): EncodedOpts {
  const struct = new Uint8Array(OPTS_BYTES)
  const view = new DataView(struct.buffer)
  const keepAlive: Uint8Array[] = []

  const field = stringField(view, keepAlive, pointerOf)

  field(MESH_OFFSET, opts.mesh)
  field(TOPIC_OFFSET, opts.topic)
  field(NICK_OFFSET, opts.nick)
  field(NAME_OFFSET, opts.name)
  field(LOOKUP_OFFSET, opts.lookup)
  field(TRANSPORT_OFFSET, opts.transport)
  field(RELAY_URLS_OFFSET, opts.relayUrls)
  view.setInt32(DISABLE_IP_OFFSET, opts.disableIp ? 1 : 0, LITTLE_ENDIAN)
  view.setInt32(DISABLE_WEBRTC_OFFSET, opts.disableWebrtc ? 1 : 0, LITTLE_ENDIAN)
  view.setBigUint64(MAX_PEERS_OFFSET, BigInt(opts.maxPeers), LITTLE_ENDIAN)

  return { struct, keepAlive }
}

/**
 * `fofoca_stream_opts`, for `fofoca_streams_bind`, under the same rules as
 * `fofoca_opts`: the same comma lists, the same path switches.
 *
 * ```c
 * typedef struct {
 *   const char *lookup;      // offset  0
 *   const char *transport;   // offset  8
 *   const char *relay_urls;  // offset 16
 *   int disable_ip;          // offset 24
 *   int disable_webrtc;      // offset 28
 * } fofoca_stream_opts;      // 32 bytes
 * ```
 */
export interface WireStreamOpts {
  readonly lookup: string | null
  readonly transport: string | null
  readonly relayUrls: string | null
  readonly disableIp: boolean
  readonly disableWebrtc: boolean
}

export const STREAM_OPTS_BYTES = 32

export function encodeStreamOpts(
  opts: WireStreamOpts,
  pointerOf: (buffer: Uint8Array) => bigint,
): EncodedOpts {
  const struct = new Uint8Array(STREAM_OPTS_BYTES)
  const view = new DataView(struct.buffer)
  const keepAlive: Uint8Array[] = []
  const field = stringField(view, keepAlive, pointerOf)
  field(0, opts.lookup)
  field(8, opts.transport)
  field(16, opts.relayUrls)
  view.setInt32(24, opts.disableIp ? 1 : 0, LITTLE_ENDIAN)
  view.setInt32(28, opts.disableWebrtc ? 1 : 0, LITTLE_ENDIAN)
  return { struct, keepAlive }
}
