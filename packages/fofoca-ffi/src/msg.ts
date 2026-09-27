/**
 * `fofoca_msg`, decoded by hand.
 *
 * ```c
 * typedef struct {
 *   char nick[64];
 *   int directed;
 *   size_t len;
 * } fofoca_msg;
 * ```
 *
 * 80 bytes, alignment 8: `directed` at 64, four bytes of padding, `len` at 72.
 * `crates/fofoca-ffi/src/ffi.rs` pins the same offsets at compile time.
 *
 * Neither `bun:ffi` nor Deno's FFI decodes C structs at all. koffi could, and
 * deliberately does not, so a change to the layout breaks in exactly one place
 * instead of one place per runtime.
 *
 * 32-bit targets are out of scope — `size_t` is four bytes there and the struct
 * is 72.
 */

const NICK_OFFSET = 0
const NICK_CAP = 64
const DIRECTED_OFFSET = 64
const LEN_OFFSET = 72

export const MSG_BYTES = 80

/**
 * Computed rather than assumed, so a big-endian port fails a test instead of
 * reading garbage lengths.
 */
const LITTLE_ENDIAN = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1

const nickDecoder = new TextDecoder('utf-8', { fatal: false })

export interface MsgMeta {
  readonly nick: string
  readonly directed: boolean
  /** The text's length in bytes, excluding the NUL. */
  readonly len: number
}

/**
 * Read one `fofoca_msg` out of a scratch buffer the engine just wrote.
 *
 * @throws if `meta` is not message-sized, or if `nick` has no terminator —
 * `write_nick` truncates at 63 bytes and always writes the NUL, so its absence
 * means the struct is not what we think it is, and reading on would run off the
 * end of the name into the integers.
 */
export function decodeMsg(meta: Uint8Array): MsgMeta {
  if (meta.byteLength < MSG_BYTES) {
    throw new RangeError(`a fofoca_msg is ${MSG_BYTES} bytes, got ${meta.byteLength}`)
  }
  const view = new DataView(meta.buffer, meta.byteOffset, MSG_BYTES)

  const nickBytes = meta.subarray(NICK_OFFSET, NICK_OFFSET + NICK_CAP)
  const terminator = nickBytes.indexOf(0)
  if (terminator < 0) {
    throw new RangeError('a fofoca_msg nick is not NUL-terminated')
  }

  return {
    nick: nickDecoder.decode(nickBytes.subarray(0, terminator)),
    directed: view.getInt32(DIRECTED_OFFSET, LITTLE_ENDIAN) !== 0,
    len: Number(view.getBigUint64(LEN_OFFSET, LITTLE_ENDIAN)),
  }
}

/** Build a `fofoca_msg` in memory. For tests, and for nothing else. */
export function encodeMsg(meta: MsgMeta): Uint8Array {
  const bytes = new Uint8Array(MSG_BYTES)
  const nick = new TextEncoder().encode(meta.nick)
  if (nick.byteLength >= NICK_CAP) {
    throw new RangeError(`a nick is at most ${NICK_CAP - 1} bytes`)
  }
  bytes.set(nick, NICK_OFFSET)
  const view = new DataView(bytes.buffer)
  view.setInt32(DIRECTED_OFFSET, meta.directed ? 1 : 0, LITTLE_ENDIAN)
  view.setBigUint64(LEN_OFFSET, BigInt(meta.len), LITTLE_ENDIAN)
  return bytes
}
