/**
 * `habilis_network_msg_v2`, decoded by hand.
 *
 * ```c
 * typedef struct {
 *   size_t size;
 *   char nick[64];
 *   char key[65];
 *   int directed;
 *   size_t len;
 * } habilis_network_msg_v2;
 * ```
 *
 * 152 bytes, alignment 8: `size` at 0, `nick` at 8, `key` at 72 (64 lowercase hex digits and the
 * NUL), three bytes of padding, `directed` at 140, `len` at 144. The caller sets `size` before
 * every call, and `habilis_network_msg_recv_v2` refuses a smaller one. The old
 * `habilis_network_msg` has no size field and keeps its 80 bytes for the callers built with it;
 * this package uses the v2 struct only.
 * `crates/habilis-network-ffi/src/ffi/habilis_network_msg_v2.rs` pins the same offsets at
 * compile time.
 *
 * Neither `bun:ffi` nor Deno's FFI decodes C structs at all. koffi could, and
 * deliberately does not, so a change to the layout breaks in exactly one place
 * instead of one place per runtime.
 *
 * 32-bit targets are out of scope — `size_t` is four bytes there and the struct
 * is 148.
 */

const SIZE_OFFSET = 0
const NICK_OFFSET = 8
const NICK_CAP = 64
const KEY_OFFSET = 72
const KEY_HEX = 64
const KEY_CAP = KEY_HEX + 1
const DIRECTED_OFFSET = 140
const LEN_OFFSET = 144

export const MSG_BYTES = 152

/**
 * Computed rather than assumed, so a big-endian port fails a test instead of
 * reading garbage lengths.
 */
const LITTLE_ENDIAN = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1

const nickDecoder = new TextDecoder('utf-8', { fatal: false })

export interface MsgMeta {
  /** The author's nickname. Two members can use one, so it names no author. */
  readonly nick: string
  /** The author's key, 64 lowercase hex digits: the address of a reply. */
  readonly key: string
  readonly directed: boolean
  /** The text's length in bytes, excluding the NUL. */
  readonly len: number
}

/**
 * Read one `habilis_network_msg_v2` out of a scratch buffer the engine just wrote.
 *
 * @throws if `meta` is not message-sized, or if `nick` has no terminator —
 * `write_nick` truncates at 63 bytes and always writes the NUL, so its absence
 * means the struct is not what we think it is, and reading on would run off the
 * end of the name into the integers. The same holds for `key`, which must be 64 digits before
 * its NUL.
 */
export function decodeMsg(meta: Uint8Array): MsgMeta {
  if (meta.byteLength < MSG_BYTES) {
    throw new RangeError(`a habilis_network_msg is ${MSG_BYTES} bytes, got ${meta.byteLength}`)
  }
  const view = new DataView(meta.buffer, meta.byteOffset, MSG_BYTES)

  const nickBytes = meta.subarray(NICK_OFFSET, NICK_OFFSET + NICK_CAP)
  const terminator = nickBytes.indexOf(0)
  if (terminator < 0) {
    throw new RangeError('a habilis_network_msg nick is not NUL-terminated')
  }

  const keyBytes = meta.subarray(KEY_OFFSET, KEY_OFFSET + KEY_CAP)
  if (keyBytes.indexOf(0) !== KEY_HEX) {
    throw new RangeError('a habilis_network_msg key is not 64 digits and a NUL')
  }

  return {
    nick: nickDecoder.decode(nickBytes.subarray(0, terminator)),
    key: nickDecoder.decode(keyBytes.subarray(0, KEY_HEX)),
    directed: view.getInt32(DIRECTED_OFFSET, LITTLE_ENDIAN) !== 0,
    len: Number(view.getBigUint64(LEN_OFFSET, LITTLE_ENDIAN)),
  }
}

/**
 * Build a `habilis_network_msg_v2` in memory, with `size` set as a caller sets it. The engine
 * calls it for the scratch buffer too, so the size is never forgotten.
 */
export function encodeMsg(meta: MsgMeta): Uint8Array {
  const bytes = new Uint8Array(MSG_BYTES)
  const nick = new TextEncoder().encode(meta.nick)
  if (nick.byteLength >= NICK_CAP) {
    throw new RangeError(`a nick is at most ${NICK_CAP - 1} bytes`)
  }
  bytes.set(nick, NICK_OFFSET)
  const key = new TextEncoder().encode(meta.key)
  if (key.byteLength !== KEY_HEX) {
    throw new RangeError(`a key is ${KEY_HEX} hex digits`)
  }
  bytes.set(key, KEY_OFFSET)
  const view = new DataView(bytes.buffer)
  view.setBigUint64(SIZE_OFFSET, BigInt(MSG_BYTES), LITTLE_ENDIAN)
  view.setInt32(DIRECTED_OFFSET, meta.directed ? 1 : 0, LITTLE_ENDIAN)
  view.setBigUint64(LEN_OFFSET, BigInt(meta.len), LITTLE_ENDIAN)
  return bytes
}
