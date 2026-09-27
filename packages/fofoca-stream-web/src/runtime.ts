/**
 * The stream runtime a page (or an agent through WebMCP) drives. A tab is one
 * end of one stream: the **reader** of a hash it was given, or the
 * **producer** of a stream it created.
 *
 * DOM-free on purpose. `main.ts` hooks the DOM onto `onChunk`; the tools in
 * `webmcp.ts` call the methods; the tests drive it over fakes.
 *
 * A reader's bytes are decoded by one `TextDecoder` for the whole stream: a
 * chunk boundary can split a multibyte character, and a per-chunk decode would
 * corrupt it.
 *
 * What arrives is kept in a bounded **log**, not a queue that a read drains.
 * Each entry carries its sequence number, its bytes and the text those bytes
 * decoded to, so:
 *
 * - reading destroys nothing, and two readers (two agents, or a tool and the
 *   page) can each follow the stream from their own cursor;
 * - a reader can ask for `base64` and get the bytes back exactly, which text
 *   cannot do for a binary payload;
 * - entries age out by bytes held, so a long stream cannot grow the tab
 *   without bound.
 */

/** The slice of `fofoca-wasm`'s `Reader` the runtime uses. */
export interface ByteSource {
  read(): Promise<Uint8Array | null>
}

/** The slice of `fofoca-wasm`'s `Producer` the runtime uses. */
export interface ByteSink {
  readonly hash: string
  attached(): Promise<void>
  write(data: Uint8Array | string): Promise<void>
  close(): Promise<void>
}

/** One delivered piece of the stream, in order. The end carries no text. */
export interface Chunk {
  readonly text: string
  readonly eof: boolean
}

/** How `read` renders the bytes it returns. */
export type Encoding = 'text' | 'base64'

/** One item from `read`: consecutive pieces merged, or the end on its own. */
export interface Item {
  readonly eof: boolean
  readonly text?: string
  readonly base64?: string
}

export interface ReadResult {
  readonly items: Item[]
  /** Pass this back as `cursor` to continue where this read stopped. */
  readonly cursor: number
}

export interface ReadOpts {
  /** How long to wait for the first entry when there is nothing to read. */
  readonly waitMs?: number
  /** Where to read from. Absent means the oldest entry still held. */
  readonly cursor?: number
  /** Default `text`. */
  readonly encoding?: Encoding
}

export interface Status {
  readonly role: 'reader' | 'producer'
  /** The stream's hash, when this tab knows it. */
  readonly hash?: string
  /** A producer's consumer has attached. */
  readonly attached: boolean
  /** The stream ended: read to its end, or closed by this producer. */
  readonly complete: boolean
  /** Why the stream stopped early, when it did. */
  readonly error?: string
  /** Bytes written or read so far. */
  readonly bytes: number
  /** Entries the log holds right now. */
  readonly buffered: number
  /** The cursor a reader wanting only what arrives next would start from. */
  readonly cursor: number
  /** The oldest cursor still readable. Anything older has aged out. */
  readonly oldestCursor: number
}

/** The longest a `read` waits for the first entry. Under a browser agent's patience. */
export const MAX_WAIT_MS = 25_000
const DEFAULT_WAIT_MS = 10_000
/** Payload bytes the log holds before its oldest entries age out. */
export const DEFAULT_MAX_BYTES = 4_194_304

interface Entry {
  readonly seq: number
  readonly eof: boolean
  readonly bytes: Uint8Array
  readonly text: string
}

export class StreamRuntime {
  readonly #source: ByteSource | undefined
  readonly #sink: ByteSink | undefined
  readonly #hash: string | undefined
  readonly #maxBytes: number
  readonly #decoder = new TextDecoder()
  readonly #log: Entry[] = []
  #nextSeq = 0
  #bytesHeld = 0
  #bytes = 0
  #attached = false
  #complete = false
  #error: string | undefined
  readonly #waiters = new Set<() => void>()

  /** Called with every chunk as it is read — the live view. */
  onChunk: ((chunk: Chunk) => void) | undefined
  /** Called after every write this runtime made, whoever asked for it. */
  onWritten: ((text: string) => void) | undefined

  private constructor(
    role: { source: ByteSource; hash?: string } | { sink: ByteSink },
    opts?: { maxBytes?: number },
  ) {
    this.#maxBytes = opts?.maxBytes ?? DEFAULT_MAX_BYTES
    if ('sink' in role) {
      this.#sink = role.sink
      this.#hash = role.sink.hash
      void role.sink.attached().then(
        () => {
          this.#attached = true
        },
        (error: unknown) => {
          // Our own close ends the wait for a reader; that is not a failure.
          if (!this.#complete) {
            this.#error = String(error)
          }
        },
      )
    } else {
      this.#source = role.source
      this.#hash = role.hash
      void this.#pump(role.source)
    }
  }

  /** The reading end of a stream. */
  static reading(source: ByteSource, opts?: { hash?: string; maxBytes?: number }): StreamRuntime {
    return new StreamRuntime(
      { source, ...(opts?.hash === undefined ? {} : { hash: opts.hash }) },
      opts,
    )
  }

  /** The writing end of a stream this tab created. */
  static producing(sink: ByteSink): StreamRuntime {
    return new StreamRuntime({ sink })
  }

  async #pump(source: ByteSource): Promise<void> {
    try {
      for (;;) {
        const bytes = await source.read()
        if (bytes === null) {
          break
        }
        this.#bytes += bytes.byteLength
        // Decoded on the way in, not at read time: the decoder carries the
        // tail of a multibyte character across chunks, and a reader starting
        // mid-stream cannot rebuild that state.
        this.#append({ eof: false, bytes, text: this.#decoder.decode(bytes, { stream: true }) })
      }
      const tail = this.#decoder.decode()
      if (tail !== '') {
        this.#append({ eof: false, bytes: new Uint8Array(), text: tail })
      }
      this.#complete = true
      this.#append({ eof: true, bytes: new Uint8Array(), text: '' })
    } catch (error) {
      this.#error = String(error)
      this.#wake()
    }
  }

  #append(entry: Omit<Entry, 'seq'>): void {
    const full: Entry = { ...entry, seq: this.#nextSeq }
    this.#nextSeq += 1
    this.#log.push(full)
    this.#bytesHeld += full.bytes.byteLength
    while (this.#bytesHeld > this.#maxBytes && this.#log.length > 1) {
      const oldest = this.#log.shift()
      this.#bytesHeld -= oldest?.bytes.byteLength ?? 0
    }
    this.onChunk?.({ text: full.eof ? '' : full.text, eof: full.eof })
    this.#wake()
  }

  #wake(): void {
    for (const waiter of this.#waiters) {
      waiter()
    }
    this.#waiters.clear()
  }

  #oldestCursor(): number {
    return this.#log[0]?.seq ?? this.#nextSeq
  }

  #producer(): ByteSink {
    if (this.#sink === undefined) {
      throw new Error('this tab reads a stream; it cannot write to it')
    }
    return this.#sink
  }

  /** Write `text`, once the consumer is attached, paced by it. */
  async write(text: string): Promise<void> {
    await this.#producer().write(text)
    this.#bytes += new TextEncoder().encode(text).byteLength
    this.onWritten?.(text)
  }

  /**
   * End the stream: the consumer reads everything written, then the end.
   * With no consumer yet, the stream is abandoned instead.
   */
  async close(): Promise<void> {
    const sink = this.#producer()
    this.#complete = true
    try {
      await sink.close()
    } catch (error) {
      this.#complete = false
      this.#error = String(error)
      throw error
    }
  }

  /**
   * Everything the log holds from `cursor` on, and the cursor to continue
   * from. A read takes nothing away, so a second reader sees the same
   * entries. Without a cursor the read starts at the oldest entry held.
   *
   * With nothing to read it waits up to `waitMs` (clamped to `MAX_WAIT_MS`)
   * for the first entry, or until `signal` aborts. That is the closest thing
   * to a stream a one-promise tool call allows.
   */
  async read(opts: ReadOpts = {}, signal?: AbortSignal): Promise<ReadResult> {
    if (this.#source === undefined) {
      throw new Error('this tab produces a stream; the consumer reads it')
    }
    const wait = Math.min(Math.max(0, opts.waitMs ?? DEFAULT_WAIT_MS), MAX_WAIT_MS)
    let from = opts.cursor ?? this.#oldestCursor()
    const settled = this.#complete || this.#error !== undefined
    if (this.#nextSeq <= from && wait > 0 && !settled && signal?.aborted !== true) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(done, wait)
        function done(): void {
          clearTimeout(timer)
          signal?.removeEventListener('abort', done)
          resolve()
        }
        signal?.addEventListener('abort', done, { once: true })
        this.#waiters.add(done)
      })
    }
    // A cursor older than the log asks for entries that aged out. Serve what
    // is left rather than nothing, and let the returned cursor say where the
    // reader now stands.
    from = Math.max(from, this.#oldestCursor())
    const window = this.#log.filter((entry) => entry.seq >= from)
    const last = window.at(-1)
    return {
      items: coalesce(window, opts.encoding ?? 'text'),
      cursor: last === undefined ? from : last.seq + 1,
    }
  }

  status(): Status {
    return {
      role: this.#sink === undefined ? 'reader' : 'producer',
      ...(this.#hash === undefined ? {} : { hash: this.#hash }),
      attached: this.#sink === undefined ? true : this.#attached,
      complete: this.#complete,
      ...(this.#error === undefined ? {} : { error: this.#error }),
      bytes: this.#bytes,
      buffered: this.#log.length,
      cursor: this.#nextSeq,
      oldestCursor: this.#oldestCursor(),
    }
  }
}

/**
 * Merge consecutive entries into one item; the end stays its own. Bytes are
 * joined before they are encoded, because two base64 strings do not
 * concatenate into the base64 of their bytes.
 */
function coalesce(entries: readonly Entry[], encoding: Encoding): Item[] {
  const runs: Entry[][] = []
  for (const entry of entries) {
    const last = runs.at(-1)
    const head = last?.[0]
    if (last !== undefined && head !== undefined && !head.eof && !entry.eof) {
      last.push(entry)
    } else {
      runs.push([entry])
    }
  }
  return runs.flatMap((run): Item[] => {
    const head = run[0]
    if (head === undefined) {
      return []
    }
    if (encoding === 'base64') {
      return [{ eof: head.eof, base64: toBase64(join(run.map((entry) => entry.bytes))) }]
    }
    return [{ eof: head.eof, text: run.map((entry) => entry.text).join('') }]
  })
}

function join(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const chunk of chunks) {
    out.set(chunk, at)
    at += chunk.byteLength
  }
  return out
}

/** `btoa` over bytes, in slices: spreading a megabyte blows the argument limit. */
function toBase64(bytes: Uint8Array): string {
  const SLICE = 0x8000
  let binary = ''
  for (let at = 0; at < bytes.length; at += SLICE) {
    binary += String.fromCharCode(...bytes.subarray(at, at + SLICE))
  }
  return btoa(binary)
}
