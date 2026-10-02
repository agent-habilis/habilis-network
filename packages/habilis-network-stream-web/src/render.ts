/**
 * What the page renders, decided without a DOM.
 *
 * A stream arrives as ~2 KB chunks, and writing each one straight into the
 * page costs a layout: appending to a `<pre>` that already holds megabytes
 * and then reading `scrollHeight` measured 77 ms **per chunk** at 4 M
 * characters, against 1.3 ms on an empty one. That work runs on the same
 * thread as the wasm engine, so the page starved its own transport as the
 * buffer grew — throughput fell roughly 5x over a session and came back on
 * reload.
 *
 * So the page writes once per animation frame, not once per chunk, and keeps
 * a bounded window of each stream. The runtime keeps every byte either way;
 * this is only the view.
 */

/** One stream's identity in the view: who sent it, how, and whether it is ours. */
export interface ViewKey {
  readonly from: string
  readonly directed: boolean
  readonly self: boolean
}

/** What one view needs applying to it after a flush. */
export interface Pending {
  readonly key: ViewKey
  /** Text to append, already joined. Empty when only `complete` changed. */
  readonly text: string
  /** The stream's end-of-stream state, when it changed since the last flush. */
  readonly complete?: boolean
}

/**
 * Characters a single view keeps. Past this the oldest are dropped: a
 * person cannot read four megabytes of scrollback, and the layout cost of
 * holding it is what this module exists to avoid. Comfortably above the
 * e2e payload, so the suite still compares a whole stream.
 */
export const MAX_VIEW_CHARS = 1_048_576

const keyOf = (key: ViewKey) => `${key.self ? 's' : 'r'}:${key.directed ? 'd' : 'b'}:${key.from}`

/**
 * Accumulates chunks per stream and hands them over in one batch per flush.
 * Pure: `main.ts` owns the DOM and the timers.
 *
 * What it holds is bounded per stream. A flush can be a long way off — a
 * hidden tab gets no animation frames at all — and a view only ever shows
 * its last `MAX_VIEW_CHARS` anyway, so keeping more than that would grow the
 * tab for text no one will see.
 */
export class Batcher {
  readonly #pending = new Map<string, { key: ViewKey; parts: string[]; held: number; complete?: boolean }>()
  readonly #max: number

  constructor(maxChars: number = MAX_VIEW_CHARS) {
    this.#max = maxChars
  }

  #entry(key: ViewKey) {
    const id = keyOf(key)
    let entry = this.#pending.get(id)
    if (entry === undefined) {
      entry = { key, parts: [], held: 0 }
      this.#pending.set(id, entry)
    }
    return entry
  }

  /** Queue text for this stream. */
  push(key: ViewKey, text: string): void {
    if (text === '') {
      return
    }
    const entry = this.#entry(key)
    entry.parts.push(text)
    entry.held += text.length
    while (entry.held > this.#max && entry.parts.length > 1) {
      const oldest = entry.parts.shift()
      entry.held -= oldest?.length ?? 0
    }
  }

  /** Queue this stream's end-of-stream state. */
  mark(key: ViewKey, complete: boolean): void {
    this.#entry(key).complete = complete
  }

  get size(): number {
    return this.#pending.size
  }

  /** Everything queued since the last flush, one entry per stream. */
  flush(): Pending[] {
    const out: Pending[] = [...this.#pending.values()].map((entry) => ({
      key: entry.key,
      text: entry.parts.join(''),
      ...(entry.complete === undefined ? {} : { complete: entry.complete }),
    }))
    this.#pending.clear()
    return out
  }
}

/**
 * How to append `text` to a view already holding `heldChars` characters,
 * under `max`. Returns the text to append and how many characters to drop
 * from the front first; the caller does both in one pass.
 */
export function fit(
  heldChars: number,
  text: string,
  max: number = MAX_VIEW_CHARS,
): { append: string; dropChars: number } {
  if (text.length >= max) {
    // The batch alone fills the view: keep its tail and drop everything held.
    return { append: text.slice(text.length - max), dropChars: heldChars }
  }
  const over = heldChars + text.length - max
  return { append: text, dropChars: over > 0 ? over : 0 }
}
