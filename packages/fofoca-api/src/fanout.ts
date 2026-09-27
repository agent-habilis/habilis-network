/**
 * One producer, many independent iterators.
 *
 * Each iterator gets its own buffer and sees every value pushed from the moment
 * it was created. Two consumers of `mesh.messages()` must never split one queue
 * between them — that is a chat where half the lines go to the logger.
 */

/**
 * Thrown by an iterator that fell too far behind and was dropped.
 *
 * Dropping loudly rather than silently, because the engine already drops
 * silently one layer down: the engine's inbound queue is bounded at 256
 * messages and a full one only surfaces one error per stall. A second silent drop here would make a lost
 * line indistinguishable from packet loss.
 */
export class MeshOverflowError extends Error {
  constructor(capacity: number) {
    super(
      `this iterator fell ${capacity} values behind and was dropped; ` +
        `read it faster, or stop holding it open`,
    )
    this.name = 'MeshOverflowError'
  }
}

/**
 * Per-iterator buffer depth. At one frame per message a full one is a few
 * MiB, and an iterator can only get there if its *consumer* stalled — the
 * engine's own 256-message queue bounds the network side long before this.
 */
export const DEFAULT_CAPACITY = 1024

interface Subscriber<T> {
  queue: T[]
  /** Set while a `next()` is parked on an empty queue. */
  wake: ((result: IteratorResult<T>) => void) | null
  /** No more values will arrive; drain what is buffered, then complete. */
  done: boolean
  /** Raised by the next `next()`, then cleared. */
  failure: Error | null
}

export class Fanout<T> {
  readonly #subscribers = new Set<Subscriber<T>>()
  readonly #capacity: number
  #ended = false

  constructor(capacity: number = DEFAULT_CAPACITY) {
    this.#capacity = capacity
  }

  /** How many iterators are live. For tests and for leak checks. */
  get size(): number {
    return this.#subscribers.size
  }

  push(value: T): void {
    for (const subscriber of this.#subscribers) {
      const wake = subscriber.wake
      if (wake) {
        subscriber.wake = null
        wake({ value, done: false })
        continue
      }
      if (subscriber.queue.length >= this.#capacity) {
        // Dropped from the set, so the others are unaffected and this one stops
        // accumulating. The error surfaces on its next `next()`.
        subscriber.queue.length = 0
        subscriber.failure = new MeshOverflowError(this.#capacity)
        this.#subscribers.delete(subscriber)
        continue
      }
      subscriber.queue.push(value)
    }
  }

  /** No further values. Every live iterator drains what it holds, then ends. */
  end(): void {
    this.#ended = true
    for (const subscriber of this.#subscribers) {
      subscriber.done = true
      const wake = subscriber.wake
      if (wake) {
        subscriber.wake = null
        wake({ value: undefined, done: true })
      }
    }
  }

  /**
   * An iterator over everything pushed from now on.
   *
   * Aborting `signal` **completes** the iteration rather than throwing it: a
   * `for await` in a terminal and a `while` in a web handler both end the same
   * way they end on `leave()`, and neither needs a `try` that does nothing.
   */
  iterate(signal?: AbortSignal): AsyncIterableIterator<T> {
    const subscriber: Subscriber<T> = {
      queue: [],
      wake: null,
      done: this.#ended || signal?.aborted === true,
      failure: null,
    }
    if (!subscriber.done) {
      this.#subscribers.add(subscriber)
    }

    const stop = () => {
      this.#subscribers.delete(subscriber)
      subscriber.done = true
      const wake = subscriber.wake
      if (wake) {
        subscriber.wake = null
        wake({ value: undefined, done: true })
      }
    }
    signal?.addEventListener('abort', stop, { once: true })

    // Called when the iteration is over for good, however it ended. Dropping
    // the abort listener matters: a long-lived signal would otherwise retain
    // every mesh a caller ever opened under it.
    const release = () => {
      this.#subscribers.delete(subscriber)
      subscriber.done = true
      subscriber.queue.length = 0
      signal?.removeEventListener('abort', stop)
    }

    const iterator: AsyncIterableIterator<T> = {
      [Symbol.asyncIterator]: () => iterator,
      next: (): Promise<IteratorResult<T>> => {
        const failure = subscriber.failure
        if (failure) {
          subscriber.failure = null
          release()
          return Promise.reject(failure)
        }
        if (subscriber.queue.length > 0) {
          return Promise.resolve({ value: subscriber.queue.shift() as T, done: false })
        }
        if (subscriber.done) {
          release()
          return Promise.resolve({ value: undefined, done: true })
        }
        return new Promise((resolve) => {
          subscriber.wake = resolve
        })
      },
      // What `break` out of a `for await` calls. Without it the buffer keeps
      // filling for a reader that has gone away, which is the leak.
      return: (): Promise<IteratorResult<T>> => {
        release()
        return Promise.resolve({ value: undefined, done: true })
      },
    }
    return iterator
  }
}
