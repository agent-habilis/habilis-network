/**
 * The stream page: one end of one stream. With a hash in the URL it reads
 * that stream; without one it creates a stream, shows its hash, and writes
 * what is typed into it. A person at the composer, an agent through WebMCP,
 * or the e2e driver through `window.stream` all drive the same runtime.
 *
 * URL contract. The hash rides in the **fragment**, which a browser never
 * sends to the server, so it stays out of access logs:
 * - `#<hash>` — read this stream. It carries the producer's own lookups.
 * - no fragment — produce a stream. `?relay=` sets a custom relay URL
 *   (repeatable) and `?transport=p2p,relay` lets the bytes fall back to the
 *   relay; a tab always finds peers through the relay.
 * - `?log=` — an `EnvFilter` for the engine's tracing, to the console.
 *
 * DOM contract (what the driver — or a person — reads):
 * - `#status` holds `#ready` (with `data-role` and `data-hash`) once the
 *   stream end is open, or `#failed` with the error text.
 * - `#webmcp` says whether the tools registered (`data-registered`).
 * - `#share` (producer) holds the hash and a link a reader can open;
 *   `data-attached` turns `true` once the reader is attached.
 * - `#streams` holds one `<pre data-self data-complete>`: what arrived
 *   (reader) or what was written (producer, `data-self="true"`). Writes are
 *   batched per animation frame; a view holds at most `MAX_VIEW_CHARS`, and
 *   `data-truncated="true"` says when older text was dropped. The runtime
 *   keeps every byte.
 * - `window.stream` — the runtime's methods, promise-returning where they are.
 */

import type { Transport } from 'fofoca-wasm'
import { bindStreams, bindStreamsFor } from 'fofoca-wasm'

import type { Pending, ViewKey } from './render.ts'
import { Batcher, MAX_VIEW_CHARS, fit } from './render.ts'
import { StreamRuntime } from './runtime.ts'
import { registerStreamTools } from './webmcp.ts'

declare global {
  interface Window {
    stream?: Pick<StreamRuntime, 'write' | 'close' | 'read' | 'status'>
  }
}

/** How often the view is flushed when animation frames are not running. */
const HIDDEN_FLUSH_MS = 500

/** The one view each role has: what arrived, or what was written. */
const READ_VIEW: ViewKey = { from: 'stream', directed: false, self: false }
const WRITE_VIEW: ViewKey = { from: 'you', directed: false, self: true }

function byId(id: string): HTMLElement {
  const element = document.getElementById(id)
  if (!element) {
    throw new Error(`stream page is missing #${id}`)
  }
  return element
}

/** The `<pre>` for a view, created on first sight. */
function streamView(key: ViewKey): HTMLPreElement {
  const streams = byId('streams')
  const existing = streams.querySelector<HTMLPreElement>(`pre[data-self="${key.self}"]`)
  if (existing) {
    return existing
  }
  const view = document.createElement('pre')
  view.dataset['from'] = key.from
  view.dataset['self'] = String(key.self)
  view.dataset['complete'] = 'false'
  streams.append(view)
  return view
}

/**
 * Apply one batch to its view: at most one text write and one scroll, and
 * the scroll only when the reader was already at the bottom. Reading
 * `scrollHeight` is what forces the layout, so it happens once here rather
 * than once per chunk.
 */
function apply(pending: Pending): void {
  const view = streamView(pending.key)
  if (pending.text !== '') {
    const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 4
    const held = view.textContent ?? ''
    const { append, dropChars } = fit(held.length, pending.text, MAX_VIEW_CHARS)
    if (dropChars > 0) {
      view.textContent = held.slice(dropChars) + append
      view.dataset['truncated'] = 'true'
    } else {
      view.append(append)
    }
    if (atBottom) {
      view.scrollTop = view.scrollHeight
    }
  }
  if (pending.complete !== undefined) {
    view.dataset['complete'] = String(pending.complete)
  }
}

/**
 * Drive a batcher from animation frames, and from a timer as well.
 *
 * A hidden tab gets no animation frames at all, so a frame-only loop leaves
 * its view arbitrarily stale and its batch growing. Timers are throttled
 * there rather than stopped, so the slow leg keeps the view roughly current
 * whatever the tab is doing. Flushing twice is harmless: the second flush
 * finds nothing.
 */
function paint(batcher: Batcher): void {
  const flush = (): void => {
    for (const pending of batcher.flush()) {
      apply(pending)
    }
  }
  const frame = (): void => {
    flush()
    requestAnimationFrame(frame)
  }
  requestAnimationFrame(frame)
  setInterval(flush, HIDDEN_FLUSH_MS)
}

async function open(log: string): Promise<StreamRuntime> {
  const hash = decodeURIComponent(window.location.hash.slice(1))
  if (hash !== '') {
    const streams = await bindStreamsFor(hash, { log })
    return StreamRuntime.reading(await streams.open(hash), { hash })
  }
  const params = new URLSearchParams(window.location.search)
  // Passed through as typed: a name that is not a transport is the engine's
  // error to raise, and it names the choices.
  const transport = params.get('transport')?.split(',') as Transport[] | undefined
  const streams = await bindStreams({
    lookup: ['relay'],
    ...(transport === undefined ? {} : { transport }),
    relayUrls: params.getAll('relay'),
    log,
  })
  return StreamRuntime.producing(await streams.create())
}

function showShare(runtime: StreamRuntime): void {
  const { hash } = runtime.status()
  if (hash === undefined) {
    return
  }
  const share = byId('share')
  share.hidden = false
  share.dataset['hash'] = hash
  share.dataset['attached'] = 'false'
  const link = document.createElement('a')
  link.href = `${window.location.origin}${window.location.pathname}#${hash}`
  link.textContent = 'reader link'
  byId('share-hash').textContent = hash
  byId('share-link').replaceChildren(link)
  const poll = setInterval(() => {
    if (runtime.status().attached) {
      share.dataset['attached'] = 'true'
      byId('share-state').textContent = 'reader attached'
      clearInterval(poll)
    }
  }, 250)
}

async function main(): Promise<void> {
  const params = new URLSearchParams(window.location.search)
  let runtime: StreamRuntime
  try {
    runtime = await open(params.get('log') ?? 'warn')
  } catch (error) {
    const failed = document.createElement('div')
    failed.id = 'failed'
    failed.textContent = String(error)
    byId('status').replaceChildren(failed)
    return
  }

  const status = runtime.status()
  const ready = document.createElement('div')
  ready.id = 'ready'
  ready.dataset['role'] = status.role
  ready.dataset['hash'] = status.hash ?? ''
  ready.textContent = status.role === 'reader' ? 'reading a stream' : 'producing a stream'
  byId('status').replaceChildren(ready)

  const batcher = new Batcher()
  paint(batcher)
  runtime.onChunk = (chunk) => {
    if (chunk.eof) {
      batcher.mark(READ_VIEW, true)
    } else {
      batcher.push(READ_VIEW, chunk.text)
      batcher.mark(READ_VIEW, false)
    }
  }
  runtime.onWritten = (text) => {
    batcher.push(WRITE_VIEW, text)
    batcher.mark(WRITE_VIEW, false)
  }

  const registered = registerStreamTools(runtime)
  byId('webmcp').dataset['registered'] = String(registered)
  byId('webmcp').textContent = registered
    ? 'WebMCP tools registered'
    : 'no WebMCP in this browser — window.stream only'

  window.stream = {
    write: (text) => runtime.write(text),
    close: async () => {
      await runtime.close()
      batcher.mark(WRITE_VIEW, true)
    },
    read: (opts, signal) => runtime.read(opts, signal),
    status: () => runtime.status(),
  }

  if (status.role === 'reader') {
    return
  }
  showShare(runtime)
  byId('composer').hidden = false
  const input = byId('input') as HTMLTextAreaElement
  const own = () => streamView(WRITE_VIEW)
  byId('send').addEventListener('click', () => {
    const text = input.value
    if (text === '') {
      return
    }
    input.value = ''
    void runtime.write(text).catch((error: unknown) => {
      own().append(`\n! write failed: ${String(error)}\n`)
    })
  })
  byId('close').addEventListener('click', () => {
    void window.stream?.close().catch((error: unknown) => {
      own().append(`\n! close failed: ${String(error)}\n`)
    })
  })
}

void main()
