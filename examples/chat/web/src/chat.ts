/**
 * The chat page's script: join the mesh the query string names and chat.
 * A person types into the composer; the e2e driver evaluates `window.chat`
 * and reads the same DOM the person sees.
 *
 * Query parameters (the harness page's dialect):
 * - `topic` or `mesh` — the mesh selector (exactly one).
 * - `nick` — this peer's nickname.
 * - `relay` — a custom relay URL (repeatable); with `topic` it is part of
 *   the derived id, so every member must pass the same.
 * - `transport` — what payload may ride, `p2p` (the default) or
 *   `p2p,relay` (id-changing, same rule).
 * - `log` — an `EnvFilter` for the engine's tracing, to the console.
 *
 * DOM contract (what the driver — or a person — reads):
 * - `#status` holds `#ready` (with `data-id`/`data-nick`) once the mesh is
 *   open, or `#failed` with the error text.
 * - `#messages` gets one `<li data-from data-directed data-self>` per
 *   chat line, own sends included.
 * - `#peers` holds the roster JSON, `data-count` the peer count.
 * - `#events` (hidden) gets one `<li data-kind>` per mesh event.
 * - `window.chat = { send, close }`, promise-returning.
 */

import { join } from 'fofoca-wasm'
import type { Mesh, Transport } from 'fofoca-wasm'

declare global {
  interface Window {
    chat?: {
      /** `/msg <nick> <text>` goes directed, anything else broadcasts. */
      send(line: string): Promise<void>
      close(): Promise<void>
    }
  }
}

function byId(id: string): HTMLElement {
  const element = document.getElementById(id)
  if (!element) {
    throw new Error(`chat page is missing #${id}`)
  }
  return element
}

function showMessage(from: string, text: string, directed: boolean, self: boolean): void {
  const item = document.createElement('li')
  item.dataset['from'] = from
  item.dataset['directed'] = String(directed)
  item.dataset['self'] = String(self)
  item.textContent = text
  byId('messages').append(item)
  byId('messages').scrollTop = byId('messages').scrollHeight
}

/** `/msg <nick> <text>` → a directed send; anything else broadcasts. */
async function sendLine(mesh: Mesh, line: string): Promise<void> {
  const direct = /^\/msg\s+(\S+)\s+(.*)$/.exec(line)
  if (direct?.[1] !== undefined && direct[2] !== undefined) {
    await mesh.send(direct[2], { to: direct[1] })
    showMessage(mesh.nick, `(to ${direct[1]}) ${direct[2]}`, true, true)
    return
  }
  await mesh.send(line)
  showMessage(mesh.nick, line, false, true)
}

async function main(): Promise<void> {
  const params = new URLSearchParams(window.location.search)
  const topic = params.get('topic')
  const id = params.get('mesh')
  const nick = params.get('nick')
  // Passed through as typed: a name that is not a transport is the engine's
  // error to raise, and it names the choices.
  const transport = params.get('transport')?.split(',') as Transport[] | undefined

  let mesh: Mesh
  try {
    mesh = await join({
      ...(topic === null ? {} : { topic }),
      ...(id === null ? {} : { id }),
      ...(nick === null ? {} : { nick }),
      ...(transport === undefined ? {} : { transport }),
      relayUrls: params.getAll('relay'),
      log: params.get('log') ?? 'warn',
    })
  } catch (error) {
    const failed = document.createElement('div')
    failed.id = 'failed'
    failed.textContent = String(error)
    byId('status').replaceChildren(failed)
    return
  }

  const ready = document.createElement('div')
  ready.id = 'ready'
  ready.dataset['id'] = mesh.id
  ready.dataset['nick'] = mesh.nick
  ready.textContent = `${mesh.nick} · ${mesh.name}`
  byId('status').replaceChildren(ready)

  let lastRoster = ''
  const refreshRoster = (): void => {
    const roster = JSON.stringify(mesh.peers, null, 1)
    if (roster === lastRoster) {
      return
    }
    lastRoster = roster
    byId('peers').textContent = roster
    byId('peers').dataset['count'] = String(mesh.peers.length)
  }
  refreshRoster()
  setInterval(refreshRoster, 500)

  window.chat = {
    send: (line) => sendLine(mesh, line),
    close: () => mesh.leave(),
  }

  const input = byId('input') as HTMLInputElement
  byId('composer').addEventListener('submit', (submit) => {
    submit.preventDefault()
    const line = input.value.trim()
    if (line === '') {
      return
    }
    input.value = ''
    void sendLine(mesh, line).catch((error: unknown) => {
      showMessage('!', `send failed: ${String(error)}`, false, true)
    })
  })

  void (async () => {
    for await (const message of mesh.messages()) {
      showMessage(message.from, message.text, message.directed, false)
    }
  })()

  for await (const event of mesh.events()) {
    const item = document.createElement('li')
    item.dataset['kind'] = event.kind
    item.textContent = JSON.stringify(event)
    byId('events').append(item)
    if (event.kind === 'joined' || event.kind === 'left') {
      showMessage('*', `${event.nick} ${event.kind}`, false, false)
    }
    refreshRoster()
  }
}

void main()
