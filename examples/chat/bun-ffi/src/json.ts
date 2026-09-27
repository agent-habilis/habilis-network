/**
 * The automation mode: NDJSON both ways.
 *
 * This is a contract, not a debug view — the e2e test and any script drive
 * the chat through it, so treat a change here as a break. Documented in
 * `examples/chat/README.md`.
 *
 * stdout, one JSON object per line:
 *   {"kind":"ready","id","name","nick"}      first line, always; the id lets a
 *                                            --create caller invite others
 *   {"kind":"message","from","text","directed"}
 *   {"kind":"joined"|"left","nick"}
 *   {"kind":"error","text"}                  the same shape as the Rust robot's
 *   {"kind":"closed","reason"}               terminal
 *   {"kind":"peers","peers":[...]}           reply to {"cmd":"peers"}
 *   {"kind":"state","value":{...}}           reply to {"cmd":"state"}
 *   {"kind":"ok","cmd":"send"|"merge"}       reply to a write
 *
 * stdin, one JSON object per line:
 *   {"cmd":"send","body":"...","to"?:"nick"}
 *   {"cmd":"peers"} · {"cmd":"state"} · {"cmd":"merge","patch":{...}} · {"cmd":"leave"}
 *
 * EOF on stdin leaves the mesh and exits 0.
 */

import * as readline from 'node:readline'
import type { Mesh } from 'fofoca-ffi'

interface SendCmd {
  cmd: 'send'
  body: string
  to?: string
}
interface MergeCmd {
  cmd: 'merge'
  patch: Record<string, unknown>
}
type ChatCmd = SendCmd | MergeCmd | { cmd: 'peers' } | { cmd: 'state' } | { cmd: 'leave' }

export async function runJson(mesh: Mesh): Promise<void> {
  const out = (event: Record<string, unknown>) => {
    process.stdout.write(`${JSON.stringify(event)}\n`)
  }

  out({ kind: 'ready', id: mesh.id, name: mesh.name, nick: mesh.nick })

  const rl = readline.createInterface({ input: process.stdin })

  const messagesLoop = (async () => {
    for await (const message of mesh.messages()) {
      out({ kind: 'message', from: message.from, text: message.text, directed: message.directed })
    }
  })()

  const eventsLoop = (async () => {
    for await (const event of mesh.events()) {
      // `ready` already went out above, with the identity attached.
      if (event.kind === 'error' || event.kind === 'info') {
        out({ kind: event.kind, text: event.message })
      } else if (event.kind !== 'ready') {
        out({ ...event })
      }
      if (event.kind === 'closed') {
        rl.close()
      }
    }
  })()

  for await (const line of rl) {
    if (line.trim() === '') {
      continue
    }
    let command: ChatCmd
    try {
      command = JSON.parse(line) as ChatCmd
    } catch (error) {
      out({ kind: 'error', text: `unreadable command: ${String(error)}` })
      continue
    }
    try {
      switch (command.cmd) {
        case 'send': {
          await mesh.send(command.body, command.to === undefined ? undefined : { to: command.to })
          out({ kind: 'ok', cmd: 'send' })
          break
        }
        case 'peers': {
          out({ kind: 'peers', peers: mesh.peers })
          break
        }
        case 'state': {
          out({ kind: 'state', value: mesh.state.value })
          break
        }
        case 'merge': {
          await mesh.state.merge(command.patch)
          out({ kind: 'ok', cmd: 'merge' })
          break
        }
        case 'leave': {
          rl.close()
          break
        }
        default: {
          out({ kind: 'error', text: `unknown cmd: ${String((command as { cmd?: unknown }).cmd)}` })
        }
      }
    } catch (error) {
      out({ kind: 'error', text: error instanceof Error ? error.message : String(error) })
    }
  }

  await mesh.leave()
  await Promise.all([messagesLoop, eventsLoop])
}
