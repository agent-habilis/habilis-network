/**
 * The human mode: a readline loop. Frames print as `nick: text`, lifecycle
 * as `* nick joined`, and a handful of slash commands cover the rest.
 */

import * as readline from 'node:readline'
import type { Mesh } from 'fofoca-ffi'

export async function runHuman(mesh: Mesh): Promise<void> {
  console.log(`joined ${mesh.name} as ${mesh.nick}`)
  console.log(`mesh id (share to invite): ${mesh.id}`)
  console.log('type to chat · /who · /state · /merge {json} · /quit')

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })

  const messagesLoop = (async () => {
    for await (const message of mesh.messages()) {
      console.log(`${message.from}${message.directed ? ' (to you)' : ''}: ${message.text}`)
    }
  })()

  const eventsLoop = (async () => {
    for await (const event of mesh.events()) {
      switch (event.kind) {
        case 'ready':
          break
        case 'joined':
          console.log(`* ${event.nick} joined`)
          break
        case 'left':
          console.log(`* ${event.nick} left`)
          break
        case 'quiet':
          console.log(`* ${event.nick} went quiet`)
          break
        case 'returned':
          console.log(`* ${event.nick} returned`)
          break
        case 'fork':
          console.log(`! ${event.nick} forked their history (seq ${event.seq})`)
          break
        case 'info':
          console.log(`* ${event.message}`)
          break
        case 'error':
          console.log(`! ${event.message}`)
          break
        case 'closed':
          console.log(`* mesh closed: ${event.reason}`)
          rl.close()
          break
        default:
          event satisfies never
      }
    }
  })()

  for await (const line of rl) {
    const input = line.trim()
    if (input === '') {
      continue
    }
    try {
      if (input === '/quit') {
        break
      } else if (input === '/who') {
        if (mesh.peers.length === 0) {
          console.log('* nobody else is here')
        }
        for (const peer of mesh.peers) {
          const seen = peer.lastSeenSecsAgo === undefined ? '' : ` · seen ${peer.lastSeenSecsAgo}s ago`
          console.log(`* ${peer.nick} · ${peer.reach} · ${peer.transport}${peer.quiet ? ' · quiet' : ''}${seen}`)
        }
      } else if (input === '/state') {
        console.log(JSON.stringify(mesh.state.value, null, 2))
      } else if (input.startsWith('/merge ')) {
        await mesh.state.merge(JSON.parse(input.slice('/merge '.length)) as Record<string, unknown>)
        console.log('* merged')
      } else if (input.startsWith('/')) {
        console.log(`! unknown command: ${input.split(' ')[0] ?? input}`)
      } else {
        await mesh.send(input)
      }
    } catch (error) {
      console.log(`! ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  rl.close()
  await mesh.leave()
  await Promise.all([messagesLoop, eventsLoop])
}
