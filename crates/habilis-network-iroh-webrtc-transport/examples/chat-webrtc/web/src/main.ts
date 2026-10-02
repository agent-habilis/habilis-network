/**
 * The tab's UI. Plain DOM — the interesting code is all in Rust next door, and
 * a framework here would only be a second thing to read before reaching it.
 */
import { loadWasm } from './wasm.ts'

/** What `ChatPeer` passes to its callback. Mirrors the `Event` enum in Rust. */
type ChatEvent =
  | { kind: 'status'; text: string }
  | { kind: 'welcome'; you: string; roster: string[] }
  | { kind: 'joined'; nick: string }
  | { kind: 'left'; nick: string }
  | { kind: 'said'; nick: string; text: string }
  | { kind: 'closed'; reason: string }

/** How often to re-read the selected path. It can move after the dial settles. */
const PATH_POLL_MS = 500

const el = <T extends HTMLElement>(id: string): T => {
  const found = document.getElementById(id)
  if (!found) throw new Error(`missing #${id}`)
  return found as T
}

const status = el<HTMLParagraphElement>('status')
const ice = el<HTMLParagraphElement>('ice')
const log = el<HTMLOListElement>('log')
const joinForm = el<HTMLFormElement>('join')
const ticketInput = el<HTMLInputElement>('ticket')
const nickInput = el<HTMLInputElement>('nick')
const compose = el<HTMLFormElement>('compose')
const textInput = el<HTMLInputElement>('text')

// The ticket rides in the fragment, which is never sent to the server: the
// capability to join stays in the browser.
const ticketFromHash = (): string => decodeURIComponent(location.hash.slice(1))
ticketInput.value = ticketFromHash()
// A hash-only navigation does not reload the document, so pasting a *new*
// room's URL into a tab that is already open leaves the old ticket in the
// field — and the tab then joins the previous room while its address bar says
// otherwise. Only before joining: once connected the field is history.
addEventListener('hashchange', () => {
  if (!joinForm.hidden) ticketInput.value = ticketFromHash()
})
// Distinct per tab, so Safari and Chrome side by side are visibly two people.
nickInput.value = suggestNick()

function suggestNick(): string {
  const agent = navigator.userAgent
  if (agent.includes('Chrome/')) return 'chrome'
  if (agent.includes('Safari/')) return 'safari'
  if (agent.includes('Firefox/')) return 'firefox'
  return 'web'
}

function say(text: string, kind: 'system' | 'message' = 'system'): void {
  const line = document.createElement('li')
  line.className = kind
  line.textContent = text
  log.append(line)
  line.scrollIntoView({ block: 'nearest' })
}

function setPath(path: string): void {
  status.dataset.path = path
  status.textContent = `connected over ${path}`
}

joinForm.addEventListener('submit', (event) => {
  event.preventDefault()
  void join(ticketInput.value.trim(), nickInput.value.trim())
})

async function join(ticket: string, nick: string): Promise<void> {
  joinForm.hidden = true
  status.textContent = 'loading…'

  let peer: Awaited<ReturnType<typeof start>>
  try {
    peer = await start(ticket, nick)
  } catch (error) {
    status.dataset.path = 'none'
    status.textContent = 'could not join'
    say(String(error))
    joinForm.hidden = false
    return
  }

  compose.hidden = false
  textInput.focus()

  compose.addEventListener('submit', (event) => {
    event.preventDefault()
    const text = textInput.value.trim()
    if (!text) return
    peer.say(text)
    // Rendered locally the moment it is sent; the room deliberately does not
    // echo a member's own messages back.
    say(`${peer.nick}: ${text}`, 'message')
    textInput.value = ''
  })

  // The path is polled rather than pushed: it is a property of the connection
  // and can change after the dial settles, which is exactly the transition
  // worth watching.
  setPath(peer.path)
  // The candidate pair is asked for repeatedly until it answers, not once when
  // the path first reads `webrtc`. Nomination is a separate event from the
  // channel opening, and it lands later on some browsers — asking a single
  // time leaves the line permanently blank on whichever browser happens to be
  // slower, which reads as "no ICE pair" rather than "asked too early".
  let icePending = false
  setInterval(() => {
    setPath(peer.path)
    if (peer.path !== 'webrtc' || ice.textContent || icePending) return
    icePending = true
    void peer
      .icePair()
      .then((pair) => {
        if (pair) ice.textContent = `ice ${pair}`
      })
      .finally(() => {
        icePending = false
      })
  }, PATH_POLL_MS)

  addEventListener('pagehide', () => peer.close())
}

async function start(ticket: string, nick: string) {
  const { ChatPeer } = await loadWasm()
  return ChatPeer.join(ticket, nick, (event: ChatEvent) => {
    switch (event.kind) {
      case 'status':
        status.textContent = `${event.text}…`
        break
      case 'welcome':
        say(`you are "${event.you}" — in the room: ${event.roster.join(', ')}`)
        break
      case 'joined':
        say(`${event.nick} joined`)
        break
      case 'left':
        say(`${event.nick} left`)
        break
      case 'said':
        say(`${event.nick}: ${event.text}`, 'message')
        break
      case 'closed':
        status.dataset.path = 'none'
        status.textContent = 'disconnected'
        say(`disconnected: ${event.reason}`)
        break
    }
  })
}
