/**
 * What the stream page asks the engine for, from its query string. Apart from
 * `main.ts` so a test can read it: `main.ts` opens a stream at import.
 */

import type { Lookup, Transport } from 'habilis-network-wasm'

/**
 * The lookups a tab can run: the relay and pkarr. The stream CLI names all
 * four when none is given, but a tab has no multicast and no UDP, so `mdns`
 * and `dht` in its hash would be a promise it cannot keep. Naming them is not
 * harmless: the hash tells a native reader to look there, and with them the
 * stream e2e's page-to-CLI scenario never attaches (the reader reports that
 * the only path is the relay). Pkarr is on, as it is for the CLI.
 */
export const DEFAULT_LOOKUP: Lookup[] = ['relay', 'pkarr']

export interface ProducerParams {
  lookup: Lookup[]
  transport?: Transport[]
  relayUrls: string[]
  pkarrUrls: string[]
}

/**
 * - `?relay=` (repeatable) — a custom relay ladder.
 * - `?transport=udp,webrtc,relay` — what the bytes may ride.
 * - `?pkarr=<url>` (repeatable) — custom pkarr relays instead of the default
 *   list. Pkarr itself is on without it. An empty value is no value.
 */
export function producerParams(params: URLSearchParams): ProducerParams {
  // Passed through as typed: a name that is not a transport is the engine's
  // error to raise, and it names the choices.
  const transport = params.get('transport')?.split(',') as Transport[] | undefined
  return {
    lookup: DEFAULT_LOOKUP,
    ...(transport === undefined ? {} : { transport }),
    relayUrls: params.getAll('relay'),
    pkarrUrls: params.getAll('pkarr').filter((url) => url !== ''),
  }
}
