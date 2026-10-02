import { WORDS } from './wordlist.ts'

/**
 * `WORDS.length` is a power of two, so masking a uniform 16-bit draw is exactly
 * unbiased — no rejection loop, no modulo skew. `wordlist.ts` asserts the power
 * of two at module load, which is what keeps that true.
 */
const MASK = WORDS.length - 1

function words(count: number): string[] {
  const draws = new Uint16Array(count)
  crypto.getRandomValues(draws)
  return Array.from(draws, (draw) => WORDS[draw & MASK] as string)
}

/**
 * A fresh `word-word` nickname.
 *
 * Two words, matching `Nickname::random`. A nickname collision is cosmetic —
 * the engine uniquifies and the mesh carries on — so 2^20 is plenty.
 */
export function randomNick(): string {
  return words(2).join('-')
}

/**
 * A fresh `word-word-word` topic string.
 *
 * Three words, unlike a nickname, because a topic is a public rendezvous: it is
 * the whole credential, and anyone who guesses it is in the room. Two words is
 * 2^20, whose birthday bound puts a coin-flip collision at roughly 1,200
 * concurrent rooms — reachable by a demo. Three is 2^30, and
 * `amber-cipher-quiver` still reads aloud and still fits `MeshName`'s 32-char
 * cap.
 */
export function randomTopic(): string {
  return words(3).join('-')
}
