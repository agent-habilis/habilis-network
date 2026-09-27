/**
 * Bind a dev server on the first free port of a short ladder.
 *
 * A port the caller named is bound exactly or not at all: a moved server on a
 * port somebody asked for, or on the one the e2e harness polls, is a silent
 * wrong answer. Only the default climbs, so a stale server left on it costs a
 * different URL in the startup log instead of a crash.
 *
 * Three identical copies: `scripts/`, and `scripts/` under the light-cycles
 * and chat-webrtc web examples, which are Bun workspaces of their own and
 * cannot import across. Change all three together.
 */

const RUNGS = 10

export function serveOnLadder<Server>(
  explicit: number | undefined,
  first: number,
  bind: (port: number) => Server,
): Server {
  if (explicit !== undefined) return bind(explicit)
  for (let port = first; port < first + RUNGS; port++) {
    try {
      return bind(port)
    } catch (error) {
      if ((error as { code?: unknown }).code !== 'EADDRINUSE') throw error
    }
  }
  console.error(`ports ${first}-${first + RUNGS - 1} are all in use; pass one explicitly`)
  process.exit(1)
}
