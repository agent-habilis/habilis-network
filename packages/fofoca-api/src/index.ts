/**
 * The fofoca mesh API.
 *
 * This package is the contract and the machinery, not a way to join a mesh.
 * Import `fofoca-wasm` in a browser tab or `fofoca-ffi` in a terminal; both
 * re-export everything here and add `join` / `create`.
 */

export type {
  CreateOpts,
  JoinOpts,
  Lane,
  Lookup,
  Mesh,
  MeshEvent,
  Message,
  Peer,
  Reach,
  StateDoc,
  Transport,
} from './types.ts'

export { randomNick, randomTopic } from './random.ts'
export { MeshOverflowError } from './fanout.ts'

// The seam. A consumer never needs these; a third backend would.
export type {
  BackendMsg,
  BackendOpen,
  BackendSink,
  MeshBackend,
  Opener,
} from './backend.ts'
export { openMesh } from './mesh.ts'
export { parseRoster, rosterPresence } from './roster.ts'
export { DEFAULT_CAPACITY, Fanout } from './fanout.ts'
