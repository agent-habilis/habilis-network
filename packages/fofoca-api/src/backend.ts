/**
 * The seam the two backends implement.
 *
 * Deliberately the narrowest thing a wasm `MeshPeer` and a worker-thread RPC
 * client can both satisfy, because everything above this line — the fan-out
 * queues, the roster cache, the UTF-8 decode, the `AbortSignal` plumbing, the
 * `AsyncDisposable` wiring — is written once and shared. A backend that grows a
 * second way to do any of that is a backend that can disagree with the other.
 */

import type { MeshEvent } from './types.ts'

export interface BackendMsg {
  readonly from: string
  readonly text: string
  readonly directed: boolean
}

/**
 * What a backend pushes up.
 *
 * Every method is synchronous and must never throw: these are called from a
 * worker `message` handler and from a wasm-bindgen callback, neither of which
 * has anywhere to put an exception.
 */
export interface BackendSink {
  msg(msg: BackendMsg): void
  /**
   * A `RosterSnapshot` JSON document, verbatim. Push freely and often — an
   * identical document is discarded on a string compare before any parse.
   */
  roster(json: string): void
  /** The shared state document as JSON. Same push-freely rule. */
  state(json: string): void
  /**
   * A peer arrived or departed, for a backend that is told rather than one that
   * has to notice. Only called when [`BackendOpen.pushesPresence`] is set.
   */
  presence(event: { kind: 'joined' | 'left'; nick: string }): void
  /** A failure with no caller waiting on it. Surfaces as `error`; the mesh stays open. */
  failed(message: string): void
  /**
   * Any other surfaced event (`quiet`, `returned`, `fork`, `info`). Optional:
   * a backend with no richer event stream than presence simply never calls
   * it, and `openMesh` wires it only when present.
   */
  event?(event: MeshEvent): void
  /** The mesh is gone and no further push will arrive. Idempotent. */
  closed(reason: string): void
}

export interface MeshBackend {
  readonly id: string
  readonly name: string
  /** The nickname the *engine* assigned, which is not always the one requested. */
  readonly nick: string
  /** The longest message in bytes that always fits one frame. */
  readonly maxMsg: number

  send(to: string | null, text: string): Promise<void>
  /**
   * Apply an RFC 7386 merge document, and resolve with the *resulting* state
   * JSON.
   *
   * Resolving with the document rather than `void` is what makes
   * `await mesh.state.merge(patch)` followed by `mesh.state.value` see the
   * patch. On the FFI backend the next state poll is up to half a second away,
   * and a read-after-write that reads stale is the worst kind of footgun.
   */
  stateMerge(patchJson: string): Promise<string>
  close(): Promise<void>
}

export interface BackendOpen {
  readonly backend: MeshBackend
  /**
   * The roster and state as of open, so `peers` and `state.value` are never
   * accidentally empty. Returned rather than pushed because the type system can
   * then catch a backend that forgot.
   */
  readonly rosterJson: string
  readonly stateJson: string
  /**
   * Whether this backend calls [`BackendSink.presence`] itself.
   *
   * The browser backend does: the engine surfaces a peer's arrival and
   * departure through its own sink, already gated on the join horizon and
   * already exactly-once, and a roster diff would be strictly worse — it would
   * announce peers learned from pre-join backlog, which the engine suppresses
   * on purpose.
   *
   * The C ABI has no callback at all, so its backend sets this `false` and
   * `openMesh` derives the same two events by diffing successive rosters. Same
   * events, worse latency. Do not fix that by changing the C ABI, which
   * mallorca already links against.
   */
  readonly pushesPresence: boolean
}

/**
 * Opening a mesh: hand the backend a sink and get the handle back.
 *
 * `sink` is passed *in* rather than returned alongside, so a message arriving
 * during open has somewhere to land before the promise resolves.
 */
export type Opener = (sink: BackendSink) => Promise<BackendOpen>

/** Re-exported for backends assembling their own event objects. */
export type { MeshEvent }
