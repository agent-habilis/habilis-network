/**
 * The mesh API, as types. Both backends implement exactly this, so a program
 * moves between a browser tab and a terminal by changing one import.
 */

/** One way a mesh's members find each other. */
export type Lookup = 'mdns' | 'dht' | 'relay'

/** One path a mesh's payload may ride. `p2p` is always on. */
export type Transport = 'p2p' | 'relay'

export interface JoinOpts {
  /**
   * Derive a mesh from a shared string. Everyone who passes the same string
   * lands in the same mesh.
   *
   * A topic mesh is always reached over the public preset — mDNS, the mainline
   * DHT and the pinned relay ladder. That is not a default you can change: the
   * derivation mixes the lookups into the mesh id, so two reaches over one
   * string are two different meshes that never meet. Hence no discovery flags
   * here.
   */
  topic?: string
  /** Join this mesh id. The id is the bearer credential — treat it as a secret. */
  id?: string
  /** Defaults to a random `word-word` nickname. */
  nick?: string
  /**
   * Topic only: what payload may ride, `['p2p']` (the default) or
   * `['p2p', 'relay']`. Mixed into the derived id, so every member must pass
   * the same list. Ignored when joining by id (the id carries it).
   */
  transport?: Transport[]
  /**
   * Topic only: a custom relay ladder replacing the default. Mixed into the
   * derived id like `transport`. Ignored when joining by id.
   */
  relayUrls?: string[]
  /** Active-view cap. Omit for the engine default. */
  maxPeers?: number
}

export interface CreateOpts {
  name?: string
  nick?: string
  /**
   * How members find each other. Naming any uses only those; naming none
   * is not "the default set" — it is a loopback mesh, reachable only from
   * this machine, which is useful for tests and surprising everywhere else.
   * `['mdns', 'dht', 'relay']` is the all-on set a topic uses.
   */
  lookup?: Lookup[]
  /**
   * What payload may ride: `['p2p']` (the default), so all data is peer to
   * peer and the relay is a meeting point only, or `['p2p', 'relay']` to let
   * payload fall back to the relay. `'relay'` needs `'relay'` in `lookup`.
   * Baked into the mesh id, so joiners inherit it.
   */
  transport?: Transport[]
  /**
   * Which relay: an ordered ladder (first preferred) replacing the default.
   * Needs `'relay'` in `lookup`, and is part of the mesh id.
   */
  relayUrls?: string[]
  /**
   * This node's own paths. Per node, not part of the id; everything the
   * target has is on by default.
   */
  paths?: { ip?: boolean; webrtc?: boolean }
  maxPeers?: number
}

/**
 * The lane a directed frame to a peer would take right now. Mirrors
 * `fofoca::transport::Lane`.
 *
 * `relay-only` is the one observation among the hints: on a mesh whose relay
 * is lookup only (the default), it names a peer no payload can reach until a
 * direct path is proven. The rest are derived from the engine's own send
 * decision; iroh picks the real path at connect time.
 */
export type Lane = 'unicast' | 'multihop' | 'relay-only' | 'unreachable'

/** How near a peer is. Mirrors `fofoca::embed::Reach`. */
export type Reach = 'direct' | 'gossip'

export interface Peer {
  nick: string
  reach: Reach
  transport: Lane
  /** Heartbeat-evicted, but still known and still returnable. */
  quiet: boolean
  /** Absent until the peer's first heartbeat is timed. */
  lastSeenSecsAgo?: number
}

/**
 * One inbound message: a whole text, as it was sent. Bulk bytes do not ride
 * the mesh; they take a stream.
 */
export interface Message {
  from: string
  text: string
  /** True when the message was addressed to us alone. */
  directed: boolean
}

export type MeshEvent =
  | { kind: 'ready' }
  | { kind: 'joined'; nick: string }
  | { kind: 'left'; nick: string }
  /** Heartbeat-evicted but still in the roster (`quiet: true`) — not `left`. */
  | { kind: 'quiet'; nick: string }
  | { kind: 'returned'; nick: string }
  /** A peer's per-author hash chain forked: two signed messages at one seq. */
  | { kind: 'fork'; nick: string; pubkey: string; seq: number }
  | { kind: 'info'; message: string }
  | { kind: 'error'; message: string }
  | { kind: 'closed'; reason: string }

export interface StateDoc {
  /** The converged document. A CRDT underneath, so concurrent writers merge. */
  readonly value: Record<string, unknown>
  /** Apply an RFC 7386 merge patch: set present keys, delete null keys, leave the rest. */
  merge(patch: Record<string, unknown>): Promise<void>
  changes(signal?: AbortSignal): AsyncIterable<Record<string, unknown>>
}

export interface Mesh extends AsyncDisposable {
  readonly id: string
  readonly name: string
  /** The nickname the engine assigned, which is not always the one requested. */
  readonly nick: string
  readonly peers: Peer[]
  readonly state: StateDoc
  /**
   * The longest message in bytes that always fits one frame. Most text fits
   * well past it; a message that does not fit is refused by `send`, not split.
   *
   * On the mesh rather than a module constant because the FFI backend learns it
   * from `fofoca_max_msg()`, and a module constant would mean loading the
   * native library at import time.
   */
  readonly maxMsg: number

  send(text: string, opts?: { to?: string }): Promise<void>

  /**
   * Every message from the moment this iterator was created. Each call gets
   * its own buffer, so two consumers never split one queue.
   */
  messages(signal?: AbortSignal): AsyncIterable<Message>
  events(signal?: AbortSignal): AsyncIterable<MeshEvent>

  leave(): Promise<void>
}
