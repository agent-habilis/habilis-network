/**
 * The mesh API, as types. Both backends implement exactly this, so a program
 * moves between a browser tab and a terminal by changing one import.
 */

/** One way a mesh's members find each other. */
export type Lookup = 'mdns' | 'dht' | 'relay'

/**
 * One path a mesh's payload may ride. A list needs `udp` or `webrtc`; a
 * browser has no UDP, so it needs `webrtc` or `relay`. `multihop` (native only,
 * and it needs `udp` or `webrtc` next to it) reaches a peer with no direct path
 * through other members. `gossip` (it needs the same) reaches a peer with no
 * other path through the frames of the mesh's gossip topic.
 */
export type Transport = 'udp' | 'webrtc' | 'multihop' | 'gossip' | 'relay'

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
   * Topic only: what payload may ride, `['udp', 'webrtc']` (the default) or
   * any list with `udp` or `webrtc`. Mixed into the derived id, so every
   * member must pass the same list. Ignored when joining by id (the id
   * carries it).
   */
  transport?: Transport[]
  /**
   * Topic only: a custom relay ladder replacing the default. Mixed into the
   * derived id like `transport`. Ignored when joining by id.
   */
  relayUrls?: string[]
  /** Active-view cap (G). Omit for the engine default, 32. */
  maxPeers?: number
  /** Ceiling of direct connections (C). Omit for the engine default, 64. */
  maxDirect?: number
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
   * What payload may ride: `['udp', 'webrtc']` (the default), so all data
   * is peer to peer and the relay is a meeting point only. Leave out `udp`
   * for a mesh on WebRTC alone, or add `'relay'` to let payload fall back to
   * the relay. `'relay'`, or a list without `'udp'`, needs `'relay'` in
   * `lookup`. Baked into the mesh id, so joiners inherit it.
   */
  transport?: Transport[]
  /**
   * Which relay: an ordered ladder (first preferred) replacing the default.
   * Needs `'relay'` in `lookup`, and is part of the mesh id.
   */
  relayUrls?: string[]
  /** Active-view cap (G). Omit for the engine default, 32. */
  maxPeers?: number
  /** Ceiling of direct connections (C). Omit for the engine default, 64. */
  maxDirect?: number
}

/**
 * The lane a directed frame to a peer would take right now. Mirrors
 * `habilis_network::transport::Lane`.
 *
 * `relay-only` is the one observation among the hints: on a mesh whose relay
 * is lookup only (the default), it names a peer no payload can reach until a
 * direct path is proven. The rest are derived from the engine's own send
 * decision; iroh picks the real path at connect time.
 */
export type Lane = 'unicast' | 'multihop' | 'relay-only' | 'unreachable'

/** How near a peer is. Mirrors `habilis_network::embed::Reach`. */
export type Reach = 'direct' | 'gossip'

export interface Peer {
  /** A label. Two live peers can use one, so it names no peer; `key` does. */
  nick: string
  /** The author key: 64 lowercase hex digits. `sendToKey` takes it. */
  key: string
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
  /** The author's nickname. Two live peers can use one, so it names no author. */
  from: string
  /** The author's key: 64 lowercase hex digits. A reply goes to this key with `sendToKey`. */
  key: string
  text: string
  /** True when the message was addressed to us alone. */
  directed: boolean
}

export type MeshEvent =
  | { kind: 'ready' }
  /**
   * `key` is the author key, 64 lowercase hex digits. Two live peers can share a nickname, so
   * `nick` alone cannot tell the events of the two apart: `key` can.
   */
  | { kind: 'joined'; nick: string; key: string }
  | { kind: 'left'; nick: string; key: string }
  /** Heartbeat-evicted but still in the roster (`quiet: true`) — not `left`. */
  | { kind: 'quiet'; nick: string; key: string }
  | { kind: 'returned'; nick: string; key: string }
  /** A peer's per-author hash chain forked: two signed messages at one seq. */
  | { kind: 'fork'; nick: string; pubkey: string; seq: number }
  | { kind: 'info'; message: string }
  | { kind: 'error'; message: string }
  | { kind: 'closed'; reason: string }

export interface StateDoc {
  /**
   * The shared state: one slice per member, keyed by the lowercase hex of the author key (64
   * digits): the session key of the member, the same key as `Peer.key` and `Message.key`, not the
   * persistent member key that signs the proof of a session. Each member writes only its own slice,
   * and every member reads every slice.
   */
  readonly value: Record<string, Record<string, unknown>>
  /** Apply an RFC 7386 merge patch: set present keys, delete null keys, leave the rest. */
  merge(patch: Record<string, unknown>): Promise<void>
  changes(signal?: AbortSignal): AsyncIterable<Record<string, Record<string, unknown>>>
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
   * from `habilis_network_max_msg()`, and a module constant would mean loading the
   * native library at import time.
   */
  readonly maxMsg: number

  send(text: string, opts?: { to?: string }): Promise<void>

  /**
   * Send to the one peer that holds an author key (64 lowercase hex digits): the `key` of a
   * `Message` or of a `Peer`. `send` with `to` refuses a nickname that two live peers use; a
   * key names one peer.
   */
  sendToKey(key: string, text: string): Promise<void>

  /**
   * Every message from the moment this iterator was created. Each call gets
   * its own buffer, so two consumers never split one queue.
   */
  messages(signal?: AbortSignal): AsyncIterable<Message>
  events(signal?: AbortSignal): AsyncIterable<MeshEvent>

  leave(): Promise<void>
}
