/*
 * fofoca.h — the C ABI of the fofoca engine.
 *
 * Hand-written, and the counterpart of `src/ffi.rs`: change one, change the
 * other. `tests/ffi_smoke.rs` exercises the same entry points from Rust, so a
 * mismatch fails a test rather than corrupting a caller's stack.
 *
 * Link against either artifact the crate builds — a cdylib for a dynamically
 * linked caller, or the staticlib an embedder links into its own binary:
 *
 *     cargo build --release -p fofoca-ffi
 *     cc prog.c -I<repo>/crates/fofoca-ffi/include \
 *        -L<repo>/target/release -lfofoca_ffi
 *
 * Conventions
 * -----------
 * - A pointer-returning call yields NULL on failure; an `int` call returns 0 on
 *   success and -1 on failure. `fofoca_last_error()` then holds the reason.
 * - Every call is blocking and thread-confined: one handle belongs to one
 *   thread. Distinct handles are independent (a single process may hold several,
 *   each with its own runtime and endpoint).
 * - A handle from fofoca_mesh_open() must be released with fofoca_mesh_close().
 */
#ifndef FOFOCA_H
#define FOFOCA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* An opaque live membership. */
typedef struct fofoca_mesh fofoca_mesh;

/*
 * How to reach a mesh. Zero-initialize, then set at most one selector:
 *
 *   - `mesh`  — join this mesh id.
 *   - `topic` — derive a public mesh from a shared string (all peers passing the
 *               same string land in the same mesh).
 *   - neither — create a fresh mesh; `lookup` says how far it reaches, and
 *               fofoca_mesh_id() returns the minted id.
 *
 * Three comma-separated lists name the mesh-wide choices a create bakes into
 * the id, one concept each: `lookup` is how members find each other,
 * `transport` is what payload may ride, `relay_urls` is which relay. A joiner
 * inherits all three from the id; a topic fixes `lookup` to all three lookups.
 *
 * String fields are NUL-terminated or NULL. `max_peers == 0` takes the engine's
 * default active-view cap.
 */
typedef struct {
  const char *mesh;
  const char *topic;
  const char *nick;       /* NULL mints a random nickname */
  const char *name;       /* mesh name on create; NULL falls back to "fofoca" */
  const char *lookup;     /* "mdns,dht,relay", any subset; NULL = none, a
                             loopback mesh reachable from this machine only */
  const char *transport;  /* "udp,webrtc,relay", any subset with "udp" or
                             "webrtc"; NULL = "udp,webrtc", so every byte of
                             data goes peer to peer. "relay", or a list without
                             "udp", needs "relay" in `lookup` */
  const char *relay_urls; /* comma-separated custom relay ladder; NULL = the
                             default. Needs "relay" in `lookup` */
  size_t max_peers;
} fofoca_opts;

/*
 * Metadata for one received message. The text lands NUL-terminated in the
 * caller's buffer; `len` is its length in bytes, excluding the NUL.
 */
typedef struct {
  char nick[64];  /* the author's nickname, truncated to 63 bytes if longer */
  int directed;   /* 1 = addressed to us specifically, 0 = broadcast */
  size_t len;
} fofoca_msg;

/* Create or join a mesh. NULL on failure. */
fofoca_mesh *fofoca_mesh_open(const fofoca_opts *opts);

/* Identity of this membership, borrowed for the handle's lifetime. */
const char *fofoca_mesh_id(const fofoca_mesh *handle);
const char *fofoca_mesh_name(const fofoca_mesh *handle);
const char *fofoca_mesh_nickname(const fofoca_mesh *handle);

/*
 * Send one message, a NUL-terminated UTF-8 text. `to` NULL broadcasts to the
 * whole mesh; otherwise it is a peer nickname and only that peer receives it.
 * A message must fit one frame: fofoca_max_msg() bytes always do, most text
 * fits well past that, and a message that does not fit is refused, not split.
 * Bulk bytes belong on a stream.
 */
int fofoca_msg_send(fofoca_mesh *handle, const char *to, const char *text);

/*
 * Take the next inbound message, waiting up to `timeout_ms`. Returns 1 with the
 * text NUL-terminated in `buf` and `out` filled, 0 on timeout, -1 on failure,
 * or -2 when the text does not fit in `cap`: nothing is written to `buf`, the
 * message stays queued, and `out->len` holds its length — retry with a buffer
 * of at least `out->len + 1` bytes.
 */
long fofoca_msg_recv(fofoca_mesh *handle, char *buf, size_t cap, int timeout_ms,
                     fofoca_msg *out);

/*
 * The shared state document — a JSON object every peer in the mesh converges on
 * (a CRDT underneath, so concurrent writers merge instead of clobbering).
 *
 * fofoca_mesh_state_merge() applies an RFC 7386 merge document: present keys are set,
 * keys set to null are removed, everything else is left alone.
 *
 * fofoca_mesh_state_json() writes the merged document into `buf` and returns the length
 * it needs, excluding the NUL. When that does not fit in `cap`, nothing is
 * written — retry with a bigger buffer. -1 on failure.
 */
int fofoca_mesh_state_merge(fofoca_mesh *handle, const char *json);
long fofoca_mesh_state_json(fofoca_mesh *handle, char *buf, size_t cap);

/* The live peer roster as JSON. Same length/`cap` convention as above. */
long fofoca_mesh_peers_json(fofoca_mesh *handle, char *buf, size_t cap);

/*
 * How many peers other than you are in the mesh right now; 0 means you are
 * alone. -1 on failure.
 *
 * Deliberately NOT the roster JSON's own "count" field, which includes you and
 * so never reads 0. This is the question a sender waiting for company has, and
 * the answer it can loop on.
 */
long fofoca_mesh_peer_count(fofoca_mesh *handle);

/*
 * Leave the mesh and free the handle. The handle is freed even when this returns
 * -1, so it must not be used again. Passing NULL is a no-op that returns 0.
 */
int fofoca_mesh_close(fofoca_mesh *handle);

/*
 * Byte streams
 * ------------
 * A producer creates a stream and hands its hash to one consumer, which opens
 * it. The bytes ride one QUIC stream on a direct path by default (hole-punched
 * UDP, or a WebRTC data channel), on the relay only when the stream's
 * `transport` names it, and never on the mesh's gossip. A stream admits exactly one
 * consumer; a second is refused. The hash is a bearer ticket: whoever holds it
 * can take that one slot.
 *
 * A node, its producers and its readers are separate handles, each released
 * with its own close; they can be closed in any order.
 */
typedef struct fofoca_streams fofoca_streams;
typedef struct fofoca_producer fofoca_producer;
typedef struct fofoca_reader fofoca_reader;

/* How a stream node reaches peers: the same lists as fofoca_opts, without the
 * mesh selectors. Zero-initialize for a loopback node. */
typedef struct {
  const char *lookup;     /* "mdns,dht,relay", any subset; NULL = loopback */
  const char *transport;  /* "udp,webrtc,relay", as fofoca_opts; NULL = "udp,webrtc" */
  const char *relay_urls; /* comma-separated custom relay ladder; NULL = default */
} fofoca_stream_opts;

/* Stand up a stream node. NULL on failure. */
fofoca_streams *fofoca_streams_bind(const fofoca_stream_opts *opts);

/* A node that can reach the producer of `hash` (its lookups and relay policy). */
fofoca_streams *fofoca_streams_bind_for(const char *hash);

/* Shut a node down; streams still open on it are abandoned. NULL is a no-op. */
int fofoca_streams_close(fofoca_streams *streams);

/* Open a new stream. With a relay lookup, blocks (at most 5 s, once) until the
 * node reaches its home relay, so the hash carries it. Release it with
 * fofoca_stream_close(). NULL on failure. */
fofoca_producer *fofoca_stream_create(fofoca_streams *streams);

/* The hash the one consumer opens the stream with, borrowed for the producer's
 * lifetime. */
const char *fofoca_stream_hash(const fofoca_producer *producer);

/*
 * Write all `len` bytes. Returns 1 once written, 0 when no consumer attached
 * within `timeout_ms` (nothing was written), -1 on failure (the consumer went
 * away). Once a consumer has attached, the call runs until every byte is out,
 * paced by the consumer.
 */
int fofoca_stream_write(fofoca_producer *producer, const uint8_t *buf, size_t len,
                        int timeout_ms);

/*
 * End the stream and free the producer. With a consumer attached, it reads
 * everything written and then the end of stream; with none, the stream is
 * abandoned and a later consumer is refused. Freed even on -1.
 */
int fofoca_stream_close(fofoca_producer *producer);

/* Take the consumer slot of the stream behind `hash`. NULL on failure: the
 * producer cannot be reached, or refuses the hash. */
fofoca_reader *fofoca_stream_open(fofoca_streams *streams, const char *hash);

/*
 * Read the next bytes, waiting up to `timeout_ms`. Returns how many bytes were
 * written to `buf` (> 0), 0 on timeout, -1 on failure (the producer refused or
 * abandoned the stream, or the link was lost), or -2 at the end of the stream.
 * Bytes that do not fit in `cap` wait for the next call.
 */
long fofoca_stream_read(fofoca_reader *reader, uint8_t *buf, size_t cap, int timeout_ms);

/* Free a reader, giving up the stream. NULL is a no-op. */
int fofoca_reader_close(fofoca_reader *reader);

/*
 * Why the most recent call on this thread failed, or NULL if it succeeded.
 * Borrowed until this thread's next fofoca_* call, so copy it to keep it.
 */
const char *fofoca_last_error(void);

/* The engine's build version stamp. Borrowed for the process's lifetime. */
const char *fofoca_version(void);

/* The longest text in bytes fofoca_msg_send() always accepts. */
size_t fofoca_max_msg(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FOFOCA_H */
