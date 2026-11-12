// One line of metrics per run folder of run.ts.
//
// usage: bun scripts/perf/summarize.ts <run dir> [<run dir> ...]
//
// Reads summary.txt (the last census line of each node), the n<i>.err logs, host.log
// and canary.log. The fields:
//
// - full / isolated / roster_med / min: how many nodes hold the whole roster, how many
//   hold none, and the median and the least roster, out of N nodes.
// - stalls / longest_s: `maintenance timer stalled` warnings, and the longest gap.
// - up / down: `gossip neighbor up` and `gossip neighbor down` lines of all nodes, the
//   link churn of the run.
// - drop_nodes / worst_drop: nodes that logged a dropped data message (the send queue of
//   a connection was full), and the worst count a node logged (a lower bound: the log
//   line appears at each power of two).
// - disc_nodes / worst_disc: the same for `send_overflow_disconnects`.
// - resent / resend_dropped: the sum of the `idle_resent` and `idle_resend_dropped`
//   deltas of every census line, which is the total over the run.
// - census_lines: the census lines of all nodes. Divide a total below by it for a mean per node
//   and interval (10 s).
// - cpu_ms / wakeups / dup / fresh: the sums of the `cpu_ms`, `idle_wakeups`,
//   `idle_duplicates` and `idle_fresh` deltas of every census line.
// - wire_in / body_in / frames_in / wire_out / body_out / frames_out: the sums of the `idle_wire_in`,
//   `idle_body_in`, `idle_frames_in`, `idle_wire_out`, `idle_body_out` and `idle_frames_out`
//   deltas (the `wire census` line). The wire is the frame as it goes on a socket; the body is its
//   payload as written in the JSON. Out counts a broadcast once, not once per neighbor.
// - d_share / d_by_kind: D, the bytes of content that came again over all bytes received: the
//   repeats that the dedup caught (`idle_bin_dup`) plus the frames that were new by id but carried
//   a change that the document had applied (`idle_bin_cdup`), by kind and in all. cdup is
//   part of the fresh bytes, so it is added to dup, not subtracted from fresh.
// - net_send_ip / net_send_relay / net_recv_ip / net_recv_relay / net_recv_custom / net_recv_dgrams /
//   net_hdr_in: the sums of the `idle_net_*` deltas: the UDP payload that the iroh socket sent and
//   received (all of QUIC: frames, acknowledgements, keep-alives, handshakes), the datagrams
//   received, and 28 bytes of IPv4 and UDP header per received datagram. The first census of a node
//   covers the time since its endpoint started. There is no send counter for the custom transports.
// - net_paths_custom / net_ip_added / net_ip_removed / net_relay_added / net_relay_removed /
//   net_custom_added / net_custom_removed: the sums of the `idle_net_*` path counters: custom paths
//   made, and paths opened and closed by kind of transport (a custom path is a WebRTC, multihop or
//   gossip path).
// - gt_frames_out / gt_bytes_out / gt_frames_in / gt_bytes_in / gt_not_for_us / gt_dropped: the sums
//   of the `idle_gt_*` deltas: the gossip transport, which carries QUIC packets as frames on the mesh
//   topic for a pair with no other path. All zero when the mesh has none. gt_of_udp_in / gt_of_udp_out:
//   its bytes over the socket bytes of the same direction.
// - gm_ctrl_out / gm_data_out / gm_ctrl_in / gm_data_in: the sums of the `idle_gm_*` deltas: the bytes of
//   the iroh-gossip protocol messages that the gossip actor wrote and read, control (membership and
//   ihave, graft, prune) and data (the `gossip` message, which carries our frames), with the 4 bytes of
//   length prefix of each. A broadcast is counted once per neighbor it is written to. gm_of_udp_in /
//   gm_of_udp_out: the gossip layer over the socket bytes of the same direction. gm_ctrl_share_*:
//   the control share of the gossip bytes. gm_bin / gm_bout / gm_nin / gm_nout: `variant:value` sums
//   by variant (join, forward_join, shuffle, shuffle_reply, neighbor, disconnect, gossip, ihave, graft,
//   prune): bytes in, bytes out, messages in, messages out.
// - frames_of_udp_in / frames_of_udp_out: wire_in and wire_out over the socket bytes of the same
//   direction. The rest is below our frames: gossip messages, QUIC framing, acknowledgements, keep-alives.
//   Out counts a broadcast once, so it understates the frames by the fan-out.
// - dup_share: the bytes of the frames that the dedup dropped as repeats, over all frames of the
//   kinds that reached it. env_in / env_out: 1 - body / wire, the share of the envelope.
// - bin_fresh / bin_dup / bin_cdup / bout: `kind:bytes` sums, by kind of frame (app, presence, peerinfo,
//   state, meta, linkstate, pingpong, shard, other), largest first.
//   tags_in / tags_out: the same for the tags of the app frames.
// - dup_by_path: the repeats of bin_dup as `arrival.kind:bytes`. The arrival is gossip or unicast: the plane. The overlay keeps a gossip message id
//   for 90 s (message_id_retention) per subscription and drops a repeat in that time, so a plain repeat on the
//   gossip plane is a copy after the 90 s or after a resubscribe, which replays frames. No eager or lazy copy
//   inside the 90 s is in it.
// - ext_<arm>: the sums of the `idle_ext_<arm>` deltas, the wakes of each arm that is not a timer.
//   Only the arms that woke.
// - ahead_max: the largest `idle_ahead_peers` gauge of any census line.
// - mem_med / mem_max: peak resident memory of the nodes, in MB.
// - load1 median and max, from host.log; canary pauses of the host over 0.5 s.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { median, show } from "./pyformat/pyformat";

const clean = (text: string) => text.replace(/\x1b\[[0-9;]*m/g, "");

const numbers = (text: string, pattern: RegExp): number[] =>
  [...text.matchAll(new RegExp(pattern.source, "g"))].map((m) => Number(m[1]));

const sum = (values: number[]): number => values.reduce((a, b) => a + b, 0);

// The census fields that are per-interval deltas, summed over a run: the summary name, then the
// census field.
const TOTALS: [string, string][] = [
  ["cpu_ms", "cpu_ms"],
  ["wakeups", "idle_wakeups"],
  ["dup", "idle_duplicates"],
  ["fresh", "idle_fresh"],
  ["wire_in", "idle_wire_in"],
  ["body_in", "idle_body_in"],
  ["frames_in", "idle_frames_in"],
  ["wire_out", "idle_wire_out"],
  ["body_out", "idle_body_out"],
  ["frames_out", "idle_frames_out"],
  ["net_send_ip", "idle_net_send_ip"],
  ["net_send_relay", "idle_net_send_relay"],
  ["net_recv_ip", "idle_net_recv_ip"],
  ["net_recv_relay", "idle_net_recv_relay"],
  ["net_recv_custom", "idle_net_recv_custom"],
  ["net_recv_dgrams", "idle_net_recv_dgrams"],
  ["net_hdr_in", "idle_net_hdr_in"],
  ["net_paths_custom", "idle_net_paths_custom"],
  ["net_ip_added", "idle_net_ip_added"],
  ["net_ip_removed", "idle_net_ip_removed"],
  ["net_relay_added", "idle_net_relay_added"],
  ["net_relay_removed", "idle_net_relay_removed"],
  ["net_custom_added", "idle_net_custom_added"],
  ["net_custom_removed", "idle_net_custom_removed"],
  ["gt_frames_out", "idle_gt_frames_out"],
  ["gt_bytes_out", "idle_gt_bytes_out"],
  ["gt_frames_in", "idle_gt_frames_in"],
  ["gt_bytes_in", "idle_gt_bytes_in"],
  ["gt_not_for_us", "idle_gt_not_for_us"],
  ["gt_dropped", "idle_gt_dropped"],
  ["gm_ctrl_out", "idle_gm_ctrl_out"],
  ["gm_data_out", "idle_gm_data_out"],
  ["gm_ctrl_in", "idle_gm_ctrl_in"],
  ["gm_data_in", "idle_gm_data_in"],
];

// A census field of `name:bytes` pairs joined by commas (`app:120,presence:40`, or `-`): add the
// bytes of each name into `into`.
function addPairs(text: string, field: string, into: Map<string, number>): void {
  for (const found of text.matchAll(new RegExp(`\\b${field}=(\\S+)`, "g"))) {
    for (const pair of (found[1] ?? "").split(",")) {
      const colon = pair.lastIndexOf(":");
      if (colon <= 0) continue;
      const name = pair.slice(0, colon);
      into.set(name, (into.get(name) ?? 0) + Number(pair.slice(colon + 1)));
    }
  }
}

const pairsText = (pairs: Map<string, number>): string =>
  [...pairs]
    .sort(([a, x], [b, y]) => y - x || a.localeCompare(b))
    .map(([name, bytes]) => `${name}:${bytes}`)
    .join(",") || "-";

const total = (pairs: Map<string, number>): number => sum([...pairs.values()]);
const percent = (part: number, whole: number): string =>
  whole > 0 ? `${((100 * part) / whole).toFixed(1)}%` : "-";

// Python's str.split("\n") in a line loop: a final newline does not make an extra line.
const lines = (text: string): string[] => {
  const parts = text.split("\n");
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts;
};

function summarize(run: string): string {
  const summaryFile = `${run}/summary.txt`;
  const rows = (existsSync(summaryFile) ? lines(readFileSync(summaryFile, "utf8")) : []).map(
    (line) => Object.fromEntries([...line.matchAll(/(\w+)=(\d+)/g)].map((m) => [m[1], m[2]])),
  );
  const census = rows.filter((row) => "roster_len" in row);
  // The runner writes no per-node row to summary.txt, so the roster of a node is read from its own log: the
  // roster_len of its last mesh census.
  const lastRosterOf = (file: string): number[] => {
    const last = [...clean(readFileSync(`${run}/${file}`, "utf8")).matchAll(/mesh census roster_len=(\d+)/g)].at(-1);
    return last?.[1] === undefined ? [] : [Number(last[1])];
  };
  const nodeLogs = readdirSync(run).filter((f) => /^n.*\.err$/.test(f));
  const roster = census.length ? census.map((row) => Number(row.roster_len)) : nodeLogs.flatMap(lastRosterOf);
  const mem = census
    .filter((row) => "peak_resident_memory_mb" in row)
    .map((row) => Number(row.peak_resident_memory_mb));
  // Only a per-node row counts: the aggregate summary of an earlier pass has no `roster_len`.
  const n = census.length || nodeLogs.length;

  const stalls: number[] = [];
  const drops = new Map<string, number>();
  const discs = new Map<string, number>();
  let up = 0;
  let down = 0;
  let resent = 0;
  let resendDropped = 0;
  let censusLines = 0;
  const totals = new Map<string, number>(TOTALS.map(([name]) => [name, 0]));
  const ext = new Map<string, number>();
  const kinds = {
    fresh: new Map<string, number>(),
    dup: new Map<string, number>(),
    cdup: new Map<string, number>(),
    dupBy: new Map<string, number>(),
    out: new Map<string, number>(),
    tagsIn: new Map<string, number>(),
    tagsOut: new Map<string, number>(),
    gmBytesOut: new Map<string, number>(),
    gmBytesIn: new Map<string, number>(),
    gmCountOut: new Map<string, number>(),
    gmCountIn: new Map<string, number>(),
  };
  const ahead: number[] = [];
  for (const file of readdirSync(run).filter((f) => /^n.*\.err$/.test(f))) {
    const text = clean(readFileSync(`${run}/${file}`, "utf8"));
    stalls.push(...numbers(text, /timer stalled[^\n]*?mono_gap_ms=(\d+)/));
    const found = numbers(text, /dropped a data message[^\n]*?dropped=(\d+)/);
    if (found.length > 0) drops.set(file, Math.max(...found));
    const refused = numbers(text, /send queue of the peer refused[^\n]*?disconnects=(\d+)/);
    if (refused.length > 0) discs.set(file, Math.max(...refused));
    up += text.split("gossip neighbor up").length - 1;
    down += text.split("gossip neighbor down").length - 1;
    resent += numbers(text, /idle_resent=(\d+)/).reduce((a, b) => a + b, 0);
    resendDropped += numbers(text, /idle_resend_dropped=(\d+)/).reduce((a, b) => a + b, 0);
    censusLines += numbers(text, /idle_wakeups=(\d+)/).length;
    for (const [name, field] of TOTALS) {
      totals.set(name, (totals.get(name) ?? 0) + sum(numbers(text, new RegExp(`\\b${field}=(\\d+)`))));
    }
    // An older census writes the CPU time as `cpu_user_ms` and `cpu_sys_ms`: the same total, in two fields.
    const split = sum(numbers(text, /\bcpu_user_ms=(\d+)/)) + sum(numbers(text, /\bcpu_sys_ms=(\d+)/));
    totals.set("cpu_ms", (totals.get("cpu_ms") ?? 0) + split);
    for (const arm of text.matchAll(/\bidle_ext_(\w+?)=(\d+)/g)) {
      ext.set(arm[1] ?? "", (ext.get(arm[1] ?? "") ?? 0) + Number(arm[2]));
    }
    addPairs(text, "idle_bin_fresh", kinds.fresh);
    addPairs(text, "idle_bin_dup", kinds.dup);
    addPairs(text, "idle_bin_cdup", kinds.cdup);
    addPairs(text, "idle_bin_dup_path", kinds.dupBy);
    addPairs(text, "idle_bout", kinds.out);
    addPairs(text, "idle_bin_tags", kinds.tagsIn);
    addPairs(text, "idle_bout_tags", kinds.tagsOut);
    addPairs(text, "idle_gm_bout", kinds.gmBytesOut);
    addPairs(text, "idle_gm_bin", kinds.gmBytesIn);
    addPairs(text, "idle_gm_nout", kinds.gmCountOut);
    addPairs(text, "idle_gm_nin", kinds.gmCountIn);
    ahead.push(...numbers(text, /\bidle_ahead_peers=(\d+)/));
  }

  const loads: number[] = [];
  if (existsSync(`${run}/host.log`)) {
    for (const line of lines(readFileSync(`${run}/host.log`, "utf8"))) {
      const found = line.match(/load=\s*([0-9.]+)/);
      if (found) loads.push(Number(found[1]));
    }
  }
  let gaps: string[] = [];
  if (existsSync(`${run}/canary.log`)) {
    gaps = [...readFileSync(`${run}/canary.log`, "utf8").matchAll(/gap_s=([0-9.]+)/g)].map((m) => m[1] ?? "");
  }

  const rosterMed = roster.length ? show(median(roster, false)) : "-";
  const rosterMin = roster.length ? String(Math.min(...roster)) : "-";
  const memMed = mem.length ? show(median(mem, false)) : "-";
  const memMax = mem.length ? String(Math.max(...mem)) : "-";
  const loadMed = loads.length ? show(median(loads, true)) : "-";
  const loadMax = loads.length ? show({ value: Math.max(...loads), float: true }) : "-";
  const maxOf = (values: number[]) => (values.length ? Math.max(...values) : 0);
  const totalsText = [...totals].map(([name, value]) => `${name}=${value}`).join(" ");
  const wireIn = totals.get("wire_in") ?? 0;
  const wireOut = totals.get("wire_out") ?? 0;
  const received = total(kinds.fresh) + total(kinds.dup);
  const netIn =
    (totals.get("net_recv_ip") ?? 0) + (totals.get("net_recv_relay") ?? 0) + (totals.get("net_recv_custom") ?? 0);
  const netOut = (totals.get("net_send_ip") ?? 0) + (totals.get("net_send_relay") ?? 0);
  // D: the bytes of content that came again, over all bytes received, by kind. A repeat that the
  // dedup caught is in `dup`; a frame that was new by id but carried a change that the document
  // held is in `cdup`, which is part of `fresh`, so the two do not overlap.
  const dByKind = [...new Set([...kinds.fresh.keys(), ...kinds.dup.keys()])]
    .map((kind): [string, number] => {
      const all = (kinds.fresh.get(kind) ?? 0) + (kinds.dup.get(kind) ?? 0);
      const again = (kinds.dup.get(kind) ?? 0) + (kinds.cdup.get(kind) ?? 0);
      return [kind, all > 0 ? (100 * again) / all : 0];
    })
    .sort(([a, x], [b, y]) => y - x || a.localeCompare(b))
    .map(([kind, share]) => `${kind}:${share.toFixed(1)}%`)
    .join(",") || "-";
  const gmIn = (totals.get("gm_ctrl_in") ?? 0) + (totals.get("gm_data_in") ?? 0);
  const gmOut = (totals.get("gm_ctrl_out") ?? 0) + (totals.get("gm_data_out") ?? 0);
  const gossipText =
    `gm_of_udp_in=${percent(gmIn, netIn)} gm_of_udp_out=${percent(gmOut, netOut)} ` +
    `gm_ctrl_share_in=${percent(totals.get("gm_ctrl_in") ?? 0, gmIn)} gm_ctrl_share_out=${percent(totals.get("gm_ctrl_out") ?? 0, gmOut)} ` +
    `gm_bin=${pairsText(kinds.gmBytesIn)} gm_bout=${pairsText(kinds.gmBytesOut)} ` +
    `gm_nin=${pairsText(kinds.gmCountIn)} gm_nout=${pairsText(kinds.gmCountOut)}`;
  const wireText =
    `gt_of_udp_in=${percent(totals.get("gt_bytes_in") ?? 0, netIn)} gt_of_udp_out=${percent(totals.get("gt_bytes_out") ?? 0, netOut)} ` +
    `frames_of_udp_in=${percent(wireIn, netIn)} frames_of_udp_out=${percent(wireOut, netOut)} ` +
    `dup_share=${percent(total(kinds.dup), received)} ` +
    `d_share=${percent(total(kinds.dup) + total(kinds.cdup), received)} d_by_kind=${dByKind} ` +
    `env_in=${percent(wireIn - (totals.get("body_in") ?? 0), wireIn)} ` +
    `env_out=${percent(wireOut - (totals.get("body_out") ?? 0), wireOut)} ` +
    `bin_fresh=${pairsText(kinds.fresh)} bin_dup=${pairsText(kinds.dup)} dup_by_path=${pairsText(kinds.dupBy)} bout=${pairsText(kinds.out)} ` +
    `tags_in=${pairsText(kinds.tagsIn)} tags_out=${pairsText(kinds.tagsOut)}`;
  // The data tags are what users create; `msg` and `app_msg` are the tags of the engine example driver
  // and of the engine tests. The tags a2a_req and a2a_resp carry directed calls that
  // can hold user text or a protocol call, so they are reported apart. The census line names only
  // its 6 largest tags per interval, so a small data tag can be missing from the sum.
  const dataTags = ["a2a_broadcast", "a2a_msg", "a2a_status", "a2a_artifact", "msg", "app_msg"];
  const callTags = ["a2a_req", "a2a_resp"];
  const tagSum = (tags: Map<string, number>, names: string[]) => names.reduce((sum, name) => sum + (tags.get(name) ?? 0), 0);
  const ratio = (metadata: number, data: number) => (data > 0 ? (metadata / data).toFixed(1) : "no-data");
  const dataIn = tagSum(kinds.tagsIn, dataTags);
  const dataOut = tagSum(kinds.tagsOut, dataTags);
  const callsIn = tagSum(kinds.tagsIn, callTags);
  const callsOut = tagSum(kinds.tagsOut, callTags);
  const ratioText =
    `data_in=${dataIn} data_out=${dataOut} calls_in=${callsIn} calls_out=${callsOut} ` +
    `meta_share_in=${percent(wireIn - dataIn, wireIn)} meta_share_out=${percent(wireOut - dataOut, wireOut)} ` +
    `meta_per_data_in=${ratio(wireIn - dataIn, dataIn)} meta_per_data_out=${ratio(wireOut - dataOut, dataOut)} ` +
    `meta_per_data_in_loose=${ratio(wireIn - dataIn - callsIn, dataIn + callsIn)} ` +
    `udp_per_data_in=${ratio(netIn, dataIn)} udp_per_data_out=${ratio(netOut, dataOut)} ` +
    `gossip_per_data_in=${ratio(gmIn, dataIn)} gossip_per_data_out=${ratio(gmOut, dataOut)}`;
  const extText = [...ext]
    .filter(([, value]) => value > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => `ext_${name}=${value}`)
    .join(" ");

  return (
    `${path.basename(run).padEnd(12)} full=${roster.filter((x) => x >= n - 1).length}/${n} ` +
    `isolated=${roster.filter((x) => x <= 1).length} roster_med=${rosterMed} ` +
    `min=${rosterMin} | stalls=${stalls.length} longest_s=${stalls.length ? Math.floor(maxOf(stalls) / 1000) : 0} ` +
    `| up=${up} down=${down} | drop_nodes=${drops.size} worst_drop=${maxOf([...drops.values()])} ` +
    `| disc_nodes=${discs.size} worst_disc=${maxOf([...discs.values()])} ` +
    `| resent=${resent} resend_dropped=${resendDropped} ` +
    `| census_lines=${censusLines} ${totalsText} ahead_max=${maxOf(ahead)} | ` +
    `${wireText} | ${gossipText} | ${ratioText} | ${extText} ` +
    `| mem_med=${memMed} mem_max=${memMax} ` +
    `| load1 median=${loadMed} max=${loadMax} ` +
    `| canary_pauses=${gaps.length}`
  );
}

interface Phase {
  name: string;
  start_ms: number;
  end_ms: number;
}

// The ratio of the metadata to the data, by phase. It needs `result.json` (the phase windows)
// and `oracle.jsonl` (the data that the runner sent); a run folder without them gets no ratio.
// A census line counts in the phase that holds its time stamp. An oracle line that names its recipients (`to`)
// counts, for each recipient, in the phase of the first census of that recipient at or after the `ts` of the
// line: the census interval that holds the payload, so the wire bytes and the data bytes of a payload that
// lands after the last loaded census both count in the phase of that census. When `receipts.jsonl` names the
// time at which the recipient received the payload (the poll that served it), that time is used, and not the
// send time: a payload that is sent before a census and received after it counts with the census that holds
// its arrival. An oracle line with no `to`
// counts in the phase that holds its `ts`. A census interval that crosses a phase edge lands whole in one phase.
//
// - <phase>_meta_bps_per_daemon: for every phase but the first phase with data, the received frame bytes per
//   second per daemon, less the data bytes that the phase holds (a late payload can land in idle2).
// - delivered_data_bytes / frame_meta_per_data / udp_meta_per_data: for the first phase with data, the sum of
//   bytes x receivers of its oracle lines, and the metadata bytes per data byte at the frame layer
//   (`idle_wire_in`) and at the UDP layer (`idle_net_recv_*`). The frame layer is asserted: wire bytes
//   below the data bytes mean that the census or the oracle is wrong, and the run fails.
//   A later phase with data (a payload that lands after the last loaded census) has the same three fields with
//   its name as a prefix, as in idle2_delivered_data_bytes, so no field is written twice.
function phaseReport(run: string): string {
  if (!existsSync(`${run}/result.json`) || !existsSync(`${run}/oracle.jsonl`)) return "";
  const phases: Phase[] = JSON.parse(readFileSync(`${run}/result.json`, "utf8")).phases ?? [];
  const nodes = readdirSync(run).filter((f) => /^n.*\.err$/.test(f));
  const inPhase = (phase: Phase, at: number) => at >= phase.start_ms && at < phase.end_ms;
  const wire = new Map<string, number>();
  const udp = new Map<string, number>();
  const delivered = new Map<string, number>();
  const censusStamps = new Map<string, number[]>(); // the node name, then its census times in ms, in order
  let sawWire = false;
  const receipts = new Map<string, number>(); // `<node>:<payload id>`, then the time of the poll that served it
  if (existsSync(`${run}/receipts.jsonl`)) {
    for (const line of lines(readFileSync(`${run}/receipts.jsonl`, "utf8"))) {
      const receipt: { to: string; payload_id: string; ts: number } = JSON.parse(line);
      const key = `${receipt.to}:${receipt.payload_id}`;
      receipts.set(key, Math.min(receipts.get(key) ?? receipt.ts, receipt.ts));
    }
  }
  const add = (into: Map<string, number>, name: string, value: number) =>
    into.set(name, (into.get(name) ?? 0) + value);
  for (const file of nodes) {
    const owner = `bench${file.match(/^n(\d+)\.err$/)?.[1]?.padStart(2, "0") ?? ""}`;
    for (const line of lines(clean(readFileSync(`${run}/${file}`, "utf8")))) {
      const stamp = line.match(/^(\d{4}-\d\d-\d\dT[0-9:.]+Z)/);
      if (!stamp || !line.includes(" census")) continue;
      sawWire ||= /\bidle_wire_in=/.test(line);
      censusStamps.set(owner, [...(censusStamps.get(owner) ?? []), Date.parse(stamp[1] ?? "")]);
      const phase = phases.find((p) => inPhase(p, Date.parse(stamp[1] ?? "")));
      if (!phase) continue;
      add(wire, phase.name, sum(numbers(line, /\bidle_wire_in=(\d+)/)));
      add(udp, phase.name, sum(["ip", "relay", "custom"].flatMap((via) => numbers(line, new RegExp(`\\bidle_net_recv_${via}=(\\d+)`)))));
    }
  }
  // A build with no wire counters (a baseline) has no frame layer to compare: no ratio, and no failure.
  if (!sawWire) return "";
  for (const line of lines(readFileSync(`${run}/oracle.jsonl`, "utf8"))) {
    const sent: { bytes: number; receivers: number; ts: number; to?: string[]; payload_id?: string } = JSON.parse(line);
    if (sent.to === undefined) {
      const phase = phases.find((p) => inPhase(p, sent.ts));
      if (phase) add(delivered, phase.name, sent.bytes * sent.receivers);
      continue;
    }
    for (const recipient of sent.to) {
      const stamps = censusStamps.get(recipient) ?? [];
      // The wire bytes of a payload count in the census that holds its arrival, so the data bytes follow the
      // receipt of the recipient when the runner recorded it, and the send time when it did not.
      const arrival = receipts.get(`${recipient}:${sent.payload_id ?? ""}`) ?? sent.ts;
      const holding = stamps.find((stamp) => stamp >= arrival) ?? arrival; // no census after it: the phase of its time
      const phase = phases.find((p) => inPhase(p, holding));
      if (phase) add(delivered, phase.name, sent.bytes);
    }
  }
  const fields: string[] = [];
  let dataPhase: string | undefined; // the first phase with data: it keeps the plain field names
  for (const phase of phases) {
    const data = delivered.get(phase.name) ?? 0;
    const frames = wire.get(phase.name) ?? 0;
    if (frames < data) {
      throw new Error(`frame layer: phase ${phase.name} received ${frames} wire bytes, below ${data} delivered data bytes`);
    }
    if (data > 0) dataPhase ??= phase.name;
    if (phase.name !== dataPhase) {
      const seconds = (phase.end_ms - phase.start_ms) / 1000;
      fields.push(`${phase.name}_meta_bps_per_daemon=${((frames - data) / (seconds * nodes.length)).toFixed(1)}`);
    }
    if (data > 0) {
      const prefix = phase.name === dataPhase ? "" : `${phase.name}_`;
      fields.push(
        `${prefix}delivered_data_bytes=${data}`,
        `${prefix}frame_meta_per_data=${((frames - data) / data).toFixed(2)}`,
        `${prefix}udp_meta_per_data=${(((udp.get(phase.name) ?? 0) - data) / data).toFixed(2)}`,
      );
    }
  }
  return fields.join(" ");
}

// The resident memory of the daemons, from the host samples of the runner (`host.jsonl`). It is read at the
// sample with the largest sum, so it is the peak of the run. `rss_n` is the daemon count of that sample:
// compare runs of different N by this column.
function rssReport(run: string): string {
  if (!existsSync(`${run}/host.jsonl`)) return "";
  const samples: { daemons: number; rss_kb_sum: number; rss_kb_max: number }[] = lines(readFileSync(`${run}/host.jsonl`, "utf8")).map((line) => JSON.parse(line));
  const peak = samples.reduce((best, now) => (now.rss_kb_sum > best.rss_kb_sum ? now : best), { daemons: 0, rss_kb_sum: 0, rss_kb_max: 0 });
  if (peak.daemons === 0) return "";
  const mb = (kb: number) => (kb / 1024).toFixed(1);
  const biggest = Math.max(...samples.map((sample) => sample.rss_kb_max));
  return `rss_n=${peak.daemons} rss_mean_mb_per_daemon=${mb(peak.rss_kb_sum / peak.daemons)} rss_max_mb=${mb(biggest)} rss_sum_mb=${mb(peak.rss_kb_sum)}`;
}

// The CPU per daemon in each phase, as a percent of one core. The runner sums the `ps` cputime of the daemon
// processes into `cpu_s_sum` of each host sample. The census of the plain baseline has no cpu fields, so this
// is the CPU number for every arm. A phase uses the first sample at or after its start and the last sample at
// or before its end, and divides by the time between them.
function cpuReport(run: string): string {
  if (!existsSync(`${run}/host.jsonl`) || !existsSync(`${run}/result.json`)) return "";
  const phases: Phase[] = JSON.parse(readFileSync(`${run}/result.json`, "utf8")).phases ?? [];
  const samples: { ts: number; daemons: number; cpu_s_sum?: number }[] = lines(readFileSync(`${run}/host.jsonl`, "utf8")).map((line) => JSON.parse(line));
  const fields: string[] = [];
  for (const phase of phases) {
    const inside = samples.filter((sample) => sample.cpu_s_sum !== undefined && sample.ts >= phase.start_ms && sample.ts <= phase.end_ms);
    const first = inside[0];
    const last = inside[inside.length - 1];
    if (!first || !last || last.ts <= first.ts || first.daemons === 0) continue;
    const seconds = (last.ts - first.ts) / 1000;
    const used = (last.cpu_s_sum ?? 0) - (first.cpu_s_sum ?? 0);
    fields.push(`${phase.name}_cpu_pct_per_daemon=${((100 * used) / (seconds * first.daemons)).toFixed(1)}`);
  }
  return fields.join(" ");
}

for (const run of process.argv.slice(2).map((r) => r.replace(/\/+$/, ""))) {
  try {
    const extra = [rssReport(run), cpuReport(run)].filter((part) => part);
    console.log(`${summarize(run)} | ${phaseReport(run)}${extra.map((part) => ` | ${part}`).join("")}`);
  } catch (error) {
    console.error(`${path.basename(run)}: ${(error as Error).message}`);
    process.exitCode = 1;
  }
}
