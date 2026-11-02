#!/usr/bin/env bun
// One benchmark run of the app binary: N real daemons in a private mesh on one host.
//
// usage: bun scripts/perf/bench.ts <app binary> <arm> [--nodes <N>] [--seed 1] [--stagger 0.5]
//          [--settle 480] [--idle 600] [--loaded 600] [--lookup <list>] [--min-avail-gib 2] [--out-root ~/bench-results]
//          [--record ~/bench-results/baseline/<arm>.json]
//
// --record names the JSON that build-arm.ts wrote. The runner copies it into result.json as `build`.
// Use it for the sha and the dirty flag: the version text of a binary built with an engine override
// can say dirty:true, because cargo rewrites Cargo.lock before the build script runs.
//
// Phases: join, settle, idle, loaded, idle. In the loaded phase every daemon sends, every 30 s, one
// broadcast of 200 bytes, one directed msg of 200 bytes to a random peer, and one task. The runner
// plays the worker of each task, so no task stays open. The workload is seeded.
//
// The run folder is <out-root>/<arm>-<UTC stamp>. It holds oracle.jsonl (see README.md), result.json,
// n<i>.err (the tracing log of daemon i, which holds the census lines) and `done`. summarize.ts reads it.

import { spawn } from "node:child_process";
import { appendFileSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, loadavg, cpus, hostname, freemem, platform } from "node:os";
import path from "node:path";
import { chooseNodes } from "./choose-n.ts";

const flags = new Map<string, string>();
const positional: string[] = [];
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const arg = argv[i] ?? "";
  if (arg.startsWith("--")) flags.set(arg.slice(2), argv[++i] ?? "");
  else positional.push(arg);
}
const [BIN = "", ARM = ""] = positional;
if (!BIN || !ARM) {
  console.error("usage: bench.ts <app binary> <arm> [--nodes N] [--seed S] [--settle s] [--idle s] [--loaded s]");
  process.exit(2);
}
const num = (name: string, fallback: number) => Number(flags.get(name) ?? fallback);
// No --nodes: the largest N that fits the memory of the host (see choose-n.ts). The host of a run is 8 GiB,
// so 64 daemons do not fit; the run says what it chose and why.
const chosen = chooseNodes(availableBytes());
const NODES = flags.has("nodes") ? num("nodes", 0) : chosen.nodes;
if (!flags.has("nodes")) console.log(chosen.why);
const SEED = num("seed", 1);
const STAGGER = num("stagger", 0.5);
const SETTLE = num("settle", 480);
const IDLE = num("idle", 600);
const LOADED = num("loaded", 600);
// No --lookup flag: `create` then uses the loopback ladder, so the 64 daemons meet over 127.0.0.1 and
// need no network. Name a lookup (mdns, dht, relay) only to test that lookup.
const LOOKUP = flags.get("lookup") ?? "";
const PERIOD = num("period", 30);
const PAYLOAD = "x".repeat(200);

const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
const OUT = path.join(flags.get("out-root") ?? path.join(homedir(), "bench-results"), `${ARM}-${stamp}`);
mkdirSync(OUT, { recursive: true });
const RUNTIME = `/tmp/agent-gossip-${process.getuid?.() ?? 0}`;

// A seeded generator (mulberry32), so the workload of a run repeats from its seed.
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const random = rng(SEED);

const sleep = (seconds: number) => Bun.sleep(seconds * 1000);

async function cli(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const proc = Bun.spawn([BIN, ...args], { stdout: "pipe", stderr: "pipe" });
  const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { code: await proc.exited, out, err };
}

// The binary prints `agent-gossip <version> (<sha> dirty:<bool>)`.
const versionText = (await cli(["--version"])).out.trim();
const build = versionText.match(/\(([0-9a-f]+) dirty:(true|false)\)/);

const result: Record<string, unknown> = {
  arm: ARM,
  binary: BIN,
  version: versionText,
  build: flags.has("record") ? JSON.parse(readFileSync(flags.get("record") ?? "", "utf8")) : null,
  sha: build?.[1] ?? null,
  dirty: build ? build[2] === "true" : null,
  host: hostname(),
  cores: cpus().length,
  seed: SEED,
  nodes: NODES,
  nodes_choice: flags.has("nodes") ? "flag" : chosen.why,
  lookup: LOOKUP,
  phases: [] as { name: string; start_ms: number; end_ms: number }[],
  load: [] as { ts: number; load1: number }[],
};
const saveResult = () => writeFileSync(`${OUT}/result.json`, JSON.stringify(result, null, 2));
const phases = result.phases as { name: string; start_ms: number; end_ms: number }[];
const loads = result.load as { ts: number; load1: number }[];
saveResult();

const nick = (i: number) => `bench${String(i).padStart(2, "0")}`;
// Not in the sessions folder of the runtime: the Stop hook of the agent counts the daemons there.
mkdirSync(`${OUT}/state`, { recursive: true });
const stateFile = (i: number) => `${OUT}/state/${nick(i)}.json`;
let gossip = "";
let seq = 0;

function oracle(sender: string, kind: string, receivers: number, bytes: number): void {
  appendFileSync(`${OUT}/oracle.jsonl`, JSON.stringify({ sender, kind, receivers, bytes, seq: seq++, ts: Date.now() }) + "\n");
}

async function abort(reason: string): Promise<never> {
  result.aborted = reason;
  saveResult();
  console.error(`aborted: ${reason}`);
  await cleanup();
  process.exit(1);
}

async function alive(i: number): Promise<boolean> {
  return (await cli(["ready", "--state-file", stateFile(i), "--timeout-secs", "5"])).code === 0;
}

async function allAlive(where: string): Promise<void> {
  const states = await Promise.all(Array.from({ length: NODES }, (_, k) => alive(k + 1)));
  const dead = states.flatMap((ok, k) => (ok ? [] : [nick(k + 1)]));
  if (dead.length > 0) await abort(`${where}: daemons not alive: ${dead.join(",")}`);
}

// Every daemon must see the other N-1 members before the idle phase starts.
async function checkMesh(): Promise<void> {
  const seen = await Promise.all(
    Array.from({ length: NODES }, async (_, k) => {
      const peers = JSON.parse((await cli(["peers", "--gossip", gossip, "--nickname", nick(k + 1)])).out || "{}").peers ?? [];
      return peers.filter((peer: { quiet: boolean }) => !peer.quiet).length;
    }),
  );
  result.roster = seen;
  saveResult();
  const short = seen.flatMap((count, k) => (count < NODES - 1 ? [`${nick(k + 1)} sees ${count} of ${NODES - 1}`] : []));
  if (short.length > 0) await abort(`mesh did not form: ${short.join(", ")}`);
}

async function cleanup(): Promise<void> {
  clearInterval(sampler);
  stopping = true;
  await Promise.all(Array.from({ length: NODES }, (_, k) => cli(["leave", gossip, "--nickname", nick(k + 1)]).catch(() => null)));
}

// The mesh prefix of the runtime folder is the head of the gossip id.
function collectLogs(): void {
  const dir = `${RUNTIME}/${gossip.slice(0, 16)}`;
  for (let i = 1; i <= NODES; i++) {
    const log = `${dir}/${nick(i)}.tracing.log`;
    if (existsSync(log)) copyFileSync(log, `${OUT}/n${i}.err`);
  }
}

// Memory that a new process can use, in bytes. os.freemem() is only the free pages, which is far too low on macOS.
function availableBytes(): number {
  if (platform() === "linux") {
    const kb = readFileSync("/proc/meminfo", "utf8").match(/MemAvailable:\s+(\d+) kB/)?.[1];
    return Number(kb ?? 0) * 1024;
  }
  const text = Bun.spawnSync(["vm_stat"]).stdout.toString();
  const pageSize = Number(text.match(/page size of (\d+) bytes/)?.[1] ?? 16384);
  const pages = (name: string) => Number(text.match(new RegExp(`Pages ${name}:\\s+(\\d+)`))?.[1] ?? 0);
  return (pages("free") + pages("inactive") + pages("speculative")) * pageSize || freemem();
}

function openFiles(): number {
  if (platform() === "linux") return Number(readFileSync("/proc/sys/fs/file-nr", "utf8").split(/\s+/)[0]);
  return Number(Bun.spawnSync(["sysctl", "-n", "kern.num_files"]).stdout.toString().trim());
}

// The system limit on open files. The limit of one process (`ulimit -n`) is written to host.jsonl, because
// every daemon inherits it: run the benchmark after `ulimit -n 10240`, as the default of macOS is 256.
function fileLimit(): number {
  if (platform() === "linux") return Number(readFileSync("/proc/sys/fs/file-max", "utf8"));
  return Number(Bun.spawnSync(["sysctl", "-n", "kern.maxfiles"]).stdout.toString().trim());
}
const processFileLimit = Bun.spawnSync(["sh", "-c", "ulimit -n"]).stdout.toString().trim();

// RSS of the daemons of this run: the processes that name the state folder of the run.
// `ps` prints cputime as [[H:]M:]S.cc, in seconds of CPU the process used since it started.
const cpuSeconds = (text: string) => text.split(":").reduce((total, part) => total * 60 + Number(part), 0);
function daemonRss(): { daemons: number; rss_kb_sum: number; rss_kb_max: number; cpu_s_sum: number } {
  const rows = Bun.spawnSync(["ps", "-axo", "rss=,cputime=,command="]).stdout.toString().split("\n");
  const mine = rows.filter((row) => row.includes(`${OUT}/state/`)).map((row) => row.trim().split(/\s+/));
  const sizes = mine.map((cols) => Number(cols[0]));
  return {
    daemons: sizes.length,
    rss_kb_sum: sizes.reduce((a, b) => a + b, 0),
    rss_kb_max: Math.max(0, ...sizes),
    cpu_s_sum: mine.reduce((total, cols) => total + cpuSeconds(cols[1] ?? "0"), 0),
  };
}

// The sample goes to host.jsonl at once, outside /tmp: a crash of the host still leaves the data.
function sample() {
  const point = {
    ts: Date.now(), load1: loadavg()[0] ?? 0, avail_bytes: availableBytes(), open_files: openFiles(),
    file_limit: fileLimit(), ulimit_n: processFileLimit, ...daemonRss(),
  };
  appendFileSync(`${OUT}/host.jsonl`, JSON.stringify(point) + "\n");
  return point;
}

// Start no new daemon when the host is near its limit. The host of the first try went down at 64 daemons.
const MAX_LOAD_PER_CORE = 2;
const MIN_AVAILABLE_BYTES = num("min-avail-gib", 2) * 1024 ** 3;
function overLimit(point: ReturnType<typeof sample>): string | null {
  if (point.load1 > MAX_LOAD_PER_CORE * cpus().length) return `load1 ${point.load1.toFixed(1)} is above ${MAX_LOAD_PER_CORE} x ${cpus().length} cores`;
  if (point.avail_bytes < MIN_AVAILABLE_BYTES) return `available memory ${(point.avail_bytes / 1024 ** 3).toFixed(1)} GiB is below ${MIN_AVAILABLE_BYTES / 1024 ** 3} GiB`;
  if (point.open_files > 0.8 * point.file_limit) return `open files ${point.open_files} are above 80% of ${point.file_limit}`;
  return null;
}

let stopping = false;
sample();
const sampler = setInterval(() => {
  loads.push({ ts: Date.now(), load1: loadavg()[0] ?? 0 });
  sample();
  if (loads.length % 6 === 0) saveResult();
}, 10_000);

// Join.
const owner = String(process.pid);
const created = await cli([
  "create", "--name", `bench-${stamp}`, "--nickname", nick(1), ...(LOOKUP ? ["--lookup", LOOKUP] : []),
  "--owner-pid", owner, "--state-file", stateFile(1),
]);
if (created.code !== 0) await abort(`create failed: ${created.err.trim()}`);
const ready = await cli(["ready", "--state-file", stateFile(1), "--timeout-secs", "60"]);
gossip = ready.out.match(/"gossip":"([^"]+)"/)?.[1] ?? "";
if (!gossip) await abort(`no gossip id: ${ready.out.trim()} ${ready.err.trim()}`);
for (let i = 2; i <= NODES; i++) {
  const limit = overLimit(sample());
  if (limit) await abort(`start-up stopped before ${nick(i)}: ${limit}`);
  const joined = await cli(["join", gossip, "--nickname", nick(i), "--owner-pid", owner, "--state-file", stateFile(i)]);
  if (joined.code !== 0) await abort(`join ${nick(i)} failed: ${joined.err.trim()}`);
  await sleep(STAGGER);
}
await allAlive("after join");

// The worker and the initiator side of every task, per daemon. One long poll at a time.
const open = new Map<string, string>(); // task id -> initiator nickname, for tasks this runner plays the worker of
// Each step of a task runs once. A repeat of an event must not start the step again, or a task loops.
const done = new Set<string>();
const once = (step: string, task: string) => !done.has(`${step}:${task}`) && !!done.add(`${step}:${task}`);
async function listen(i: number): Promise<void> {
  const me = nick(i);
  while (!stopping) {
    // The bell (--long) only waits. A plain poll serves the events and moves the read cursor.
    await cli(["poll", "--gossip", gossip, "--nickname", me, "--long", "--max-secs", "60"]);
    const polled = await cli(["poll", "--gossip", gossip, "--nickname", me]);
    let events: any[] = [];
    try {
      events = JSON.parse(polled.out || "[]");
    } catch {
      continue;
    }
    for (const event of events) {
      if (event.event !== "task" || event.self || event.to !== me) continue;
      const task = event.task_id as string;
      appendFileSync(
        `${OUT}/events.jsonl`,
        JSON.stringify({ me, task, kind: event.kind, state: event.state, author: event.author, ts: Date.now() }) + "\n",
      );
      if (event.kind === "message" && event.state === "submitted" && once("work", task)) {
        // The worker: working, then the artifact. The initiator approves, and then the worker completes.
        open.set(task, event.author);
        await cli(["a2a", "status", "--gossip", gossip, "--nickname", me, "--task-id", task, "--state", "working"]);
        oracle(me, "task_status", 1, 0);
        await cli(["a2a", "artifact", "--gossip", gossip, "--nickname", me, "--task-id", task, "--text", PAYLOAD]);
        oracle(me, "task_artifact", 1, PAYLOAD.length);
      } else if (event.kind === "artifact-update" && once("approve", task)) {
        // The initiator: approve the result.
        await cli([
          "a2a", "call", "--gossip", gossip, "--nickname", me, "--to", event.author,
          "--method", "SendMessage", "--task-id", task, "--text", "approved",
        ]);
        oracle(me, "task_status", 1, "approved".length);
      } else if (event.kind === "message" && event.state === "working" && open.has(task) && once("complete", task)) {
        open.delete(task);
        await cli(["a2a", "status", "--gossip", gossip, "--nickname", me, "--task-id", task, "--state", "completed"]);
        oracle(me, "task_status", 1, 0);
      }
    }
  }
}

// The workload of one daemon: every PERIOD s, one broadcast, one msg, one task.
async function load(i: number, until: number): Promise<void> {
  const me = nick(i);
  await sleep(random() * PERIOD);
  while (Date.now() < until && !stopping) {
    const started = Date.now();
    const others = Array.from({ length: NODES }, (_, k) => nick(k + 1)).filter((n) => n !== me);
    const to = others[Math.floor(random() * others.length)] ?? me;
    await cli(["a2a", "broadcast", "--gossip", gossip, "--nickname", me, "--text", PAYLOAD]);
    oracle(me, "broadcast", NODES - 1, PAYLOAD.length);
    await cli(["a2a", "msg", "--gossip", gossip, "--nickname", me, "--to", to, "--text", PAYLOAD]);
    oracle(me, "msg", 1, PAYLOAD.length);
    await cli(["a2a", "call", "--gossip", gossip, "--nickname", me, "--to", to, "--method", "SendMessage", "--label", "bench", "--text", PAYLOAD]);
    oracle(me, "task_brief", 1, PAYLOAD.length);
    await sleep(Math.max(0, PERIOD - (Date.now() - started) / 1000));
  }
}

async function phase(name: string, seconds: number, work?: () => Promise<void>): Promise<void> {
  const entry = { name, start_ms: Date.now(), end_ms: 0 };
  phases.push(entry);
  saveResult();
  if (work) await Promise.all([work(), sleep(seconds)]);
  else await sleep(seconds);
  entry.end_ms = Date.now();
  saveResult();
  await allAlive(`end of ${name}`);
}

for (let i = 1; i <= NODES; i++) void listen(i);
await sleep(SETTLE);
await checkMesh();
await phase("idle1", IDLE);
await phase("loaded", LOADED, async () => {
  const until = Date.now() + LOADED * 1000;
  await Promise.all(Array.from({ length: NODES }, (_, k) => load(k + 1, until)));
});
await phase("idle2", IDLE);

collectLogs();
await cleanup();
writeFileSync(`${OUT}/done`, "done\n");
console.log(`run folder: ${OUT}`);
console.log(`bun scripts/perf/summarize.ts ${OUT}`);
