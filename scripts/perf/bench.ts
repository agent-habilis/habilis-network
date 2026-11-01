#!/usr/bin/env bun
// One benchmark run of the app binary: N real daemons in a private mesh on one host.
//
// usage: bun scripts/perf/bench.ts <app binary> <arm> [--nodes 64] [--seed 1] [--stagger 0.5]
//          [--settle 480] [--idle 600] [--loaded 600] [--lookup mdns] [--out-root ~/bench-results]
//
// Phases: join, settle, idle, loaded, idle. In the loaded phase every daemon sends, every 30 s, one
// broadcast of 200 bytes, one directed msg of 200 bytes to a random peer, and one task. The runner
// plays the worker of each task, so no task stays open. The workload is seeded.
//
// The run folder is <out-root>/<arm>-<UTC stamp>. It holds oracle.jsonl (see README.md), result.json,
// n<i>.err (the tracing log of daemon i, which holds the census lines) and `done`. summarize.ts reads it.

import { spawn } from "node:child_process";
import { appendFileSync, copyFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir, loadavg, cpus, hostname } from "node:os";
import path from "node:path";

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
const NODES = num("nodes", 64);
const SEED = num("seed", 1);
const STAGGER = num("stagger", 0.5);
const SETTLE = num("settle", 480);
const IDLE = num("idle", 600);
const LOADED = num("loaded", 600);
const LOOKUP = flags.get("lookup") ?? "mdns";
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
  sha: build?.[1] ?? null,
  dirty: build ? build[2] === "true" : null,
  host: hostname(),
  cores: cpus().length,
  seed: SEED,
  nodes: NODES,
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

let stopping = false;
const sampler = setInterval(() => {
  loads.push({ ts: Date.now(), load1: loadavg()[0] ?? 0 });
  if (loads.length % 6 === 0) saveResult();
}, 10_000);

// Join.
const owner = String(process.pid);
const created = await cli([
  "create", "--name", `bench-${stamp}`, "--nickname", nick(1), "--lookup", LOOKUP,
  "--owner-pid", owner, "--state-file", stateFile(1),
]);
if (created.code !== 0) await abort(`create failed: ${created.err.trim()}`);
const ready = await cli(["ready", "--state-file", stateFile(1), "--timeout-secs", "60"]);
gossip = ready.out.match(/"gossip":"([^"]+)"/)?.[1] ?? "";
if (!gossip) await abort(`no gossip id: ${ready.out.trim()} ${ready.err.trim()}`);
for (let i = 2; i <= NODES; i++) {
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
