#!/usr/bin/env bun
// Stream a growing file to one reader: its last lines, then every line
// appended, until you stop it. Options after the file go to habilis-network-stream.
//
//   bun examples/tail/tail.ts app.log --web-url http://127.0.0.1:3020/
//
// HABILIS_NETWORK_STREAM names the binary when it is not on PATH.

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { constants, tmpdir } from "node:os";
import path from "node:path";

const [file, ...options] = process.argv.slice(2);
if (!file) {
  console.error("usage: tail.ts <file> [habilis-network-stream options]");
  process.exit(1);
}

// Not a pipeline: `tail -f` never ends by itself, and a pipeline waits for it
// after habilis-network-stream has exited. Through a FIFO, the stop handler ends it instead.
// The FIFO carries the file's bytes, so only this user may open it: a private
// directory (mkdtemp is 0700) and a 0600 FIFO inside it.
const dir = mkdtempSync(path.join(process.env.TMPDIR || tmpdir(), "tail-stream."));
const fifo = path.join(dir, "input");
spawnSync("mkfifo", ["-m", "600", fifo], { stdio: "inherit" });

let tailPid = 0;
let streamPid = 0;
let stopping = false;

const killQuietly = (pid: number, signal: NodeJS.Signals = "SIGTERM") => {
  try {
    process.kill(pid, signal);
  } catch {
    // The process is already gone.
  }
};
const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

// Leave the directory and the tail behind, whichever way we exit.
process.on("exit", () => {
  rmSync(dir, { recursive: true, force: true });
  if (tailPid) killQuietly(tailPid);
});

// `exec` makes the shell the tail, so tailPid is the tail itself. The shell opens the FIFO for
// writing and waits there until the reader opens it.
const tail = Bun.spawn(["sh", "-c", 'exec tail -f "$1" > "$2"', "sh", file, fifo], {
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
});
tailPid = tail.pid;

// The reader is the stream binary, with the FIFO on its standard input.
const streamBin = process.env.HABILIS_NETWORK_STREAM || "habilis-network-stream";
const stream = Bun.spawn(["sh", "-c", 'exec "$HABILIS_BIN" "$@" < "$0"', fifo, ...options], {
  env: { ...process.env, HABILIS_BIN: streamBin },
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
});
streamPid = stream.pid;

// Ctrl-C, SIGTERM or SIGHUP to this script ends the input, so a reader gets the end of the
// stream. habilis-network-stream reads its input only once a reader attaches, so with none yet
// it would wait forever: it gets 10 s, more than its own graceful close takes (a 5 s drain,
// then the node close), and is then stopped.
async function stop(): Promise<void> {
  if (stopping) return;
  stopping = true;
  // Nothing to wait for yet: leave now; the exit handler cleans up.
  if (!streamPid) process.exit(143);
  killQuietly(tailPid);
  for (let i = 0; i < 100; i++) {
    if (!alive(streamPid)) return;
    await Bun.sleep(100);
  }
  killQuietly(streamPid, "SIGTERM");
}
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.on(signal, () => void stop());
}

// The exit code of the stream. A signal gives 128 plus its number, as a shell reports it.
await stream.exited;
const signalNumber = stream.signalCode ? constants.signals[stream.signalCode] : undefined;
process.exit(stream.exitCode ?? (signalNumber ? 128 + signalNumber : 0));
