#!/usr/bin/env bun
// Runs the browser test of the Nostr data lane against a relay that this script starts. A page cannot
// run a relay, so `serve_relay` runs beside the browser and the test reads its address at build time.
// Build the example first: `cargo build -p habilis-network-iroh-nostr-address-lookup --features
// test-relay --example serve_relay`.

import { spawn, spawnSync } from "node:child_process";
import { closeSync, existsSync, openSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const ADDRESS = "127.0.0.1:7447";
const WAIT_MS = 30_000;
const POLL_MS = 200;

// The test says `skipped:` and passes when the address of the relay was not set at build time. A run
// that skipped proved nothing, so it must fail.
export function skippedIn(output: string): boolean {
  return output.includes("skipped:");
}

// Whether the relay has printed that its port is open.
export function isListening(log: string): boolean {
  return /^listening ws:\/\//m.test(log);
}

function readLog(file: string): string {
  return existsSync(file) ? readFileSync(file, "utf8") : "";
}

async function main(): Promise<number> {
  const logFile = path.join(tmpdir(), `serve-relay-${process.pid}.log`);
  const logFd = openSync(logFile, "w");
  const relay = spawn(path.join(ROOT, "target/debug/examples/serve_relay"), [ADDRESS], {
    stdio: ["ignore", logFd, logFd],
  });
  closeSync(logFd);
  let exited = false;
  relay.on("exit", () => {
    exited = true;
  });
  try {
    const deadline = Date.now() + WAIT_MS;
    while (!isListening(readLog(logFile))) {
      if (exited || Date.now() > deadline) {
        console.error(`the relay did not listen (waited at most ${WAIT_MS / 1000} s); its log:`);
        console.error(readLog(logFile));
        return 1;
      }
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    }
    const test = spawnSync(
      "cargo",
      [
        "test",
        "--target",
        "wasm32-unknown-unknown",
        "-p",
        "habilis-network-iroh-nostr-address-lookup",
        "--test",
        "data_browser",
      ],
      {
        cwd: ROOT,
        encoding: "utf8",
        env: {
          ...process.env,
          NOSTR_TEST_RELAY_URL: `ws://${ADDRESS}`,
          WASM_BINDGEN_USE_BROWSER: "1",
        },
      },
    );
    const output = `${test.stdout ?? ""}${test.stderr ?? ""}`;
    process.stdout.write(output);
    if (test.status !== 0) return test.status ?? 1;
    if (skippedIn(output)) {
      console.error("the test skipped: the relay address never reached it");
      return 1;
    }
    return 0;
  } finally {
    relay.kill();
  }
}

if (import.meta.main) process.exit(await main());
