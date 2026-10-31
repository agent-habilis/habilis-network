#!/usr/bin/env bun
//
// Build light-cycles-web for the browser: cargo to a .wasm, wasm-bindgen to
// the glue. Adapted from the chat-webrtc example's build-wasm.ts — same
// toolchain, same shape.
//
// No wasm-pack and no bundler plugin, on purpose — this is the whole
// toolchain, and it fits on a screen.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TARGET = "wasm32-unknown-unknown";
const here = path.dirname(fileURLToPath(import.meta.url));
process.chdir(path.join(here, "wasm"));

const fail = (lines: string[]): never => {
  for (const line of lines) console.error(line);
  process.exit(1);
};

// Run a command with its output on this terminal. Stop with its exit code if it fails.
function run(cmd: string, args: string[], env: NodeJS.ProcessEnv = process.env): void {
  const proc = spawnSync(cmd, args, { stdio: "inherit", env });
  if (proc.status !== 0) process.exit(proc.status ?? 1);
}

// Fail on the prerequisite rather than a hundred lines of downstream errors.
const installed = spawnSync("rustup", ["target", "list", "--installed"], { encoding: "utf8" });
if (!(installed.stdout ?? "").split("\n").includes(TARGET)) {
  fail([`error: the ${TARGET} target is not installed`, `       rustup target add ${TARGET}`]);
}
if (!Bun.which("wasm-bindgen")) {
  fail(["error: wasm-bindgen is not on PATH", "       cargo install wasm-bindgen-cli"]);
}

// `ring`'s C core is compiled for wasm32, and Apple's clang has no wasm backend
// — it fails with a wall of errors that never mentions the real cause. Homebrew
// LLVM does have one. Non-macOS systems ship a clang that can, so a miss here is
// only fatal on a Mac, and the build below will say so plainly.
const env: NodeJS.ProcessEnv = { ...process.env };
for (const candidate of ["/opt/homebrew/opt/llvm/bin/clang", "/usr/local/opt/llvm/bin/clang"]) {
  if (existsSync(candidate)) {
    env.CC = candidate;
    env[`CC_${TARGET.replaceAll("-", "_")}`] = candidate;
    break;
  }
}
if (process.platform === "darwin" && !env.CC) {
  fail(["error: no Homebrew LLVM clang found, and Apple clang cannot emit wasm", "       brew install llvm"]);
}

// `--no-default-features`: the portable half of `habilis-network`/`habilis-network-netplay`
// only — see wasm/Cargo.toml's own comment on why.
run("cargo", ["build", "--release", "--target", TARGET, "--no-default-features"], env);

// Cargo says where the build landed: `CARGO_TARGET_DIR` and `build.target-dir` both move it.
const metadata = spawnSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
  encoding: "utf8",
  env,
});
if (metadata.status !== 0) process.exit(metadata.status ?? 1);
const targetDir: string = JSON.parse(metadata.stdout).target_directory;
const artifact = path.join(targetDir, TARGET, "release", "light_cycles_web.wasm");

// `--target web` emits ES modules that fetch the binary themselves, which is
// what the frontend next door loads. Only one target is generated: this
// example has one consumer, and a second would only be a second thing to keep
// in step.
run("wasm-bindgen", ["--target", "web", "--out-dir", "dist", artifact], env);

console.log(`\nbuilt ${path.join(process.cwd(), "dist")}/light_cycles_web_bg.wasm`);
