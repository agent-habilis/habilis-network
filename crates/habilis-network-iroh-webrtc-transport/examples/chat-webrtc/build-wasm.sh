#!/usr/bin/env bash
#
# Build chat-web for the browser: cargo to a .wasm, wasm-bindgen to the glue.
#
# No wasm-pack and no bundler plugin, on purpose — this is the whole toolchain,
# and it fits on a screen.

set -euo pipefail

cd "$(dirname "$0")/chat-web"

TARGET=wasm32-unknown-unknown
ARTIFACT="target/$TARGET/release/chat_web.wasm"

# Fail on the prerequisite rather than a hundred lines of downstream errors.
if ! rustup target list --installed | grep -qx "$TARGET"; then
  echo "error: the $TARGET target is not installed" >&2
  echo "       rustup target add $TARGET" >&2
  exit 1
fi
if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen is not on PATH" >&2
  echo "       cargo install wasm-bindgen-cli" >&2
  exit 1
fi

# `ring`'s C core is compiled for wasm32, and Apple's clang has no wasm backend
# — it fails with a wall of errors that never mentions the real cause. Homebrew
# LLVM does have one. Non-macOS systems ship a clang that can, so a miss here is
# only fatal on a Mac, and the build below will say so plainly.
for candidate in /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang; do
  if [ -x "$candidate" ]; then
    export CC="$candidate"
    export "CC_${TARGET//-/_}=$candidate"
    break
  fi
done
if [ "$(uname -s)" = "Darwin" ] && [ -z "${CC:-}" ]; then
  echo "error: no Homebrew LLVM clang found, and Apple clang cannot emit wasm" >&2
  echo "       brew install llvm" >&2
  exit 1
fi

cargo build --release --target "$TARGET"

# `--target web` emits ES modules that fetch the binary themselves, which is
# what the Bun app next door loads. Only one target is generated: this example
# has one consumer, and a second would only be a second thing to keep in step.
wasm-bindgen --target web --out-dir dist "$ARTIFACT"

printf '\nbuilt %s\n' "$(cd dist && pwd)/chat_web_bg.wasm"
printf 'next: cd web && bun install && bun run dev\n'
