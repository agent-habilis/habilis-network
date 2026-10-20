# habilis-network — Windows port

This document gives the requirements and the test plan for the Windows port.
It is a hand-off: an agent can start the work from this document alone.
The style follows ASD-STE100 Simplified Technical English.

## 1. Goal

The target is Windows 11 x64 (`x86_64-pc-windows-msvc`).
The port is done when all of these are true:

- `cargo build`, `cargo clippy -- -D warnings` and `cargo test` pass for the workspace on Windows, with the default features (`host`, `mdns`, `dht`).
- The Windows CI jobs of [R11](#r11-windows-on-ci) run on every pull request, are required checks, and are green.
- The agent-gossip scenario in [§6](#6-test-plan-on-a-real-windows-machine) passes on a real Windows machine, with a macOS or Linux peer.

Backwards compatibility is not necessary.
Ids, wire formats, the IPC protocol and the C ABI can change.

## 2. Current state

The workspace compiles on Windows, and the `windows` job of `ci.yml` runs clippy and the tests there.
The IPC of a daemon works on Windows, over a named pipe. The graceful stop does not work yet, and the state file can fail to update.

| Requirement | State |
|---|---|
| R1. Compile | Done. `libc` and `windows-sys` come in through `host`, each on its own target. |
| R2. Runtime base | Done. `runtime_base` returns `<LocalAppData>\<product>\run`, and `ensure_runtime_base` rejects a reparse point at the base (`crates/habilis-network-util/src/lib.rs`). |
| R3. IPC | Done. On Windows the endpoint is a named pipe with a random name and a DACL of the user, and a client checks the owner of the pipe. Discovery reads a `<nick>.ipc` marker on every OS (`crates/habilis-network/src/transport/ipc.rs`). |
| R4. Process helpers | Done. `is_alive`, `live_start_time`, `comm_of` and `parent_of` have Windows versions in `process.rs`. `parent_of` also gives no parent when the creator has exited or is newer than its child. |
| R5. Graceful stop | Open. There is no IPC `Quit`. `terminate` on Windows returns `Unsupported`. |
| R6. Owner watch | Open. `spawn_orphan_watch` is `cfg(unix)` only. |
| R7. Console events | Open. Only ctrl-c reaches the quit channel. |
| R8. State file | Open. `state_file.rs` still replaces the file with `std::fs::rename`. |
| R9. FFI | Open. `ffi.rs` and `habilis_network.h` still use `c_long` / `long`. `dlopen/node.ts` and `abi.ts` are not changed. `tasks/src/ffi.rs` still reads `libhabilis_network_ffi.a`. |
| R10. Tooling and tests | Done. `cdp.rs` has no `win64` build and says why. Set `$CHROME_FOR_TESTING` to a local Chrome. |
| R11. Windows on CI | Partly done. The `windows` job of `ci.yml`, the Windows leg of `matrix.yml`, and part 1 of `host_lifecycle.rs` (steps 1 and 2) run. Open: `cargo task ffi` (with R9), steps 3 and 4 of `host_lifecycle.rs` (with R5 and R6), the `e2e.yml` stream job, and the required-check setting of the repository. The Node `isize` mapping is not tested until R9. |
| R12. Runtime base of a Unix client | Open. A Unix client does not check the base before it reads a marker. |

The descriptions of [§2.2](#22-runtime-breaks) and the open lines of [§2.3](#23-tooling-and-tests) are still true. Their line numbers can be out of date.
[§2.1](#21-build-blockers) is kept as the record of what R1 changed.

### 2.1 Build blockers

All of these are fixed (R1). The line numbers are from before the fix.

| Location | Problem |
|---|---|
| `crates/habilis-network-util/src/lib.rs:63` | `runtime_base` returns `/tmp/{product}-{uid}`. |
| `crates/habilis-network-util/src/lib.rs:75` | `current_uid` calls `libc::geteuid`. |
| `crates/habilis-network-util/src/lib.rs` (`ensure_runtime_base`) | Uses `DirBuilderExt`, `MetadataExt` and `PermissionsExt` for the `0700`, owner and symlink checks. |
| `crates/habilis-network-util/src/process.rs` | `parent_of`, `comm_of` and `live_start_time` exist only for macOS and Linux. `ancestry_contains` (`:121`) calls `parent_of`. `is_alive` (`:91`) and `terminate` (`:104`) call `libc::kill`. |
| `crates/habilis-network/src/daemon/shutdown.rs:154-198` | `validate_owner_pid`, `owner_start` and `Owner::lost` have only a `host` gate, and they call `live_start_time`. |
| `crates/habilis-network/src/daemon/shutdown.rs:113` | `spawn_quit_signal_tasks` uses `exit_on_quit` and `owner` only under `cfg(unix)`. On Windows this is an unused-variable error under `-D warnings`. |
| `crates/habilis-network/src/transport/ipc.rs:114` | `PermissionsExt` sets `0600` on the socket, with no `cfg(unix)`. |
| `crates/habilis-network-logging/src/sink.rs:57`, `:139` | `OpenOptionsExt::mode(0o600)` on the log file, with no `cfg(unix)`. |
| `Cargo.toml:188`, `crates/habilis-network/Cargo.toml:151`, `crates/habilis-network-util/Cargo.toml:46` | `libc` is not scoped to a target. |

These parts were already correct on Windows:

- `crates/habilis-network/src/daemon/state_file.rs:209-221` has a `cfg(unix)` / `cfg(not(unix))` split.
- `habilis-network-util` `resident_memory` falls back to `None`.
- `habilis-network-stream-cli` gates its `libc` use on `cfg(unix)`.
- The tests that cut a link or an IP port use in-process iroh hooks, not `pf` or `iptables`.
- `packages/habilis-network-ffi/src/discover.ts:15` already returns `habilis_network_ffi.dll` on `win32`.

### 2.2 Runtime breaks

These problems occur after the workspace compiles. The three IPC items that were here (the name, the discovery and the security of the endpoint) are done with R3.

- **Stop.** `terminate` sends `SIGTERM`. Windows has no polite signal. `TerminateProcess` is a hard kill, so the `Left` broadcast does not go out and the state file stays. Until R5, `terminate` on Windows returns `Unsupported`.
- **Owner watch.** `spawn_orphan_watch` (`shutdown.rs:214`) is `cfg(unix)` only. On Windows a daemon does not stop when its owner dies.
- **Console events.** Only ctrl-c is handled. Close, logoff and shutdown events skip the graceful path.
- **State file.** `state_file.rs:225` writes a temporary file and renames it over the target. On Windows the rename fails while a reader holds the file open without `FILE_SHARE_DELETE`.
- **Node FFI.** `packages/habilis-network-ffi/src/dlopen/node.ts:26` maps `isize` to koffi `long`. On Win64, `long` is 4 bytes, so return values are truncated. `abi.ts:14` says "8 bytes on every target here", which is false on Windows.
- **C ABI.** `crates/habilis-network-ffi/src/ffi.rs` returns `c_long`, and `include/habilis_network.h:107`, `:122`, `:125`, `:135`, `:212` declare `long`. Both sides agree, but on Windows the value is 32-bit.

### 2.3 Tooling and tests

Open (R9):

- `tasks/src/ffi.rs:17` uses `libhabilis_network_ffi.a`. On MSVC the static library is `habilis_network_ffi.lib`.
- `tasks/src/ffi.rs` falls back to `nm -gU`, and finds `bin/llvm-nm` with no `.exe`. The symbol filter knows Mach-O and ELF, not COFF.

Open (other):

- `tasks/src/util/cdp.rs` has no `win64` Chrome for Testing build. It says so, and `$CHROME_FOR_TESTING` names a local Chrome instead.
- `tasks/src/util/wasm.rs` looks for clang only in Homebrew paths.
- `scripts/perf/*.sh` and `examples/tail/tail.sh` are bash. They stay Unix-only. Say so in their headers.

Done (R10):

- `tasks/src/util/webdriver.rs` uses the `which` crate.
- `crates/habilis-network-chunks/tests/origin.rs` uses `File::set_modified`, not `touch -t`.
- The path assertions in `crates/habilis-network-util/src/lib.rs` and `crates/habilis-network/src/transport/ipc.rs` are correct on each OS.

### 2.4 Toolchain

`str0m` pulls in `aws-lc-sys`.
On MSVC it needs the Visual Studio C++ build tools, CMake and NASM.

## 3. Requirements: habilis-network

Do this work on the `feat-windows-support` branch (PR #5).

### R1. Compile

- Put each item of [§2.1](#21-build-blockers) behind `cfg(unix)` or `cfg(windows)`.
- Move `libc` to `[target.'cfg(unix)'.dependencies]`.
- Add `windows-sys` under `[target.'cfg(windows)'.dependencies]`, with only the features that the code uses.
- Keep the `unsafe` blocks small, with a `SAFETY:` comment each, as the `libc` blocks have now.

### R2. Runtime base

- On Windows, `runtime_base(product)` returns `<LocalAppData>\<product>\run`.
- Get `LocalAppData` from `SHGetKnownFolderPath(FOLDERID_LocalAppData)`, not from an environment variable. This keeps the rule that every context computes the same base.
- Do not add a uid suffix. The profile directory is already per user.
- `ensure_runtime_base` rejects a reparse point at the base. This replaces the symlink check.
- The directory inherits the profile ACL. Do not set a new ACL.
- Ask for the path with `KF_FLAG_DONT_VERIFY`, so a profile folder that is not on disk yet gives the same path. If the shell cannot name a profile for the token of the process, the base is `<temp>\<product>\run`, and a warn says so. The temp directory is also per user.
- The local nickname is the stem of every per-member file: `<nick>.state.json`, `<nick>.tracing.log` and `<nick>.ipc`.
- On Windows, `setup_mesh` refuses a local nickname that is no valid file stem, and gives the reason. The reason is one of these:
  - the nickname contains one of `: * ? " |`;
  - it ends with a dot;
  - it is a device name, also with an extension: `con`, `prn`, `aux`, `nul`, `com0` to `com9`, `lpt0` to `lpt9`, the superscript `com¹` to `com³` and `lpt¹` to `lpt³`, `conin$` or `conout$`.
- Windows 10 and Windows Server 2022 map a device name to the device. Windows 11 accepts it. The rule follows the documented naming rules, so one nickname works on every Windows.
- The rule is `file_name::windows_file_stem_problem` in `habilis-network-util`. The wire rule of `Nickname` does not change, so a peer on another OS keeps its name. A random nickname (`word-word`) always passes.
- The file system of Windows does not differentiate case. `Alice` and `alice` on one mesh on one machine share the state file and the marker. A local check cannot see the other daemon, so this is not refused.

### R3. IPC

Done. The design changed from the first text of this section, after review. The reasons are below.

**The marker, on every OS.** A daemon writes the name of its endpoint in `<mesh folder>/<nick>.ipc`, one line, after the listener exists and before the daemon reports ready. A client finds the daemon through the marker, so discovery does not depend on the endpoint being a file. `active_endpoints` reads the markers. The marker is written by the writer of the state file (`.tmp.<pid>`, then a rename), born `0600` on Unix. A marker that cannot be written fails the bind. The shutdown removes the marker only while it still names this daemon. The marker is not in the state file, because a `--state-file` override can put the state file outside the base, and an in-process node writes none. On Unix the endpoint is the same socket as before.

**The name of the pipe.** `\\.\pipe\habilis-` and 128 random bits in hex. Pipe names live in one namespace for the whole machine, and any account can make a pipe with a free name.

- A fixed name, as this section first asked (`<product>-<user hash>-<mesh-prefix>-<nick>`), lets another account make the pipe first. Then the bind fails, and clients reach that account.
- A random name cannot be taken before it exists. After that it is public: any account lists pipe names, for example with `Get-ChildItem \\.\pipe\`. So the name is no secret, and the protection is the DACL and the owner check below.
- The name has no mesh prefix and no nickname. The mesh prefix is part of the mesh id, and the list of pipe names is open to every account.

**The DACL.** The pipe has the security descriptor `O:<user>D:P(A;;GA;;;<user>)`: the user owns it, and no other account can open it.

- Without a descriptor, a pipe gives read access to Everyone.
- The `O:` sets the owner to the user, also in an elevated process, whose default owner is the Administrators group. `OW` (owner rights) is not used, because an elevated daemon would then refuse a non-elevated client of the same user.
- `GA` is needed: the listener makes a new instance after each accept. `SYSTEM` and `Administrators` are not in the DACL: the control plane is per user.

**The client.** On Windows a client opens the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so the server can identify the client but not act as it. Without the flags, an account with `SeImpersonatePrivilege` (every service account) that took the name after a crash could act as the user. Then the client checks that the user owns the pipe, before it sends a byte. A pipe of another owner, or one whose owner cannot be read, is `ForeignEndpoint`. An absent endpoint, a pipe that is still busy after 3 more tries, and a pipe whose DACL leaves the user out are `NoDaemon`.

**The API.** `runtime::ipc::active_socket_paths` is `active_endpoints` (`Vec<IpcName>`), and `send_to_path` is `send_to_endpoint`. `IpcName`, `ForeignEndpoint` and `NoDaemon` are public. The Win32 calls are in `habilis-network-util` (`win_security`).

**Limits.**

- A marker that a crash leaves stays until a client fails to connect to it, as a stale socket file did. Until R5, `terminate` has no stop on Windows but `TerminateProcess`, so a stale marker is the common case there.
- On Unix, two daemons with the same nickname on one mesh have the same socket path, and the second bind replaces the first. That is not new.
- The DACL cannot be tested with a second user on CI. T4 tests it on the real machine.

### R4. Process helpers

Add Windows versions in `crates/habilis-network-util/src/process.rs`:

| Function | Windows implementation |
|---|---|
| `is_alive` | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, then `GetExitCodeProcess` is `STILL_ACTIVE`. |
| `live_start_time` | `GetProcessTimes`, creation time. |
| `comm_of` | `QueryFullProcessImageNameW`, file stem with no `.exe`. |
| `parent_of` | `CreateToolhelp32Snapshot` and `Process32NextW`. |
| `ancestry_contains` | No change. It stays generic over `parent_of`. |

### R5. Graceful stop

- Add an IPC `Quit` command. It runs the same path as `SIGTERM`: broadcast `Left`, remove the state file and the marker, exit. It answers the client before the process exits.
- `terminate` sends `Quit` on every OS. On Unix, `SIGTERM` stays as the fallback when the IPC send fails.

### R6. Owner watch

- On Windows, watch the `--owner-pid` process with `is_alive` and `live_start_time`. The start time guards against pid reuse.
- Windows has no `getppid`. Without an owner pid, there is no watch.

### R7. Console events

Ctrl-c, `ctrl_break`, `ctrl_close`, `ctrl_logoff` and `ctrl_shutdown` (`tokio::signal::windows`) all take the graceful path.

### R8. State file

- The atomic replace must work while a reader holds the file. Use `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, and retry for a short time on a sharing violation.
- Readers in this repository open the file with `FILE_SHARE_DELETE`.
- The file is private through the inherited profile ACL.

### R9. FFI

- Change `c_long` to `i64` in `ffi.rs`, and `long` to `int64_t` in `habilis_network.h`.
- Map `isize` to a 64-bit integer in `dlopen/node.ts`. Fix the comment in `abi.ts`.
- `cargo task ffi` (`tasks/src/ffi.rs`) uses `habilis_network_ffi.lib` on Windows, finds `llvm-nm.exe`, and reads COFF symbols.

### R10. Tooling and tests

- Replace `which` in `webdriver.rs` with the `which` crate.
- Add `win64` to `cdp.rs`, or skip it with a reason.
- Replace `touch -t` in `chunks/tests/origin.rs` with `File::set_modified`.
- Make the path assertions in `util/lib.rs` and `ipc.rs` correct on each OS.

### R11. Windows on CI

Windows tests run on CI for every change, so the port cannot break without a red check.
The real machine of [§6](#6-test-plan-on-a-real-windows-machine) then tests only what CI cannot.

**`ci.yml`: a `windows` job.**

- The job runs on `windows-latest`, on every push and pull request, as the `check` job does.
- It is a required check for `main`. It has no `continue-on-error`.
- It runs the native steps of the Linux `check` job:

  ```
  cargo clippy --workspace --all-targets -- -D warnings
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace
  cargo test -p habilis-network --features blob
  cargo test -p habilis-network-iroh-webrtc-transport --features native
  cargo task ffi
  ```

  `cargo task ffi` is not in the job yet: it needs R9. Add it to the job with R9.
- The job sets `CARGO_PROFILE_DEV_DEBUG=0`. With debug info, two debug builds wrote 19.9 GB on a developer machine and did not finish. Without it, all the cargo commands of the job wrote 6 GB.
- It also runs `bun install --frozen-lockfile` and `bun run test`. This tests `discover.ts` and the Node `isize` mapping on `win32`. Until R9, the smoke test is skipped on Windows, so the `isize` mapping is not tested.
- The Linux job keeps `cargo fmt --check`, `cargo doc` and the wasm32 steps.
- Steps that need bash stay on Linux: `Clippy list names only functions` and the light-cycles web job.

**A host lifecycle test.**
Add `crates/habilis-network/tests/host_lifecycle.rs`.
It runs on every OS, so CI tests on Windows what T4 and T6 test by hand:

1. Start a node in `Cli` driver mode, with a runtime base in a temporary directory.
2. IPC `Info` returns the node, and `active_endpoints` finds it.
3. IPC `Quit` stops the node. The state file and the endpoint are gone.
4. Start a node with the pid of a child process as its owner. Kill the child. The node stops within one owner-watch interval.

Steps 1 and 2 are done (part 1). Steps 3 and 4 need the node in a child process: in `Cli` mode a quit ends the process with `std::process::exit`, which would end the test binary. Part 1 stops the node with an abort of its task.

**Nightly and e2e.**

- `matrix.yml`: add `windows-latest` next to `ubuntu-latest` with `strategy.matrix.os`.
- `e2e.yml`: add `windows-latest` to the `stream` job with `strategy.matrix.os`.

**Runner toolchain.**

- Install NASM for `aws-lc-sys`, for example with `ilammy/setup-nasm`. CMake and the MSVC build tools are already on `windows-latest`.
- Use `Swatinem/rust-cache`, as the other jobs do.

### R12. Runtime base of a Unix client

On Unix the base is `/tmp/<product>-<uid>`, a path that another user can create first. Today only the writers check the base (`ensure_runtime_base`). If another user creates the base, the daemon refuses to start, but a client reads the socket or the marker that the other user put there, and sends it the commands. This gap was there before R3, with the socket file.

- Add `check_runtime_base(base)`, with the checks of `ensure_runtime_base` and no create: a folder, owned by the user, with no group or other bits.
- The client calls it before it reads a marker, and returns `ForeignEndpoint` when the base is not the user's.
- On Windows the base is in the profile, which another user cannot create, so the client needs only the owner check of the pipe.

## 4. Requirements: agent-gossip

This work is in the agent-gossip repository, on its own branch.
Start it after the engine work of [§3](#3-requirements-habilis-network).

### G0. Prerequisite

- Merge `chore-migrate-habilis-network` into agent-gossip `main`. On `main` the engine is still the old `fofoca` package.
- During development, point the engine at a local checkout:

  ```toml
  [patch."https://github.com/agent-habilis/habilis-network"]
  habilis-network = { path = "../habilis-network/feat-windows-support/crates/habilis-network" }
  ```

  Add an entry for each engine crate that `Cargo.lock` pulls from that URL.

### G1. Detach

`detach_if_owned` (`crates/agent-gossip/src/cli/mod.rs:161-216`) calls `setsid` in `pre_exec`.

- On Unix, keep it.
- On Windows, spawn with `creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB)`. If the spawn fails with access denied, try again without `CREATE_BREAKAWAY_FROM_JOB`.
- On Windows, set stdin, stdout and stderr to null.

### G2. Unix-only code

- `cli/bell.rs`: put `mode(0o600)` behind `cfg(unix)`. `File::try_lock` works on Windows.
- `cli/signal.rs`: on Windows, use ctrl-c only.
- `home_dir` (`cli/agent.rs`) and `home_path` (`status.rs`): fall back to `USERPROFILE`.
- The engine renamed two IPC calls (R3): `cli/doctor.rs` and `cli/session.rs` change `active_socket_paths` to `active_endpoints` and `send_to_path` to `send_to_endpoint`, four lines.
- The test fixtures build the path of the unix socket by hand (`agent-gossip-test-fixtures/src/lib.rs`, and the readiness checks of three `tests/*.rs` files). On Unix they keep working. On Windows they use `active_endpoints` and `send_to_endpoint`.
- `docs/manual.txt` and `docs/windows-port/specs/E3-control-socket.md` name the old socket design. Update them.

### G3. Leave

`leave` (`cli/session.rs`) stops the daemon with the engine `terminate`, which sends `Quit` (R5).

### G4. Skills

The skill launch lines are bash. They use `/tmp/agent-gossip-$(id -u)` and `$PPID` (`skills/shared/daemon-session.md`, `skills/gossip-leave/workflow.md`).
On Windows, Claude Code runs Bash tool calls in Git Bash. There, `$PPID` is an MSYS pid, not the Windows pid of the agent.

- Add `--state-file auto` and `--owner-pid auto`. The binary finds the runtime base and the pid of its parent agent.
- Change the skills to use `auto`, so the same skill text works on every OS.
- Update the snapshots in `crates/agent-gossip/src/cli/snapshots/`.

### G5. Distribution

- Add a `windows-latest` job to CI. It builds, runs the tests, and runs a smoke test:
  1. `agent-gossip create`, with `--owner-pid` set to the pid of the job shell.
  2. `broadcast`, then `poll`.
  3. `leave`. Then no `agent-gossip.exe` process stays, and the state file is gone.
- Make the job a required check.
- Add `x86_64-pc-windows-msvc` to `release.yml`, packaged as a `.zip`.
- Add a Windows install route to the README. Homebrew does not cover Windows.

## 5. Order of work

Make one commit for each step where possible.
Step 1 is done. In step 2, the `windows` job and the `matrix.yml` leg are done. Step 3 is done. In step 4, R4 is done.

1. **Compile (R1, R10).** First check from macOS with `cargo xwin check --target x86_64-pc-windows-msvc`. Then build on the Windows machine.
2. **CI (R11).** Add the `windows` job when the workspace compiles. From this step on, each change must be green on Windows.
3. **Runtime base and IPC (R2, R3).** Add the `Info` and `active_endpoints` part of `host_lifecycle.rs`.
4. **Process helpers, `Quit`, owner watch, console events (R4 to R7).** Add the `Quit` and owner-watch parts of `host_lifecycle.rs`.
5. **State file and FFI ABI (R8, R9).**
6. **agent-gossip (G0 to G5).**

## 6. Test plan on a real Windows machine

The machine is Windows 11 x64.
T1 to T4 also run on CI ([R11](#r11-windows-on-ci)). On the real machine, they confirm the CI result on a computer that is not a CI runner.
T5 to T7 run only on the real machine.
Run the commands in PowerShell unless the step says otherwise.
Record each result as a checklist item in the PR #5 description.
For each failure, attach the log from the log directory that `doctor` shows.

### 6.1 Machine setup

1. Install Visual Studio Build Tools with the "Desktop development with C++" workload.
2. Install rustup. The toolchain in `rust-toolchain.toml` installs on the first `cargo` call.
3. Install Git for Windows, CMake, NASM and Bun.
4. Install Claude Code.
5. Clone the repository and check out `feat-windows-support`.
6. On the first run, allow the Windows Firewall prompt for private networks.
7. Make sure that the disk has 15 GB free or more. Build without debug info, as the CI job does:

   ```powershell
   $env:CARGO_PROFILE_DEV_DEBUG = "0"
   ```

   With debug info, two debug builds of the test executables wrote 19.9 GB and did not finish.
   To keep the setting, use `setx CARGO_PROFILE_DEV_DEBUG 0` and open a new shell. The setting then applies to all Rust projects of the user.

### T1. Build and unit tests

```powershell
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Pass: all three are green.

### T2. Loopback integration tests

```powershell
cargo test -p habilis-network --test gossip_only
cargo test -p habilis-network --test rendezvous_release_loopback
cargo test -p habilis-network --test underlay_webrtc_loopback
cargo task matrix --list
```

Then run two cells from the list by name.
Pass: all are green, and no test hangs past its own timeout.

### T3. FFI

```powershell
cargo build --release -p habilis-network-ffi
cargo task ffi
bun test packages/habilis-network-ffi
```

Then run `examples/chat/bun-ffi` on Windows and join a mesh with a macOS peer.
Send a message in each direction.
Do it again under Node with koffi. This tests the `isize` fix of R9.
Pass: the messages arrive, and the peer count is correct on both sides.

### T4. Runtime directory and IPC security

1. Start a daemon. The runtime base appears under `%LOCALAPPDATA%`.
2. `Get-Acl` on the base shows only the user, `SYSTEM` and `Administrators`.
3. `[System.IO.Directory]::GetFiles("\\.\pipe\")` lists the pipe, `habilis-` and 32 hex digits. The marker `<nick>.ipc` in the mesh folder holds the same name.
   Read the ACL of the pipe with Sysinternals `accesschk.exe -l -o \\.\pipe\habilis-*`. The user is the owner and the only entry. `Get-Acl` cannot read a pipe.
4. Create a second local user. Connect to the pipe as that user with `runas /user:<second-user>`. The connection is refused.

### T5. agent-gossip lifecycle

Do this after G0 to G5.
Use one Windows peer and one macOS peer.

1. Run `agent-gossip plug` on Windows.
2. In Claude Code on Windows, run `/gossip-create`.
3. On macOS, run `/gossip-join <id>`.
4. Broadcast from each side. Each side receives the message.
5. `poll --long` on Windows wakes up when the macOS peer sends.
6. Run `/gossip-msg` in each direction.
7. `/gossip-status` on each side lists both peers.
8. `/gossip-doctor` on Windows finds the active mesh.
9. Run `/gossip-leave` on Windows.

Pass:

- macOS shows that the Windows peer left.
- The Windows state file is gone.
- `Get-Process agent-gossip` finds no process.

### T6. Failure paths

| Action on Windows | Expected result |
|---|---|
| Kill the Claude Code process that owns the daemon (`Stop-Process -Force`). | The daemon stops within one owner-watch interval. macOS sees the peer leave or time out. |
| Close the console window of a foreground node. | The graceful `Left` arrives on macOS (`ctrl_close`). |
| Sign out, then sign in. | No stale state file stays. |
| Pid reuse after the owner dies. | A unit test covers this: the start time does not match, so the watch stops the daemon. |

### T7. Network

| Setup | Expected result |
|---|---|
| Windows and macOS on the same LAN. | mDNS finds the peer. |
| Windows behind a home NAT, macOS on a different network. | A direct path or the relay connects them. |
| Windows Firewall blocks the program. | The relay still connects them. |

## 7. Build on Linux and WSL

Use WSL 2 on the same machine to run the Linux steps of `ci.yml`.
A WSL peer is not a second machine. In the default NAT networking mode, it does not test T7. Use it for T1 to T3 only, or set `networkingMode=mirrored`.

### 7.1 Limits

With the WSL defaults, a build of the workspace can stop with no memory.
The defaults are half of the RAM, a small swap (2 GB on a machine with 16 GB) and all of the processors.
Cargo then runs one `rustc` and one link for each processor, and the test executables are large with debug info.

1. Set the limits of the WSL VM in `%USERPROFILE%\.wslconfig`. These values are for a machine with 16 GB and 16 threads:

   ```ini
   [wsl2]
   memory=10GB
   swap=8GB
   processors=8
   ```

   Run `wsl --shutdown` from PowerShell. The limits apply when WSL starts again.
   Docker Desktop uses the same VM memory. Stop it while you build.
2. Set the build limits in `~/.bashrc`:

   ```bash
   export CARGO_PROFILE_DEV_DEBUG=0
   export CARGO_BUILD_JOBS=6
   export RUST_TEST_THREADS=4
   ```

   `RUST_TEST_THREADS` limits the tests that run at the same time in one test executable. Many tests start real nodes.

### 7.2 Disk

- Clone the repository in the Linux file system, for example `~/dev/habilis-network`. Do not build in `/mnt/c`. There, all file access goes through 9P. 9P is slow. Also, `target/` goes to the Windows disk.
- The disk of the distribution is an `ext4.vhdx` file on the Windows disk. It grows when the build writes, and it does not become smaller when you delete files. To give the free space back:

  1. In WSL, run `sudo fstrim -a`.
  2. In PowerShell, run `wsl -l -v` to find the name of the distribution, then `wsl --shutdown`.
  3. Run `diskpart` as administrator, and type:

     ```
     select vdisk file="<path to ext4.vhdx>"
     compact vdisk
     exit
     ```

  `wsl --manage <distribution> --set-sparse true` makes WSL do this automatically. Some WSL releases turned sparse disks off after reports of data corruption, so use `diskpart`.
- If the disk is already sparse, step 1 alone gives the space back, while WSL runs. `diskpart` then refuses `compact vdisk`: its message ends with "must not be sparse". Steps 2 and 3 do not apply. This was seen on one WSL release.
- If the disk is full, run `cargo clean`. It removes `target/`.

### 7.3 Commands

These are some of the native steps of the `check` job of `ci.yml`.

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p habilis-network --features blob
cargo test -p habilis-network-iroh-webrtc-transport --features native
```

The Linux job of `ci.yml` also runs `cargo fmt --check`, `cargo doc`, the `--all-features` clippy, `cargo test -p tasks --features bench` and the wasm32 steps. You can run them in WSL too.
