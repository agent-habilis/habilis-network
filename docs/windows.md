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

The workspace compiles on Windows, and the `windows` job of `ci.yml` runs clippy, `cargo task ffi` and the tests there.
The IPC of a daemon works on Windows, over a named pipe. A daemon stops gracefully on an IPC `quit`, on the exit of its owner, and on ctrl-c, ctrl-break and the close of its console. A CLI daemon also stops gracefully on a logoff, a shutdown and `taskkill /PID` without `/F`.

| Requirement | State |
|---|---|
| R1. Compile | Done. `libc` and `windows-sys` come in through `host`, each on its own target. |
| R2. Runtime base | Done. `runtime_base` returns `<LocalAppData>\<product>\run`, and `ensure_runtime_base` rejects a reparse point at the base (`crates/habilis-network-util/src/lib.rs`). |
| R3. IPC | Done. On Windows the endpoint is a named pipe with a random name and a DACL of the user, and a client checks the owner of the pipe. On Windows discovery reads a `<nick>.ipc` marker. On Unix a client finds the socket by its path, as on `main` (`crates/habilis-network/src/transport/ipc.rs`). |
| R4. Process helpers | Done. `is_alive`, `live_start_time`, `comm_of` and `parent_of` have Windows versions in `process.rs`. `parent_of` also gives no parent when the creator has exited or is newer than its child. |
| R5. Graceful stop | Done. On Windows the engine answers an IPC `quit` and takes the path of `SIGTERM`. `runtime::ipc::terminate` stops a daemon on every OS: with the quit on Windows, with `SIGTERM` on Unix, as on `main` (`crates/habilis-network/src/transport/ipc.rs`). |
| R6. Owner watch | Done. A daemon with `--owner-pid` watches its owner on every OS (`crates/habilis-network/src/daemon/shutdown.rs`). The watch of the parent pid stays Unix only. |
| R7. Console events | Done. Ctrl-c, ctrl-break, close, logoff and shutdown feed the quit channel (`crates/habilis-network/src/daemon/shutdown.rs`). A logoff and a shutdown do not reach these listeners in a node that loaded `user32.dll`, and a node loads it: a CLI daemon gets them through a window (R13). |
| R8. State file | Done. The replace and the remove of the state file and of the IPC marker run again for up to 50 ms while a reader blocks them (`crates/habilis-network-util/src/file_retry.rs`). |
| R9. FFI | Done. On Windows the five calls that returned `long` return `int64_t`, through the `habilis_network_len` of the header, which stays `long` on every other target (`crates/habilis-network-ffi`). The loaders read them as `i64`, koffi as `int64_t` on Windows. `cargo task ffi` reads `habilis_network_ffi.lib` with `llvm-nm.exe` (`tasks/src/ffi.rs`). |
| R10. Tooling and tests | Done. `cdp.rs` has no `win64` build and says why. Set `$CHROME_FOR_TESTING` to a local Chrome. |
| R11. Windows on CI | Partly done. The `windows` job of `ci.yml`, the Windows leg of `matrix.yml`, and the six steps of `host_lifecycle.rs` run. `cargo task ffi` and the smoke test of the Bun loader against the release DLL run in the `windows` job (R9). Open: the `e2e.yml` stream job, and the required-check setting of the repository. The Node loader (koffi) runs on no CI job, only in T3. Until the fix of #31 is in `agent-habilis/iroh`, a `[patch]` in the root `Cargo.toml` points the iroh family at that fix: on Windows the test relay logged a client reset as ERROR, which failed loopback tests under the rule of #22. The four loopback tests of #31 run on Windows again. The patch holds only in this workspace. |
| R12. Runtime base of a Unix client | Partly done. `check_runtime_base` exists. The IPC client does not call it in this port, because the port leaves Unix as it is on `main` ([R14](#r14-unix-as-on-main)). The client check goes to its own change on `main`. See [R12](#r12-runtime-base-of-a-unix-client). |
| R13. Logoff and shutdown | Done. A CLI daemon has a hidden window, and a logoff, a shutdown, a close by the Restart Manager or a `WM_CLOSE` feeds the quit channel (`crates/habilis-network-util/src/win_session.rs`, `crates/habilis-network/src/daemon/shutdown.rs`). |
| R14. Unix as on `main` | Done on Windows; the run on Linux is open. The client check of R12 is out of the port. On Unix a client finds a daemon by its socket path again, the engine answers no IPC command, the lines of the daemon are as on `main`, and the C header declares `long`. See [R14](#r14-unix-as-on-main). |

[§2.2](#22-runtime-breaks) has no open item. The open lines of [§2.3](#23-tooling-and-tests) are still true, but their line numbers can be out of date.
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

These problems occurred after the workspace compiled. None is left. The three IPC items that were here (the name, the discovery and the security of the endpoint) are done with R3. The stop item is done with R5, the owner watch item with R6, the console events item with R7 and R13 (a logoff and a shutdown), the state file item with R8, and the two FFI items (the Node mapping and the C ABI) with R9.

### 2.3 Tooling and tests

Open:

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

**The marker, on Windows.** A daemon writes the name of its pipe in `<mesh folder>/<nick>.ipc`, one line, after the listener exists and before the daemon reports ready. A client finds the daemon through the marker, because a pipe is not a file in the mesh folder. On Windows `active_endpoints` reads the markers. The marker is written by the writer of the state file (`.tmp.<pid>`, then a rename). A marker that cannot be written fails the bind. The shutdown removes the marker only while it still names this daemon. The marker is not in the state file, because a `--state-file` override can put the state file outside the base, and an in-process node writes none. On Unix a daemon writes no marker: the endpoint is the same socket as on `main`, and a client finds it by its path ([R14](#r14-unix-as-on-main)). The first version of R3 wrote the marker on every OS, so a client of the port did not find a daemon of `main`.

**The name of the pipe.** `\\.\pipe\habilis-` and 128 random bits in hex. Pipe names live in one namespace for the whole machine, and any account can make a pipe with a free name.

- A fixed name, as this section first asked (`<product>-<user hash>-<mesh-prefix>-<nick>`), lets another account make the pipe first. Then the bind fails, and clients reach that account.
- A random name cannot be taken before it exists. After that it is public: any account lists pipe names, for example with `Get-ChildItem \\.\pipe\`. So the name is no secret, and the protection is the DACL and the owner check below.
- The name has no mesh prefix and no nickname. The mesh prefix is part of the mesh id, and the list of pipe names is open to every account.

**The DACL.** The pipe has the security descriptor `O:<user>D:P(A;;GA;;;<user>)`: the user owns it, and no other account can open it.

- Without a descriptor, a pipe gives read access to Everyone.
- The `O:` sets the owner to the user, also in an elevated process, whose default owner is the Administrators group. `OW` (owner rights) is not used, because an elevated daemon would then refuse a non-elevated client of the same user.
- `GA` is needed: the listener makes a new instance after each accept. `SYSTEM` and `Administrators` are not in the DACL: the control plane is per user.

**The client.** On Windows a client opens the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so the server can identify the client but not act as it. Without the flags, an account with `SeImpersonatePrivilege` (every service account) that took the name after a crash could act as the user. Then the client checks that the user owns the pipe, before it sends a byte. A pipe of another owner, or one whose owner cannot be read, is `ForeignEndpoint`. An absent endpoint, a pipe that is still busy after 3 more tries, and a pipe whose DACL leaves the user out are `NoDaemon`.

**The API.** `active_endpoints` (`Vec<IpcName>`) and `send_to_endpoint` work on every OS, and a client that runs on Windows uses them. On Unix `active_socket_paths` and `send_to_path` stay, with the signatures of `main`, and `active_endpoints` lists the same sockets. `IpcName`, `ForeignEndpoint` and `NoDaemon` are public. The Win32 calls are in `habilis-network-util` (`win_security`).

**Limits.**

- A marker that a crash leaves stays until a client fails to connect to it, as a stale socket file does on Unix. A graceful stop removes the marker of its own daemon (R5). A hard kill, such as `Stop-Process -Force`, leaves it, as a crash does.
- Two daemons with the same nickname on one mesh: the read and the remove of the marker at the exit of the first are two steps, so a write of the second between them is possible. Then the marker of the live second daemon goes, and no client finds it. On Unix the second bind replaces the socket of the first, as on `main`.
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

Done.

**The command.** On Windows the engine answers `{"command":"quit","mesh":"<mesh id>"}` on the IPC endpoint, before the app sees the line. Every app with an IPC endpoint on Windows gets it, and an app command with that shape never reaches the app there. A line that does not parse as that command goes to the app as before. On Unix the engine answers no command, as on `main` ([R14](#r14-unix-as-on-main)): a daemon there stops on `SIGTERM`.

**The path.** The daemon writes `{"ok":true}`, then feeds the quit channel that the signals and the owner watch feed. The shutdown then removes the state file and the marker, broadcasts `Left`, and exits. So the client has the answer before the process exits. The channel is fed also when the client does not read the answer.

**The mesh guard.** A quit for another mesh is refused and stops nothing, so a stale marker cannot stop another session.

**The client.** `runtime::ipc::quit(&QuitTarget)` sends the quit at the address of `send`: the runtime base, the mesh and the nickname. Its `QuitError` tells the cases apart: the quit was not heard (`Unreached`), the daemon is too old to know it (`OldDaemon`), or the daemon refused it (`Refused`). On Unix it is `Unsupported` and opens no connection. `runtime::ipc::terminate(&QuitTarget, pid)` stops a daemon on every OS: on Windows it sends the quit, and on Unix it sends `SIGTERM` to `pid`. On Unix the caller must know that `pid` is the daemon of the target, for example from its `Info` answer.

**Two `terminate` functions.** `util::process::terminate(pid)` does not change: it only signals a pid, and on Windows it returns `Unsupported`, because the util crate sits below the IPC. It keeps its name, because a rename would break a caller on Unix.

### R6. Owner watch

Done.

**The watch.** A daemon with `--owner-pid` (`EventLoopConfig::with_owner_pid`) watches its owner on every OS, with the same code. Every `PPID_WATCH_INTERVAL` (1.5 s), `Owner::lost` compares `live_start_time` of the owner with the start time that it read at startup. The start time guards against pid reuse. The watch calls `live_start_time` only, not `is_alive`: on Windows `live_start_time` gives `None` for an owner that exited, also while a handle still holds it, as `is_alive` does. When the owner is gone, the watch feeds the quit channel, and on Windows it writes `owner exited; leaving` (target `habilis_network::lifecycle`). The daemon then takes the path of `SIGTERM`.

**No owner, no watch on Windows.** Windows has no `getppid`, does not reparent an orphan, and can reuse the pid of a dead parent. So a daemon with no owner pid has no watch on Windows. The watch of the parent pid stays Unix only.

**Limits.**

- An owner that this process cannot read is refused at startup. On Windows the error says "is not running or cannot be read", and that is a live owner of another account. On Unix the error is "is not running", as on `main`. An owner that cannot be read later counts as gone: the watch fails closed. An owner of the same user is readable also across integrity levels.
- An owner that exits with the code 259 (`STILL_ACTIVE`) reads as alive while a handle holds it.
- The start time has the resolution of the system clock (about 15.6 ms). A reused pid with the same start time would need the owner to exit, every handle to close, and the pid to come back within one tick.
- An owner that puts the daemon in a job with `KILL_ON_JOB_CLOSE` kills it hard, before the watch, with no `Left`.
- A watch that holds a handle of the owner from startup and waits on it would be immediate and immune to pid reuse. It needs new `unsafe` code, and the start time already covers reuse, so it is a possible later change.

**Who uses it.** agent-gossip does not start a daemon on Windows before G1, and its skills pass the MSYS `$PPID` before G4. Until then, step 4 of the host lifecycle test proves the watch on Windows, on CI.

### R7. Console events

Done.

**The listeners.** `spawn_console_event_tasks` in `crates/habilis-network/src/daemon/shutdown.rs` makes the five listeners of `tokio::signal::windows`. Each feeds the quit channel, so the daemon takes the path of `SIGTERM`, and writes `console event; leaving` (target `habilis_network::lifecycle`). The listeners are made before the node is ready: an event with no live receiver goes to the default handler, which ends the process with `STATUS_CONTROL_C_EXIT` and no `Left`.

**The deadline.** On a close, a logoff or a shutdown, Windows ends the process when the handler returns. So the handler of tokio never returns, and the process lives until the `std::process::exit` of the quit path, or until the deadline of Windows: about 5 s for a close, and `WaitToKillAppTimeout` (5 s by default) for a logoff or a shutdown. The quit path removes the state file and the marker first, then sends the `Left` and waits 500 ms. Then the loop releases the rendezvous and closes the endpoints that it owns (`Router::shutdown`, then `Endpoint::close`), which iroh says can take up to about 3 s with bad connectivity, and only then exits. About 3.5 s in the worst case is still inside the deadline of a close, and the state file and the marker are already gone before it.

**Limits.**

- A logoff and a shutdown do not reach these listeners. Windows does not give them to the console handler of a process that loaded `user32.dll` or `gdi32.dll`. A node loads both: iroh's `netwatch` uses COM through the `wmi` crate, and the runtime base uses `SHGetKnownFolderPath` of `shell32.dll`. On a node in `Cli` mode, `USER32.dll`, `GDI32.dll`, `ole32.dll` and `combase.dll` were loaded. The listeners stay, for a build that does not load them. A CLI daemon gets them through the window of R13.
- Only a process with a console gets console events: a node in the foreground of a terminal. A process started with `DETACHED_PROCESS` has no console. With `CREATE_NO_WINDOW` it has a hidden console that nobody closes. The daemon of agent-gossip on Windows (G1) is one of these, so the IPC `quit` of R5 and the owner watch of R6 stop it, and the window of R13 gets its logoff and its shutdown.
- A process in a new process group (`CREATE_NEW_PROCESS_GROUP`), or the child of a parent that ignores ctrl-c, ignores ctrl-c. Ctrl-break still reaches it.

**The test.** Step 5 of the host lifecycle test starts a node in a console of its own and sends it ctrl-break and ctrl-c from a third process, through `win_console::send_console_event` of `habilis-network-util` (behind `test-fixtures`). Without the listeners, the ctrl-break test fails: the node exits with `0xC000013A`. No process can raise a close, so T6 tests it by hand.

### R8. State file

Done.

**What blocks the replace.** `write_private_atomic` (`crates/habilis-network/src/daemon/state_file.rs`) writes the state file and the IPC marker: a sibling `<file>.tmp.<pid>`, then `std::fs::rename` over the target. The rename of `std` calls `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, and on error 5 it replaces the file with POSIX semantics. So it replaces a file that a reader holds with `FILE_SHARE_DELETE`, and a switch to `MoveFileExW` would add nothing. A reader without `FILE_SHARE_DELETE` makes the rename fail with error 5 (`ERROR_ACCESS_DENIED`), and the remove fail with error 32 (`ERROR_SHARING_VIOLATION`), while it holds the file.

**Measured** on a Windows 11 host, with Rust 1.95:

| Reader, in a tight loop | Failed renames | Failed removes |
|---|---|---|
| None | 0 of 3000 | 0 of 2000 |
| PowerShell `Get-Content -Raw` | 2620 of 3000 | 297 and 312 of 2000 |
| .NET `[IO.File]::ReadAllText` | 2640 of 3000 | not measured |
| .NET `[IO.File]::Open(..., 'ReadWrite,Delete')` | 0 of 3000 | not measured |

With a retry every 1 ms for up to 100 ms, no rename and no remove failed. The worst wait was 10.7 ms for a rename and 17.6 ms for a remove.

**The fix.** `util::file_retry::retry_while_shared` runs the rename and the remove again every `SHARED_FILE_RETRY_STEP` (1 ms) while they fail with error 5 or 32, up to `SHARED_FILE_RETRY_DEADLINE` (50 ms). Any other error comes back at once. It wraps the rename of `write_private_atomic`, the remove of `StateFile::remove` on Windows, and the remove of the marker (`IpcMarker::remove_if_ours`). On Windows `StateFile::remove` logs a remove that fails for a reason other than a missing file, and a failed rename removes its tmp file. On Unix the retry runs the operation once, and both are as on `main`.

**Limits.**

- The state file is written in line, in the loop of the daemon, every `STATE_REFRESH` and on a change of members. With a reader that blocks it, one write can stall the loop for up to the deadline plus one sleep, about 65 ms. At a graceful exit the two removes, the state file and then the marker, can each wait as long before the `Left`, so about 130 ms in all, well inside the deadline of R7.
- Error 5 is also a real refusal, such as a rename over a directory. The retry delays that error by the deadline, and then it comes back unchanged.
- A reader that holds the file for longer than the deadline, such as an editor, makes the write fail. The daemon logs the failure once, and the next write tries again.
- Every reader in this repository and in agent-gossip uses `std::fs`, which opens with `FILE_SHARE_DELETE`, so none of them blocks a write. A reader in PowerShell, such as a statusline, should open the file with `[IO.File]::Open($path, 'Open', 'Read', 'ReadWrite,Delete')`, not with `Get-Content`.
- Under the runtime base of R2 (`<LocalAppData>\<product>\run`) the file is private through the inherited profile ACL. A `--state-file` outside the base gets the ACL of the folder that it names.

### R9. FFI

Done.

- The five calls that returned `long` return `habilis_network_len` in `habilis_network.h`, and `CLen` in `ffi.rs`. On Windows it is `int64_t` (`i64`): `long` is 32 bits there, and the Bun and Deno loaders read 64 bits, so a -1 came back as 4294967295. On every other target it is `long` (`c_long`), so the header of Linux and macOS declares the same types as on `main` ([R14](#r14-unix-as-on-main)). The first version of R9 used `int64_t` on every target, which on macOS is `long long`, another C type than `long`.
- In `packages/habilis-network-ffi` the internal `CType` `'isize'` is `'i64'`, and the Node loader gives koffi `int64_t` on Windows and `long` elsewhere. `abi.test.ts` holds the return type of each call against the header, and the `#ifdef` of the type. `smoke.test.ts` reads -1 from a call with a NULL handle.
- `cargo task ffi` (`tasks/src/ffi.rs`) reads `habilis_network_ffi.lib` on Windows with the `llvm-nm.exe` of the `llvm-tools` component. COFF symbols on x86_64 have no underscore, so the same parse reads them, as it reads ELF.

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
  cargo task ffi
  cargo test --workspace
  cargo test -p habilis-network --features blob
  cargo test -p habilis-network-iroh-webrtc-transport --features native
  ```

  `llvm-tools` is in the toolchain step, for `cargo task ffi` (R9).
- The job sets `CARGO_PROFILE_DEV_DEBUG=0`. With debug info, two debug builds wrote 19.9 GB on a developer machine and did not finish. Without it, all the cargo commands of the job wrote 6 GB.
- It also runs `bun install --frozen-lockfile` and `bun run test`, after `cargo task ffi`. This tests `discover.ts` on `win32`, and the smoke tests load the release DLL through the Bun loader. A second step runs `smoke.test.ts` with `HABILIS_NETWORK_LIB` set to the DLL, so a missing DLL fails the step and the tests are not skipped. The Node loader (koffi) is not run on CI.
- The Linux job keeps `cargo fmt --check`, `cargo doc` and the wasm32 steps.
- Steps that need bash stay on Linux: `Clippy list names only functions` and the light-cycles web job.

**A host lifecycle test.**
Add `crates/habilis-network/tests/host_lifecycle.rs`.
It runs on every OS, so CI tests on Windows what T4 and T6 test by hand:

1. Start a node in `Cli` driver mode, with a runtime base in a temporary directory.
2. IPC `Info` returns the node, and `active_endpoints` finds it.
3. On Windows the IPC `quit` stops the node, and on Unix the `SIGTERM` of `terminate`. The state file is gone, and nothing answers on the endpoint.
4. Start a node with the pid of a child process as its owner. Kill the child. The node stops within one owner-watch interval plus the `Left` delay.
5. On Windows, start a node in a console of its own. Ctrl-break and ctrl-c stop it by the graceful path.
6. On Windows, send the window of one node a logoff (`WM_QUERYENDSESSION`, then `WM_ENDSESSION`), and post the window of another node a `WM_CLOSE`. Each stops its node by the graceful path, and the node logs the line of the event.

The six steps are done. In `Cli` mode a quit ends the process with `std::process::exit`, which would end the test binary. So every step runs the node in a child process: the test binary itself, with only its `child_node` entry selected. In step 4 the owner is a second child process, the test binary with only its `owner_process` entry selected. In step 5 the sender of the event is a second child process, with only its `console_sender` entry selected. In step 6 the test sends the messages itself (`win_session::send_session_end` and `post_window_close`, behind `test-fixtures`). In the test nothing ends the node when its window procedure returns, so the wait of the node until its `Left` is tested by hand (T6). Step 1 kills its child at the end. An abort of an in-process node would drop its endpoint with no `Endpoint::close`, and iroh logs that as an ERROR, which fails a test since #22.

**Nightly and e2e.**

- `matrix.yml`: add `windows-latest` next to `ubuntu-latest` with `strategy.matrix.os`.
- `e2e.yml`: add `windows-latest` to the `stream` job with `strategy.matrix.os`.

**Runner toolchain.**

- Install NASM for `aws-lc-sys`, for example with `ilammy/setup-nasm`. CMake and the MSVC build tools are already on `windows-latest`.
- Use `Swatinem/rust-cache`, as the other jobs do.

### R12. Runtime base of a Unix client

On Unix the base is `/tmp/<product>-<uid>`, a path that another user can create first. Only the writers check the base (`ensure_runtime_base`). If another user creates the base, the daemon refuses to start, but a client reads the socket or the marker that the other user put there, and sends it the commands. This gap was there before R3, with the socket file.

Partly done.

- `check_runtime_base(base)` (`crates/habilis-network-util/src/lib.rs`) has the checks of `ensure_runtime_base`, creates nothing and changes nothing. It returns `RuntimeBaseCheck`: `Private` (a folder of the user with no group or other bits), `Absent`, or `Refused` with the reason. A base at `0755` is refused, not tightened.
- The IPC client does not call it. A port commit made `send` and `active_endpoints` refuse a base that is not private, with `UnsafeRuntimeBase`. R14 took that commit out, because it changed the behavior of a Unix client, and the port leaves Unix as it is on `main`.
- On Windows the base is in the profile, which another user cannot create, so the client needs only the owner check of the pipe.

Follow-up items, outside the port:

- A change on `main` makes the IPC client check the base, in its own pull request, and names it as a change of behavior. On `main`, `send` connects to the socket path and `active_socket_paths` lists the sockets, so the change is written for that code, not taken from the port.
- In the same change: `read_identity`, `read_session_entry` and `read_snapshot` (`runtime::state_file`) read the state files under the same base and do not check it. `doctor` in agent-gossip should show why it finds no daemon.
- A caller that makes the base itself with `create_dir_all` (`0755` under the usual umask), as some fixtures and tests of agent-gossip do, would get the refusal. Check them before that change lands.

### R13. Logoff and shutdown

Before R13, a logoff or a shutdown ended a daemon with no `Left`, because the process loaded `user32.dll` (see R7). The state file stayed with the pid of a dead process. The readers of agent-gossip skip such a file: `cli/session.rs` checks that the pid is alive and is `agent-gossip`, and `cli/mod.rs` refuses an old `last_updated`.

Done.

- `win_session::watch_session_end` (`crates/habilis-network-util/src/win_session.rs`) makes a hidden top-level window on a thread of its own, with a message loop. A message-only window (`HWND_MESSAGE`) gets no broadcast message, so it is of no use here. The call returns when the window exists, so the window is there when the node is ready.
- `WM_QUERYENDSESSION` gets `TRUE`, so the daemon never stops the end of the session. `WM_ENDSESSION` with `TRUE` gives the kind from the bits of `lParam`: a logoff, a shutdown, or a close by the Restart Manager (`ENDSESSION_CLOSEAPP`). `WM_CLOSE`, which `taskkill /PID` without `/F` sends, is an event too. The window does not destroy itself on it.
- Only the CLI daemon has the window (`spawn_session_end_watch` in `crates/habilis-network/src/daemon/shutdown.rs`): it alone exits the process. On the end of the session it feeds the quit channel, writes `session end; leaving`, and its window thread does not return, because Windows ends the process when it does. The process lives until the `std::process::exit` of the quit path, or until the deadline (`WaitToKillAppTimeout`, 5 s by default). On `WM_CLOSE` it feeds the quit channel, writes `window close; leaving`, and returns, because a close has no deadline.
- The quit path fits the deadline: the state file and the marker go first (about 130 ms), then the `Left` and its 500 ms, then the release of the rendezvous (up to about 3 s with bad connectivity). The quit arm of the loop is read only when the current arm ends, so a probe that runs adds its time. The console events of R7 have the same gap.
- When the window cannot be made, the daemon logs a warn and runs on, with the behavior from before R13.
- A window makes Windows count the process as a window process in the order of a shutdown.
- `WM_CLOSE` carries no sender, so the window cannot refuse one. A process of the same user could already stop the daemon (`taskkill /F`, the IPC `quit`). The window adds one sender: a process of another account on the same desktop, at the same or a higher integrity level. It can only make the daemon leave, and it gets no data back. Windows blocks a sender at a lower integrity level, except a `uiAccess` process.
- Step 6 of the host lifecycle test ([R11](#r11-windows-on-ci)) sends the messages to the window of a node in a child process. The wait of the node until its `Left` is tested by hand, in T6.

Follow-up items, outside R13:

- agent-gossip needs no code change for R13, only the engine version that has it. After G1, the sign-out row and the `taskkill` row of T6 check it.
- The window gets the end of the session only in the interactive session of the user, on window station `WinSta0`. A child process gets the window station and the desktop of its parent, and the creation flags of G1 do not change them. So the daemon of G1 gets the end of the session only when its parent is in that session. A daemon under a service or an SSH session gets none. A service gets `SERVICE_CONTROL_SHUTDOWN` from the service control manager instead.
- The window thread does not return from `WM_ENDSESSION`, so the screen of the apps that are still open can list the daemon, by the title of the window (`habilis-network-session`) or by the name of the program. In T6 a logoff with one CLI daemon and no peer showed no such screen. The daemon logged `leaving mesh`, after its `Left`, and left no state file or marker. T6 did not show why: the quit path may have ended before the deadline, or Windows may not list a hidden window. A slow quit path, such as a release of the rendezvous with bad connectivity, can still make the screen show. T6 did not test that. `ShutdownBlockReasonCreate` sets a reason that a user can read, such as "leaving the mesh". It is not known whether a reason makes the screen show on each logoff, so R13 does not use it. Add it only when a user sees the screen.

### R14. Unix as on `main`

Many projects build on the engine. The port leaves Linux and macOS as they are on `main`: the API, the ABI, the C header, the wire and the behavior. A change of the port is Windows only, or it adds an item and changes none. A change of Unix behavior goes to its own pull request on `main`.

Done on Windows.

- The client check of the runtime base ([R12](#r12-runtime-base-of-a-unix-client)) is out of the port.
- On Unix a client finds a daemon by its socket path, as on `main`. The IPC marker is Windows only. `active_socket_paths` and `send_to_path` are back on Unix, with the signatures of `main`, and `active_endpoints` and `send_to_endpoint` work on every OS. The IPC log lines of Unix have the target, the text and the fields of `main`.
- The lines and the messages that the port added to the daemon are Windows only: the warn of a failed remove of the state file, the removal of the tmp file after a failed rename, the `info` line of the owner watch, and the "or cannot be read" of a refused owner. The `info` line of the parent watch, which is Unix only, is gone.
- The engine answers the IPC `quit` only on Windows. On Unix every line reaches the app, `quit` is `QuitError::Unsupported`, and `terminate` sends `SIGTERM`. The signal handlers and the owner watch of Unix start where they started on `main`, after the bind of the IPC socket.
- The C header declares `long` on every target but Windows, through `habilis_network_len`, and `int64_t` on Windows.

What stays different on Unix:

- The port adds items, such as `IpcName`, `active_endpoints`, `send_to_endpoint`, `QuitTarget`, `QuitError`, `quit`, `terminate` and `check_runtime_base`. An item that exists on `main` keeps its signature and its behavior. The exception is the internal `CType` of `packages/habilis-network-ffi`, a private package, where `'isize'` is `'i64'` (R9). Linux has not checked this yet.
- The `[patch]` of iroh ([R11](#r11-windows-on-ci)) holds in this workspace on every OS, so a build of this workspace on Linux or macOS uses the fork. A project that depends on the engine does not get it. It changes only the level of one relay log line. The patch goes when the fix is in `agent-habilis/iroh`.

Open:

- The proof runs on a Linux machine before the push: `cargo semver-checks` against `main` for each library crate, and agent-gossip `main` against `main` and against the port, with no change to agent-gossip.

Follow-up items, outside R14:

- On Unix two fixes that R14 made Windows only go to their own pull request on `main`: the removal of the tmp file after a failed rename, and the target `habilis_network::lifecycle` on the IPC log lines (the bind, the listening line, an accept error, an idle connection).

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
- On Unix `active_socket_paths` and `send_to_path` do not change, so `cli/doctor.rs` and `cli/session.rs` keep them. On Windows they use `active_endpoints` and `send_to_endpoint`, behind `cfg(windows)`.
- The test fixtures build the path of the unix socket by hand (`agent-gossip-test-fixtures/src/lib.rs`, and the readiness checks of three `tests/*.rs` files). On Unix they keep working. On Windows they use `active_endpoints` and `send_to_endpoint`.
- `docs/manual.txt` and `docs/windows-port/specs/E3-control-socket.md` name the old socket design. Update them.

### G3. Leave

`leave` (`cli/session.rs`) stops the daemon with `runtime::ipc::terminate` (R5) in place of `util::process::terminate`. It already has the target (the runtime base, the mesh and the nickname) and the pid that its `Info` check confirms. On Unix `runtime::ipc::terminate` sends the same `SIGTERM`, so `leave` does what it did before. On Windows it sends the IPC quit.

`util::process::terminate` keeps its name and its Windows version, which returns `Unsupported`: a rename would break a caller on Unix ([R14](#r14-unix-as-on-main)).

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
Step 1 is done. In step 2, the `windows` job and the `matrix.yml` leg are done. Step 3 is done. In step 4, R4 to R7 are done. Step 5 is done. R13 is done too. R14 is done on Windows, and its run on Linux is open. R12 is partly done.

1. **Compile (R1, R10).** First check from macOS with `cargo xwin check --target x86_64-pc-windows-msvc`. Then build on the Windows machine.
2. **CI (R11).** Add the `windows` job when the workspace compiles. From this step on, each change must be green on Windows.
3. **Runtime base and IPC (R2, R3).** Add the `Info` and `active_endpoints` part of `host_lifecycle.rs`.
4. **Process helpers, `quit`, owner watch, console events (R4 to R7).** Add the `quit`, owner-watch and console-event parts of `host_lifecycle.rs`.
5. **State file and FFI ABI (R8, R9).**
6. **Unix as on `main` (R14).** Before agent-gossip, so that the engine it pins changes nothing on Unix.
7. **agent-gossip (G0 to G5).**

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
Do it again under Node with koffi. This tests the koffi `int64_t` mapping of R9, which no CI job runs.
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
| Kill the Claude Code process that owns the daemon (`Stop-Process -Force`), after G1. | The daemon stops within one owner-watch interval plus the `Left` delay, about 2 s. macOS sees the peer leave. |
| Close the console window of a foreground node. | The graceful `Left` arrives on macOS (`ctrl_close`). |
| Stop a daemon with an IPC `quit` (`/gossip-leave` after G3). | The graceful `Left` arrives on macOS. The state file and the marker are gone. |
| Sign out, then sign in, with a CLI daemon running. | The graceful `Left` arrives on macOS, and no stale state file stays (R13). While the daemon holds `WM_ENDSESSION`, Windows can show its screen of the apps that are still open; "Sign out anyway" can end the daemon before its quit path ends, and then the `Left` can be lost. |
| Stop a daemon with `taskkill /PID <pid>`, without `/F`. | The daemon logs `window close; leaving`, the graceful `Left` arrives on macOS, and the state file and the marker are gone (R13). |
| Pid reuse after the owner dies. | A unit test covers this: the start time does not match, so the watch stops the daemon. |
| Read the state file with `Get-Content` in a loop while a daemon runs. | `last_updated` keeps moving, and the daemon logs no `state file write failed`. |

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
