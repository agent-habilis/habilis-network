#[cfg(feature = "host")]
use std::fs;
#[cfg(feature = "host")]
use std::io;
#[cfg(feature = "host")]
use std::io::ErrorKind;
#[cfg(feature = "host")]
use std::path;
/// The per-mesh folder name — the first 16 characters of the mesh
/// identifier. The stem of every per-mesh file (socket / log / state), so it
/// lives here rather than in any one module. See [`mesh_runtime_dir`].
///
/// An id is bare Base58, so the stem is plain ASCII and needs no escaping or
/// separator-stripping before it lands in a path.
///
/// # Examples
///
/// The same mesh id always gives the same prefix.
///
/// ```
/// use habilis_network_util::mesh_prefix;
///
/// assert_eq!(mesh_prefix("abc"), mesh_prefix("abc"));
/// ```
#[must_use]
pub fn mesh_prefix(mesh_id: &str) -> String {
    mesh_id.chars().take(16).collect()
}

/// The per-user runtime base for `product` — every per-mesh folder lives under
/// it. Consumers call this **once** and pass the resulting base down; nothing
/// below re-derives it.
///
/// A single world-traversable base would let any *other* local user enumerate
/// meshes and read the (world-readable) per-member log files. Scoping the base
/// to the user's id — and creating it `0700` (see [`ensure_runtime_base`]) —
/// closes that cross-user exposure.
///
/// `product` is the consumer's name, supplied rather than assumed: the engine
/// is embedded by more than one binary and must not claim a path under any
/// single one's name. It is a **parameter, not a registered global**, precisely
/// because of the determinism requirement below — a global set on some entry
/// paths and missed on others would relocate the base for exactly the callers
/// that must agree, and do it silently.
///
/// The path is otherwise a **fixed function of the uid alone**, deliberately
/// *not* of the environment: a daemon started in one context (say an
/// interactive shell) and a later `leave` / `session` / `msg` run in another
/// (cron, a statusline helper, `sudo`) must compute the *same* base or the
/// consumer can no longer find the daemon's socket and state file. That rules
/// out `$XDG_RUNTIME_DIR` (which varies across those contexts and would
/// silently relocate everything) and keeps us consistent with the project's "no
/// env-var config" rule. The `-<uid>` suffix adds only a few bytes, so the
/// socket path stays well inside the `AF_UNIX` `sun_path` ~104-byte limit.
///
/// # Examples
///
/// The runtime base for a product is an absolute path.
///
/// ```
/// use habilis_network_util::runtime_base;
///
/// assert!(runtime_base("chat").is_absolute());
/// ```
#[must_use]
#[cfg(feature = "host")]
pub fn runtime_base(product: &str) -> path::PathBuf {
    path::PathBuf::from(format!("/tmp/{product}-{}", current_uid()))
}

/// This process's effective user id — the id a newly created file/dir is
/// *owned by*, so the id [`ensure_runtime_base`] must validate against (a
/// `getuid`/`geteuid` split under a setuid wrapper would otherwise reject a
/// base we just created ourselves). The one place the crate calls libc, so the
/// single `unsafe` block has one documented home (mirrors the termios FFI in
/// `main`). `geteuid` has no safety preconditions.
#[cfg(feature = "host")]
#[expect(unsafe_code, reason = "libc::geteuid FFI; no safe std wrapper exists")]
fn current_uid() -> u32 {
    // SAFETY: geteuid cannot fail and reads no memory.
    unsafe { libc::geteuid() }
}

/// Ensure `base` (from [`runtime_base`]) exists as a private (`0700`) directory
/// this user owns, tightening or rejecting a hostile pre-created one. Idempotent and
/// **run on every call, never cached** — a cached success would let a base
/// deleted mid-run (the OS `/tmp` reaper) silently reappear at `0755`.
///
/// Every writer that creates a file under the base must call this (directly, or
/// via [`ensure_mesh_runtime_dir`] / [`ensure_parent_private`]) **and honour
/// its error** first: skipping it lets an attacker who pre-creates the base as a
/// symlink redirect a `0600` state file (which carries the mesh id + an app bearer
/// token) into an attacker-readable location. Callers whose target may be a
/// `--state-file` / `--log-dir` override (outside the base) should go through
/// [`ensure_parent_private`], which gates on [`is_under_runtime_base`].
///
/// # Errors
/// The base exists but is a symlink, is not a directory, or is owned by another
/// user (a squatting attempt — a clear message so the operator can remove it);
/// or the create / chmod syscalls fail. Fails *closed*: a failure here must
/// abort the write, never fall through to an unvalidated directory.
///
/// # Examples
///
/// It creates the directory on disk, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use std::path::Path;
/// use habilis_network_util::ensure_runtime_base;
///
/// # fn demo(base: &Path) -> std::io::Result<()> {
/// ensure_runtime_base(base)?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "host")]
pub fn ensure_runtime_base(base: &path::Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

    // Deliberately *not* cached: a long-running daemon writes on every heartbeat,
    // and the OS `/tmp` reaper (systemd-tmpfiles, macOS periodic) can delete the
    // base mid-run. Re-creating + re-validating every call — a handful of cheap
    // syscalls — is what keeps a reaped base from silently reappearing at the
    // umask default `0755` on the next write. Idempotent and concurrency-safe:
    // racing creates collapse to `AlreadyExists`, the checks are read-only.
    match fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(base)
    {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // `symlink_metadata` does not follow a link, so a base swapped for a symlink
    // into a world-readable dir is rejected rather than trusted.
    let meta = fs::symlink_metadata(base)?;
    if !meta.file_type().is_dir() {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "runtime dir {} is not a directory — remove it",
                base.display()
            ),
        ));
    }
    if meta.uid() != current_uid() {
        // A local user squatted our predictable /tmp path. We refuse to write
        // secrets into a dir we do not own; the operator must clear it.
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "runtime dir {} is owned by another user (squatted) — remove it and retry",
                base.display()
            ),
        ));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(base, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Whether `path` is inside `base`. A `--state-file` / `--log-dir` override can
/// point outside the base and must not be gated on its validation.
///
/// # Examples
///
/// A path inside the runtime base is under it.
///
/// ```
/// use habilis_network_util::{is_under_runtime_base, mesh_runtime_dir, runtime_base};
///
/// let base = runtime_base("chat");
/// assert!(is_under_runtime_base(&base, &mesh_runtime_dir(&base, "abc")));
/// ```
#[must_use]
#[cfg(feature = "host")]
pub fn is_under_runtime_base(base: &path::Path, path: &path::Path) -> bool {
    path.starts_with(base)
}

/// Prepare the parent directory of a file about to be written at `path`, with
/// the fail-closed base policy in one place: when `path` is under `base`,
/// validate the private base first (aborting on a squat/symlink) so
/// `create_dir_all` never follows an attacker's redirect; when it is an override
/// outside the base, just create the parent. The single home for the "gate on
/// `is_under_runtime_base`, then ensure, then `create_dir_all`" sequence — the
/// token-bearing state file and the log sink both route through here so the
/// policy cannot drift between copies.
///
/// # Errors
/// [`ensure_runtime_base`] rejected the base, or the parent create failed.
/// `base` is `None` for a consumer that configured no runtime base at all —
/// there is then no protected directory to validate, only a parent to create.
///
/// # Examples
///
/// It creates directories on disk, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use std::path::Path;
/// use habilis_network_util::ensure_parent_private;
///
/// # fn demo(base: &Path, path: &Path) -> std::io::Result<()> {
/// ensure_parent_private(Some(base), path)?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "host")]
pub fn ensure_parent_private(base: Option<&path::Path>, path: &path::Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    if let Some(base) = base
        && is_under_runtime_base(base, path)
    {
        ensure_runtime_base(base)?;
    }
    if let Some(parent) = path.parent() {
        // Mode 0700 (not plain `create_dir_all`, which is 0755): closes the
        // narrow window where the reaper deletes the base between the ensure
        // above and this create, and keeps the per-mesh subdir private too.
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(parent)?;
    }
    Ok(())
}

/// A mesh's runtime folder — `<base>/<mesh-prefix>/`. All of one mesh's
/// per-member files (`<nick>.tracing.log`, `<nick>.ipc.sock`,
/// `<nick>.state.json`) live here, so the socket, log, and state-file path
/// builders all derive from it. Pure — a path only; use
/// [`ensure_mesh_runtime_dir`] when about to *create* files under it.
///
/// # Examples
///
/// A mesh directory lies inside the runtime base.
///
/// ```
/// use habilis_network_util::{mesh_runtime_dir, runtime_base};
///
/// let base = runtime_base("chat");
/// assert!(mesh_runtime_dir(&base, "abc").starts_with(&base));
/// ```
#[must_use]
#[cfg(feature = "host")]
pub fn mesh_runtime_dir(base: &path::Path, mesh_id: &str) -> path::PathBuf {
    base.join(mesh_prefix(mesh_id))
}

/// Validate the private base (fail closed on a squat/symlink), then create the
/// per-mesh subdir. The choke point for writers whose target is *always* under
/// the base — the socket bind, the blob spool, the `.recv` dir. (The state file
/// and log sink can take a `--state-file` / `--log-dir` override outside the
/// base, so they route through [`ensure_parent_private`] instead.)
///
/// # Errors
/// [`ensure_runtime_base`] rejected the base, or the subdir create failed.
///
/// # Examples
///
/// It creates the mesh directory on disk, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use std::path::Path;
/// use habilis_network_util::ensure_mesh_runtime_dir;
///
/// # fn demo(base: &Path) -> std::io::Result<()> {
/// ensure_mesh_runtime_dir(base, "abc")?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "host")]
pub fn ensure_mesh_runtime_dir(base: &path::Path, mesh_id: &str) -> io::Result<path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt as _;
    ensure_runtime_base(base)?;
    let dir = mesh_runtime_dir(base, mesh_id);
    // 0700, and closes the reaper race (see `ensure_parent_private`).
    fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&dir)?;
    Ok(dir)
}
