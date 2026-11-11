#[cfg(feature = "host")]
use std::fs;
#[cfg(feature = "host")]
use std::io;
#[cfg(feature = "host")]
use std::io::ErrorKind;
#[cfg(feature = "host")]
use std::path;

#[cfg(all(unix, feature = "host"))]
use rustix::process::geteuid;

#[cfg(all(unix, feature = "host"))]
use crate::runtime_base_check::RuntimeBaseCheck;

#[cfg(all(windows, feature = "host"))]
use std::env;
#[cfg(all(windows, feature = "host"))]
use windows_sys::core;
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
#[cfg(all(unix, feature = "host"))]
pub fn runtime_base(product: &str) -> path::PathBuf {
    path::PathBuf::from(format!("/tmp/{product}-{}", current_uid()))
}

/// The Windows base: `<LocalAppData>\<product>\run` (R2 of
/// `docs/windows.md`). The profile directory is already per user, so there is
/// no uid suffix. `LocalAppData` comes from the shell, not from `%LOCALAPPDATA%`,
/// for the rule above: every context computes the same base.
///
/// The shell call fails only when it cannot name a profile for the token of
/// the process. The base is then the per-user temp directory, which two users
/// also do not share, and a warn says that the base moved: a daemon and a CLI
/// that see two different bases cannot find each other.
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
#[cfg(all(windows, feature = "host"))]
pub fn runtime_base(product: &str) -> path::PathBuf {
    let root = local_app_data().unwrap_or_else(|| {
        let temp = env::temp_dir();
        tracing::warn!(
            target: "habilis_network::lifecycle",
            temp = %temp.display(),
            "the shell gave no LocalAppData folder; the runtime base is in the temp directory"
        );
        temp
    });
    root.join(product).join("run")
}

/// The `LocalAppData` known folder of the current user. `KF_FLAG_DONT_VERIFY`
/// asks for the path without a check that the folder is on disk, so a profile
/// folder that is not made yet still gives the same path. `None` when the
/// shell cannot name the folder for this user.
#[cfg(all(windows, feature = "host"))]
#[expect(
    unsafe_code,
    reason = "SHGetKnownFolderPath and CoTaskMemFree FFI; no safe std wrapper"
)]
fn local_app_data() -> Option<path::PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;
    use std::{ptr, slice};

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
    };

    // The GUID is a `const`, so it needs a place before it has an address.
    let folder = FOLDERID_LocalAppData;
    let mut raw: core::PWSTR = ptr::null_mut();
    // The flag is a positive `i32` constant and the parameter is a `u32`.
    let flags = KF_FLAG_DONT_VERIFY.cast_unsigned();
    // SAFETY: `folder` lives for the call, `flags` is a plain value, a null
    // token names the current user, and `raw` is a valid pointer to one
    // `PWSTR`.
    let status =
        unsafe { SHGetKnownFolderPath(&raw const folder, flags, ptr::null_mut(), &raw mut raw) };
    let found = (status >= 0 && !raw.is_null()).then(|| {
        // SAFETY: on success `raw` is a NUL-terminated UTF-16 string that the
        // shell allocated. The scan stops at the NUL, and the slice is copied
        // before the free below.
        let wide = unsafe {
            let mut length = 0;
            while *raw.add(length) != 0 {
                length += 1;
            }
            slice::from_raw_parts(raw, length)
        };
        path::PathBuf::from(OsString::from_wide(wide))
    });
    // SAFETY: the shell allocates `raw` with the COM allocator, also when the
    // call fails, and nothing reads it after this. A null pointer is a no-op.
    unsafe {
        CoTaskMemFree(raw.cast_const().cast());
    }
    found
}

/// This process's effective user id — the id a newly created file/dir is
/// *owned by*, so the id [`ensure_runtime_base`] must validate against (a
/// `getuid`/`geteuid` split under a setuid wrapper would otherwise reject a
/// base we just created ourselves).
#[cfg(all(unix, feature = "host"))]
fn current_uid() -> u32 {
    geteuid().as_raw()
}

/// A recursive directory builder that makes `0700` directories where the
/// platform has modes. On Windows a directory inherits the ACL of its parent
/// (R2 of `docs/windows.md`), so there is nothing to set.
#[cfg(feature = "host")]
fn private_dir_builder() -> fs::DirBuilder {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
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
#[cfg(all(unix, feature = "host"))]
pub fn ensure_runtime_base(base: &path::Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    // Deliberately *not* cached: a long-running daemon writes on every heartbeat,
    // and the OS `/tmp` reaper (systemd-tmpfiles, macOS periodic) can delete the
    // base mid-run. Re-creating + re-validating every call — a handful of cheap
    // syscalls — is what keeps a reaped base from silently reappearing at the
    // umask default `0755` on the next write. Idempotent and concurrency-safe:
    // racing creates collapse to `AlreadyExists`, the checks are read-only.
    match private_dir_builder().create(base) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // `symlink_metadata` does not follow a link, so a base swapped for a symlink
    // into a world-readable dir is rejected rather than trusted.
    let meta = fs::symlink_metadata(base)?;
    if !meta.file_type().is_dir() {
        return Err(not_a_directory(base));
    }
    if meta.uid() != current_uid() {
        // A local user squatted our predictable /tmp path. We refuse to write
        // secrets into a dir we do not own; the operator must clear it.
        return Err(squatted(base));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(base, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The Windows twin of [`ensure_runtime_base`]: create the base and check that
/// it is a directory and not a reparse point (R2 of `docs/windows.md`). The
/// check refuses every reparse point, not only a link: a junction or a symlink
/// at the base could send the state file into a folder that another user
/// reads. The ACL is the one that the profile gives, so there
/// is nothing to set.
///
/// # Errors
/// The create failed, or the base is a reparse point or not a directory.
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
#[cfg(all(windows, feature = "host"))]
pub fn ensure_runtime_base(base: &path::Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;

    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    match private_dir_builder().create(base) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // `symlink_metadata` reads the reparse point itself, not its target.
    let meta = fs::symlink_metadata(base)?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "runtime dir {} is a reparse point (a junction or a link) — remove it and retry",
                base.display()
            ),
        ));
    }
    if !meta.file_type().is_dir() {
        return Err(not_a_directory(base));
    }
    Ok(())
}

/// The refusal of a base that is not a directory, a link included. One text for
/// [`ensure_runtime_base`] and [`check_runtime_base`].
#[cfg(feature = "host")]
fn not_a_directory(base: &path::Path) -> io::Error {
    io::Error::new(
        ErrorKind::AlreadyExists,
        format!(
            "runtime dir {} is not a directory — remove it",
            base.display()
        ),
    )
}

/// The refusal of a base that another user owns. One text for
/// [`ensure_runtime_base`] and [`check_runtime_base`].
#[cfg(all(unix, feature = "host"))]
fn squatted(base: &path::Path) -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        format!(
            "runtime dir {} is owned by another user (squatted) — remove it and retry",
            base.display()
        ),
    )
}

/// Check the base of a client before it reads a file under it (R12 of
/// `docs/windows.md`). The checks are the ones of [`ensure_runtime_base`], but
/// this creates nothing and changes nothing: a client must not repair a base,
/// and a base that is open to other users is refused, not tightened. A daemon
/// always leaves its base at `0700`, because its bind goes through
/// [`ensure_runtime_base`].
///
/// The base is `/tmp/<product>-<uid>`, a path that another user can create
/// first. A client that does not check it can reach an endpoint that the
/// other user put there. The IPC client of `habilis-network` does not call
/// it yet.
///
/// # Errors
/// The base could not be read for a reason other than its absence.
///
/// # Examples
///
/// It reads the base on disk, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use std::path::Path;
/// use habilis_network_util::{RuntimeBaseCheck, check_runtime_base};
///
/// # fn demo(base: &Path) -> std::io::Result<()> {
/// let private = matches!(check_runtime_base(base)?, RuntimeBaseCheck::Private);
/// # let _ = private;
/// # Ok(())
/// # }
/// ```
#[cfg(all(unix, feature = "host"))]
pub fn check_runtime_base(base: &path::Path) -> io::Result<RuntimeBaseCheck> {
    check_runtime_base_owned_by(base, current_uid())
}

/// [`check_runtime_base`] with the owner as a parameter, so that a test can
/// prove the owner check without a second account.
#[cfg(all(unix, feature = "host"))]
fn check_runtime_base_owned_by(base: &path::Path, uid: u32) -> io::Result<RuntimeBaseCheck> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    // `symlink_metadata` does not follow a link, as in `ensure_runtime_base`.
    let meta = match fs::symlink_metadata(base) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(RuntimeBaseCheck::Absent);
        }
        Err(error) => return Err(error),
    };
    if !meta.file_type().is_dir() {
        return Ok(RuntimeBaseCheck::Refused(not_a_directory(base)));
    }
    if meta.uid() != uid {
        return Ok(RuntimeBaseCheck::Refused(squatted(base)));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Ok(RuntimeBaseCheck::Refused(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "runtime dir {} is open to other users (mode {:o}) — remove it and retry",
                base.display(),
                meta.permissions().mode() & 0o777
            ),
        )));
    }
    Ok(RuntimeBaseCheck::Private)
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
    if let Some(base) = base
        && is_under_runtime_base(base, path)
    {
        ensure_runtime_base(base)?;
    }
    if let Some(parent) = path.parent() {
        // Mode 0700 (not plain `create_dir_all`, which is 0755): closes the
        // narrow window where the reaper deletes the base between the ensure
        // above and this create, and keeps the per-mesh subdir private too.
        private_dir_builder().create(parent)?;
    }
    Ok(())
}

/// A mesh's runtime folder — `<base>/<mesh-prefix>/`. All of one mesh's
/// per-member files (`<nick>.tracing.log`, the IPC marker `<nick>.ipc` on
/// Windows, the socket `<nick>.ipc.sock` on Unix, `<nick>.state.json`) live
/// here, so the marker, socket, log, and state-file path builders all derive
/// from it. Pure — a path only; use [`ensure_mesh_runtime_dir`] when about to
/// *create* files under it.
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
    ensure_runtime_base(base)?;
    let dir = mesh_runtime_dir(base, mesh_id);
    // 0700, and closes the reaper race (see `ensure_parent_private`).
    private_dir_builder().create(&dir)?;
    Ok(dir)
}

#[cfg(all(test, feature = "host"))]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs as unix_fs;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::{env, fs, io, process};

    #[cfg(unix)]
    use super::{RuntimeBaseCheck, check_runtime_base, check_runtime_base_owned_by, current_uid};

    /// A junction needs no privilege, so a user who can write next to the base
    /// can put one there. The base must refuse it, and accept a plain folder.
    #[cfg(windows)]
    #[test]
    fn ensure_runtime_base_rejects_a_junction() {
        use std::path::PathBuf;
        use std::{env, fs, io, process};

        /// Removes the junction and the test folder also when an assertion
        /// fails. `remove_dir` on a junction removes the link, not the target.
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir(self.0.join("base"));
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        let _guard = ::habilis_network_test_tracing::init();
        let root = env::temp_dir().join(format!("hn-r2-{}", process::id()));
        // A pid can come back, so a folder that an earlier run left goes first.
        drop(Cleanup(root.clone()));
        let cleanup = Cleanup(root.clone());
        let target = root.join("target");
        let base = root.join("base");
        fs::create_dir_all(&target).expect("create the target");
        let mut command = process::Command::new("cmd");
        command.args(["/C", "mklink", "/J"]).arg(&base).arg(&target);
        let made: process::Output = command.output().expect("run mklink");
        assert!(made.status.success(), "mklink /J failed: {made:?}");

        let error = super::ensure_runtime_base(&base).expect_err("a junction is refused");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        super::ensure_runtime_base(&target).expect("a plain folder is accepted");
        drop(cleanup);
        assert!(!root.exists(), "the test folder is removed");
    }

    /// A private test folder under the temp dir, removed also when an
    /// assertion fails.
    #[cfg(unix)]
    struct TempRoot(PathBuf);

    #[cfg(unix)]
    impl TempRoot {
        fn new(tag: &str) -> Self {
            let root = env::temp_dir().join(format!("hn-r12-{}-{tag}", process::id()));
            // A pid can come back, so a folder that an earlier run left goes first.
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("create the test folder");
            Self(root)
        }
    }

    #[cfg(unix)]
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The mode of `path`, without the file type bits.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::symlink_metadata(path)
            .expect("read the mode")
            .permissions()
            .mode()
            & 0o777
    }

    /// The kind of the refusal, or a panic that names what was found.
    #[cfg(unix)]
    fn refused(found: io::Result<RuntimeBaseCheck>) -> io::ErrorKind {
        match found.expect("the check reads the base") {
            RuntimeBaseCheck::Refused(error) => error.kind(),
            found @ (RuntimeBaseCheck::Private | RuntimeBaseCheck::Absent) => {
                panic!("expected a refusal, got {found:?}")
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn check_runtime_base_accepts_a_private_folder_of_its_owner_only() {
        let _guard = ::habilis_network_test_tracing::init();
        let root = TempRoot::new("owner");
        let base = root.0.join("base");
        super::ensure_runtime_base(&base).expect("make a private base");
        let uid = current_uid();

        assert!(
            matches!(
                check_runtime_base_owned_by(&base, uid),
                Ok(RuntimeBaseCheck::Private)
            ),
            "a private base of its owner is accepted"
        );
        assert!(
            matches!(check_runtime_base(&base), Ok(RuntimeBaseCheck::Private)),
            "the base of this user is private"
        );
        assert_eq!(
            refused(check_runtime_base_owned_by(&base, uid.wrapping_add(1))),
            io::ErrorKind::PermissionDenied,
            "a base of another owner is refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_runtime_base_refuses_an_open_folder_and_leaves_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = ::habilis_network_test_tracing::init();
        let root = TempRoot::new("open");
        let base = root.0.join("base");
        fs::create_dir(&base).expect("make the base");
        // Set, not left to the umask, so that the test does not depend on it.
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).expect("open the base");

        assert_eq!(
            refused(check_runtime_base(&base)),
            io::ErrorKind::PermissionDenied,
            "an open base is refused"
        );
        assert_eq!(mode_of(&base), 0o755, "the check changes no mode");
    }

    #[cfg(unix)]
    #[test]
    fn check_runtime_base_refuses_a_link_and_a_file() {
        let _guard = ::habilis_network_test_tracing::init();
        let root = TempRoot::new("link");
        let target = root.0.join("target");
        super::ensure_runtime_base(&target).expect("make a private folder");
        let link = root.0.join("link");
        unix_fs::symlink(&target, &link).expect("make the link");
        let file = root.0.join("file");
        fs::write(&file, b"").expect("make the file");

        assert_eq!(
            refused(check_runtime_base(&link)),
            io::ErrorKind::AlreadyExists,
            "a link is refused"
        );
        assert_eq!(
            refused(check_runtime_base(&file)),
            io::ErrorKind::AlreadyExists,
            "a file is refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_runtime_base_creates_no_absent_base() {
        let _guard = ::habilis_network_test_tracing::init();
        let root = TempRoot::new("absent");
        let base = root.0.join("base");

        assert!(
            matches!(check_runtime_base(&base), Ok(RuntimeBaseCheck::Absent)),
            "an absent base is absent"
        );
        assert!(!base.exists(), "the check creates nothing");
    }
}
