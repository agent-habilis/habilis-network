//! The Windows security calls of the IPC named pipe (R3 of `docs/windows.md`):
//! who the current user is, the security descriptor that gives the pipe to that
//! user alone, the check that a pipe belongs to that user, and a client open
//! that lets the server identify the client but not act as it.
//!
//! Every Win32 call of the engine lives in this crate, so the `unsafe` blocks
//! have one home. The callers in `habilis-network` only see safe functions.

use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{
    AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle, RawHandle,
};

use windows_sys::Win32::Foundation::{
    ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    CopySid, DACL_SECURITY_INFORMATION, EqualSid, GetLengthSid, GetTokenInformation, IsValidSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A security identifier, held as its own bytes.
///
/// The words are `u32` because a `SID` is 4-byte aligned: a `Vec<u8>` would not
/// promise that to the calls that read it. A SID is 8 bytes plus 4 per
/// sub-authority, so the words hold the SID bytes exactly, and the derived
/// equality is the same comparison that `EqualSid` makes.
#[derive(PartialEq, Eq)]
pub struct Sid {
    words: Vec<u32>,
}

impl Sid {
    /// Copy the SID at `psid` into an owned value.
    #[expect(unsafe_code, reason = "IsValidSid, GetLengthSid and CopySid FFI")]
    fn copy_from(psid: PSID) -> io::Result<Self> {
        // SAFETY: `IsValidSid` only reads the SID header at `psid`, which the
        // caller got from a successful Win32 call.
        if psid.is_null() || unsafe { IsValidSid(psid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a valid SID",
            ));
        }
        // SAFETY: the SID is valid, as checked above.
        let length = unsafe { GetLengthSid(psid) };
        let mut words = vec![0_u32; usize::try_from(length).unwrap_or(0).div_ceil(4)];
        // SAFETY: `words` holds at least `length` bytes, is 4-byte aligned, and
        // does not overlap the source.
        if unsafe { CopySid(length, words.as_mut_ptr().cast(), psid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { words })
    }

    /// Parse the text form, such as `S-1-5-18`.
    ///
    /// # Errors
    /// The text is not a SID.
    #[expect(unsafe_code, reason = "ConvertStringSidToSidW and LocalFree FFI")]
    pub fn from_text(text: &str) -> io::Result<Self> {
        let wide = wide_nul(text);
        let mut psid: PSID = std::ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that lives for the
        // call, and `psid` is a valid pointer to one `PSID`.
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut psid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid = Self::copy_from(psid);
        // SAFETY: the call allocated `psid` with `LocalAlloc`, and nothing reads
        // it after the copy above.
        unsafe {
            LocalFree(psid);
        }
        sid
    }

    /// The text form, such as `S-1-5-21-…-1001`.
    ///
    /// # Errors
    /// The conversion fails, which happens only when memory runs out.
    #[expect(unsafe_code, reason = "ConvertSidToStringSidW and LocalFree FFI")]
    pub fn to_text(&self) -> io::Result<String> {
        let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
        // SAFETY: `self.psid()` is a valid SID that lives for the call, and `raw`
        // is a valid pointer to one `PWSTR`.
        if unsafe { ConvertSidToStringSidW(self.psid(), &raw mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success `raw` is a NUL-terminated UTF-16 string. The scan
        // stops at the NUL, and the text is copied before the free below.
        let text = unsafe {
            let mut len = 0;
            while *raw.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(raw, len))
        };
        // SAFETY: the call allocated `raw` with `LocalAlloc`, and nothing reads
        // it after the copy above.
        unsafe {
            LocalFree(raw.cast());
        }
        Ok(text)
    }

    /// The pointer that the Win32 calls take. The calls only read through it.
    fn psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }
}

impl std::fmt::Debug for Sid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_text() {
            Ok(text) => formatter.write_str(&text),
            Err(_) => formatter.write_str("Sid(?)"),
        }
    }
}

/// The user SID of the token of this process. It is `TokenUser`, not
/// `TokenOwner`: in an elevated token the owner is the Administrators group,
/// and the user is still the person who runs the process.
///
/// # Errors
/// The token cannot be opened or read.
#[expect(
    unsafe_code,
    reason = "OpenProcessToken and GetTokenInformation FFI; no safe std wrapper"
)]
pub fn current_user_sid() -> io::Result<Sid> {
    let mut raw: RawHandle = std::ptr::null_mut();
    // SAFETY: the pseudo-handle of this process needs no close, and `raw` is a
    // valid pointer to one handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a token handle that the call just opened and nothing else
    // owns.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };

    // The first call asks for the size. It fails with
    // `ERROR_INSUFFICIENT_BUFFER` and writes the size that the second call needs.
    let mut needed = 0_u32;
    // SAFETY: a null buffer of length 0 is allowed, and `needed` is a valid
    // pointer to one `u32`.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut needed,
        );
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    // `u64` words keep the buffer aligned for the `TOKEN_USER` and the SID in it.
    let mut buffer = vec![0_u64; usize::try_from(needed).unwrap_or(0).div_ceil(8)];
    // SAFETY: `buffer` holds at least `needed` bytes, and `needed` is a valid
    // pointer to one `u32`.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer starts with a `TOKEN_USER`, and the SID that
    // it points to lies inside the same buffer, which lives until the copy.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    Sid::copy_from(user.User.Sid)
}

/// The security descriptor of the IPC pipe, in SDDL and as UTF-16 with a
/// trailing NUL: `O:<user>D:P(A;;GA;;;<user>)`. The owner is the user, and the
/// one entry of the protected DACL gives the user all access. Nobody else is in
/// the list, so every other account is refused.
///
/// The `O:` matters for an elevated process: its default owner is the
/// Administrators group, and the client check of [`handle_owner_is`] would then
/// refuse our own daemon. A process may name its own user SID as owner with no
/// privilege. `GA` is needed because the listener makes a new instance of the
/// pipe after each accept, and that needs a right that only `GA` or `GW` gives.
///
/// # Errors
/// The user SID cannot be read or written as text.
pub fn user_sddl() -> io::Result<Vec<u16>> {
    let user = current_user_sid()?.to_text()?;
    Ok(wide_nul(&format!("O:{user}D:P(A;;GA;;;{user})")))
}

/// Whether the owner of the kernel object behind `handle` is `expected`.
///
/// A read of the owner that fails counts as `false`: the pipe of an attacker can
/// deny us `READ_CONTROL`, and the check must fail closed. A client opens the
/// pipe with `GENERIC_READ`, which includes `READ_CONTROL`, so our own pipe
/// always answers.
#[must_use]
#[expect(unsafe_code, reason = "GetSecurityInfo and LocalFree FFI")]
pub fn handle_owner_is(handle: BorrowedHandle<'_>, expected: &Sid) -> bool {
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is open for the call. The two out pointers are valid,
    // and the three that are null ask for nothing.
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    // SAFETY: on success `owner` points into `descriptor`, which is still
    // allocated, and `expected` is a valid SID.
    let same = status == 0 && !owner.is_null() && unsafe { EqualSid(owner, expected.psid()) } != 0;
    if !descriptor.is_null() {
        // SAFETY: the call allocated `descriptor` with `LocalAlloc`, and `owner`,
        // which points into it, is not read after this.
        unsafe {
            LocalFree(descriptor);
        }
    }
    same
}

/// The DACL of the kernel object behind `handle`, as SDDL text such as
/// `D:P(A;;FA;;;S-1-5-21-…)`. The access mask is the specific one: a generic
/// right such as `GA` reads back as the right of the object type, `FA` for a
/// pipe. A well-known SID reads back as its SDDL alias, such as `LA` for the
/// built-in Administrator, so compare a trustee with [`Sid::from_text`], not as
/// text. For a check or a diagnosis of the IPC pipe.
///
/// # Errors
/// The handle has no `READ_CONTROL`, or the conversion fails.
#[expect(
    unsafe_code,
    reason = "GetSecurityInfo, ConvertSecurityDescriptorToStringSecurityDescriptorW and LocalFree FFI"
)]
pub fn dacl_text(handle: BorrowedHandle<'_>) -> io::Result<String> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is open for the call. The descriptor out pointer is
    // valid, and the four that are null ask for nothing.
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `descriptor` is the valid descriptor that the call just gave, and
    // `raw` is a valid pointer to one `PWSTR`; the length pointer may be null.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &raw mut raw,
            std::ptr::null_mut(),
        )
    };
    let text = if converted == 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: on success `raw` is a NUL-terminated UTF-16 string. The scan
        // stops at the NUL, and the text is copied before the free below.
        let text = unsafe {
            let mut len = 0;
            while *raw.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(raw, len))
        };
        // SAFETY: the conversion allocated `raw` with `LocalAlloc`, and nothing
        // reads it after the copy above.
        unsafe {
            LocalFree(raw.cast());
        }
        Ok(text)
    };
    // SAFETY: `GetSecurityInfo` allocated `descriptor` with `LocalAlloc`, and
    // nothing reads it after this.
    unsafe {
        LocalFree(descriptor);
    }
    text
}

/// Open the client end of the named pipe `name` (a `\\.\pipe\…` path) for
/// overlapped read and write, as `interprocess` does, plus
/// `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`. With those flags the
/// server can learn who the client is but cannot act as the client: a pipe that
/// another account took over after a crash gets no usable token. The
/// `interprocess` connect sets neither flag.
///
/// # Errors
/// The OS error of the open, unchanged: `ERROR_FILE_NOT_FOUND` when no pipe has
/// the name, `ERROR_PIPE_BUSY` when every instance is in use, and
/// `ERROR_ACCESS_DENIED` when the DACL of the pipe leaves us out.
#[expect(unsafe_code, reason = "CreateFileW FFI; std cannot set the SQOS flags")]
pub fn open_pipe_identification(name: &str) -> io::Result<OwnedHandle> {
    let wide = wide_nul(name);
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that lives for the call.
    // The other arguments are plain values or null, which the call allows.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a handle that the call just made and nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// Whether an error of [`open_pipe_identification`] says that every instance of
/// the pipe is in use (`ERROR_PIPE_BUSY`), which a short wait can clear.
#[must_use]
pub fn is_pipe_busy(error: &io::Error) -> bool {
    error.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok()
}

/// `text` as UTF-16 with a trailing NUL, the form that the `W` calls take.
fn wide_nul(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use std::os::windows::io::{AsHandle as _, FromRawHandle as _, OwnedHandle};

    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE};

    use super::{
        Sid, current_user_sid, dacl_text, handle_owner_is, open_pipe_identification, user_sddl,
        wide_nul,
    };

    /// A pipe name of this test run alone.
    fn pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\hn-util-test-{}-{tag}", std::process::id())
    }

    /// The server end of a byte pipe with the descriptor of [`user_sddl`], made
    /// with the raw call so that the test does not depend on `interprocess`.
    fn serve_pipe(name: &str) -> OwnedHandle {
        serve_pipe_with(name, &user_sddl().expect("the SDDL of the user"))
    }

    /// The server end of a byte pipe with the descriptor `sddl` (UTF-16, NUL).
    #[expect(unsafe_code, reason = "the test builds a pipe with raw Win32 calls")]
    fn serve_pipe_with(name: &str, sddl: &[u16]) -> OwnedHandle {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and lives for the call, and
        // `descriptor` is a valid out pointer; the size pointer may be null.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(converted, 0, "{}", std::io::Error::last_os_error());
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("a small struct"),
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let wide = wide_nul(name);
        // SAFETY: the name and the attributes live for the call.
        let raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE,
                1,
                512,
                512,
                0,
                &raw const attributes,
            )
        };
        // SAFETY: the conversion allocated `descriptor` with `LocalAlloc`, and
        // the pipe keeps its own copy.
        unsafe {
            LocalFree(descriptor);
        }
        assert_ne!(
            raw,
            INVALID_HANDLE_VALUE,
            "{}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `raw` is the new pipe handle, owned by nothing else.
        unsafe { OwnedHandle::from_raw_handle(raw) }
    }

    #[test]
    fn the_user_sid_is_a_user_or_service_sid() {
        let text = current_user_sid()
            .expect("the user SID")
            .to_text()
            .expect("text");
        assert!(text.starts_with("S-1-5-"), "{text}");
    }

    #[test]
    fn a_sid_survives_the_text_round_trip() {
        let user = current_user_sid().expect("the user SID");
        let again = Sid::from_text(&user.to_text().expect("text")).expect("parse");
        assert_eq!(user, again);
        let system = Sid::from_text("S-1-5-18").expect("the SYSTEM SID");
        assert_ne!(user, system);
        assert!(Sid::from_text("not a sid").is_err());
        // An SDDL alias parses too: `LA` is the built-in Administrator, RID 500.
        let admin = Sid::from_text("LA").expect("the LA alias");
        assert!(admin.to_text().expect("text").ends_with("-500"));
    }

    #[test]
    fn the_sddl_names_the_user_as_owner_and_as_the_one_entry() {
        let user = current_user_sid()
            .expect("the user SID")
            .to_text()
            .expect("text");
        let sddl = user_sddl().expect("the SDDL");
        assert_eq!(sddl.last(), Some(&0), "NUL-terminated");
        let text = String::from_utf16(&sddl[..sddl.len() - 1]).expect("UTF-16");
        assert_eq!(text, format!("O:{user}D:P(A;;GA;;;{user})"));
    }

    // The owner is the user even when the test runs elevated, because the SDDL
    // names it. Another SID is refused, which is what the client check does with
    // the pipe of another account.
    #[test]
    fn a_pipe_made_with_the_user_sddl_is_owned_by_the_user() {
        let server = serve_pipe(&pipe_name("owner"));
        let user = current_user_sid().expect("the user SID");
        let system = Sid::from_text("S-1-5-18").expect("the SYSTEM SID");
        assert!(handle_owner_is(server.as_handle(), &user));
        assert!(!handle_owner_is(server.as_handle(), &system));
        // The DACL has one entry, all access for the user. The trustee can read
        // back as an alias (`LA` when the test runs as the built-in
        // Administrator), so the test compares the SID.
        let dacl = dacl_text(server.as_handle()).expect("the DACL");
        let trustee = dacl
            .strip_prefix("D:P(A;;FA;;;")
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or_else(|| panic!("one entry with all access: {dacl}"));
        assert_eq!(Sid::from_text(trustee).expect("a SID or an alias"), user);
    }

    #[test]
    fn the_identification_open_reaches_the_pipe_and_sees_its_owner() {
        let name = pipe_name("open");
        let _server = serve_pipe(&name);
        let client = open_pipe_identification(&name).expect("the client end opens");
        let user = current_user_sid().expect("the user SID");
        assert!(handle_owner_is(client.as_handle(), &user));
    }

    /// The property that `open_pipe_identification` exists for: a server that
    /// impersonates such a client gets an identification token only, so it can
    /// learn who the client is and cannot act as the client. The server must
    /// read from the pipe before it can impersonate, so the client writes one
    /// byte first.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the test impersonates the client with raw Win32 calls"
    )]
    fn a_server_can_only_identify_a_client_opened_for_identification() {
        use std::io::{Read as _, Write as _};
        use std::os::windows::io::{AsRawHandle as _, RawHandle};

        use windows_sys::Win32::Security::{
            GetTokenInformation, RevertToSelf, SecurityIdentification, TOKEN_QUERY,
            TokenImpersonationLevel,
        };
        use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
        use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

        let name = pipe_name("identify");
        let server = serve_pipe(&name);
        let client = open_pipe_identification(&name).expect("the client end opens");
        // `std::fs::File` waits for the overlapped write of the client handle.
        std::fs::File::from(client)
            .write_all(b"x")
            .expect("the client writes");
        let mut server = std::fs::File::from(server);
        let mut byte = [0_u8; 1];
        server.read_exact(&mut byte).expect("the server reads");

        // SAFETY: `server` is the open server end of a pipe that has data read.
        let impersonated = unsafe { ImpersonateNamedPipeClient(server.as_raw_handle()) };
        assert_ne!(impersonated, 0, "{}", std::io::Error::last_os_error());
        let mut raw: RawHandle = std::ptr::null_mut();
        // SAFETY: the pseudo-handle of this thread needs no close. `OpenAsSelf`
        // is true, because an identification token cannot open objects, and
        // `raw` is a valid pointer to one handle.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut raw) };
        let level = (opened != 0).then(|| {
            // SAFETY: `raw` is the token that the call just opened.
            let token = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut level = 0_i32;
            let mut written = 0_u32;
            // SAFETY: `level` is a valid buffer of the size given, and `written`
            // is a valid pointer to one `u32`.
            let ok = unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenImpersonationLevel,
                    (&raw mut level).cast(),
                    u32::try_from(size_of::<i32>()).expect("a small size"),
                    &raw mut written,
                )
            };
            (ok != 0).then_some(level)
        });
        // SAFETY: the thread impersonates the client; this returns it to the
        // token of the process before any assert can unwind.
        let reverted = unsafe { RevertToSelf() };
        assert_ne!(reverted, 0, "{}", std::io::Error::last_os_error());
        assert_eq!(level.flatten(), Some(SecurityIdentification));
    }

    // A pipe whose DACL leaves us out refuses the open with ERROR_ACCESS_DENIED,
    // which is no busy pipe: the client treats it as no daemon of ours. An empty
    // protected DACL refuses even the owner the read and write rights.
    #[test]
    fn the_identification_open_of_a_pipe_that_leaves_us_out_is_access_denied() {
        let name = pipe_name("denied");
        let user = current_user_sid()
            .expect("the user SID")
            .to_text()
            .expect("text");
        let _server = serve_pipe_with(&name, &wide_nul(&format!("O:{user}D:P")));
        let error = open_pipe_identification(&name).expect_err("access denied");
        assert_eq!(
            error.raw_os_error(),
            i32::try_from(ERROR_ACCESS_DENIED).ok(),
            "{error}"
        );
        assert!(!super::is_pipe_busy(&error));
    }

    // A well-known SID reads back from `dacl_text` as its SDDL alias, on every
    // account: SYSTEM is `SY`. So a test compares a trustee as a `Sid`, never as
    // text, and the alias parses back to the SID. The server handle reads the
    // DACL, though the DACL leaves the user out, because the owner holds
    // READ_CONTROL on its own object.
    #[test]
    fn a_well_known_trustee_reads_back_as_its_alias_and_parses_to_its_sid() {
        let user = current_user_sid()
            .expect("the user SID")
            .to_text()
            .expect("text");
        let server = serve_pipe_with(
            &pipe_name("alias"),
            &wide_nul(&format!("O:{user}D:P(A;;GA;;;S-1-5-18)")),
        );
        let dacl = dacl_text(server.as_handle()).expect("the DACL");
        assert_eq!(dacl, "D:P(A;;FA;;;SY)");
        let system = Sid::from_text("S-1-5-18").expect("the SYSTEM SID");
        assert_eq!(Sid::from_text("SY").expect("the SY alias"), system);
    }

    #[test]
    fn the_identification_open_of_a_missing_pipe_is_file_not_found() {
        let error = open_pipe_identification(&pipe_name("missing")).expect_err("no such pipe");
        assert_eq!(
            error.raw_os_error(),
            i32::try_from(ERROR_FILE_NOT_FOUND).ok(),
            "{error}"
        );
    }
}
