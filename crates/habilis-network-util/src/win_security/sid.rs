//! A Windows security identifier.

use std::{fmt, io, ptr, slice};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{CopySid, GetLengthSid, IsValidSid, PSID};
use windows_sys::core;

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
    pub(super) fn copy_from(psid: PSID) -> io::Result<Self> {
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
    pub fn parse(text: &str) -> io::Result<Self> {
        let wide = super::wide_nul(text);
        let mut psid: PSID = ptr::null_mut();
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
        let mut raw: core::PWSTR = ptr::null_mut();
        // SAFETY: `self.psid()` is a valid SID that lives for the call, and `raw`
        // is a valid pointer to one `PWSTR`.
        if unsafe { ConvertSidToStringSidW(self.psid(), &raw mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success `raw` is a NUL-terminated UTF-16 string. The scan
        // stops at the NUL, and the text is copied before the free below.
        let text = unsafe {
            let mut length = 0;
            while *raw.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(slice::from_raw_parts(raw, length))
        };
        // SAFETY: the call allocated `raw` with `LocalAlloc`, and nothing reads
        // it after the copy above.
        unsafe {
            LocalFree(raw.cast());
        }
        Ok(text)
    }

    /// The pointer that the Win32 calls take. The calls only read through it.
    pub(super) fn psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_text() {
            Ok(text) => formatter.write_str(&text),
            Err(_) => formatter.write_str("Sid(?)"),
        }
    }
}
