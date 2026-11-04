//! The name of the local control endpoint of one daemon.

use std::fmt;
#[cfg(unix)]
use std::path;

use interprocess::local_socket::{GenericFilePath, Name};

use super::ipc_name_error::IpcNameError;

/// The longest marker line that a reader takes. A real name is a socket path
/// inside the runtime base, or the 49 characters of a pipe name.
const MAX_IPC_NAME_BYTES: usize = 512;

/// The name of the local control endpoint of one daemon: the path of a unix
/// socket on Unix, the name of a named pipe (`\\.\pipe\…`) on Windows.
///
/// On Unix the name is the socket path in the mesh folder, which a client
/// derives as the daemon does. On Windows a daemon writes the name in its
/// marker (`<mesh folder>/<nick>.ipc`), and a client reads it from there, so
/// discovery does not depend on the endpoint being a file. Not a secret: on
/// Windows any local account can list pipe names. That is why a Windows name
/// carries no mesh prefix and no nickname, only `habilis-` and 128 random bits.
///
/// # Examples
///
/// A relative path is no endpoint on any OS.
///
/// ```
/// use habilis_network::runtime::ipc::IpcName;
///
/// assert!(IpcName::new("relative/x.sock".to_owned()).is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpcName(String);

impl IpcName {
    /// Check a raw name, such as a marker line. Not `const`: the field is a
    /// `String`.
    ///
    /// # Errors
    /// The name is empty, longer than 512 bytes, holds a line break, or is not
    /// an endpoint of this OS: an absolute path on Unix, a local pipe
    /// (`\\.\pipe\` and a name) on Windows. A remote pipe (`\\host\pipe\…`) is
    /// refused.
    pub fn new(raw: String) -> Result<Self, IpcNameError> {
        if raw.is_empty() {
            return Err(IpcNameError::Empty);
        }
        if raw.len() > MAX_IPC_NAME_BYTES {
            return Err(IpcNameError::TooLong(MAX_IPC_NAME_BYTES));
        }
        if raw.contains(['\n', '\r']) {
            return Err(IpcNameError::LineBreak);
        }
        #[cfg(unix)]
        let endpoint = path::Path::new(&raw).is_absolute();
        #[cfg(windows)]
        let endpoint: bool = raw
            .strip_prefix(r"\\.\pipe\")
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('\\'));
        if !endpoint {
            return Err(IpcNameError::NotAnEndpoint(raw));
        }
        Ok(Self(raw))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The one conversion into an `interprocess` name, for the server and the
    /// client alike. `GenericFilePath` takes a socket path on Unix, and on
    /// Windows a `\\.\pipe\…` path as it is.
    pub(super) fn to_name(&self) -> anyhow::Result<Name<'_>> {
        use interprocess::local_socket::PathNameType as _;
        use std::{borrow, ffi};
        Ok(GenericFilePath::map(borrow::Cow::Borrowed(
            ffi::OsStr::new(self.0.as_str()),
        ))?)
    }
}

impl fmt::Display for IpcName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
