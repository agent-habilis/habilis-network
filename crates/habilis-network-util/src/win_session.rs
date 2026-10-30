//! The end of the Windows session, for a daemon (R13 of `docs/windows.md`).
//!
//! Windows does not give a logoff or a shutdown to the console handler of a
//! process that loaded `user32.dll` or `gdi32.dll`, and a node loads both. It
//! sends `WM_QUERYENDSESSION` and `WM_ENDSESSION` to the top-level windows of
//! the process instead. [`watch_session_end`] makes a hidden top-level window
//! on a thread of its own, so the process gets them. A message-only window
//! (`HWND_MESSAGE`) gets no broadcast message, so this module does not use one.
//!
//! The window also gets `WM_CLOSE`, which `taskkill /PID` without `/F` sends.
//! It reports it, and it does not destroy itself, so a later end of the
//! session still reaches it.
//!
//! The class is registered under the module of the process. If two copies of
//! this code are in one process (two libraries that each link it), the second
//! copy uses the class of the first, and its events go to the handler of the
//! first copy. Today only the CLI daemon makes a window.

use std::cell::RefCell;
use std::io;
use std::sync::mpsc;
#[cfg(any(test, feature = "test-fixtures"))]
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_CLASS_ALREADY_EXISTS, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, ENDSESSION_CLOSEAPP, ENDSESSION_LOGOFF,
    GetMessageW, MSG, RegisterClassW, WM_CLOSE, WM_ENDSESSION, WM_QUERYENDSESSION, WNDCLASSW,
    WS_OVERLAPPED,
};

/// The class of the window. A test finds the window of a process by it.
const CLASS: &str = "habilis-network-session";

/// What the window of [`watch_session_end`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// `WM_ENDSESSION` with `TRUE`: the session ends, and Windows ends the
    /// process when the window procedure returns.
    End(SessionEnd),
    /// `WM_CLOSE`: a request to close, with no deadline.
    Close,
}

/// Why the session ends, from the bits of the `lParam` of `WM_ENDSESSION`.
///
/// A forced end (`ENDSESSION_CRITICAL`) is one of these too: the bit only says
/// that the process cannot refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The user logs off (`ENDSESSION_LOGOFF`).
    Logoff,
    /// The system shuts down or restarts (no bit).
    Shutdown,
    /// The Restart Manager closes the process (`ENDSESSION_CLOSEAPP`), for
    /// example an installer that replaces its file.
    CloseApp,
}

impl SessionEnd {
    fn from_lparam(lparam: LPARAM) -> Self {
        let bits = lparam.cast_unsigned();
        if bits & ENDSESSION_CLOSEAPP as usize != 0 {
            Self::CloseApp
        } else if bits & ENDSESSION_LOGOFF as usize != 0 {
            Self::Logoff
        } else {
            Self::Shutdown
        }
    }
}

/// The `lParam` that carries the bits `flags`, as Windows sends it: the bits
/// themselves, not a sign-extended number.
#[cfg(any(test, feature = "test-fixtures"))]
fn lparam_of(flags: u32) -> LPARAM {
    // A `usize` has at least 32 bits on Windows, so the conversion never fails.
    usize::try_from(flags).map_or(0, usize::cast_signed)
}

/// The timeout of `SendMessageTimeoutW`, in the milliseconds it takes.
#[cfg(any(test, feature = "test-fixtures"))]
fn timeout_ms(span: Duration) -> u32 {
    u32::try_from(span.as_millis()).unwrap_or(u32::MAX)
}

/// The handler of an event, one for each window thread.
type OnEvent = Box<dyn FnMut(SessionEvent)>;

thread_local! {
    /// The `on_event` of the window of this thread. A window gets its messages
    /// on the thread that made it, so each window has its own.
    static ON_EVENT: RefCell<Option<OnEvent>> = const { RefCell::new(None) };
}

/// Make a hidden top-level window on a thread of its own, and give its events
/// to `on_event`.
///
/// It returns when the window exists, so a message sent after the return
/// reaches `on_event`. The thread lives until the process ends.
///
/// `on_event` runs on the window thread. On [`SessionEvent::End`], Windows ends
/// the process when `on_event` returns, so a caller that needs time to leave
/// does not return from it. `on_event` must not panic: a panic in a window
/// procedure aborts the process.
///
/// `WM_QUERYENDSESSION` gets `TRUE`, so the window never stops the end of the
/// session. A `WM_ENDSESSION` with `FALSE` (the end was cancelled) gives no
/// event.
///
/// # Errors
/// The thread cannot start, or the window cannot be made.
pub fn watch_session_end(on_event: impl FnMut(SessionEvent) + Send + 'static) -> io::Result<()> {
    spawn_window(Box::new(on_event)).map(drop)
}

/// [`watch_session_end`], which gives the window to the tests as its address.
fn spawn_window(on_event: Box<dyn FnMut(SessionEvent) + Send>) -> io::Result<usize> {
    let (made_tx, made_rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("session-end".to_owned())
        .spawn(move || {
            ON_EVENT.set(Some(on_event));
            match make_window() {
                Ok(window) => {
                    let _ = made_tx.send(Ok(window.expose_provenance()));
                    pump_messages();
                }
                Err(error) => {
                    let _ = made_tx.send(Err(error));
                }
            }
        })?;
    made_rx
        .recv()
        .map_err(|_| io::Error::other("the window thread ended before it made the window"))?
}

/// The class name, as the wide string that the calls take.
fn class_name() -> Vec<u16> {
    CLASS.encode_utf16().chain([0]).collect()
}

/// Register the class, once for the process, and make one hidden window of it.
#[expect(
    unsafe_code,
    reason = "GetModuleHandleW, RegisterClassW and CreateWindowExW FFI"
)]
fn make_window() -> io::Result<HWND> {
    let class = class_name();
    // SAFETY: a null name gives the module of the process.
    let module = unsafe { GetModuleHandleW(std::ptr::null()) };
    let window_class = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(window_procedure),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: module,
        hIcon: std::ptr::null_mut(),
        hCursor: std::ptr::null_mut(),
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: class.as_ptr(),
    };
    // SAFETY: the struct and the name it points to live across the call. A
    // second window of the process finds the class already there, which is
    // the class it needs.
    if unsafe { RegisterClassW(&raw const window_class) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_CLASS_ALREADY_EXISTS.cast_signed()) {
            return Err(error);
        }
    }
    // SAFETY: the class name lives across the call. No `WS_VISIBLE`, no parent
    // and no menu: a hidden top-level window.
    let window = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            class.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            module,
            std::ptr::null(),
        )
    };
    if window.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(window)
}

/// The message loop of the window thread. It ends only if `GetMessageW` fails
/// or gets `WM_QUIT`, which nothing posts.
#[expect(unsafe_code, reason = "GetMessageW and DispatchMessageW FFI")]
fn pump_messages() {
    let mut message = MSG::default();
    // SAFETY: `message` lives across each call. A null window takes the
    // messages of every window of this thread.
    while unsafe { GetMessageW(&raw mut message, std::ptr::null_mut(), 0, 0) } > 0 {
        // SAFETY: `message` is the one that `GetMessageW` filled.
        unsafe {
            DispatchMessageW(&raw const message);
        }
    }
}

/// Give `event` to the `on_event` of this thread. An event that arrives while
/// `on_event` runs is dropped: a panic here would abort the process.
fn report(event: SessionEvent) {
    ON_EVENT.with(|slot| {
        if let Ok(mut on_event) = slot.try_borrow_mut()
            && let Some(on_event) = on_event.as_mut()
        {
            on_event(event);
        }
    });
}

/// The window procedure of the class.
#[expect(unsafe_code, reason = "a window procedure, and DefWindowProcW FFI")]
unsafe extern "system" fn window_procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            if wparam != 0 {
                report(SessionEvent::End(SessionEnd::from_lparam(lparam)));
            }
            0
        }
        // Not `DefWindowProcW`, which destroys the window.
        WM_CLOSE => {
            report(SessionEvent::Close);
            0
        }
        // SAFETY: the arguments that Windows gave this procedure.
        _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
}

#[cfg(feature = "test-fixtures")]
pub use fixtures::{post_window_close, send_session_end};

/// The messages that Windows sends at the end of a session, sent to another
/// process, for the tests of a daemon. Only for tests and tools: the library
/// that ships has no function that ends the session of a process.
#[cfg(feature = "test-fixtures")]
mod fixtures {
    use std::io;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        ENDSESSION_LOGOFF, EnumWindows, GetClassNameW, GetWindowThreadProcessId, PostMessageW,
        SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_CLOSE, WM_ENDSESSION, WM_QUERYENDSESSION,
    };
    use windows_sys::core::BOOL;

    use super::{CLASS, lparam_of, timeout_ms};

    /// How long `WM_QUERYENDSESSION` may take. The window answers at once.
    const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

    /// How long the send of `WM_ENDSESSION` waits. A daemon does not return
    /// from it, so the send ends at this timeout or when the process exits.
    const END_TIMEOUT: Duration = Duration::from_secs(1);

    /// Send `pid` a logoff, as Windows does: `WM_QUERYENDSESSION`, then
    /// `WM_ENDSESSION` with `TRUE`, to each window of [`watch_session_end`]
    /// that the process has.
    ///
    /// The send of `WM_ENDSESSION` blocks for up to 1 s, and its result is not
    /// read: the window of a daemon does not return from it. Call it from a
    /// thread that may block.
    ///
    /// [`watch_session_end`]: super::watch_session_end
    ///
    /// # Errors
    /// `pid` has no such window, or a window does not answer
    /// `WM_QUERYENDSESSION` with `TRUE`.
    #[expect(unsafe_code, reason = "SendMessageTimeoutW FFI")]
    pub fn send_session_end(pid: u32) -> io::Result<()> {
        let windows = windows_of(pid)?;
        for &window in &windows {
            let mut answer = 0;
            // SAFETY: plain value arguments, and `answer` lives across the
            // call.
            let sent = unsafe {
                SendMessageTimeoutW(
                    window,
                    WM_QUERYENDSESSION,
                    0,
                    lparam_of(ENDSESSION_LOGOFF),
                    SMTO_ABORTIFHUNG,
                    timeout_ms(QUERY_TIMEOUT),
                    &raw mut answer,
                )
            };
            if sent == 0 {
                return Err(io::Error::last_os_error());
            }
            if answer != 1 {
                return Err(io::Error::other(format!(
                    "the window answered WM_QUERYENDSESSION with {answer}"
                )));
            }
        }
        for &window in &windows {
            let mut answer = 0;
            // SAFETY: as above. The result is not read: see the doc.
            let _ = unsafe {
                SendMessageTimeoutW(
                    window,
                    WM_ENDSESSION,
                    1,
                    lparam_of(ENDSESSION_LOGOFF),
                    SMTO_ABORTIFHUNG,
                    timeout_ms(END_TIMEOUT),
                    &raw mut answer,
                )
            };
        }
        Ok(())
    }

    /// Post `WM_CLOSE` to each window of [`watch_session_end`] that `pid`
    /// has, as `taskkill /PID` without `/F` does.
    ///
    /// [`watch_session_end`]: super::watch_session_end
    ///
    /// # Errors
    /// `pid` has no such window, or the post fails.
    #[expect(unsafe_code, reason = "PostMessageW FFI")]
    pub fn post_window_close(pid: u32) -> io::Result<()> {
        for window in windows_of(pid)? {
            // SAFETY: plain value arguments.
            if unsafe { PostMessageW(window, WM_CLOSE, 0, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// What [`windows_of`] looks for and what it found.
    struct Search {
        pid: u32,
        class: Vec<u16>,
        found: Vec<HWND>,
    }

    /// The top-level windows of `pid` that have the class of the module.
    #[expect(unsafe_code, reason = "EnumWindows FFI")]
    pub(super) fn windows_of(pid: u32) -> io::Result<Vec<HWND>> {
        let mut search = Search {
            pid,
            class: CLASS.encode_utf16().collect(),
            found: Vec::new(),
        };
        // SAFETY: `search` lives across the call, and `each_window` is the only
        // reader of the pointer.
        let _ = unsafe {
            EnumWindows(
                Some(each_window),
                (&raw mut search).expose_provenance().cast_signed(),
            )
        };
        if search.found.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("process {pid} has no window of class {CLASS}"),
            ));
        }
        Ok(search.found)
    }

    /// The callback of `EnumWindows`: keep `window` if it is one of the search.
    #[expect(
        unsafe_code,
        reason = "an EnumWindows callback, GetWindowThreadProcessId and GetClassNameW FFI"
    )]
    unsafe extern "system" fn each_window(window: HWND, search: LPARAM) -> BOOL {
        // SAFETY: `windows_of` passes a pointer to a `Search` that lives
        // across `EnumWindows`, and nothing else reads it meanwhile.
        let search = unsafe {
            &mut *std::ptr::with_exposed_provenance_mut::<Search>(search.cast_unsigned())
        };
        let mut owner = 0;
        // SAFETY: `owner` lives across the call.
        unsafe {
            GetWindowThreadProcessId(window, &raw mut owner);
        }
        if owner != search.pid {
            return 1;
        }
        let mut name = [0_u16; 64];
        // SAFETY: the buffer and its length match.
        let len = unsafe { GetClassNameW(window, name.as_mut_ptr(), 64) };
        let name = name.get(..usize::try_from(len).unwrap_or(0)).unwrap_or(&[]);
        if name == search.class.as_slice() {
            search.found.push(window);
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        ENDSESSION_CLOSEAPP, ENDSESSION_CRITICAL, ENDSESSION_LOGOFF, IsWindow, SMTO_ABORTIFHUNG,
        SendMessageTimeoutW, WM_CLOSE, WM_ENDSESSION, WM_QUERYENDSESSION,
    };

    use super::{SessionEnd, SessionEvent, lparam_of, spawn_window, timeout_ms};

    /// A window of its own, and the events that its `on_event` got.
    fn window() -> (HWND, Receiver<SessionEvent>) {
        let (events_tx, events_rx) = mpsc::channel();
        let window = spawn_window(Box::new(move |event| {
            let _ = events_tx.send(event);
        }))
        .expect("the window");
        (std::ptr::with_exposed_provenance_mut(window), events_rx)
    }

    /// Send `message` to `window` and give its answer.
    #[expect(unsafe_code, reason = "SendMessageTimeoutW FFI")]
    fn send(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> usize {
        let mut answer = 0;
        // SAFETY: plain value arguments, and `answer` lives across the call.
        let sent = unsafe {
            SendMessageTimeoutW(
                window,
                message,
                wparam,
                lparam,
                SMTO_ABORTIFHUNG,
                timeout_ms(Duration::from_secs(5)),
                &raw mut answer,
            )
        };
        assert_ne!(
            sent,
            0,
            "the send failed: {}",
            std::io::Error::last_os_error()
        );
        answer
    }

    /// The event that `on_event` got, if one came. The send returns only after
    /// the window procedure, so an event is already in the channel: no wait.
    fn next(events: &Receiver<SessionEvent>) -> Option<SessionEvent> {
        events.try_recv().ok()
    }

    #[test]
    fn the_window_lets_the_session_end_and_reports_no_event_for_the_query() {
        let (window, events) = window();
        assert_eq!(send(window, WM_QUERYENDSESSION, 0, 0), 1);
        assert_eq!(next(&events), None);
    }

    #[test]
    fn the_end_of_the_session_reports_its_kind() {
        let (window, events) = window();
        for (bits, kind) in [
            (ENDSESSION_LOGOFF, SessionEnd::Logoff),
            (0, SessionEnd::Shutdown),
            (ENDSESSION_CLOSEAPP, SessionEnd::CloseApp),
            (ENDSESSION_CRITICAL, SessionEnd::Shutdown),
            (ENDSESSION_CRITICAL | ENDSESSION_LOGOFF, SessionEnd::Logoff),
        ] {
            assert_eq!(send(window, WM_ENDSESSION, 1, lparam_of(bits)), 0);
            assert_eq!(
                next(&events),
                Some(SessionEvent::End(kind)),
                "bits {bits:#x}"
            );
        }
    }

    #[test]
    fn a_cancelled_end_of_the_session_reports_no_event() {
        let (window, events) = window();
        send(window, WM_ENDSESSION, 0, lparam_of(ENDSESSION_LOGOFF));
        assert_eq!(next(&events), None);
    }

    #[test]
    #[expect(unsafe_code, reason = "IsWindow FFI")]
    fn a_close_is_reported_and_the_window_stays() {
        let (window, events) = window();
        assert_eq!(send(window, WM_CLOSE, 0, 0), 0);
        assert_eq!(next(&events), Some(SessionEvent::Close));
        // SAFETY: a plain value argument.
        assert_ne!(
            unsafe { IsWindow(window) },
            0,
            "the close destroyed the window"
        );
        // The window still gets the end of the session.
        send(window, WM_ENDSESSION, 1, lparam_of(ENDSESSION_LOGOFF));
        assert_eq!(next(&events), Some(SessionEvent::End(SessionEnd::Logoff)));
    }

    #[test]
    fn two_windows_of_one_process_report_to_their_own_handler() {
        let (first, first_events) = window();
        let (second, second_events) = window();
        send(second, WM_CLOSE, 0, 0);
        assert_eq!(next(&second_events), Some(SessionEvent::Close));
        assert_eq!(next(&first_events), None);
        send(first, WM_CLOSE, 0, 0);
        assert_eq!(next(&first_events), Some(SessionEvent::Close));
    }

    /// Only the lookup: a send to the windows of this process would reach the
    /// windows of the other tests, which run at the same time.
    #[cfg(feature = "test-fixtures")]
    #[test]
    fn the_lookup_finds_the_window_of_this_process() {
        let (window, _events) = window();
        let found = super::fixtures::windows_of(std::process::id()).expect("a window");
        assert!(
            found.contains(&window),
            "{found:?} does not hold {window:?}"
        );
    }
}
