//! A console event sent to another process, for the tests of the console
//! events of a daemon (R7 of `docs/windows.md`).
//!
//! `GenerateConsoleCtrlEvent` reaches only the processes that share the
//! console of the caller. So the sender leaves its own console, attaches to the
//! console of the target, and raises the event there. A test gives the target
//! a console of its own ([`CREATE_NO_WINDOW`]), so the test does not depend on
//! the console of the runner.
//!
//! The sender changes the console of the calling process. Call it only from a
//! process that exists to send the event, never from the process of a node.
//! `FreeConsole` makes the console handles invalid, so give that process a
//! stdout and a stderr that are not the console (null or a pipe).
//!
//! Only for tests and tools: the module is behind `test-fixtures`, so the
//! library that ships has no function that changes the console of the process.

use std::io;

use windows_sys::Win32::System::Console::{
    AttachConsole, CTRL_BREAK_EVENT, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
    SetConsoleCtrlHandler,
};
pub use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

/// The console events that a process can raise.
///
/// `GenerateConsoleCtrlEvent` raises only these two. Closing the console, a
/// logoff and a shutdown come from the system alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleEvent {
    /// Ctrl+C, to every process of the console of the target.
    CtrlC,
    /// Ctrl+Break, to the process group of the target only. The target must be
    /// the root of its own group ([`CREATE_NEW_PROCESS_GROUP`]), so the id of
    /// the group is its pid.
    CtrlBreak,
}

/// Send `event` to the process `pid`, through its console.
///
/// Leaves the console of the calling process: see the module doc.
///
/// # Errors
/// `pid` has no console that this process can attach to, or the event cannot
/// be raised.
#[expect(
    unsafe_code,
    reason = "FreeConsole, AttachConsole, SetConsoleCtrlHandler and GenerateConsoleCtrlEvent FFI"
)]
pub fn send_console_event(pid: u32, event: ConsoleEvent) -> io::Result<()> {
    // The result is not read: the call fails when this process has no console,
    // and that is the state the next call needs. `AttachConsole` fails while a
    // console is still attached.
    // SAFETY: no argument; it only detaches this process from its console.
    let _ = unsafe { FreeConsole() };
    // SAFETY: a plain value argument.
    if unsafe { AttachConsole(pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let (kind, group) = match event {
        ConsoleEvent::CtrlC => {
            // Group 0 is every process of the console, this one too. With no
            // handler routine, TRUE makes this process ignore ctrl-c.
            // SAFETY: a null routine and a plain value.
            if unsafe { SetConsoleCtrlHandler(None, 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
            (CTRL_C_EVENT, 0)
        }
        // This process is not in the group of the target, so it does not get
        // the event.
        ConsoleEvent::CtrlBreak => (CTRL_BREAK_EVENT, pid),
    };
    // SAFETY: plain value arguments.
    if unsafe { GenerateConsoleCtrlEvent(kind, group) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Turn off the flag that makes this process ignore ctrl-c.
///
/// A process gets the flag from a parent that ignores ctrl-c, and a process
/// started with [`CREATE_NEW_PROCESS_GROUP`] has it from the start. With the
/// flag on, no handler of the process gets ctrl-c. A test calls this in a
/// target that must get ctrl-c whoever started the test.
///
/// # Errors
/// The flag cannot be changed.
#[expect(unsafe_code, reason = "SetConsoleCtrlHandler FFI")]
pub fn allow_ctrl_c() -> io::Result<()> {
    // SAFETY: a null routine and a plain value. With no routine, FALSE turns
    // the flag off.
    if unsafe { SetConsoleCtrlHandler(None, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use std::io::{BufRead as _, BufReader};
    use std::os::windows::process::CommandExt as _;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::STATUS_CONTROL_C_EXIT;

    use super::{
        CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, ConsoleEvent, allow_ctrl_c, send_console_event,
    };

    /// The environment that selects the target of [`console_sender`]: its pid
    /// and `c` or `break`.
    const SENDER_ENV: &str = "HABILIS_UTIL_CONSOLE_SENDER";

    /// The line that [`idle_target`] writes when ctrl-c is on.
    const TARGET_READY: &str = "idle target ready";

    /// How long the target sleeps. A target that runs this long was not
    /// stopped by the event.
    const TARGET_LIFE: Duration = Duration::from_secs(30);

    /// How long a test waits for the target to stop after the event.
    const STOP_DEADLINE: Duration = Duration::from_secs(10);

    /// Not a test: the target. It has no console handler of its own, so the
    /// default handler stops it on either event. It turns ctrl-c on first,
    /// because a parent that ignores ctrl-c gives it the flag, and then says
    /// so on stdout: an event sent before that line could be ignored.
    #[test]
    #[ignore = "a process for the console tests, started by them"]
    fn idle_target() {
        allow_ctrl_c().expect("ctrl-c on");
        println!("{TARGET_READY}");
        std::thread::sleep(TARGET_LIFE);
    }

    /// Not a test: the sender, a process of its own because it leaves its
    /// console. It panics, and so exits with an error, when the send fails.
    #[test]
    #[ignore = "a process for the console tests, started by them"]
    fn console_sender() {
        let spec = std::env::var(SENDER_ENV).expect("the target of the sender");
        let (pid, event) = spec.split_once(' ').expect("a pid and an event");
        let event = match event {
            "c" => ConsoleEvent::CtrlC,
            "break" => ConsoleEvent::CtrlBreak,
            other => panic!("unknown event {other}"),
        };
        send_console_event(pid.parse().expect("a pid"), event).expect("the console event");
    }

    /// This test binary, with only `entry` selected.
    fn entry(entry: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("the test binary"));
        command.args([
            &format!("win_console::tests::{entry}"),
            "--exact",
            "--ignored",
            "--nocapture",
        ]);
        command
    }

    /// A child that is killed on drop, so a test that fails leaves no process
    /// behind.
    struct Killed(Child);

    impl Drop for Killed {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// The target, in a console of its own, once it has turned ctrl-c on.
    fn spawn_target(new_group: bool) -> Killed {
        let flags = if new_group {
            CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        } else {
            CREATE_NO_WINDOW
        };
        let mut target = Killed(
            entry("idle_target")
                .creation_flags(flags)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("the target"),
        );
        let stdout = target.0.stdout.take().expect("piped");
        let ready = BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .any(|line| line == TARGET_READY);
        assert!(ready, "the target exited before it was ready");
        target
    }

    /// Run the sender for `pid`, and give its exit status and its output.
    /// `CREATE_NO_WINDOW` shows no window on a runner with no console; the
    /// sender leaves that console at once.
    fn run_sender(pid: u32, event: &str) -> (ExitStatus, String) {
        let output = entry("console_sender")
            .env(SENDER_ENV, format!("{pid} {event}"))
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
            .expect("the sender");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status, text)
    }

    /// Wait for `child` to exit, up to [`STOP_DEADLINE`].
    fn wait_for_exit(child: &mut Child) -> Option<ExitStatus> {
        let start = Instant::now();
        while start.elapsed() < STOP_DEADLINE {
            if let Some(status) = child.try_wait().expect("the target status") {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// Send `event` to a new target, and check that the default handler
    /// stopped it.
    fn assert_event_stops_target(event: &str, new_group: bool) {
        let mut target = spawn_target(new_group);
        let (status, output) = run_sender(target.0.id(), event);
        assert!(status.success(), "the sender failed: {status}\n{output}");
        let exit = wait_for_exit(&mut target.0).unwrap_or_else(|| {
            panic!("the target did not stop within {STOP_DEADLINE:?} of ctrl-{event}")
        });
        assert_eq!(exit.code(), Some(STATUS_CONTROL_C_EXIT), "{exit}");
    }

    #[test]
    fn ctrl_break_stops_a_process_in_its_own_group() {
        assert_event_stops_target("break", true);
    }

    #[test]
    fn ctrl_c_stops_a_process_of_the_console() {
        assert_event_stops_target("c", false);
    }

    #[test]
    fn a_process_that_exited_gives_an_error() {
        let mut gone = Command::new("cmd")
            .args(["/c", "exit"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("cmd");
        let pid = gone.id();
        // `gone` holds the handle of the process until the end of the test,
        // and Windows does not reuse a pid while a handle holds it. So the
        // sender cannot reach another process with this pid.
        gone.wait().expect("cmd exits");
        let (status, output) = run_sender(pid, "break");
        assert!(
            !status.success(),
            "the sender reached a process that exited\n{output}"
        );
        assert!(output.contains("the console event"), "{output}");
    }
}
