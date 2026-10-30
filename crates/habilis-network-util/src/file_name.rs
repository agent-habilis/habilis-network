//! The rule that a name must obey to be the stem of a file on Windows.
//!
//! The local nickname is the stem of every per-member file (`<nick>.state.json`,
//! `<nick>.tracing.log`, the IPC marker). A `Nickname` already refuses control
//! characters, whitespace and the path separators, but the Windows file-naming
//! rules refuse more: five characters, a trailing dot, and the names of the
//! legacy devices. Windows 10 and Windows Server 2022 map `con.state.json` to the
//! console device; Windows 11 accepts it. The rule follows the documented rules,
//! so one nickname works on every Windows. It is pure and compiles everywhere,
//! so its tests run on every OS. Only the
//! call that applies it to the local nickname is `cfg(windows)`: the wire rule
//! of `Nickname` does not change, and a peer on another OS keeps its name.

/// The characters that a Windows file name cannot hold and that a `Nickname`
/// allows. `< > / \` and the control characters are already refused there.
const FORBIDDEN: [char; 5] = [':', '*', '?', '"', '|'];

/// The device names that the Windows naming rules reserve, whatever the
/// extension: `con.txt` is the console too. The superscript digits are devices as
/// well. `conin$` and `conout$` are console pseudo-files, special only as a bare
/// name; they are here because a nickname gains nothing from them.
const RESERVED: [&str; 32] = [
    "con", "prn", "aux", "nul", "conin$", "conout$", "com0", "com1", "com2", "com3", "com4",
    "com5", "com6", "com7", "com8", "com9", "com¹", "com²", "com³", "lpt0", "lpt1", "lpt2", "lpt3",
    "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "lpt¹", "lpt²", "lpt³",
];

/// Why `stem` cannot be the stem of a file on Windows, or `None` when it can.
/// The reason completes the sentence "the name …".
#[must_use]
pub fn windows_file_stem_problem(stem: &str) -> Option<&'static str> {
    if stem.chars().any(|ch| FORBIDDEN.contains(&ch)) {
        return Some("contains one of : * ? \" |, which Windows refuses in a file name");
    }
    if stem.ends_with('.') {
        return Some("ends with a dot, which a Windows file name cannot keep");
    }
    // Windows reads the device name before the first dot, and folds ASCII case
    // only. The superscript digits have no case.
    let device = stem
        .split_once('.')
        .map_or(stem, |(head, _)| head)
        .to_ascii_lowercase();
    if RESERVED.contains(&device.as_str()) {
        return Some("is a Windows device name, which Windows 10 maps to the device");
    }
    None
}

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;

    use super::windows_file_stem_problem;

    #[test]
    fn the_names_that_windows_refuses_are_refused() {
        for stem in [
            "con", "CON", "Con.txt", "nul", "aux.x.y", "prn", "com0", "COM9", "lpt9", "com¹",
            "LPT³", "conin$", "CONOUT$", "a:b", "a*", "why?", "say\"hi", "pipe|d", "dot.",
        ] {
            assert!(
                windows_file_stem_problem(stem).is_some(),
                "{stem:?} must be refused"
            );
        }
    }

    #[test]
    fn names_that_only_look_like_a_device_are_accepted() {
        for stem in [
            "con-x",
            "console",
            "com10",
            "lpt",
            "a.b",
            "x.con",
            "nul-void",
            "word-word",
            "alice",
            "日本",
        ] {
            assert_eq!(
                windows_file_stem_problem(stem),
                None,
                "{stem:?} must be accepted"
            );
        }
    }
}
