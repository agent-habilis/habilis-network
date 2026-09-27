//! `cargo task ffi` — build the C ABI as a static library and prove it exports
//! what its header promises.
//!
//! The C ABI is the whole point of `fofoca-ffi` and its only non-Rust consumer
//! links the archive, so building it the way that consumer does is the only
//! check that means anything. A name declared in `fofoca.h` but missing from
//! the archive fails the consumer's link long after this went green.

use std::collections::BTreeSet;

use xshell::{Shell, cmd};

use crate::TaskOutcome;
use crate::util::{output, repo_root};

const ARCHIVE: &str = "target/release/libfofoca_ffi.a";
const HEADER: &str = "crates/fofoca-ffi/include/fofoca.h";

pub(crate) fn run(sh: &Shell) -> TaskOutcome {
    output::status("Building", "fofoca-ffi (release staticlib)");
    cmd!(sh, "cargo build --release -p fofoca-ffi")
        .quiet()
        .run()?;

    let archive = repo_root().join(ARCHIVE);
    if !archive.exists() {
        return Err(format!("{ARCHIVE} was not produced").into());
    }

    let declared = declared(&std::fs::read_to_string(repo_root().join(HEADER))?);
    let (reader, flags) = symbol_reader(sh);
    // Non-zero status and a warning for every archive member with no symbols,
    // and a rust staticlib has plenty. The symbols it did print are still the
    // answer; the diff below is what judges the archive.
    let exported = exported(
        &cmd!(sh, "{reader} {flags...} {archive}")
            .quiet()
            .ignore_stderr()
            .ignore_status()
            .read()?,
    );
    if exported.is_empty() {
        return Err(format!(
            "{reader} read no fofoca symbols at all — it likely cannot parse the \
             thin-LTO bitcode objects rustc emits. Install the toolchain's own \
             reader with `rustup component add llvm-tools`."
        )
        .into());
    }

    output::status(
        "Checking",
        &format!("{} declarations against the archive", declared.len()),
    );

    // Both ways: a declaration with no export is a link error for the caller,
    // and an export with no declaration is a call nobody outside can see.
    let missing: Vec<&str> = declared.difference(&exported).map(String::as_str).collect();
    let undeclared: Vec<&str> = exported.difference(&declared).map(String::as_str).collect();
    if missing.is_empty() && undeclared.is_empty() {
        return Ok(());
    }
    for name in &missing {
        output::detail(&format!("{name} (declared, not exported)"));
    }
    for name in &undeclared {
        output::detail(&format!("{name} (exported, not declared)"));
    }
    Err(format!(
        "{HEADER} and the staticlib disagree: {} declared but not exported, {} exported but not declared",
        missing.len(),
        undeclared.len()
    )
    .into())
}

/// The symbol reader to use, and its flags for "defined, external only".
///
/// `[profile.release] lto = "thin"` makes the crate's own codegen units LLVM
/// bitcode rather than Mach-O, and a system `nm` older than the rustc that
/// wrote them cannot read exactly those objects — the ones holding the C ABI.
/// It then reports every declaration missing, which is the most alarming
/// possible way to say "I could not look". The toolchain ships a reader that
/// always matches, under the `llvm-tools` component; prefer it and keep the
/// system one as the fallback for a machine without the component.
fn symbol_reader(sh: &Shell) -> (String, Vec<&'static str>) {
    if let Some(path) = bundled_nm(sh) {
        return (path, vec!["--defined-only", "--extern-only"]);
    }
    ("nm".to_owned(), vec!["-gU"])
}

/// `llvm-nm` from the active toolchain, if the `llvm-tools` component is there.
fn bundled_nm(sh: &Shell) -> Option<String> {
    let sysroot = cmd!(sh, "rustc --print sysroot")
        .quiet()
        .ignore_stderr()
        .read()
        .ok()?;
    let triple = host_triple(sh)?;
    let path = std::path::Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(triple)
        .join("bin/llvm-nm");
    path.exists().then(|| path.display().to_string())
}

fn host_triple(sh: &Shell) -> Option<String> {
    let version = cmd!(sh, "rustc -vV").quiet().ignore_stderr().read().ok()?;
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
}

/// Every `fofoca_*` name the header applies as a function, prose included —
/// the doc comments name the same functions the declarations do, and a name in
/// a comment that no longer exists is drift worth catching.
fn declared(header: &str) -> BTreeSet<String> {
    let bytes = header.as_bytes();
    let mut names = BTreeSet::new();

    for (start, _) in header.match_indices("fofoca_") {
        let preceded_by_word = start
            .checked_sub(1)
            .is_some_and(|prev| bytes[prev] == b'_' || bytes[prev].is_ascii_alphanumeric());
        if preceded_by_word {
            continue;
        }
        let len = header[start..]
            .find(|ch: char| !(ch.is_ascii_lowercase() || ch == '_'))
            .unwrap_or(header.len() - start);
        if header[start + len..].starts_with('(') {
            names.insert(header[start..start + len].to_owned());
        }
    }
    names
}

/// Every `fofoca_*` symbol the archive defines.
///
/// Mach-O prefixes an underscore and ELF does not, so the prefix is optional
/// here and the runner works on both.
fn exported(nm: &str) -> BTreeSet<String> {
    nm.lines()
        .filter_map(|line| line.split_whitespace().next_back())
        .map(|symbol| symbol.strip_prefix('_').unwrap_or(symbol))
        // The shape of a C entry point. `nm` also prints archive member names
        // (`fofoca_util-….rcgu.o:`) as headers, and those are not symbols.
        .filter(|symbol| {
            symbol.starts_with("fofoca_")
                && symbol
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
        .map(str::to_owned)
        .collect()
}
