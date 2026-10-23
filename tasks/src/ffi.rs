//! `cargo task ffi` — build the C ABI as a static library and prove it exports
//! what its header promises.
//!
//! The C ABI is the whole point of `habilis-network-ffi` and its only non-Rust consumer
//! links the archive, so building it the way that consumer does is the only
//! check that means anything. A name declared in `habilis_network.h` but missing from
//! the archive fails the consumer's link long after this went green.

use std::collections::BTreeSet;

use xshell::{Shell, cmd};

use crate::TaskOutcome;
use crate::util::{metadata, output, repo_root};

/// Relative to the target directory, which cargo owns. MSVC names a staticlib
/// `<crate>.lib`, with no `lib` prefix. The `habilis_network_ffi.dll.lib` beside it
/// is the import library of the cdylib, not the archive.
const ARCHIVE: &str = if cfg!(target_env = "msvc") {
    "release/habilis_network_ffi.lib"
} else {
    "release/libhabilis_network_ffi.a"
};
const HEADER: &str = "crates/habilis-network-ffi/include/habilis_network.h";

pub(crate) fn run(sh: &Shell) -> TaskOutcome {
    output::status("Building", "habilis-network-ffi (release staticlib)");
    cmd!(sh, "cargo build --release -p habilis-network-ffi")
        .quiet()
        .run()?;

    let archive = metadata(sh)?.target_directory.join(ARCHIVE);
    if !archive.exists() {
        return Err(format!("{} was not produced", archive.display()).into());
    }

    let declared = declared(&std::fs::read_to_string(repo_root().join(HEADER))?);
    let (reader, flags) = symbol_reader(sh)?;
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
            "{reader} read no habilis-network symbols at all — it likely cannot parse the \
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
/// system one as the fallback for a machine without the component. Windows has
/// no system `nm`, so there the component is required.
fn symbol_reader(sh: &Shell) -> Result<(String, Vec<&'static str>), String> {
    if let Some(path) = bundled_nm(sh) {
        return Ok((path, vec!["--defined-only", "--extern-only"]));
    }
    if cfg!(windows) {
        return Err(
            "the toolchain has no llvm-nm, and Windows has no system `nm` to fall \
                    back to. Install it with `rustup component add llvm-tools`."
                .to_owned(),
        );
    }
    Ok(("nm".to_owned(), vec!["-gU"]))
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
        .join("bin")
        .join(format!("llvm-nm{}", std::env::consts::EXE_SUFFIX));
    path.exists().then(|| path.display().to_string())
}

fn host_triple(sh: &Shell) -> Option<String> {
    let version = cmd!(sh, "rustc -vV").quiet().ignore_stderr().read().ok()?;
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
}

/// Every `habilis_network_*` name the header applies as a function, prose included —
/// the doc comments name the same functions the declarations do, and a name in
/// a comment that no longer exists is drift worth catching.
fn declared(header: &str) -> BTreeSet<String> {
    let bytes = header.as_bytes();
    let mut names = BTreeSet::new();

    for (start, _) in header.match_indices("habilis_network_") {
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

/// Every `habilis_network_*` symbol the archive defines.
///
/// Mach-O prefixes an underscore, and ELF and COFF on `x86_64` do not, so the prefix
/// is optional here and the runner works on all three.
fn exported(nm: &str) -> BTreeSet<String> {
    nm.lines()
        .filter_map(|line| line.split_whitespace().next_back())
        .map(|symbol| symbol.strip_prefix('_').unwrap_or(symbol))
        // The shape of a C entry point. `nm` also prints archive member names
        // (`habilis_network_util-….rcgu.o:`) as headers, and those are not symbols.
        .filter(|symbol| {
            symbol.starts_with("habilis_network_")
                && symbol
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::exported;
    use habilis_network_test_tracing::test;

    /// The C entry points of a sample, and nothing else.
    fn names(nm: &str) -> Vec<String> {
        exported(nm).into_iter().collect()
    }

    #[test]
    fn exported_reads_elf() {
        let nm = "\
habilis_network_ffi-1f2e3d4c5b6a7980.habilis_network_ffi.abc123-cgu.0.rcgu.o:
0000000000001230 T habilis_network_mesh_open
0000000000004560 T habilis_network_version
0000000000007890 T _ZN19habilis_network_ffi4mesh4Mesh4recv17h0123456789abcdefE
";
        assert_eq!(
            names(nm),
            ["habilis_network_mesh_open", "habilis_network_version"]
        );
    }

    #[test]
    fn exported_reads_mach_o_without_its_underscore() {
        let nm = "\
habilis_network_ffi-1f2e3d4c5b6a7980.habilis_network_ffi.abc123-cgu.0.rcgu.o:
0000000000001230 T _habilis_network_mesh_open
0000000000004560 T _habilis_network_version
";
        assert_eq!(
            names(nm),
            ["habilis_network_mesh_open", "habilis_network_version"]
        );
    }

    /// Lines of `llvm-nm --defined-only --extern-only` on the MSVC staticlib,
    /// taken from a real run on Windows: 32-bit addresses, no underscore, and a
    /// member header that is no symbol.
    #[test]
    fn exported_reads_coff() {
        let nm = "\
habilis_network_ffi.habilis_network_ffi.87d421e0072b2311-cgu.10.rcgu.o:
00000000 T _ZN19habilis_network_ffi4mesh4Mesh4recv28_$u7b$$u7b$closure$u7d$$u7d$17h525413074163e98dE.llvm.5446166027588183135
00000000 T habilis_network_mesh_open
00000000 T habilis_network_mesh_peer_count
00000000 T habilis_network_version
";
        assert_eq!(
            names(nm),
            [
                "habilis_network_mesh_open",
                "habilis_network_mesh_peer_count",
                "habilis_network_version"
            ]
        );
    }
}
