use super::{Kind, Scope};

pub(crate) struct Step {
    pub(crate) kind: Kind,
    pub(crate) scope: Scope,
    /// Everything after the package selection.
    pub(crate) args: &'static [&'static str],
}

impl Step {
    /// The full argument list, ready to hand to cargo.
    pub(crate) fn command(&self, packages: &[String]) -> Vec<String> {
        let mut argv = vec![self.kind.subcommand().to_owned()];

        if self.kind.is_wasm() {
            argv.push("--target".to_owned());
            argv.push("wasm32-unknown-unknown".to_owned());
        }

        match self.scope {
            // A scoped run replaces the whole workspace with the named crates;
            // an unscoped one keeps `--workspace`.
            Scope::Workspace if packages.is_empty() => argv.push("--workspace".to_owned()),
            Scope::Workspace => argv.extend(
                packages
                    .iter()
                    .flat_map(|name| ["-p".to_owned(), name.clone()]),
            ),
            Scope::Crate(name) => {
                argv.push("-p".to_owned());
                argv.push(name.to_owned());
            }
        }

        argv.extend(self.args.iter().map(|&arg| arg.to_owned()));

        if self.kind.denies_warnings() {
            argv.push("--".to_owned());
            argv.push("-D".to_owned());
            argv.push("warnings".to_owned());
        }
        // `clippy.toml` lists the Tokio calls that panic in a browser, and the lint is off in
        // the workspace: a wasm32 row turns it on for every crate it compiles.
        if self.kind == Kind::WasmClippy {
            argv.push("-D".to_owned());
            argv.push("clippy::disallowed_methods".to_owned());
        }

        argv
    }

    /// The status line: the participle cargo would use, then the part of the
    /// invocation that says which slice of the workspace this row is.
    pub(crate) fn describe(&self, packages: &[String]) -> (&'static str, String) {
        let subject = self
            .command(packages)
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ");
        (self.kind.verb(), subject)
    }
}
