//! Host-filesystem policy for the two `sandbox_run` arguments that name a
//! **host** path: `stdin_file` (read) and `copy_out[].host` (write).
//!
//! # Why this exists
//!
//! Every other argument to `sandbox_run` describes work to do *inside* the VM.
//! These two do not: they name files on the machine running the server. Until
//! 0.11.0 they were used verbatim, which made each of them a primitive the MCP
//! caller could aim anywhere:
//!
//! ```text
//!   sandbox_run(cmd="cat", stdin_file="~/.isopod/credentials.json")
//!       → the store's contents come back in `stdout`
//!   sandbox_run(cmd=…, copy_out=[{guest:"/tmp/x", host:"~/.ssh/authorized_keys"}])
//!       → guest-authored bytes land on the host, parent dirs created
//! ```
//!
//! That matters more than it would for a CLI flag, because of who the caller is.
//! The CLI's caller is the operator, who owns those files already. The MCP
//! caller is a **language model whose context may have been written by the code
//! being sandboxed** — the same premise the credential store is built on. A
//! credential system whose whole design is "the run may only name an alias,
//! because the caller cannot be trusted to name a secret" is undone by a
//! sibling argument that reads the store, and undone again by one that rewrites
//! it.
//!
//! # The policy
//!
//! Both paths are resolved and required to sit inside a **confinement root**,
//! which defaults to the server's working directory — the project a coding agent
//! is working in, which is exactly what artifact extraction and large stdin
//! payloads are for. Symlinks are resolved *before* the check, so a link planted
//! inside the root cannot reach outside it.
//!
//! | Variable | Effect |
//! |---|---|
//! | `ISOPOD_MCP_HOST_IO_ROOT` | Confine to this directory instead of the cwd. The literal value `/` restores the pre-0.11.0 behaviour, explicitly and visibly. |
//! | `ISOPOD_MCP_HOST_IO=off` | Refuse both arguments outright. |
//! | `ISOPOD_MCP_STDIN_FILE=off` | Refuse `stdin_file` only. |
//! | `ISOPOD_MCP_COPY_OUT=off` | Refuse `copy_out` only. |
//!
//! The CLI is deliberately unaffected: there the caller is the operator, and
//! confining them to their own project directory would be a regression with no
//! threat behind it.

use std::path::{Component, Path, PathBuf};

/// Which host-path argument is being checked. Only used to name the right
/// variable in a refusal, so an operator is told the exact knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `stdin_file` — the server reads this path.
    Read,
    /// `copy_out[].host` — the server writes this path.
    Write,
}

impl Access {
    /// The environment variable that disables just this one.
    const fn switch(self) -> &'static str {
        match self {
            Self::Read => "ISOPOD_MCP_STDIN_FILE",
            Self::Write => "ISOPOD_MCP_COPY_OUT",
        }
    }

    /// The argument's name, as the caller wrote it.
    const fn argument(self) -> &'static str {
        match self {
            Self::Read => "stdin_file",
            Self::Write => "copy_out[].host",
        }
    }
}

/// The resolved policy for one server process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIo {
    /// `None` when host I/O is unconfined (`ISOPOD_MCP_HOST_IO_ROOT=/`).
    root: Option<PathBuf>,
    read_enabled: bool,
    write_enabled: bool,
}

impl HostIo {
    /// Read the policy from the environment.
    ///
    /// Resolved once at startup rather than per call, so a mid-session
    /// environment change cannot widen the policy, and so a misconfiguration is
    /// visible in the server's log line at boot instead of on the first use.
    #[must_use]
    pub fn from_env() -> Self {
        // Unset means on. Any set value that is not recognisably affirmative
        // means OFF, including one this build does not know — a security switch
        // must not stay open because someone wrote `disabled` instead of `off`.
        // The value is echoed so an operator who meant "on" can see why it isn't.
        let off = |name: &str| match std::env::var(name) {
            Err(_) => false,
            Ok(v) => {
                let v = v.trim().to_ascii_lowercase();
                let on = matches!(v.as_str(), "on" | "1" | "true" | "yes" | "enabled");
                if !on && !matches!(v.as_str(), "off" | "0" | "false" | "no" | "disabled") {
                    eprintln!(
                        "isopod: {name}={v:?} is not a value I recognise; treating it as \"off\". \
                         Use \"on\" or \"off\"."
                    );
                }
                !on
            }
        };
        let all_off = off("ISOPOD_MCP_HOST_IO");
        Self {
            root: Self::root_from_env(),
            read_enabled: !all_off && !off("ISOPOD_MCP_STDIN_FILE"),
            write_enabled: !all_off && !off("ISOPOD_MCP_COPY_OUT"),
        }
    }

    /// The confinement root: the override if set, else the working directory.
    ///
    /// A cwd that cannot be read fails **closed** — `root` becomes an
    /// unmatchable path rather than `None`, because `None` means "unconfined"
    /// and an unreadable cwd is not a reason to grant more access.
    fn root_from_env() -> Option<PathBuf> {
        /// A root that matches nothing, so an unusable configuration refuses every
        /// path instead of accepting every path.
        const UNMATCHABLE: &str = "/nonexistent/isopod-host-io-unresolved";

        let from_cwd = || {
            std::env::current_dir()
                .and_then(std::fs::canonicalize)
                .unwrap_or_else(|_| PathBuf::from(UNMATCHABLE))
        };
        let resolved = match std::env::var_os("ISOPOD_MCP_HOST_IO_ROOT") {
            // An empty value is what an unset shell variable expands to, and what
            // an `"env": {"ISOPOD_MCP_HOST_IO_ROOT": ""}` block in an MCP
            // registration produces. Treating it as a root was a fail-open:
            // `Path::starts_with("")` is true for EVERY path, so the policy
            // admitted everything while `describe()` reported "confined to ".
            Some(v) if v.is_empty() || v.to_string_lossy().trim().is_empty() => {
                eprintln!(
                    "isopod: ISOPOD_MCP_HOST_IO_ROOT is set but empty; using the working \
                     directory instead. Set it to a path, or to \"/\" to disable the \
                     confinement deliberately."
                );
                from_cwd()
            }
            Some(v) => std::fs::canonicalize(&v).unwrap_or_else(|_| PathBuf::from(v)),
            None => from_cwd(),
        };
        // `/` is not a confinement — every path is inside it — so it collapses to
        // the explicit unconfined case rather than being reported as a root. A
        // server started with `/` as its working directory would otherwise log
        // "confined to /" while accepting every host path there is, and every
        // spelling that canonicalises to `/` would do the same.
        if resolved == Path::new("/") {
            return None;
        }
        // Anything that is not an absolute path below the root is not a usable
        // confinement. Fail closed rather than reporting a root that matches
        // everything or nothing in a way the operator cannot see.
        if !resolved.is_absolute() || resolved.components().count() < 2 {
            eprintln!(
                "isopod: ISOPOD_MCP_HOST_IO_ROOT resolved to {resolved:?}, which is not a \
                 usable confinement root; refusing every host path until it is fixed."
            );
            return Some(PathBuf::from(UNMATCHABLE));
        }
        Some(resolved)
    }

    /// isopod's own state directory, resolved once.
    ///
    /// Refused unconditionally — see [`HostIo::check`]. `None` only if the home
    /// directory cannot be determined at all, in which case there is nothing to
    /// carve out and the run has bigger problems.
    fn state_dir() -> Option<PathBuf> {
        let home = isopod_core::paths::isopod_home().ok()?;
        // Canonicalise if it exists so the comparison is against the same shape as
        // a resolved argument; fall back to the literal path if it does not.
        Some(std::fs::canonicalize(&home).unwrap_or(home))
    }

    /// Build an explicit policy, for tests. The real server always resolves its
    /// policy from the environment.
    #[cfg(test)]
    #[must_use]
    pub fn new(root: Option<PathBuf>, read_enabled: bool, write_enabled: bool) -> Self {
        Self {
            root,
            read_enabled,
            write_enabled,
        }
    }

    /// A one-line description for the server's startup log.
    #[must_use]
    pub fn describe(&self) -> String {
        let where_ = match &self.root {
            Some(r) => format!("confined to {}", r.display()),
            None => "UNCONFINED (ISOPOD_MCP_HOST_IO_ROOT=/)".to_string(),
        };
        format!(
            "{where_}; stdin_file={}, copy_out={}",
            if self.read_enabled { "on" } else { "off" },
            if self.write_enabled { "on" } else { "off" },
        )
    }

    /// Check one caller-supplied host path for `access`.
    ///
    /// Returns the path to actually use, which is the **resolved** one — so the
    /// value that was validated is the value that gets opened, closing the gap
    /// between checking one path and using another.
    ///
    /// # Errors
    /// A message naming the argument, the root, and the variable that would
    /// widen the policy. The caller is a model, but this message is also what an
    /// operator reads when their own legitimate call is refused, so it has to
    /// say what to do rather than only what happened.
    pub fn check(&self, raw: &str, access: Access) -> Result<PathBuf, String> {
        let enabled = match access {
            Access::Read => self.read_enabled,
            Access::Write => self.write_enabled,
        };
        if !enabled {
            return Err(format!(
                "{} is disabled on this isopod MCP server ({}=off). Pass the data \
                 inline via `stdin`, or read the result from `stdout`, or have the \
                 operator re-enable it.",
                access.argument(),
                access.switch(),
            ));
        }
        if raw.is_empty() {
            return Err(format!("{} must not be empty", access.argument()));
        }
        // `~` is not expanded by any shell here — the server reads the path
        // directly — so a caller passing it would otherwise get a confusing
        // "no such file" for a path that looks obviously valid.
        if raw.starts_with('~') {
            return Err(format!(
                "{} does not expand `~`; pass an absolute path or one relative to \
                 the server's working directory",
                access.argument(),
            ));
        }

        let resolved = match access {
            // The file must already exist, so full canonicalisation applies and
            // resolves every symlink in the chain.
            Access::Read => std::fs::canonicalize(raw)
                .map_err(|e| format!("{} {raw:?} cannot be read: {e}", access.argument()))?,
            // The destination usually does not exist yet. Canonicalise the
            // deepest ancestor that does, then re-append the rest — so a symlink
            // anywhere in the existing prefix is still resolved before the check.
            Access::Write => resolve_for_write(Path::new(raw)).map_err(|e| {
                format!(
                    "{} {raw:?} is not a usable destination: {e}",
                    access.argument()
                )
            })?,
        };

        // isopod's own state is refused whatever the root is, including when the
        // confinement is switched off. The root defaults to the server's working
        // directory, and `$HOME` is an entirely ordinary working directory for an
        // MCP registration — which put `~/.isopod` *inside* the confinement and
        // handed back exactly the credential-store read this module exists to
        // stop. A root is a boundary the operator chooses; this one is not
        // theirs to move, because no `sandbox_run` argument has any business
        // naming isopod's own store, its `file:` sources, or another run's logs.
        if let Some(state) = Self::state_dir() {
            if resolved.starts_with(&state) {
                return Err(format!(
                    "{} {raw:?} resolves to {}, which is inside isopod's own state \
                     directory {}. That is refused for every root, and with the \
                     confinement switched off: the credential store lives there, and \
                     a run that could read it would not need an alias, while one that \
                     could rewrite it could point an alias at a host of its choosing.",
                    access.argument(),
                    resolved.display(),
                    state.display(),
                ));
            }
        }

        // A hard link is a second name for an inode, so path resolution has
        // nothing to say about it: a link inside the root to a file outside it
        // canonicalises to itself and passes every prefix test. Reading one hands
        // back the out-of-root file's contents; writing one truncates the shared
        // inode. Refusing multiply-linked files costs nothing real — neither a
        // stdin payload nor a build artifact is normally hard-linked — and it is
        // the only check a path-based confinement can make here.
        if let Ok(meta) = std::fs::symlink_metadata(&resolved) {
            use std::os::unix::fs::MetadataExt as _;
            if meta.is_file() && meta.nlink() > 1 {
                return Err(format!(
                    "{} {raw:?} has {} hard links, so it is also reachable under another \
                     name that may be outside this server's host-I/O root. A path check \
                     cannot tell those names apart, so isopod refuses the file rather \
                     than guess. Copy it to a single-linked path and pass that.",
                    access.argument(),
                    meta.nlink(),
                ));
            }
        }

        let Some(root) = &self.root else {
            return Ok(resolved);
        };
        if !resolved.starts_with(root) {
            return Err(format!(
                "{} {raw:?} resolves to {}, which is outside this server's host-I/O \
                 root {}. Host paths are confined so that a caller cannot read or \
                 overwrite files the sandbox was never given — including isopod's \
                 own credential store. Use a path inside the root, or have the \
                 operator set ISOPOD_MCP_HOST_IO_ROOT (or `/` to disable the \
                 confinement).",
                access.argument(),
                resolved.display(),
                root.display(),
            ));
        }
        Ok(resolved)
    }
}

/// Strip the components that say nothing about *which file* is named, so every
/// guard below sees the same final component the kernel will.
///
/// `Path::components` already drops repeated separators, a trailing separator
/// and any interior `.`, which is the whole set of spellings that made the
/// dangling-symlink guard skippable: `symlink_metadata("link/")` reports
/// `ENOTDIR`, so the guard never fired, while `file_name()`/`parent()`
/// normalised the trailing component away again and handed the walk-up loop the
/// bare in-root name. Four spellings — `link/`, `link//`, `link/.`, `link/./` —
/// all reached `File::create`, which followed the link out of the root.
///
/// `..` is deliberately **kept**. It is not a spelling of the same file: it
/// names a different one, and it stays refused the way it already is — by
/// canonicalising the existing prefix (which collapses it) and failing the
/// root test, or by [`Path::file_name`] returning `None` for it in the walk-up.
fn normalize_destination(path: &Path) -> PathBuf {
    path.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect()
}

/// Resolve a write destination whose final component may not exist.
///
/// Walks up to the deepest existing ancestor, canonicalises **that**, then
/// re-appends the remaining components. A `..` in the remainder is refused
/// rather than normalised: it cannot be resolved against a directory that does
/// not exist yet, and guessing would be exactly the matcher/filesystem
/// disagreement this check exists to prevent.
fn resolve_for_write(raw: &Path) -> Result<PathBuf, String> {
    // Before any guard runs, so no guard can be shown a different final
    // component from the one the write will open.
    let normalized = normalize_destination(raw);
    let path: &Path = &normalized;
    if path.as_os_str().is_empty() {
        return Err("the destination names no file".into());
    }
    // An existing destination is resolved outright — including a symlink, whose
    // target is where a write would actually land.
    if path.exists() {
        return std::fs::canonicalize(path).map_err(|e| e.to_string());
    }
    // A *dangling* symlink is the case that made this check a fiction. `exists()`
    // follows the link and reports false when the target is absent, so a link to
    // a not-yet-existing file outside the root fell through to the walk-up loop
    // below, which treated the link's own name as an ordinary not-yet-existing
    // component and returned `<root>/<link>` — inside the root, and accepted.
    // `File::create` then followed the link and wrote the guest's bytes wherever
    // it pointed, while the result reported the in-root path. Each layer of that
    // is individually reasonable, which is why it survived a test suite whose
    // every symlink case had an existing target.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{} is a symbolic link whose target does not exist, so where a write \
                 would land cannot be resolved and checked. isopod will not write \
                 through it — name the destination directly",
                path.display()
            ));
        }
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("the server's working directory is unreadable: {e}"))?
            .join(path)
    };
    let mut remainder: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cursor = absolute.as_path();
    loop {
        // Same trap, one level up: `<root>/link/sub/artifact` where `link` dangles.
        // Every component below it "does not exist", so without this the loop
        // would walk straight past the link and re-append its name.
        if !cursor.exists() {
            if let Ok(meta) = std::fs::symlink_metadata(cursor) {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "{} is a symbolic link whose target does not exist, so this \
                         destination cannot be resolved and checked",
                        cursor.display()
                    ));
                }
            }
        }
        if cursor.exists() {
            let base = std::fs::canonicalize(cursor).map_err(|e| e.to_string())?;
            let mut out = base;
            for part in remainder.iter().rev() {
                out.push(part);
            }
            return Ok(out);
        }
        match cursor.file_name() {
            Some(name) => {
                remainder.push(name);
                cursor = cursor.parent().ok_or("no existing ancestor directory")?;
            }
            // A trailing `.`/`..`/root component with nothing existing beneath it.
            None => return Err("path has no resolvable ancestor".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn policy(root: &Path) -> HostIo {
        HostIo::new(
            Some(std::fs::canonicalize(root).expect("canonicalize root")),
            true,
            true,
        )
    }

    #[test]
    fn a_path_inside_the_root_is_accepted_for_both_directions() {
        let dir = tmp();
        let p = policy(dir.path());
        let inside = dir.path().join("payload.txt");
        std::fs::write(&inside, b"hi").expect("write");

        let got = p
            .check(inside.to_str().unwrap(), Access::Read)
            .expect("read inside the root");
        assert_eq!(got, std::fs::canonicalize(&inside).unwrap());

        // A write destination that does not exist yet, nested under a directory
        // that also does not exist yet.
        let out = dir.path().join("nested/deeper/artifact.tar");
        let got = p
            .check(out.to_str().unwrap(), Access::Write)
            .expect("write inside the root");
        assert!(got.starts_with(std::fs::canonicalize(dir.path()).unwrap()));
        assert!(got.ends_with("nested/deeper/artifact.tar"));
    }

    #[test]
    fn the_credential_store_is_out_of_reach() {
        // The attack that motivated this module, in the shape it was actually
        // demonstrated: read the store, learn every alias and `file:` source,
        // then read the sources.
        let dir = tmp();
        let elsewhere = tmp();
        let p = policy(dir.path());
        let secret = elsewhere.path().join("credentials.json");
        std::fs::write(&secret, b"{\"version\":1}").expect("write");

        let err = p
            .check(secret.to_str().unwrap(), Access::Read)
            .expect_err("a path outside the root must be refused");
        assert!(err.contains("outside this server's host-I/O root"), "{err}");
        assert!(
            err.contains("credential store"),
            "the why is in the message: {err}"
        );
        assert!(
            err.contains("ISOPOD_MCP_HOST_IO_ROOT"),
            "the way out too: {err}"
        );
    }

    #[test]
    fn a_symlink_planted_inside_the_root_cannot_reach_out() {
        // Confining the *spelling* of a path would be no confinement at all: the
        // sandbox can create files on the host through copy_out, so a link
        // inside the root is something a caller can arrange.
        let dir = tmp();
        let elsewhere = tmp();
        let p = policy(dir.path());
        let target = elsewhere.path().join("secret");
        std::fs::write(&target, b"tok").expect("write");
        let link = dir.path().join("innocent.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = p
            .check(link.to_str().unwrap(), Access::Read)
            .expect_err("a symlink out of the root must be refused");
        assert!(err.contains("outside"), "{err}");

        // And the same for a write through a symlinked directory.
        let linkdir = dir.path().join("out");
        std::os::unix::fs::symlink(elsewhere.path(), &linkdir).expect("symlink dir");
        let err = p
            .check(linkdir.join("artifact").to_str().unwrap(), Access::Write)
            .expect_err("a write through a symlinked dir must be refused");
        assert!(err.contains("outside"), "{err}");
    }

    #[test]
    fn a_symlink_whose_target_does_not_exist_yet_cannot_be_written_through() {
        // The escape the first version of this module shipped with. `Path::exists`
        // follows the link and returns false when the target is absent, so the
        // "resolve it outright" branch was skipped and the walk-up loop treated
        // the link's own name as an ordinary new file — yielding an in-root path
        // that passed, after which `File::create` followed the link and wrote
        // outside. Demonstrated end to end through the MCP server before the fix.
        let dir = tmp();
        let elsewhere = tmp();
        let p = policy(dir.path());

        let target = elsewhere.path().join("pwned"); // deliberately NOT created
        let link = dir.path().join("innocent.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = p
            .check(link.to_str().unwrap(), Access::Write)
            .expect_err("a dangling symlink must not be written through");
        assert!(err.contains("does not exist"), "{err}");
        assert!(!target.exists(), "nothing may have been created");

        // And one level up: every component under a dangling link also "does not
        // exist", so the loop must notice the link rather than walk past it.
        let dirlink = dir.path().join("outdir");
        std::os::unix::fs::symlink(elsewhere.path().join("absent"), &dirlink).expect("symlink");
        let err = p
            .check(
                dirlink.join("sub/artifact.tar").to_str().unwrap(),
                Access::Write,
            )
            .expect_err("a dangling symlink as an ancestor must be refused too");
        assert!(err.contains("does not exist"), "{err}");

        // The ordinary case still works: a new file under a real directory.
        assert!(p
            .check(
                dir.path().join("fresh.txt").to_str().unwrap(),
                Access::Write
            )
            .is_ok());
    }

    /// Every spelling of the same symlink, dangling and live.
    ///
    /// The fix above was tested with exactly one spelling — `link`, with no
    /// trailing separator — and the escape survived one character away.
    /// `symlink_metadata("link/")` returns `ENOTDIR`, so the guard never ran,
    /// while `file_name()`/`parent()` normalised the separator away again and
    /// handed the walk-up the bare in-root name. Four spellings reached
    /// `File::create`; on a real MCP server all four overwrote a file outside
    /// the root while reporting the in-root path back to the operator.
    ///
    /// The table is the point: a refusal branch is only as good as the input
    /// classes next to the one that reproduced it.
    #[test]
    fn every_spelling_of_a_symlink_is_refused_not_just_the_bare_one() {
        let dir = tmp();
        let elsewhere = tmp();
        let p = policy(dir.path());

        // A link to a file that exists (the overwrite case) and one to a file
        // that does not (the create case). Both are outside the root.
        let live_target = elsewhere.path().join("precious");
        std::fs::write(&live_target, b"must survive").expect("write");
        let dangling_target = elsewhere.path().join("not-yet"); // deliberately absent
        std::os::unix::fs::symlink(&live_target, dir.path().join("livelink")).expect("symlink");
        std::os::unix::fs::symlink(&dangling_target, dir.path().join("danglink")).expect("symlink");
        // And a link to a directory outside the root, written *through*.
        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("dirlink")).expect("symlink");

        let root = dir.path().display().to_string();
        for link in ["livelink", "danglink"] {
            for suffix in ["", "/", "//", "/.", "/./", "/././", "/.//./"] {
                let raw = format!("{root}/{link}{suffix}");
                let err = p
                    .check(&raw, Access::Write)
                    .expect_err("{raw} must not be writable through");
                assert!(
                    err.contains("outside this server's host-I/O root")
                        || err.contains("does not exist"),
                    "{raw}: refused for the wrong reason: {err}"
                );
            }
        }
        for suffix in ["new.txt", "sub/new.txt", "./new.txt", ".//new.txt"] {
            let raw = format!("{root}/dirlink/{suffix}");
            assert!(
                p.check(&raw, Access::Write).is_err(),
                "{raw} must not be writable through a symlinked directory"
            );
        }
        assert_eq!(
            std::fs::read(&live_target).expect("read"),
            b"must survive",
            "no check may have written anything"
        );
        assert!(!dangling_target.exists(), "nothing may have been created");

        // The same spellings of an ordinary in-root destination still resolve,
        // and to the same file — a normalisation that refused these would break
        // every legitimate trailing-separator path an operator writes.
        let plain = format!("{root}/artifact.tar");
        let want = p.check(&plain, Access::Write).expect("plain destination");
        for suffix in ["", "/", "//", "/.", "/./"] {
            let raw = format!("{plain}{suffix}");
            assert_eq!(
                p.check(&raw, Access::Write).expect("in-root destination"),
                want,
                "{raw} must resolve to the same file as {plain}"
            );
        }
    }

    #[test]
    fn a_trailing_separator_does_not_normalise_a_parent_hop_away() {
        // `.` is dropped because it names the same file; `..` names a different
        // one and stays refused. Both directions matter: dropping `..` too would
        // turn `<root>/a/../../etc/passwd` into an in-root path.
        let dir = tmp();
        let p = policy(dir.path());
        let root = dir.path().display().to_string();
        for raw in [
            format!("{root}/../escape"),
            format!("{root}/../escape/"),
            format!("{root}/./../escape"),
            format!("{root}/sub/../../escape"),
            format!("{root}/nonexistent/../../escape"),
        ] {
            assert!(
                p.check(&raw, Access::Write).is_err(),
                "{raw} must not resolve to an in-root path"
            );
        }
        // And the normaliser itself: `.` goes, `..` stays.
        assert_eq!(
            normalize_destination(Path::new("/a/./b//c/.")),
            PathBuf::from("/a/b/c")
        );
        assert_eq!(
            normalize_destination(Path::new("/a/../b/")),
            PathBuf::from("/a/../b")
        );
    }

    #[test]
    fn a_hard_link_is_refused_because_a_path_check_cannot_see_it() {
        // A second name for an inode canonicalises to itself, so every prefix test
        // passes while the bytes belong to a file outside the root. Reading one
        // returns that file; writing one truncates it.
        let dir = tmp();
        let elsewhere = tmp();
        let p = policy(dir.path());

        let outside = elsewhere.path().join("secret");
        std::fs::write(&outside, b"tok").expect("write");
        let inside = dir.path().join("notes.txt");
        match std::fs::hard_link(&outside, &inside) {
            Ok(()) => {}
            // Two tempdirs can land on different filesystems; then the attack is
            // not available either and there is nothing to assert.
            Err(_) => return,
        }

        for access in [Access::Read, Access::Write] {
            let err = p
                .check(inside.to_str().unwrap(), access)
                .expect_err("a multiply-linked file must be refused");
            assert!(err.contains("hard link"), "{err}");
        }
        // A single-linked file in the same directory is unaffected.
        let plain = dir.path().join("plain.txt");
        std::fs::write(&plain, b"x").expect("write");
        assert!(p.check(plain.to_str().unwrap(), Access::Read).is_ok());
    }

    #[test]
    fn isopod_s_own_state_directory_is_refused_whatever_the_root_is() {
        // The root defaults to the server's working directory, and `$HOME` is an
        // ordinary working directory for an MCP registration — which puts
        // `~/.isopod` *inside* the confinement and hands back the exact credential
        // store read this module exists to stop. The carve-out is not the
        // operator's to move, so it holds for a chosen root and for the
        // explicitly-unconfined case alike.
        let home = tmp();
        std::env::set_var("ISOPOD_HOME", home.path());
        let store = home.path().join("credentials.json");
        std::fs::write(&store, b"{\"version\":1}").expect("write");

        // Root = the parent of the state dir: the store is inside the root, and
        // still refused.
        let outer = HostIo::new(
            Some(std::fs::canonicalize(home.path().parent().unwrap()).unwrap()),
            true,
            true,
        );
        let err = outer
            .check(store.to_str().unwrap(), Access::Read)
            .expect_err("the store must be refused even from inside the root");
        assert!(err.contains("state directory"), "{err}");

        // Unconfined: still refused.
        let none = HostIo::new(None, true, true);
        let err = none
            .check(store.to_str().unwrap(), Access::Write)
            .expect_err("the store must be refused with the confinement off");
        assert!(err.contains("state directory"), "{err}");

        std::env::remove_var("ISOPOD_HOME");
    }

    #[test]
    fn an_empty_root_is_not_a_root() {
        // `Path::starts_with("")` is true for every path, so storing `""` as the
        // root admitted everything while `describe()` reported "confined to ".
        // An empty value is what an unset shell variable expands to.
        let restore = std::env::var_os("ISOPOD_MCP_HOST_IO_ROOT");
        for empty in ["", "   "] {
            std::env::set_var("ISOPOD_MCP_HOST_IO_ROOT", empty);
            let root = HostIo::root_from_env().expect("must not read as unconfined");
            assert_ne!(root, PathBuf::new(), "an empty root matches everything");
            assert!(root.is_absolute(), "root {root:?} must be absolute");
            assert!(
                root.components().count() >= 2,
                "root {root:?} is not usable"
            );
        }
        match restore {
            Some(v) => std::env::set_var("ISOPOD_MCP_HOST_IO_ROOT", v),
            None => std::env::remove_var("ISOPOD_MCP_HOST_IO_ROOT"),
        }
    }

    #[test]
    fn an_unrecognised_switch_value_reads_as_off() {
        // A security switch must not stay open because someone wrote "disabled"
        // instead of "off". Unset is on; anything not affirmative is off.
        let restore = std::env::var_os("ISOPOD_MCP_STDIN_FILE");
        for value in ["off", "0", "false", "no", "disabled", "nope", "maybe"] {
            std::env::set_var("ISOPOD_MCP_STDIN_FILE", value);
            assert!(
                !HostIo::from_env().read_enabled,
                "{value:?} must not leave stdin_file enabled"
            );
        }
        for value in ["on", "1", "true", "yes", "ENABLED"] {
            std::env::set_var("ISOPOD_MCP_STDIN_FILE", value);
            assert!(
                HostIo::from_env().read_enabled,
                "{value:?} must leave stdin_file enabled"
            );
        }
        std::env::remove_var("ISOPOD_MCP_STDIN_FILE");
        assert!(HostIo::from_env().read_enabled, "unset means on");
        if let Some(v) = restore {
            std::env::set_var("ISOPOD_MCP_STDIN_FILE", v);
        }
    }

    #[test]
    fn traversal_out_of_the_root_is_refused() {
        let dir = tmp();
        let p = policy(dir.path());
        // Resolution, not spelling, is what rejects this: canonicalising the
        // existing prefix collapses the `..` and the prefix check then fails.
        let escape = dir.path().join("../../etc/passwd");
        assert!(p.check(escape.to_str().unwrap(), Access::Read).is_err());
        // Also as a write destination, where the final component is absent.
        let escape_w = dir.path().join("../../tmp/isopod-escape-canary");
        assert!(p.check(escape_w.to_str().unwrap(), Access::Write).is_err());
    }

    #[test]
    fn each_direction_can_be_disabled_independently() {
        let dir = tmp();
        let root = Some(std::fs::canonicalize(dir.path()).unwrap());
        let inside = dir.path().join("f");
        std::fs::write(&inside, b"x").expect("write");
        let raw = inside.to_str().unwrap();

        let read_only = HostIo::new(root.clone(), true, false);
        assert!(read_only.check(raw, Access::Read).is_ok());
        let err = read_only.check(raw, Access::Write).unwrap_err();
        assert!(err.contains("ISOPOD_MCP_COPY_OUT=off"), "{err}");

        let write_only = HostIo::new(root.clone(), false, true);
        assert!(write_only.check(raw, Access::Write).is_ok());
        let err = write_only.check(raw, Access::Read).unwrap_err();
        assert!(err.contains("ISOPOD_MCP_STDIN_FILE=off"), "{err}");

        let neither = HostIo::new(root, false, false);
        assert!(neither.check(raw, Access::Read).is_err());
        assert!(neither.check(raw, Access::Write).is_err());
    }

    #[test]
    fn unconfined_is_reachable_but_has_to_be_asked_for() {
        // `ISOPOD_MCP_HOST_IO_ROOT=/` restores the old behaviour. It stays
        // possible because some deployments genuinely are single-trust — but it
        // is now a stated choice that shows up in the startup log.
        let elsewhere = tmp();
        let f = elsewhere.path().join("anywhere");
        std::fs::write(&f, b"x").expect("write");
        let p = HostIo::new(None, true, true);
        assert!(p.check(f.to_str().unwrap(), Access::Read).is_ok());
        assert!(p.describe().contains("UNCONFINED"), "{}", p.describe());
    }

    #[test]
    fn a_tilde_path_is_refused_with_the_reason() {
        let dir = tmp();
        let p = policy(dir.path());
        // No shell is involved, so `~` would otherwise fail as "no such file"
        // for a path that looks obviously fine.
        let err = p
            .check("~/.isopod/credentials.json", Access::Read)
            .unwrap_err();
        assert!(err.contains("does not expand"), "{err}");
    }

    #[test]
    fn a_root_of_slash_is_reported_as_unconfined_not_as_a_root() {
        // Reached two ways: the explicit `ISOPOD_MCP_HOST_IO_ROOT=/`, and a server
        // whose working directory happens to be `/`. Both accept every host path,
        // so both have to say so in the startup log — "confined to /" would read as
        // a confinement that is not there.
        //
        // Env vars are process-global, so this test sets and clears its own rather
        // than running in parallel with a reader of the same variable.
        let restore = std::env::var_os("ISOPOD_MCP_HOST_IO_ROOT");
        for spelling in ["/", "//", "/."] {
            std::env::set_var("ISOPOD_MCP_HOST_IO_ROOT", spelling);
            let root = HostIo::root_from_env();
            assert_eq!(root, None, "root {spelling:?} must read as unconfined");
        }
        match restore {
            Some(v) => std::env::set_var("ISOPOD_MCP_HOST_IO_ROOT", v),
            None => std::env::remove_var("ISOPOD_MCP_HOST_IO_ROOT"),
        }
    }

    #[test]
    fn describe_names_the_root_for_the_startup_log() {
        let dir = tmp();
        let p = policy(dir.path());
        let d = p.describe();
        assert!(d.contains("confined to"), "{d}");
        assert!(d.contains("stdin_file=on"), "{d}");
        assert!(d.contains("copy_out=on"), "{d}");
    }
}
