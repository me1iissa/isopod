//! `isopod dev build-fc` — build the vendored Firecracker (pinned at the
//! `v1.16.1` tag under `vendor/firecracker`) with the host toolchain.
//!
//! The vendored tree carries its own Cargo workspace and a `rust-toolchain.toml`
//! pin; rustup auto-installs whatever it declares. A GNU-target `--release`
//! build of the `firecracker` and `snapshot-editor` binaries is sufficient for
//! dev use (upstream's musl-static build is only needed for jailer chroots),
//! and the results are copied into `~/.isopod/bin/`.
//!
//! Per PLAN.md, a failed vendored build is *reportable, not blocking*: the M0
//! release binaries under `~/.isopod/m0/bin` remain the fallback. So build
//! failures for environment reasons are captured into a `{ok:false, error,
//! findings}` outcome rather than propagated as a hard error, and the build is
//! bounded by [`BUILD_TIMEOUT`].

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;

use crate::paths;

/// Wall-clock ceiling for the vendored build. If the compile runs longer than
/// this it is killed and reported as an environment failure (the M0 binaries
/// remain usable), rather than letting the command hang indefinitely.
const BUILD_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Paths of the freshly built binaries after they are copied into `~/.isopod/bin`.
#[derive(Debug, Clone, Serialize)]
pub struct BinPaths {
    /// The `firecracker` VMM binary.
    pub firecracker: PathBuf,
    /// The `snapshot-editor` tool.
    pub snapshot_editor: PathBuf,
}

/// Outcome of [`build_fc`], serialized verbatim as the CLI's stdout JSON.
///
/// On success `ok` is `true` and the build fields are populated. On an
/// environment failure `ok` is `false` and `error`/`findings` explain why (the
/// build metadata `fc_git_describe`/`build_hash` are still filled in when they
/// could be read).
#[derive(Debug, Clone, Serialize)]
pub struct BuildFcOutcome {
    /// Whether the build succeeded and binaries were installed.
    pub ok: bool,
    /// Installed binary paths (present only on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin_paths: Option<BinPaths>,
    /// `git describe --tags` of the vendored submodule (e.g. `v1.16.1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fc_git_describe: Option<String>,
    /// Submodule HEAD sha, suffixed `-dirty` when the worktree has changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_hash: Option<String>,
    /// Wall-clock seconds the build (or failed attempt) took.
    pub took_s: f64,
    /// Human-readable failure summary (present only on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Detailed findings for the coordinator (present only on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<String>,
}

/// Build the vendored Firecracker and install `firecracker` + `snapshot-editor`
/// into `~/.isopod/bin`.
///
/// Returns `Ok(outcome)` in both the success and the environment-failure case
/// (inspect [`BuildFcOutcome::ok`]); only genuinely unexpected host errors
/// (missing submodule, unreadable `~/.isopod`) surface as `Err`.
///
/// # Errors
/// Returns an error if the vendored submodule is absent or `git`/filesystem
/// metadata for the submodule cannot be read.
pub fn build_fc() -> Result<BuildFcOutcome> {
    let dir = vendored_dir()?;
    if !dir.join("Cargo.toml").exists() {
        bail!(
            "vendored firecracker not found at {} (is the `vendor/firecracker` submodule checked out?)",
            dir.display()
        );
    }

    let describe = run_git(&dir, &["describe", "--tags"]);
    let build_hash = git_build_hash(&dir)?;

    let start = Instant::now();
    let run = run_build(&dir)?;
    let took_s = start.elapsed().as_secs_f64();

    match run {
        BuildRun::Success { target_dir } => {
            let bin_dir = paths::isopod_home()?.join("bin");
            std::fs::create_dir_all(&bin_dir)
                .with_context(|| format!("creating {}", bin_dir.display()))?;

            let fc_dst = bin_dir.join("firecracker");
            let se_dst = bin_dir.join("snapshot-editor");
            install_binary(&find_binary(&target_dir, "firecracker")?, &fc_dst)?;
            install_binary(&find_binary(&target_dir, "snapshot-editor")?, &se_dst)?;

            Ok(BuildFcOutcome {
                ok: true,
                bin_paths: Some(BinPaths {
                    firecracker: fc_dst,
                    snapshot_editor: se_dst,
                }),
                fc_git_describe: describe,
                build_hash: Some(build_hash),
                took_s,
                error: None,
                findings: None,
            })
        }
        BuildRun::Failure { error, findings } => Ok(BuildFcOutcome {
            ok: false,
            bin_paths: None,
            fc_git_describe: describe,
            build_hash: Some(build_hash),
            took_s,
            error: Some(error),
            findings: Some(findings),
        }),
    }
}

/// Locate `vendor/firecracker` relative to this crate (resolved from
/// `CARGO_MANIFEST_DIR` so it works regardless of the process's cwd).
fn vendored_dir() -> Result<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")); // crates/core
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("cannot locate workspace root from {}", manifest.display()))?;
    Ok(root.join("vendor/firecracker"))
}

/// The result of a build attempt.
enum BuildRun {
    /// Build succeeded; binaries live under `target_dir`.
    Success {
        /// Cargo target directory the vendored build wrote to.
        target_dir: PathBuf,
    },
    /// Build failed (or timed out) for an environment reason.
    Failure {
        /// One-line error summary.
        error: String,
        /// Detailed findings (log tail, toolchain notes).
        findings: String,
    },
}

/// Invoke `cargo build --release -p firecracker -p snapshot-editor` in the
/// vendored tree, bounded by [`BUILD_TIMEOUT`]. Cargo's output is captured to a
/// log file (kept for inspection); our own stdout stays clean for the JSON line.
fn run_build(dir: &Path) -> Result<BuildRun> {
    let build_root = dir.join("build");
    std::fs::create_dir_all(&build_root).ok();
    let log_path = build_root.join("build-fc.log");
    let log = std::fs::File::create(&log_path)
        .with_context(|| format!("creating build log {}", log_path.display()))?;
    let log_err = log.try_clone().context("duplicating build-log fd")?;

    eprintln!(
        "build-fc: building vendored firecracker (toolchain per {}/rust-toolchain.toml); \
         output -> {}",
        dir.display(),
        log_path.display()
    );

    let mut cmd = Command::new("cargo");
    cmd.current_dir(dir)
        .arg("build")
        .arg("--release")
        .args(["-p", "firecracker", "-p", "snapshot-editor"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));

    // Firecracker's in-tree seccompiler links the system libseccomp
    // (`cargo::rustc-link-lib=seccomp`). Hosts with only the runtime package
    // lack the unversioned `libseccomp.so` linker symlink; supply a private one.
    if let Some(link_dir) = seccomp_link_dir() {
        eprintln!(
            "build-fc: `libseccomp.so` linker symlink absent; adding private {} to LIBRARY_PATH \
             (install `libseccomp-dev` to avoid this)",
            link_dir.display()
        );
        let mut value = OsString::from(&link_dir);
        if let Some(existing) = std::env::var_os("LIBRARY_PATH") {
            value.push(":");
            value.push(existing);
        }
        cmd.env("LIBRARY_PATH", value);
    }

    let mut child = cmd
        .spawn()
        .context("spawning cargo (is cargo/rustup on PATH?)")?;

    let deadline = Instant::now() + BUILD_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("polling cargo build")? {
            if status.success() {
                return Ok(BuildRun::Success {
                    // .cargo/config.toml pins target-dir = build/cargo_target.
                    target_dir: dir.join("build/cargo_target"),
                });
            }
            return Ok(BuildRun::Failure {
                error: format!("cargo build failed with status {status}"),
                findings: failure_findings(&log_path, dir),
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(BuildRun::Failure {
                error: format!(
                    "vendored build exceeded the {}-minute cap and was killed",
                    BUILD_TIMEOUT.as_secs() / 60
                ),
                findings: format!(
                    "The vendored firecracker build did not finish within {} minutes and was \
                     terminated. The M0 release binaries under ~/.isopod/m0/bin remain the \
                     fallback. Build log: {}",
                    BUILD_TIMEOUT.as_secs() / 60,
                    log_path.display()
                ),
            });
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Compose a detailed failure report from the tail of the captured build log.
fn failure_findings(log_path: &Path, dir: &Path) -> String {
    let tail = std::fs::read_to_string(log_path)
        .ok()
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(40);
            lines[start..].join("\n")
        })
        .unwrap_or_else(|| "<no build log captured>".to_string());
    format!(
        "Vendored firecracker build failed. The toolchain is pinned by \
         {dir}/rust-toolchain.toml (rustup auto-installs it). Firecracker links the system \
         libseccomp at build time, so `libseccomp-dev` (or the runtime `libseccomp2` plus a \
         `libseccomp.so` linker symlink) must be present. The M0 release binaries under \
         ~/.isopod/m0/bin remain the fallback. Full log: {log}. Last lines:\n{tail}",
        dir = dir.display(),
        log = log_path.display(),
    )
}

/// If the unversioned `libseccomp.so` linker name is not resolvable in the
/// standard library directories but a versioned runtime lib is, materialise a
/// private `~/.isopod/linklibs/libseccomp.so` symlink and return its directory
/// to prepend to `LIBRARY_PATH`. Returns `None` when no workaround is needed or
/// possible.
fn seccomp_link_dir() -> Option<PathBuf> {
    const LINKER_NAME: &str = "libseccomp.so";
    const SEARCH: [&str; 4] = [
        "/usr/lib/x86_64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/usr/lib",
        "/usr/local/lib",
    ];

    // Nothing to do if the dev symlink already exists somewhere standard.
    if SEARCH
        .iter()
        .any(|d| Path::new(d).join(LINKER_NAME).exists())
    {
        return None;
    }

    // Find a versioned runtime lib (`libseccomp.so.2`, `libseccomp.so.2.5.5`, …).
    let runtime = SEARCH.iter().find_map(|d| {
        std::fs::read_dir(d).ok()?.flatten().find_map(|e| {
            let name = e.file_name();
            name.to_string_lossy()
                .starts_with("libseccomp.so.")
                .then(|| e.path())
        })
    })?;

    let link_dir = paths::isopod_home().ok()?.join("linklibs");
    std::fs::create_dir_all(&link_dir).ok()?;
    let link = link_dir.join(LINKER_NAME);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&runtime, &link).ok()?;
    Some(link_dir)
}

/// Find a built binary named `name` under `target_dir`, checking the direct
/// `release/` dir first and any `<triple>/release/` dir second.
fn find_binary(target_dir: &Path, name: &str) -> Result<PathBuf> {
    let direct = target_dir.join("release").join(name);
    if direct.exists() {
        return Ok(direct);
    }
    if let Ok(entries) = std::fs::read_dir(target_dir) {
        for e in entries.flatten() {
            let cand = e.path().join("release").join(name);
            if cand.exists() {
                return Ok(cand);
            }
        }
    }
    bail!(
        "built binary `{name}` not found under {}",
        target_dir.display()
    )
}

/// Copy `src` to `dst` and mark it executable (`0755`).
fn install_binary(src: &Path, dst: &Path) -> Result<()> {
    std::fs::copy(src, dst)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", dst.display()))?;
    Ok(())
}

/// The build hash: submodule HEAD sha, suffixed `-dirty` if the worktree is not
/// clean. Used as a snapshot-cache compatibility domain (PLAN.md).
fn git_build_hash(dir: &Path) -> Result<String> {
    let head = run_git(dir, &["rev-parse", "HEAD"])
        .ok_or_else(|| anyhow!("`git rev-parse HEAD` failed in {}", dir.display()))?;
    let dirty = run_git(dir, &["status", "--porcelain"])
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    Ok(if dirty { format!("{head}-dirty") } else { head })
}

/// Run a `git` subcommand in `dir`, returning trimmed stdout on success.
fn run_git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
