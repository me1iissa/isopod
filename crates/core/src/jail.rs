//! Rootless microjail (F2) — the host-side half.
//!
//! When the runtime flag `ISOPOD_JAIL=1` is set, every Firecracker spawn is
//! wrapped in the [`isopod-jail`](../../jail) launcher via the existing
//! `command_prefix` seam. The launcher gives the VMM a second isolation layer
//! with **no privileged host component**: a per-VM delegated cgroup (cpu /
//! memory / pids caps — this also closes F4), a single-id user + pid namespace
//! (a VMM/KVM escape lands as an unprivileged, unmapped id on the host), and a
//! `pivot_root` chroot built from identity bind mounts.
//!
//! # Identity path mapping
//! Every path Firecracker touches (its binary, the guest kernel, the base
//! squashfs, committed layer images, the per-VM scratch, `--api-sock`, the vsock
//! uds, `--log-path`, and snapshot `vmstate`/`memfile`) lives under the real host
//! filesystem — almost all under `~/.isopod`. The launcher bind-mounts each into
//! the chroot **at its identical absolute path**, so Firecracker's argv and every
//! API payload are byte-for-byte the same whether jailed or not, and no path
//! rewriting is needed anywhere. Because a bind mount shares the underlying inode,
//! the `api.sock` / `vsock.sock` that Firecracker creates inside the chroot at
//! `<vm_dir>/…` are the *same inode* `isopod-core` reaches at the real host path —
//! so socket connect and reaping work unchanged.
//!
//! # Flag semantics
//! [`is_enabled`] gates everything. When it is `false` no code here runs, no
//! jail process is spawned, no cgroup is created, and the Firecracker argv is
//! byte-identical to the historical path — the runtime flag (not a Cargo feature)
//! makes that trivially provable by the skipped call sites.
//!
//! Relevant public specs: `cgroups(7)`, `user_namespaces(7)`, `capabilities(7)`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::paths;
use crate::vm::Resources;

/// Runtime flag that turns the jail on (`ISOPOD_JAIL=1`). Off by default.
const ENABLE_VAR: &str = "ISOPOD_JAIL";
/// Optional override for the `isopod-jail` binary path.
const JAIL_BIN_VAR: &str = "ISOPOD_JAIL_BIN";
/// Optional override (MiB) for the guest-memory cgroup overhead added on top of
/// the guest RAM when computing `memory.max`.
const MEM_OVERHEAD_VAR: &str = "ISOPOD_JAIL_MEM_OVERHEAD_MIB";

/// The cgroup v2 unified-hierarchy mount point.
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
/// The single slice all per-VM cgroups sit under.
const ISOPOD_SLICE: &str = "isopod.slice";
/// The cgroup cpu bandwidth period (µs); `cpu.max` is `<quota> <period>`.
const CPU_PERIOD_US: u64 = 100_000;
/// `pids.max` for a jailed VM: Firecracker plus its vcpu/vmm/api threads and the
/// jail supervisor come to ~20 in practice; 128 is generous headroom.
const PIDS_MAX: u32 = 128;

/// Whether the jail is enabled for this process (`ISOPOD_JAIL=1`).
#[must_use]
pub fn is_enabled() -> bool {
    std::env::var(ENABLE_VAR).as_deref() == Ok("1")
}

/// One identity bind mount for the chroot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    path: PathBuf,
    writable: bool,
}

impl Bind {
    /// A read-only bind of `path`.
    pub fn ro(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writable: false,
        }
    }

    /// A read-write bind of `path`.
    pub fn rw(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writable: true,
        }
    }

    /// The `--bind` argument the launcher expects: `<path>:ro` or `<path>:rw`.
    fn arg(&self) -> String {
        format!(
            "{}:{}",
            self.path.display(),
            if self.writable { "rw" } else { "ro" }
        )
    }
}

/// A prepared jail: the `command_prefix` to prepend to the Firecracker argv, plus
/// the created cgroup leaf and chroot dir (for teardown).
#[derive(Debug, Clone)]
pub struct JailSpec {
    /// The exec-prefix (`[jail_bin, --cgroup, …, --root, …, --, ]`) prepended to
    /// the Firecracker argv.
    pub prefix: Vec<String>,
    /// The per-VM leaf cgroup Firecracker is placed in (removed at teardown).
    pub cgroup_leaf: PathBuf,
    /// The chroot directory (`<vm_dir>/jail-root`).
    pub root: PathBuf,
}

/// The standard chroot binds for a run/resume: the whole isopod home read-only
/// (covers the FC binary if under it, the kernel, base squashfs, committed
/// layers, and snapshots), and the VM directory read-write (its `api.sock`,
/// `vsock.sock`, scratch, and logs), nested over the read-only home bind. An
/// `$ISOPOD_FC_BIN` outside the home is bound read-only as a file (Firecracker
/// release binaries are statically linked, so the file alone suffices).
///
/// # Errors
/// If the isopod home cannot be resolved.
pub fn standard_binds(vm_dir: &Path, fc_path: &Path) -> Result<Vec<Bind>> {
    let mut binds = binds_for(&paths::isopod_home()?, vm_dir, fc_path);
    // A dynamically-linked Firecracker needs its ELF interpreter + shared objects
    // present in the chroot; bind each at its identical path read-only. Empty for
    // a static binary, so this is a no-op there (and future-proof for a musl FC).
    for lib in fc_runtime_libs(fc_path) {
        binds.push(Bind::ro(lib));
    }
    Ok(binds)
}

/// Pure inner of [`standard_binds`] (home injected) so it is unit-testable.
fn binds_for(home: &Path, vm_dir: &Path, fc_path: &Path) -> Vec<Bind> {
    let mut binds = vec![Bind::ro(home), Bind::rw(vm_dir)];
    if !fc_path.starts_with(home) {
        binds.push(Bind::ro(fc_path));
    }
    binds
}

/// The ELF interpreter + shared objects `fc_path` loads at runtime, resolved via
/// `ldd` and returned as absolute host paths (deduped, existing). Empty for a
/// static binary or if `ldd` is unavailable — the jail then fails loudly at
/// `exec` with a clear ENOENT, which is a legible signal, not a silent bypass.
fn fc_runtime_libs(fc_path: &Path) -> Vec<PathBuf> {
    let out = match std::process::Command::new("ldd").arg(fc_path).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    parse_ldd(&String::from_utf8_lossy(&out))
        .into_iter()
        .filter(|p| p.exists())
        .collect()
}

/// Parse absolute library paths out of `ldd` output. Handles both the
/// `libc.so.6 => /path/libc.so.6 (0x…)` form and the bare interpreter line
/// `/lib64/ld-linux-x86-64.so.2 (0x…)`. `linux-vdso.so.1` (no path) is skipped.
fn parse_ldd(text: &str) -> Vec<PathBuf> {
    let mut libs: Vec<PathBuf> = Vec::new();
    for line in text.lines() {
        let candidate = match line.split_once("=>") {
            Some((_, rhs)) => rhs.split_whitespace().next(),
            None => line.split_whitespace().next(),
        };
        if let Some(c) = candidate {
            if c.starts_with('/') {
                let p = PathBuf::from(c);
                if !libs.contains(&p) {
                    libs.push(p);
                }
            }
        }
    }
    libs
}

/// The standard device nodes to expose in the chroot: `/dev/kvm` (the VMM),
/// `/dev/null`, `/dev/urandom`, and — for networked runs — `/dev/net/tun`.
#[must_use]
pub fn standard_devs(network: bool) -> Vec<PathBuf> {
    let mut devs = vec![
        PathBuf::from("/dev/kvm"),
        PathBuf::from("/dev/null"),
        PathBuf::from("/dev/urandom"),
    ];
    if network {
        devs.push(PathBuf::from("/dev/net/tun"));
    }
    devs
}

/// Validate that the jail can run: unprivileged user namespaces are available, a
/// delegated cgroup v2 root with the cpu/memory/pids controllers is reachable
/// *and contains this process*, the `isopod-jail` helper is present, and
/// `/dev/kvm` is openable. Names the fix on any failure.
///
/// `ISOPOD_JAIL=1` is an explicit hardening opt-in, so a failure here is a hard
/// error (the caller must not silently fall back to running unjailed).
///
/// # Errors
/// If any precondition is unmet.
pub fn preflight() -> Result<()> {
    check_userns()?;
    check_cgroup_delegation()?;
    resolve_jail_bin().context("locating the isopod-jail helper binary")?;
    check_kvm()?;
    Ok(())
}

/// Create this run's per-VM cgroup (with limits) and chroot dir, resolve the
/// launcher, and assemble the `command_prefix`.
///
/// The caller runs [`preflight`] once earlier; `setup` still surfaces a clear
/// error if a step fails.
///
/// # Errors
/// If the uid/gid cannot be read, the cgroup cannot be created or limited, the
/// chroot dir cannot be created, or the launcher cannot be resolved.
pub fn setup(
    vm_dir: &Path,
    resources: Resources,
    binds: &[Bind],
    devs: &[PathBuf],
) -> Result<JailSpec> {
    let (uid, gid) = real_uid_gid()?;
    let vm_id = vm_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| anyhow!("vm_dir {} has no final component", vm_dir.display()))?;

    let root = vm_dir.join("jail-root");
    std::fs::create_dir_all(&root)
        .with_context(|| format!("creating chroot dir {}", root.display()))?;

    let cgroup_leaf = create_cgroup(&vm_id, resources)?;
    let jail_bin = resolve_jail_bin()?;

    let mut prefix = vec![
        jail_bin.to_string_lossy().into_owned(),
        "--cgroup".to_string(),
        cgroup_leaf.to_string_lossy().into_owned(),
        "--root".to_string(),
        root.to_string_lossy().into_owned(),
        "--uid".to_string(),
        uid.to_string(),
        "--gid".to_string(),
        gid.to_string(),
    ];
    for b in binds {
        prefix.push("--bind".to_string());
        prefix.push(b.arg());
    }
    for d in devs {
        prefix.push("--dev".to_string());
        prefix.push(d.to_string_lossy().into_owned());
    }
    prefix.push("--".to_string());

    Ok(JailSpec {
        prefix,
        cgroup_leaf,
        root,
    })
}

/// Best-effort teardown: remove the leaf cgroup, then prune an emptied
/// `isopod.slice`. The chroot skeleton (empty mountpoint dirs/files) is removed
/// with the VM directory by the normal vm gc / `--keep` handling; the chroot's
/// bind mounts live in the child's private mount namespace and vanish when it
/// exits, so there is no host mount-table leak to clean up.
pub fn teardown(spec: &JailSpec) {
    // rmdir succeeds only once the cgroup has no member processes (Firecracker is
    // already reaped by the caller's teardown); a lingering leaf is harmless and
    // is swept on the next run.
    let _ = std::fs::remove_dir(&spec.cgroup_leaf);
    if let Some(slice) = spec.cgroup_leaf.parent() {
        let _ = std::fs::remove_dir(slice); // only when no other leaves remain
    }
}

/// Remove empty leftover `isopod.slice/*` leaf cgroups (crash recovery), mirroring
/// [`crate::net::sweep_stale`]. Best-effort; a live VM's leaf stays (`EBUSY`).
pub fn sweep_stale_cgroups() {
    // Only reap leaves older than this. A leaf is created (empty) in `setup` and
    // joined by the jail supervisor only once Firecracker has forked, so a
    // concurrent run's just-created leaf must never be swept mid-window — that
    // would make its cgroup join fail (ENOENT). Normal cleanup is immediate via
    // `teardown`; this sweep only reclaims crash-orphaned leaves, which are old.
    // cgroup v2 leaf dirs carry a stable create-time mtime, so age is reliable.
    const MIN_AGE: Duration = Duration::from_secs(60);
    let Ok(deleg) = delegated_cgroup_root() else {
        return;
    };
    let slice = deleg.join(ISOPOD_SLICE);
    if let Ok(entries) = std::fs::read_dir(&slice) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // Unknown age -> skip (conservative; never risk the create/join race).
            let young = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_none_or(|age| age < MIN_AGE);
            if young {
                continue;
            }
            // A live VM's leaf still has member procs -> remove_dir EBUSY, harmless.
            let _ = std::fs::remove_dir(path);
        }
    }
    // Prune the slice itself once its last leaf is gone (ENOTEMPTY otherwise).
    let _ = std::fs::remove_dir(&slice);
}

// ===========================================================================
// cgroup v2 placement.
// ===========================================================================

/// Create `isopod.slice/<vm_id>` under the delegated root, enable the cpu/memory/
/// pids controllers, set the per-VM limits, and return the leaf path.
fn create_cgroup(vm_id: &str, resources: Resources) -> Result<PathBuf> {
    let deleg = delegated_cgroup_root()?;
    let slice = deleg.join(ISOPOD_SLICE);
    std::fs::create_dir_all(&slice).with_context(|| format!("creating {}", slice.display()))?;
    // Enable controllers for the slice's children (idempotent if already set).
    // The slice holds no processes, so this is legal under the cgroup-v2
    // "no internal processes" rule.
    std::fs::write(slice.join("cgroup.subtree_control"), "+cpu +memory +pids").with_context(
        || {
            format!(
                "enabling cpu/memory/pids controllers on {}",
                slice.join("cgroup.subtree_control").display()
            )
        },
    )?;

    let leaf = slice.join(vm_id);
    std::fs::create_dir_all(&leaf)
        .with_context(|| format!("creating leaf cgroup {}", leaf.display()))?;

    // memory.max: guest RAM + VMM overhead. A runaway guest hits its own cap and
    // is cgroup-OOM-killed (only Firecracker dies; the host is unaffected) — F4.
    std::fs::write(
        leaf.join("memory.max"),
        mem_max_bytes(resources).to_string(),
    )
    .with_context(|| format!("setting memory.max on {}", leaf.display()))?;
    // cpu.max: `<vcpus * period> <period>` — a busy guest cannot starve the host.
    std::fs::write(leaf.join("cpu.max"), cpu_max_value(resources))
        .with_context(|| format!("setting cpu.max on {}", leaf.display()))?;
    // pids.max: a fork bomb inside the VMM process tree cannot exhaust host pids.
    std::fs::write(leaf.join("pids.max"), PIDS_MAX.to_string())
        .with_context(|| format!("setting pids.max on {}", leaf.display()))?;

    Ok(leaf)
}

/// Resolve the delegated cgroup v2 root (the boundary systemd delegates to the
/// user session, `user@<uid>.service`).
///
/// Primary: walk our own `/proc/self/cgroup` path up through the
/// `user@<uid>.service` component. Fallback: the conventional
/// `user.slice/user-<uid>.slice/user@<uid>.service` path (used when the process
/// runs outside the session's own subtree but the delegation still exists).
fn delegated_cgroup_root() -> Result<PathBuf> {
    let (uid, _gid) = real_uid_gid()?;
    if let Ok(raw) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(rel) = parse_cgroup_v2_path(&raw) {
            if let Some(deleg_rel) = truncate_through_user_service(rel) {
                let p = cgroup_mount().join(deleg_rel.trim_start_matches('/'));
                if p.is_dir() {
                    return Ok(p);
                }
            }
        }
    }
    let conv = cgroup_mount()
        .join("user.slice")
        .join(format!("user-{uid}.slice"))
        .join(format!("user@{uid}.service"));
    if conv.is_dir() {
        return Ok(conv);
    }
    bail!(
        "no delegated cgroup v2 root found (expected a systemd user session at {}); \
         cgroup limits require running inside `user@{uid}.service`",
        conv.display()
    )
}

fn cgroup_mount() -> PathBuf {
    PathBuf::from(CGROUP_MOUNT)
}

/// Extract the cgroup v2 unified path from `/proc/<pid>/cgroup` (the single
/// `0::<path>` line).
fn parse_cgroup_v2_path(raw: &str) -> Option<&str> {
    raw.lines()
        .find_map(|line| line.strip_prefix("0::").map(str::trim))
}

/// Truncate a cgroup path through (and including) the `user@<uid>.service`
/// component — the systemd delegation boundary. `None` if there is no such
/// component (e.g. a non-session `/init.scope`).
fn truncate_through_user_service(rel: &str) -> Option<String> {
    let mut kept: Vec<&str> = Vec::new();
    for comp in rel.split('/').filter(|c| !c.is_empty()) {
        kept.push(comp);
        if is_user_service(comp) {
            return Some(format!("/{}", kept.join("/")));
        }
    }
    None
}

/// Whether `comp` is a `user@<digits>.service` cgroup component.
fn is_user_service(comp: &str) -> bool {
    comp.strip_prefix("user@")
        .and_then(|r| r.strip_suffix(".service"))
        .map(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

/// The current process's absolute cgroup v2 path.
fn current_cgroup_abs() -> Result<PathBuf> {
    let raw = std::fs::read_to_string("/proc/self/cgroup").context("reading /proc/self/cgroup")?;
    let rel = parse_cgroup_v2_path(&raw)
        .ok_or_else(|| anyhow!("no cgroup v2 (0::) line in /proc/self/cgroup"))?;
    Ok(cgroup_mount().join(rel.trim_start_matches('/')))
}

// ===========================================================================
// Preflight checks.
// ===========================================================================

fn check_userns() -> Result<()> {
    match std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        Some(0) => bail!(
            "unprivileged user namespaces are disabled \
             (/proc/sys/user/max_user_namespaces = 0)"
        ),
        None => bail!(
            "cannot read /proc/sys/user/max_user_namespaces; \
             unprivileged user namespaces may be unavailable"
        ),
        Some(_) => {}
    }
    // Debian/Ubuntu opt-out knob (absent on most kernels).
    if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if s.trim() == "0" {
            bail!(
                "unprivileged user namespaces are disabled \
                 (kernel.unprivileged_userns_clone = 0); \
                 enable with `sysctl kernel.unprivileged_userns_clone=1`"
            );
        }
    }
    Ok(())
}

fn check_cgroup_delegation() -> Result<()> {
    let deleg = delegated_cgroup_root().context("resolving the delegated cgroup v2 root")?;
    let controllers_path = deleg.join("cgroup.controllers");
    let controllers = std::fs::read_to_string(&controllers_path)
        .with_context(|| format!("reading {}", controllers_path.display()))?;
    for c in ["cpu", "memory", "pids"] {
        if !controllers.split_whitespace().any(|x| x == c) {
            bail!(
                "delegated cgroup {} is missing the `{c}` controller (has: {})",
                deleg.display(),
                controllers.trim()
            );
        }
    }
    // The process must sit inside the delegated subtree, or moving Firecracker
    // into a leaf under it is denied by cgroup delegation containment (the
    // nearest-common-ancestor rule).
    let current = current_cgroup_abs()?;
    if !current.starts_with(&deleg) {
        bail!(
            "isopod must run inside your systemd user session for cgroup delegation: \
             current cgroup {} is outside the delegated root {} \
             (start isopod from a normal login shell)",
            current.display(),
            deleg.display()
        );
    }
    Ok(())
}

fn check_kvm() -> Result<()> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map(|_| ())
        .context("opening /dev/kvm read-write (is the runtime user in the `kvm` group?)")
}

// ===========================================================================
// Small pure helpers (unit-tested).
// ===========================================================================

/// Read the real uid/gid from `/proc/self/status`.
fn real_uid_gid() -> Result<(u32, u32)> {
    let status =
        std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
    let uid = parse_status_id(&status, "Uid:")
        .ok_or_else(|| anyhow!("no parseable Uid line in /proc/self/status"))?;
    let gid = parse_status_id(&status, "Gid:")
        .ok_or_else(|| anyhow!("no parseable Gid line in /proc/self/status"))?;
    Ok((uid, gid))
}

/// Parse the first (real) id from a `Uid:`/`Gid:` line of `/proc/self/status`.
fn parse_status_id(status: &str, prefix: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix(prefix)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|first| first.parse().ok())
    })
}

/// The guest-memory cgroup overhead (MiB): `$ISOPOD_JAIL_MEM_OVERHEAD_MIB` when
/// set, else [`default_overhead_mib`].
fn mem_overhead_mib(mem_mib: u32) -> u64 {
    if let Ok(v) = std::env::var(MEM_OVERHEAD_VAR) {
        if let Ok(n) = v.trim().parse::<u64>() {
            return n;
        }
    }
    default_overhead_mib(mem_mib)
}

/// Default VMM overhead (MiB) added to the guest RAM for `memory.max`:
/// `max(256, mem_mib / 4)`.
fn default_overhead_mib(mem_mib: u32) -> u64 {
    std::cmp::max(256, u64::from(mem_mib) / 4)
}

/// `memory.max` value in bytes: guest RAM plus [`mem_overhead_mib`].
fn mem_max_bytes(resources: Resources) -> u64 {
    let total_mib = u64::from(resources.mem_mib) + mem_overhead_mib(resources.mem_mib);
    total_mib * 1024 * 1024
}

/// `cpu.max` value: `<vcpus * period> <period>` (full CPUs).
fn cpu_max_value(resources: Resources) -> String {
    format!(
        "{} {}",
        u64::from(resources.vcpus) * CPU_PERIOD_US,
        CPU_PERIOD_US
    )
}

/// Resolve the `isopod-jail` binary: `$ISOPOD_JAIL_BIN`, then a sibling of the
/// current executable, then `~/.isopod/bin/isopod-jail`.
fn resolve_jail_bin() -> Result<PathBuf> {
    let env = std::env::var_os(JAIL_BIN_VAR)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("isopod-jail")));
    let home_bin = paths::isopod_home()?.join("bin/isopod-jail");
    resolve_jail_bin_from(env, sibling, home_bin, &|p| p.exists())
}

/// Pure resolution of the launcher path (precedence + existence injected) so it
/// is unit-testable without the filesystem or environment.
fn resolve_jail_bin_from(
    env: Option<PathBuf>,
    sibling: Option<PathBuf>,
    home_bin: PathBuf,
    exists: &dyn Fn(&Path) -> bool,
) -> Result<PathBuf> {
    if let Some(path) = env {
        if exists(&path) {
            return Ok(path);
        }
        bail!(
            "$ISOPOD_JAIL_BIN points at {} but no file exists there",
            path.display()
        );
    }
    if let Some(s) = sibling {
        if exists(&s) {
            return Ok(s);
        }
    }
    if exists(&home_bin) {
        return Ok(home_bin);
    }
    bail!(
        "no isopod-jail binary found: set $ISOPOD_JAIL_BIN, install it beside the \
         isopod binary, or provide {}",
        home_bin.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(vcpus: u32, mem_mib: u32) -> Resources {
        // Resources has public fields; construct directly for the pure tests.
        Resources { vcpus, mem_mib }
    }

    #[test]
    fn parse_cgroup_v2_path_reads_unified_line() {
        assert_eq!(
            parse_cgroup_v2_path("0::/user.slice/user-1000.slice/user@1000.service/app.slice"),
            Some("/user.slice/user-1000.slice/user@1000.service/app.slice")
        );
        // Legacy v1 lines (numbered) are ignored; only 0:: counts.
        assert_eq!(
            parse_cgroup_v2_path("1:name=systemd:/foo\n0::/bar\n"),
            Some("/bar")
        );
        assert_eq!(parse_cgroup_v2_path("2:cpu:/only-v1"), None);
    }

    #[test]
    fn is_user_service_matches_only_the_delegation_unit() {
        assert!(is_user_service("user@1000.service"));
        assert!(is_user_service("user@0.service"));
        assert!(!is_user_service("user.slice"));
        assert!(!is_user_service("user@abc.service"));
        assert!(!is_user_service("user@1000.scope"));
        assert!(!is_user_service("app.slice"));
    }

    #[test]
    fn truncate_through_user_service_finds_delegation_boundary() {
        assert_eq!(
            truncate_through_user_service(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/isopod.service"
            ),
            Some("/user.slice/user-1000.slice/user@1000.service".to_string())
        );
        // No delegation unit present (e.g. WSL2 init context).
        assert_eq!(truncate_through_user_service("/init.scope"), None);
        assert_eq!(
            truncate_through_user_service("/system.slice/foo.service"),
            None
        );
    }

    #[test]
    fn parse_status_id_reads_the_real_id() {
        let status = "Name:\tbash\nUid:\t1000\t1000\t1000\t1000\nGid:\t1007\t1007\t1007\t1007\n";
        assert_eq!(parse_status_id(status, "Uid:"), Some(1000));
        assert_eq!(parse_status_id(status, "Gid:"), Some(1007));
        assert_eq!(parse_status_id(status, "Absent:"), None);
    }

    #[test]
    fn default_overhead_is_floor_256_then_quarter() {
        assert_eq!(
            default_overhead_mib(256),
            256,
            "floor binds for small guests"
        );
        assert_eq!(default_overhead_mib(512), 256, "512/4=128 < 256 floor");
        assert_eq!(default_overhead_mib(2048), 512, "2048/4 = 512");
        assert_eq!(default_overhead_mib(4096), 1024, "4096/4 = 1024");
    }

    #[test]
    fn mem_max_is_guest_plus_overhead_in_bytes() {
        // 512 MiB guest + 256 MiB overhead = 768 MiB.
        assert_eq!(mem_max_bytes(res(1, 512)), 768 * 1024 * 1024);
        // 2048 MiB guest + 512 MiB overhead = 2560 MiB.
        assert_eq!(mem_max_bytes(res(2, 2048)), 2560 * 1024 * 1024);
    }

    #[test]
    fn cpu_max_is_full_cpus() {
        assert_eq!(cpu_max_value(res(1, 512)), "100000 100000");
        assert_eq!(cpu_max_value(res(2, 512)), "200000 100000");
        assert_eq!(cpu_max_value(res(4, 512)), "400000 100000");
    }

    #[test]
    fn bind_arg_encodes_mode() {
        assert_eq!(Bind::ro("/home/u/.isopod").arg(), "/home/u/.isopod:ro");
        assert_eq!(
            Bind::rw("/home/u/.isopod/vms/dev-1").arg(),
            "/home/u/.isopod/vms/dev-1:rw"
        );
    }

    #[test]
    fn binds_cover_home_and_vm_dir_and_external_fc() {
        let home = Path::new("/home/u/.isopod");
        let vm_dir = Path::new("/home/u/.isopod/vms/dev-1");

        // FC under home -> just home ro + vm_dir rw.
        let fc_in = Path::new("/home/u/.isopod/bin/firecracker");
        assert_eq!(
            binds_for(home, vm_dir, fc_in),
            vec![Bind::ro(home), Bind::rw(vm_dir)]
        );

        // FC outside home -> add a read-only bind of the binary.
        let fc_out = Path::new("/opt/fc/firecracker");
        assert_eq!(
            binds_for(home, vm_dir, fc_out),
            vec![Bind::ro(home), Bind::rw(vm_dir), Bind::ro(fc_out)]
        );
    }

    #[test]
    fn parse_ldd_extracts_interpreter_and_libs() {
        let dynamic = "\tlinux-vdso.so.1 (0x00007fff)\n\
             \tlibgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x0000774f)\n\
             \tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x0000774f)\n\
             \t/lib64/ld-linux-x86-64.so.2 (0x0000774f)\n";
        assert_eq!(
            parse_ldd(dynamic),
            vec![
                PathBuf::from("/lib/x86_64-linux-gnu/libgcc_s.so.1"),
                PathBuf::from("/lib/x86_64-linux-gnu/libc.so.6"),
                PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            ]
        );
        // A static binary yields no absolute-path lines.
        assert!(parse_ldd("\tnot a dynamic executable\n").is_empty());
        assert!(parse_ldd("\tstatically linked\n").is_empty());
    }

    #[test]
    fn standard_devs_adds_tun_only_when_networked() {
        assert_eq!(
            standard_devs(false),
            vec![
                PathBuf::from("/dev/kvm"),
                PathBuf::from("/dev/null"),
                PathBuf::from("/dev/urandom"),
            ]
        );
        assert!(standard_devs(true).contains(&PathBuf::from("/dev/net/tun")));
    }

    #[test]
    fn jail_bin_precedence() {
        let exists = |p: &Path| {
            [
                "/env/isopod-jail",
                "/target/debug/isopod-jail",
                "/home/u/.isopod/bin/isopod-jail",
            ]
            .iter()
            .any(|s| Path::new(s) == p)
        };
        // Env override wins.
        let got = resolve_jail_bin_from(
            Some(PathBuf::from("/env/isopod-jail")),
            Some(PathBuf::from("/target/debug/isopod-jail")),
            PathBuf::from("/home/u/.isopod/bin/isopod-jail"),
            &exists,
        )
        .unwrap();
        assert_eq!(got, PathBuf::from("/env/isopod-jail"));

        // Missing env override errors, naming the var.
        let err = resolve_jail_bin_from(
            Some(PathBuf::from("/env/missing")),
            None,
            PathBuf::from("/home/u/.isopod/bin/isopod-jail"),
            &exists,
        )
        .unwrap_err();
        assert!(err.to_string().contains("ISOPOD_JAIL_BIN"));

        // No env -> sibling next.
        let got = resolve_jail_bin_from(
            None,
            Some(PathBuf::from("/target/debug/isopod-jail")),
            PathBuf::from("/home/u/.isopod/bin/isopod-jail"),
            &exists,
        )
        .unwrap();
        assert_eq!(got, PathBuf::from("/target/debug/isopod-jail"));

        // No env, sibling absent -> home bin.
        let got = resolve_jail_bin_from(
            None,
            Some(PathBuf::from("/nope/isopod-jail")),
            PathBuf::from("/home/u/.isopod/bin/isopod-jail"),
            &exists,
        )
        .unwrap();
        assert_eq!(got, PathBuf::from("/home/u/.isopod/bin/isopod-jail"));

        // Nothing anywhere -> error.
        assert!(resolve_jail_bin_from(
            None,
            Some(PathBuf::from("/nope/isopod-jail")),
            PathBuf::from("/also/nope"),
            &exists,
        )
        .is_err());
    }
}
