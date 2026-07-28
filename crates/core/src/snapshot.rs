//! Warm-pool full-snapshot save/restore (M6 — the speed path).
//!
//! A fresh `sandbox_run` that boots straight from a squashfs base (no committed
//! stage layers, no `--commit-as`, networking on) doesn't need a ~400 ms cold
//! boot every time: it can **resume** a memory snapshot of a booted-idle VM in
//! low-single-digit-to-tens of milliseconds. This module builds those snapshots
//! and resumes them.
//!
//! # Warm VM shape
//! The snapshotted VM is deliberately drive-path-free past its read-only root:
//! the squashfs **base** as `vda` (read-only, shared by every resume at a fixed
//! path), a NIC, a vsock, and `isopod.upper=ram` (the overlay upperdir lives on
//! a tmpfs captured *inside* the memory image) — and **no scratch drive**. That
//! is what lets one snapshot resume as N concurrent VMs with no per-VM
//! backing-file path to collide on. Only the NIC (retargeted to the claimed
//! slot's host tap via `network_overrides`) and the vsock (`vsock_override`) are
//! rebound on resume.
//!
//! # Cache key & invalidation
//! A memory snapshot is fragile by design: it is only resumable on the same FC
//! build, host CPU, guest kernel and exact guest memory size it was captured
//! with. So each snapshot is keyed on
//! `(fc build, kernel identity, cpu model, base flavor, vcpus, mem_mib,
//! snapshot format)` — see [`SnapshotKey`] — and stored under
//! `~/.isopod/snapshots/<keyhash>/`. Any mismatch simply doesn't find a snapshot
//! (a different key ⇒ a different directory), and the caller cold-boots and
//! rebuilds. WSL2 auto-updates its kernel, so this invalidation fires in
//! practice; it must never surface as a run error.
//!
//! # Post-resume reconfiguration
//! The snapshot bakes in the *build-time* slot's addressing. After resume the
//! host pushes the claimed slot's IP/gw/dns over vsock
//! ([`crate::agent::AgentClient::configure_net`]) and resyncs the clock
//! ([`crate::agent::AgentClient::sync_clock_now`]) — vsock connections are
//! reconnect-per-request, so the pause/resume that severed the old ones is
//! transparent.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use isopod_fc::models::{
    BootSource, Drive, MachineConfig, NetworkInterface, NetworkOverride, SnapshotCreateParams,
    SnapshotLoadParams, Vsock,
};
use isopod_fc::{FcProcess, FcProcessConfig, LogLevel, StdioMode, VmId};

use crate::agent::AgentClient;
use crate::net;
use crate::paths;
use crate::vm::Resources;

/// The Firecracker snapshot data-format version this build (v1.16.1) emits. Part
/// of the cache key: a format bump is its own compatibility domain.
pub const SNAPSHOT_FORMAT: &str = "v10";

/// How long to wait for the guest agent's vsock to answer after a resume/boot.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Basename of the microVM state file inside a snapshot directory.
const VMSTATE_FILE: &str = "vmstate";
/// Basename of the guest-memory file inside a snapshot directory.
const MEMFILE_FILE: &str = "memfile";
/// Basename of the human/machine-readable metadata inside a snapshot directory.
const META_FILE: &str = "meta.json";
/// Per-snapshot build lock, inside the keyhash directory so `warmpool rm`
/// reclaims it with everything else.
const BUILD_LOCK_FILE: &str = "build.lock";

// ===========================================================================
// Snapshot cache key (pure; host detection is factored out for testability).
// ===========================================================================

/// The compatibility key a warm-pool snapshot is stored under.
///
/// Every field is a dimension a Firecracker memory snapshot is bound to. The
/// key is turned into a stable directory name by [`SnapshotKey::keyhash`] and a
/// human line by [`SnapshotKey::summary`]; both are pure over these fields, so
/// they are unit-testable with injected values (no host probing required).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotKey {
    /// Firecracker build identity (`firecracker --version` first line).
    pub fc_build: String,
    /// Guest-kernel identity: the vmlinux filename plus its byte length.
    pub kernel_id: String,
    /// Host CPU model (`/proc/cpuinfo` `model name`) — snapshots don't move
    /// across microarchitectures.
    pub cpu_model: String,
    /// Squashfs base-flavor slug the VM boots (`base-sqfs` / `base-alpine`).
    pub base: String,
    /// Content id of the built base image (the sidecar-recorded sha256, or
    /// `"unstamped"`). A rebuilt base image — same flavor, new content — must
    /// key to a different snapshot, or resumes silently reuse a stale guest
    /// (dogfood finding #25).
    pub base_sha256: String,
    /// Guest vCPU count (fixed in the saved vmstate).
    pub vcpus: u32,
    /// Guest memory in MiB (the memory file is a byte image of exactly this much
    /// RAM, so it cannot be resumed at a different size).
    pub mem_mib: u32,
    /// Snapshot data-format version ([`SNAPSHOT_FORMAT`]).
    pub snapshot_format: String,
}

impl SnapshotKey {
    /// Assemble a key from its parts (host detection already performed by the
    /// caller). Pure — no I/O — so it can be exercised in unit tests.
    #[must_use]
    pub fn new(
        fc_build: impl Into<String>,
        kernel_id: impl Into<String>,
        cpu_model: impl Into<String>,
        base: impl Into<String>,
        base_sha256: impl Into<String>,
        resources: Resources,
    ) -> Self {
        Self {
            fc_build: fc_build.into(),
            kernel_id: kernel_id.into(),
            cpu_model: cpu_model.into(),
            base: base.into(),
            base_sha256: base_sha256.into(),
            vcpus: resources.vcpus,
            mem_mib: resources.mem_mib,
            snapshot_format: SNAPSHOT_FORMAT.to_string(),
        }
    }

    /// The exact bytes hashed for [`keyhash`](Self::keyhash): one labelled
    /// `field=value` line per dimension, order-fixed. Labels + newlines make the
    /// encoding unambiguous, so two distinct shapes can never collide by
    /// concatenation.
    fn key_material(&self) -> String {
        format!(
            "isopod-snapshot-key-v2\n\
             fc_build={}\n\
             kernel_id={}\n\
             cpu_model={}\n\
             base={}\n\
             base_sha256={}\n\
             vcpus={}\n\
             mem_mib={}\n\
             snapshot_format={}\n",
            self.fc_build,
            self.kernel_id,
            self.cpu_model,
            self.base,
            self.base_sha256,
            self.vcpus,
            self.mem_mib,
            self.snapshot_format,
        )
    }

    /// A stable, filesystem-safe directory name for this key: the first 16 hex
    /// chars of the SHA-256 of the key material. Collision-free in practice
    /// (64-bit space) and identical across runs on the same host configuration.
    #[must_use]
    pub fn keyhash(&self) -> String {
        let digest = Sha256::digest(self.key_material().as_bytes());
        hex::encode(&digest[..8])
    }

    /// A one-line human summary (for `warmpool list` / diagnostics).
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{base}@{sha} {vcpus}c/{mem}m · {fc} · {kernel} · {cpu} · {fmt}",
            base = self.base,
            sha = &self.base_sha256[..self.base_sha256.len().min(8)],
            vcpus = self.vcpus,
            mem = self.mem_mib,
            fc = self.fc_build,
            kernel = self.kernel_id,
            cpu = self.cpu_model,
            fmt = self.snapshot_format,
        )
    }
}

// ===========================================================================
// Host detection (the impure half — reads the real machine).
// ===========================================================================

/// Detect the Firecracker build identity by running `<fc_bin> --version` and
/// taking its first output line (e.g. `Firecracker v1.16.1`).
///
/// # Errors
/// If the binary cannot be executed or emits no parseable version line.
pub fn detect_fc_build(fc_bin: &Path) -> Result<String> {
    let out = std::process::Command::new(fc_bin)
        .arg("--version")
        .output()
        .with_context(|| format!("running `{} --version`", fc_bin.display()))?;
    // `--version` prints to stdout; be tolerant and fall back to stderr.
    let text = if out.stdout.is_empty() {
        String::from_utf8_lossy(&out.stderr)
    } else {
        String::from_utf8_lossy(&out.stdout)
    };
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| anyhow::anyhow!("`firecracker --version` produced no output"))?;
    Ok(line.to_string())
}

/// Detect the host CPU model from `/proc/cpuinfo`'s first `model name` line.
///
/// # Errors
/// If `/proc/cpuinfo` cannot be read or has no `model name` line.
pub fn detect_cpu_model() -> Result<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").context("reading /proc/cpuinfo")?;
    parse_cpu_model(&cpuinfo)
}

/// Parse the CPU `model name` value out of `/proc/cpuinfo` text (split out so it
/// is unit-testable off a fixed fixture).
fn parse_cpu_model(cpuinfo: &str) -> Result<String> {
    for line in cpuinfo.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            if let Some((_, val)) = rest.split_once(':') {
                let val = val.trim();
                if !val.is_empty() {
                    return Ok(val.to_string());
                }
            }
        }
    }
    bail!("no `model name` line found in /proc/cpuinfo")
}

/// The guest-kernel identity used in the key: the vmlinux filename plus its
/// on-disk byte length (`vmlinux-6.18.36:27680232`). A kernel swap (WSL2
/// auto-update rebuilding/replacing it) changes either the name or the length
/// and so invalidates the snapshot.
///
/// # Errors
/// If the kernel file's metadata cannot be read.
pub fn kernel_identity(kernel_path: &Path) -> Result<String> {
    let len = std::fs::metadata(kernel_path)
        .with_context(|| format!("stat kernel {}", kernel_path.display()))?
        .len();
    let name = kernel_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vmlinux".to_string());
    Ok(format!("{name}:{len}"))
}

// ===========================================================================
// On-disk layout.
// ===========================================================================

/// The three files that constitute one stored snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotArtifacts {
    /// The snapshot directory (`~/.isopod/snapshots/<keyhash>`).
    pub dir: PathBuf,
    /// The microVM state file.
    pub vmstate: PathBuf,
    /// The guest-memory file.
    pub memfile: PathBuf,
    /// The metadata sidecar.
    pub meta: PathBuf,
}

impl SnapshotArtifacts {
    fn in_dir(dir: PathBuf) -> Self {
        let vmstate = dir.join(VMSTATE_FILE);
        let memfile = dir.join(MEMFILE_FILE);
        let meta = dir.join(META_FILE);
        Self {
            dir,
            vmstate,
            memfile,
            meta,
        }
    }

    /// Whether all three files are present (a complete, resumable snapshot).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.vmstate.is_file() && self.memfile.is_file() && self.meta.is_file()
    }
}

/// Resolve the on-disk artifact paths for `key` (does not create anything or
/// check for existence).
///
/// # Errors
/// If the isopod home / snapshots dir cannot be resolved.
pub fn artifacts_for(key: &SnapshotKey) -> Result<SnapshotArtifacts> {
    let dir = paths::snapshots_dir()?.join(key.keyhash());
    Ok(SnapshotArtifacts::in_dir(dir))
}

/// The metadata written alongside each snapshot (`meta.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// The full compatibility key.
    pub key: SnapshotKey,
    /// The directory-name hash of [`key`](Self::key).
    pub keyhash: String,
    /// A one-line human summary.
    pub summary: String,
    /// When the snapshot was built (Unix seconds).
    pub created_unix: u64,
    /// Size of the vmstate file in bytes.
    pub vmstate_bytes: u64,
    /// Size of the memory file in bytes.
    pub memfile_bytes: u64,
}

// ===========================================================================
// Build (`ensure`).
// ===========================================================================

/// Everything [`ensure`] needs to build a snapshot.
pub struct BuildCtx<'a> {
    /// Path to the firecracker binary.
    pub fc_bin: &'a Path,
    /// Path to the guest kernel (vmlinux).
    pub kernel: &'a Path,
    /// Path to the squashfs base image booted as the read-only `vda` root.
    pub base_sqfs: &'a Path,
    /// Host-validated vCPU / memory allocation (must match `key`).
    pub resources: Resources,
    /// The cache key this snapshot is stored under.
    pub key: &'a SnapshotKey,
}

/// Ensure a snapshot for `ctx.key` exists, building it if absent, and return its
/// artifact paths. A present, complete snapshot is reused untouched.
///
/// Building cold-boots a warm-shape VM (base squashfs + NIC + vsock +
/// `isopod.upper=ram`, no scratch), waits for the agent, resyncs the clock,
/// pauses, writes a Full snapshot, then tears the builder down. It claims and
/// releases its own network slot, so it can run before the caller claims the
/// run's slot (only one free slot is required).
///
/// # Errors
/// If no network slot is free, the builder fails to boot or become ready, or the
/// snapshot cannot be written. All errors are recoverable by the caller (cold
/// boot instead).
///
/// The returned bool is `true` iff this call built the snapshot (vs reusing a
/// complete cached one) — callers surface it so a first-use run can explain why
/// its `total_ms` includes seconds of one-time build cost (dogfood finding #20).
pub async fn ensure(ctx: &BuildCtx<'_>) -> Result<(SnapshotArtifacts, bool)> {
    ensure_at(artifacts_for(ctx.key)?, ctx, BUILD_LOCK_WAIT).await
}

/// [`ensure`] against explicit artifacts and an explicit wait.
///
/// The seam exists because the interesting behaviour — a second arrival waiting
/// out the first and then *reusing* what it published — happens entirely before
/// any VM is booted, and is therefore testable without one. `ensure` resolves
/// its directory from `$ISOPOD_HOME`, which is process-global; a test that set
/// it would steer every test beside it, which is a trap this codebase has
/// already fallen into twice.
async fn ensure_at(
    artifacts: SnapshotArtifacts,
    ctx: &BuildCtx<'_>,
    wait: Duration,
) -> Result<(SnapshotArtifacts, bool)> {
    if artifacts.is_complete() {
        return Ok((artifacts, false));
    }

    // Two runs of the same warm shape reach here together as a matter of
    // course: any rebuild empties the pool for every shape at once, and the
    // MCP surface actively invites concurrent sandboxes. Unlocked, both saw an
    // incomplete snapshot, both dumped several hundred MiB into the same two
    // fixed `.partial` names, and both renamed — so one run could publish a
    // file the other was still writing, and the pool would then hand that
    // snapshot to every later resume. This is the one warm-pool defect that
    // publishes corrupt state rather than merely wasting work.
    std::fs::create_dir_all(&artifacts.dir)
        .with_context(|| format!("creating snapshot dir {}", artifacts.dir.display()))?;
    let _lock = match acquire_build_lock(&artifacts, wait).await? {
        Some(lock) => lock,
        None => {
            // The lock was not taken, which is two different situations and
            // only one of them is a failure. Usually the other process finished
            // while we waited — that is the good case, and the whole point of
            // waiting: this run gets the snapshot it would otherwise have built
            // a second copy of.
            if artifacts.is_complete() {
                return Ok((artifacts, false));
            }
            // Otherwise somebody has been building for longer than the wait
            // allows. Cold boot is always correct — it is what a cache miss
            // does — so the caller gets a slower run rather than a race.
            eprintln!(
                "warmpool: another process has been building this snapshot for over {} s; \
                 cold-booting instead",
                wait.as_secs()
            );
            return Err(anyhow::anyhow!(
                "timed out waiting for another process to finish building this snapshot"
            ));
        }
    };

    // The wait may have been spent watching the winner finish. Re-check under
    // the lock: a second arrival should end up *using* the snapshot, not
    // building a second one over the top of it.
    if artifacts.is_complete() {
        return Ok((artifacts, false));
    }

    build(ctx, &artifacts).await?;
    Ok((artifacts, true))
}

/// How long a second arrival waits for whoever got here first.
///
/// Long enough to cover a real build — the several-second memory dump plus the
/// builder VM's own boot — and bounded, because the fallback is a cold boot and
/// a cold boot is never wrong. Waiting forever on a process that has wedged
/// would turn one stuck builder into a stuck host.
const BUILD_LOCK_WAIT: Duration = Duration::from_secs(90);
/// How often the waiter retries the lock.
const BUILD_LOCK_POLL: Duration = Duration::from_millis(200);

/// Take the per-snapshot build lock, waiting up to `wait`.
///
/// `Ok(None)` means the lock was not taken — either because the holder finished
/// (in which case the snapshot is now complete and the caller wants it) or
/// because `wait` expired. The caller distinguishes them; both are handled and
/// only the second is a failure.
///
/// `wait` is a parameter rather than the constant so a test can exercise the
/// expiry without waiting [`BUILD_LOCK_WAIT`] for it.
///
/// The lock lives *inside* the keyhash directory rather than beside it so that
/// `warmpool rm` — which removes whole directories and skips plain files —
/// reclaims it along with everything else. A lock file the pruner cannot see is
/// a lock file that accumulates forever.
async fn acquire_build_lock(
    artifacts: &SnapshotArtifacts,
    wait: Duration,
) -> Result<Option<std::fs::File>> {
    let path = artifacts.dir.join(BUILD_LOCK_FILE);
    let deadline = std::time::Instant::now() + wait;
    loop {
        match try_build_lock(&path) {
            Ok(Some(file)) => return Ok(Some(file)),
            Ok(None) => {}
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("claiming the build lock {}", path.display())))
            }
        }
        // Held by someone else. If they have finished, there is nothing left to
        // wait for — return and let the caller find the completed snapshot.
        if artifacts.is_complete() {
            return Ok(None);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(BUILD_LOCK_POLL).await;
    }
}

/// One non-blocking attempt at the build lock. Same shape as the network
/// slot's claim: `O_NOFOLLOW`, a regular-file check, and `LOCK_EX | LOCK_NB`,
/// so a crashed owner's lock is already gone and needs no staleness heuristic.
fn try_build_lock(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::io::AsRawFd as _;

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let kind = file.metadata()?.file_type();
    if !kind.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is not a regular file ({kind:?}); a build lock has to be one, so \
                 isopod will not flock this and claim the build is held",
                path.display()
            ),
        ));
    }
    // SAFETY: `flock` takes a raw fd and an operation, mutating no memory.
    // `file` owns the descriptor and outlives the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let e = std::io::Error::last_os_error();
    // EWOULDBLOCK (== EAGAIN) is the point of LOCK_NB: held, not broken.
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(e)
}

/// Generate a `dev-<8 hex>` VM id (shares the `dev-` prefix so the orphan reaper
/// covers a builder abandoned by a killed CLI).
fn generate_vm_id() -> Result<String> {
    let mut buf = [0u8; 4];
    let mut f = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    std::io::Read::read_exact(&mut f, &mut buf).context("reading /dev/urandom")?;
    Ok(format!(
        "dev-{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3]
    ))
}

/// Spawn a piped Firecracker process and start a detached task draining its
/// serial console to `console_log` (readiness is signalled over vsock, so no
/// marker channel is needed). Firecracker's own structured log goes to a sibling
/// `firecracker.log`.
async fn spawn_piped_draining(
    fc_bin: &Path,
    api_sock: &Path,
    vm_id: &str,
    console_log: &Path,
    prefix: Vec<String>,
) -> Result<FcProcess> {
    let id = VmId::new(vm_id)
        .map_err(|e| anyhow::anyhow!("invalid VM id {vm_id:?} for snapshot process: {e}"))?;
    let fc_log = console_log.with_file_name("firecracker.log");
    let mut config = FcProcessConfig::new(fc_bin, api_sock)
        .id(id)
        .stdio(StdioMode::Piped)
        .log_path(&fc_log)
        .log_level(LogLevel::Warning)
        .socket_timeout(Duration::from_secs(10));
    // Jail exec-prefix (ISOPOD_JAIL=1). Empty when off, so the argv is
    // byte-identical to the historical snapshot build/resume path.
    if !prefix.is_empty() {
        config = config.command_prefix(prefix);
    }
    let mut proc = FcProcess::spawn(config)
        .await
        .context("spawning firecracker")?;
    if let Some(stdout) = proc.child_mut().stdout.take() {
        let log = tokio::fs::File::create(console_log)
            .await
            .with_context(|| format!("creating {}", console_log.display()))?;
        // Detached: the drain ends on its own when the VMM exits and the pipe
        // closes. We never need to join it (console.log is for inspection
        // only). The shared drain caps the persisted bytes (F3) — a raw
        // `tokio::io::copy` here was an uncapped guest-controlled disk sink.
        tokio::spawn(crate::vm::console::drain_to_log(stdout, log));
    }
    Ok(proc)
}

/// The NIC config for the warm shape / a resume, bound to `slot`.
fn slot_nic(slot: &net::Slot) -> NetworkInterface {
    NetworkInterface {
        iface_id: "eth0".to_string(),
        host_dev_name: slot.tap_name(),
        guest_mac: Some(slot.guest_mac()),
        mtu: None,
        rx_rate_limiter: None,
        tx_rate_limiter: None,
    }
}

/// Do the actual build: boot the warm-shape VM, snapshot it, tear it down, and
/// atomically publish the artifacts + `meta.json`.
async fn build(ctx: &BuildCtx<'_>, artifacts: &SnapshotArtifacts) -> Result<()> {
    // Reap any firecracker orphaned by a crashed run — its tap would wedge the
    // slot — then claim one for the builder. The slot lock itself needs no
    // reclaiming: a crashed owner's `flock` is already gone.
    crate::vm::reap_orphans();
    let slot = net::claim().context("claiming a network slot for the snapshot builder")?;

    let vm_id = generate_vm_id()?;
    let vm_dir = paths::vms_dir()?.join(&vm_id);
    std::fs::create_dir_all(&vm_dir)
        .with_context(|| format!("creating builder VM dir {}", vm_dir.display()))?;
    // owner.pid + a minimal meta so the orphan reaper treats this builder as a
    // live VM (its dir shows up in `vm ls` and is later gc'd like any other).
    let _ = std::fs::write(vm_dir.join("owner.pid"), std::process::id().to_string());
    let created_unix = now_unix();
    let _ = std::fs::write(
        vm_dir.join("meta.json"),
        format!(
            "{}\n",
            serde_json::json!({
                "vm_id": vm_id,
                "name": "warmpool-builder",
                "flavor": ctx.key.base,
                "created_unix": created_unix,
            })
        ),
    );

    let api_sock = vm_dir.join("api.sock");
    let vsock_uds = vm_dir.join("vsock.sock");
    let console_log = vm_dir.join("console.log");

    // Jail the builder's Firecracker too (ISOPOD_JAIL=1) so its cold boot has the
    // same second isolation layer as a run. It always networks (it claims a slot).
    // A setup failure propagates: the caller (run's warm path) then cold-boots the
    // run itself jailed, so the untrusted path is never left unjailed.
    let jail_spec = if crate::jail::is_enabled() {
        // The snapshot output dir (vmstate/memfile) lives under the read-only home
        // bind, so a jailed Firecracker's write there would EROFS. Create it now
        // (so the bind source exists) and add an explicit rw bind nested over the
        // read-only home, exactly like vm_dir.
        std::fs::create_dir_all(&artifacts.dir)
            .with_context(|| format!("creating snapshot dir {}", artifacts.dir.display()))?;
        let mut binds = crate::jail::standard_binds(&vm_dir, ctx.fc_bin)?;
        binds.push(crate::jail::Bind::rw(&artifacts.dir));
        let devs = crate::jail::standard_devs(true);
        Some(crate::jail::setup(&vm_dir, ctx.resources, &binds, &devs)?)
    } else {
        None
    };
    let jail_prefix = jail_spec
        .as_ref()
        .map(|s| s.prefix.clone())
        .unwrap_or_default();

    let mut proc =
        spawn_piped_draining(ctx.fc_bin, &api_sock, &vm_id, &console_log, jail_prefix).await?;
    let client = proc.client().context("building the API client")?;

    // Boot args: the shared optimized set + RAM-upper warm mode + the builder
    // slot's static addressing (baked into the snapshot; re-applied per-resume).
    let args = format!(
        "{base} isopod.upper=ram isopod.net={net} isopod.gw={gw} isopod.dns={dns}",
        base = crate::vm::BOOT_ARGS,
        net = slot.guest_cidr(),
        gw = slot.host_ip(),
        dns = net::DEFAULT_DNS,
    );

    let snapshot_result = async {
        client
            .put_machine_config(&MachineConfig::new(
                ctx.resources.vcpus,
                u64::from(ctx.resources.mem_mib),
            ))
            .await
            .context("PUT /machine-config")?;
        client
            .put_boot_source(&BootSource::new(ctx.kernel.to_string_lossy(), args))
            .await
            .context("PUT /boot-source")?;
        // vda: the squashfs base — read-only root. NO scratch drive (upper=ram).
        client
            .put_drive(&Drive::virtio(
                "base",
                ctx.base_sqfs.to_string_lossy(),
                true,
                true,
            ))
            .await
            .context("PUT /drives/base")?;
        client
            .put_network_interface(&slot_nic(&slot))
            .await
            .context("PUT /network-interfaces/eth0")?;
        client
            .put_vsock(&Vsock::new(3, vsock_uds.to_string_lossy()))
            .await
            .context("PUT /vsock")?;
        client.instance_start().await.context("InstanceStart")?;

        // Wait for the agent, then resync the clock so the captured guest clock
        // is as fresh as possible (every resume resyncs again regardless).
        let agent = AgentClient::new(&vsock_uds);
        agent
            .wait_ready(AGENT_READY_TIMEOUT)
            .await
            .with_context(|| {
                format!(
                    "snapshot builder agent readiness check failed (vsock ping, \
                     {AGENT_READY_TIMEOUT:?} budget); serial log at {}",
                    console_log.display()
                )
            })?;
        agent
            .sync_clock_now()
            .await
            .context("syncing the builder clock over vsock")?;

        // Pause the vCPUs, then write a Full snapshot to temp paths in the
        // snapshot dir; publish atomically once both files are written.
        std::fs::create_dir_all(&artifacts.dir)
            .with_context(|| format!("creating snapshot dir {}", artifacts.dir.display()))?;
        client.pause().await.context("PATCH /vm {Paused}")?;
        // Staged under this process's own names. The build lock above is what
        // makes concurrent builds safe; this is the belt to its braces, so that
        // if the lock is ever lost — a refactor, a filesystem that does not
        // honour `flock` — a loser can still only ever destroy its own bytes
        // rather than publish half of somebody else's.
        let stamp = std::process::id();
        let tmp_state = artifacts.dir.join(format!("vmstate.{stamp}.partial"));
        let tmp_mem = artifacts.dir.join(format!("memfile.{stamp}.partial"));
        client
            .create_snapshot(&SnapshotCreateParams::full(
                tmp_state.to_string_lossy(),
                tmp_mem.to_string_lossy(),
            ))
            .await
            .context("PUT /snapshot/create {Full}")?;
        Ok::<(PathBuf, PathBuf), anyhow::Error>((tmp_state, tmp_mem))
    }
    .await;

    // Tear the builder down regardless of how the snapshot turned out. The VM is
    // paused on the happy path; shutdown() SIGKILLs the group if it does not
    // exit promptly. The slot is released when `slot` drops at end of scope.
    if let Err(e) = proc.shutdown(Duration::from_secs(3)).await {
        eprintln!("warmpool build: warning: builder shutdown returned: {e}");
    }
    // Tear the builder's jail cgroup down (Firecracker is reaped); best-effort.
    if let Some(spec) = &jail_spec {
        crate::jail::teardown(spec);
    }

    let (tmp_state, tmp_mem) = snapshot_result?;

    // Publish atomically, then write meta.json.
    std::fs::rename(&tmp_state, &artifacts.vmstate).with_context(|| {
        format!(
            "publishing {} -> {}",
            tmp_state.display(),
            artifacts.vmstate.display()
        )
    })?;
    std::fs::rename(&tmp_mem, &artifacts.memfile).with_context(|| {
        format!(
            "publishing {} -> {}",
            tmp_mem.display(),
            artifacts.memfile.display()
        )
    })?;
    write_meta(ctx.key, artifacts)?;
    Ok(())
}

/// Write the `meta.json` sidecar for a freshly built snapshot.
fn write_meta(key: &SnapshotKey, artifacts: &SnapshotArtifacts) -> Result<()> {
    let vmstate_bytes = std::fs::metadata(&artifacts.vmstate)
        .map(|m| m.len())
        .unwrap_or(0);
    let memfile_bytes = std::fs::metadata(&artifacts.memfile)
        .map(|m| m.len())
        .unwrap_or(0);
    let meta = SnapshotMeta {
        key: key.clone(),
        keyhash: key.keyhash(),
        summary: key.summary(),
        created_unix: now_unix(),
        vmstate_bytes,
        memfile_bytes,
    };
    let json = serde_json::to_string_pretty(&meta).context("serializing snapshot meta")?;
    let tmp = artifacts
        .dir
        .join(format!("meta.json.{}.partial", std::process::id()));
    std::fs::write(&tmp, format!("{json}\n"))
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &artifacts.meta)
        .with_context(|| format!("finalizing {}", artifacts.meta.display()))?;
    Ok(())
}

// ===========================================================================
// Resume.
// ===========================================================================

/// Resume the snapshot for `key` into `slot`, returning the running Firecracker
/// process and a ready [`AgentClient`] positioned for exec.
///
/// A **fresh** Firecracker process is spawned (snapshot load requires a pristine
/// process), the snapshot is loaded File-backed with `resume_vm: true`, its
/// `eth0` retargeted to the claimed slot's host tap and its vsock repointed at
/// `<vm_dir>/vsock.sock`. Post-resume the guest is re-IP'd into the claimed
/// slot's `/30` ([`AgentClient::configure_net`]) and its clock resynced — so NAT
/// egress works even though the snapshot baked slot 0's addressing.
///
/// The API socket, vsock socket and console log are placed under `vm_dir`
/// exactly as the cold path does, so the caller's teardown/reaping is identical.
///
/// # Errors
/// If the snapshot is missing/incomplete, the load fails (a stale snapshot after
/// a kernel/FC change — the caller must fall back to a cold boot), or the agent
/// never answers.
pub async fn resume(
    key: &SnapshotKey,
    fc_bin: &Path,
    slot: &net::Slot,
    vm_dir: &Path,
    jail_prefix: Vec<String>,
    broker: Option<&net::broker::BrokerEndpoints>,
) -> Result<(FcProcess, AgentClient)> {
    let artifacts = artifacts_for(key)?;
    if !artifacts.is_complete() {
        bail!(
            "no complete snapshot for key {} at {}",
            key.keyhash(),
            artifacts.dir.display()
        );
    }

    let vm_id = vm_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dev-resume".to_string());
    let api_sock = vm_dir.join("api.sock");
    let vsock_uds = vm_dir.join("vsock.sock");
    let console_log = vm_dir.join("console.log");

    // The resume runs in the run's own vm_dir, so the run's jail (built in
    // `run_exec`) wraps it via `jail_prefix`; empty when ISOPOD_JAIL is off.
    let proc = spawn_piped_draining(fc_bin, &api_sock, &vm_id, &console_log, jail_prefix).await?;
    let client = proc.client().context("building the API client")?;

    let params = SnapshotLoadParams::file_backed(
        artifacts.vmstate.to_string_lossy(),
        artifacts.memfile.to_string_lossy(),
        true,
    )
    .with_network_overrides(vec![NetworkOverride {
        iface_id: "eth0".to_string(),
        host_dev_name: slot.tap_name(),
    }])
    .with_vsock_override(vsock_uds.to_string_lossy());
    client.load_snapshot(&params).await.with_context(|| {
        format!(
            "PUT /snapshot/load (resume; retarget eth0 -> slot {}, tap {})",
            slot.index(),
            slot.tap_name()
        )
    })?;

    let agent = AgentClient::new(&vsock_uds);
    agent
        .wait_ready(AGENT_READY_TIMEOUT)
        .await
        .with_context(|| {
            format!(
                "resumed guest agent readiness check failed (vsock ping, \
                 {AGENT_READY_TIMEOUT:?} budget); serial log at {}",
                console_log.display()
            )
        })?;
    // Re-IP eth0 into the CLAIMED slot's /30 (the snapshot baked the build-time
    // slot's address). Without this, NAT would not route. A filtered run also
    // hands over its broker endpoints here and points the resolver at the
    // gateway: the snapshot was built on a public slot, so its baked resolvers
    // are exactly the ones this slot may not reach.
    let (dns, broker_cfg) = match broker {
        Some(b) => (
            vec![b.dns.clone()],
            Some(isopod_proto::BrokerConfig {
                socks: b.socks.clone(),
                http: b.http.clone(),
                inject: b.inject.clone(),
            }),
        ),
        None => (default_dns_list(), None),
    };
    agent
        .configure_net(&slot.guest_cidr(), &slot.host_ip(), &dns, broker_cfg)
        .await
        .context("reconfiguring guest network after resume")?;
    // The resumed guest's wall clock is as stale as the snapshot; resync it.
    agent
        .sync_clock_now()
        .await
        .context("syncing the resumed guest clock over vsock")?;

    Ok((proc, agent))
}

/// The default DNS resolvers as a list (splitting the comma-joined
/// [`net::DEFAULT_DNS`]).
fn default_dns_list() -> Vec<String> {
    net::DEFAULT_DNS
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

// ===========================================================================
// Store management (for the `warmpool` CLI).
// ===========================================================================

/// List every stored snapshot's metadata, newest first. Directories missing or
/// with an unreadable `meta.json` are skipped.
///
/// # Errors
/// If the snapshots directory cannot be read.
pub fn list() -> Result<Vec<SnapshotMeta>> {
    let dir = paths::snapshots_dir()?;
    let mut metas = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("reading snapshots dir {}", dir.display()))?
        .flatten()
    {
        if !entry.path().is_dir() {
            continue;
        }
        let meta_path = entry.path().join(META_FILE);
        if let Ok(raw) = std::fs::read_to_string(&meta_path) {
            if let Ok(meta) = serde_json::from_str::<SnapshotMeta>(&raw) {
                metas.push(meta);
            }
        }
    }
    metas.sort_by_key(|m| std::cmp::Reverse(m.created_unix));
    Ok(metas)
}

/// Remove one snapshot by its keyhash (or a unique keyhash prefix). Returns the
/// removed snapshot's metadata.
///
/// # Errors
/// If no snapshot matches, the prefix is ambiguous, or the directory cannot be
/// removed.
pub fn remove(keyhash: &str) -> Result<SnapshotMeta> {
    let dir = paths::snapshots_dir()?;
    let matches: Vec<SnapshotMeta> = list()?
        .into_iter()
        .filter(|m| m.keyhash == keyhash || m.keyhash.starts_with(keyhash))
        .collect();
    match matches.as_slice() {
        [] => bail!("no snapshot matches {keyhash:?}"),
        [one] => {
            let target = dir.join(&one.keyhash);
            std::fs::remove_dir_all(&target)
                .with_context(|| format!("removing {}", target.display()))?;
            Ok(one.clone())
        }
        many => bail!(
            "{keyhash:?} is ambiguous ({} snapshots match: {})",
            many.len(),
            many.iter()
                .map(|m| m.keyhash.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Remove every stored snapshot, returning the removed keyhashes.
///
/// # Errors
/// If the snapshots directory cannot be read or a removal fails.
pub fn remove_all() -> Result<Vec<String>> {
    let dir = paths::snapshots_dir()?;
    let mut removed = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("reading snapshots dir {}", dir.display()))?
        .flatten()
    {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        std::fs::remove_dir_all(entry.path())
            .with_context(|| format!("removing snapshot {name}"))?;
        removed.push(name);
    }
    removed.sort();
    Ok(removed)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> SnapshotKey {
        SnapshotKey::new(
            "Firecracker v1.16.1",
            "vmlinux-6.18.36:27680232",
            "13th Gen Intel(R) Core(TM) i7-13620H",
            "base-alpine",
            "a3f1c2d4e5b60718293a4b5c6d7e8f9012345678901234567890123456789012",
            Resources {
                vcpus: 1,
                mem_mib: 512,
            },
        )
    }

    #[test]
    fn keyhash_is_stable_and_16_hex() {
        let k = sample_key();
        let h = k.keyhash();
        assert_eq!(h.len(), 16, "keyhash is 16 hex chars");
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        // Deterministic across constructions.
        assert_eq!(h, sample_key().keyhash());
    }

    #[test]
    fn keyhash_changes_on_any_dimension() {
        let base = sample_key();
        let h = base.keyhash();

        let mut fc = base.clone();
        fc.fc_build = "Firecracker v1.17.0".into();
        assert_ne!(fc.keyhash(), h, "fc build changes the hash");

        let mut kern = base.clone();
        kern.kernel_id = "vmlinux-6.19.0:27680233".into();
        assert_ne!(kern.keyhash(), h, "kernel identity changes the hash");

        let mut cpu = base.clone();
        cpu.cpu_model = "AMD EPYC".into();
        assert_ne!(cpu.keyhash(), h, "cpu model changes the hash");

        let mut b = base.clone();
        b.base = "base-sqfs".into();
        assert_ne!(b.keyhash(), h, "base flavor changes the hash");

        let mut bs = base.clone();
        bs.base_sha256 = "unstamped".into();
        assert_ne!(bs.keyhash(), h, "base image content id changes the hash");

        let mut v = base.clone();
        v.vcpus = 2;
        assert_ne!(v.keyhash(), h, "vcpus changes the hash");

        let mut m = base.clone();
        m.mem_mib = 1024;
        assert_ne!(m.keyhash(), h, "mem changes the hash");

        let mut f = base.clone();
        f.snapshot_format = "v11".into();
        assert_ne!(f.keyhash(), h, "snapshot format changes the hash");
    }

    #[test]
    fn new_populates_resources_and_format() {
        let k = sample_key();
        assert_eq!(k.vcpus, 1);
        assert_eq!(k.mem_mib, 512);
        assert_eq!(k.snapshot_format, SNAPSHOT_FORMAT);
    }

    #[test]
    fn summary_mentions_all_dimensions() {
        let s = sample_key().summary();
        assert!(s.contains("base-alpine"));
        assert!(s.contains("1c/512m"));
        assert!(s.contains("Firecracker v1.16.1"));
        assert!(s.contains("vmlinux-6.18.36"));
        assert!(s.contains("i7-13620H"));
        assert!(s.contains(SNAPSHOT_FORMAT));
    }

    #[test]
    fn parse_cpu_model_reads_first_model_name() {
        let sample = "processor\t: 0\nvendor_id\t: GenuineIntel\n\
                      model name\t: 13th Gen Intel(R) Core(TM) i7-13620H\n\
                      processor\t: 1\nmodel name\t: something else\n";
        assert_eq!(
            parse_cpu_model(sample).unwrap(),
            "13th Gen Intel(R) Core(TM) i7-13620H"
        );
    }

    #[test]
    fn parse_cpu_model_errors_without_line() {
        assert!(parse_cpu_model("processor\t: 0\n").is_err());
    }

    #[test]
    fn kernel_identity_is_name_and_len() {
        let dir = tempfile::tempdir().unwrap();
        let kern = dir.path().join("vmlinux-6.18.36");
        std::fs::write(&kern, vec![0u8; 1234]).unwrap();
        assert_eq!(kernel_identity(&kern).unwrap(), "vmlinux-6.18.36:1234");
    }

    #[test]
    fn default_dns_list_splits_the_const() {
        assert_eq!(default_dns_list(), vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn artifacts_is_complete_requires_all_three() {
        let dir = tempfile::tempdir().unwrap();
        let a = SnapshotArtifacts::in_dir(dir.path().join("snap"));
        std::fs::create_dir_all(&a.dir).unwrap();
        assert!(!a.is_complete());
        std::fs::write(&a.vmstate, b"s").unwrap();
        std::fs::write(&a.memfile, b"m").unwrap();
        assert!(!a.is_complete(), "meta.json still missing");
        std::fs::write(&a.meta, b"{}").unwrap();
        assert!(a.is_complete());
    }

    #[test]
    fn snapshot_meta_round_trips() {
        let key = sample_key();
        let meta = SnapshotMeta {
            keyhash: key.keyhash(),
            summary: key.summary(),
            key,
            created_unix: 1_700_000_000,
            vmstate_bytes: 4096,
            memfile_bytes: 536_870_912,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: SnapshotMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.keyhash, meta.keyhash);
        assert_eq!(back.memfile_bytes, 536_870_912);
        assert_eq!(back.key.base, "base-alpine");
    }

    // --- the build lock (dogfood finding #32) ---------------------------
    //
    // Unlocked, two runs of the same warm shape both saw an incomplete
    // snapshot, both dumped hundreds of MiB into the same two fixed `.partial`
    // names, and both renamed — one could publish a file the other was still
    // writing, and every later resume would then get it. These exercise the
    // lock itself; `ensure`'s use of it needs a real VM and is not unit-
    // testable, so the mutation for this guard targets the call site.

    fn artifacts_in(dir: &Path) -> SnapshotArtifacts {
        std::fs::create_dir_all(dir).expect("mkdir");
        SnapshotArtifacts::in_dir(dir.to_path_buf())
    }

    #[tokio::test]
    async fn one_builder_takes_the_lock_and_a_second_does_not() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = artifacts_in(&tmp.path().join("keyhash"));

        let first = acquire_build_lock(&a, Duration::from_millis(50))
            .await
            .expect("no error")
            .expect("the first builder must get the lock");

        // The second arrival finds it held, and the snapshot never completes,
        // so it gives up rather than building on top of the first.
        let second = acquire_build_lock(&a, Duration::from_millis(50))
            .await
            .expect("no error");
        assert!(second.is_none(), "two builders held the lock at once");

        // And once the first is done, the lock is free again — flock releases
        // on close, so a crashed builder needs no staleness heuristic.
        drop(first);
        assert!(
            acquire_build_lock(&a, Duration::from_millis(50))
                .await
                .expect("no error")
                .is_some(),
            "the lock outlived its holder"
        );
    }

    #[tokio::test]
    async fn the_waiter_stops_as_soon_as_the_snapshot_appears() {
        // The case the wait exists for: the loser should end up *using* the
        // winner's snapshot, and should not sit out the full timeout to learn
        // that. A waiter that only ever expires would turn every concurrent
        // second call into a 90-second stall.
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = artifacts_in(&tmp.path().join("keyhash"));
        let _held = acquire_build_lock(&a, Duration::from_millis(50))
            .await
            .expect("no error")
            .expect("held");

        // The winner publishes while the loser is waiting.
        for f in [&a.vmstate, &a.memfile, &a.meta] {
            std::fs::write(f, b"x").expect("publish");
        }
        assert!(a.is_complete());

        let t0 = std::time::Instant::now();
        let got = acquire_build_lock(&a, Duration::from_secs(30))
            .await
            .expect("no error");
        assert!(got.is_none(), "the lock is still held by the winner");
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the waiter sat out the timeout instead of noticing the snapshot \
             was published: {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn the_lock_is_inside_the_snapshot_directory_so_the_pruner_reclaims_it() {
        // `warmpool rm` removes directories and skips plain files, so a lock
        // beside the keyhash dir would survive every prune, forever.
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("keyhash");
        let a = artifacts_in(&dir);
        let lock = try_build_lock(&dir.join(BUILD_LOCK_FILE))
            .expect("no error")
            .expect("locked");
        assert!(dir.join(BUILD_LOCK_FILE).is_file());
        drop(lock);
        std::fs::remove_dir_all(&dir).expect("the pruner removes the whole dir");
        assert!(!dir.exists());
        // And it is not one of the three files completeness is judged on.
        assert!(!a.is_complete());
    }

    #[test]
    fn a_lock_path_that_is_not_a_regular_file_is_refused() {
        // Same reasoning as the network slot's claim: flocking something that
        // is not a file and reporting "held" would be a lie in the one
        // direction that matters.
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("keyhash");
        std::fs::create_dir_all(dir.join(BUILD_LOCK_FILE)).expect("mkdir over the lock name");
        let err = try_build_lock(&dir.join(BUILD_LOCK_FILE)).expect_err("must refuse");
        assert!(
            err.to_string().contains("regular file")
                || err.kind() == std::io::ErrorKind::IsADirectory,
            "{err}"
        );
    }

    /// A `BuildCtx` whose paths are never opened: every assertion below is
    /// about what happens *before* a VM would be booted.
    fn unusable_ctx(key: &SnapshotKey) -> BuildCtx<'_> {
        BuildCtx {
            fc_bin: Path::new("/nonexistent/firecracker"),
            kernel: Path::new("/nonexistent/vmlinux"),
            base_sqfs: Path::new("/nonexistent/base.sqfs"),
            resources: Resources {
                vcpus: key.vcpus,
                mem_mib: key.mem_mib,
            },
            key,
        }
    }

    #[tokio::test]
    async fn a_second_run_waits_for_the_first_and_then_reuses_what_it_published() {
        // The finding, at the call site. Two runs of the same warm shape arrive
        // together; the loser must end up USING the winner's snapshot. Before
        // the lock it started its own build into the same fixed `.partial`
        // names, which is how a half-written memory file got published.
        //
        // No VM is booted: the ctx's paths do not exist, so if this test ever
        // reaches `build` it fails loudly rather than silently passing.
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = artifacts_in(&tmp.path().join("keyhash"));
        let key = sample_key();

        let held = acquire_build_lock(&a, Duration::from_millis(50))
            .await
            .expect("no error")
            .expect("the winner holds the lock");

        // The winner finishes shortly after the loser starts waiting.
        let publish = {
            let a = SnapshotArtifacts::in_dir(a.dir.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                for f in [&a.vmstate, &a.memfile, &a.meta] {
                    std::fs::write(f, b"x").expect("publish");
                }
                drop(held);
            })
        };

        let ctx = unusable_ctx(&key);
        let (got, built) = ensure_at(
            SnapshotArtifacts::in_dir(a.dir.clone()),
            &ctx,
            Duration::from_secs(30),
        )
        .await
        .expect("the loser must succeed by reusing, not fail");
        publish.await.expect("publisher");

        assert!(!built, "the loser rebuilt a snapshot that already existed");
        assert!(got.is_complete());
        // And it left no staging file of its own behind.
        let strays: Vec<_> = std::fs::read_dir(&a.dir)
            .expect("read_dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("partial"))
            .collect();
        assert!(strays.is_empty(), "the loser started writing: {strays:?}");
    }

    #[tokio::test]
    async fn a_complete_snapshot_is_reused_without_taking_the_lock_at_all() {
        // The control for the test above: the common path must not be made
        // slower or lock-dependent by any of this.
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = artifacts_in(&tmp.path().join("keyhash"));
        for f in [&a.vmstate, &a.memfile, &a.meta] {
            std::fs::write(f, b"x").expect("publish");
        }
        let key = sample_key();
        let ctx = unusable_ctx(&key);
        let (_, built) = ensure_at(
            SnapshotArtifacts::in_dir(a.dir.clone()),
            &ctx,
            Duration::from_secs(1),
        )
        .await
        .expect("reuse");
        assert!(!built);
        assert!(
            !a.dir.join(BUILD_LOCK_FILE).exists(),
            "the fast path took a lock it does not need"
        );
    }
}
