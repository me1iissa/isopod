//! VM lifecycle. M1 ships only the ephemeral **dev boot** path: resolve the
//! artifacts (firecracker binary, guest kernel, rootfs), boot a throwaway
//! microVM through [`isopod_fc`], watch its serial console for the boot-liveness
//! markers, measure boot latency, then tear it down — never dirtying any cached
//! image. The full boot/exec/stage lifecycle lands in later milestones.
//!
//! Public entry points:
//! * [`dev_boot`] — the `isopod dev boot` routine (synchronous; drives an async
//!   boot internally).
//! * [`build_fc`] — the `isopod dev build-fc` routine (build the vendored FC).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;

use isopod_fc::models::{BootSource, Drive, MachineConfig, Vsock};
use isopod_fc::{FcClient, FcProcess, FcProcessConfig, LogLevel, StdioMode, VmId};

use crate::agent::{AgentClient, ExecSpec, StreamCapture};
use crate::image::{self, RootfsFlavor};
use crate::paths;

mod build_fc;
mod console;

pub use build_fc::{build_fc, BinPaths, BuildFcOutcome};

/// Per-stream inline capture cap for `isopod run` (64 KiB, per the PLAN's
/// head-truncation policy); everything is still teed in full to the log files.
const INLINE_CAP: usize = 64 * 1024;

/// Guest-agent vsock readiness deadline after `InstanceStart`.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Exact optimized boot args (M0 `NOTES-boot.md`): `quiet` plus the i8042
/// keyboard-probe disables that reclaim ~440 ms of cold boot, matching the
/// fc-client live test verbatim.
const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda init=/init quiet \
     i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd 8250.nr_uarts=1";

/// Default bound on how long [`dev_boot`] waits for the boot markers.
pub const DEFAULT_BOOT_TIMEOUT: Duration = Duration::from_secs(15);

/// The dev rootfs flavor M1 boots.
const DEV_FLAVOR: RootfsFlavor = RootfsFlavor::DevBusybox;

/// Where the firecracker binary [`dev_boot`] used was resolved from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FcProvenance {
    /// From the `$ISOPOD_FC_BIN` override.
    Env,
    /// From `~/.isopod/bin/firecracker` (produced by `isopod dev build-fc`).
    VendoredBuild,
    /// From `~/.isopod/m0/bin/firecracker` (the M0 spike release binary).
    M0Release,
}

/// A resolved firecracker binary and where it came from.
#[derive(Debug, Clone, Serialize)]
pub struct FcBinary {
    /// Absolute path to the firecracker binary.
    pub path: PathBuf,
    /// How the path was resolved.
    pub provenance: FcProvenance,
}

/// Options for [`dev_boot`].
#[derive(Debug, Clone)]
pub struct DevBootOptions {
    /// Keep the VM directory's throwaway rootfs copy instead of deleting it.
    pub keep: bool,
    /// Bound on how long to wait for the boot markers.
    pub timeout: Duration,
    /// Rootfs flavor to boot. The marker-based liveness check only fits the
    /// `dev-busybox` flavor (which emits `ISOPOD-BOOT-COMPLETE`/`TICK`); other
    /// flavors are accepted so they can be boot-smoke-tested in isolation.
    pub flavor: RootfsFlavor,
}

impl Default for DevBootOptions {
    fn default() -> Self {
        Self {
            keep: false,
            timeout: DEFAULT_BOOT_TIMEOUT,
            flavor: DEV_FLAVOR,
        }
    }
}

/// Result of a successful [`dev_boot`], serialized verbatim as the CLI's stdout
/// JSON.
#[derive(Debug, Clone, Serialize)]
pub struct DevBootReport {
    /// Always `true` on the success path (the CLI emits `{ok:false,…}` on error).
    pub ok: bool,
    /// The generated VM id (`dev-<8 hex>`).
    pub vm_id: String,
    /// Milliseconds from `InstanceStart` returning to the boot marker appearing.
    pub boot_ms: f64,
    /// Number of `TICK` liveness lines observed (guaranteed `>= 2` on success).
    pub ticks_observed: u32,
    /// The firecracker binary used and its provenance.
    pub fc_binary: FcBinary,
    /// Absolute path to the guest kernel used.
    pub kernel_path: PathBuf,
    /// Rootfs flavor booted (e.g. `dev-busybox`).
    pub rootfs_flavor: String,
    /// Absolute path to the retained serial `console.log`.
    pub serial_log_path: PathBuf,
}

/// Boot a throwaway dev microVM and report boot latency + liveness.
///
/// Synchronous entry point: resolves artifacts (fetching the kernel / building
/// the rootfs if absent), then drives an async boot on an internal current-thread
/// runtime. The cached rootfs is never mutated — a sparse copy is booted and
/// removed afterwards (unless [`DevBootOptions::keep`]); `console.log` is always
/// retained for inspection.
///
/// # Errors
/// Returns an error if an artifact cannot be resolved, the VMM fails to boot, or
/// the boot markers are not observed within [`DevBootOptions::timeout`].
pub fn dev_boot(opts: DevBootOptions) -> Result<DevBootReport> {
    // Resolve artifacts *before* entering async: fetch_kernel / build_rootfs use
    // a blocking HTTP client, which would panic if driven from inside a tokio
    // runtime.
    let fc = resolve_fc_bin()?;
    let kernel = resolve_kernel()?;
    let (rootfs, rootfs_flavor) = resolve_rootfs(opts.flavor)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(run_boot(fc, kernel, rootfs, rootfs_flavor, opts))
}

/// Resolve the firecracker binary path and provenance, honouring the
/// `$ISOPOD_FC_BIN` override then the vendored-build and M0-release locations.
fn resolve_fc_bin() -> Result<FcBinary> {
    let home = paths::isopod_home()?;
    let env = std::env::var_os("ISOPOD_FC_BIN")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    resolve_fc_bin_from(
        env,
        home.join("bin/firecracker"),
        home.join("m0/bin/firecracker"),
        &|p| p.exists(),
    )
}

/// Pure resolution of the firecracker binary, split out so precedence is
/// unit-testable without touching the filesystem or process environment.
///
/// Precedence: an explicit `$ISOPOD_FC_BIN` wins (and must exist), then the
/// vendored build, then the M0 release binary.
fn resolve_fc_bin_from(
    env: Option<PathBuf>,
    vendored: PathBuf,
    m0: PathBuf,
    exists: &dyn Fn(&Path) -> bool,
) -> Result<FcBinary> {
    if let Some(path) = env {
        if exists(&path) {
            return Ok(FcBinary {
                path,
                provenance: FcProvenance::Env,
            });
        }
        bail!(
            "$ISOPOD_FC_BIN points at {} but no file exists there",
            path.display()
        );
    }
    if exists(&vendored) {
        return Ok(FcBinary {
            path: vendored,
            provenance: FcProvenance::VendoredBuild,
        });
    }
    if exists(&m0) {
        return Ok(FcBinary {
            path: m0,
            provenance: FcProvenance::M0Release,
        });
    }
    bail!(
        "no firecracker binary found: set $ISOPOD_FC_BIN, run `isopod dev build-fc`, \
         or provide {} or {}",
        vendored.display(),
        m0.display()
    )
}

/// Resolve a guest kernel from `~/.isopod/images`, preferring the 6.18 series;
/// fetches a CI vmlinux if none is present.
fn resolve_kernel() -> Result<PathBuf> {
    let images = paths::images_dir()?;
    if let Some(p) = newest_with_prefix(&images, "vmlinux-6.18")? {
        return Ok(p);
    }
    if let Some(p) = newest_with_prefix(&images, "vmlinux-")? {
        return Ok(p);
    }
    eprintln!("dev boot: no guest kernel present; fetching a 6.18 CI vmlinux…");
    Ok(image::fetch_kernel("6.18", false)?.kernel_path)
}

/// Resolve the rootfs image for `flavor`, building it unprivileged if absent.
/// Returns the image path and its flavor slug.
fn resolve_rootfs(flavor: RootfsFlavor) -> Result<(PathBuf, String)> {
    let images = paths::images_dir()?;
    let dest = images.join(format!("rootfs-{}.ext4", flavor.slug()));
    if dest.exists() {
        return Ok((dest, flavor.slug().to_string()));
    }
    eprintln!(
        "no rootfs for `{}` present; building it unprivileged…",
        flavor.slug()
    );
    let out = image::build_rootfs(flavor, false)?;
    Ok((out.rootfs_path, out.flavor))
}

/// Return the regular-file entry in `dir` with the lexicographically-greatest
/// name starting with `prefix` (kernel version strings sort correctly this way).
fn newest_with_prefix(dir: &Path, prefix: &str) -> Result<Option<PathBuf>> {
    let mut best: Option<(String, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading an entry in {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(prefix) || !entry.path().is_file() {
            continue;
        }
        match &best {
            Some((best_name, _)) if *best_name >= name => {}
            _ => best = Some((name, entry.path())),
        }
    }
    Ok(best.map(|(_, path)| path))
}

/// Generate an ephemeral VM id `dev-<8 hex>` from `/dev/urandom` (std only).
fn generate_vm_id() -> Result<String> {
    let mut buf = [0u8; 4];
    let mut f = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    std::io::Read::read_exact(&mut f, &mut buf).context("reading /dev/urandom")?;
    Ok(format!(
        "dev-{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3]
    ))
}

/// Sparse-aware copy of `src` to `dst` (holes preserved) via `cp --sparse=always`.
fn sparse_copy(src: &Path, dst: &Path) -> Result<()> {
    let status = std::process::Command::new("cp")
        .arg("--sparse=always")
        .arg(src)
        .arg(dst)
        .status()
        .context("spawning cp for the sparse rootfs copy")?;
    if !status.success() {
        bail!(
            "cp --sparse=always {} {} failed ({status})",
            src.display(),
            dst.display()
        );
    }
    Ok(())
}

/// Async driver: create the VM dir, sparse-copy the rootfs, boot + measure, then
/// clean up the throwaway copy (keeping `console.log`).
async fn run_boot(
    fc: FcBinary,
    kernel: PathBuf,
    rootfs: PathBuf,
    rootfs_flavor: String,
    opts: DevBootOptions,
) -> Result<DevBootReport> {
    let vm_id = generate_vm_id()?;
    let vm_dir = paths::vms_dir()?.join(&vm_id);
    std::fs::create_dir_all(&vm_dir)
        .with_context(|| format!("creating VM dir {}", vm_dir.display()))?;

    let console_log = vm_dir.join("console.log");
    let rootfs_copy = vm_dir.join("rootfs.ext4");
    let api_sock = vm_dir.join("api.sock");

    // Always boot a throwaway copy; the cached image must stay pristine.
    sparse_copy(&rootfs, &rootfs_copy)?;

    let driven = drive_vm(
        &fc,
        &kernel,
        &rootfs_copy,
        &api_sock,
        &console_log,
        &vm_id,
        &opts,
    )
    .await;

    // Remove the throwaway rootfs copy unless --keep; keep console.log regardless.
    if !opts.keep {
        match std::fs::remove_file(&rootfs_copy) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "dev boot: warning: could not remove {}: {e}",
                rootfs_copy.display()
            ),
        }
    }

    let (boot_ms, ticks) = driven?;
    Ok(DevBootReport {
        ok: true,
        vm_id,
        boot_ms,
        ticks_observed: ticks,
        fc_binary: fc,
        kernel_path: kernel,
        rootfs_flavor,
        serial_log_path: console_log,
    })
}

/// Spawn a piped Firecracker process and take its stdout pipe (the relayed
/// guest serial console). Firecracker's own structured logs go to a sibling
/// `firecracker.log` so the caller's `console.log` holds pure guest serial.
///
/// Shared by the dev-boot (marker-watching) and run (quiet-tee) flows.
async fn spawn_fc_piped(
    fc: &FcBinary,
    api_sock: &Path,
    vm_id: &str,
    console_log: &Path,
) -> Result<(FcProcess, tokio::process::ChildStdout)> {
    let id = VmId::new(vm_id).map_err(|e| anyhow!("generated an invalid VM id {vm_id:?}: {e}"))?;
    let fc_log = console_log.with_file_name("firecracker.log");
    let mut proc = FcProcess::spawn(
        FcProcessConfig::new(&fc.path, api_sock)
            .id(id)
            .stdio(StdioMode::Piped)
            .log_path(&fc_log)
            .log_level(LogLevel::Warning)
            .socket_timeout(Duration::from_secs(10)),
    )
    .await
    .context("spawning firecracker")?;
    let stdout = proc
        .child_mut()
        .stdout
        .take()
        .ok_or_else(|| anyhow!("firecracker stdout was not piped"))?;
    Ok((proc, stdout))
}

/// Pre-boot configuration common to every ephemeral VM: 1 vCPU / 256 MiB, the
/// optimized boot args, and the root device.
async fn configure_boot(client: &FcClient, kernel: &Path, rootfs: &Path) -> Result<()> {
    client
        .put_machine_config(&MachineConfig::new(1, 256))
        .await
        .context("PUT /machine-config")?;
    client
        .put_boot_source(&BootSource::new(kernel.to_string_lossy(), BOOT_ARGS))
        .await
        .context("PUT /boot-source")?;
    client
        .put_drive(&Drive::virtio(
            "rootfs",
            rootfs.to_string_lossy(),
            true,
            true,
        ))
        .await
        .context("PUT /drives/rootfs")?;
    Ok(())
}

/// Spawn firecracker, configure 1 vCPU / 256 MiB, boot, and watch the serial
/// console for the boot + liveness markers. On any error the [`FcProcess`] drop
/// guard still tears the VMM down. Returns `(boot_ms, ticks_observed)`.
async fn drive_vm(
    fc: &FcBinary,
    kernel: &Path,
    rootfs_copy: &Path,
    api_sock: &Path,
    console_log: &Path,
    vm_id: &str,
    opts: &DevBootOptions,
) -> Result<(f64, u32)> {
    let (mut proc, stdout) = spawn_fc_piped(fc, api_sock, vm_id, console_log).await?;

    // Tee guest serial (relayed on FC stdout) to console.log + a marker channel.
    let log = tokio::fs::File::create(console_log)
        .await
        .with_context(|| format!("creating {}", console_log.display()))?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, String)>();
    let drain = tokio::spawn(console::drain_serial(stdout, log, tx));

    // Pre-boot configuration.
    let client = proc.client().context("building the API client")?;
    configure_boot(&client, kernel, rootfs_copy).await?;

    // Boot, then measure from InstanceStart *returning* to the boot marker
    // appearing (the ~27 ms API round-trip is excluded, per the M0 methodology).
    client.instance_start().await.context("InstanceStart")?;
    let t_boot = Instant::now();
    let (boot_ms, ticks) = wait_for_markers(&mut rx, t_boot, opts.timeout).await;

    // Graceful shutdown, then let the drain task finish as the pipe closes.
    if let Err(e) = proc.shutdown(Duration::from_secs(2)).await {
        eprintln!("dev boot: warning: graceful shutdown returned: {e}");
    }
    let _ = drain.await;

    let boot_ms = boot_ms.ok_or_else(|| {
        anyhow!(
            "boot marker ISOPOD-BOOT-COMPLETE not observed within {:?}; serial log at {}",
            opts.timeout,
            console_log.display()
        )
    })?;
    if ticks < 2 {
        bail!(
            "only {ticks} TICK line(s) observed (need >= 2) within {:?}; serial log at {}",
            opts.timeout,
            console_log.display()
        );
    }
    Ok((boot_ms, ticks))
}

/// Consume serial lines until the boot marker plus two ticks are seen, or the
/// deadline passes. Returns `(boot_ms, ticks_seen)` where `boot_ms` is `Some`
/// once `ISOPOD-BOOT-COMPLETE` was observed.
async fn wait_for_markers(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<(Instant, String)>,
    t_boot: Instant,
    timeout: Duration,
) -> (Option<f64>, u32) {
    let deadline = t_boot + timeout;
    let mut boot_ms: Option<f64> = None;
    let mut ticks = 0u32;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match tokio::time::timeout(deadline - now, rx.recv()).await {
            Ok(Some((ts, line))) => {
                match console::classify_line(&line) {
                    console::Marker::BootComplete => {
                        if boot_ms.is_none() {
                            boot_ms =
                                Some(ts.saturating_duration_since(t_boot).as_secs_f64() * 1000.0);
                        }
                    }
                    console::Marker::Tick => ticks += 1,
                    console::Marker::Other => {}
                }
                if boot_ms.is_some() && ticks >= 2 {
                    break;
                }
            }
            // Serial closed (VMM exited) or deadline elapsed.
            Ok(None) | Err(_) => break,
        }
    }
    (boot_ms, ticks)
}

// ===========================================================================
// Ephemeral run flow (`isopod run`): boot -> vsock exec -> destroy.
// ===========================================================================

/// The default agent rootfs flavor slug for `isopod run`.
pub const DEFAULT_RUN_FLAVOR: &str = "dev-agent";

/// Options for [`run_ephemeral`].
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Command + arguments to run in the guest (`argv[0]` is the program).
    pub argv: Vec<String>,
    /// Extra environment variables to set for the command.
    pub env: Vec<(String, String)>,
    /// Working directory in the guest (agent default `/root` when `None`).
    pub cwd: Option<String>,
    /// Outer wall-clock budget in seconds (covers boot + exec; default 120).
    pub timeout_s: u64,
    /// Rootfs flavor to boot (the agent flavor, `dev-agent`, by default).
    pub flavor: RootfsFlavor,
    /// Keep the VM directory's throwaway rootfs copy instead of deleting it.
    pub keep: bool,
    /// Reserved for M4; ignored for now (control RPC is vsock, so exec works
    /// with or without a NIC).
    pub network: bool,
}

/// Result of a [`run_ephemeral`], serialized verbatim as `isopod run`'s JSON.
#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    /// Always `true` on the success path (the CLI emits `{ok:false,…}` on error).
    pub ok: bool,
    /// The generated VM id (`dev-<8 hex>`).
    pub vm_id: String,
    /// Process exit code (`null` if the command was killed by a signal).
    pub exit_code: Option<i32>,
    /// Terminating signal, if any.
    pub signal: Option<i32>,
    /// `true` if the timeout budget fired (in-guest or host-side wall clock).
    pub timed_out: bool,
    /// Captured stdout head (lossy UTF-8, capped at 64 KiB).
    pub stdout: String,
    /// Captured stderr head (lossy UTF-8, capped at 64 KiB).
    pub stderr: String,
    /// `true` if stdout exceeded the inline cap (full output is in the log).
    pub stdout_truncated: bool,
    /// `true` if stderr exceeded the inline cap (full output is in the log).
    pub stderr_truncated: bool,
    /// Total stdout bytes produced (regardless of the inline cap).
    pub stdout_bytes: u64,
    /// Total stderr bytes produced (regardless of the inline cap).
    pub stderr_bytes: u64,
    /// Exec duration in milliseconds (guest-reported, or host-measured on a
    /// host-side wall-clock timeout).
    pub exec_ms: u64,
    /// Total wall time of the whole run in milliseconds.
    pub total_ms: u64,
    /// The firecracker binary used and its provenance.
    pub fc_binary: FcBinary,
    /// Rootfs flavor booted (e.g. `dev-agent`).
    pub rootfs_flavor: String,
    /// Absolute path to the retained serial `console.log`.
    pub serial_log_path: PathBuf,
    /// Absolute path to the retained full stdout log.
    pub stdout_log_path: PathBuf,
    /// Absolute path to the retained full stderr log.
    pub stderr_log_path: PathBuf,
}

/// Compute the in-guest exec timeout from the outer budget and elapsed time,
/// floored at 1 ms (0 would be indistinguishable from "no limit" downstream).
fn exec_budget(outer_ms: u64, elapsed_ms: u64) -> u64 {
    outer_ms.saturating_sub(elapsed_ms).max(1)
}

/// Parse repeated `KEY=VALUE` env arguments (splitting on the first `=`; the
/// value may itself contain `=`). Rejects a missing `=` or an empty key.
///
/// # Errors
/// Returns an error naming the offending item if it is not `KEY=VALUE`.
pub fn parse_env_kv(items: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item.split_once('=') {
            Some(("", _)) => {
                bail!("invalid --env {item:?}: variable name must not be empty")
            }
            Some((k, v)) => out.push((k.to_string(), v.to_string())),
            None => bail!("invalid --env {item:?}: expected KEY=VALUE"),
        }
    }
    Ok(out)
}

/// Boot an ephemeral agent microVM, run one command over vsock, and destroy it.
///
/// Synchronous entry point (mirrors [`dev_boot`]): resolves artifacts (building
/// the flavor rootfs if absent), then drives the async lifecycle on an internal
/// current-thread runtime. Readiness is signalled by a vsock ping — *not* serial
/// markers — after which the host clock is pushed to the guest and the command
/// is executed with its output teed to `exec-stdout.log` / `exec-stderr.log` in
/// the VM directory. The rootfs copy is removed afterwards (unless
/// [`RunOptions::keep`]); the serial and exec logs are always retained.
///
/// # Errors
/// Returns an error if an artifact cannot be resolved, the VMM fails to boot,
/// the agent never becomes ready, or the exec RPC fails.
pub fn run_ephemeral(opts: RunOptions) -> Result<RunReport> {
    if opts.argv.is_empty() {
        bail!("run_ephemeral requires a non-empty argv");
    }
    let t_total = Instant::now();
    let fc = resolve_fc_bin()?;
    let kernel = resolve_kernel()?;
    let (rootfs, flavor_slug) = resolve_rootfs(opts.flavor)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(run_exec(fc, kernel, rootfs, flavor_slug, opts, t_total))
}

/// Async driver: create the VM dir, sparse-copy the rootfs, boot + exec, then
/// clean up the throwaway copy (keeping the logs).
async fn run_exec(
    fc: FcBinary,
    kernel: PathBuf,
    rootfs: PathBuf,
    flavor_slug: String,
    opts: RunOptions,
    t_total: Instant,
) -> Result<RunReport> {
    let vm_id = generate_vm_id()?;
    let vm_dir = paths::vms_dir()?.join(&vm_id);
    std::fs::create_dir_all(&vm_dir)
        .with_context(|| format!("creating VM dir {}", vm_dir.display()))?;

    let console_log = vm_dir.join("console.log");
    let stdout_log = vm_dir.join("exec-stdout.log");
    let stderr_log = vm_dir.join("exec-stderr.log");
    let rootfs_copy = vm_dir.join("rootfs.ext4");
    let api_sock = vm_dir.join("api.sock");
    let vsock_uds = vm_dir.join("vsock.sock");

    // Always boot a throwaway copy; the cached image must stay pristine.
    sparse_copy(&rootfs, &rootfs_copy)?;

    let driven = drive_exec(DriveExecCtx {
        fc: &fc,
        kernel: &kernel,
        rootfs_copy: &rootfs_copy,
        api_sock: &api_sock,
        vsock_uds: &vsock_uds,
        console_log: &console_log,
        stdout_log: &stdout_log,
        stderr_log: &stderr_log,
        vm_id: &vm_id,
        opts: &opts,
        t_total,
    })
    .await;

    // Remove the throwaway rootfs copy unless --keep; keep every log regardless.
    if !opts.keep {
        match std::fs::remove_file(&rootfs_copy) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "run: warning: could not remove {}: {e}",
                rootfs_copy.display()
            ),
        }
    }

    let exec = driven?;
    Ok(RunReport {
        ok: true,
        vm_id,
        exit_code: exec.exit_code,
        signal: exec.signal,
        timed_out: exec.timed_out,
        stdout: exec.stdout.lossy_string(),
        stderr: exec.stderr.lossy_string(),
        stdout_truncated: exec.stdout.truncated,
        stderr_truncated: exec.stderr.truncated,
        stdout_bytes: exec.stdout.total_bytes,
        stderr_bytes: exec.stderr.total_bytes,
        exec_ms: exec.exec_ms,
        total_ms: t_total.elapsed().as_millis() as u64,
        fc_binary: fc,
        rootfs_flavor: flavor_slug,
        serial_log_path: console_log,
        stdout_log_path: stdout_log,
        stderr_log_path: stderr_log,
    })
}

/// Everything [`drive_exec`] needs (bundled to keep the arg count sane).
struct DriveExecCtx<'a> {
    fc: &'a FcBinary,
    kernel: &'a Path,
    rootfs_copy: &'a Path,
    api_sock: &'a Path,
    vsock_uds: &'a Path,
    console_log: &'a Path,
    stdout_log: &'a Path,
    stderr_log: &'a Path,
    vm_id: &'a str,
    opts: &'a RunOptions,
    t_total: Instant,
}

/// The exec-flow's intermediate result (before it is folded into a [`RunReport`]).
struct ExecResult {
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    exec_ms: u64,
    stdout: StreamCapture,
    stderr: StreamCapture,
}

/// Boot the VM (with a vsock device), wait for the agent, sync the clock, run
/// the command, then halt. The VMM is always torn down before returning, even
/// on error (both via this function's explicit halt/shutdown and the
/// [`FcProcess`] drop guard).
async fn drive_exec(ctx: DriveExecCtx<'_>) -> Result<ExecResult> {
    let (mut proc, stdout_pipe) =
        spawn_fc_piped(ctx.fc, ctx.api_sock, ctx.vm_id, ctx.console_log).await?;

    // Tee guest serial to console.log (no marker channel — readiness is vsock).
    let log = tokio::fs::File::create(ctx.console_log)
        .await
        .with_context(|| format!("creating {}", ctx.console_log.display()))?;
    let drain = tokio::spawn(console::drain_to_log(stdout_pipe, log));

    // Pre-boot configuration, including the hybrid-vsock device.
    let client = proc.client().context("building the API client")?;
    configure_boot(&client, ctx.kernel, ctx.rootfs_copy).await?;
    client
        .put_vsock(&Vsock::new(3, ctx.vsock_uds.to_string_lossy()))
        .await
        .context("PUT /vsock")?;
    client.instance_start().await.context("InstanceStart")?;

    let agent = AgentClient::new(ctx.vsock_uds);

    // Do the exec inside an async block so we can guarantee halt+teardown runs
    // regardless of how the exec path resolves.
    let outcome = run_command(&agent, &ctx).await;

    // Best-effort in-guest halt, then wait for FC to exit; force if it hangs.
    let _ = agent.halt(true).await;
    match tokio::time::timeout(Duration::from_secs(3), proc.wait()).await {
        Ok(Ok(_status)) => {}
        _ => {
            if let Err(e) = proc.shutdown(Duration::from_secs(2)).await {
                eprintln!("run: warning: forced shutdown returned: {e}");
            }
        }
    }
    let _ = drain.await;

    outcome
}

/// Wait for readiness, sync the clock, then exec with a host-side wall-clock
/// safety net around the guest's own in-guest timeout.
async fn run_command(agent: &AgentClient, ctx: &DriveExecCtx<'_>) -> Result<ExecResult> {
    agent
        .wait_ready(AGENT_READY_TIMEOUT)
        .await
        .with_context(|| {
            format!(
                "guest agent did not answer a vsock ping within {AGENT_READY_TIMEOUT:?}; \
                 serial log at {}",
                ctx.console_log.display()
            )
        })?;
    agent
        .sync_clock_now()
        .await
        .context("syncing the guest clock over vsock")?;

    let outer_ms = ctx.opts.timeout_s.saturating_mul(1000);
    let elapsed_ms = ctx.t_total.elapsed().as_millis() as u64;
    let remaining_ms = exec_budget(outer_ms, elapsed_ms);
    let spec = ExecSpec {
        argv: ctx.opts.argv.clone(),
        env: ctx.opts.env.clone(),
        cwd: ctx.opts.cwd.clone(),
        timeout_ms: Some(remaining_ms),
        stdin: None,
        stdout_log: ctx.stdout_log.to_path_buf(),
        stderr_log: ctx.stderr_log.to_path_buf(),
        inline_cap: INLINE_CAP,
    };

    // Give the host wall a grace margin over the guest's own timeout so the
    // guest fires first and we get a clean ExecDone; the host wall only trips
    // if the guest is wedged.
    let t_exec = Instant::now();
    let wall = Duration::from_millis(remaining_ms) + Duration::from_secs(5);
    match tokio::time::timeout(wall, agent.exec(spec)).await {
        Ok(Ok(o)) => Ok(ExecResult {
            exit_code: o.exit_code,
            signal: o.signal,
            timed_out: o.timed_out,
            exec_ms: o.duration_ms,
            stdout: o.stdout,
            stderr: o.stderr,
        }),
        Ok(Err(e)) => Err(anyhow::Error::new(e).context("exec over vsock")),
        Err(_elapsed) => {
            // Host wall fired: the live stream was dropped, so recover whatever
            // was teed to the log files and report a timeout.
            let stdout = capture_from_log(ctx.stdout_log, INLINE_CAP).await?;
            let stderr = capture_from_log(ctx.stderr_log, INLINE_CAP).await?;
            Ok(ExecResult {
                exit_code: None,
                signal: None,
                timed_out: true,
                exec_ms: t_exec.elapsed().as_millis() as u64,
                stdout,
                stderr,
            })
        }
    }
}

/// Reconstruct a [`StreamCapture`] from a teed log file (used to recover output
/// after a host-side wall-clock timeout drops the live stream).
async fn capture_from_log(path: &Path, cap: usize) -> Result<StreamCapture> {
    match tokio::fs::read(path).await {
        Ok(data) => Ok(StreamCapture::from_bytes(&data, cap)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(StreamCapture::from_bytes(&[], cap))
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `exists` predicate matching a fixed allow-list of paths.
    fn exists_set<'a>(present: &'a [&'a str]) -> impl Fn(&Path) -> bool + 'a {
        move |p: &Path| present.iter().any(|s| Path::new(s) == p)
    }

    #[test]
    fn env_override_wins_when_present() {
        let bin = resolve_fc_bin_from(
            Some(PathBuf::from("/opt/fc")),
            PathBuf::from("/home/u/.isopod/bin/firecracker"),
            PathBuf::from("/home/u/.isopod/m0/bin/firecracker"),
            &exists_set(&[
                "/opt/fc",
                "/home/u/.isopod/bin/firecracker",
                "/home/u/.isopod/m0/bin/firecracker",
            ]),
        )
        .expect("env path resolves");
        assert_eq!(bin.path, PathBuf::from("/opt/fc"));
        assert_eq!(bin.provenance, FcProvenance::Env);
    }

    #[test]
    fn env_override_missing_is_an_error() {
        let err = resolve_fc_bin_from(
            Some(PathBuf::from("/opt/fc")),
            PathBuf::from("/home/u/.isopod/bin/firecracker"),
            PathBuf::from("/home/u/.isopod/m0/bin/firecracker"),
            &exists_set(&["/home/u/.isopod/m0/bin/firecracker"]),
        )
        .expect_err("missing env path must error");
        assert!(err.to_string().contains("ISOPOD_FC_BIN"));
    }

    #[test]
    fn vendored_build_preferred_over_m0() {
        let bin = resolve_fc_bin_from(
            None,
            PathBuf::from("/home/u/.isopod/bin/firecracker"),
            PathBuf::from("/home/u/.isopod/m0/bin/firecracker"),
            &exists_set(&[
                "/home/u/.isopod/bin/firecracker",
                "/home/u/.isopod/m0/bin/firecracker",
            ]),
        )
        .expect("vendored resolves");
        assert_eq!(bin.provenance, FcProvenance::VendoredBuild);
        assert_eq!(bin.path, PathBuf::from("/home/u/.isopod/bin/firecracker"));
    }

    #[test]
    fn falls_back_to_m0_when_only_m0_present() {
        let bin = resolve_fc_bin_from(
            None,
            PathBuf::from("/home/u/.isopod/bin/firecracker"),
            PathBuf::from("/home/u/.isopod/m0/bin/firecracker"),
            &exists_set(&["/home/u/.isopod/m0/bin/firecracker"]),
        )
        .expect("m0 resolves");
        assert_eq!(bin.provenance, FcProvenance::M0Release);
    }

    #[test]
    fn errors_when_no_binary_anywhere() {
        let err = resolve_fc_bin_from(
            None,
            PathBuf::from("/home/u/.isopod/bin/firecracker"),
            PathBuf::from("/home/u/.isopod/m0/bin/firecracker"),
            &exists_set(&[]),
        )
        .expect_err("no binary must error");
        assert!(err.to_string().contains("no firecracker binary"));
    }

    #[test]
    fn provenance_serializes_kebab_case() {
        assert_eq!(
            serde_json::to_value(FcProvenance::VendoredBuild).unwrap(),
            serde_json::json!("vendored-build")
        );
        assert_eq!(
            serde_json::to_value(FcProvenance::M0Release).unwrap(),
            serde_json::json!("m0-release")
        );
        assert_eq!(
            serde_json::to_value(FcProvenance::Env).unwrap(),
            serde_json::json!("env")
        );
    }

    #[test]
    fn generated_vm_id_is_valid_and_shaped() {
        let id = generate_vm_id().expect("urandom read");
        assert!(id.starts_with("dev-"), "id was {id}");
        assert_eq!(id.len(), 12, "dev- plus 8 hex chars");
        // Must satisfy the fc-client id charset.
        assert!(VmId::new(&id).is_ok(), "generated id must be a valid VmId");
    }

    #[test]
    fn parse_env_splits_on_first_equals() {
        let got = parse_env_kv(&["A=1".into(), "B=x=y".into(), "C=".into()]).unwrap();
        assert_eq!(
            got,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "x=y".to_string()),
                ("C".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn parse_env_rejects_bad_items() {
        assert!(parse_env_kv(&["NOEQUALS".into()]).is_err());
        assert!(parse_env_kv(&["=value".into()]).is_err());
    }

    #[test]
    fn exec_budget_subtracts_elapsed_and_floors_at_one() {
        assert_eq!(exec_budget(120_000, 5_000), 115_000);
        // Already over budget -> floored at 1 ms (never 0).
        assert_eq!(exec_budget(1_000, 5_000), 1);
        assert_eq!(exec_budget(1_000, 1_000), 1);
        // No elapsed time -> full budget.
        assert_eq!(exec_budget(120_000, 0), 120_000);
    }

    #[test]
    fn run_report_serializes_expected_shape() {
        let report = RunReport {
            ok: true,
            vm_id: "dev-abcd1234".into(),
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            stdout: "hi\n".into(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_bytes: 3,
            stderr_bytes: 0,
            exec_ms: 12,
            total_ms: 200,
            fc_binary: FcBinary {
                path: PathBuf::from("/x/firecracker"),
                provenance: FcProvenance::VendoredBuild,
            },
            rootfs_flavor: "dev-agent".into(),
            serial_log_path: PathBuf::from("/v/console.log"),
            stdout_log_path: PathBuf::from("/v/exec-stdout.log"),
            stderr_log_path: PathBuf::from("/v/exec-stderr.log"),
        };
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["exit_code"], serde_json::json!(0));
        assert_eq!(v["signal"], serde_json::Value::Null);
        assert_eq!(v["stdout"], serde_json::json!("hi\n"));
        assert_eq!(v["stdout_bytes"], serde_json::json!(3));
        assert_eq!(
            v["fc_binary"]["provenance"],
            serde_json::json!("vendored-build")
        );
        for key in [
            "ok",
            "vm_id",
            "exit_code",
            "signal",
            "timed_out",
            "stdout",
            "stderr",
            "stdout_truncated",
            "stderr_truncated",
            "stdout_bytes",
            "stderr_bytes",
            "exec_ms",
            "total_ms",
            "fc_binary",
            "rootfs_flavor",
            "serial_log_path",
            "stdout_log_path",
            "stderr_log_path",
        ] {
            assert!(v.get(key).is_some(), "RunReport JSON missing key {key:?}");
        }
    }
}
