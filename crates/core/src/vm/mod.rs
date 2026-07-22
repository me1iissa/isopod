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

use isopod_fc::models::{BootSource, Drive, MachineConfig, NetworkInterface, Vsock};
use isopod_fc::{FcClient, FcProcess, FcProcessConfig, LogLevel, StdioMode, VmId};

use crate::agent::{AgentClient, ExecSpec, StreamCapture};
use crate::image::{self, RootfsFlavor};
use crate::net;
use crate::paths;
use crate::snapshot::{self, SnapshotKey};
use crate::stage::{self, StageMeta};

mod build_fc;
mod console;
mod registry;
mod resources;

pub use build_fc::{build_fc, BinPaths, BuildFcOutcome};
pub use registry::{gc as vm_gc, list as vm_list, reap_orphans, GcReport, VmRecord};
pub use resources::{Resources, DEFAULT_MEM_MIB, DEFAULT_VCPUS};

/// Per-stream inline capture cap for `isopod run` (64 KiB, per the PLAN's
/// head-truncation policy); everything is still teed in full to the log files.
const INLINE_CAP: usize = 64 * 1024;

/// Guest-agent vsock readiness deadline after `InstanceStart`.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Exact optimized boot args (M0 `NOTES-boot.md`): `quiet` plus the i8042
/// keyboard-probe disables that reclaim ~440 ms of cold boot, matching the
/// fc-client live test verbatim.
pub(crate) const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda \
     init=/init quiet i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd 8250.nr_uarts=1";

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
    /// The generated VM id (`dev-<8 hex>`) — the stable primary key.
    pub vm_id: String,
    /// Human-memorable vanity name (seeded deterministically from `vm_id`).
    pub name: String,
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

/// Choose a vanity name for `vm_id` (unique among VMs recorded under the vms
/// dir) and persist `<vm_dir>/meta.json` with the instance metadata. The vm_id
/// stays the primary key; the name is the human/model-memorable handle.
fn assign_vanity_name(vm_id: &str, vm_dir: &Path, flavor: &str) -> Result<String> {
    let mut taken = std::collections::HashSet::new();
    if let Ok(entries) = std::fs::read_dir(vm_dir.parent().unwrap_or(vm_dir)) {
        for entry in entries.flatten() {
            let meta_path = entry.path().join("meta.json");
            if let Ok(raw) = std::fs::read_to_string(meta_path) {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if let Some(name) = meta.get("name").and_then(|v| v.as_str()) {
                        taken.insert(name.to_string());
                    }
                }
            }
        }
    }
    let name = crate::names::unique_name(vm_id, |n| taken.contains(n));
    let created_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let meta = serde_json::json!({
        "vm_id": vm_id,
        "name": name,
        "flavor": flavor,
        "created_unix": created_unix,
    });
    std::fs::write(vm_dir.join("meta.json"), format!("{meta}\n"))
        .with_context(|| format!("writing {}", vm_dir.join("meta.json").display()))?;
    Ok(name)
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
    let vanity = assign_vanity_name(&vm_id, &vm_dir, &rootfs_flavor)?;

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
        name: vanity,
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

/// Assemble the guest kernel command line for a run: the shared optimized
/// [`BOOT_ARGS`], plus ` isopod.layers=<N>` for the overlay topology, plus the
/// static net config (` isopod.net=… isopod.gw=… isopod.dns=…`) when a slot is
/// claimed. Split out so the arg contract is unit-testable without a live VM.
fn build_boot_args(disk: &DiskConfig, net: Option<&net::Slot>) -> String {
    let mut args = String::from(BOOT_ARGS);
    if let DiskConfig::Stage { layer_paths, .. } = disk {
        args.push_str(&format!(" isopod.layers={}", layer_paths.len()));
    }
    if let Some(slot) = net {
        args.push_str(&format!(
            " isopod.net={} isopod.gw={} isopod.dns={}",
            slot.guest_cidr(),
            slot.host_ip(),
            net::DEFAULT_DNS,
        ));
    }
    args
}

/// Pre-boot configuration for `isopod run`, dispatching on the disk topology.
///
/// `Flavor` reproduces the M2 single-ext4 root byte-for-byte. `Stage` puts the
/// squashfs base as the read-only root `vda`, each committed layer read-only in
/// root-first (oldest-first) order as `vdb..`, and the fresh writable scratch
/// last; it also appends ` isopod.layers=<N>` to the boot args so the guest
/// agent assembles the overlay. Drives appear in the guest as `/dev/vd{a,b,…}`
/// in PUT order, so the ordering here is the contract with the guest agent.
///
/// When `net` is `Some`, the claimed slot's tap is attached as `eth0` pre-boot
/// and its static config is baked into the boot args (the guest agent applies it
/// via ioctls); when `None` (`--no-network`) no NIC is attached at all.
///
/// `resources` sets the guest vCPU count and memory size (already host-validated
/// upstream in [`run_ephemeral`]).
async fn configure_run_boot(
    client: &FcClient,
    kernel: &Path,
    disk: &DiskConfig,
    resources: Resources,
    net: Option<&net::Slot>,
) -> Result<()> {
    client
        .put_machine_config(&MachineConfig::new(
            resources.vcpus,
            u64::from(resources.mem_mib),
        ))
        .await
        .context("PUT /machine-config")?;
    let args = build_boot_args(disk, net);
    client
        .put_boot_source(&BootSource::new(kernel.to_string_lossy(), args))
        .await
        .context("PUT /boot-source")?;
    match disk {
        DiskConfig::Flavor { rootfs_copy } => {
            client
                .put_drive(&Drive::virtio(
                    "rootfs",
                    rootfs_copy.to_string_lossy(),
                    true,
                    true,
                ))
                .await
                .context("PUT /drives/rootfs")?;
        }
        DiskConfig::Stage {
            base_sqfs,
            layer_paths,
            scratch,
            ..
        } => {
            // vda: squashfs base — read-only root device.
            client
                .put_drive(&Drive::virtio(
                    "base",
                    base_sqfs.to_string_lossy(),
                    true,
                    true,
                ))
                .await
                .context("PUT /drives/base")?;
            // vdb..: committed stage layers, read-only, oldest-first.
            for (i, layer) in layer_paths.iter().enumerate() {
                let id = format!("layer{i}");
                client
                    .put_drive(&Drive::virtio(
                        id.as_str(),
                        layer.to_string_lossy(),
                        false,
                        true,
                    ))
                    .await
                    .with_context(|| format!("PUT /drives/{id}"))?;
            }
            // last drive: fresh writable scratch (the overlay upperdir).
            client
                .put_drive(&Drive::virtio(
                    "scratch",
                    scratch.to_string_lossy(),
                    false,
                    false,
                ))
                .await
                .context("PUT /drives/scratch")?;
        }
    }
    // eth0: the claimed slot's host tap, with the slot's deterministic MAC.
    if let Some(slot) = net {
        let iface = NetworkInterface {
            iface_id: "eth0".to_string(),
            host_dev_name: slot.tap_name(),
            guest_mac: Some(slot.guest_mac()),
            mtu: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        };
        client
            .put_network_interface(&iface)
            .await
            .context("PUT /network-interfaces/eth0")?;
    }
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

/// Reserved `--stage` word: overlay topology with **zero** committed layers —
/// a fresh scratch straight on top of the squashfs base.
const STAGE_BASE: &str = "base";

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
    /// Ignored when [`stage`](Self::stage) is set (the overlay topology boots
    /// the squashfs base instead).
    pub flavor: RootfsFlavor,
    /// Keep the VM directory's throwaway disk copy instead of deleting it.
    pub keep: bool,
    /// Attach a NAT-egress NIC (default `true`). When set, a network slot is
    /// claimed (requiring `sudo isopod setup` to have run), the slot's tap is
    /// wired in pre-boot, and the guest is handed static net config on the
    /// kernel command line. `false` (`--no-network`) attaches no NIC at all;
    /// control RPC is vsock, so exec works identically either way.
    pub network: bool,
    /// Fork from a committed stage: its `stage_id`, vanity name, or unique label
    /// prefix. The reserved word `base` boots the overlay topology with zero
    /// layers (fresh from the squashfs base). `None` keeps the legacy dev-agent
    /// ext4 topology with no overlay (zero regression from M2).
    pub stage: Option<String>,
    /// After a clean run, commit the scratch upperdir as a new stage with this
    /// label. Only honoured in the overlay topology (requires [`stage`](Self::stage)).
    pub commit_as: Option<String>,
    /// Squashfs base image the overlay topology boots as `vda` (only used with
    /// [`stage`](Self::stage)): [`RootfsFlavor::BaseSqfs`] (busybox, default) or
    /// [`RootfsFlavor::BaseAlpine`] (python/node/git/gcc toolchain).
    pub base: RootfsFlavor,
    /// Bytes written to the command's stdin (then closed). `None` = no stdin.
    pub stdin: Option<Vec<u8>>,
    /// Requested guest vCPU count. Validated against the host CPU count (and
    /// Firecracker's 1-or-even rule) by [`resources::resolve`]; an out-of-range
    /// value is a hard error, never silently clamped. Use [`DEFAULT_VCPUS`] for
    /// the default.
    pub vcpus: u32,
    /// Requested guest memory in MiB. Validated against the host's free RAM
    /// (leaving headroom) by [`resources::resolve`]; an out-of-range value is a
    /// hard error, never silently clamped. Use [`DEFAULT_MEM_MIB`] for the
    /// default.
    pub mem_mib: u32,
    /// Requested writable scratch size in MiB — the overlay upperdir (the ext4
    /// scratch drive) of a `--stage` run. `None` uses [`stage::DEFAULT_SCRATCH_MIB`].
    /// Validated ([`MIN_SCRATCH_MIB`]..=[`MAX_SCRATCH_MIB`]) before boot; an
    /// out-of-range value is a hard error. Ignored by the legacy dev-agent
    /// topology and by warm resumes (which use a RAM/tmpfs upper) — passing it
    /// forces the cold ext4 path so the requested size always takes effect.
    pub scratch_mib: Option<u32>,
}

/// Which boot path served a run: a warm snapshot resume or a cold boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RunPath {
    /// The VM was resumed from a warm-pool memory snapshot.
    Warm,
    /// The VM was cold-booted (not warm-eligible, or a resume fell back).
    Cold,
}

/// Result of a [`run_ephemeral`], serialized verbatim as `isopod run`'s JSON.
#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    /// Always `true` on the success path (the CLI emits `{ok:false,…}` on error).
    pub ok: bool,
    /// The generated VM id (`dev-<8 hex>`) — the stable primary key.
    pub vm_id: String,
    /// Human-memorable vanity name (seeded deterministically from `vm_id`).
    pub name: String,
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
    /// Which boot path served this run (`warm` snapshot resume vs `cold` boot).
    pub path: RunPath,
    /// Snapshot-resume duration in milliseconds — the time from spawning the
    /// fresh Firecracker process through a ready, network-reconfigured guest.
    /// Present only on the warm path; compare against a cold run's `total_ms`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_ms: Option<u64>,
    /// Guest vCPU count the VM actually booted with (host-validated).
    pub vcpus: u32,
    /// Guest memory in MiB the VM actually booted with (host-validated).
    pub mem_mib: u32,
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
    /// The `stage_id` committed by `--commit-as` (present only when a stage was
    /// committed this run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage_id: Option<String>,
    /// The vanity name of the committed stage (present only alongside
    /// [`stage_id`](Self::stage_id)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage_name: Option<String>,
    /// The claimed network slot index (present only when networking is on).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<usize>,
    /// The guest's IP for this run (`10.107.<slot>.2`; present only when
    /// networking is on).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_ip: Option<String>,
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
    // Fail fast, before any artifact resolution or disk copy, if a networked run
    // was asked for but the host has not been set up.
    if opts.network {
        require_network_setup()?;
    }
    // Validate the requested resource shape against real host capacity *before*
    // booting anything: an over-cap request must error with no VM launched.
    let resources = resources::resolve_for_host(opts.vcpus, opts.mem_mib)?;
    // Validate the requested scratch size too (default when unset); an
    // out-of-range value errors here with no VM launched.
    let scratch_mib = resolve_scratch_mib(opts.scratch_mib)?;
    let t_total = Instant::now();
    let fc = resolve_fc_bin()?;
    let kernel = resolve_kernel()?;

    // `--stage` switches to the overlay topology (squashfs base + committed
    // layers + fresh scratch); without it, boot the legacy dev-agent ext4
    // exactly as M2 did (zero regression).
    let plan = match &opts.stage {
        Some(stage_ref) => resolve_stage_plan(stage_ref, opts.base)?,
        None => {
            let (rootfs, flavor_slug) = resolve_rootfs(opts.flavor)?;
            BootPlan::Flavor {
                rootfs,
                flavor_slug,
            }
        }
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(run_exec(
        fc,
        kernel,
        plan,
        resources,
        scratch_mib,
        opts,
        t_total,
    ))
}

/// How a run's guest disks are laid out. `Flavor` is the legacy single-ext4
/// root (no overlay); `Stage` is the overlay topology (squashfs base as `vda`,
/// N committed read-only stage layers `vdb..`, then a fresh writable scratch).
enum BootPlan {
    /// Legacy dev-agent ext4 root, no overlay.
    Flavor {
        /// Cached rootfs image to sparse-copy and boot.
        rootfs: PathBuf,
        /// Flavor slug reported in the [`RunReport`].
        flavor_slug: String,
    },
    /// Overlay topology.
    Stage {
        /// Squashfs base image (`vda`, read-only root).
        base_sqfs: PathBuf,
        /// Base flavor slug this run booted (recorded on any committed stage so
        /// forks reuse the same base — a chain must share one base).
        base_flavor: String,
        /// Committed layer artifacts, root-first (oldest-first) = the PUT order
        /// for `vdb..`.
        layer_paths: Vec<PathBuf>,
        /// The forked stage's `stage_id` (the commit parent); `None` for `base`.
        parent: Option<String>,
    },
}

/// Resolve a `--stage <ref>` into a [`BootPlan::Stage`]: locate the squashfs
/// base, and (unless `ref` is the reserved word `base`) resolve the stage and
/// its full layer chain.
fn resolve_stage_plan(stage_ref: &str, base: RootfsFlavor) -> Result<BootPlan> {
    // A fresh `--stage base` run uses the requested base flavor. Forking an
    // existing stage instead uses the stage's RECORDED base — the layers were
    // built against that base's root, so booting them on a different base would
    // produce a broken merge; the recorded base is authoritative and `--base` is
    // ignored for forks (removing a silent footgun).
    if stage_ref == STAGE_BASE {
        return Ok(BootPlan::Stage {
            base_sqfs: image::base_image_path(base)?,
            base_flavor: base.slug().to_string(),
            layer_paths: Vec::new(),
            parent: None,
        });
    }
    let meta = stage::resolve(stage_ref)?;
    let recorded_base = RootfsFlavor::from_slug(&meta.base)?;
    let layer_paths = stage::chain_paths(&meta)?;
    Ok(BootPlan::Stage {
        base_sqfs: image::base_image_path(recorded_base)?,
        base_flavor: meta.base.clone(),
        layer_paths,
        parent: Some(meta.stage_id),
    })
}

/// Async driver: create the VM dir, materialize the guest disks, boot + exec,
/// optionally commit the scratch as a stage, then clean up (keeping the logs).
async fn run_exec(
    fc: FcBinary,
    kernel: PathBuf,
    plan: BootPlan,
    resources: Resources,
    scratch_mib: u64,
    opts: RunOptions,
    t_total: Instant,
) -> Result<RunReport> {
    // Reap any firecracker orphaned by a previous run whose CLI was killed
    // before `kill_on_drop` could fire (Ctrl-C, MCP-client timeout, SIGKILL) —
    // otherwise its held tap wedges that network slot (dogfood finding #7).
    registry::reap_orphans();

    let vm_id = generate_vm_id()?;
    let vm_dir = paths::vms_dir()?.join(&vm_id);
    std::fs::create_dir_all(&vm_dir)
        .with_context(|| format!("creating VM dir {}", vm_dir.display()))?;
    // Record the owning CLI pid so the reaper can tell a live run's VMM from an
    // orphaned one regardless of process reparenting.
    let _ = std::fs::write(vm_dir.join("owner.pid"), std::process::id().to_string());

    let flavor_label = match &plan {
        BootPlan::Flavor { flavor_slug, .. } => flavor_slug.clone(),
        // Report the ACTUAL base the overlay booted (base-sqfs vs base-alpine),
        // not a hardcoded constant — a stage run on the Alpine toolchain base
        // must not mislabel itself as busybox (dogfood finding via MCP).
        BootPlan::Stage { base_flavor, .. } => base_flavor.clone(),
    };
    let vanity = assign_vanity_name(&vm_id, &vm_dir, &flavor_label)?;

    let console_log = vm_dir.join("console.log");
    let stdout_log = vm_dir.join("exec-stdout.log");
    let stderr_log = vm_dir.join("exec-stderr.log");
    let api_sock = vm_dir.join("api.sock");
    let vsock_uds = vm_dir.join("vsock.sock");

    // Warm-pool eligibility + key. Eligible iff `--stage base` (a fresh
    // base-squashfs overlay, zero layers), no `--commit-as`, and networking on.
    // Build the snapshot (if missing) BEFORE claiming the run's slot, so the
    // builder — which claims its own slot — and the run each need only one free
    // slot. A build failure silently disables warm for this run (cold-boot).
    let warm_key = match warm_snapshot_key(&fc, &kernel, &plan, resources, &opts) {
        Some(key) => match ensure_snapshot(&fc, &kernel, &plan, resources, &key).await {
            Ok(()) => Some(key),
            Err(e) => {
                eprintln!("run: warm-pool snapshot build failed ({e:#}); cold-booting");
                None
            }
        },
        None => None,
    };

    // Claim a network slot (default-on). The slot's Drop releases the lock, so
    // it must outlive the whole boot/exec/teardown — it stays live until this
    // function returns. `--no-network` attaches no NIC.
    let net_slot = if opts.network {
        Some(claim_network()?)
    } else {
        None
    };
    let (slot_index, guest_ip) = match &net_slot {
        Some(s) => (Some(s.index()), Some(s.guest_ip())),
        None => (None, None),
    };

    let boot = boot_and_exec(BootCtx {
        fc: &fc,
        kernel: &kernel,
        plan: &plan,
        resources,
        scratch_mib,
        warm_key: warm_key.as_ref(),
        net: net_slot.as_ref(),
        api_sock: &api_sock,
        vsock_uds: &vsock_uds,
        console_log: &console_log,
        stdout_log: &stdout_log,
        stderr_log: &stderr_log,
        vm_id: &vm_id,
        vm_dir: &vm_dir,
        opts: &opts,
        t_total,
    })
    .await;

    // Commit the scratch into the stage store (only a clean cold Stage run has a
    // scratch; a warm resume has no disk to commit) *before* removing it.
    let commit_outcome = match &boot.disk {
        Some(disk) => maybe_commit_stage(disk, &opts, &boot.exec),
        None => Ok(None),
    };

    // Remove throwaway disk(s) unless --keep; keep every log regardless.
    if !opts.keep {
        if let Some(disk) = &boot.disk {
            cleanup_disk(disk);
        }
    }

    // Surface a commit failure ahead of the exec result: the user explicitly
    // asked to persist the stage.
    let committed = commit_outcome?;
    let exec = boot.exec?;
    Ok(RunReport {
        ok: true,
        name: vanity,
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
        path: boot.path,
        resume_ms: boot.resume_ms,
        vcpus: resources.vcpus,
        mem_mib: resources.mem_mib,
        fc_binary: fc,
        rootfs_flavor: flavor_label,
        serial_log_path: console_log,
        stdout_log_path: stdout_log,
        stderr_log_path: stderr_log,
        stage_id: committed.as_ref().map(|m| m.stage_id.clone()),
        stage_name: committed.as_ref().map(|m| m.name.clone()),
        slot: slot_index,
        guest_ip,
    })
}

/// Compute the warm-pool snapshot key for a run, or `None` when the run is not
/// warm-eligible (or host detection failed — which simply means "cold-boot").
///
/// Warm-eligible iff `--stage base` (a fresh base-squashfs overlay with zero
/// committed layers), no `--commit-as` (the RAM upper has no scratch to commit),
/// no `--scratch-mib` (an explicit disk-backed scratch forces the cold ext4 path
/// so the requested size takes effect — a warm resume uses a RAM/tmpfs upper),
/// and networking on (resume retargets a NIC and re-IPs the guest). A stage
/// *fork*, a committing run, a sized-scratch run, or `--no-network` cold-boots
/// unchanged. A legacy `stage: None` (dev-agent ext4) run is intentionally
/// excluded: its rootfs differs from the base-squashfs warm shape.
fn warm_snapshot_key(
    fc: &FcBinary,
    kernel: &Path,
    plan: &BootPlan,
    resources: Resources,
    opts: &RunOptions,
) -> Option<SnapshotKey> {
    if !matches!(&opts.stage, Some(s) if s == STAGE_BASE) {
        return None;
    }
    if opts.commit_as.is_some() || !opts.network || opts.scratch_mib.is_some() {
        return None;
    }
    let BootPlan::Stage { base_flavor, .. } = plan else {
        return None;
    };
    match build_snapshot_key(fc, kernel, base_flavor, resources) {
        Ok(key) => Some(key),
        Err(e) => {
            eprintln!("run: could not compute the warm-pool key ({e:#}); cold-booting");
            None
        }
    }
}

/// Assemble a [`SnapshotKey`] from detected host facts plus the run's base flavor
/// and resource shape.
fn build_snapshot_key(
    fc: &FcBinary,
    kernel: &Path,
    base_flavor: &str,
    resources: Resources,
) -> Result<SnapshotKey> {
    let fc_build = snapshot::detect_fc_build(&fc.path)?;
    let cpu_model = snapshot::detect_cpu_model()?;
    let kernel_id = snapshot::kernel_identity(kernel)?;
    Ok(SnapshotKey::new(
        fc_build,
        kernel_id,
        cpu_model,
        base_flavor,
        resources,
    ))
}

/// Build the warm-pool snapshot for `key` (from the run's base-squashfs plan) if
/// it is not already present. A no-op if the snapshot exists.
async fn ensure_snapshot(
    fc: &FcBinary,
    kernel: &Path,
    plan: &BootPlan,
    resources: Resources,
    key: &SnapshotKey,
) -> Result<()> {
    let BootPlan::Stage { base_sqfs, .. } = plan else {
        bail!("warm-pool build requires the base-squashfs topology");
    };
    snapshot::ensure(&snapshot::BuildCtx {
        fc_bin: &fc.path,
        kernel,
        base_sqfs,
        resources,
        key,
    })
    .await
    .map(|_| ())
}

/// Result of `isopod warmpool build`, serialized verbatim as the CLI's stdout
/// JSON.
#[derive(Debug, Clone, Serialize)]
pub struct WarmpoolBuildReport {
    /// Always `true` on the success path.
    pub ok: bool,
    /// The snapshot directory-name hash.
    pub keyhash: String,
    /// A one-line human summary of the compatibility key.
    pub summary: String,
    /// The squashfs base flavor the snapshot boots.
    pub base: String,
    /// Guest vCPU count the snapshot was captured at.
    pub vcpus: u32,
    /// Guest memory (MiB) the snapshot was captured at.
    pub mem_mib: u32,
    /// `true` if a complete snapshot already existed (no rebuild performed).
    pub cached: bool,
    /// Size of the microVM state file in bytes.
    pub vmstate_bytes: u64,
    /// Size of the guest-memory file in bytes.
    pub memfile_bytes: u64,
    /// The snapshot directory (`~/.isopod/snapshots/<keyhash>`).
    pub snapshot_dir: PathBuf,
    /// Firecracker build identity in the key.
    pub fc_build: String,
    /// Guest-kernel identity in the key.
    pub kernel_id: String,
    /// Host CPU model in the key.
    pub cpu_model: String,
    /// Snapshot data-format version in the key.
    pub snapshot_format: String,
}

/// Force-build (or reuse) the warm-pool snapshot for a `(base, vcpus, mem_mib)`
/// configuration — the `isopod warmpool build` entry point.
///
/// Synchronous (mirrors [`run_ephemeral`]): resolves the firecracker binary,
/// guest kernel and base image, host-validates the resources, computes the
/// snapshot key on this host, then drives [`snapshot::ensure`] on an internal
/// runtime. Building boots a networked VM, so it requires the one-time host
/// setup (`sudo isopod setup`).
///
/// # Errors
/// If `base` is not a squashfs base, host setup has not run, an artifact cannot
/// be resolved, the resource shape is out of range, or the build fails.
pub fn warmpool_build(base: RootfsFlavor, vcpus: u32, mem_mib: u32) -> Result<WarmpoolBuildReport> {
    if !base.is_squashfs_base() {
        bail!(
            "--base {} is not a squashfs base (use base-sqfs or base-alpine)",
            base.slug()
        );
    }
    // Building attaches a NIC, so it needs the one-time host networking setup.
    require_network_setup()?;
    let resources = resources::resolve_for_host(vcpus, mem_mib)?;
    let fc = resolve_fc_bin()?;
    let kernel = resolve_kernel()?;
    let base_sqfs = image::base_image_path(base)?;
    let key = build_snapshot_key(&fc, &kernel, base.slug(), resources)?;
    let artifacts = snapshot::artifacts_for(&key)?;
    let cached = artifacts.is_complete();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(snapshot::ensure(&snapshot::BuildCtx {
        fc_bin: &fc.path,
        kernel: &kernel,
        base_sqfs: &base_sqfs,
        resources,
        key: &key,
    }))?;

    let vmstate_bytes = std::fs::metadata(&artifacts.vmstate)
        .map(|m| m.len())
        .unwrap_or(0);
    let memfile_bytes = std::fs::metadata(&artifacts.memfile)
        .map(|m| m.len())
        .unwrap_or(0);
    Ok(WarmpoolBuildReport {
        ok: true,
        keyhash: key.keyhash(),
        summary: key.summary(),
        base: base.slug().to_string(),
        vcpus: resources.vcpus,
        mem_mib: resources.mem_mib,
        cached,
        vmstate_bytes,
        memfile_bytes,
        snapshot_dir: artifacts.dir,
        fc_build: key.fc_build,
        kernel_id: key.kernel_id,
        cpu_model: key.cpu_model,
        snapshot_format: key.snapshot_format,
    })
}

/// Error out (naming the sudo command) if networking is requested but the
/// one-time host setup has not run. Cheap and side-effect-free, so it is called
/// early in [`run_ephemeral`] to fail fast before any disk is materialized.
///
/// # Errors
/// If `sudo isopod setup` has not created the slot manifest.
fn require_network_setup() -> Result<()> {
    if !net::setup_manifest_exists() {
        bail!(
            "networking requires one-time host setup that has not run.\n\
             Run it once (the only step that needs root):\n\
             \n    sudo isopod setup\n\n\
             or re-run this command with --no-network to boot without a NIC."
        );
    }
    // Setup ran, but tap devices do not survive a host/WSL2 restart. Detect the
    // evaporated-taps case here and name the fix, instead of failing deep in
    // boot with a raw Firecracker "Open tap device failed: Operation not
    // permitted / Invalid TUN/TAP Backend" that gives no hint (dogfood #13).
    if !net::provisioned_taps_present().context("checking provisioned tap devices")? {
        bail!(
            "networking was provisioned but its tap devices are missing — the \
             host was most likely restarted (WSL2 tears down tap devices on \
             restart). Re-provision it (the only step that needs root):\n\
             \n    sudo isopod setup\n\n\
             or re-run this command with --no-network to boot without a NIC."
        );
    }
    Ok(())
}

/// Lower bound on a requested [`RunOptions::scratch_mib`]; below this, ext4
/// metadata leaves too little usable space to be worth booting.
pub const MIN_SCRATCH_MIB: u32 = 128;

/// Upper bound on a requested [`RunOptions::scratch_mib`] (64 GiB). The scratch
/// image is sparse, but `mkfs.ext4` still lays out inode tables proportional to
/// the apparent size, so an unbounded request is refused.
pub const MAX_SCRATCH_MIB: u32 = 64 * 1024;

/// Validate an optional scratch-size request, returning the resolved size in MiB
/// ([`stage::DEFAULT_SCRATCH_MIB`] when unset). Never silently clamps — an
/// out-of-range request errors, matching the vcpus/mem_mib contract.
fn resolve_scratch_mib(requested: Option<u32>) -> Result<u64> {
    match requested {
        None => Ok(stage::DEFAULT_SCRATCH_MIB),
        Some(mib) if (MIN_SCRATCH_MIB..=MAX_SCRATCH_MIB).contains(&mib) => Ok(u64::from(mib)),
        Some(mib) => bail!(
            "requested scratch size {mib} MiB is out of range \
             ({MIN_SCRATCH_MIB}..={MAX_SCRATCH_MIB} MiB)"
        ),
    }
}

/// Claim a network slot for a networked run, requiring the one-time host setup.
///
/// Sweeps stale locks first (crash recovery), then claims the lowest free slot.
///
/// # Errors
/// If `sudo isopod setup` has not run (names the command), or every slot is in
/// use.
fn claim_network() -> Result<net::Slot> {
    require_network_setup()?;
    // Best-effort: reclaim slots orphaned by crashed runs before claiming.
    if let Err(e) = net::sweep_stale() {
        eprintln!("run: warning: stale-slot sweep failed (continuing): {e:#}");
    }
    net::claim()
}

/// The resolved, materialized guest-disk layout for one run.
enum DiskConfig {
    /// Legacy single-ext4 root (throwaway copy of a cached flavor image).
    Flavor {
        /// The booted throwaway rootfs copy (removed unless `--keep`).
        rootfs_copy: PathBuf,
    },
    /// Overlay topology.
    Stage {
        /// Squashfs base (`vda`, read-only root).
        base_sqfs: PathBuf,
        /// Base flavor slug (recorded on any stage committed from this run).
        base_flavor: String,
        /// Committed layers, root-first (the `vdb..` PUT order).
        layer_paths: Vec<PathBuf>,
        /// Fresh writable scratch (the overlay upperdir; removed unless `--keep`).
        scratch: PathBuf,
        /// Commit parent for `--commit-as` (`None` when forked from `base`).
        parent: Option<String>,
    },
}

/// Create the per-run disk artifacts named by `plan` inside `vm_dir`.
fn prepare_disk(plan: &BootPlan, vm_dir: &Path, scratch_mib: u64) -> Result<DiskConfig> {
    match plan {
        BootPlan::Flavor { rootfs, .. } => {
            let rootfs_copy = vm_dir.join("rootfs.ext4");
            sparse_copy(rootfs, &rootfs_copy)?;
            Ok(DiskConfig::Flavor { rootfs_copy })
        }
        BootPlan::Stage {
            base_sqfs,
            base_flavor,
            layer_paths,
            parent,
        } => {
            let scratch = vm_dir.join("scratch.ext4");
            stage::make_scratch_ext4(&scratch, scratch_mib)?;
            Ok(DiskConfig::Stage {
                base_sqfs: base_sqfs.clone(),
                base_flavor: base_flavor.clone(),
                layer_paths: layer_paths.clone(),
                scratch,
                parent: parent.clone(),
            })
        }
    }
}

/// Remove the run's throwaway disk (the flavor rootfs copy, or the scratch);
/// read-only base/committed-layer images are shared and never touched.
fn cleanup_disk(disk: &DiskConfig) {
    let throwaway = match disk {
        DiskConfig::Flavor { rootfs_copy } => rootfs_copy,
        DiskConfig::Stage { scratch, .. } => scratch,
    };
    match std::fs::remove_file(throwaway) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!(
            "run: warning: could not remove {}: {e}",
            throwaway.display()
        ),
    }
}

/// Commit the scratch as a new stage when `--commit-as` is set and the run
/// completed cleanly (overlay topology, exec succeeded, and did not time out —
/// a timed-out guest may have an unsynced scratch). Returns the committed stage
/// on success, `Ok(None)` when there is nothing to commit, and `Err` only if the
/// commit itself failed.
fn maybe_commit_stage(
    disk: &DiskConfig,
    opts: &RunOptions,
    driven: &Result<ExecResult>,
) -> Result<Option<StageMeta>> {
    let DiskConfig::Stage {
        scratch,
        parent,
        base_flavor,
        ..
    } = disk
    else {
        // Guard against a nonsensical --commit-as on the non-overlay topology.
        if opts.commit_as.is_some() {
            eprintln!("run: ignoring --commit-as: nothing to commit without --stage");
        }
        return Ok(None);
    };
    let Some(label) = &opts.commit_as else {
        return Ok(None);
    };
    let Ok(exec) = driven else {
        return Ok(None); // exec failed outright; nothing worth committing
    };
    if exec.timed_out {
        eprintln!(
            "run: not committing stage {label:?}: the exec timed out (scratch may be inconsistent)"
        );
        return Ok(None);
    }
    // Commit only a *successful* run: `--commit-as` expresses intent to capture a
    // known-good state, so committing after a failed command (e.g. a `pip install`
    // that errored) would silently produce a stage missing what the user meant to
    // bake in (dogfood finding). Non-zero exit → skip with a clear reason.
    if exec.exit_code != Some(0) {
        eprintln!(
            "run: not committing stage {label:?}: the command exited {} \
             (commit only captures a successful run; re-run so it exits 0 to commit)",
            exec.exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| format!("via signal {:?}", exec.signal))
        );
        return Ok(None);
    }
    let meta = stage::commit(scratch, label, parent.as_deref(), base_flavor)?;
    eprintln!(
        "run: committed stage {} ({}) labelled {:?}",
        meta.stage_id, meta.name, meta.label
    );
    Ok(Some(meta))
}

/// Everything [`boot_and_exec`] needs (bundled to keep the arg count sane).
struct BootCtx<'a> {
    fc: &'a FcBinary,
    kernel: &'a Path,
    /// The disk topology (materialized lazily on the cold path only).
    plan: &'a BootPlan,
    /// Host-validated vCPU / memory allocation for this VM.
    resources: Resources,
    /// Resolved writable-scratch size (MiB) for a cold Stage run's ext4 upper.
    scratch_mib: u64,
    /// The warm-pool snapshot key when this run is warm-eligible and its
    /// snapshot is present (`None` ⇒ always cold-boot).
    warm_key: Option<&'a SnapshotKey>,
    /// Claimed network slot (`None` for `--no-network`).
    net: Option<&'a net::Slot>,
    api_sock: &'a Path,
    vsock_uds: &'a Path,
    console_log: &'a Path,
    stdout_log: &'a Path,
    stderr_log: &'a Path,
    vm_id: &'a str,
    /// The run's VM directory (the resume path derives its socket paths from it).
    vm_dir: &'a Path,
    opts: &'a RunOptions,
    t_total: Instant,
}

/// The subset of a run [`run_command`] / [`exec_and_teardown`] need after the VM
/// is up (shared by the warm and cold boot paths).
struct ExecParams<'a> {
    opts: &'a RunOptions,
    console_log: &'a Path,
    stdout_log: &'a Path,
    stderr_log: &'a Path,
    t_total: Instant,
}

/// A booted-or-resumed VM ready for the shared exec tail.
struct BootedVm {
    proc: FcProcess,
    agent: AgentClient,
    /// Serial-drain task to await at teardown. The cold path spawns one; the
    /// warm path drains detached inside [`snapshot::resume`], so it is `None`.
    drain: Option<tokio::task::JoinHandle<()>>,
}

/// Outcome of [`boot_and_exec`]: the exec result plus which path served it and
/// (cold only) the materialized disk to commit/clean up.
struct BootOutcome {
    exec: Result<ExecResult>,
    path: RunPath,
    resume_ms: Option<u64>,
    disk: Option<DiskConfig>,
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

/// Bring a VM up (warm resume or cold boot), run the command, and tear it down.
///
/// Warm-eligible runs with a present snapshot resume it into the claimed slot;
/// **any** resume failure (a stale snapshot after a kernel/FC change, a missing
/// file, a load error) falls back SILENTLY to a cold boot — a resume problem
/// must never surface as a run error (WSL2 kernel auto-updates invalidate
/// snapshots in practice). The exec + halt + teardown tail is shared by both
/// paths.
async fn boot_and_exec(ctx: BootCtx<'_>) -> BootOutcome {
    let params = ExecParams {
        opts: ctx.opts,
        console_log: ctx.console_log,
        stdout_log: ctx.stdout_log,
        stderr_log: ctx.stderr_log,
        t_total: ctx.t_total,
    };

    // Warm path: resume the snapshot into the claimed slot.
    if let (Some(key), Some(slot)) = (ctx.warm_key, ctx.net) {
        let t_resume = Instant::now();
        match snapshot::resume(key, &ctx.fc.path, slot, ctx.vm_dir).await {
            Ok((proc, agent)) => {
                let resume_ms = t_resume.elapsed().as_millis() as u64;
                let vm = BootedVm {
                    proc,
                    agent,
                    drain: None,
                };
                let exec = exec_and_teardown(vm, &params).await;
                return BootOutcome {
                    exec,
                    path: RunPath::Warm,
                    resume_ms: Some(resume_ms),
                    disk: None,
                };
            }
            Err(e) => {
                eprintln!("run: warm resume failed ({e:#}); falling back to a cold boot");
            }
        }
    }

    // Cold path: materialize the disk, cold-boot, run.
    let disk = match prepare_disk(ctx.plan, ctx.vm_dir, ctx.scratch_mib) {
        Ok(d) => d,
        Err(e) => {
            return BootOutcome {
                exec: Err(e),
                path: RunPath::Cold,
                resume_ms: None,
                disk: None,
            };
        }
    };
    let vm = match cold_boot(&ctx, &disk).await {
        Ok(vm) => vm,
        Err(e) => {
            return BootOutcome {
                exec: Err(e),
                path: RunPath::Cold,
                resume_ms: None,
                disk: Some(disk),
            };
        }
    };
    let exec = exec_and_teardown(vm, &params).await;
    BootOutcome {
        exec,
        path: RunPath::Cold,
        resume_ms: None,
        disk: Some(disk),
    }
}

/// Cold-boot: spawn Firecracker, tee serial to `console.log`, configure the disk
/// topology + NIC + hybrid vsock, and start. Returns the running VM plus the
/// serial-drain handle to await at teardown.
async fn cold_boot(ctx: &BootCtx<'_>, disk: &DiskConfig) -> Result<BootedVm> {
    let (proc, stdout_pipe) =
        spawn_fc_piped(ctx.fc, ctx.api_sock, ctx.vm_id, ctx.console_log).await?;

    // Tee guest serial to console.log (no marker channel — readiness is vsock).
    let log = tokio::fs::File::create(ctx.console_log)
        .await
        .with_context(|| format!("creating {}", ctx.console_log.display()))?;
    let drain = tokio::spawn(console::drain_to_log(stdout_pipe, log));

    // Pre-boot configuration, including the hybrid-vsock device.
    let client = proc.client().context("building the API client")?;
    configure_run_boot(&client, ctx.kernel, disk, ctx.resources, ctx.net).await?;
    client
        .put_vsock(&Vsock::new(3, ctx.vsock_uds.to_string_lossy()))
        .await
        .context("PUT /vsock")?;
    client.instance_start().await.context("InstanceStart")?;

    let agent = AgentClient::new(ctx.vsock_uds);
    Ok(BootedVm {
        proc,
        agent,
        drain: Some(drain),
    })
}

/// Run the command against a booted-or-resumed VM, then always halt + tear the
/// VMM down (even on error, backed by the [`FcProcess`] drop guard).
async fn exec_and_teardown(mut vm: BootedVm, params: &ExecParams<'_>) -> Result<ExecResult> {
    let outcome = run_command(&vm.agent, params).await;

    // Best-effort in-guest halt, then wait for FC to exit; force if it hangs.
    let _ = vm.agent.halt(true).await;
    match tokio::time::timeout(Duration::from_secs(3), vm.proc.wait()).await {
        Ok(Ok(_status)) => {}
        _ => {
            if let Err(e) = vm.proc.shutdown(Duration::from_secs(2)).await {
                eprintln!("run: warning: forced shutdown returned: {e}");
            }
        }
    }
    if let Some(drain) = vm.drain {
        let _ = drain.await;
    }
    outcome
}

/// Wait for readiness, sync the clock, then exec with a host-side wall-clock
/// safety net around the guest's own in-guest timeout. The warm path already
/// pinged + resynced + reconfigured the network inside [`snapshot::resume`]; the
/// redundant ping/clock-sync here are cheap and idempotent, so a single tail
/// serves both boot paths.
async fn run_command(agent: &AgentClient, ctx: &ExecParams<'_>) -> Result<ExecResult> {
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
        stdin: ctx.opts.stdin.clone(),
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
    fn scratch_mib_resolves_default_and_enforces_bounds() {
        // Unset -> the module default.
        assert_eq!(resolve_scratch_mib(None).unwrap(), stage::DEFAULT_SCRATCH_MIB);
        // In-range values pass through unchanged (as u64).
        assert_eq!(
            resolve_scratch_mib(Some(MIN_SCRATCH_MIB)).unwrap(),
            u64::from(MIN_SCRATCH_MIB)
        );
        assert_eq!(resolve_scratch_mib(Some(4096)).unwrap(), 4096);
        assert_eq!(
            resolve_scratch_mib(Some(MAX_SCRATCH_MIB)).unwrap(),
            u64::from(MAX_SCRATCH_MIB)
        );
        // Out of range errors, never silently clamps.
        assert!(resolve_scratch_mib(Some(MIN_SCRATCH_MIB - 1)).is_err());
        assert!(resolve_scratch_mib(Some(MAX_SCRATCH_MIB + 1)).is_err());
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
            name: "radiant-gjallarhorn".into(),
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
            path: RunPath::Cold,
            resume_ms: None,
            vcpus: 1,
            mem_mib: 512,
            fc_binary: FcBinary {
                path: PathBuf::from("/x/firecracker"),
                provenance: FcProvenance::VendoredBuild,
            },
            rootfs_flavor: "dev-agent".into(),
            serial_log_path: PathBuf::from("/v/console.log"),
            stdout_log_path: PathBuf::from("/v/exec-stdout.log"),
            stderr_log_path: PathBuf::from("/v/exec-stderr.log"),
            stage_id: None,
            stage_name: None,
            slot: None,
            guest_ip: None,
        };
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["exit_code"], serde_json::json!(0));
        assert_eq!(v["signal"], serde_json::Value::Null);
        assert_eq!(v["stdout"], serde_json::json!("hi\n"));
        assert_eq!(v["stdout_bytes"], serde_json::json!(3));
        assert_eq!(v["vcpus"], serde_json::json!(1));
        assert_eq!(v["mem_mib"], serde_json::json!(512));
        // Cold path: `path` is "cold" and `resume_ms` is omitted entirely.
        assert_eq!(v["path"], serde_json::json!("cold"));
        assert!(
            v.get("resume_ms").is_none(),
            "resume_ms must be absent on the cold path"
        );
        assert_eq!(
            v["fc_binary"]["provenance"],
            serde_json::json!("vendored-build")
        );
        // The optional stage fields are omitted entirely when no stage was
        // committed (skip_serializing_if = Option::is_none).
        assert!(
            v.get("stage_id").is_none(),
            "stage_id must be absent when None"
        );
        assert!(
            v.get("stage_name").is_none(),
            "stage_name must be absent when None"
        );
        // Networking-off run: slot/guest_ip omitted entirely.
        assert!(v.get("slot").is_none(), "slot must be absent when None");
        assert!(
            v.get("guest_ip").is_none(),
            "guest_ip must be absent when None"
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
            "path",
            "vcpus",
            "mem_mib",
            "fc_binary",
            "rootfs_flavor",
            "serial_log_path",
            "stdout_log_path",
            "stderr_log_path",
        ] {
            assert!(v.get(key).is_some(), "RunReport JSON missing key {key:?}");
        }
    }

    #[test]
    fn run_report_includes_stage_fields_when_committed() {
        let report = RunReport {
            ok: true,
            name: "umbral-thorn".into(),
            vm_id: "dev-11223344".into(),
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_bytes: 0,
            stderr_bytes: 0,
            exec_ms: 3,
            total_ms: 120,
            path: RunPath::Warm,
            resume_ms: Some(18),
            vcpus: 2,
            mem_mib: 1024,
            fc_binary: FcBinary {
                path: PathBuf::from("/x/firecracker"),
                provenance: FcProvenance::VendoredBuild,
            },
            rootfs_flavor: "base-alpine".into(),
            serial_log_path: PathBuf::from("/v/console.log"),
            stdout_log_path: PathBuf::from("/v/exec-stdout.log"),
            stderr_log_path: PathBuf::from("/v/exec-stderr.log"),
            stage_id: Some("st-0123456789abcdef".into()),
            stage_name: Some("radiant-ghost".into()),
            slot: Some(3),
            guest_ip: Some("10.107.3.2".into()),
        };
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["rootfs_flavor"], serde_json::json!("base-alpine"));
        assert_eq!(v["vcpus"], serde_json::json!(2));
        assert_eq!(v["mem_mib"], serde_json::json!(1024));
        // Warm path: `path` is "warm" and `resume_ms` is present.
        assert_eq!(v["path"], serde_json::json!("warm"));
        assert_eq!(v["resume_ms"], serde_json::json!(18));
        assert_eq!(v["stage_id"], serde_json::json!("st-0123456789abcdef"));
        assert_eq!(v["stage_name"], serde_json::json!("radiant-ghost"));
        assert_eq!(v["slot"], serde_json::json!(3));
        assert_eq!(v["guest_ip"], serde_json::json!("10.107.3.2"));
    }

    #[test]
    fn build_boot_args_appends_layers_and_net() {
        // Flavor topology, no network: bare boot args.
        let flavor = DiskConfig::Flavor {
            rootfs_copy: PathBuf::from("/v/rootfs.ext4"),
        };
        assert_eq!(build_boot_args(&flavor, None), BOOT_ARGS);

        // Stage topology adds isopod.layers=<N>.
        let stage = DiskConfig::Stage {
            base_sqfs: PathBuf::from("/i/base.sqfs"),
            base_flavor: "base-sqfs".into(),
            layer_paths: vec![PathBuf::from("/a"), PathBuf::from("/b")],
            scratch: PathBuf::from("/v/scratch.ext4"),
            parent: None,
        };
        let args = build_boot_args(&stage, None);
        assert!(args.starts_with(BOOT_ARGS));
        assert!(args.contains(" isopod.layers=2"));
        assert!(!args.contains("isopod.net="));
    }
}
