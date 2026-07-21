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

use isopod_fc::models::{BootSource, Drive, MachineConfig};
use isopod_fc::{FcProcess, FcProcessConfig, LogLevel, StdioMode, VmId};

use crate::image::{self, RootfsFlavor};
use crate::paths;

mod build_fc;
mod console;

pub use build_fc::{build_fc, BinPaths, BuildFcOutcome};

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
}

impl Default for DevBootOptions {
    fn default() -> Self {
        Self {
            keep: false,
            timeout: DEFAULT_BOOT_TIMEOUT,
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
    let (rootfs, rootfs_flavor) = resolve_rootfs()?;

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

/// Resolve the dev rootfs image, building it unprivileged if absent. Returns the
/// image path and its flavor slug.
fn resolve_rootfs() -> Result<(PathBuf, String)> {
    let images = paths::images_dir()?;
    let dest = images.join(format!("rootfs-{}.ext4", DEV_FLAVOR.slug()));
    if dest.exists() {
        return Ok((dest, DEV_FLAVOR.slug().to_string()));
    }
    eprintln!(
        "dev boot: no rootfs present; building `{}` unprivileged…",
        DEV_FLAVOR.slug()
    );
    let out = image::build_rootfs(DEV_FLAVOR, false)?;
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
    let id = VmId::new(vm_id).map_err(|e| anyhow!("generated an invalid VM id {vm_id:?}: {e}"))?;

    // Send Firecracker's own structured logs to a sibling file so console.log
    // holds pure guest serial. Guest ttyS0 is relayed to FC stdout regardless.
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

    // Tee guest serial (relayed on FC stdout) to console.log + a marker channel.
    let stdout = proc
        .child_mut()
        .stdout
        .take()
        .ok_or_else(|| anyhow!("firecracker stdout was not piped"))?;
    let log = tokio::fs::File::create(console_log)
        .await
        .with_context(|| format!("creating {}", console_log.display()))?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, String)>();
    let drain = tokio::spawn(console::drain_serial(stdout, log, tx));

    // Pre-boot configuration.
    let client = proc.client().context("building the API client")?;
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
            rootfs_copy.to_string_lossy(),
            true,
            true,
        ))
        .await
        .context("PUT /drives/rootfs")?;

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
}
