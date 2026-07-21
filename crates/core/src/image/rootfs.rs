//! `isopod image build-rootfs` — assemble a guest rootfs and lay it down as a
//! sparse ext4 image, fully unprivileged.
//!
//! The M0 spike proved the unprivileged path: populate a directory, then
//! `mkfs.ext4 -d <dir> <img> <size>` as an ordinary user (the upstream
//! getting-started recipe needs `sudo mkfs.ext4 -d`, which this host cannot do).
//! CI kernels set `CONFIG_DEVTMPFS_MOUNT=y`, so `/dev/console` appears without any
//! `mknod`, and a shebang `/sbin/init` runs as PID 1 via `CONFIG_BINFMT_SCRIPT`.
//!
//! The module is structured so additional flavors (e.g. `alpine`, M2) slot in as
//! new [`RootfsFlavor`] variants with their own populate step, sharing the common
//! directory-assembly and mkfs plumbing.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::paths;

/// Default apparent size of the ext4 image (sparse on disk).
const ROOTFS_SIZE: &str = "64M";
/// Static musl busybox used by the M0 spike; the download fallback is pinned to
/// this digest.
const BUSYBOX_URL: &str = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox";
const BUSYBOX_SHA256: &str = "6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348";
/// Preferred host-provided busybox (Ubuntu ships a static build).
const SYSTEM_BUSYBOX: &str = "/bin/busybox";

/// Which rootfs to build.
///
/// * `dev-busybox` is the M1 smoke image (busybox init, serial `TICK`).
/// * `dev-agent` is the M2 image: the same busybox base, but `/sbin/init` is the
///   real `isopod-guest-agent` musl binary serving the vsock RPC.
/// * `base-sqfs` is the M3 stage base: the `dev-agent` population plus the empty
///   overlay mountpoints, packed **read-only with `mksquashfs`** into `base.sqfs`
///   (not `mkfs.ext4`) — the bottom layer of every stage overlay chain.
/// * `alpine` is reserved for the full toolchain agent rootfs (not yet built).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootfsFlavor {
    /// Minimal static-busybox image whose init emits `TICK <uptime>` on serial —
    /// the boot liveness signal `isopod dev boot` and the fc-client live test key on.
    DevBusybox,
    /// Busybox base with the `isopod-guest-agent` musl binary as `/sbin/init`:
    /// the M2 exec image. Boots the real PID 1 agent and serves exec/file RPC on
    /// vsock while emitting the same `ISOPOD-*` / `TICK` markers as `dev-busybox`.
    DevAgent,
    /// M3 stage base: the `dev-agent` population plus empty overlay mountpoints
    /// (`/rom`, `/overlay`, `/layers/0..9`, `/mnt`), packed read-only with
    /// `mksquashfs` into `base.sqfs`. The agent overlays committed stage layers
    /// and a writable scratch on top of it and pivots in.
    BaseSqfs,
    /// Alpine + toolchain agent rootfs (not yet implemented).
    Alpine,
}

impl RootfsFlavor {
    /// Stable on-disk / CLI slug for this flavor.
    pub fn slug(self) -> &'static str {
        match self {
            RootfsFlavor::DevBusybox => "dev-busybox",
            RootfsFlavor::DevAgent => "dev-agent",
            RootfsFlavor::BaseSqfs => "base-sqfs",
            RootfsFlavor::Alpine => "alpine",
        }
    }

    /// Parse a flavor from its CLI slug.
    pub fn from_slug(slug: &str) -> Result<Self> {
        match slug {
            "dev-busybox" => Ok(RootfsFlavor::DevBusybox),
            "dev-agent" => Ok(RootfsFlavor::DevAgent),
            "base-sqfs" => Ok(RootfsFlavor::BaseSqfs),
            "alpine" => Ok(RootfsFlavor::Alpine),
            other => {
                bail!(
                    "unknown rootfs flavor '{other}' \
                     (known: dev-busybox, dev-agent, base-sqfs, alpine)"
                )
            }
        }
    }
}

/// Result of [`build_rootfs`], serialized verbatim as the CLI's stdout JSON.
#[derive(Debug, Serialize)]
pub struct BuildRootfsOutcome {
    /// Always `true` on the success path.
    pub ok: bool,
    /// Absolute path to the image (ext4, or `base.sqfs` for `base-sqfs`).
    pub rootfs_path: PathBuf,
    /// Flavor slug that was built.
    pub flavor: String,
    /// Apparent (logical) size in bytes.
    pub bytes_apparent: u64,
    /// Allocated (on-disk) size in bytes — smaller than apparent because sparse.
    pub bytes_allocated: u64,
    /// Lowercase hex SHA-256 of the image file.
    pub sha256: String,
    /// `true` if the image already existed and the build was skipped.
    pub cached: bool,
}

/// Build (or reuse) the rootfs image for `flavor`.
///
/// Idempotent: an existing `~/.isopod/images/rootfs-<flavor>.ext4` is reused
/// unless `force` is set.
pub fn build_rootfs(flavor: RootfsFlavor, force: bool) -> Result<BuildRootfsOutcome> {
    let images = paths::images_dir()?;
    let dest = image_dest(&images, flavor);

    if dest.exists() && !force {
        eprintln!(
            "build-rootfs: {} already present, skipping build",
            dest.display()
        );
        return outcome_for(&dest, flavor, true);
    }

    // Assemble the rootfs tree in a temp dir alongside the destination.
    let assembly = tempfile::tempdir_in(&images).context("creating assembly dir")?;
    let root = assembly.path();
    assemble_common(root)?;
    match flavor {
        RootfsFlavor::DevBusybox => populate_dev_busybox(root)?,
        RootfsFlavor::DevAgent => populate_dev_agent(root)?,
        RootfsFlavor::BaseSqfs => populate_base_sqfs(root)?,
        RootfsFlavor::Alpine => bail!("alpine flavor is not implemented yet"),
    }

    // Pack into a temp image, then atomically rename into place. `base-sqfs` is a
    // read-only squashfs; every other flavor is a sparse ext4.
    let tmp_img = tempfile::NamedTempFile::new_in(&images).context("creating temp image")?;
    match flavor {
        RootfsFlavor::BaseSqfs => run_mksquashfs(root, tmp_img.path())?,
        _ => run_mkfs(Some(root), tmp_img.path(), ROOTFS_SIZE)?,
    }
    // fsync via a fresh handle: a packer may have re-created the inode.
    std::fs::File::open(tmp_img.path())
        .and_then(|f| f.sync_all())
        .context("fsync image")?;
    let (_, tmp_path) = tmp_img.keep().context("finalizing temp image")?;
    std::fs::rename(&tmp_path, &dest)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), dest.display()))?;

    outcome_for(&dest, flavor, false)
}

/// Destination image path for `flavor` under `images`: `base.sqfs` for the
/// squashfs stage base, `rootfs-<slug>.ext4` for the ext4 flavors.
fn image_dest(images: &Path, flavor: RootfsFlavor) -> PathBuf {
    match flavor {
        RootfsFlavor::BaseSqfs => images.join("base.sqfs"),
        other => images.join(format!("rootfs-{}.ext4", other.slug())),
    }
}

/// Build the JSON outcome for an existing image file.
fn outcome_for(dest: &Path, flavor: RootfsFlavor, cached: bool) -> Result<BuildRootfsOutcome> {
    let meta = std::fs::metadata(dest).with_context(|| format!("stat {}", dest.display()))?;
    Ok(BuildRootfsOutcome {
        ok: true,
        rootfs_path: dest.to_path_buf(),
        flavor: flavor.slug().to_string(),
        bytes_apparent: meta.len(),
        bytes_allocated: meta.blocks() * 512,
        sha256: paths::sha256_file(dest)?,
        cached,
    })
}

/// Pseudo-filesystem mountpoints every flavor needs. `/dev` is auto-mounted by
/// the kernel (devtmpfs) but the directory must exist first. `/tmp` and
/// `/var/tmp` get the sticky 1777 mode real tools expect (dogfood finding:
/// scripts assume a writable /tmp exists).
fn assemble_common(root: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for dir in ["proc", "sys", "dev", "etc", "var"] {
        std::fs::create_dir_all(root.join(dir)).with_context(|| format!("mkdir {dir}"))?;
    }
    for tmp in ["tmp", "var/tmp"] {
        let p = root.join(tmp);
        std::fs::create_dir_all(&p).with_context(|| format!("mkdir {tmp}"))?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o1777))
            .with_context(|| format!("chmod 1777 {tmp}"))?;
    }
    Ok(())
}

/// Populate the `dev-busybox` flavor: static busybox + a script init that emits
/// the `TICK` liveness signal via busybox `init` reading `/etc/inittab`.
fn populate_dev_busybox(root: &Path) -> Result<()> {
    write_dev_busybox_layout(root)?;
    provision_busybox(&root.join("bin/busybox"))?;
    Ok(())
}

/// Write everything for the `dev-busybox` layout *except* the busybox binary
/// (split out so it is unit-testable without a real busybox or network).
fn write_dev_busybox_layout(root: &Path) -> Result<()> {
    for dir in ["bin", "sbin"] {
        std::fs::create_dir_all(root.join(dir)).with_context(|| format!("mkdir {dir}"))?;
    }

    // /sbin/init — PID 1 via BINFMT_SCRIPT. Does the mounts + boot markers with
    // the exact commands the M0 spike proved, then hands off to busybox init so
    // /etc/inittab drives the respawning TICK loop.
    let init = "#!/bin/sh\n\
        /bin/busybox mount -t proc proc /proc\n\
        /bin/busybox mount -t sysfs sysfs /sys\n\
        /bin/busybox echo \"ISOPOD-INIT-START\"\n\
        /bin/busybox echo \"ISOPOD-BOOT-COMPLETE uptime=$(/bin/busybox cat /proc/uptime)\"\n\
        exec /bin/busybox init\n";
    write_exec(&root.join("sbin/init"), init)?;

    // /sbin/tick — respawned by busybox init, emits the serial liveness signal.
    let tick = "#!/bin/sh\n\
        while : ; do\n\
        \x20 /bin/busybox echo \"TICK $(/bin/busybox cat /proc/uptime)\"\n\
        \x20 /bin/busybox sleep 1\n\
        done\n";
    write_exec(&root.join("sbin/tick"), tick)?;

    // /etc/inittab — consumed by busybox init (empty id => actions run on the
    // system console, i.e. ttyS0).
    let inittab = "::sysinit:/bin/busybox echo ISOPOD-SYSINIT\n\
        ::respawn:/sbin/tick\n\
        ::ctrlaltdel:/bin/busybox reboot\n\
        ::shutdown:/bin/busybox echo ISOPOD-SHUTDOWN\n";
    std::fs::write(root.join("etc/inittab"), inittab).context("writing /etc/inittab")?;

    // /bin/sh -> busybox (needed for the shebang scripts) and /init -> /sbin/init
    // so the kernel finds init whether or not an explicit `init=` arg is passed.
    symlink_force(Path::new("busybox"), &root.join("bin/sh"))?;
    symlink_force(Path::new("sbin/init"), &root.join("init"))?;
    Ok(())
}

/// Busybox applets the `dev-agent` image symlinks onto `/bin/busybox` so exec
/// requests can PATH-resolve common commands (the agent's baseline `PATH`
/// includes `/bin`). The shell (`sh`) and `sleep` are load-bearing for the M2
/// exec tests; the rest are the everyday coreutils an agent workload expects.
const DEV_AGENT_APPLETS: &[&str] = &[
    "sh", "sleep", "echo", "cat", "ls", "env", "pwd", "true", "false", "printf", "head", "tail",
    "grep", "sed", "mkdir", "rmdir", "rm", "cp", "mv", "ln", "chmod", "sync", "mount", "umount",
    "uname", "id", "dd", "wc", "sort", "date", "touch", "stat",
];

/// Populate the `dev-agent` flavor: the busybox base of `dev-busybox`, but with
/// the real `isopod-guest-agent` musl binary installed as `/sbin/init`. The agent
/// is PID 1, so there is no busybox `init` / `inittab` — the agent does the
/// mounts, boot markers, `TICK` loop, and vsock RPC itself.
fn populate_dev_agent(root: &Path) -> Result<()> {
    let agent = locate_checked_agent()?;
    write_dev_agent_layout(root, &agent)?;
    provision_busybox(&root.join("bin/busybox"))?;
    Ok(())
}

/// Empty overlay mountpoint directories the `base-sqfs` image ships (relative to
/// the rootfs). `/rom` is reserved; `/overlay` is the scratch (writable upper)
/// mountpoint; `/mnt` is the pivot staging point. `/layers/0..9` are the stage
/// layer mountpoints (see [`BASE_LAYER_SLOTS`]).
const BASE_OVERLAY_DIRS: &[&str] = &["rom", "overlay", "mnt"];
/// Number of preallocated `/layers/<i>` stage mountpoints (`/layers/0..9`).
const BASE_LAYER_SLOTS: usize = 10;

/// Populate the `base-sqfs` flavor: the `dev-agent` population (agent as
/// `/sbin/init`, busybox applets, `/bin/sh`, `/root`) plus the empty overlay
/// mountpoints the stage topology pivots through. Packed read-only with
/// `mksquashfs` rather than `mkfs.ext4`.
fn populate_base_sqfs(root: &Path) -> Result<()> {
    let agent = locate_checked_agent()?;
    write_dev_agent_layout(root, &agent)?;
    provision_busybox(&root.join("bin/busybox"))?;
    write_base_overlay_dirs(root)?;
    Ok(())
}

/// Create the empty overlay mountpoints (`/rom`, `/overlay`, `/mnt`,
/// `/layers/0..9`) — split out so it is unit-testable without a busybox or agent.
fn write_base_overlay_dirs(root: &Path) -> Result<()> {
    for dir in BASE_OVERLAY_DIRS {
        std::fs::create_dir_all(root.join(dir)).with_context(|| format!("mkdir /{dir}"))?;
    }
    for i in 0..BASE_LAYER_SLOTS {
        let dir = root.join(format!("layers/{i}"));
        std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    }
    Ok(())
}

/// Locate the guest-agent musl binary and verify it is a static x86_64 ELF (a
/// dynamic binary would fail to run as PID 1 in the minimal guest).
fn locate_checked_agent() -> Result<PathBuf> {
    let agent = locate_guest_agent()?;
    if !elf_is_static_x86_64(&agent)? {
        bail!(
            "guest-agent binary {} is not a static x86_64 ELF; rebuild with \
             `cargo build --release --target x86_64-unknown-linux-musl -p isopod-guest-agent`",
            agent.display()
        );
    }
    Ok(agent)
}

/// Write the `dev-agent` layout *except* the busybox binary (split out so it is
/// unit-testable with a stand-in agent binary and no real busybox or network).
fn write_dev_agent_layout(root: &Path, agent_bin: &Path) -> Result<()> {
    for dir in ["bin", "sbin", "root"] {
        std::fs::create_dir_all(root.join(dir)).with_context(|| format!("mkdir {dir}"))?;
    }

    // /sbin/init IS the guest agent (a real ELF PID 1, not a shebang script).
    let init = root.join("sbin/init");
    std::fs::copy(agent_bin, &init)
        .with_context(|| format!("copying guest-agent {} -> sbin/init", agent_bin.display()))?;
    set_exec(&init)?;

    // /bin/sh and the applet set point at busybox; /init -> /sbin/init so the
    // kernel finds PID 1 whether or not an explicit `init=` arg is passed.
    symlink_force(Path::new("busybox"), &root.join("bin/sh"))?;
    for applet in DEV_AGENT_APPLETS {
        symlink_force(Path::new("busybox"), &root.join("bin").join(applet))?;
    }
    symlink_force(Path::new("sbin/init"), &root.join("init"))?;
    Ok(())
}

/// Locate the `isopod-guest-agent` static musl binary that becomes `/sbin/init`.
///
/// Resolution order:
/// 1. `ISOPOD_GUEST_AGENT_BIN` if set (explicit override).
/// 2. `$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/isopod-guest-agent`.
/// 3. `<workspace>/target/x86_64-unknown-linux-musl/release/isopod-guest-agent`.
///
/// Returns a clear "build it first" error if the binary is absent — the agent is
/// a separate compile target (`musl`) that the caller must produce beforehand.
fn locate_guest_agent() -> Result<PathBuf> {
    const REL: &str = "x86_64-unknown-linux-musl/release/isopod-guest-agent";
    const BUILD_HINT: &str =
        "cargo build --release --target x86_64-unknown-linux-musl -p isopod-guest-agent";

    if let Some(explicit) = std::env::var_os("ISOPOD_GUEST_AGENT_BIN") {
        let p = PathBuf::from(explicit);
        if !p.exists() {
            bail!(
                "ISOPOD_GUEST_AGENT_BIN points at {}, which does not exist; build it first: {BUILD_HINT}",
                p.display()
            );
        }
        return Ok(p);
    }

    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"));
    let bin = target_dir.join(REL);
    if !bin.exists() {
        bail!(
            "guest-agent musl binary not found at {}; build it first: {BUILD_HINT}",
            bin.display()
        );
    }
    Ok(bin)
}

/// Absolute path to the workspace root, derived from this crate's manifest dir
/// (`crates/core` → `..` → `..`).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Provide a static x86_64 busybox at `dest`: prefer the host's static build,
/// else download the pinned musl static binary. Always verified to be a
/// statically linked x86_64 ELF (a dynamic binary would fail in the guest).
fn provision_busybox(dest: &Path) -> Result<()> {
    let sys = Path::new(SYSTEM_BUSYBOX);
    if sys.exists() && elf_is_static_x86_64(sys).unwrap_or(false) {
        eprintln!("build-rootfs: using host {SYSTEM_BUSYBOX} (static x86_64)");
        std::fs::copy(sys, dest).with_context(|| format!("copying {SYSTEM_BUSYBOX}"))?;
        set_exec(dest)?;
        return Ok(());
    }

    eprintln!("build-rootfs: host busybox unusable; downloading pinned static musl busybox");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("isopod-image/0.1")
        .build()
        .context("building HTTP client")?;
    let bytes = client
        .get(BUSYBOX_URL)
        .send()
        .with_context(|| format!("GET {BUSYBOX_URL}"))?
        .error_for_status()
        .with_context(|| format!("GET {BUSYBOX_URL}"))?
        .bytes()
        .context("reading busybox body")?;

    let got = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    if got != BUSYBOX_SHA256 {
        bail!("busybox sha256 mismatch: expected {BUSYBOX_SHA256}, got {got}");
    }
    std::fs::write(dest, &bytes).context("writing busybox")?;
    set_exec(dest)?;
    if !elf_is_static_x86_64(dest)? {
        bail!("downloaded busybox is not a static x86_64 ELF");
    }
    Ok(())
}

/// Run `mkfs.ext4` unprivileged onto `img` sized `size`. With `dir = Some(d)` the
/// filesystem is prepopulated from `d` (`-d`); with `None` an empty filesystem is
/// laid down (the scratch/pool path). Journal is disabled and itable/journal init
/// is eager, matching the M0 recipe for deterministic prewarmed images. Note:
/// mkfs.ext4 requires options to precede the `device [size]` operands.
fn run_mkfs(dir: Option<&Path>, img: &Path, size: &str) -> Result<()> {
    let mut cmd = Command::new("mkfs.ext4");
    cmd.arg("-q")
        .args(["-O", "^has_journal"])
        .args(["-E", "lazy_itable_init=0,lazy_journal_init=0"]);
    if let Some(d) = dir {
        cmd.arg("-d").arg(d);
    }
    let out = cmd
        .arg(img)
        .arg(size)
        .output()
        .context("spawning mkfs.ext4 (is e2fsprogs installed?)")?;
    if !out.status.success() {
        bail!(
            "mkfs.ext4 failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Pack `root` into a read-only squashfs image at `img` with
/// `mksquashfs <root> <img> -all-root -noappend` (quiet). `-all-root` maps every
/// file to uid/gid 0 so the unprivileged build produces a root-owned image;
/// `-noappend` overwrites the pre-created temp file rather than appending.
fn run_mksquashfs(root: &Path, img: &Path) -> Result<()> {
    let out = Command::new("mksquashfs")
        .arg(root)
        .arg(img)
        .arg("-all-root")
        .arg("-noappend")
        .arg("-quiet")
        .arg("-no-progress")
        .output()
        .context("spawning mksquashfs (is squashfs-tools installed?)")?;
    if !out.status.success() {
        bail!(
            "mksquashfs failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Create a fresh, empty, writable **sparse ext4** image at `path` sized
/// `size_mib` mebibytes — the overlay *scratch* drive (and the prewarmed
/// empty-image pool) that the stage machinery layers a writable upper on.
///
/// Fully unprivileged: a sparse regular file laid out by `mkfs.ext4` with **no**
/// `-d` (the filesystem is empty), the journal disabled, and lazy inode-table /
/// journal init disabled so a prewarmed image boots deterministically without a
/// first-write init storm (the M0 recipe). Overwrites any existing file at
/// `path`.
///
/// # Errors
/// Fails if the file cannot be created or `mkfs.ext4` is missing / errors.
pub fn make_scratch_ext4(path: &Path, size_mib: u64) -> Result<()> {
    // Truncate/create the backing file; mkfs lays the fs out sparsely to `size`.
    std::fs::File::create(path)
        .with_context(|| format!("creating scratch image {}", path.display()))?;
    run_mkfs(None, path, &format!("{size_mib}M"))
}

/// Write `contents` to `path` and mark it executable (`0755`).
fn write_exec(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    set_exec(path)
}

/// Set mode `0755` on an existing file.
fn set_exec(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", path.display()))
}

/// Create `link -> target`, replacing any existing link.
fn symlink_force(target: &Path, link: &Path) -> Result<()> {
    if link.symlink_metadata().is_ok() {
        std::fs::remove_file(link).ok();
    }
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))
}

/// Best-effort check that `path` is a statically linked x86_64 ELF (no
/// `PT_INTERP` program header). Guards against baking a dynamic binary that would
/// fail to run in the minimal guest.
fn elf_is_static_x86_64(path: &Path) -> Result<bool> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    // ELF header is 64 bytes for ELF64.
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Ok(false);
    }
    if data[4] != 2 {
        return Ok(false); // not ELF64
    }
    let u16le = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
    let u64le = |o: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[o..o + 8]);
        u64::from_le_bytes(b)
    };
    if u16le(18) != 62 {
        return Ok(false); // e_machine != EM_X86_64
    }
    let phoff = u64le(32) as usize;
    let phentsize = u16le(54) as usize;
    let phnum = u16le(56) as usize;
    if phentsize == 0 {
        return Ok(false);
    }
    // PT_INTERP == 3 => dynamically linked.
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + 4 > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if p_type == 3 {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavor_slug_roundtrip() {
        for flavor in [
            RootfsFlavor::DevBusybox,
            RootfsFlavor::DevAgent,
            RootfsFlavor::BaseSqfs,
            RootfsFlavor::Alpine,
        ] {
            assert_eq!(RootfsFlavor::from_slug(flavor.slug()).unwrap(), flavor);
        }
        assert_eq!(
            RootfsFlavor::from_slug("base-sqfs").unwrap(),
            RootfsFlavor::BaseSqfs
        );
        assert!(RootfsFlavor::from_slug("nope").is_err());
    }

    #[test]
    fn base_sqfs_dest_is_squashfs_not_ext4() {
        let images = Path::new("/x/images");
        assert_eq!(
            image_dest(images, RootfsFlavor::BaseSqfs),
            images.join("base.sqfs")
        );
        assert_eq!(
            image_dest(images, RootfsFlavor::DevAgent),
            images.join("rootfs-dev-agent.ext4")
        );
    }

    #[test]
    fn base_overlay_dirs_present() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_base_overlay_dirs(root).unwrap();
        for d in ["rom", "overlay", "mnt"] {
            assert!(root.join(d).is_dir(), "missing overlay mountpoint /{d}");
        }
        for i in 0..BASE_LAYER_SLOTS {
            assert!(
                root.join(format!("layers/{i}")).is_dir(),
                "missing stage mountpoint /layers/{i}"
            );
        }
    }

    #[test]
    fn make_scratch_ext4_writes_valid_sparse_superblock() {
        // Hermetic skip when e2fsprogs is unavailable.
        if Command::new("mkfs.ext4").arg("-V").output().is_err() {
            eprintln!("SKIP make_scratch_ext4 test: mkfs.ext4 not found");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("scratch.ext4");
        make_scratch_ext4(&img, 16).expect("mkfs scratch");

        let meta = std::fs::metadata(&img).unwrap();
        assert_eq!(meta.len(), 16 * 1024 * 1024, "apparent size is 16 MiB");
        // On-disk allocation far below apparent size ⇒ the empty image is sparse.
        assert!(
            meta.blocks() * 512 < meta.len(),
            "empty scratch image should be sparse"
        );
        // ext4 superblock magic 0xEF53 (little-endian) at byte offset 0x438.
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&img).unwrap();
        f.seek(SeekFrom::Start(0x438)).unwrap();
        let mut magic = [0u8; 2];
        f.read_exact(&mut magic).unwrap();
        assert_eq!(magic, [0x53, 0xEF], "ext4 superblock magic present");
    }

    #[test]
    fn dev_agent_layout_installs_agent_as_init() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assemble_common(root).unwrap();

        // Stand-in for the real musl agent — the layout copies whatever bytes it
        // is handed; the ELF static-check lives in `populate_dev_agent`.
        let fake_agent = dir.path().join("fake-agent");
        std::fs::write(&fake_agent, b"\x7fELF fake agent bytes").unwrap();
        write_dev_agent_layout(root, &fake_agent).unwrap();

        // /sbin/init is a regular executable file (the copied agent), NOT a
        // shebang script and NOT a symlink.
        let init = root.join("sbin/init");
        let meta = std::fs::symlink_metadata(&init).unwrap();
        assert!(meta.file_type().is_file(), "sbin/init must be a real file");
        assert!(
            meta.permissions().mode() & 0o111 != 0,
            "sbin/init must be executable"
        );
        assert_eq!(
            std::fs::read(&init).unwrap(),
            b"\x7fELF fake agent bytes",
            "sbin/init must be the agent binary bytes"
        );

        // No busybox init machinery for this flavor.
        assert!(
            !root.join("etc/inittab").exists(),
            "dev-agent must not ship an inittab (agent is PID 1)"
        );
        assert!(!root.join("sbin/tick").exists());

        // /init -> /sbin/init, /bin/sh -> busybox, and the applet set is present.
        assert!(root
            .join("init")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        for applet in ["sh", "sleep", "echo"] {
            let link = root.join("bin").join(applet);
            assert!(
                link.symlink_metadata().unwrap().file_type().is_symlink(),
                "/bin/{applet} must be a busybox symlink"
            );
            assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("busybox"));
        }

        // Default exec cwd exists.
        assert!(root.join("root").is_dir(), "/root must exist (default cwd)");
    }

    #[test]
    fn layout_has_executable_init_and_inittab() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assemble_common(root).unwrap();
        write_dev_busybox_layout(root).unwrap();

        // init present + executable.
        let init = root.join("sbin/init");
        let meta = std::fs::metadata(&init).unwrap();
        assert!(meta.is_file(), "sbin/init must be a regular file");
        assert!(
            meta.permissions().mode() & 0o111 != 0,
            "sbin/init must be executable"
        );

        // init emits the boot markers and hands off to busybox init.
        let init_body = std::fs::read_to_string(&init).unwrap();
        assert!(init_body.starts_with("#!/bin/sh"));
        assert!(init_body.contains("ISOPOD-BOOT-COMPLETE"));
        assert!(init_body.contains("exec /bin/busybox init"));

        // inittab respawns the tick loop.
        let inittab = std::fs::read_to_string(root.join("etc/inittab")).unwrap();
        assert!(inittab.contains("::respawn:/sbin/tick"));
        assert!(inittab.contains("::sysinit:"));

        // tick emits the TICK liveness signal.
        let tick = std::fs::read_to_string(root.join("sbin/tick")).unwrap();
        assert!(tick.contains("TICK $(/bin/busybox cat /proc/uptime)"));
        assert!(
            std::fs::metadata(root.join("sbin/tick"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111
                != 0
        );

        // pseudo-fs mountpoints and /bin/sh symlink exist.
        for d in ["proc", "sys", "dev", "tmp"] {
            assert!(root.join(d).is_dir(), "missing mountpoint /{d}");
        }
        assert!(root
            .join("bin/sh")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(root
            .join("init")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn elf_check_rejects_non_elf() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("notelf");
        std::fs::write(&f, b"#!/bin/sh\necho hi\n").unwrap();
        assert!(!elf_is_static_x86_64(&f).unwrap());
    }
}
