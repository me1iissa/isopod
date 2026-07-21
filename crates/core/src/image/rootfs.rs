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

/// Which rootfs to build. `dev-busybox` is the M1 smoke image; `alpine` is
/// reserved for M2 (the real agent rootfs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootfsFlavor {
    /// Minimal static-busybox image whose init emits `TICK <uptime>` on serial —
    /// the boot liveness signal `isopod dev boot` and the fc-client live test key on.
    DevBusybox,
    /// Alpine + toolchain agent rootfs (not yet implemented — M2).
    Alpine,
}

impl RootfsFlavor {
    /// Stable on-disk / CLI slug for this flavor.
    pub fn slug(self) -> &'static str {
        match self {
            RootfsFlavor::DevBusybox => "dev-busybox",
            RootfsFlavor::Alpine => "alpine",
        }
    }

    /// Parse a flavor from its CLI slug.
    pub fn from_slug(slug: &str) -> Result<Self> {
        match slug {
            "dev-busybox" => Ok(RootfsFlavor::DevBusybox),
            "alpine" => Ok(RootfsFlavor::Alpine),
            other => bail!("unknown rootfs flavor '{other}' (known: dev-busybox, alpine)"),
        }
    }
}

/// Result of [`build_rootfs`], serialized verbatim as the CLI's stdout JSON.
#[derive(Debug, Serialize)]
pub struct BuildRootfsOutcome {
    /// Always `true` on the success path.
    pub ok: bool,
    /// Absolute path to the ext4 image.
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
    let dest = images.join(format!("rootfs-{}.ext4", flavor.slug()));

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
        RootfsFlavor::Alpine => bail!("alpine flavor is not implemented yet (M2)"),
    }

    // mkfs into a temp image, then atomically rename into place.
    let tmp_img = tempfile::NamedTempFile::new_in(&images).context("creating temp image")?;
    run_mkfs(root, tmp_img.path(), ROOTFS_SIZE)?;
    tmp_img.as_file().sync_all().context("fsync rootfs image")?;
    let (_, tmp_path) = tmp_img.keep().context("finalizing temp image")?;
    std::fs::rename(&tmp_path, &dest)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), dest.display()))?;

    outcome_for(&dest, flavor, false)
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
/// the kernel (devtmpfs) but the directory must exist first.
fn assemble_common(root: &Path) -> Result<()> {
    for dir in ["proc", "sys", "dev", "tmp", "etc"] {
        std::fs::create_dir_all(root.join(dir)).with_context(|| format!("mkdir {dir}"))?;
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

/// Run `mkfs.ext4 -d <root> <img> <size>` unprivileged. Journal is disabled and
/// itable/journal init is eager, matching the M0 recipe for deterministic images.
/// Note: mkfs.ext4 requires options to precede the `device [size]` operands.
fn run_mkfs(root: &Path, img: &Path, size: &str) -> Result<()> {
    let out = Command::new("mkfs.ext4")
        .arg("-q")
        .args(["-O", "^has_journal"])
        .args(["-E", "lazy_itable_init=0,lazy_journal_init=0"])
        .arg("-d")
        .arg(root)
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
        assert_eq!(
            RootfsFlavor::from_slug("dev-busybox").unwrap(),
            RootfsFlavor::DevBusybox
        );
        assert_eq!(
            RootfsFlavor::from_slug("alpine").unwrap(),
            RootfsFlavor::Alpine
        );
        assert!(RootfsFlavor::from_slug("nope").is_err());
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
