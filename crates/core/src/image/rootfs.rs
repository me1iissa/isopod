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
use serde::{Deserialize, Serialize};

use crate::paths;

/// Default apparent size of the ext4 image (sparse on disk).
const ROOTFS_SIZE: &str = "64M";
/// Static musl busybox used by the M0 spike; the download fallback is pinned to
/// this digest.
const BUSYBOX_URL: &str = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox";
const BUSYBOX_SHA256: &str = "6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348";
/// Preferred host-provided busybox (Ubuntu ships a static build).
const SYSTEM_BUSYBOX: &str = "/bin/busybox";

// ---- base-alpine flavor pins -------------------------------------------------
//
// The `base-alpine` dev base is assembled with Alpine's `apk.static` against a
// pinned stable branch. Three things are pinned for reproducibility: the branch,
// and the two bootstrap packages (`apk-tools-static` and `alpine-keys`) by version
// **and** sha256.
//
// To bump: pick the new stable branch from <https://dl-cdn.alpinelinux.org/alpine/>,
// point `ALPINE_BRANCH` at it, then find the versions that branch serves under
// `<branch>/main/x86_64/` for `apk-tools-static-*.apk` and `alpine-keys-*.apk`,
// download each, run `sha256sum`, and re-pin the four constants below. The package
// set is a rolling reference of what that branch ships — no digest to bump there.

/// Pinned Alpine stable branch for the `base-alpine` flavor.
const ALPINE_BRANCH: &str = "v3.24";
/// Alpine CDN mirror root; the main/community repositories derive from the branch.
const ALPINE_CDN: &str = "https://dl-cdn.alpinelinux.org/alpine";

/// `apk-tools-static` package version (ships the static `apk.static` bootstrapper).
const APK_TOOLS_STATIC_VERSION: &str = "3.0.6-r0";
/// sha256 of `apk-tools-static-<version>.apk` under `<branch>/main/x86_64/`.
const APK_TOOLS_STATIC_SHA256: &str =
    "a62f54609910d1eb23d8ebcf69dd7954280fe76047452bb88410122cbca14a6e";
/// `alpine-keys` package version (the repository-signing public keys).
const ALPINE_KEYS_VERSION: &str = "2.6-r0";
/// sha256 of `alpine-keys-<version>.apk` under `<branch>/main/x86_64/`.
const ALPINE_KEYS_SHA256: &str = "dd211936d544f4050924ce8aec078d24e7b1b036ae70b30bd07867349587c708";

/// Packages installed into the `base-alpine` dev rootfs: the base layout + busybox
/// userland, a Python and Node toolchain, git, a C build toolchain (make + cmake),
/// and GNU coreutils — the everyday tools an agent workload builds and runs code
/// with. GNU coreutils covers the flag surface busybox applets lack (e.g.
/// `cp --sparse=always`, which isopod's own test suite needs in-guest); cmake was
/// long *documented* as present but never actually shipped (dogfood finding).
const ALPINE_PACKAGES: &[&str] = &[
    "alpine-baselayout",
    "busybox",
    "coreutils",
    "python3",
    "py3-pip",
    "nodejs",
    "npm",
    "git",
    "gcc",
    "musl-dev",
    "make",
    "cmake",
];

/// Public DNS resolvers baked into the guest `/etc/resolv.conf` (PLAN: DNS is
/// public resolvers, not host-derived).
const RESOLV_CONF: &str = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";

/// Which rootfs to build.
///
/// * `dev-busybox` is the M1 smoke image (busybox init, serial `TICK`).
/// * `dev-agent` is the M2 image: the same busybox base, but `/sbin/init` is the
///   real `isopod-guest-agent` musl binary serving the vsock RPC.
/// * `base-sqfs` is the M3 stage base: the `dev-agent` population plus the empty
///   overlay mountpoints, packed **read-only with `mksquashfs`** into `base.sqfs`
///   (not `mkfs.ext4`) — the bottom layer of every stage overlay chain.
/// * `base-alpine` is the full Alpine dev base: `apk.static` installs a Python +
///   Node + git + C toolchain, the guest agent is `/sbin/init`, the overlay
///   mountpoints are pre-created, and the tree is packed read-only with
///   `mksquashfs` into `base-alpine.sqfs` — a drop-in stage base alongside
///   `base.sqfs` but with a real toolchain instead of just busybox.
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
    /// Full Alpine dev base: an `apk.static`-installed Python/Node/git/C
    /// toolchain with the guest agent as `/sbin/init` and the overlay
    /// mountpoints, packed read-only with `mksquashfs` into `base-alpine.sqfs`.
    /// A richer drop-in alternative to [`RootfsFlavor::BaseSqfs`].
    BaseAlpine,
}

impl RootfsFlavor {
    /// Every flavor, in build order — the working set of `isopod image build-all`
    /// and `isopod image ls`. A `PROTO_VERSION` bump must rebuild all of these
    /// together (finding #17).
    pub const ALL: [RootfsFlavor; 4] = [
        RootfsFlavor::DevBusybox,
        RootfsFlavor::DevAgent,
        RootfsFlavor::BaseSqfs,
        RootfsFlavor::BaseAlpine,
    ];

    /// `true` for flavors that embed the guest agent (and therefore speak a
    /// specific `PROTO_VERSION`); `dev-busybox` is the agent-less M1 smoke image.
    pub fn has_agent(self) -> bool {
        !matches!(self, RootfsFlavor::DevBusybox)
    }

    /// Stable on-disk / CLI slug for this flavor.
    pub fn slug(self) -> &'static str {
        match self {
            RootfsFlavor::DevBusybox => "dev-busybox",
            RootfsFlavor::DevAgent => "dev-agent",
            RootfsFlavor::BaseSqfs => "base-sqfs",
            RootfsFlavor::BaseAlpine => "base-alpine",
        }
    }

    /// Parse a flavor from its CLI slug.
    pub fn from_slug(slug: &str) -> Result<Self> {
        match slug {
            "dev-busybox" => Ok(RootfsFlavor::DevBusybox),
            "dev-agent" => Ok(RootfsFlavor::DevAgent),
            "base-sqfs" => Ok(RootfsFlavor::BaseSqfs),
            "base-alpine" => Ok(RootfsFlavor::BaseAlpine),
            other => {
                bail!(
                    "unknown rootfs flavor '{other}' \
                     (known: dev-busybox, dev-agent, base-sqfs, base-alpine)"
                )
            }
        }
    }

    /// `true` for the read-only squashfs **base** flavors that a stage overlay
    /// chain can boot as its `vda` root ([`RootfsFlavor::BaseSqfs`],
    /// [`RootfsFlavor::BaseAlpine`]).
    pub fn is_squashfs_base(self) -> bool {
        matches!(self, RootfsFlavor::BaseSqfs | RootfsFlavor::BaseAlpine)
    }
}

/// Result of [`build_rootfs`], serialized verbatim as the CLI's stdout JSON.
#[derive(Debug, Serialize)]
pub struct BuildRootfsOutcome {
    /// Always `true` on the success path.
    pub ok: bool,
    /// Absolute path to the image (ext4, or a `*.sqfs` for the squashfs base
    /// flavors: `base.sqfs` for `base-sqfs`, `base-alpine.sqfs` for `base-alpine`).
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
        RootfsFlavor::BaseAlpine => populate_base_alpine(root)?,
    }

    // Pack into a temp image, then atomically rename into place. The squashfs
    // base flavors are read-only squashfs; every other flavor is a sparse ext4.
    let tmp_img = tempfile::NamedTempFile::new_in(&images).context("creating temp image")?;
    if flavor.is_squashfs_base() {
        run_mksquashfs(root, tmp_img.path())?;
    } else {
        run_mkfs(Some(root), tmp_img.path(), ROOTFS_SIZE)?;
    }
    // fsync via a fresh handle: a packer may have re-created the inode.
    std::fs::File::open(tmp_img.path())
        .and_then(|f| f.sync_all())
        .context("fsync image")?;
    let (_, tmp_path) = tmp_img.keep().context("finalizing temp image")?;
    std::fs::rename(&tmp_path, &dest)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), dest.display()))?;

    // Stamp the build-metadata sidecar so the run path can refuse a
    // proto-stale image *before* any VM work (finding #17).
    write_image_meta(&dest, flavor)?;

    outcome_for(&dest, flavor, false)
}

/// Destination image path for `flavor` under `images`: `base.sqfs` /
/// `base-alpine.sqfs` for the squashfs stage bases, `rootfs-<slug>.ext4` for the
/// ext4 flavors.
fn image_dest(images: &Path, flavor: RootfsFlavor) -> PathBuf {
    match flavor {
        RootfsFlavor::BaseSqfs => images.join("base.sqfs"),
        RootfsFlavor::BaseAlpine => images.join("base-alpine.sqfs"),
        other => images.join(format!("rootfs-{}.ext4", other.slug())),
    }
}

/// Absolute path to the read-only squashfs **base image** a stage overlay chain
/// boots as its `vda` root, for a squashfs-base flavor ([`RootfsFlavor::BaseSqfs`]
/// or [`RootfsFlavor::BaseAlpine`]).
///
/// This is the seam the VM run path resolves a base selection through: it returns
/// the on-disk image path only when the image actually exists, otherwise a clear
/// "build it first" error naming the exact `isopod image build-rootfs` invocation.
///
/// # Errors
/// Errors if `flavor` is not a squashfs base, if the isopod home cannot be
/// resolved, or if the base image has not been built yet.
pub fn base_image_path(flavor: RootfsFlavor) -> Result<PathBuf> {
    base_image_path_in(&paths::images_dir()?, flavor)
}

/// [`base_image_path`] against an explicit `images` dir (unit-testable without
/// mutating `$ISOPOD_HOME`).
fn base_image_path_in(images: &Path, flavor: RootfsFlavor) -> Result<PathBuf> {
    if !flavor.is_squashfs_base() {
        bail!(
            "flavor '{}' is not a squashfs base image (expected base-sqfs or base-alpine)",
            flavor.slug()
        );
    }
    let dest = image_dest(images, flavor);
    if !dest.exists() {
        bail!(
            "base image not found at {}; build it first: \
             `isopod image build-rootfs --flavor {}`",
            dest.display(),
            flavor.slug()
        );
    }
    // Fail fast on a proto-stale base before any VM work (findings #17/#19).
    check_image_proto(&dest)?;
    Ok(dest)
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

// ===========================================================================
// Image build-metadata sidecars (`<image>.meta.json`) — the proto-skew guard
// (dogfood finding #17) and the warm-pool content id (finding #25).
// ===========================================================================

/// Build metadata stamped next to every built image as `<image>.meta.json`
/// (same sidecar convention as `StageMeta` / `SnapshotMeta`). The recorded
/// proto version lets the run path refuse a stale image before any VM work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    /// Flavor slug this image was built as.
    pub flavor: String,
    /// `isopod_proto::PROTO_VERSION` at build time — what the baked-in guest
    /// agent speaks. `None` for the agent-less `dev-busybox`.
    pub proto_version: Option<u32>,
    /// sha256 of the guest-agent binary baked in (`None` for `dev-busybox`).
    pub agent_sha256: Option<String>,
    /// sha256 of the packed image file (the warm-pool content id).
    pub sha256: String,
    /// Unix time the image was built.
    pub built_unix: u64,
}

/// Sidecar path for an image: `<image>.meta.json`.
fn image_meta_path(image: &Path) -> PathBuf {
    let mut s = image.as_os_str().to_owned();
    s.push(".meta.json");
    PathBuf::from(s)
}

/// Stamp `<image>.meta.json` for a freshly built image.
fn write_image_meta(image: &Path, flavor: RootfsFlavor) -> Result<()> {
    let (proto_version, agent_sha256) = if flavor.has_agent() {
        let agent = locate_checked_agent()?;
        (
            Some(isopod_proto::PROTO_VERSION),
            Some(paths::sha256_file(&agent)?),
        )
    } else {
        (None, None)
    };
    let meta = ImageMeta {
        flavor: flavor.slug().to_string(),
        proto_version,
        agent_sha256,
        sha256: paths::sha256_file(image)?,
        built_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let path = image_meta_path(image);
    let json = serde_json::to_vec_pretty(&meta).context("serializing image meta")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read an image's sidecar. `Ok(None)` when no sidecar exists (an image built
/// before stamping landed).
pub fn read_image_meta(image: &Path) -> Result<Option<ImageMeta>> {
    let path = image_meta_path(image);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    };
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {}", path.display()))
        .map(Some)
}

/// Pre-boot guard: refuse an image whose sidecar records a different guest
/// protocol than this host build speaks — failing fast with the fix, instead of
/// the in-boot vsock timeout (or, on the networked path, a masking tap error;
/// findings #17/#19). A missing or unreadable sidecar only warns: images built
/// before stamping existed must keep working.
pub fn check_image_proto(image: &Path) -> Result<()> {
    match read_image_meta(image) {
        Ok(Some(meta)) => {
            if let Some(v) = meta.proto_version {
                if v != isopod_proto::PROTO_VERSION {
                    bail!(
                        "guest image {} was built for protocol v{v}, but this isopod speaks \
                         v{} — rebuild every guest image together: `isopod image build-all`",
                        image.display(),
                        isopod_proto::PROTO_VERSION,
                    );
                }
            }
            Ok(())
        }
        Ok(None) => {
            eprintln!(
                "run: warning: {} has no build-metadata sidecar (built by an older isopod); \
                 rebuild via `isopod image build-all` to enable pre-boot proto checks",
                image.display()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "run: warning: unreadable image metadata for {}: {e:#}",
                image.display()
            );
            Ok(())
        }
    }
}

/// Cheap content id for a flavor's built image: the sidecar's recorded sha256,
/// or `"unstamped"` when no sidecar exists. Keyed into the warm-pool
/// `SnapshotKey` so a rebuilt base gets fresh snapshots instead of silently
/// resuming stale ones (finding #25) — without hashing hundreds of MB per run.
pub fn base_content_id(flavor: RootfsFlavor) -> Result<String> {
    let images = paths::images_dir()?;
    let dest = image_dest(&images, flavor);
    Ok(read_image_meta(&dest)?
        .map(|m| m.sha256)
        .unwrap_or_else(|| "unstamped".to_string()))
}

/// One row of `isopod image ls`.
#[derive(Debug, Serialize)]
pub struct ImageEntry {
    /// Flavor slug.
    pub flavor: String,
    /// On-disk image path.
    pub path: PathBuf,
    /// Whether the image file exists.
    pub present: bool,
    /// Image size in bytes (present images only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_apparent: Option<u64>,
    /// Proto version stamped in the sidecar (absent for agent-less flavors and
    /// unstamped images).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto_version: Option<u32>,
    /// Present but carrying no sidecar (built before stamping landed).
    pub unstamped: bool,
    /// Sidecar proto disagrees with this host build — rebuild required.
    pub stale: bool,
    /// Unix build time from the sidecar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub built_unix: Option<u64>,
}

/// Result of `isopod image ls`: every flavor with its stamp status.
#[derive(Debug, Serialize)]
pub struct ImageList {
    /// Always `true` on the success path.
    pub ok: bool,
    /// The protocol version this host build speaks.
    pub host_proto: u32,
    /// One entry per flavor ([`RootfsFlavor::ALL`] order).
    pub images: Vec<ImageEntry>,
}

/// Enumerate every flavor's image with its sidecar stamp status (`image ls`).
pub fn list_images() -> Result<ImageList> {
    let images_dir = paths::images_dir()?;
    let mut images = Vec::with_capacity(RootfsFlavor::ALL.len());
    for flavor in RootfsFlavor::ALL {
        let path = image_dest(&images_dir, flavor);
        let present = path.exists();
        let meta = if present {
            read_image_meta(&path)?
        } else {
            None
        };
        let bytes_apparent = present
            .then(|| std::fs::metadata(&path).map(|m| m.len()).ok())
            .flatten();
        let proto_version = meta.as_ref().and_then(|m| m.proto_version);
        let stale = matches!(proto_version, Some(v) if v != isopod_proto::PROTO_VERSION);
        images.push(ImageEntry {
            flavor: flavor.slug().to_string(),
            path,
            present,
            bytes_apparent,
            proto_version,
            unstamped: present && meta.is_none(),
            stale,
            built_unix: meta.as_ref().map(|m| m.built_unix),
        });
    }
    Ok(ImageList {
        ok: true,
        host_proto: isopod_proto::PROTO_VERSION,
        images,
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

/// Populate the `base-alpine` flavor: an unprivileged `apk.static` install of the
/// pinned Alpine toolchain into `root`, then the isopod stage-base scaffolding —
/// the guest agent as `/sbin/init`, the overlay mountpoints, and a sane runtime
/// config. `assemble_common` has already created the pseudo-fs mountpoints and the
/// sticky `/tmp` (apk merges its baselayout over them cleanly).
///
/// Every step is unprivileged. `apk.static` runs in `--usermode` (apk 3.x's
/// rootless mode) and emits ownership warnings for files it cannot chown as a
/// normal user — harmless, because `mksquashfs -all-root` normalizes every inode
/// to uid/gid 0 when the tree is packed.
fn populate_base_alpine(root: &Path) -> Result<()> {
    // Resolve the agent up front so a missing/dynamic binary fails before the
    // (slow, networked) apk install rather than after it.
    let agent = locate_checked_agent()?;

    // Downloaded apks + extracted bootstrap tools live in a temp dir dropped at
    // the end of this function (never packed into the image).
    let work = tempfile::tempdir().context("creating alpine bootstrap workdir")?;
    let apk_static = fetch_apk_static(work.path())?;
    let keys_dir = fetch_alpine_keys(work.path())?;
    run_apk_install(&apk_static, &keys_dir, root)?;
    retain_apk_runtime(root, &apk_static, &keys_dir)?;

    install_busybox_applets(root)?;
    install_agent_init(root, &agent)?;
    write_base_overlay_dirs(root)?;
    write_alpine_runtime_config(root)?;
    Ok(())
}

/// Essential busybox applet install paths used as a fallback if enumerating the
/// installed busybox's own applet set fails. These give the base a usable
/// coreutils userland (the everyday tools an agent workload expects) even without
/// enumeration; the primary path installs busybox's *full* applet set.
const FALLBACK_APPLET_PATHS: &[&str] = &[
    "bin/cat",
    "bin/ls",
    "bin/cp",
    "bin/mv",
    "bin/rm",
    "bin/mkdir",
    "bin/rmdir",
    "bin/ln",
    "bin/chmod",
    "bin/touch",
    "bin/echo",
    "bin/pwd",
    "bin/sleep",
    "bin/sync",
    "bin/mount",
    "bin/umount",
    "bin/uname",
    "usr/bin/env",
    "usr/bin/head",
    "usr/bin/tail",
    "usr/bin/wc",
    "usr/bin/sort",
    "usr/bin/find",
    "usr/bin/grep",
    "usr/bin/sed",
    "usr/bin/awk",
    "usr/bin/id",
    "usr/bin/stat",
    "bin/date",
    "usr/bin/tar",
    "usr/bin/wget",
    "usr/bin/xargs",
    "usr/bin/which",
];

/// Recreate the busybox applet symlinks (`/bin/cat`, `/usr/bin/grep`, …) that
/// Alpine's busybox post-install trigger would have installed. That trigger is a
/// package script, and the base is built with `--no-scripts` (scripts assume a
/// booted system), so without this the image would ship only `/bin/busybox` and
/// `/bin/sh` — every other coreutil would be "not found".
///
/// The applet set is taken from the installed busybox itself (`--list-full`, run
/// on the host through its musl loader), so it always matches the exact busybox
/// build; a curated [`FALLBACK_APPLET_PATHS`] set is used if that enumeration
/// fails. Each applet becomes an absolute symlink to `/bin/busybox`, and any
/// pre-existing path (a real package binary, or the `busybox-binsh` `/bin/sh`) is
/// left untouched.
fn install_busybox_applets(root: &Path) -> Result<()> {
    let applets = match enumerate_busybox_applets(root) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => {
            eprintln!("build-rootfs: busybox --list-full was empty; using fallback applet set");
            FALLBACK_APPLET_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
        Err(e) => {
            eprintln!(
                "build-rootfs: could not enumerate busybox applets ({e}); using fallback set"
            );
            FALLBACK_APPLET_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
    };

    let busybox_target = Path::new("/bin/busybox");
    for rel in applets {
        // Defensive: ignore absolute or parent-escaping paths from `--list-full`.
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() || rel.split('/').any(|c| c == "..") {
            continue;
        }
        let link = root.join(rel);
        if link.symlink_metadata().is_ok() {
            continue; // never clobber a real binary or the existing /bin/sh link
        }
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir for applet {}", link.display()))?;
        }
        std::os::unix::fs::symlink(busybox_target, &link)
            .with_context(|| format!("symlink applet {}", link.display()))?;
    }
    Ok(())
}

/// Enumerate the installed busybox's applet install paths via `busybox
/// --list-full`. The guest busybox is a dynamically linked musl binary, so it is
/// invoked on the host through its own musl loader
/// (`/lib/ld-musl-x86_64.so.1 /bin/busybox --list-full`) — the reliable way to run
/// a musl binary on a glibc host. Returns install paths relative to the rootfs
/// (`bin/cat`, `usr/bin/awk`, …).
fn enumerate_busybox_applets(root: &Path) -> Result<Vec<String>> {
    let loader = root.join("lib/ld-musl-x86_64.so.1");
    let busybox = root.join("bin/busybox");
    if !loader.exists() {
        bail!("musl loader {} not present", loader.display());
    }
    if !busybox.exists() {
        bail!("busybox {} not present", busybox.display());
    }
    let out = Command::new(&loader)
        .arg(&busybox)
        .arg("--list-full")
        .output()
        .context("running busybox --list-full via musl loader")?;
    if !out.status.success() {
        bail!(
            "busybox --list-full failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

/// Download the pinned `apk-tools-static` package, verify its sha256, extract the
/// static `apk.static` binary into `work`, and return its path.
fn fetch_apk_static(work: &Path) -> Result<PathBuf> {
    let file = format!("apk-tools-static-{APK_TOOLS_STATIC_VERSION}.apk");
    let url = format!("{ALPINE_CDN}/{ALPINE_BRANCH}/main/x86_64/{file}");
    let apk = work.join(&file);
    download_verified(&url, APK_TOOLS_STATIC_SHA256, &apk)?;
    extract_member(&apk, work, "sbin/apk.static")?;
    let bin = work.join("sbin/apk.static");
    set_exec(&bin)?;
    if !elf_is_static_x86_64(&bin)? {
        bail!("extracted apk.static is not a static x86_64 ELF");
    }
    Ok(bin)
}

/// Download the pinned `alpine-keys` package, verify its sha256, extract its
/// `etc/apk/keys` directory into `work`, and return that directory's path — the
/// `--keys-dir` apk verifies repository signatures against (so the install runs
/// with proper key verification, not `--allow-untrusted`).
fn fetch_alpine_keys(work: &Path) -> Result<PathBuf> {
    let file = format!("alpine-keys-{ALPINE_KEYS_VERSION}.apk");
    let url = format!("{ALPINE_CDN}/{ALPINE_BRANCH}/main/x86_64/{file}");
    let apk = work.join(&file);
    download_verified(&url, ALPINE_KEYS_SHA256, &apk)?;
    extract_member(&apk, work, "etc/apk/keys")?;
    let keys = work.join("etc/apk/keys");
    if !keys.is_dir() {
        bail!("alpine-keys package did not yield etc/apk/keys");
    }
    Ok(keys)
}

/// Run the pinned `apk.static` unprivileged: initialize a fresh apk database under
/// `root` and install [`ALPINE_PACKAGES`] from the pinned branch's main +
/// community repositories, verifying signatures against `keys_dir`.
///
/// `--usermode` is apk 3.x's rootless mode (required to build the database as a
/// non-root user); `--no-scripts` skips package trigger scripts (they assume a
/// booted system and a live `/dev`). Ownership warnings are expected and benign
/// (see [`populate_base_alpine`]).
fn run_apk_install(apk_static: &Path, keys_dir: &Path, root: &Path) -> Result<()> {
    let main = format!("{ALPINE_CDN}/{ALPINE_BRANCH}/main");
    let community = format!("{ALPINE_CDN}/{ALPINE_BRANCH}/community");
    eprintln!(
        "build-rootfs: apk.static installing {} packages from Alpine {ALPINE_BRANCH}",
        ALPINE_PACKAGES.len()
    );
    let out = Command::new(apk_static)
        .arg("--root")
        .arg(root)
        .args(["--arch", "x86_64"])
        .arg("--repository")
        .arg(&main)
        .arg("--repository")
        .arg(&community)
        .arg("--keys-dir")
        .arg(keys_dir)
        .args(["--usermode", "--initdb", "--no-scripts", "add"])
        .args(ALPINE_PACKAGES)
        .output()
        .context("spawning apk.static")?;
    if !out.status.success() {
        bail!(
            "apk.static add failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Keep a working `apk` in the packed image so an online guest can `apk add`
/// packages at runtime (dogfood finding #15): copy the already-verified static
/// `apk.static` to `/sbin/apk.static` (with an `/sbin/apk` convenience symlink)
/// and the repository-signing keys to `/etc/apk/keys`. The repositories file and
/// the apk database already exist (`write_alpine_runtime_config` /
/// `run_apk_install`), so in-guest `apk add <pkg>` is fully self-serve.
fn retain_apk_runtime(root: &Path, apk_static: &Path, keys_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("sbin")).context("mkdir /sbin")?;
    let dest = root.join("sbin/apk.static");
    std::fs::copy(apk_static, &dest)
        .with_context(|| format!("copying {} -> sbin/apk.static", apk_static.display()))?;
    set_exec(&dest)?;
    symlink_force(Path::new("apk.static"), &root.join("sbin/apk"))?;

    let keys_dest = root.join("etc/apk/keys");
    std::fs::create_dir_all(&keys_dest).context("mkdir /etc/apk/keys")?;
    for entry in std::fs::read_dir(keys_dir)
        .with_context(|| format!("reading keys dir {}", keys_dir.display()))?
        .flatten()
    {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            std::fs::copy(entry.path(), keys_dest.join(entry.file_name()))
                .with_context(|| format!("copying key {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Install the guest agent as `/sbin/init` (a real ELF PID 1, overwriting any
/// pre-existing init link) and point `/init -> /sbin/init` so the kernel finds
/// PID 1 regardless of the `init=` boot arg. `/sbin` already exists (Alpine's
/// baselayout provides it).
fn install_agent_init(root: &Path, agent_bin: &Path) -> Result<()> {
    let init = root.join("sbin/init");
    // Remove any existing entry first so a symlink init is replaced by the binary
    // (rather than `copy` writing through the link to its target).
    if init.symlink_metadata().is_ok() {
        std::fs::remove_file(&init)
            .with_context(|| format!("removing existing {}", init.display()))?;
    }
    std::fs::copy(agent_bin, &init)
        .with_context(|| format!("copying guest-agent {} -> sbin/init", agent_bin.display()))?;
    set_exec(&init)?;
    symlink_force(Path::new("sbin/init"), &root.join("init"))?;
    Ok(())
}

/// Write the guest runtime config the Alpine base ships: a public-resolver
/// `/etc/resolv.conf` and an `/etc/apk/repositories` pointing at the pinned branch
/// (the static apk + signing keys are retained by [`retain_apk_runtime`], so an
/// online guest really can `apk add` more packages at runtime). Both parent dirs
/// exist after the apk install.
fn write_alpine_runtime_config(root: &Path) -> Result<()> {
    std::fs::write(root.join("etc/resolv.conf"), RESOLV_CONF)
        .context("writing /etc/resolv.conf")?;
    let apk_dir = root.join("etc/apk");
    std::fs::create_dir_all(&apk_dir).context("mkdir /etc/apk")?;
    let repos =
        format!("{ALPINE_CDN}/{ALPINE_BRANCH}/main\n{ALPINE_CDN}/{ALPINE_BRANCH}/community\n");
    std::fs::write(apk_dir.join("repositories"), repos).context("writing /etc/apk/repositories")?;
    remove_pep668_markers(root)?;
    Ok(())
}

/// Delete every `pythonX.Y/EXTERNALLY-MANAGED` marker so `pip install` works
/// out of the box. PEP 668 marks a distro's Python as "externally managed" to
/// stop users breaking the system interpreter — but an isopod guest is a
/// disposable sandbox whose entire purpose is to install packages freely, so
/// the marker is pure friction here (dogfood finding: bare `pip install` else
/// fails with a PEP-668 error and an agent must know to pass
/// `--break-system-packages`).
fn remove_pep668_markers(root: &Path) -> Result<()> {
    let libdir = root.join("usr/lib");
    let Ok(entries) = std::fs::read_dir(&libdir) else {
        return Ok(()); // no /usr/lib (non-python base): nothing to do
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("python3") {
            let marker = entry.path().join("EXTERNALLY-MANAGED");
            match std::fs::remove_file(&marker) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(
                        anyhow::Error::new(e).context(format!("removing {}", marker.display()))
                    )
                }
            }
        }
    }
    Ok(())
}

/// Download `url` into `dest`, verifying the body's sha256 against `expected`
/// (lowercase hex). The whole body is buffered — apks are small (single-digit MB).
fn download_verified(url: &str, expected: &str, dest: &Path) -> Result<()> {
    eprintln!("build-rootfs: downloading {url}");
    let bytes = http_client(Duration::from_secs(120))?
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?
        .bytes()
        .with_context(|| format!("reading body of {url}"))?;
    let got = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    if got != expected {
        bail!("sha256 mismatch for {url}: expected {expected}, got {got}");
    }
    std::fs::write(dest, &bytes).with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

/// Extract a single `member` (file or directory) from an Alpine `.apk` (a
/// concatenation of gzip streams) into `dest` via `tar`. GNU tar reads across the
/// concatenated streams; `--warning=no-unknown-keyword` silences the benign
/// `APK-TOOLS.checksum` extended-header notices apks carry.
fn extract_member(apk: &Path, dest: &Path, member: &str) -> Result<()> {
    let out = Command::new("tar")
        .arg("-xzf")
        .arg(apk)
        .arg("-C")
        .arg(dest)
        .arg("--warning=no-unknown-keyword")
        .arg(member)
        .output()
        .context("spawning tar (is it installed?)")?;
    if !out.status.success() {
        bail!(
            "tar failed to extract {member} from {} ({}): {}",
            apk.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// A blocking HTTP client with the shared isopod-image user agent and `timeout`.
fn http_client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent("isopod-image/0.1")
        .build()
        .context("building HTTP client")
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
    if bin.exists() {
        return Ok(bin);
    }
    // Installed layout: the distro package ships the prebuilt static agent.
    let system = PathBuf::from("/usr/lib/isopod/isopod-guest-agent");
    if system.exists() {
        return Ok(system);
    }
    bail!(
        "guest-agent musl binary not found at {} or {}; build it first ({BUILD_HINT}) \
         or install the isopod package",
        bin.display(),
        system.display()
    );
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
    let client = http_client(Duration::from_secs(120))?;
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
            RootfsFlavor::BaseAlpine,
        ] {
            assert_eq!(RootfsFlavor::from_slug(flavor.slug()).unwrap(), flavor);
        }
        assert_eq!(
            RootfsFlavor::from_slug("base-alpine").unwrap(),
            RootfsFlavor::BaseAlpine
        );
        assert!(RootfsFlavor::from_slug("nope").is_err());
        // The retired placeholder slug no longer resolves.
        assert!(RootfsFlavor::from_slug("alpine").is_err());
    }

    #[test]
    fn base_sqfs_dest_is_squashfs_not_ext4() {
        let images = Path::new("/x/images");
        assert_eq!(
            image_dest(images, RootfsFlavor::BaseSqfs),
            images.join("base.sqfs")
        );
        assert_eq!(
            image_dest(images, RootfsFlavor::BaseAlpine),
            images.join("base-alpine.sqfs")
        );
        assert_eq!(
            image_dest(images, RootfsFlavor::DevAgent),
            images.join("rootfs-dev-agent.ext4")
        );
    }

    #[test]
    fn is_squashfs_base_only_for_base_flavors() {
        assert!(RootfsFlavor::BaseSqfs.is_squashfs_base());
        assert!(RootfsFlavor::BaseAlpine.is_squashfs_base());
        assert!(!RootfsFlavor::DevBusybox.is_squashfs_base());
        assert!(!RootfsFlavor::DevAgent.is_squashfs_base());
    }

    #[test]
    fn alpine_pins_are_well_formed() {
        // sha256 pins are exactly 64 lowercase hex chars.
        for sha in [APK_TOOLS_STATIC_SHA256, ALPINE_KEYS_SHA256] {
            assert_eq!(sha.len(), 64, "sha256 must be 64 hex chars: {sha}");
            assert!(
                sha.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "sha256 must be lowercase hex: {sha}"
            );
        }
        // The two sha pins are distinct (guards against a copy-paste pin error).
        assert_ne!(APK_TOOLS_STATIC_SHA256, ALPINE_KEYS_SHA256);
        // Version pins look like `<ver>-r<rev>`; the branch looks like `v<major>.<minor>`.
        for ver in [APK_TOOLS_STATIC_VERSION, ALPINE_KEYS_VERSION] {
            assert!(
                ver.contains("-r"),
                "apk version pin should carry a -r rev: {ver}"
            );
        }
        assert!(
            ALPINE_BRANCH.starts_with('v') && ALPINE_BRANCH.contains('.'),
            "branch pin should look like v3.24: {ALPINE_BRANCH}"
        );
        // The install set covers the headline toolchain the flavor advertises —
        // including cmake (long documented, only now shipped) and GNU coreutils
        // (busybox's cp lacks --sparse, which isopod's own in-guest test runs
        // need; findings #15 + gauntlet).
        for pkg in [
            "python3",
            "nodejs",
            "npm",
            "git",
            "gcc",
            "make",
            "cmake",
            "coreutils",
        ] {
            assert!(
                ALPINE_PACKAGES.contains(&pkg),
                "base-alpine package set must include {pkg}"
            );
        }
    }

    #[test]
    fn retain_apk_runtime_installs_apk_and_keys() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let apk = work.path().join("apk.static");
        std::fs::write(&apk, b"#!fake-apk").unwrap();
        let keys = work.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(
            keys.join("alpine-devel@lists.alpinelinux.org-1.rsa.pub"),
            b"k",
        )
        .unwrap();

        retain_apk_runtime(root.path(), &apk, &keys).unwrap();

        let installed = root.path().join("sbin/apk.static");
        assert!(installed.is_file(), "apk.static must be copied in");
        let mode = std::fs::metadata(&installed).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "apk.static must be executable");
        assert_eq!(
            std::fs::read_link(root.path().join("sbin/apk")).unwrap(),
            Path::new("apk.static"),
            "/sbin/apk must be a relative symlink to apk.static"
        );
        assert!(root
            .path()
            .join("etc/apk/keys/alpine-devel@lists.alpinelinux.org-1.rsa.pub")
            .is_file());
    }

    #[test]
    fn image_meta_sidecar_round_trip_and_proto_check() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("base-alpine.sqfs");
        std::fs::write(&img, b"fake image").unwrap();

        // No sidecar: read gives None, check warns-and-passes.
        assert!(read_image_meta(&img).unwrap().is_none());
        check_image_proto(&img).unwrap();

        // Current-proto sidecar: passes.
        let meta = ImageMeta {
            flavor: "base-alpine".into(),
            proto_version: Some(isopod_proto::PROTO_VERSION),
            agent_sha256: Some("ab".repeat(32)),
            sha256: "cd".repeat(32),
            built_unix: 1,
        };
        std::fs::write(image_meta_path(&img), serde_json::to_vec(&meta).unwrap()).unwrap();
        assert_eq!(
            read_image_meta(&img).unwrap().unwrap().flavor,
            "base-alpine"
        );
        check_image_proto(&img).unwrap();

        // Stale-proto sidecar: refused, naming the rebuild command.
        let stale = ImageMeta {
            proto_version: Some(isopod_proto::PROTO_VERSION + 1),
            ..meta.clone()
        };
        std::fs::write(image_meta_path(&img), serde_json::to_vec(&stale).unwrap()).unwrap();
        let err = check_image_proto(&img).unwrap_err().to_string();
        assert!(err.contains("build-all"), "error must name the fix: {err}");

        // Agent-less sidecar (proto None, dev-busybox): always passes.
        let busybox = ImageMeta {
            flavor: "dev-busybox".into(),
            proto_version: None,
            agent_sha256: None,
            ..meta
        };
        std::fs::write(image_meta_path(&img), serde_json::to_vec(&busybox).unwrap()).unwrap();
        check_image_proto(&img).unwrap();
    }

    #[test]
    fn base_image_path_rejects_non_base_flavor() {
        let images = Path::new("/x/images");
        assert!(base_image_path_in(images, RootfsFlavor::DevAgent).is_err());
        assert!(base_image_path_in(images, RootfsFlavor::DevBusybox).is_err());
    }

    #[test]
    fn base_image_path_errors_when_missing_but_resolves_when_present() {
        let images = tempfile::tempdir().unwrap();
        // Absent → a "build it first" error, not a path.
        let err = base_image_path_in(images.path(), RootfsFlavor::BaseAlpine)
            .expect_err("missing base image must error");
        assert!(
            err.to_string().contains("build it first"),
            "error should guide the user to build: {err}"
        );
        // Present → returns the exact image path.
        let img = images.path().join("base-alpine.sqfs");
        std::fs::write(&img, b"sqfs").unwrap();
        assert_eq!(
            base_image_path_in(images.path(), RootfsFlavor::BaseAlpine).unwrap(),
            img
        );
    }

    #[test]
    fn install_agent_init_and_runtime_config() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Alpine's apk provides /sbin; emulate that plus a pre-existing init link
        // (the "overwriting alpine's init link" case).
        std::fs::create_dir_all(root.join("sbin")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        symlink_force(Path::new("/bin/busybox"), &root.join("sbin/init")).unwrap();

        let fake_agent = root.join("fake-agent");
        std::fs::write(&fake_agent, b"\x7fELF fake agent bytes").unwrap();
        install_agent_init(root, &fake_agent).unwrap();

        // /sbin/init is now the agent *binary* (a real file), not a symlink.
        let init = root.join("sbin/init");
        let meta = std::fs::symlink_metadata(&init).unwrap();
        assert!(meta.file_type().is_file(), "sbin/init must be a real file");
        assert!(
            meta.permissions().mode() & 0o111 != 0,
            "sbin/init executable"
        );
        assert_eq!(
            std::fs::read(&init).unwrap(),
            b"\x7fELF fake agent bytes",
            "sbin/init must be the agent bytes, not alpine's init link"
        );
        // /init -> /sbin/init.
        let ilink = root.join("init");
        assert!(ilink.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_link(&ilink).unwrap(), Path::new("sbin/init"));

        // Runtime config: resolv.conf (public resolvers) + apk/repositories.
        write_alpine_runtime_config(root).unwrap();
        let resolv = std::fs::read_to_string(root.join("etc/resolv.conf")).unwrap();
        assert!(
            resolv.contains("nameserver "),
            "resolv.conf has a nameserver"
        );
        let repos = std::fs::read_to_string(root.join("etc/apk/repositories")).unwrap();
        assert!(
            repos.contains(ALPINE_BRANCH),
            "repositories pinned to branch"
        );
        assert!(repos.contains("/main") && repos.contains("/community"));
    }

    #[test]
    fn install_busybox_applets_fallback_and_no_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // No musl loader present ⇒ enumeration fails ⇒ the fallback applet set is
        // installed as symlinks to /bin/busybox.
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        // A real package binary and the busybox-binsh /bin/sh link must survive.
        std::fs::write(root.join("usr/bin/real-tool"), b"binary").unwrap();
        symlink_force(Path::new("/bin/busybox"), &root.join("bin/sh")).unwrap();

        install_busybox_applets(root).unwrap();

        // A representative fallback applet is now a symlink to /bin/busybox.
        for rel in ["bin/cat", "usr/bin/grep", "usr/bin/awk"] {
            let link = root.join(rel);
            let meta = link.symlink_metadata().unwrap();
            assert!(meta.file_type().is_symlink(), "{rel} must be a symlink");
            assert_eq!(
                std::fs::read_link(&link).unwrap(),
                Path::new("/bin/busybox")
            );
        }
        // Pre-existing entries are never clobbered.
        assert!(
            root.join("usr/bin/real-tool")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_file(),
            "a real binary must not be replaced by an applet symlink"
        );
        assert_eq!(
            std::fs::read_link(root.join("bin/sh")).unwrap(),
            Path::new("/bin/busybox"),
            "existing /bin/sh link preserved"
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

    /// Full `base-alpine` build against the live Alpine CDN — the network-gated
    /// integration test (mirrors the `fetch_kernel` ignored test). Requires the
    /// prebuilt guest-agent musl binary (see [`locate_guest_agent`]) plus `tar`
    /// and `mksquashfs`. Builds into a scratch `$ISOPOD_HOME` so it never touches
    /// the user's real image cache. Run explicitly:
    ///
    /// ```text
    /// cargo build --release --target x86_64-unknown-linux-musl -p isopod-guest-agent
    /// cargo test -p isopod-core --lib -- --ignored base_alpine_live_build --nocapture
    /// ```
    #[test]
    #[ignore = "requires network (dl-cdn.alpinelinux.org), a prebuilt guest-agent, tar + mksquashfs"]
    fn base_alpine_live_build() {
        let home = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("ISOPOD_HOME");
        std::env::set_var("ISOPOD_HOME", home.path());
        let built = build_rootfs(RootfsFlavor::BaseAlpine, true);
        match prev {
            Some(v) => std::env::set_var("ISOPOD_HOME", v),
            None => std::env::remove_var("ISOPOD_HOME"),
        }
        let outcome = built.expect("base-alpine build should succeed");
        assert!(outcome.ok);
        assert_eq!(outcome.flavor, "base-alpine");
        assert!(
            outcome.rootfs_path.ends_with("base-alpine.sqfs"),
            "dest should be base-alpine.sqfs: {}",
            outcome.rootfs_path.display()
        );
        assert!(outcome.rootfs_path.exists(), "image file must exist");
        // Squashfs of a full toolchain is comfortably tens of MB.
        assert!(
            outcome.bytes_apparent > 20 * 1024 * 1024,
            "unexpectedly small image: {} bytes",
            outcome.bytes_apparent
        );
        assert_eq!(outcome.sha256.len(), 64, "sha256 recorded");
    }
}
