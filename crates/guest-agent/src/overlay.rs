//! Overlay-root assembly, in two flavors that share the same overlay mount +
//! `pivot_root` tail.
//!
//! **Drive-backed stage mode (`isopod.layers=<N>`).** The guest was booted from
//! the read-only squashfs base at `/dev/vda` with `N` committed stage layers and
//! one fresh writable scratch drive attached after it. Firecracker exposes
//! virtio-blk drives as `/dev/vda`, `/dev/vdb`, … in PUT order, so past the `vda`
//! root the **last** extra device is the scratch and the **first `N`** are the
//! committed stage layers (bottom-to-top). Assembly:
//!
//! 1. Mount the scratch ext4 read-write at `/overlay`.
//! 2. Mount each committed stage layer read-only at `/layers/<i>` (1-based).
//! 3. Create the overlay `upper`/`work` dirs on `/overlay` and perform **one**
//!    multi-lowerdir overlay mount at `/mnt`
//!    (`lowerdir=/layers/N/upper:…:/layers/1/upper:/`, topmost first, the
//!    squashfs base `/` as the bottom layer; `upperdir=/overlay/upper`,
//!    `workdir=/overlay/work`, `redirect_dir=on`) — never overlay-on-overlay,
//!    which the kernel caps at depth two.
//! 4. `pivot_root` into the merged view and re-establish the pseudo-filesystems.
//!
//! Each committed stage layer's raw image is a previous run's scratch ext4, so
//! its meaningful tree (files, whiteouts, `trusted.overlay.*` xattrs) lives under
//! its `/upper` subdirectory — that is what the lowerdir chain points at.
//!
//! **RAM-upper mode (`isopod.upper=ram`, with no `isopod.layers` or `=0`).** The
//! warm-pool topology: there is **no scratch drive** at all (a per-VM scratch file
//! at a shared baked path would collide across concurrent snapshot restores).
//! Instead the overlay `upper`/`work` live on a **tmpfs** mounted at `/overlay`,
//! captured inside the memory snapshot, so all writes land in guest RAM (bounded
//! by `mem_mib`). The overlay is base-only (`lowerdir=/`). Steps 3–4 are shared
//! with the drive-backed path via [`assemble_overlay_and_pivot`].
//!
//! Absent both keys the agent boots exactly as before (a writable ext4 root needs
//! no overlay).

use std::io;

use crate::cmdline;
use crate::server::log;
use crate::sys::{self, MS_NOATIME, MS_RDONLY};

/// Command-line key whose presence switches the agent into overlay-root mode;
/// the value is the committed stage-layer count (`>= 0`).
const LAYERS_KEY: &str = "isopod.layers";
/// Command-line key selecting the overlay upper-dir backing. The only recognized
/// value is [`UPPER_RAM`]; any other value (or absence) uses the drive-backed
/// scratch.
const UPPER_KEY: &str = "isopod.upper";
/// [`UPPER_KEY`] value selecting a tmpfs (guest-RAM) overlay upper — the warm-pool
/// mode with no scratch drive.
const UPPER_RAM: &str = "ram";

/// Staging mountpoint for the merged overlay before `pivot_root` makes it `/`.
const STAGING: &str = "/mnt";
/// Overlay upper-backing mountpoint inside the base image: an ext4 scratch drive
/// in drive-backed mode, or a tmpfs in RAM-upper mode.
const SCRATCH_MNT: &str = "/overlay";
/// Overlay upperdir (on the upper-backing fs).
const UPPER_DIR: &str = "/overlay/upper";
/// Overlay workdir (on the upper-backing fs, sibling of the upperdir).
const WORK_DIR: &str = "/overlay/work";

/// Assemble the stage overlay root **iff** `/proc/cmdline` requests it.
///
/// Best-effort by design: a failure here leaves the guest on the read-only base
/// root (read-only execs and the vsock RPC still work, so the host can diagnose)
/// rather than panicking PID 1. Must be called after the pseudo-filesystems are
/// mounted (it reads `/proc/cmdline` and the `/dev/vd*` nodes).
pub fn assemble_if_requested() {
    let cmdline = match std::fs::read_to_string("/proc/cmdline") {
        Ok(s) => s,
        Err(e) => {
            log(&format!("overlay: cannot read /proc/cmdline: {e}"));
            return;
        }
    };
    let layers = parse_layers(&cmdline);
    let upper = parse_upper(&cmdline);
    // Assemble an overlay root when EITHER the stage topology (`isopod.layers`)
    // or the RAM-upper warm-pool mode (`isopod.upper=ram`) is requested. With
    // neither, this is a legacy writable-ext4-root boot and we do nothing.
    let n_layers = match (layers, upper) {
        (Some(n), _) => n,
        (None, UpperMode::Ram) => 0, // warm-pool base: RAM upper, no committed layers
        (None, UpperMode::Drive) => return,
    };
    match assemble(n_layers, upper) {
        Ok(()) => log(&format!(
            "overlay: stage root assembled (layers={n_layers}, upper={})",
            upper.as_str()
        )),
        Err(e) => log(&format!(
            "overlay: FAILED to assemble stage root (layers={n_layers}, upper={}): {e}; \
             continuing on the read-only base root",
            upper.as_str()
        )),
    }
}

/// Where the overlay `upper`/`work` dirs live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpperMode {
    /// A writable ext4 **scratch drive** (the last extra block device) — the
    /// durable path that can be committed as a stage.
    Drive,
    /// A **tmpfs** in guest RAM — the warm-pool path: no scratch drive, so the
    /// whole VM (upper included) is captured in a memory snapshot and no
    /// per-VM disk backing-file path can collide across concurrent resumes.
    Ram,
}

impl UpperMode {
    fn as_str(self) -> &'static str {
        match self {
            UpperMode::Drive => "drive",
            UpperMode::Ram => "ram",
        }
    }
}

/// Parse `isopod.upper=<mode>`; only `ram` selects the tmpfs upper, everything
/// else (including absence) is the drive-backed scratch.
fn parse_upper(cmdline: &str) -> UpperMode {
    match cmdline::value(cmdline, UPPER_KEY) {
        Some(v) if v == UPPER_RAM => UpperMode::Ram,
        _ => UpperMode::Drive,
    }
}

/// Parse the `isopod.layers=<N>` value out of a kernel command line.
///
/// `Some(n)` when the key is present (build the overlay root), `None` when it is
/// absent (legacy writable-root boot). A present-but-unparseable value degrades
/// to zero layers so a writable scratch is still layered over the read-only base.
fn parse_layers(cmdline: &str) -> Option<usize> {
    let value = cmdline::value(cmdline, LAYERS_KEY)?;
    Some(value.parse::<usize>().unwrap_or(0))
}

/// Do the actual scratch/layer mounts, the single overlay mount, and the pivot.
fn assemble(n_layers: usize, upper: UpperMode) -> io::Result<()> {
    // Private propagation so `pivot_root` is not blocked by shared mounts.
    if let Err(e) = sys::make_root_private() {
        log(&format!(
            "overlay: make_root_private failed (continuing): {e}"
        ));
    }

    // Mount the overlay upper backing at /overlay, and resolve the committed
    // stage-layer block devices. In drive mode the LAST extra device is the
    // writable scratch (upper lives on it); in RAM mode there is no scratch
    // drive at all — the upper is a tmpfs — so every extra device is a layer.
    let extras = enumerate_extra_block_devices()?;
    let layers: Vec<String> = match upper {
        UpperMode::Drive => {
            let (scratch, layers) = split_scratch_and_layers(&extras, n_layers)?;
            if extras.len() != n_layers + 1 {
                log(&format!(
                    "overlay: layers={n_layers} implies {} extra drive(s) but found {} ({extras:?}); \
                     using the last as scratch and the first {} as layers",
                    n_layers + 1,
                    extras.len(),
                    layers.len()
                ));
            }
            sys::mount_with_data(&scratch, SCRATCH_MNT, "ext4", MS_NOATIME, None)
                .map_err(|e| annotate(e, &format!("mount scratch {scratch} at {SCRATCH_MNT}")))?;
            layers
        }
        UpperMode::Ram => {
            if extras.len() != n_layers {
                log(&format!(
                    "overlay: upper=ram layers={n_layers} implies {n_layers} layer drive(s) \
                     but found {} ({extras:?}); using the first {n_layers} as layers",
                    extras.len(),
                ));
            }
            // A fresh tmpfs upper — no size cap (defaults to half of RAM), which
            // the guest's mem_mib already bounds. Nothing to enumerate as scratch.
            sys::mount_with_data("tmpfs", SCRATCH_MNT, "tmpfs", MS_NOATIME, None)
                .map_err(|e| annotate(e, &format!("mount tmpfs upper at {SCRATCH_MNT}")))?;
            extras.iter().take(n_layers).cloned().collect()
        }
    };
    std::fs::create_dir_all(UPPER_DIR)?;
    std::fs::create_dir_all(WORK_DIR)?;

    // Each committed stage layer → /layers/<i> (1-based; PUT order is bottom→top).
    for (i, dev) in layers.iter().enumerate() {
        let mnt = layer_mountpoint(i + 1);
        sys::mount_with_data(dev, &mnt, "ext4", MS_RDONLY | MS_NOATIME, None)
            .map_err(|e| annotate(e, &format!("mount layer {dev} at {mnt}")))?;
    }

    // Single merged overlay staged at /mnt.
    mount_merged_overlay(layers.len())?;

    // pivot_root(".", ".") idiom: stack the old root over the new one, then
    // lazily detach it — no put_old directory is written into the overlay upper.
    sys::chdir(STAGING).map_err(|e| annotate(e, "chdir to staging"))?;
    sys::pivot_root(".", ".").map_err(|e| annotate(e, "pivot_root"))?;
    sys::umount_detach(".").map_err(|e| annotate(e, "detach old root"))?;
    sys::chdir("/").map_err(|e| annotate(e, "chdir to new root"))?;

    // Re-establish the pseudo-filesystems in the new root (the base-root ones
    // left with the detached old root).
    crate::mount_pseudo_filesystems();
    Ok(())
}

/// Mount the single merged overlay at [`STAGING`].
///
/// `redirect_dir=on` (per the stage contract, for rename-heavy builds) is tried
/// first; if the running kernel lacks it the mount is retried without, so boot
/// never wedges on an optional feature.
fn mount_merged_overlay(n_layers: usize) -> io::Result<()> {
    let lower = lowerdir_chain(n_layers);
    let base = format!("lowerdir={lower},upperdir={UPPER_DIR},workdir={WORK_DIR}");
    let with_redirect = format!("{base},redirect_dir=on");
    match sys::mount_with_data(
        "overlay",
        STAGING,
        "overlay",
        MS_NOATIME,
        Some(&with_redirect),
    ) {
        Ok(()) => Ok(()),
        Err(e) => {
            log(&format!(
                "overlay: redirect_dir=on rejected ({e}); retrying without it"
            ));
            sys::mount_with_data("overlay", STAGING, "overlay", MS_NOATIME, Some(&base))
                .map_err(|e2| annotate(e2, &format!("overlay mount at {STAGING} ({base})")))
        }
    }
}

/// Mountpoint for the 1-based `index`-th committed stage layer.
fn layer_mountpoint(index: usize) -> String {
    format!("/layers/{index}")
}

/// Build the overlay `lowerdir` chain for `n` committed layers, topmost first:
/// `/layers/N/upper:…:/layers/1/upper:/`. With `n == 0` it is just `/` (the
/// squashfs base as the only, bottom, layer). Each stage layer's tree is its
/// `/upper` subdirectory (the raw scratch image's overlay upperdir).
fn lowerdir_chain(n: usize) -> String {
    let mut parts: Vec<String> = (1..=n)
        .rev()
        .map(|i| format!("/layers/{i}/upper"))
        .collect();
    parts.push("/".to_string());
    parts.join(":")
}

/// Split the enumerated extra block devices into `(scratch, layers)`: the last
/// device is the writable scratch, the first `n_layers` are the read-only
/// committed stage layers (bottom-to-top). Defensive against a device-count
/// mismatch — never indexes past the slice.
fn split_scratch_and_layers(
    extras: &[String],
    n_layers: usize,
) -> io::Result<(String, Vec<String>)> {
    let scratch = extras
        .last()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no scratch block device past vda (need at least the scratch drive)",
            )
        })?
        .clone();
    let take = n_layers.min(extras.len().saturating_sub(1));
    let layers = extras[..take].to_vec();
    Ok((scratch, layers))
}

/// List `/dev/vd*` whole-disk virtio devices past the `vda` root, in PUT
/// (lexicographic) order, as full `/dev/…` paths.
fn enumerate_extra_block_devices() -> io::Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir("/dev")?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| is_extra_virtio_disk(n))
        .collect();
    // Lexicographic order matches PUT order for the single-letter suffixes
    // (`vdb`..`vdz`) that practical stage-chain depths ever reach.
    names.sort();
    Ok(names.into_iter().map(|n| format!("/dev/{n}")).collect())
}

/// True for a whole-disk virtio device name past `vda`: `vd` followed by an
/// all-lowercase-letter suffix, excluding the `vda` root and any partition
/// (which carries trailing digits).
fn is_extra_virtio_disk(name: &str) -> bool {
    match name.strip_prefix("vd") {
        Some(suffix) if name != "vda" => {
            !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_lowercase())
        }
        _ => false,
    }
}

/// Attach `ctx` to an `io::Error`, preserving its kind.
fn annotate(e: io::Error, ctx: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{ctx}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_layers_absent_is_none() {
        assert_eq!(
            parse_layers("console=ttyS0 quiet root=/dev/vda init=/init"),
            None
        );
    }

    #[test]
    fn parse_layers_zero_is_some_zero() {
        assert_eq!(parse_layers("root=/dev/vda isopod.layers=0 quiet"), Some(0));
    }

    #[test]
    fn parse_layers_reads_count() {
        assert_eq!(parse_layers("isopod.layers=3"), Some(3));
        assert_eq!(parse_layers("a b isopod.layers=12 c"), Some(12));
    }

    #[test]
    fn parse_layers_bad_value_degrades_to_zero() {
        assert_eq!(parse_layers("isopod.layers=xyz"), Some(0));
        assert_eq!(parse_layers("isopod.layers="), Some(0));
    }

    #[test]
    fn lowerdir_chain_zero_is_base_only() {
        assert_eq!(lowerdir_chain(0), "/");
    }

    #[test]
    fn lowerdir_chain_orders_topmost_first() {
        assert_eq!(lowerdir_chain(1), "/layers/1/upper:/");
        assert_eq!(
            lowerdir_chain(3),
            "/layers/3/upper:/layers/2/upper:/layers/1/upper:/"
        );
    }

    #[test]
    fn layer_mountpoint_is_one_based() {
        assert_eq!(layer_mountpoint(1), "/layers/1");
        assert_eq!(layer_mountpoint(9), "/layers/9");
    }

    #[test]
    fn is_extra_virtio_disk_filters() {
        assert!(is_extra_virtio_disk("vdb"));
        assert!(is_extra_virtio_disk("vdc"));
        assert!(!is_extra_virtio_disk("vda")); // the root
        assert!(!is_extra_virtio_disk("vdb1")); // a partition
        assert!(!is_extra_virtio_disk("sda")); // not virtio
        assert!(!is_extra_virtio_disk("vd")); // no suffix
        assert!(!is_extra_virtio_disk("vdB")); // uppercase never appears
    }

    #[test]
    fn split_maps_last_to_scratch_first_n_to_layers() {
        let extras = vec![
            "/dev/vdb".to_string(),
            "/dev/vdc".to_string(),
            "/dev/vdd".to_string(),
        ];
        let (scratch, layers) = split_scratch_and_layers(&extras, 2).unwrap();
        assert_eq!(scratch, "/dev/vdd");
        assert_eq!(layers, vec!["/dev/vdb".to_string(), "/dev/vdc".to_string()]);
    }

    #[test]
    fn split_zero_layers_is_scratch_only() {
        let extras = vec!["/dev/vdb".to_string()];
        let (scratch, layers) = split_scratch_and_layers(&extras, 0).unwrap();
        assert_eq!(scratch, "/dev/vdb");
        assert!(layers.is_empty());
    }

    #[test]
    fn split_never_indexes_past_available_devices() {
        // layers=5 requested but only two extras present: take at most one layer.
        let extras = vec!["/dev/vdb".to_string(), "/dev/vdc".to_string()];
        let (scratch, layers) = split_scratch_and_layers(&extras, 5).unwrap();
        assert_eq!(scratch, "/dev/vdc");
        assert_eq!(layers, vec!["/dev/vdb".to_string()]);
    }

    #[test]
    fn split_empty_errors() {
        assert!(split_scratch_and_layers(&[], 0).is_err());
    }
}
