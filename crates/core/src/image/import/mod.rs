//! Turn an unpacked OCI rootfs into a base image isopod can boot.
//!
//! [`isopod_oci_unpack`] produces a directory tree and knows nothing about
//! isopod. This module is the other half: it adds the few things the guest
//! agent needs in order to be PID 1, packs the result with the same pinned
//! `mksquashfs` invocation the built-in flavors use, and stamps a sidecar that
//! records where the image came from. It also owns the other end of an imported
//! image's life: enumerating what has been imported (which is what lets
//! `isopod image ls` answer for imported bases as well as built ones) and
//! removing one, refused while a stage still stands on it.
//!
//! # What "adaptation" actually is
//!
//! A normal Debian- or Alpine-derived image already ships `/bin/sh`, the
//! pseudo-filesystem mountpoints and a sticky `/tmp`. What it does not ship is
//! an init that speaks isopod's vsock RPC, or the three empty directories the
//! agent pivots through. So the adaptation is **three empty directories, one
//! binary, one symbolic link and one sidecar** — deliberately small, because
//! every byte of it is a difference between the image the operator asked for
//! and the image they get.
//!
//! The image's own `/sbin/init` is left alone. On a Debian-derived image that
//! is systemd, and replacing it would be a silent content mutation with no
//! purpose: the kernel is booted with `init=/init`, so `/init` is the only path
//! that has to be isopod's.
//!
//! # The promise, stated correctly
//!
//! **isopod runs your image's filesystem, with isopod's init.** Not "isopod
//! runs your container". An imported image's `ENTRYPOINT` can never be PID 1,
//! because PID 1 is the agent that does the overlay mounts, the pivot and the
//! RPC. The entrypoint and command are recorded so an operator can see what the
//! image was for, and never executed.
//!
//! # setuid, and why it is applied here and nowhere else
//!
//! The extractor never writes a setuid, setgid or sticky bit to the host tree —
//! those bits would sit in the operator's home directory, on files an attacker
//! authored, before any VM exists. It records them instead. This module turns
//! that record into a `mksquashfs` pseudo-file, so the bits exist **inside the
//! image** and nowhere else. Stripping them outright is not an option: it
//! breaks `ping`, `sudo` and `newgrp`, and inside the guest everything is
//! already root, so they grant nothing there anyway.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use isopod_oci_registry::Puller;
use isopod_oci_unpack::layout::{Compression, Layout, Platform};
use isopod_oci_unpack::{Limits, Unpacker};

use super::base::IMPORTED_PREFIX;
use super::rootfs::{self, ImageMeta, RootfsFlavor};
use crate::paths;

/// Directory mode for everything this module creates.
///
/// Explicit, never left to `create_dir`'s umask masking. The image's content id
/// is its identity, so a mode that varies with the operator's shell means the
/// same source image imports to two different base images on two hosts — and a
/// stage stamped against one cannot be forked on the other. The extractor
/// learned this the expensive way; the adaptation must not reintroduce it.
const DIR_MODE: u32 = 0o755;

/// Mode for `/tmp` when the image does not ship one.
const TMP_MODE: u32 = 0o1777;

/// Where the guest agent is installed inside an imported image.
///
/// Not `/sbin/init`: see the module documentation. A dotted directory keeps it
/// out of the way of the image's own layout.
const AGENT_DIR: &str = ".isopod";
/// Path of the agent binary within the image, relative to its root.
const AGENT_PATH: &str = ".isopod/init";

/// Empty mountpoints an isopod base must ship, created if the image lacks them.
///
/// `/overlay` is where the writable scratch is mounted, `/mnt` is the pivot
/// staging point, and `/layers` is where the guest mounts a tmpfs and creates
/// one mountpoint per committed stage layer.
///
/// `/layers` must exist and must be **empty**: a tmpfs needs something to mount
/// over, and preallocating numbered subdirectories is what once capped a chain
/// at nine layers. `/rom` is deliberately absent — it was created by every
/// built-in flavor, read by nothing, and removed in 0.12.0.
const OVERLAY_DIRS: &[&str] = &["overlay", "mnt", "layers"];

/// Pseudo-filesystem mountpoints. The kernel mounts devtmpfs over `/dev`, but
/// the directory has to exist first.
const PSEUDO_DIRS: &[&str] = &["proc", "sys", "dev", "etc", "var"];

/// Where an imported base lands, and the shell-safe name it is addressed by.
///
/// Imported bases live under their own directory so that `images/` stays
/// enumerable by flavor: nothing here is a [`rootfs::RootfsFlavor`], and the
/// design deliberately does not add a variant for one.
pub fn imported_image_path(images: &Path, slug: &str) -> Result<PathBuf> {
    validate_slug(slug)?;
    Ok(images.join("oci").join(format!("{slug}.sqfs")))
}

/// Refuse a slug that could name anything other than a file in the imports
/// directory.
///
/// This is the string that becomes a path, so it gets the treatment a path
/// component gets rather than the treatment a label gets: an allow-list, not a
/// scan for the bad cases someone thought of.
fn validate_slug(slug: &str) -> Result<()> {
    if slug.is_empty() {
        bail!("an imported image needs a name");
    }
    if slug.len() > 128 {
        bail!("image name '{slug}' is longer than 128 characters");
    }
    if slug.starts_with('.') || slug.starts_with('-') {
        bail!("image name '{slug}' may not start with '.' or '-'");
    }
    if let Some(bad) = slug
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        bail!(
            "image name '{slug}' contains {bad:?}; \
             names may use letters, digits, '.', '_' and '-' only"
        );
    }
    Ok(())
}

/// Where an imported image came from, recorded in its sidecar.
///
/// Enough to re-derive the image: the reference that was asked for, the
/// manifest that reference resolved to, and every blob that went into it. A
/// re-import from cached blobs is then a local operation, which matters because
/// **every guest-agent rebuild invalidates every imported base** — the
/// freshness check compares the agent hash, and agent hashes change far more
/// often than the protocol version does.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciProvenance {
    /// The reference as the operator wrote it, e.g. `alpine:3.20`.
    pub source_ref: String,
    /// The platform the index resolved to, e.g. `linux/amd64`.
    pub platform: String,
    /// Digest of the single-platform manifest this image was built from.
    pub manifest_digest: String,
    /// Digest of the config blob.
    pub config_digest: String,
    /// Layer blob digests, in application order.
    pub layer_digests: Vec<String>,
    /// The image config's environment, merged **under** a run's own env.
    pub env: Vec<String>,
    /// The image config's working directory: a run's default cwd.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Recorded, never executed. See the module documentation.
    pub entrypoint: Vec<String>,
    /// Recorded, never executed.
    pub cmd: Vec<String>,
    /// Recorded and **ignored**: the guest agent execs as root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The image shipped its own `/init` and it was replaced by isopod's.
    pub replaced_init: bool,
    /// Paths carrying setuid, setgid or sticky bits inside the image.
    pub setuid_paths: Vec<String>,
}

/// What the adaptation did, for the command's output.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AdaptReport {
    /// Directories created because the image did not ship them.
    pub dirs_created: Vec<String>,
    /// The image shipped an `/init` and it was replaced.
    pub replaced_init: bool,
    /// `/tmp` was created (the image did not ship one).
    pub created_tmp: bool,
    /// Special-mode paths carried into the image via the pseudo-file.
    pub special_modes: usize,
}

/// Result of a completed import.
#[derive(Debug, Clone, Serialize)]
pub struct ImportOutcome {
    /// Always `true` on the success path.
    pub ok: bool,
    /// Absolute path to the packed image.
    pub image_path: PathBuf,
    /// The name the image is addressed by.
    pub slug: String,
    /// Image size in bytes.
    pub bytes: u64,
    /// The image's content id — what a stage records and the warm pool keys on.
    pub sha256: String,
    /// What the adaptation changed.
    pub adapt: AdaptReport,
    /// Where the image came from.
    pub provenance: OciProvenance,
    /// Notices an operator has to see, because they describe something the
    /// import decided **not** to do. These belong in the command's output and
    /// not only in the documentation: nobody reads the documentation for the
    /// thing that silently did not happen.
    pub notes: Vec<String>,
}

// ===========================================================================
// Adaptation
// ===========================================================================

/// Add what the guest agent needs to be PID 1 in `tree`.
///
/// `tree` is an unpacked rootfs, still on the host and still owned by the
/// operator. `agent` is the static musl guest-agent binary.
///
/// # Errors
/// Refuses an image with no `/bin/sh`, since the MCP surface sends
/// `["/bin/sh", "-c", …]` and a run would otherwise fail with a bare exit 127
/// long after the import looked like it worked.
pub fn adapt(tree: &Path, agent: &Path) -> Result<AdaptReport> {
    if resolve_in_tree(tree, "bin/sh").is_none() {
        bail!(
            "this image has no /bin/sh, so isopod cannot run a command in it. \
             Distroless and scratch-based images are not importable: the exec \
             surface is `/bin/sh -c <command>`. Import a base with a shell \
             (alpine, debian, ubuntu) and add your application to it."
        );
    }

    let mut report = AdaptReport {
        dirs_created: Vec::new(),
        replaced_init: false,
        created_tmp: false,
        special_modes: 0,
    };

    for dir in PSEUDO_DIRS.iter().chain(OVERLAY_DIRS.iter()) {
        if ensure_dir(tree, dir)? {
            report.dirs_created.push(format!("/{dir}"));
        }
    }

    // `/tmp` is created only if the image lacks one; an image that ships its own
    // keeps whatever mode it chose. The sticky bit is not written here — it goes
    // into the pseudo-file with every other special mode, so nothing setuid,
    // setgid or sticky is ever materialised on the host.
    if ensure_dir(tree, "tmp")? {
        report.dirs_created.push("/tmp".into());
        report.created_tmp = true;
    }

    // The agent, and the one path the kernel actually boots.
    ensure_dir(tree, AGENT_DIR)?;
    let dest = tree.join(AGENT_PATH);
    std::fs::copy(agent, &dest)
        .with_context(|| format!("installing the guest agent at /{AGENT_PATH}"))?;
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 /{AGENT_PATH}"))?;

    let init = tree.join("init");
    if std::fs::symlink_metadata(&init).is_ok() {
        report.replaced_init = true;
        remove_any(&init).context("removing the image's own /init")?;
    }
    // Relative, so it resolves against the image's root rather than the host's
    // at any point where something other than the kernel reads it.
    std::os::unix::fs::symlink(AGENT_PATH, &init)
        .with_context(|| format!("symlink /init -> /{AGENT_PATH}"))?;

    Ok(report)
}

/// Create `tree/rel` if it is not already a directory, with an explicit mode.
/// Returns whether it was created.
fn ensure_dir(tree: &Path, rel: &str) -> Result<bool> {
    let path = tree.join(rel);
    match std::fs::symlink_metadata(&path) {
        // Already a directory, or a symbolic link to one — a usrmerge image
        // points `/var/run` and friends at other places, and replacing those
        // would be exactly the silent content mutation this module avoids.
        Ok(md) if md.is_dir() || md.file_type().is_symlink() => return Ok(false),
        Ok(_) => bail!(
            "the image has a non-directory at /{rel}, which isopod needs as a \
             directory; this image cannot be adapted"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("stat /{rel}")));
        }
    }
    std::fs::create_dir_all(&path).with_context(|| format!("mkdir /{rel}"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(DIR_MODE))
        .with_context(|| format!("chmod {DIR_MODE:o} /{rel}"))?;
    Ok(true)
}

/// Remove a file, symbolic link or directory at `path`.
fn remove_any(path: &Path) -> Result<()> {
    let md = std::fs::symlink_metadata(path)?;
    if md.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Resolve `rel` **within** `tree`, following symbolic links against the
/// tree's own root, and return the resolved host path if something is there.
///
/// `Path::exists()` is the wrong tool and quietly gives the wrong answer: an
/// image's `/bin/sh -> /bin/busybox` is an absolute link, and `exists()`
/// resolves it against the **host's** root. On any ordinary machine
/// `/bin/busybox` may well be present, so a distroless image with a dangling
/// `/bin/sh` link would pass the shell check and fail much later, inside a VM,
/// as exit 127.
///
/// Loops are bounded rather than detected: a self-referential link costs
/// [`MAX_HOPS`] `readlink` calls and then reports absent, which is the right
/// answer for a link that resolves to nothing.
fn resolve_in_tree(tree: &Path, rel: &str) -> Option<PathBuf> {
    /// `SYMLOOP_MAX`, which is what the kernel would give up after too.
    const MAX_HOPS: usize = 40;

    let mut pending: Vec<String> = split(rel);
    let mut resolved: Vec<String> = Vec::new();
    let mut hops = 0usize;

    while let Some(component) = pending.first().cloned() {
        pending.remove(0);
        match component.as_str() {
            "" | "." => continue,
            ".." => {
                // Clamped at the root: an image's own path cannot address the
                // host, exactly as it could not once the image is mounted.
                resolved.pop();
                continue;
            }
            _ => {}
        }
        resolved.push(component);
        let here = tree.join(resolved.join("/"));
        let md = std::fs::symlink_metadata(&here).ok()?;
        if md.file_type().is_symlink() {
            hops += 1;
            if hops > MAX_HOPS {
                return None;
            }
            let target = std::fs::read_link(&here).ok()?;
            let target = target.to_str()?;
            resolved.pop();
            if target.starts_with('/') {
                resolved.clear();
            }
            let mut rest = split(target);
            rest.append(&mut pending);
            pending = rest;
        }
    }
    let out = tree.join(resolved.join("/"));
    std::fs::symlink_metadata(&out).ok().map(|_| out)
}

fn split(p: &str) -> Vec<String> {
    p.split('/').map(str::to_string).collect()
}

// ===========================================================================
// The pseudo-file: special modes, applied inside the image only
// ===========================================================================

/// Render one `mksquashfs` pseudo-file line modifying `path`'s mode.
///
/// The path is **always quoted and escaped**, never interpolated raw. Every one
/// of these paths came out of an attacker-authored tar, and the pseudo-file
/// format is line- and space-delimited with a type field in the second
/// position: an entry named `evil c 0666 0 0 1 3` would otherwise render a line
/// that reads as "create a character device". Measured, that particular payload
/// makes `mksquashfs` exit 1 rather than build the node — but only because `m`
/// is not a valid octal mode, which is not a property worth depending on.
///
/// Control characters cannot reach here: the extractor refuses any name
/// containing one, so a newline cannot forge a whole line. Quoting covers the
/// rest — spaces, `#`, quotes and backslashes are all legal in a tar name.
fn pseudo_line(path: &str, mode: u32) -> String {
    let escaped = path.replace('\\', r"\\").replace('"', "\\\"");
    format!("\"{escaped}\" m {mode:o} 0 0\n")
}

/// Write the pseudo-file for `modes` and return its path.
fn write_pseudo_file(dir: &Path, modes: &[(String, u32)]) -> Result<PathBuf> {
    let path = dir.join("pseudo");
    let mut f =
        std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    for (p, mode) in modes {
        f.write_all(pseudo_line(p, *mode).as_bytes())
            .with_context(|| format!("writing a pseudo-file entry for {p}"))?;
    }
    f.sync_all().context("fsync pseudo-file")?;
    Ok(path)
}

/// How many entries in `image` carry a setuid, setgid or sticky bit.
///
/// Counted rather than matched per path, and that is the point: `mksquashfs`
/// **silently ignores** a pseudo-file line naming a path it cannot find, and
/// exits 0 while doing it. So a mis-encoded path does not fail the pack — it
/// produces an image quietly missing the bit, which for `/bin/su` or `ping` is
/// a broken image that looks fine. A count is also immune to the thing that
/// makes per-path matching fragile here: the names may contain spaces, quotes
/// and `#`, so parsing them back out of a listing is its own source of error.
fn count_special_modes(image: &Path) -> Result<usize> {
    let out = std::process::Command::new("unsquashfs")
        .arg("-ll")
        .arg(image)
        .output()
        .context("spawning unsquashfs (is squashfs-tools installed?)")?;
    if !out.status.success() {
        bail!(
            "unsquashfs -ll failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| {
            // The mode string is the first field: `-rwsr-xr-x`, `drwxrwxrwt`.
            let Some(mode) = line.split_whitespace().next() else {
                return false;
            };
            mode.len() == 10
                && mode
                    .chars()
                    .skip(1)
                    .any(|c| matches!(c, 's' | 'S' | 't' | 'T'))
        })
        .count())
}

// ===========================================================================
// Pack and stamp
// ===========================================================================

/// Everything the caller has to supply that this module cannot work out.
pub struct ImportSpec<'a> {
    /// The name the image will be addressed by.
    pub slug: &'a str,
    /// Special modes recorded by the extractor, applied inside the image only.
    pub special_modes: &'a [(String, u32)],
    /// Where the image came from.
    pub provenance: OciProvenance,
}

/// Pack an adapted tree into a base image and stamp its sidecar.
///
/// The pack is the same pinned invocation the built-in flavors use, so an
/// imported base gets the same guarantee: the content id follows the tree and
/// not the clock, and re-importing the same source image on the same host with
/// the same squashfs-tools yields the same id — which is what lets a stage
/// stamped against an imported base survive a re-import.
pub fn pack_and_stamp(
    tree: &Path,
    images: &Path,
    spec: &ImportSpec<'_>,
    adapt: AdaptReport,
) -> Result<ImportOutcome> {
    let dest = imported_image_path(images, spec.slug)?;
    let parent = dest.parent().expect("the imports path has a parent");
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let work = tempfile::tempdir_in(parent).context("creating a pack workdir")?;

    // `/tmp` created by the adaptation needs its sticky bit inside the image,
    // and it is applied here with everything else rather than written to the
    // host tree.
    let mut modes: Vec<(String, u32)> = spec.special_modes.to_vec();
    if adapt.created_tmp {
        modes.push(("tmp".to_string(), TMP_MODE));
    }
    modes.sort();
    modes.dedup_by(|a, b| a.0 == b.0);

    let pseudo = write_pseudo_file(work.path(), &modes)?;
    let tmp_img = work.path().join("image.sqfs");
    rootfs::pack_squashfs_with_pseudo(tree, &tmp_img, &pseudo)?;

    // `mksquashfs` ignores a pseudo-file line it cannot place, silently and
    // with exit 0, so "it packed" is not evidence the bits landed.
    let applied = count_special_modes(&tmp_img)?;
    if applied != modes.len() {
        bail!(
            "the packed image carries {applied} setuid/setgid/sticky entries but \
             {} were recorded — the pack step did not apply every mode it was \
             given, and an image missing them is one where `ping` and `sudo` \
             silently do not work",
            modes.len()
        );
    }

    std::fs::File::open(&tmp_img)
        .and_then(|f| f.sync_all())
        .context("fsync the packed image")?;

    let provenance = spec.provenance.clone();
    rootfs::publish_imported_image(&tmp_img, &dest, spec.slug, provenance.clone())?;

    let bytes = std::fs::metadata(&dest)
        .with_context(|| format!("stat {}", dest.display()))?
        .len();
    let sha256 = paths::sha256_file(&dest)?;

    let mut notes = Vec::new();
    if provenance.user.is_some() {
        notes.push(format!(
            "the image's USER ({}) is ignored: isopod's guest agent execs as root",
            provenance.user.as_deref().unwrap_or_default()
        ));
    }
    if !provenance.entrypoint.is_empty() || !provenance.cmd.is_empty() {
        notes.push(
            "the image's ENTRYPOINT and CMD are recorded but never executed: PID 1 \
             is isopod's guest agent, which does the overlay mounts and the pivot"
                .to_string(),
        );
    }
    if adapt.replaced_init {
        notes.push("the image shipped its own /init and it was replaced".to_string());
    }

    Ok(ImportOutcome {
        ok: true,
        image_path: dest,
        slug: spec.slug.to_string(),
        bytes,
        sha256,
        adapt: AdaptReport {
            special_modes: modes.len(),
            ..adapt
        },
        provenance,
        notes,
    })
}

/// Read an imported image's sidecar, if it has one.
pub fn read_provenance(image: &Path) -> Result<Option<OciProvenance>> {
    Ok(rootfs::read_image_meta(image)?.and_then(|m: ImageMeta| m.oci))
}

// ===========================================================================
// Listing and removing imported bases
// ===========================================================================

/// Every imported base under `images`, as `(name, image path)`, sorted by name.
///
/// The directory **is** the index: the image file is the only record that an
/// image was imported, so there is no second list to drift out of step with it.
/// Everything else in there is skipped, and the cases worth naming are the ones
/// that look like an image and are not — a directory called `x.sqfs`, a link
/// that resolves to nothing, and the `.meta.json` sidecars, which live beside
/// their images rather than under them. A name the import could not have
/// produced is skipped too: listing it would offer a base that
/// [`BaseRef::parse`](super::BaseRef::parse) then refuses.
pub(crate) fn list_imported(images: &Path) -> Result<Vec<(String, PathBuf)>> {
    let dir = images.join("oci");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        // Nothing has ever been imported: an empty list, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("reading {}", dir.display()))),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading an entry in {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sqfs") {
            continue;
        }
        // `metadata`, not `symlink_metadata`: a link to a real image is one, and
        // a link to nothing is not, whatever it is called.
        if !std::fs::metadata(&path)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if validate_slug(name).is_err() {
            continue;
        }
        out.push((name.to_string(), path));
    }
    out.sort();
    Ok(out)
}

/// Result of `isopod image rm`.
#[derive(Debug, Clone, Serialize)]
pub struct RemoveImportOutcome {
    /// Always `true` on the success path.
    pub ok: bool,
    /// The base that is gone, spelled the way it was booted: `oci:<name>`.
    pub removed: String,
    /// Where the image was.
    pub image_path: PathBuf,
    /// Bytes freed — the image and its sidecar, not the cached layer blobs.
    pub bytes_freed: u64,
    /// `true` when stages recording this base were overridden with `--force`.
    pub forced: bool,
    /// Stages that record this base. Non-empty only on a forced removal, which
    /// is the one case where the operator has to be handed what they broke.
    pub stages: Vec<String>,
    /// Notices an operator has to see: what a forced removal cost, and where
    /// the bytes that were *not* freed still are.
    pub notes: Vec<String>,
}

/// Remove an imported base, refusing while a stage records it.
///
/// # Errors
/// If no image of that name is imported, or stages record it and `force` is
/// not set.
pub fn remove_imported(name: &str, force: bool) -> Result<RemoveImportOutcome> {
    remove_imported_in(&paths::images_dir()?, &paths::stages_dir()?, name, force)
}

/// [`remove_imported`] against explicit directories — the seam the tests drive,
/// since `$ISOPOD_HOME` is process-global.
pub(crate) fn remove_imported_in(
    images: &Path,
    stages: &Path,
    name: &str,
    force: bool,
) -> Result<RemoveImportOutcome> {
    let name = imported_name(name)?;
    let path = imported_image_path(images, name)?;
    if !path.exists() {
        bail!(
            "no imported image named '{name}' at {}; `isopod image ls` lists what is here",
            path.display()
        );
    }
    let base = format!("{IMPORTED_PREFIX}{name}");

    // A stage's layers are overlay upperdirs over one specific root, so a stage
    // that recorded this base is a stage that cannot boot without it. The check
    // is an exact match on the recorded string and not a prefix one: `oci:app`
    // and `oci:app-2` are different bases, and a prefix test would have the
    // second protecting the first.
    let holders: Vec<String> = crate::stage::list_in(stages)?
        .into_iter()
        .filter(|s| s.base == base)
        .map(|s| format!("{} ({})", s.stage_id, s.label))
        .collect();
    if !holders.is_empty() && !force {
        bail!(
            "refusing to remove {base}: still the base of: {}. Those layers were made \
             over that root and mean nothing without it, so they stop booting until \
             the same image is imported under the same name; pass --force to remove \
             it anyway",
            holders.join(", ")
        );
    }

    // Read the provenance before the image it lives beside is deleted — the
    // cached blobs outlive the image, and an operator who wants those bytes
    // back has to be told where they are.
    let source_ref = read_provenance(&path)?.map(|p| p.source_ref);
    let bytes_freed = rootfs::remove_image_and_meta(&path)?;

    let mut notes = Vec::new();
    if force && !holders.is_empty() {
        notes.push(format!(
            "{} stage(s) still record {base} and cannot boot until an image is \
             imported under that name again",
            holders.len()
        ));
    }
    if let Some(reference) = &source_ref {
        notes.push(format!(
            "the cached layer blobs for {reference} are kept at {}, so a re-import is \
             local; delete that directory to reclaim them",
            blob_cache_dir(images, reference).display()
        ));
    }
    Ok(RemoveImportOutcome {
        ok: true,
        removed: base,
        image_path: path,
        bytes_freed,
        forced: force && !holders.is_empty(),
        stages: if force { holders } else { Vec::new() },
        notes,
    })
}

/// The imported name an `image rm` argument addresses.
///
/// `oci:alpine-3.20` and `alpine-3.20` both name the same image, because
/// `oci:` is how every other surface spells it and retyping it here is not a
/// test worth setting. The prefix is stripped, never required.
///
/// A **bare** name that is a built-in flavor is refused rather than looked for
/// under `oci/`: `isopod image rm base-alpine` means "delete the toolchain
/// base" to whoever typed it, and "no imported image named base-alpine" answers
/// a question they did not ask. `oci:base-alpine` still addresses an imported
/// image of that name — which is the whole reason the prefix exists.
fn imported_name(spelling: &str) -> Result<&str> {
    if let Some(name) = spelling.strip_prefix(IMPORTED_PREFIX) {
        return Ok(name);
    }
    if RootfsFlavor::from_slug(spelling).is_ok() {
        bail!(
            "'{spelling}' is a built-in flavor, not an imported image, and \
             `isopod image rm` removes imported images only. Rebuild it with \
             `isopod image build-rootfs --flavor {spelling} --force`, or pass \
             `{IMPORTED_PREFIX}{spelling}` if you really did import an image of \
             that name"
        );
    }
    Ok(spelling)
}

// ===========================================================================
// The whole import, end to end
// ===========================================================================

/// Where the image comes from. All three end up in the same place — an OCI
/// image layout on disk — and share every step after that.
#[derive(Debug, Clone)]
pub enum ImportSource {
    /// A registry reference, e.g. `alpine:3.20`.
    Registry(String),
    /// A directory that already is an OCI image layout.
    OciLayout(PathBuf),
    /// A `docker save` tarball.
    DockerSave(PathBuf),
}

impl ImportSource {
    /// What the sidecar records as the source, and what a slug is derived from.
    fn describe(&self) -> String {
        match self {
            Self::Registry(r) => r.clone(),
            Self::OciLayout(p) | Self::DockerSave(p) => p.display().to_string(),
        }
    }
}

/// Turn a reference or a path into a name that may become a file.
///
/// `alpine:3.20` becomes `alpine-3.20`, `ghcr.io/org/app:v1` becomes
/// `ghcr.io-org-app-v1`. Anything the name rules do not allow becomes `-`, and
/// runs of `-` collapse so a path full of separators does not become a row of
/// dashes. The result still goes through [`validate_slug`]: this is a
/// convenience, not the guard.
pub fn slug_for(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for c in source.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_') {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches(|c| c == '-' || c == '.').to_string();
    if trimmed.is_empty() {
        "image".to_string()
    } else {
        trimmed
    }
}

/// How much of a reference stays readable in its cache directory's name.
const CACHE_NAME_MAX: usize = 48;

/// Where a registry reference's layer blobs are cached.
///
/// Keyed by a digest of the **whole** reference rather than by its slug.
/// [`slug_for`] maps every run of characters a name may not contain to a single
/// dash, so `a/b:c` and `a-b-c` produce the same string, as do
/// `ghcr.io/x/y` and `ghcr.io-x-y` — and that string used to be the whole key.
///
/// A shared cache directory is not merely untidy, because the directory is an
/// **OCI image layout**: it holds content-addressed blobs, which two references
/// can safely share, and one `index.json`, which they cannot. `index.json` is
/// rewritten by every pull to name that pull's manifest, and the import reads
/// it back immediately afterwards. Two imports of colliding references running
/// at once therefore interleave into an image packed from the *other*
/// reference's manifest and layers, while its sidecar records the reference
/// that was asked for and that reference's manifest digest. Nothing detects it:
/// every blob verifies against its own digest, because nothing was substituted
/// at the blob level. Digests answer "are these the bytes that were named"; the
/// key has to answer "whose layout is this", and a lossy one cannot.
///
/// The readable prefix is kept so the cache is still browsable, and truncated
/// because a reference can be far longer than a directory name wants to be.
fn blob_cache_dir(images: &Path, reference: &str) -> PathBuf {
    images.join("oci-blobs").join(blob_cache_key(reference))
}

/// The directory name [`blob_cache_dir`] uses: a readable prefix, then enough
/// of the reference's sha256 that two references cannot collide.
fn blob_cache_key(reference: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(reference.as_bytes()));
    let readable: String = slug_for(reference).chars().take(CACHE_NAME_MAX).collect();
    // Truncation can land mid-separator; a trailing dash reads as a missing
    // component rather than a cut one.
    let readable = readable.trim_end_matches(['-', '.']);
    format!("{readable}-{}", &digest[..16])
}

/// Pull, unpack, adapt, pack and stamp — the whole import.
///
/// `slug` names the resulting base; when absent it is derived from the source.
/// `force` overwrites an image of that name.
pub fn import(source: &ImportSource, slug: Option<&str>, force: bool) -> Result<ImportOutcome> {
    let images = paths::images_dir()?;
    let slug = match slug {
        Some(s) => s.to_string(),
        None => slug_for(&source.describe()),
    };
    let dest = imported_image_path(&images, &slug)?;
    if dest.exists() && !force {
        bail!(
            "an imported image named '{slug}' is already at {}; \
             pass --force to replace it, or --name to import alongside it",
            dest.display()
        );
    }

    // The agent is resolved before any network or disk work, so a missing one
    // fails in a second rather than after a gigabyte.
    let agent = rootfs::locate_checked_agent_pub()?;

    let work = tempfile::tempdir().context("creating an import workdir")?;
    let (layout_dir, pulled) = materialise_layout(source, work.path(), &images)?;

    let layout = open_layout(&layout_dir, source)?;
    let platform = Platform::host();
    let manifest = layout
        .resolve(&platform)
        .with_context(|| format!("resolving {platform} in the image index"))?;
    let config = layout
        .config(&manifest.config)
        .context("reading the image config")?;

    // Unpack every layer onto one tree. The blobs were verified as whole files
    // before any of this: `tar` stops at the end-of-archive marker, so
    // verifying while the caller reads would verify only part of a blob.
    let tree = work.path().join("rootfs");
    let mut unpacker = Unpacker::create(&tree, Limits::default())
        .map_err(|e| anyhow::anyhow!("preparing the unpack destination: {e}"))?;
    for layer in &manifest.layers {
        let blob = layout
            .blob(layer)
            .with_context(|| format!("opening layer {}", layer.digest))?;
        let compression = Compression::of(&layer.media_type).ok_or_else(|| {
            anyhow::anyhow!(
                "layer {} has media type '{}', which isopod cannot unpack. \
                 Foreign (\"non-distributable\") layers are not in the image at \
                 all — their bytes live somewhere the registry only points at.",
                layer.digest,
                layer.media_type
            )
        })?;
        let applied = match compression {
            Compression::None => unpacker.apply_layer(blob),
            Compression::Gzip => unpacker.apply_layer(flate2::read::GzDecoder::new(blob)),
            Compression::Zstd => bail!(
                "layer {} is zstd-compressed, which this build cannot decompress. \
                 Nearly every image in the wild is gzip; re-push the image with \
                 gzip layers, or import it from a `docker save` tarball.",
                layer.digest
            ),
        };
        applied.map_err(|e| anyhow::anyhow!("layer {}: {e}", layer.digest))?;
    }
    let report = unpacker
        .finish()
        .map_err(|e| anyhow::anyhow!("promoting the unpacked tree: {e}"))?;

    let adapted = adapt(&tree, &agent)?;

    let provenance = OciProvenance {
        source_ref: source.describe(),
        platform: platform.to_string(),
        manifest_digest: pulled.unwrap_or_else(|| manifest.config.digest.to_string()),
        config_digest: manifest.config.digest.to_string(),
        layer_digests: manifest
            .layers
            .iter()
            .map(|l| l.digest.to_string())
            .collect(),
        env: config.env.clone(),
        working_dir: config.working_dir.clone(),
        entrypoint: config.entrypoint.clone(),
        cmd: config.cmd.clone(),
        user: config.user.clone(),
        replaced_init: adapted.replaced_init,
        setuid_paths: report.setuid_paths.iter().map(|(p, _)| p.clone()).collect(),
    };

    let spec = ImportSpec {
        slug: &slug,
        special_modes: &report.setuid_paths,
        provenance,
    };
    let mut outcome = pack_and_stamp(&tree, &images, &spec, adapted)?;

    // Things the extractor decided not to materialise. An operator wondering
    // where a device node went has to be told, and the documentation is not
    // where they will look.
    if !report.devices_skipped.is_empty() {
        outcome.notes.push(format!(
            "{} device or FIFO entries were skipped rather than created; the guest \
             gets its /dev from a devtmpfs the agent mounts",
            report.devices_skipped.len()
        ));
    }
    if report.xattrs_dropped > 0 {
        outcome.notes.push(format!(
            "{} extended attributes were dropped",
            report.xattrs_dropped
        ));
    }
    Ok(outcome)
}

/// Open `dir` as an OCI image layout, explaining a failure in terms of where
/// the bytes came from.
///
/// The reader's own message is "no `oci-layout`", which is accurate and
/// unhelpful: what an operator needs to know is *which* of the three ways in
/// they used and what that failure means for it. A pull that was interrupted
/// leaves exactly this, on purpose — `index.json` is written last, so an
/// incomplete layout is one the reader refuses rather than one it half-believes.
/// A tarball, on the other hand, is far more likely to be the **legacy**
/// `docker save` format, which is not a layout at all.
fn open_layout(dir: &Path, source: &ImportSource) -> Result<Layout> {
    match Layout::open(dir) {
        Ok(l) => Ok(l),
        Err(e) => {
            // `manifest.json` with no `oci-layout` is the pre-OCI archive
            // Docker has emitted for a decade: a top-level manifest naming
            // `<hash>/layer.tar` directories. Refusing it by name beats
            // refusing it as a corrupt layout, which is what it looks like.
            if dir.join("manifest.json").is_file() && !dir.join("oci-layout").is_file() {
                bail!(
                    "{} is a legacy `docker save` archive (a top-level manifest.json \
                     naming <hash>/layer.tar), not an OCI image layout, and isopod \
                     reads the OCI layout only. Either re-export it with a Docker \
                     that writes an OCI archive (`docker save` on 25+ with the \
                     containerd image store), or `skopeo copy docker-archive:<tar> \
                     oci:<dir>` and import that with --oci-layout.",
                    source.describe()
                );
            }
            let hint = match source {
                ImportSource::Registry(_) => {
                    " — an interrupted pull leaves exactly this, since index.json is \
                     written last; re-run to resume it"
                }
                ImportSource::DockerSave(_) => {
                    " — the tarball extracted, but its contents are not an image layout"
                }
                ImportSource::OciLayout(_) => "",
            };
            // Named as the operator wrote it: for a tarball the extraction
            // directory is a temporary path they have never seen.
            Err(anyhow::Error::new(e))
                .with_context(|| format!("reading the image layout in {}{hint}", source.describe()))
        }
    }
}

/// Get an OCI image layout on disk for `source`, returning it and the manifest
/// digest when the source knew one.
fn materialise_layout(
    source: &ImportSource,
    work: &Path,
    images: &Path,
) -> Result<(PathBuf, Option<String>)> {
    match source {
        ImportSource::Registry(reference) => {
            // Blobs are cached outside the workdir so a re-import after an
            // agent rebuild — which invalidates every imported base — does not
            // re-download a gigabyte it already has.
            let cache = blob_cache_dir(images, reference);
            let mut puller =
                Puller::new(reference).map_err(|e| anyhow::anyhow!("{reference}: {e}"))?;
            let pulled = puller
                .pull_into(&cache)
                .map_err(|e| anyhow::anyhow!("pulling {reference}: {e}"))?;
            Ok((cache, Some(pulled.manifest_digest.to_string())))
        }
        ImportSource::OciLayout(dir) => Ok((dir.clone(), None)),
        ImportSource::DockerSave(tar) => {
            // A `docker save` tarball is attacker-authored too, so it is
            // extracted by the same confined extractor the layers go through
            // rather than by a second, laxer one. Whiteouts and special modes
            // are meaningless in an archive of blobs, and costing nothing is
            // the right price for not maintaining a second tar reader.
            let dest = work.join("layout");
            let file =
                std::fs::File::open(tar).with_context(|| format!("opening {}", tar.display()))?;
            let mut u = Unpacker::create(&dest, Limits::default())
                .map_err(|e| anyhow::anyhow!("preparing to extract the tarball: {e}"))?;
            u.apply_layer(file)
                .map_err(|e| anyhow::anyhow!("extracting {}: {e}", tar.display()))?;
            u.finish()
                .map_err(|e| anyhow::anyhow!("extracting {}: {e}", tar.display()))?;
            Ok((dest, None))
        }
    }
}

#[cfg(test)]
mod tests;
