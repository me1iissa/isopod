//! Stage store — the persistent, content-addressed layer store under
//! `~/.isopod/stages/`.
//!
//! A *stage* is the frozen scratch image a previous run left behind: a
//! read-only sparse ext4 whose content is that run's overlay upperdir (upper
//! files + whiteouts + `trusted.overlay.*` xattrs, preserved byte-exactly). The
//! raw image **is** the artifact — it is never tarred (that would silently drop
//! whiteout char-devices and overlay xattrs, breaking deletions in later
//! layers). Stages are immutable once written; a later run *forks* a stage by
//! booting on top of its chain and *stacks* by committing a fresh layer.
//!
//! On-disk layout, per stage:
//! ```text
//! ~/.isopod/stages/<stage_id>/
//! ├── layer.ext4   # the read-only artifact (mode 0444)
//! └── meta.json    # [`StageMeta`]
//! ```
//! `stage_id` is `st-` followed by the first 16 hex characters of the BLAKE3
//! hash of `layer.ext4`, so identical content always maps to the same id and a
//! re-commit is idempotent.
//!
//! Every public entry point resolves the store root through [`crate::paths`];
//! the `*_in` helpers take an explicit root so the logic is unit-testable
//! against a temp directory without touching `$ISOPOD_HOME` (which is
//! process-global and unsafe to mutate from parallel tests).

use std::collections::HashSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths;

/// Maximum stage-chain depth (root-first chain length, self included).
///
/// Bounded by Firecracker's virtio-MMIO IRQ slot budget (~19 devices; the base
/// squashfs, the writable scratch, vsock and — later — the NIC consume ~5),
/// which PLAN.md pins at a practical layer cap of 10. A chain longer than this
/// could never be booted as drives, so both [`commit`] and [`chain_paths`]
/// reject it.
pub const MAX_CHAIN_DEPTH: usize = 10;

/// Default apparent size of a fresh scratch ext4, in MiB (1 GiB, sparse).
pub const DEFAULT_SCRATCH_MIB: u64 = 1024;

/// Basename of the read-only layer artifact inside a stage directory.
const LAYER_FILE: &str = "layer.ext4";
/// Basename of the stage metadata file inside a stage directory.
const META_FILE: &str = "meta.json";

/// Metadata describing one committed stage.
///
/// Serialized verbatim to `meta.json` and re-used as the CLI's JSON view (so the
/// on-disk schema and the `isopod stage` output never drift). `parent` and
/// `chain` reference stages by their `stage_id`; `chain` is root-first and
/// includes this stage itself as its final element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageMeta {
    /// Content-addressed id: `st-<first 16 hex of BLAKE3(layer.ext4)>`.
    pub stage_id: String,
    /// Human-memorable vanity name (seeded from `stage_id`, unique among stages).
    pub name: String,
    /// User-supplied label passed to `--commit-as` / [`commit`].
    pub label: String,
    /// The stage this one was forked from (`None` for a base-rooted stage).
    pub parent: Option<String>,
    /// Full lineage, root-first, ending with `stage_id` itself.
    pub chain: Vec<String>,
    /// Base image identifier (always `base-sqfs` in v1).
    pub base: String,
    /// Creation time (Unix seconds).
    pub created_unix: u64,
    /// Apparent (logical) size of `layer.ext4` in bytes.
    pub bytes_apparent: u64,
    /// Allocated (on-disk) size of `layer.ext4` in bytes (smaller — it is sparse).
    pub bytes_allocated: u64,
}

/// Commit a scratch image as a new stage and return its metadata.
///
/// The image is BLAKE3-hashed (streamed, no full-file buffering) to derive the
/// content-addressed `stage_id`, sparse-copied into the store, then frozen
/// `0444`. `parent` is the `stage_id` this scratch was forked from (`None` for a
/// stage rooted directly on the squashfs base); the new stage's `chain` is the
/// parent's chain with `stage_id` appended.
///
/// Idempotent on content: if a stage with the same `stage_id` already exists it
/// is returned unchanged (the artifact is immutable, so `label`/`parent` on the
/// second call are ignored).
///
/// # Errors
/// - the label is empty,
/// - the named `parent` does not exist,
/// - the resulting chain would exceed [`MAX_CHAIN_DEPTH`],
/// - or the file cannot be hashed / copied / written.
pub fn commit(
    scratch_path: &Path,
    label: &str,
    parent: Option<&str>,
    base: &str,
) -> Result<StageMeta> {
    commit_in(&paths::stages_dir()?, scratch_path, label, parent, base)
}

/// List every committed stage, sorted oldest-first (`created_unix`, then
/// `stage_id`). Directories without a parseable `meta.json` are skipped (an
/// in-progress or foreign directory is not an error); a corrupt `meta.json` is
/// logged to stderr and skipped.
///
/// # Errors
/// If the stages directory cannot be read.
pub fn list() -> Result<Vec<StageMeta>> {
    list_in(&paths::stages_dir()?)
}

/// Resolve a stage by `stage_id`, vanity name, or unique label prefix.
///
/// Resolution order: exact `stage_id`, then exact vanity name, then exact label,
/// then unique label prefix. An ambiguous match (or no match) is an error naming
/// the candidates.
///
/// # Errors
/// [`anyhow::Error`] if nothing matches or the reference is ambiguous.
pub fn resolve(reference: &str) -> Result<StageMeta> {
    resolve_in(&paths::stages_dir()?, reference)
}

/// Remove a stage, refusing if any *other* stage's chain still references it.
///
/// # Errors
/// If the reference does not resolve, the stage is still referenced by another
/// stage's chain, or the directory cannot be removed.
pub fn remove(reference: &str) -> Result<StageMeta> {
    remove_in(&paths::stages_dir()?, reference)
}

/// Resolve a stage's `layer.ext4` paths in overlay-lowerdir order (root-first =
/// oldest-first), validating the chain depth and that every referenced layer
/// exists on disk.
///
/// The returned paths are attached to the VM as read-only drives `vdb..` in this
/// exact order, so the guest mounts the oldest layer at `/layers/1` and the tip
/// at `/layers/N`.
///
/// # Errors
/// If the chain is empty/malformed, exceeds [`MAX_CHAIN_DEPTH`], or references a
/// stage whose `layer.ext4` is missing.
pub fn chain_paths(stage: &StageMeta) -> Result<Vec<PathBuf>> {
    chain_paths_in(&paths::stages_dir()?, stage)
}

/// Create a fresh, empty, sparse ext4 scratch image at `path` sized `size_mib`
/// MiB.
///
/// The journal is disabled and itable/journal init is eager, matching the
/// deterministic-image recipe used elsewhere; the guest agent creates the
/// overlay `upper`/`work` directories inside it at boot.
///
/// Canonical implementation: [`crate::image::make_scratch_ext4`] (the guest-image
/// track owns the scratch builder; this re-export keeps existing callers stable).
pub use crate::image::make_scratch_ext4;

/// The content-addressed stage id for `path`: `st-` + first 16 hex characters of
/// the streamed BLAKE3 hash of the file.
///
/// # Errors
/// If the file cannot be opened or read.
pub fn stage_id_for(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher).with_context(|| format!("hashing {}", path.display()))?;
    let hex = hex::encode(hasher.finalize().as_bytes());
    Ok(format!("st-{}", &hex[..16]))
}

// ===========================================================================
// Root-parameterized implementations (unit-testable without $ISOPOD_HOME).
// ===========================================================================

fn commit_in(
    root: &Path,
    scratch_path: &Path,
    label: &str,
    parent: Option<&str>,
    base: &str,
) -> Result<StageMeta> {
    if label.trim().is_empty() {
        bail!("stage label must not be empty");
    }
    let stage_id = stage_id_for(scratch_path)?;

    // Content-addressed store: identical bytes ⇒ identical id ⇒ idempotent.
    if let Some(existing) = get_by_id_in(root, &stage_id)? {
        eprintln!(
            "stage commit: {stage_id} already present (content-addressed); \
             returning existing stage {:?}",
            existing.name
        );
        return Ok(existing);
    }

    // Resolve the parent and build the root-first chain (self last). A stacked
    // stage MUST share its parent's base: the layers are overlay upperdirs built
    // against that base's root, so mounting them over a different base would
    // silently produce a broken merge (e.g. site-packages with no interpreter).
    let (parent_id, mut chain) = match parent {
        Some(pid) => {
            let pmeta = get_by_id_in(root, pid)?
                .ok_or_else(|| anyhow!("parent stage {pid:?} not found in the stage store"))?;
            if pmeta.base != base {
                bail!(
                    "base mismatch: stacking on stage {pid:?} (base {:?}) but this run used \
                     base {base:?}; a chain must share one base",
                    pmeta.base
                );
            }
            (Some(pmeta.stage_id), pmeta.chain)
        }
        None => (None, Vec::new()),
    };
    chain.push(stage_id.clone());
    if chain.len() > MAX_CHAIN_DEPTH {
        bail!(
            "stage chain depth {} exceeds the maximum of {MAX_CHAIN_DEPTH} \
             (virtio-MMIO slot budget); flatten the chain first",
            chain.len()
        );
    }

    // Vanity name, unique among existing stages.
    let taken: HashSet<String> = list_in(root)?.into_iter().map(|s| s.name).collect();
    let name = crate::names::unique_name(&stage_id, |n| taken.contains(n));

    let dir = root.join(&stage_id);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating stage dir {}", dir.display()))?;

    // Sparse-copy the artifact, then freeze it read-only. Write to a `.partial`
    // sibling and rename so a crash never leaves a half-written `layer.ext4`.
    let layer = dir.join(LAYER_FILE);
    let layer_tmp = dir.join("layer.ext4.partial");
    sparse_copy(scratch_path, &layer_tmp)?;
    std::fs::set_permissions(&layer_tmp, std::fs::Permissions::from_mode(0o444))
        .with_context(|| format!("chmod 0444 {}", layer_tmp.display()))?;
    std::fs::rename(&layer_tmp, &layer)
        .with_context(|| format!("finalizing {}", layer.display()))?;

    let fmeta = std::fs::metadata(&layer).with_context(|| format!("stat {}", layer.display()))?;
    let meta = StageMeta {
        stage_id,
        name,
        label: label.to_string(),
        parent: parent_id,
        chain,
        base: base.to_string(),
        created_unix: now_unix(),
        bytes_apparent: fmeta.len(),
        bytes_allocated: fmeta.blocks() * 512,
    };
    write_meta(&dir, &meta)?;
    Ok(meta)
}

fn list_in(root: &Path) -> Result<Vec<StageMeta>> {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        // A never-populated store is an empty list, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("reading {}", root.display()))),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading an entry in {}", root.display()))?;
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = entry.path();
        if !dir.join(META_FILE).exists() {
            continue; // in-progress or foreign directory
        }
        match read_meta(&dir) {
            Ok(m) => out.push(m),
            Err(e) => eprintln!("stage list: skipping {}: {e:#}", dir.display()),
        }
    }
    out.sort_by(|a, b| {
        a.created_unix
            .cmp(&b.created_unix)
            .then_with(|| a.stage_id.cmp(&b.stage_id))
    });
    Ok(out)
}

fn resolve_in(root: &Path, reference: &str) -> Result<StageMeta> {
    let stages = list_in(root)?;

    // 1. Exact stage_id (ids are unique).
    if let Some(m) = stages.iter().find(|s| s.stage_id == reference) {
        return Ok(m.clone());
    }
    // 2. Exact vanity name (names are unique among stages).
    let by_name: Vec<&StageMeta> = stages.iter().filter(|s| s.name == reference).collect();
    match by_name.len() {
        1 => return Ok(by_name[0].clone()),
        n if n > 1 => return Err(ambiguous("name", reference, &by_name)),
        _ => {}
    }
    // 3. Exact label (an exact label wins even if it prefixes another label).
    let label_exact: Vec<&StageMeta> = stages.iter().filter(|s| s.label == reference).collect();
    match label_exact.len() {
        1 => return Ok(label_exact[0].clone()),
        n if n > 1 => return Err(ambiguous("label", reference, &label_exact)),
        _ => {}
    }
    // 4. Unique label prefix.
    let by_prefix: Vec<&StageMeta> = stages
        .iter()
        .filter(|s| s.label.starts_with(reference))
        .collect();
    match by_prefix.len() {
        0 => bail!(
            "no stage matches {reference:?} (by id, vanity name, or label prefix); \
             {} stage(s) in the store",
            stages.len()
        ),
        1 => Ok(by_prefix[0].clone()),
        _ => Err(ambiguous("label prefix", reference, &by_prefix)),
    }
}

fn remove_in(root: &Path, reference: &str) -> Result<StageMeta> {
    let target = resolve_in(root, reference)?;
    let referencing: Vec<String> = list_in(root)?
        .into_iter()
        .filter(|s| s.stage_id != target.stage_id && s.chain.iter().any(|c| c == &target.stage_id))
        .map(|s| format!("{} ({})", s.stage_id, s.label))
        .collect();
    if !referencing.is_empty() {
        bail!(
            "refusing to remove {} ({}): still referenced by the chain of: {}",
            target.stage_id,
            target.label,
            referencing.join(", ")
        );
    }
    let dir = root.join(&target.stage_id);
    std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    Ok(target)
}

fn chain_paths_in(root: &Path, stage: &StageMeta) -> Result<Vec<PathBuf>> {
    if stage.chain.is_empty() {
        bail!("stage {} has an empty chain", stage.stage_id);
    }
    if stage.chain.len() > MAX_CHAIN_DEPTH {
        bail!(
            "stage {} chain depth {} exceeds the maximum of {MAX_CHAIN_DEPTH}",
            stage.stage_id,
            stage.chain.len()
        );
    }
    if stage.chain.last().map(String::as_str) != Some(stage.stage_id.as_str()) {
        bail!(
            "stage {} chain is malformed (tip {:?} is not the stage itself)",
            stage.stage_id,
            stage.chain.last()
        );
    }
    let mut out = Vec::with_capacity(stage.chain.len());
    for id in &stage.chain {
        let layer = root.join(id).join(LAYER_FILE);
        if !layer.exists() {
            bail!(
                "stage {} references stage {id}, whose layer {} is missing",
                stage.stage_id,
                layer.display()
            );
        }
        out.push(layer);
    }
    Ok(out)
}

// -- small helpers ----------------------------------------------------------

fn get_by_id_in(root: &Path, id: &str) -> Result<Option<StageMeta>> {
    let dir = root.join(id);
    if !dir.join(META_FILE).exists() {
        return Ok(None);
    }
    Ok(Some(read_meta(&dir)?))
}

fn read_meta(dir: &Path) -> Result<StageMeta> {
    let mp = dir.join(META_FILE);
    let raw = std::fs::read_to_string(&mp).with_context(|| format!("reading {}", mp.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", mp.display()))
}

fn write_meta(dir: &Path, meta: &StageMeta) -> Result<()> {
    let json = serde_json::to_string_pretty(meta).context("serializing stage meta")?;
    let tmp = dir.join("meta.json.partial");
    std::fs::write(&tmp, format!("{json}\n"))
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, dir.join(META_FILE))
        .with_context(|| format!("finalizing {}", dir.join(META_FILE).display()))
}

fn sparse_copy(src: &Path, dst: &Path) -> Result<()> {
    let status = std::process::Command::new("cp")
        .arg("--sparse=always")
        .arg(src)
        .arg(dst)
        .status()
        .context("spawning cp for the sparse layer copy")?;
    if !status.success() {
        bail!(
            "cp --sparse=always {} {} failed ({status})",
            src.display(),
            dst.display()
        );
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ambiguous(kind: &str, reference: &str, candidates: &[&StageMeta]) -> anyhow::Error {
    let list = candidates
        .iter()
        .map(|s| format!("{} ({})", s.stage_id, s.label))
        .collect::<Vec<_>>()
        .join(", ");
    anyhow!("{kind} {reference:?} is ambiguous; candidates: {list}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `bytes` to a fresh file under `dir` and return its path. Stands in
    /// for a real scratch ext4 — `commit` copies and hashes raw bytes, so any
    /// content exercises the store faithfully.
    fn fixture(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn commit_round_trip_meta_and_id_and_mode() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let content = b"isopod stage fixture content \x00\x01\x02";
        let scratch = fixture(home.path(), "scratch.img", content);
        let meta = commit_in(&root, &scratch, "demo/first", None, "base-sqfs").unwrap();

        // Content-addressed id is the first 16 hex of BLAKE3(content).
        let expect_id = format!(
            "st-{}",
            &hex::encode(blake3::hash(content).as_bytes())[..16]
        );
        assert_eq!(meta.stage_id, expect_id);
        assert!(meta.stage_id.starts_with("st-"));
        assert_eq!(meta.stage_id.len(), 3 + 16);

        assert_eq!(meta.label, "demo/first");
        assert_eq!(meta.parent, None);
        assert_eq!(meta.chain, vec![meta.stage_id.clone()]);
        assert_eq!(meta.base, "base-sqfs");
        assert!(!meta.name.is_empty());
        assert!(meta.bytes_apparent >= content.len() as u64);

        // Artifact exists and is frozen read-only (0444).
        let layer = root.join(&meta.stage_id).join("layer.ext4");
        let mode = std::fs::metadata(&layer).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o444, "layer.ext4 must be chmod 444, got {mode:o}");
        assert_eq!(std::fs::read(&layer).unwrap(), content, "content preserved");

        // meta.json round-trips.
        let reread = get_by_id_in(&root, &meta.stage_id).unwrap().unwrap();
        assert_eq!(reread, meta);

        // Idempotent: re-committing identical content returns the same stage.
        let again = commit_in(&root, &scratch, "some/other-label", None, "base-sqfs").unwrap();
        assert_eq!(again, meta, "re-commit of identical content is idempotent");
        assert_eq!(
            list_in(&root).unwrap().len(),
            1,
            "no duplicate stage created"
        );
    }

    #[test]
    fn commit_rejects_empty_label() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = fixture(home.path(), "s.img", b"x");
        assert!(commit_in(&root, &scratch, "   ", None, "base-sqfs").is_err());
    }

    #[test]
    fn resolve_by_id_name_and_unique_label_prefix() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"alpha-bytes"),
            "alpha",
            None,
            "base-sqfs",
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"alpine-bytes"),
            "alpine",
            None,
            "base-sqfs",
        )
        .unwrap();
        let c = commit_in(
            &root,
            &fixture(home.path(), "c", b"beta-bytes"),
            "beta",
            None,
            "base-sqfs",
        )
        .unwrap();

        // Exact id.
        assert_eq!(resolve_in(&root, &a.stage_id).unwrap().stage_id, a.stage_id);
        // Exact vanity name.
        assert_eq!(resolve_in(&root, &b.name).unwrap().stage_id, b.stage_id);
        // Unique label prefix ("be" only matches "beta").
        assert_eq!(resolve_in(&root, "be").unwrap().stage_id, c.stage_id);
        // Exact label wins even though "alpha" shares the "alp" prefix family.
        assert_eq!(resolve_in(&root, "alpha").unwrap().stage_id, a.stage_id);
        // Unique longer prefix.
        assert_eq!(resolve_in(&root, "alph").unwrap().stage_id, a.stage_id);
    }

    #[test]
    fn resolve_ambiguous_prefix_errors_with_candidates() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"aa"),
            "alpha",
            None,
            "base-sqfs",
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"bb"),
            "alpine",
            None,
            "base-sqfs",
        )
        .unwrap();

        let err = resolve_in(&root, "alp").expect_err("ambiguous prefix must error");
        let msg = err.to_string();
        assert!(msg.contains("ambiguous"), "{msg}");
        assert!(
            msg.contains(&a.stage_id) && msg.contains(&b.stage_id),
            "{msg}"
        );

        assert!(resolve_in(&root, "nonexistent").is_err());
    }

    #[test]
    fn chain_paths_are_root_first_and_reference_existing_layers() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"layerA"),
            "A",
            None,
            "base-sqfs",
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"layerB"),
            "B",
            Some(&a.stage_id),
            "base-sqfs",
        )
        .unwrap();
        let c = commit_in(
            &root,
            &fixture(home.path(), "c", b"layerC"),
            "C",
            Some(&b.stage_id),
            "base-sqfs",
        )
        .unwrap();

        assert_eq!(c.parent.as_deref(), Some(b.stage_id.as_str()));
        assert_eq!(
            c.chain,
            vec![a.stage_id.clone(), b.stage_id.clone(), c.stage_id.clone()]
        );

        let paths = chain_paths_in(&root, &c).unwrap();
        let ids: Vec<String> = paths
            .iter()
            .map(|p| {
                p.parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(
            ids,
            vec![a.stage_id, b.stage_id, c.stage_id],
            "root-first order"
        );
        assert!(paths.iter().all(|p| p.ends_with("layer.ext4")));
    }

    #[test]
    fn commit_with_missing_parent_errors() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let err = commit_in(
            &root,
            &fixture(home.path(), "s", b"z"),
            "l",
            Some("st-doesnotexist0"),
            "base-sqfs",
        )
        .expect_err("missing parent must error");
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn chain_paths_errors_on_missing_layer() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"pA"),
            "A",
            None,
            "base-sqfs",
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"pB"),
            "B",
            Some(&a.stage_id),
            "base-sqfs",
        )
        .unwrap();
        // Delete parent A's directory out from under B (bypassing `remove`, which
        // would refuse). B's chain now dangles.
        std::fs::remove_dir_all(root.join(&a.stage_id)).unwrap();

        let err = chain_paths_in(&root, &b).expect_err("dangling parent must error");
        assert!(err.to_string().contains("missing"), "{err}");
    }

    #[test]
    fn chain_paths_rejects_over_depth_chains() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        // Hand-built meta with a chain one past the cap.
        let over: Vec<String> = (0..=MAX_CHAIN_DEPTH)
            .map(|i| format!("st-{i:016x}"))
            .collect();
        let meta = StageMeta {
            stage_id: over.last().unwrap().clone(),
            name: "n".into(),
            label: "l".into(),
            parent: None,
            chain: over.clone(),
            base: "base-sqfs".into(),
            created_unix: 0,
            bytes_apparent: 0,
            bytes_allocated: 0,
        };
        let err = chain_paths_in(&root, &meta).expect_err("over-depth chain must error");
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn commit_rejects_chain_past_the_depth_cap() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        // Build a legal chain exactly MAX_CHAIN_DEPTH deep, then one more.
        let mut parent: Option<String> = None;
        for i in 0..MAX_CHAIN_DEPTH {
            let f = fixture(
                home.path(),
                &format!("f{i}"),
                format!("layer-{i}").as_bytes(),
            );
            let m = commit_in(&root, &f, &format!("l{i}"), parent.as_deref(), "base-sqfs").unwrap();
            assert_eq!(m.chain.len(), i + 1);
            parent = Some(m.stage_id);
        }
        let over = fixture(home.path(), "over", b"one-too-many");
        let err = commit_in(&root, &over, "over", parent.as_deref(), "base-sqfs")
            .expect_err("committing past the cap must error");
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn remove_refuses_referenced_stage_then_allows_after_tip_gone() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"rA"),
            "A",
            None,
            "base-sqfs",
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"rB"),
            "B",
            Some(&a.stage_id),
            "base-sqfs",
        )
        .unwrap();

        // A is referenced by B's chain ⇒ refused.
        let err = remove_in(&root, &a.stage_id).expect_err("referenced stage must be refused");
        assert!(err.to_string().contains("referenced"), "{err}");

        // The tip B has no dependents ⇒ removable; then A becomes removable.
        let removed_b = remove_in(&root, &b.stage_id).unwrap();
        assert_eq!(removed_b.stage_id, b.stage_id);
        assert!(!root.join(&b.stage_id).exists());
        remove_in(&root, &a.stage_id).expect("A removable once B is gone");
        assert!(list_in(&root).unwrap().is_empty());
    }

    #[test]
    fn list_is_sorted_and_skips_non_stage_dirs() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        // A foreign directory with no meta.json is ignored.
        std::fs::create_dir_all(root.join("not-a-stage")).unwrap();

        commit_in(
            &root,
            &fixture(home.path(), "x", b"one"),
            "one",
            None,
            "base-sqfs",
        )
        .unwrap();
        commit_in(
            &root,
            &fixture(home.path(), "y", b"two"),
            "two",
            None,
            "base-sqfs",
        )
        .unwrap();
        let listed = list_in(&root).unwrap();
        assert_eq!(listed.len(), 2, "foreign dir skipped");
        assert!(
            listed[0].created_unix <= listed[1].created_unix,
            "oldest-first"
        );
    }

    #[test]
    fn list_of_empty_store_is_empty() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        // Note: not created — list must treat a missing store as empty.
        assert!(list_in(&root).unwrap().is_empty());
    }

    /// End-to-end over a *real* ext4 image: `make_scratch_ext4` yields a sparse
    /// filesystem, and committing it preserves the bytes exactly, freezes 0444,
    /// and content-addresses it by BLAKE3. Skipped cleanly where `mkfs.ext4` is
    /// unavailable (it is present on the target host).
    #[test]
    fn make_scratch_and_commit_real_ext4() {
        if which_mkfs().is_none() {
            eprintln!("skipping: mkfs.ext4 not found on PATH");
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let scratch = home.path().join("scratch.ext4");
        make_scratch_ext4(&scratch, 32).expect("mkfs a 32 MiB scratch");

        // Sparse: on-disk allocation is well under the 32 MiB apparent size.
        let m = std::fs::metadata(&scratch).unwrap();
        assert_eq!(m.len(), 32 * 1024 * 1024, "apparent size is 32 MiB");
        assert!(
            m.blocks() * 512 < m.len(),
            "scratch must be sparse (allocated {} < apparent {})",
            m.blocks() * 512,
            m.len()
        );

        let meta = commit_in(&root, &scratch, "e2e/real-ext4", None, "base-sqfs").unwrap();
        assert_eq!(meta.stage_id, stage_id_for(&scratch).unwrap());

        let layer = root.join(&meta.stage_id).join("layer.ext4");
        assert_eq!(
            std::fs::metadata(&layer).unwrap().permissions().mode() & 0o777,
            0o444
        );
        assert_eq!(
            std::fs::read(&layer).unwrap(),
            std::fs::read(&scratch).unwrap(),
            "committed layer is byte-identical to the scratch ext4"
        );
        assert_eq!(meta.bytes_apparent, 32 * 1024 * 1024);
    }

    fn which_mkfs() -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join("mkfs.ext4"))
                .find(|p| p.exists())
        })
    }
}
