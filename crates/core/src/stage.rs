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

/// Identity of the squashfs base a stage's layers were built against.
///
/// The flavor slug alone does not identify a base: `base-alpine` is rebuilt
/// whenever its pinned packages or the baked-in guest agent move, and a stage's
/// layers are overlay upperdirs over *that build's* root. `sha256` is the
/// content id the image's build sidecar records ([`crate::image::ImageMeta`]),
/// or `None` for an image carrying no sidecar — one built before stamping
/// existed, where nothing can be compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseId {
    /// Base flavor slug (`base-sqfs` / `base-alpine`).
    pub flavor: String,
    /// The sha256 the image's build sidecar *claims* for it, when there is one.
    ///
    /// Deliberately not a re-hash: hashing hundreds of MB on every run to catch
    /// a case that only arises if someone edits the image store by hand is the
    /// wrong trade. It does mean this identifies the recorded build, not the
    /// bytes on disk — [`check_base`] can only be as truthful as the sidecar.
    pub sha256: Option<String>,
}

impl BaseId {
    /// A base identity with whatever content id the caller could establish.
    #[must_use]
    pub fn new(flavor: impl Into<String>, sha256: Option<String>) -> Self {
        Self {
            flavor: flavor.into(),
            sha256,
        }
    }

    /// A base whose content id is unknown (no build sidecar). Stages committed
    /// against it record no stamp, and forks of them are not content-checked.
    #[must_use]
    pub fn unstamped(flavor: impl Into<String>) -> Self {
        Self::new(flavor, None)
    }
}

/// The outcome of comparing a stage's recorded base against the base image this
/// host would actually boot it on. See [`check_base`].
///
/// The two failure modes are separate variants rather than one `Mismatch`
/// because they have different answers: a rebuilt base is the *same* root moved
/// on, which an operator may knowingly accept, while another flavor is a
/// different root entirely and is never acceptable. Collapsing them into one
/// value let a caller write a single `if allow_skew` arm and excuse both — which
/// is exactly what happened, and what the type now prevents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseCheck {
    /// Compatible — either the content ids match, or one side records none and
    /// there is nothing to compare.
    Ok,
    /// The stage records a content id but the image on this host has no
    /// sidecar, so the comparison could not be made. Carries the advisory.
    Unverifiable(String),
    /// Same flavor, different build: the image has been rebuilt since the layers
    /// were made over it. Refusable-but-overridable — the operator may know the
    /// layers do not depend on what changed.
    RebuiltBase(String),
    /// A different base flavor altogether. **Never** overridable: these layers
    /// were not built over an older version of this root, they were built over
    /// another one.
    WrongFlavor(String),
}

impl BaseCheck {
    /// The explanation, for the variants that carry one.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        match self {
            BaseCheck::Ok => None,
            BaseCheck::Unverifiable(m) | BaseCheck::RebuiltBase(m) | BaseCheck::WrongFlavor(m) => {
                Some(m)
            }
        }
    }

    /// Whether this verdict blocks the fork outright, regardless of any opt-in.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(self, BaseCheck::WrongFlavor(_))
    }
}

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
    /// Base image identifier (`base-sqfs` / `base-alpine`).
    pub base: String,
    /// Content id (sha256) of the base image *build* the layers were made
    /// against, when that image carried a build sidecar.
    ///
    /// `None` for a stage committed before this field existed, or on an
    /// unstamped image. Unstamped stages keep booting unchecked: nothing was
    /// recorded, so there is nothing to disagree with (see [`check_base`]).
    #[serde(default)]
    pub base_sha256: Option<String>,
    /// Creation time (Unix seconds).
    pub created_unix: u64,
    /// Apparent (logical) size of `layer.ext4` in bytes.
    pub bytes_apparent: u64,
    /// Allocated (on-disk) size of `layer.ext4` in bytes (smaller — it is sparse).
    pub bytes_allocated: u64,
}

impl StageMeta {
    /// The base identity this stage was committed against.
    #[must_use]
    pub fn base_id(&self) -> BaseId {
        BaseId::new(self.base.clone(), self.base_sha256.clone())
    }
}

/// Compare the base a stage was committed on against `current` — the base image
/// this host would boot it on now.
///
/// A rebuilt base image is not the base the stage's layers were made over. The
/// layers are overlay upperdirs, so they still *mount*: the merge succeeds and
/// the breakage surfaces later, as a chain whose contents no longer match the
/// root beneath them (site-packages whose interpreter moved is the usual shape).
/// This is the check that turns that into a refusal before the VM boots.
///
/// Pure — every input is supplied by the caller, so the messages are unit
/// testable without an image store. Policy (refuse / warn / override) belongs to
/// the caller; this only reports what the comparison says.
#[must_use]
pub fn check_base(stage: &StageMeta, current: &BaseId) -> BaseCheck {
    if stage.base != current.flavor {
        return BaseCheck::WrongFlavor(format!(
            "stage {} ({:?}) was committed on base {:?}, but this run resolved base {:?}. \
             A stage's layers only mean anything over the base they were built on; fork it \
             without `--base` (a stage's recorded base is authoritative) or rebuild the stage \
             on {:?}.",
            stage.stage_id, stage.label, stage.base, current.flavor, current.flavor,
        ));
    }
    // Nothing recorded ⇒ nothing to disagree with. Every stage committed before
    // stamping existed lands here, and keeps booting exactly as it did. A blank
    // stamp counts as nothing recorded: it cannot have come from `sha256_file`,
    // and comparing it produces "was built on image , but this host's is …".
    let Some(stamped) = non_empty(stage.base_sha256.as_deref()) else {
        return BaseCheck::Ok;
    };
    let Some(present) = non_empty(current.sha256.as_deref()) else {
        return BaseCheck::Unverifiable(format!(
            "stage {} ({:?}) records the {} image it was built on ({}), but that image has no \
             build-metadata sidecar on this host, so the two cannot be compared — the stage is \
             booting on a base that may not be the one its layers were made over. Rebuilding \
             the image (`isopod image build-rootfs --flavor {} --force`) restores the stamp. \
             The pack is timestamp-pinned, so an unchanged tree restores the SAME id and \
             nothing else changes; if the tree has moved on — a new agent, different \
             packages — the id is new, and every stage recording the old one then refuses to \
             fork until it is rebuilt or booted with the opt-in.",
            stage.stage_id,
            stage.label,
            stage.base,
            short_id(stamped),
            stage.base,
        ));
    };
    if stamped == present {
        return BaseCheck::Ok;
    }
    BaseCheck::RebuiltBase(format!(
        "stage {} ({:?}) was built on {} image {}, but this host's {} image is {} — it has been \
         rebuilt since. The stage's layers are overlay upperdirs over the older root, so they \
         would mount silently over the new one and leave a chain that no longer matches what is \
         beneath it. Rebuild the stage on the current image: re-run what produced it starting \
         from `--stage base --base {}`.",
        stage.stage_id,
        stage.label,
        stage.base,
        short_id(stamped),
        stage.base,
        short_id(present),
        stage.base,
    ))
}

/// A content id that is present and not blank.
fn non_empty(sha: Option<&str>) -> Option<&str> {
    sha.map(str::trim).filter(|s| !s.is_empty())
}

/// First 12 characters of a content id, for messages (full sha256s make the
/// difference between two of them harder to see, not easier).
///
/// Counts characters, not bytes: these ids come off disk as `String`s with no
/// validation, so a corrupt or hand-edited `meta.json` can carry any UTF-8 at
/// all. Byte-slicing one would abort inside the function that exists to explain
/// a refusal — turning "your stage cannot boot, here is why" into a panic.
fn short_id(sha: &str) -> String {
    sha.chars().take(12).collect()
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
/// `base` is the base image this run actually booted; its content id is stamped
/// into the stage so a later fork can refuse a base that has been rebuilt since
/// (see [`check_base`]).
///
/// `allow_base_skew` carries the operator's opt-out forward from the boot. A run
/// that was allowed to *start* on a rebuilt base must also be allowed to save
/// what it produced — otherwise the escape hatch strands the work it exists to
/// enable, and rebasing a stage onto a new image becomes impossible. A *flavor*
/// mismatch is refused either way: those layers are not stale, they belong to a
/// different root.
///
/// # Errors
/// - the label is empty,
/// - the named `parent` does not exist,
/// - the parent was committed on a base this one may not stack on,
/// - the resulting chain would exceed [`MAX_CHAIN_DEPTH`],
/// - or the file cannot be hashed / copied / written.
pub fn commit(
    scratch_path: &Path,
    label: &str,
    parent: Option<&str>,
    base: &BaseId,
    allow_base_skew: bool,
) -> Result<StageMeta> {
    commit_in(
        &paths::stages_dir()?,
        scratch_path,
        label,
        parent,
        base,
        allow_base_skew,
    )
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

/// Compare **every stage in a chain** against the base image this host would
/// boot it on, returning the most serious verdict.
///
/// [`check_base`] alone is not enough, because a chain is only as sound as its
/// oldest layer. Checking the tip lets one unstamped link launder everything
/// behind it: fork a stamped stage while the image is unstamped and the commit
/// records `None`; that child then compares clean against any image forever,
/// while its chain still mounts an ancestor's layers built over a root that is
/// gone. The ancestors are what get mounted, so the ancestors are what must be
/// checked.
///
/// Severity order is [`BaseCheck::WrongFlavor`] > [`BaseCheck::RebuiltBase`] >
/// [`BaseCheck::Unverifiable`] > [`BaseCheck::Ok`]; the message names the
/// offending ancestor, which is rarely the stage the operator asked for.
///
/// # Errors
/// If the stage store cannot be read.
pub fn check_base_chain(stage: &StageMeta, current: &BaseId) -> Result<BaseCheck> {
    check_base_chain_in(&paths::stages_dir()?, stage, current)
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

/// Read-buffer size for [`stage_id_for`]'s hash pass, in bytes (4 MiB).
///
/// `std::io::copy`'s 8 KiB stack buffer made the pass syscall-bound: 131072
/// `read()` calls per apparent GiB, each one also paying to zero-fill its slice
/// when it lands in a hole. 4 MiB cuts that to 256 calls and keeps BLAKE3's
/// SIMD kernels fed with large slices. Larger buffers measured no faster.
const HASH_BUF_LEN: usize = 4 * 1024 * 1024;

/// The content-addressed stage id for `path`: `st-` + first 16 hex characters of
/// the streamed BLAKE3 hash of the file.
///
/// The digest is over the file's full **apparent** bytes — holes in a sparse
/// file read back as zeros, and those zeros are part of the identity. This is
/// load-bearing: every stage id in every existing store was derived this way,
/// so an implementation that fed the hasher anything else (skipping holes, say)
/// would silently re-identify every stage and orphan every fork. Only the I/O
/// pattern may change here, never the bytes.
///
/// # Errors
/// If the file cannot be opened or read.
pub fn stage_id_for(path: &Path) -> Result<String> {
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; HASH_BUF_LEN];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!("hashing {}", path.display())))
            }
        };
        hasher.update(&buf[..n]);
    }
    let hex = hex::encode(hasher.finalize().as_bytes());
    Ok(format!("st-{}", &hex[..16]))
}

// ===========================================================================
// Root-parameterized implementations (unit-testable without $ISOPOD_HOME).
// ===========================================================================

pub(crate) fn commit_in(
    root: &Path,
    scratch_path: &Path,
    label: &str,
    parent: Option<&str>,
    base: &BaseId,
    allow_base_skew: bool,
) -> Result<StageMeta> {
    if label.trim().is_empty() {
        bail!("stage label must not be empty");
    }
    let stage_id = stage_id_for(scratch_path)?;
    let by_id = get_by_id_in(root, &stage_id)?;
    let by_label = list_in(root)?.into_iter().find(|s| s.label == label);

    match (by_id, by_label) {
        // Content-addressed store: identical bytes *under the same label* ⇒
        // identical id ⇒ genuinely idempotent. Re-running the same build is the
        // ordinary way to reach this, and it must keep succeeding.
        (Some(existing), Some(same)) if existing.stage_id == same.stage_id => {
            eprintln!(
                "stage commit: {stage_id} already present (content-addressed); \
                 returning existing stage {:?}",
                existing.name
            );
            return Ok(existing);
        }
        // A label is a *reference* other runs resolve by, and `resolve_in` returns
        // an exact label match before it considers prefixes — so committing a stage
        // labelled exactly what another workflow uses as a prefix would silently
        // redirect that workflow onto this layer chain. The caller picks the label,
        // so refusing is the only way that stays impossible.
        (_, Some(clash)) => bail!(
            "stage label {label:?} already refers to stage {} (name {:?}). Labels are how \
             other runs name a stage, so reusing one would move an existing reference onto \
             different content. Pick another label, or fork what is already there with \
             `--stage {label}`.",
            clash.stage_id,
            clash.name,
        ),
        // Same bytes, different label. The store is keyed by content, so the
        // requested label cannot be recorded at all: reporting success here handed
        // back the *other* stage's id and name, and every later `stage: "<label>"`
        // then failed to resolve — which reads as a lost commit rather than a label
        // that was never written.
        (Some(existing), None) => bail!(
            "this scratch is byte-identical to stage {} (label {:?}), so committing it as \
             {label:?} would record nothing: the store is content-addressed, and one set of \
             bytes has one id. Use `--stage {}` to build on it, or make the layer differ.",
            existing.stage_id,
            existing.label,
            existing.label,
        ),
        (None, None) => {}
    }

    // Resolve the parent and build the root-first chain (self last). A stacked
    // stage MUST share its parent's base: the layers are overlay upperdirs built
    // against that base's root, so mounting them over a different base would
    // silently produce a broken merge (e.g. site-packages with no interpreter).
    let (parent_id, mut chain) = match parent {
        Some(pid) => {
            let pmeta = get_by_id_in(root, pid)?
                .ok_or_else(|| anyhow!("parent stage {pid:?} not found in the stage store"))?;
            // Same flavor is not enough: a rebuilt image is a different root
            // under the same slug, and the run path refuses to boot that fork
            // unless the operator opted out. Re-checking here keeps the store
            // from recording a mixed-build chain that nobody asked for, while
            // letting the opt-out through — that is how a stage gets rebased
            // onto a new image at all.
            //
            // The whole parent CHAIN is checked, not just the parent: the new
            // layer is mounted over every ancestor, so an ancestor built over a
            // vanished root is this commit's problem too, however clean the
            // immediate parent looks.
            match check_base_chain_in(root, &pmeta, base)? {
                BaseCheck::Ok => {}
                BaseCheck::Unverifiable(why) => {
                    eprintln!("stage commit: stacking on stage {pid:?}: {why}");
                }
                v @ BaseCheck::WrongFlavor(_) => {
                    bail!(
                        "refusing to stack on stage {pid:?}: {}",
                        v.message().unwrap_or_default()
                    );
                }
                v @ BaseCheck::RebuiltBase(_) => {
                    let why = v.message().unwrap_or_default();
                    if !allow_base_skew {
                        bail!("refusing to stack on stage {pid:?}: {why}");
                    }
                    eprintln!(
                        "stage commit: stacking on stage {pid:?} across a rebuilt base, \
                         as the caller allowed: {why}"
                    );
                }
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
        base: base.flavor.clone(),
        base_sha256: base.sha256.clone(),
        created_unix: now_unix(),
        bytes_apparent: fmeta.len(),
        bytes_allocated: fmeta.blocks() * 512,
    };
    write_meta(&dir, &meta)?;
    Ok(meta)
}

pub(crate) fn list_in(root: &Path) -> Result<Vec<StageMeta>> {
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

pub(crate) fn resolve_in(root: &Path, reference: &str) -> Result<StageMeta> {
    // The empty string is a prefix of every label, so step 4 below resolved it to
    // whatever the single stage in a one-stage store happened to be — forking a
    // layer chain nobody named. An omitted stage has its own spelling (`None`,
    // which means the toolchain base); an empty one is a mistake.
    if reference.trim().is_empty() {
        bail!(
            "stage reference must not be empty (omit it entirely to start from the \
             toolchain base)"
        );
    }
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

pub(crate) fn check_base_chain_in(
    root: &Path,
    stage: &StageMeta,
    current: &BaseId,
) -> Result<BaseCheck> {
    // Rank so the worst verdict in the chain is the one returned: a single
    // WrongFlavor ancestor decides the whole chain, and an Unverifiable link
    // must not mask a RebuiltBase one further down.
    fn rank(c: &BaseCheck) -> u8 {
        match c {
            BaseCheck::Ok => 0,
            BaseCheck::Unverifiable(_) => 1,
            BaseCheck::RebuiltBase(_) => 2,
            BaseCheck::WrongFlavor(_) => 3,
        }
    }

    let mut worst = BaseCheck::Ok;
    for id in &stage.chain {
        // The tip is in its own chain; use the meta we were handed rather than
        // re-reading it, so a caller checking an uncommitted stage still works.
        let ancestor = if id == &stage.stage_id {
            stage.clone()
        } else {
            match get_by_id_in(root, id)? {
                Some(m) => m,
                // A layer with no readable meta.json: the artifact is there (a
                // missing one is `chain_paths`' error to raise) but nothing says
                // what it was built over. That is precisely the state this check
                // must not read as "fine".
                None => {
                    let unknown = BaseCheck::Unverifiable(format!(
                        "stage {} ({:?}) has an ancestor {id} whose metadata is missing, so what \
                         its layers were built over cannot be established.",
                        stage.stage_id, stage.label,
                    ));
                    if rank(&unknown) > rank(&worst) {
                        worst = unknown;
                    }
                    continue;
                }
            }
        };
        let verdict = check_base(&ancestor, current);
        if rank(&verdict) > rank(&worst) {
            worst = verdict;
        }
    }
    // Name the chain when the offending stage is not the one that was asked for:
    // "stage X was built on …" is baffling when the operator typed Y.
    if let (Some(msg), true) = (worst.message(), stage.chain.len() > 1) {
        let annotated = format!(
            "{msg} (reached through the chain of stage {} ({:?}), which mounts that layer)",
            stage.stage_id, stage.label,
        );
        worst = match worst {
            BaseCheck::Unverifiable(_) => BaseCheck::Unverifiable(annotated),
            BaseCheck::RebuiltBase(_) => BaseCheck::RebuiltBase(annotated),
            BaseCheck::WrongFlavor(_) => BaseCheck::WrongFlavor(annotated),
            BaseCheck::Ok => BaseCheck::Ok,
        };
    }
    Ok(worst)
}

pub(crate) fn chain_paths_in(root: &Path, stage: &StageMeta) -> Result<Vec<PathBuf>> {
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

    /// The busybox base with no content id — the shape every store test that is
    /// not about base stamping wants, and the shape a host with unstamped images
    /// produces.
    fn sqfs() -> BaseId {
        BaseId::unstamped("base-sqfs")
    }

    /// The busybox base as a specific build.
    fn sqfs_build(sha: &str) -> BaseId {
        BaseId::new("base-sqfs", Some(sha.to_string()))
    }

    #[test]
    fn commit_round_trip_meta_and_id_and_mode() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let content = b"isopod stage fixture content \x00\x01\x02";
        let scratch = fixture(home.path(), "scratch.img", content);
        let meta = commit_in(&root, &scratch, "demo/first", None, &sqfs(), false).unwrap();

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

        // Idempotent: re-committing identical content under the SAME label returns
        // the same stage. This is the case that happens in practice — the same
        // build run twice — and it must stay a no-op rather than an error.
        let again = commit_in(&root, &scratch, "demo/first", None, &sqfs(), false).unwrap();
        assert_eq!(again, meta, "re-commit of identical content is idempotent");
        assert_eq!(
            list_in(&root).unwrap().len(),
            1,
            "no duplicate stage created"
        );

        // Identical content under a DIFFERENT label is refused, and says why. It
        // used to report success while recording nothing: the store is keyed by
        // content, so the requested label was silently dropped and every later
        // `stage: "some/other-label"` failed to resolve — which reads as a commit
        // that was lost rather than a label that was never written.
        let why = commit_in(&root, &scratch, "some/other-label", None, &sqfs(), false)
            .expect_err("must refuse")
            .to_string();
        assert!(why.contains("byte-identical"), "{why}");
        assert!(why.contains("demo/first"), "{why}");
        assert_eq!(list_in(&root).unwrap().len(), 1, "still no duplicate");
    }

    #[test]
    fn a_label_cannot_be_moved_onto_different_content() {
        // `resolve_in` prefers an exact label match over a prefix match, so a stage
        // labelled exactly what another workflow uses as a *prefix* would capture
        // that workflow's reference — and `commit_as` is chosen by the caller.
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let first = fixture(home.path(), "a.img", b"first content");
        let original = commit_in(&root, &first, "myenv", None, &sqfs(), false).unwrap();
        // "my" resolves to it today, by unique label prefix.
        assert_eq!(resolve_in(&root, "my").unwrap().stage_id, original.stage_id);

        let second = fixture(home.path(), "b.img", b"different content entirely");
        let why = commit_in(&root, &second, "my", None, &sqfs(), false)
            .map(|_| String::new())
            .unwrap_or_else(|e| e.to_string());
        // Committing *is* allowed here — "my" is not an existing label, only a
        // prefix of one — but the reference it captures must now be unambiguous
        // rather than silently redirected.
        if why.is_empty() {
            let after = resolve_in(&root, "my").unwrap();
            assert_ne!(
                after.stage_id, original.stage_id,
                "an exact label match is the documented winner"
            );
        }

        // The case that must never be permitted: reusing the exact label.
        let third = fixture(home.path(), "c.img", b"third content");
        let why = commit_in(&root, &third, "myenv", None, &sqfs(), false)
            .expect_err("an exact label collision must be refused")
            .to_string();
        assert!(why.contains("already refers to"), "{why}");
        assert_eq!(
            resolve_in(&root, "myenv").unwrap().stage_id,
            original.stage_id,
            "the existing reference still points where it did"
        );
    }

    #[test]
    fn an_empty_stage_reference_does_not_resolve_to_whatever_is_there() {
        // "" is a prefix of every label, so the unique-prefix step resolved it to
        // the sole stage in a one-stage store and forked a layer chain nobody named.
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = fixture(home.path(), "s.img", b"only stage");
        commit_in(&root, &scratch, "sole", None, &sqfs(), false).unwrap();

        for empty in ["", "   "] {
            let why = resolve_in(&root, empty)
                .expect_err("an empty reference must not resolve")
                .to_string();
            assert!(why.contains("must not be empty"), "{why}");
        }
        // The real reference still works, so this is not a general regression.
        assert_eq!(resolve_in(&root, "sole").unwrap().label, "sole");
    }

    #[test]
    fn commit_rejects_empty_label() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = fixture(home.path(), "s.img", b"x");
        assert!(commit_in(&root, &scratch, "   ", None, &sqfs(), false).is_err());
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
            &sqfs(),
            false,
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"alpine-bytes"),
            "alpine",
            None,
            &sqfs(),
            false,
        )
        .unwrap();
        let c = commit_in(
            &root,
            &fixture(home.path(), "c", b"beta-bytes"),
            "beta",
            None,
            &sqfs(),
            false,
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
            &sqfs(),
            false,
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"bb"),
            "alpine",
            None,
            &sqfs(),
            false,
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
            &sqfs(),
            false,
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"layerB"),
            "B",
            Some(&a.stage_id),
            &sqfs(),
            false,
        )
        .unwrap();
        let c = commit_in(
            &root,
            &fixture(home.path(), "c", b"layerC"),
            "C",
            Some(&b.stage_id),
            &sqfs(),
            false,
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
            &sqfs(),
            false,
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
            &sqfs(),
            false,
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"pB"),
            "B",
            Some(&a.stage_id),
            &sqfs(),
            false,
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
            base_sha256: None,
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
            let m = commit_in(
                &root,
                &f,
                &format!("l{i}"),
                parent.as_deref(),
                &sqfs(),
                false,
            )
            .unwrap();
            assert_eq!(m.chain.len(), i + 1);
            parent = Some(m.stage_id);
        }
        let over = fixture(home.path(), "over", b"one-too-many");
        let err = commit_in(&root, &over, "over", parent.as_deref(), &sqfs(), false)
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
            &sqfs(),
            false,
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"rB"),
            "B",
            Some(&a.stage_id),
            &sqfs(),
            false,
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
            &sqfs(),
            false,
        )
        .unwrap();
        commit_in(
            &root,
            &fixture(home.path(), "y", b"two"),
            "two",
            None,
            &sqfs(),
            false,
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

        let meta = commit_in(&root, &scratch, "e2e/real-ext4", None, &sqfs(), false).unwrap();
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

    /// `stage_id_for` is the identity of every stage ever committed, so its
    /// digest must be byte-identical to the one the store was built on: the
    /// BLAKE3 of the file's full apparent bytes, streamed through
    /// `std::io::copy` — holes included, as the zeros they read back as. The
    /// buffered read exists to change the I/O pattern, never the bytes; this
    /// test holds the old implementation in place as the definition.
    #[test]
    fn the_buffered_hash_is_byte_identical_to_the_streamed_hash_ids_were_built_on() {
        /// The pre-0.12.4 implementation, verbatim: the digest every existing
        /// stage id in every existing store was derived with.
        fn streamed_id(path: &Path) -> String {
            let mut file = std::fs::File::open(path).unwrap();
            let mut hasher = blake3::Hasher::new();
            std::io::copy(&mut file, &mut hasher).unwrap();
            format!("st-{}", &hex::encode(hasher.finalize().as_bytes())[..16])
        }

        let home = tempfile::tempdir().unwrap();

        // A sparse file shaped to exercise every boundary the buffered loop
        // has: data at the start, data straddling the first buffer boundary,
        // holes between and after, and an apparent size that is NOT a multiple
        // of the buffer — so the pass ends on a short read inside a hole.
        let p = home.path().join("scratch.img");
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::File::create(&p).unwrap();
            f.write_all(b"isopod sparse hash fixture").unwrap();
            f.seek(SeekFrom::Start(HASH_BUF_LEN as u64 - 17)).unwrap();
            f.write_all(&[0xAB; 64]).unwrap();
            f.set_len(2 * HASH_BUF_LEN as u64 + 137).unwrap();
        }
        let m = std::fs::metadata(&p).unwrap();
        assert!(
            m.blocks() * 512 < m.len(),
            "fixture must be genuinely sparse (allocated {} < apparent {})",
            m.blocks() * 512,
            m.len()
        );

        assert_eq!(
            stage_id_for(&p).unwrap(),
            streamed_id(&p),
            "the buffered hash changed the digest; every existing stage id \
             would be silently re-identified"
        );
        // And both equal the hash of the apparent bytes read back whole —
        // holes hash as their zeros, not as nothing.
        let apparent = std::fs::read(&p).unwrap();
        assert_eq!(apparent.len() as u64, m.len());
        assert_eq!(
            stage_id_for(&p).unwrap(),
            format!(
                "st-{}",
                &hex::encode(blake3::hash(&apparent).as_bytes())[..16]
            ),
            "the id must be the hash of the file's apparent bytes"
        );

        // The same equality over the production writer's artifact: a real
        // sparse ext4 from `make_scratch_ext4`, when mkfs.ext4 is available.
        if which_mkfs().is_some() {
            let scratch = home.path().join("scratch.ext4");
            make_scratch_ext4(&scratch, 32).expect("mkfs a 32 MiB scratch");
            assert_eq!(stage_id_for(&scratch).unwrap(), streamed_id(&scratch));
        } else {
            eprintln!("skipping the ext4 half: mkfs.ext4 not found on PATH");
        }
    }

    // -- base stamping and the skew check ------------------------------------

    #[test]
    fn commit_stamps_the_base_build_and_it_survives_the_round_trip() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let scratch = fixture(home.path(), "s", b"stamped");
        let meta = commit_in(
            &root,
            &scratch,
            "stamped",
            None,
            &sqfs_build("aa11bb22cc33"),
            false,
        )
        .unwrap();
        assert_eq!(meta.base, "base-sqfs");
        assert_eq!(meta.base_sha256.as_deref(), Some("aa11bb22cc33"));

        // Through the real writer and back through the real reader: the stamp is
        // what a later fork will actually see.
        let reread = resolve_in(&root, "stamped").unwrap();
        assert_eq!(reread, meta);
        assert_eq!(reread.base_id(), sqfs_build("aa11bb22cc33"));
    }

    /// The 35 stages that exist on a real host were committed before this field
    /// did. Their `meta.json` has no `base_sha256` key at all, and they must keep
    /// loading, resolving and forking exactly as they did.
    ///
    /// The fixture is produced by the production writer and then has the one key
    /// removed — hand-writing the legacy JSON would test a shape the writer never
    /// emitted.
    #[test]
    fn a_stage_committed_before_stamping_still_loads_and_forks() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let scratch = fixture(home.path(), "legacy", b"pre-stamp layer");
        let meta = commit_in(&root, &scratch, "legacy/env", None, &sqfs(), false).unwrap();

        // Strip the key, leaving every other field exactly as written.
        let mp = root.join(&meta.stage_id).join(META_FILE);
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&mp).unwrap())
                .expect("the writer emits valid JSON");
        assert!(
            doc.as_object_mut().unwrap().remove("base_sha256").is_some(),
            "the writer must have emitted the key for this test to be removing it"
        );
        std::fs::write(&mp, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

        let legacy =
            resolve_in(&root, "legacy/env").expect("a pre-stamp meta.json must still load");
        assert_eq!(legacy.base_sha256, None);
        assert_eq!(legacy.stage_id, meta.stage_id);
        assert_eq!(list_in(&root).unwrap().len(), 1);
        assert_eq!(chain_paths_in(&root, &legacy).unwrap().len(), 1);

        // Unstamped ⇒ unchecked, on any build of the recorded base.
        assert_eq!(check_base(&legacy, &sqfs()), BaseCheck::Ok);
        assert_eq!(
            check_base(&legacy, &sqfs_build("whatever-is-there")),
            BaseCheck::Ok
        );

        // And it can still be stacked on.
        let next = fixture(home.path(), "next", b"stacked on a legacy stage");
        let stacked = commit_in(
            &root,
            &next,
            "legacy/env2",
            Some(&legacy.stage_id),
            &sqfs(),
            false,
        )
        .unwrap();
        assert_eq!(
            stacked.chain,
            vec![legacy.stage_id, stacked.stage_id.clone()]
        );
    }

    #[test]
    fn check_base_accepts_the_build_the_stage_was_made_on() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = fixture(home.path(), "s", b"same build");
        let meta = commit_in(
            &root,
            &scratch,
            "env",
            None,
            &sqfs_build("deadbeef1234"),
            false,
        )
        .unwrap();

        assert_eq!(
            check_base(&meta, &sqfs_build("deadbeef1234")),
            BaseCheck::Ok
        );
    }

    #[test]
    fn check_base_refuses_an_image_rebuilt_since_the_stage_was_committed() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = fixture(home.path(), "s", b"built on the old image");
        let meta = commit_in(
            &root,
            &scratch,
            "env/deps",
            None,
            &sqfs_build("0000aaaa1111bbbb"),
            false,
        )
        .unwrap();

        let BaseCheck::RebuiltBase(why) = check_base(&meta, &sqfs_build("9999cccc8888dddd")) else {
            panic!("a rebuilt base must not be accepted");
        };
        // Both ids, the stage, and a way out — a refusal naming neither build
        // leaves the operator guessing which image changed.
        assert!(why.contains("0000aaaa1111"), "stamped id: {why}");
        assert!(why.contains("9999cccc8888"), "present id: {why}");
        assert!(
            why.contains(&meta.stage_id) && why.contains("env/deps"),
            "{why}"
        );
        assert!(
            why.contains("--stage base --base base-sqfs"),
            "the fix: {why}"
        );
        // Short ids, not full 64-hex walls of text.
        assert!(!why.contains("0000aaaa1111bbbb"), "id is shortened: {why}");
    }

    #[test]
    fn check_base_reports_an_unstamped_image_as_unverifiable() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = fixture(home.path(), "s", b"stamped stage, unstamped image");
        let meta = commit_in(
            &root,
            &scratch,
            "env",
            None,
            &sqfs_build("abcdef012345"),
            false,
        )
        .unwrap();

        let BaseCheck::Unverifiable(why) = check_base(&meta, &sqfs()) else {
            panic!("an image with no sidecar cannot be compared, and must say so");
        };
        assert!(why.contains("abcdef012345"), "{why}");
        assert!(
            why.contains("build-rootfs --flavor base-sqfs --force"),
            "the fix names the one flavor, not a whole-store rebuild: {why}"
        );
        // Following the advice can re-stamp the image as a new build, which
        // turns this warning into a refusal for every stage holding the old id.
        // Since the pack is timestamp-pinned that only happens when the tree
        // really moved, but advice that can cost that much has to say so.
        assert!(
            why.contains("refuses to fork"),
            "the cost of the fix: {why}"
        );
    }

    #[test]
    fn check_base_refuses_a_different_flavor() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = fixture(home.path(), "s", b"busybox layer");
        let meta = commit_in(&root, &scratch, "env", None, &sqfs(), false).unwrap();

        let BaseCheck::WrongFlavor(why) = check_base(&meta, &BaseId::unstamped("base-alpine"))
        else {
            panic!("a stage's layers do not transfer between flavors");
        };
        assert!(
            why.contains("base-sqfs") && why.contains("base-alpine"),
            "{why}"
        );
    }

    /// The run path refuses to boot a fork across a rebuilt base, so a stacked
    /// commit across one should be unreachable — but the store is what the chain
    /// outlives, and a caller that never went through the run path must not be
    /// able to record a mixed-build chain by accident.
    #[test]
    fn stacking_refuses_a_parent_built_on_another_image() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"parent"),
            "A",
            None,
            &sqfs_build("1111111111111111"),
            false,
        )
        .unwrap();

        let err = commit_in(
            &root,
            &fixture(home.path(), "b", b"child"),
            "B",
            Some(&a.stage_id),
            &sqfs_build("2222222222222222"),
            false,
        )
        .expect_err("stacking across a rebuilt base must be refused");
        let msg = err.to_string();
        assert!(msg.contains("refusing to stack"), "{msg}");
        assert!(
            msg.contains("111111111111") && msg.contains("222222222222"),
            "{msg}"
        );
        assert_eq!(list_in(&root).unwrap().len(), 1, "nothing was recorded");

        // Same image ⇒ ordinary stacking, unaffected.
        let ok = commit_in(
            &root,
            &fixture(home.path(), "c", b"child"),
            "B",
            Some(&a.stage_id),
            &sqfs_build("1111111111111111"),
            false,
        )
        .unwrap();
        assert_eq!(ok.base_sha256.as_deref(), Some("1111111111111111"));
    }

    /// The laundering shape, at the store level: A stamped, B committed while
    /// the image was unstamped, C on a third image. Checking only the immediate
    /// parent let B's `None` vouch for A, so C — whose chain still mounts A's
    /// layer — was recorded with nobody having opted into anything.
    #[test]
    fn an_unstamped_link_cannot_launder_a_stale_ancestor() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"A"),
            "A",
            None,
            &sqfs_build("1111111111111111"),
            false,
        )
        .unwrap();
        // The image lost its sidecar: nothing can be compared, so B is allowed
        // and records nothing. This link is legitimate — it is what it hides
        // that is not.
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"B"),
            "B",
            Some(&a.stage_id),
            &sqfs(),
            false,
        )
        .expect("an unverifiable base is not a mismatch");
        assert_eq!(b.base_sha256, None);

        // A third image. B alone looks clean against it; B's CHAIN does not.
        let err = commit_in(
            &root,
            &fixture(home.path(), "c", b"C"),
            "C",
            Some(&b.stage_id),
            &sqfs_build("2222222222222222"),
            false,
        )
        .expect_err("an ancestor built over a vanished root must refuse the stack");
        let msg = err.to_string();
        assert!(
            msg.contains(&a.stage_id),
            "names the ancestor, not just the parent: {msg}"
        );
        assert_eq!(list_in(&root).unwrap().len(), 2, "nothing new was recorded");

        // And the verdict is reported for the chain, not only for the tip.
        assert!(matches!(
            check_base_chain_in(&root, &b, &sqfs_build("2222222222222222")).unwrap(),
            BaseCheck::RebuiltBase(_)
        ));
        assert_eq!(
            check_base(&b, &sqfs_build("2222222222222222")),
            BaseCheck::Ok,
            "the tip alone still looks fine — which is exactly why the chain is what counts"
        );
    }

    /// Content ids come off disk as unvalidated strings. Truncating one by bytes
    /// aborts inside the function whose whole job is to explain a refusal.
    #[test]
    fn a_corrupt_content_id_still_produces_a_refusal_rather_than_a_panic() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();
        let meta = commit_in(
            &root,
            &fixture(home.path(), "s", b"x"),
            "env",
            None,
            &sqfs_build("0123456789€uro-not-a-sha"),
            false,
        )
        .unwrap();

        let BaseCheck::RebuiltBase(why) = check_base(&meta, &sqfs_build("abcdef0123456789")) else {
            panic!("a different id is still a different id, however malformed");
        };
        assert!(
            why.contains("0123456789€"),
            "truncates on characters: {why}"
        );
    }

    /// A stamped parent on a host whose image lost its sidecar: nothing can be
    /// compared, so stacking proceeds and the new layer records what it knows,
    /// which is nothing. It must not inherit a stamp it never verified.
    #[test]
    fn stacking_on_an_unstamped_image_records_no_stamp() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"parent"),
            "A",
            None,
            &sqfs_build("3333333333333333"),
            false,
        )
        .unwrap();
        let b = commit_in(
            &root,
            &fixture(home.path(), "b", b"child"),
            "B",
            Some(&a.stage_id),
            &sqfs(),
            false,
        )
        .expect("an unverifiable base is not a mismatch");
        assert_eq!(b.base_sha256, None);
    }

    /// The opt-in exists so a stage can be rebased onto a rebuilt image. It has
    /// to reach the commit too: a run allowed to boot across the skew and then
    /// refused the commit would throw away exactly the work the operator asked
    /// for. It does not extend to a different flavor — those layers are for
    /// another root, not an older one.
    #[test]
    fn the_opt_in_stacks_across_a_rebuilt_image_but_never_across_flavors() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("stages");
        std::fs::create_dir_all(&root).unwrap();

        let a = commit_in(
            &root,
            &fixture(home.path(), "a", b"parent"),
            "A",
            None,
            &sqfs_build("4444444444444444"),
            false,
        )
        .unwrap();

        let rebased = commit_in(
            &root,
            &fixture(home.path(), "b", b"child"),
            "B",
            Some(&a.stage_id),
            &sqfs_build("5555555555555555"),
            true,
        )
        .expect("the operator opted in; the layer is saved");
        assert_eq!(rebased.chain, vec![a.stage_id.clone(), rebased.stage_id]);
        assert_eq!(
            rebased.base_sha256.as_deref(),
            Some("5555555555555555"),
            "the new layer records the image it was actually built on, not its parent's"
        );

        let err = commit_in(
            &root,
            &fixture(home.path(), "c", b"other-flavor child"),
            "C",
            Some(&a.stage_id),
            &BaseId::new("base-alpine", Some("4444444444444444".into())),
            true,
        )
        .expect_err("the opt-in is about a rebuilt base, not a different one");
        assert!(err.to_string().contains("base-alpine"), "{err}");
    }
}
