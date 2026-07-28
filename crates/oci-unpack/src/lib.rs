//! Apply untrusted OCI image layers onto a host directory tree.
//!
//! # Why this crate is separate, and why it is paranoid
//!
//! isopod's whole posture is that guest content stays inside a microVM. Layer
//! extraction breaks that shape: an image is a stack of tar archives written by
//! someone else, and they are unpacked **on the host, as the operator's user,
//! before any VM exists**. Nothing else in the project writes attacker-chosen
//! bytes outside the sandbox boundary, so this crate is built and reviewed on
//! its own, with no dependency on `isopod-core` and no knowledge of isopod.
//!
//! The attack that motivates the design is not a single malicious path — those
//! are easy. It is the **cross-layer symlink**, where each layer is individually
//! innocent:
//!
//! ```text
//!   layer 1:  foo -> /home/melissa        an ordinary symbolic link
//!   layer 2:  foo/.bashrc                 an ordinary file, in-root by spelling
//!   result:   ~/.bashrc overwritten       if the parent chain is ever followed
//! ```
//!
//! `crates/mcp/src/hostio.rs` solves the neighbouring problem — confining a
//! caller-supplied path against the live filesystem — with `canonicalize`. That
//! answer is unavailable here: the tree is being built as it goes and the
//! adversary chooses what is in it, so confinement has to be computed against
//! the **logical tree the extractor is constructing**, never against the host.
//!
//! # How confinement is achieved
//!
//! Every path is walked one component at a time from a descriptor for the
//! staging root, with `openat(2)` and `O_NOFOLLOW`. A symbolic link in any
//! parent position therefore cannot be traversed — the syscall fails, and the
//! layer is refused. That is stronger than checking a resolved path, and it is
//! immune to the case that has broken this project's confinements twice: a
//! **dangling** link, whose target does not exist and so does not `stat`.
//! `O_NOFOLLOW` never looks at the target at all.
//!
//! Symbolic links are still *created* faithfully, targets and all, because
//! inside the finished image they will be resolved against the image's own
//! root. They are simply never followed while building it.
//!
//! # Invariants
//!
//! 1. Every entry name is normalised and confined before anything is opened;
//!    `..`, absolute paths, control characters and non-UTF-8 are refused.
//! 2. Parent resolution walks the logical tree, never the host. A link planted
//!    by layer *N* is not followed by layer *N+1*.
//! 3. `O_NOFOLLOW` on every open, and a directory-fd walk from the root, so a
//!    race on a parent component cannot redirect a write.
//! 4. Hard-link targets are confined by the same walk as entry paths.
//! 5. Character devices, block devices and FIFOs are skipped and reported,
//!    never created.
//! 6. setuid, setgid and sticky bits are never written to the host tree. They
//!    are recorded in [`Report::setuid_paths`] so the pack step can restore
//!    them **inside** the image, where everything is root already and they
//!    grant nothing — and where dropping them outright would break `ping`,
//!    `sudo` and `newgrp`.
//! 7. Whiteouts never survive. `.wh.<name>` deletes; `.wh..wh..opq` discards
//!    everything the lower layers accumulated in that directory. Getting this
//!    subtly wrong yields an image that *works* while containing files the
//!    author deleted — including a secret a `RUN rm` was meant to remove.
//! 8. Every limit failure names the limit, the cap, and the field that raises it.
//! 9. Refusal is total. Layers are applied to a staging directory that is
//!    removed on drop and renamed into place only by [`Unpacker::finish`], so a
//!    refused import leaves no tree behind at all.
//!
//! # Shape
//!
//! ```no_run
//! use isopod_oci_unpack::{Limits, Unpacker};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut u = Unpacker::create(std::path::Path::new("/tmp/rootfs"), Limits::default())?;
//! for layer in ["a.tar", "b.tar"] {
//!     // Layers are applied in order; the caller decompresses.
//!     u.apply_layer(std::fs::File::open(layer)?)?;
//! }
//! let report = u.finish()?;
//! println!("{} entries, {} setuid", report.entries_written, report.setuid_paths.len());
//! # Ok(()) }
//! ```
//!
//! Limits are cumulative over the [`Unpacker`]'s lifetime, not per layer: an
//! image bomb is a property of the image, and a per-layer cap would multiply by
//! however many layers the manifest declares.
//!
//! The tar entry stream is read with the `tar` crate, but `Archive::unpack` is
//! never called: its traversal handling is precisely what this crate replaces.
//!
//! Conventions for whiteouts, entry types and PAX records follow the [OCI Image
//! Layer specification](https://github.com/opencontainers/image-spec/blob/main/layer.md).

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod digest;
pub mod layout;
mod name;
// The only module permitted `unsafe`: `openat` and friends have no safe
// equivalent in `std`, and keeping them in one place is what makes the
// confinement reviewable.
#[allow(unsafe_code)]
mod sys;

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod layout_tests;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use name::Plan;
use sys::Dir;
use tar::EntryType;

/// Ceilings applied while unpacking, so a malicious image cannot exhaust the
/// host before it is ever inspected.
///
/// The byte counters are checked against what is actually **written**, not
/// against any size the archive declares, so a compression bomb is caught by
/// the same guard as an honestly large file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Total bytes written across every layer of one image.
    pub max_total_bytes: u64,
    /// Bytes written for any single entry.
    pub max_entry_bytes: u64,
    /// Entries read across every layer, including whiteouts and skipped nodes.
    pub max_entries: u64,
    /// Bytes in one entry name, as the archive spells it.
    pub max_path_len: usize,
    /// Path components in one entry name.
    ///
    /// Not cosmetic: it is the bound on the recursion in the subtree delete and
    /// the opaque-directory prune, both of which walk a tree whose depth the
    /// archive chose. Real images do not exceed about 15.
    pub max_path_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_bytes: 8 << 30,
            max_entry_bytes: 4 << 30,
            max_entries: 500_000,
            max_path_len: 4096,
            max_path_depth: 256,
        }
    }
}

/// What one layer, or one whole image, turned out to contain.
///
/// The `Vec` fields are the ones a caller must act on rather than merely log:
/// the pack step needs [`Report::setuid_paths`] to restore modes inside the
/// image, and an operator needs [`Report::devices_skipped`] to understand why
/// a node the image shipped is missing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Files, directories, symbolic links and hard links materialised.
    pub entries_written: u64,
    /// File content bytes written.
    pub bytes_written: u64,
    /// `.wh.<name>` markers processed, including ones that matched nothing.
    pub whiteouts_applied: u64,
    /// `.wh..wh..opq` markers processed.
    pub opaque_dirs_applied: u64,
    /// Character/block device and FIFO entries, skipped rather than created.
    pub devices_skipped: Vec<String>,
    /// `(path, mode & 0o7777)` for every entry carrying setuid, setgid or the
    /// sticky bit. The host tree has the permission bits only; these are for
    /// the pack step to reapply inside the image.
    pub setuid_paths: Vec<(String, u32)>,
    /// Extended-attribute PAX records seen and dropped.
    pub xattrs_dropped: u64,
}

impl Report {
    /// Fold one layer's report into a running total.
    fn merge(&mut self, other: &Report) {
        self.entries_written += other.entries_written;
        self.bytes_written += other.bytes_written;
        self.whiteouts_applied += other.whiteouts_applied;
        self.opaque_dirs_applied += other.opaque_dirs_applied;
        self.xattrs_dropped += other.xattrs_dropped;
        self.devices_skipped
            .extend(other.devices_skipped.iter().cloned());
        self.setuid_paths.extend(other.setuid_paths.iter().cloned());
    }
}

/// Why an image was refused.
///
/// Every variant is fatal to the whole import. This crate never sanitises a
/// name and carries on: "we fixed your path for you" is how a traversal turns
/// into a write nobody audited, and an image that needs fixing is an image
/// whose provenance the operator should look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// An entry name contains `..`.
    PathEscapesRoot {
        /// The name, as the archive spelled it.
        entry: String,
    },
    /// An entry name starts with `/`.
    AbsolutePath {
        /// The name, as the archive spelled it.
        entry: String,
    },
    /// A parent component of an entry is a symbolic link.
    SymlinkEscape {
        /// The entry that was being written.
        entry: String,
        /// The component that is a link.
        via: String,
    },
    /// A hard link named a target outside the tree, or one reachable only
    /// through a symbolic link.
    HardlinkEscape {
        /// The link being created.
        entry: String,
        /// The target it named.
        target: String,
    },
    /// An entry name is not UTF-8.
    NonUtf8Name {
        /// The raw bytes, so an operator can identify the entry.
        raw: Vec<u8>,
    },
    /// An entry name contains a control character.
    ControlCharInName {
        /// The name, with the offending byte escaped.
        entry: String,
    },
    /// A [`Limits`] ceiling was reached.
    LimitExceeded {
        /// The [`Limits`] field, by name.
        limit: &'static str,
        /// Its value at the time of the refusal.
        cap: u64,
        /// How to raise it.
        raise: &'static str,
    },
    /// The archive contradicts the layer specification.
    Malformed {
        /// The entry involved, if one is known.
        entry: String,
        /// What is wrong with it.
        detail: String,
    },
    /// The host refused an operation the extractor asked for.
    Io {
        /// The tree-relative path being worked on.
        path: String,
        /// The underlying error.
        detail: String,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathEscapesRoot { entry } => write!(
                f,
                "layer entry {entry:?} contains `..`, so it names a path outside the image \
                 root. isopod refuses the image rather than normalising the name: a path the \
                 archive did not spell is a path no later whiteout or duplicate check agrees \
                 about. Rebuild the image with a tool that emits root-relative entries."
            ),
            Self::AbsolutePath { entry } => write!(
                f,
                "layer entry {entry:?} is an absolute path. Layer entries are relative to the \
                 image root; an absolute one is either a build tool writing outside its own \
                 image or an attempt to reach the host filesystem. Rebuild the image."
            ),
            Self::SymlinkEscape { entry, via } => write!(
                f,
                "layer entry {entry:?} would be written through {via:?}, which is a symbolic \
                 link. A later layer writing through a link an earlier one planted is the \
                 classic image escape — the link can point anywhere on the host, and each \
                 layer looks innocent on its own. isopod never follows a link while unpacking, \
                 so this image cannot be imported. Layers built by diffing a real filesystem \
                 do not contain such an entry; one that does was hand-crafted."
            ),
            Self::HardlinkEscape { entry, target } => write!(
                f,
                "layer entry {entry:?} is a hard link to {target:?}, which is not a plain path \
                 inside the image root, or is reachable only through a symbolic link. A hard \
                 link is a second name for an inode, so it would give the image write access \
                 to a host file no path check could see. Rebuild the image."
            ),
            Self::NonUtf8Name { raw } => write!(
                f,
                "a layer entry name is not valid UTF-8 ({:?}). Every path isopod reports, \
                 compares and hands to the pack step is text, so a name that cannot be text \
                 would be recorded as something other than what was written. Rebuild the \
                 image with UTF-8 names.",
                String::from_utf8_lossy(raw)
            ),
            Self::ControlCharInName { entry } => write!(
                f,
                "layer entry \"{entry}\" contains a control character. A newline forges lines \
                 in any log or report that quotes the name, and a NUL truncates it at the \
                 syscall boundary so that what was checked and what gets created differ. \
                 Rebuild the image with printable names."
            ),
            Self::LimitExceeded { limit, cap, raise } => write!(
                f,
                "this image exceeds the `{limit}` unpack limit of {cap}. The ceilings exist so \
                 an image cannot fill the disk or the inode table before anyone has looked at \
                 it. If the image is genuinely this large, raise `{raise}`."
            ),
            Self::Malformed { entry, detail } => {
                if entry.is_empty() {
                    write!(f, "this layer is not a readable tar archive: {detail}")
                } else {
                    write!(f, "layer entry {entry:?} is malformed: {detail}")
                }
            }
            Self::Io { path, detail } => write!(
                f,
                "unpacking {path:?} failed: {detail}. Nothing was promoted — the staging tree \
                 is removed, so the destination is untouched."
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// The permission bits this crate is willing to put on the host tree.
///
/// Invariant 6: setuid, setgid and sticky are dropped here and recorded for the
/// pack step. Container semantics survive inside the image; nothing setuid is
/// ever materialised in the operator's home directory on the way there.
const fn host_mode(raw: u32) -> u32 {
    raw & 0o777
}

/// The mode of a directory the extractor creates on its own — one no entry in
/// any layer describes, brought into being only because something below it had
/// to be written.
///
/// It is applied with an explicit `fchmod` rather than left to `mkdirat`'s mode
/// argument, which the kernel masks with the process umask. That masking is the
/// bug this constant exists to prevent: an operator running under `umask 077`
/// would get an image whose every implicit directory is `0o700` instead of
/// `0o755`. The regular-file path already sets its mode explicitly for the same
/// reason; the directories created on the way to it did not.
///
/// The consequence is not only fidelity. The pack step turns this tree into an
/// image whose sha256 *is* its identity, so a mode that varies with the
/// operator's shell means the same source image imports to two different images
/// on two hosts, and stages stamped against one cannot be forked on the other.
const DIR_MODE: u32 = 0o755;

/// Applies layers onto a staging tree and promotes it only on success.
///
/// Dropping an `Unpacker` that has not been [`finish`](Unpacker::finish)ed
/// removes the staging tree. That is invariant 9: a refused image leaves
/// nothing behind, so a half-applied layer can never be mistaken for a base.
#[derive(Debug)]
pub struct Unpacker {
    dest: PathBuf,
    staging: PathBuf,
    root: Dir,
    limits: Limits,
    total: Report,
    entries_seen: u64,
    /// Directory modes that cannot be applied yet because they would deny this
    /// process write access to a tree it is still building. Keyed by components
    /// so that reverse iteration yields children before parents.
    deferred_modes: BTreeMap<Vec<String>, u32>,
    promoted: bool,
}

impl Unpacker {
    /// Create a staging tree for `dest`, which must not exist.
    ///
    /// Staging is a sibling of `dest`, so the promotion at the end is a rename
    /// within one filesystem and therefore atomic.
    ///
    /// # Errors
    /// [`Refusal::Io`] if `dest` already exists, if its parent is not writable,
    /// or if a staging directory from an interrupted run is still there.
    pub fn create(dest: &Path, limits: Limits) -> Result<Self, Refusal> {
        let io = |path: &Path, e: &dyn fmt::Display| Refusal::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        };
        let file_name = dest
            .file_name()
            .ok_or_else(|| io(dest, &"the destination names no directory"))?;
        // `symlink_metadata`, not `exists`: a dangling symbolic link at `dest`
        // does not "exist" but would still make the promoting rename land
        // somewhere other than where the caller asked.
        if std::fs::symlink_metadata(dest).is_ok() {
            return Err(io(
                dest,
                &"already exists; unpack destinations are created fresh",
            ));
        }
        let staging = dest.with_file_name(format!(
            ".{}.oci-unpack.{}",
            file_name.to_string_lossy(),
            std::process::id()
        ));
        // `create_dir` fails with EEXIST rather than adopting whatever is at the
        // staging name — a leftover from a killed run, or a directory planted
        // there. The same reasoning as the copy-out staging file in `isopod-core`.
        std::fs::create_dir(&staging).map_err(|e| io(&staging, &e))?;
        let root = match Dir::open_root(&staging) {
            Ok(d) => d,
            Err(e) => {
                let _ = std::fs::remove_dir(&staging);
                return Err(io(&staging, &e));
            }
        };
        // `create_dir` asked for 0o777 and got 0o777 & ~umask, so without this
        // the root of the image would be whatever the operator's shell happened
        // to be set to. See [`DIR_MODE`]. The archive's own mode for `.` is
        // deliberately not honoured: a root the image could set to 0o000 is one
        // the teardown could not read, and invariant 9 would fail exactly when
        // it matters.
        if let Err(e) = root.chmod(DIR_MODE) {
            let _ = std::fs::remove_dir(&staging);
            return Err(io(&staging, &e));
        }
        Ok(Self {
            dest: dest.to_path_buf(),
            staging,
            root,
            limits,
            total: Report::default(),
            entries_seen: 0,
            deferred_modes: BTreeMap::new(),
            promoted: false,
        })
    }

    /// The running total across every layer applied so far.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.total
    }

    /// The staging directory, for a caller that wants to inspect or adapt the
    /// tree before it is promoted.
    #[must_use]
    pub fn staging_path(&self) -> &Path {
        &self.staging
    }

    /// Apply one layer onto the accumulated tree, returning what *this* layer
    /// contributed. Layers must be applied in manifest order.
    ///
    /// `layer` is an already-decompressed tar stream: media-type handling is the
    /// caller's, and keeping it out of here means the byte counters sit on the
    /// decompressed side, where a bomb is measured by what it costs rather than
    /// by what it declares.
    ///
    /// # Errors
    /// Any [`Refusal`]. The staging tree is left as it is; drop the `Unpacker`
    /// — or simply let it go out of scope — to discard it.
    pub fn apply_layer<R: Read>(&mut self, layer: R) -> Result<Report, Refusal> {
        let mut rep = Report::default();
        // Everything this layer put on the tree, including the intermediate
        // directories it had to create. The opaque-directory prune is defined
        // against exactly this set: an opaque marker hides what the *lower*
        // layers left, so the correct action is "delete every child except the
        // ones this layer wrote" — which is also what makes the result
        // independent of where in the layer the marker appears, as the OCI
        // layer specification requires.
        let mut written: HashSet<String> = HashSet::new();
        let mut archive = tar::Archive::new(layer);
        let entries = archive.entries().map_err(|e| Refusal::Malformed {
            entry: String::new(),
            detail: e.to_string(),
        })?;
        for entry in entries {
            let mut entry = entry.map_err(|e| Refusal::Malformed {
                entry: String::new(),
                detail: e.to_string(),
            })?;
            self.entries_seen += 1;
            if self.entries_seen > self.limits.max_entries {
                return Err(Refusal::LimitExceeded {
                    limit: "max_entries",
                    cap: self.limits.max_entries,
                    raise: "Limits::max_entries",
                });
            }
            let raw = entry.path_bytes().into_owned();
            match name::plan(&raw, &self.limits)? {
                Plan::Root => {}
                Plan::Opaque { parent } => self.opaque(&parent, &written, &mut rep)?,
                Plan::Whiteout { parent, target } => self.whiteout(&parent, &target, &mut rep)?,
                Plan::Write(components) => {
                    self.write_entry(&mut entry, components, &mut rep, &mut written)?;
                }
            }
        }
        self.total.merge(&rep);
        Ok(rep)
    }

    /// Apply the deferred directory modes and rename the staging tree onto the
    /// destination.
    ///
    /// # Errors
    /// [`Refusal::Io`] if the promotion fails; the staging tree is then removed
    /// like after any other refusal, so the destination is never partly written.
    pub fn finish(mut self) -> Result<Report, Refusal> {
        // Deepest first. A directory whose recorded mode denies the owner write
        // access must not get it until everything beneath it is in place — which
        // is the whole reason these were deferred. `BTreeMap` orders a prefix
        // before its extensions, so reversing yields children before parents.
        let modes = std::mem::take(&mut self.deferred_modes);
        for (components, mode) in modes.iter().rev() {
            let dir = match self.dir_existing(components, "<deferred mode>") {
                Ok(Some(d)) => d,
                // A later layer deleted the directory, or replaced it with a
                // file. Nothing is there to carry the mode, which is not an
                // error — the image simply moved on.
                Ok(None) => continue,
                // Or replaced it with a symbolic link, which is how every
                // usrmerge image is shaped (`/lib -> usr/lib`). That is the
                // same "the directory is gone" case and it arrives here as an
                // escape only because the walk cannot tell, at the last
                // component, that nothing is about to be written through it.
                // Refusing would reject an ordinary image at the very end of
                // its unpack, and do it with a message accusing the author of
                // hand-crafting an attack. Skipping is safe because this loop
                // only ever *chmods a directory it already created*: no path is
                // opened for writing, and a link means there is no such
                // directory left to chmod.
                Err(Refusal::SymlinkEscape { .. }) => continue,
                Err(e) => return Err(e),
            };
            dir.chmod(*mode).map_err(|e| Refusal::Io {
                path: name::join(components),
                detail: e.to_string(),
            })?;
        }
        std::fs::rename(&self.staging, &self.dest).map_err(|e| Refusal::Io {
            path: self.dest.display().to_string(),
            detail: e.to_string(),
        })?;
        self.promoted = true;
        Ok(std::mem::take(&mut self.total))
    }

    // --- entry handling -------------------------------------------------

    fn write_entry<R: Read>(
        &mut self,
        entry: &mut tar::Entry<'_, R>,
        components: Vec<String>,
        rep: &mut Report,
        written: &mut HashSet<String>,
    ) -> Result<(), Refusal> {
        let path = name::join(&components);
        let kind = entry.header().entry_type();
        let malformed = |detail: String| Refusal::Malformed {
            entry: path.clone(),
            detail,
        };

        // Nothing is created for these, so no parent is resolved and no
        // directory is brought into being on their behalf. The guest gets its
        // /dev from a devtmpfs the agent mounts, so a missing node costs
        // nothing — but an operator wondering where it went has to be told.
        if matches!(kind, EntryType::Char | EntryType::Block | EntryType::Fifo) {
            rep.devices_skipped.push(path);
            return Ok(());
        }
        if kind == EntryType::GNUSparse {
            return Err(malformed(
                "GNU sparse entries are not supported: the hole map would have to be trusted \
                 to place writes. Repack the layer without sparse encoding."
                    .into(),
            ));
        }
        if !matches!(
            kind,
            EntryType::Regular
                | EntryType::Continuous
                | EntryType::Directory
                | EntryType::Symlink
                | EntryType::Link
        ) {
            return Err(malformed(format!(
                "unsupported tar entry type {:?}",
                kind.as_byte() as char
            )));
        }

        let raw_mode = entry
            .header()
            .mode()
            .map_err(|e| malformed(format!("unreadable mode: {e}")))?
            & 0o7777;
        let link_name = entry.link_name_bytes().map(std::borrow::Cow::into_owned);
        rep.xattrs_dropped += count_xattrs(entry);

        let last = components.last().expect("plan yields no empty component");
        let parent = self.dir_create(&components[..components.len() - 1], &path, written)?;
        let last_os = OsStr::new(last.as_str());
        let io = |e: &std::io::Error| Refusal::Io {
            path: path.clone(),
            detail: e.to_string(),
        };

        match kind {
            EntryType::Directory => {
                self.ensure_dir(&parent, last_os, &path)?;
                // Recorded either way, so a later layer's mode for the same
                // directory wins over an earlier layer's.
                self.set_dir_mode(&parent, last_os, &components, host_mode(raw_mode), &path)?;
            }
            EntryType::Regular | EntryType::Continuous => {
                let mode = host_mode(raw_mode);
                let mut file = match parent.create_file(last_os, mode) {
                    Ok(f) => f,
                    Err(e) if is(&e, libc::EEXIST) => {
                        remove_child(&parent, last_os, &self.limits, 0).map_err(|e| io(&e))?;
                        parent.create_file(last_os, mode).map_err(|e| io(&e))?
                    }
                    Err(e) => return Err(io(&e)),
                };
                // `openat`'s mode argument is masked by the process umask, so
                // the bits the image asked for have to be set explicitly.
                file.set_permissions(std::fs::Permissions::from_mode(mode))
                    .map_err(|e| io(&e))?;
                self.copy_bounded(entry, &mut file, &path, rep)?;
            }
            EntryType::Symlink => {
                let target = link_name.ok_or_else(|| malformed("symlink with no target".into()))?;
                if target.is_empty() {
                    return Err(malformed("symlink with an empty target".into()));
                }
                // The target is stored verbatim and never resolved here; see the
                // crate documentation. What matters for confinement is that
                // nothing this extractor does will ever traverse it.
                if let Err(e) = parent.symlink(&target, last_os) {
                    if !is(&e, libc::EEXIST) {
                        return Err(io(&e));
                    }
                    remove_child(&parent, last_os, &self.limits, 0).map_err(|e| io(&e))?;
                    parent.symlink(&target, last_os).map_err(|e| io(&e))?;
                }
            }
            EntryType::Link => {
                let target =
                    link_name.ok_or_else(|| malformed("hard link with no target".into()))?;
                self.hardlink(&parent, last_os, &target, &path)?;
            }
            _ => unreachable!("entry types were filtered above"),
        }

        // A symbolic link's mode is not stored on Linux (`lstat` always reports
        // 0o777), so recording one would be a claim the pack step cannot honour.
        if raw_mode & 0o7000 != 0 && kind != EntryType::Symlink {
            rep.setuid_paths.push((path.clone(), raw_mode));
        }
        rep.entries_written += 1;
        written.insert(path);
        Ok(())
    }

    /// Copy an entry's content, refusing **before** writing the byte that would
    /// cross a ceiling, so a bomb costs the cap and not a byte more.
    fn copy_bounded<R: Read>(
        &mut self,
        entry: &mut tar::Entry<'_, R>,
        file: &mut std::fs::File,
        path: &str,
        rep: &mut Report,
    ) -> Result<(), Refusal> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut this_entry: u64 = 0;
        loop {
            let n = entry.read(&mut buf).map_err(|e| Refusal::Malformed {
                entry: path.to_string(),
                detail: format!("truncated entry data: {e}"),
            })?;
            if n == 0 {
                return Ok(());
            }
            let n64 = n as u64;
            if this_entry + n64 > self.limits.max_entry_bytes {
                return Err(Refusal::LimitExceeded {
                    limit: "max_entry_bytes",
                    cap: self.limits.max_entry_bytes,
                    raise: "Limits::max_entry_bytes",
                });
            }
            if self.total.bytes_written + rep.bytes_written + n64 > self.limits.max_total_bytes {
                return Err(Refusal::LimitExceeded {
                    limit: "max_total_bytes",
                    cap: self.limits.max_total_bytes,
                    raise: "Limits::max_total_bytes",
                });
            }
            file.write_all(&buf[..n]).map_err(|e| Refusal::Io {
                path: path.to_string(),
                detail: e.to_string(),
            })?;
            this_entry += n64;
            rep.bytes_written += n64;
        }
    }

    fn hardlink(
        &self,
        parent: &Dir,
        last: &OsStr,
        target: &[u8],
        path: &str,
    ) -> Result<(), Refusal> {
        let escape = || Refusal::HardlinkEscape {
            entry: path.to_string(),
            target: String::from_utf8_lossy(target).into_owned(),
        };
        let missing = || Refusal::Malformed {
            entry: path.to_string(),
            detail: format!(
                "hard link to {:?}, which no earlier entry created",
                String::from_utf8_lossy(target)
            ),
        };
        // The same normalisation as an entry name — invariant 4. A hard link is
        // a second name for an inode, so this check is the only thing between
        // the image and any host file it can name.
        let components = match name::plan(target, &self.limits) {
            Ok(Plan::Write(c)) => c,
            _ => return Err(escape()),
        };
        let (tail, head) = components
            .split_last()
            .expect("plan yields no empty component");
        // Deliberately the non-creating walk: a hard link to a path the image
        // never shipped is malformed, and inventing the parent would turn it
        // into a silently empty file.
        let target_dir = match self.dir_existing(head, path) {
            Ok(Some(d)) => d,
            Ok(None) => return Err(missing()),
            // A link in the *target's* parent chain is an escape by the target,
            // not by the entry, so it is reported as one.
            Err(Refusal::SymlinkEscape { .. }) => return Err(escape()),
            Err(e) => return Err(e),
        };
        let io = |e: &std::io::Error| Refusal::Io {
            path: path.to_string(),
            detail: e.to_string(),
        };
        let tail_os = OsStr::new(tail.as_str());
        match parent.link_from(&target_dir, tail_os, last) {
            Ok(()) => Ok(()),
            Err(e) if is(&e, libc::EEXIST) => {
                remove_child(parent, last, &self.limits, 0).map_err(|e| io(&e))?;
                parent
                    .link_from(&target_dir, tail_os, last)
                    .map_err(|e| io(&e))
            }
            Err(e) if is(&e, libc::ENOENT) => Err(missing()),
            Err(e) => Err(io(&e)),
        }
    }

    // --- whiteouts ------------------------------------------------------

    fn whiteout(&self, parent: &[String], target: &str, rep: &mut Report) -> Result<(), Refusal> {
        rep.whiteouts_applied += 1;
        let path = name::join(parent);
        // Nothing accumulated there means nothing to delete. A whiteout for a
        // path that never existed is a no-op, not an error: rebasing an image
        // routinely leaves markers for files the new lower layers never had.
        let Some(dir) = self.dir_existing(parent, &path)? else {
            return Ok(());
        };
        remove_child(&dir, OsStr::new(target), &self.limits, 0).map_err(|e| Refusal::Io {
            path: if path.is_empty() {
                target.to_string()
            } else {
                format!("{path}/{target}")
            },
            detail: e.to_string(),
        })
    }

    fn opaque(
        &self,
        parent: &[String],
        written: &HashSet<String>,
        rep: &mut Report,
    ) -> Result<(), Refusal> {
        rep.opaque_dirs_applied += 1;
        let path = name::join(parent);
        // As with `.wh.`, a marker for a directory the accumulated tree does not
        // have hides nothing. Creating it here would materialise a directory out
        // of a delete instruction.
        let Some(dir) = self.dir_existing(parent, &path)? else {
            return Ok(());
        };
        prune(&dir, parent, written, &self.limits, 0).map_err(|e| Refusal::Io {
            path,
            detail: e.to_string(),
        })
    }

    // --- the confined walk ----------------------------------------------

    /// Descend to `components`, creating directories that are missing.
    ///
    /// Every component is opened with `O_NOFOLLOW`, so a symbolic link anywhere
    /// in the chain refuses the layer instead of redirecting the write. This is
    /// invariants 2 and 3, and it is why a *dangling* link is handled by the
    /// same code as a live one: nothing ever looks at a link's target.
    fn dir_create(
        &self,
        components: &[String],
        entry: &str,
        written: &mut HashSet<String>,
    ) -> Result<Dir, Refusal> {
        let mut cur = self.root.try_clone().map_err(|e| Refusal::Io {
            path: String::new(),
            detail: e.to_string(),
        })?;
        for (i, comp) in components.iter().enumerate() {
            let so_far = name::join(&components[..=i]);
            let name = OsStr::new(comp.as_str());
            let io = |e: &std::io::Error| Refusal::Io {
                path: so_far.clone(),
                detail: e.to_string(),
            };
            cur = match cur.open_dir(name) {
                Ok(d) => d,
                Err(e) if is(&e, libc::ENOENT) => {
                    // An EEXIST here would mean something appeared between the
                    // two calls; the reopen below is what decides, and it is
                    // still O_NOFOLLOW, so a planted link cannot win the race.
                    let _ = cur.mkdir(name, DIR_MODE);
                    let made = cur.open_dir(name).map_err(|e| io(&e))?;
                    // `mkdirat`'s mode is masked by the umask; the image's
                    // layout must not depend on the operator's shell.
                    made.chmod(DIR_MODE).map_err(|e| io(&e))?;
                    made
                }
                Err(e) => {
                    let st = cur.lstat(name).map_err(|_| io(&e))?;
                    if sys::is_symlink(&st) {
                        return Err(Refusal::SymlinkEscape {
                            entry: entry.to_string(),
                            via: so_far,
                        });
                    }
                    if sys::is_dir(&st) {
                        return Err(io(&e));
                    }
                    // A file, device or FIFO where this layer needs a directory:
                    // the later layer wins, exactly as it would if the entry
                    // itself were a directory. No type confusion is possible,
                    // because the replacement is by name and never through the
                    // old inode.
                    remove_child(&cur, name, &self.limits, 0).map_err(|e| io(&e))?;
                    cur.mkdir(name, DIR_MODE).map_err(|e| io(&e))?;
                    let made = cur.open_dir(name).map_err(|e| io(&e))?;
                    made.chmod(DIR_MODE).map_err(|e| io(&e))?;
                    made
                }
            };
            written.insert(so_far);
        }
        Ok(cur)
    }

    /// Descend to `components` without creating anything; `Ok(None)` if some
    /// component is absent. Symbolic links refuse here too.
    fn dir_existing(&self, components: &[String], entry: &str) -> Result<Option<Dir>, Refusal> {
        let mut cur = self.root.try_clone().map_err(|e| Refusal::Io {
            path: String::new(),
            detail: e.to_string(),
        })?;
        for (i, comp) in components.iter().enumerate() {
            let so_far = name::join(&components[..=i]);
            let name = OsStr::new(comp.as_str());
            cur = match cur.open_dir(name) {
                Ok(d) => d,
                Err(e) if is(&e, libc::ENOENT) => return Ok(None),
                Err(e) => {
                    let st = cur.lstat(name).map_err(|_| Refusal::Io {
                        path: so_far.clone(),
                        detail: e.to_string(),
                    })?;
                    if sys::is_symlink(&st) {
                        return Err(Refusal::SymlinkEscape {
                            entry: entry.to_string(),
                            via: so_far,
                        });
                    }
                    // A non-directory in the chain: nothing lives beneath it,
                    // which for a whiteout or an opaque marker means there is
                    // nothing to hide.
                    return Ok(None);
                }
            };
        }
        Ok(Some(cur))
    }

    /// Make `name` a directory under `parent`, replacing whatever is there.
    fn ensure_dir(&self, parent: &Dir, name: &OsStr, path: &str) -> Result<(), Refusal> {
        let io = |e: &std::io::Error| Refusal::Io {
            path: path.to_string(),
            detail: e.to_string(),
        };
        match parent.mkdir(name, DIR_MODE) {
            Ok(()) => Ok(()),
            Err(e) if is(&e, libc::EEXIST) => {
                let st = parent.lstat(name).map_err(|e| io(&e))?;
                if sys::is_dir(&st) {
                    return Ok(());
                }
                // A symbolic link, or a file, that a later layer replaces with a
                // directory. Removing it by name never touches a link's target.
                remove_child(parent, name, &self.limits, 0).map_err(|e| io(&e))?;
                parent.mkdir(name, 0o755).map_err(|e| io(&e))
            }
            Err(e) => Err(io(&e)),
        }
    }

    fn set_dir_mode(
        &mut self,
        parent: &Dir,
        name: &OsStr,
        components: &[String],
        mode: u32,
        path: &str,
    ) -> Result<(), Refusal> {
        // A directory that denies its owner write or search access cannot be
        // built into, so its mode waits until `finish`. Everything else is
        // applied now, which keeps the deferred map to the handful of entries
        // that really need it rather than one per directory in the image.
        if mode & 0o700 == 0o700 {
            parent
                .open_dir(name)
                .and_then(|d| d.chmod(mode))
                .map_err(|e| Refusal::Io {
                    path: path.to_string(),
                    detail: e.to_string(),
                })?;
            // A later layer's permissive mode has to erase an earlier layer's
            // deferred restrictive one, or `finish` would reapply the old mode
            // over the new.
            self.deferred_modes.remove(components);
        } else {
            self.deferred_modes.insert(components.to_vec(), mode);
        }
        Ok(())
    }
}

impl Drop for Unpacker {
    fn drop(&mut self) {
        if self.promoted {
            return;
        }
        // Invariant 9. Torn down through the same non-following walk that built
        // it, so a link inside the staging tree cannot make the cleanup delete
        // something outside it.
        if let Ok(children) = self.root.entries() {
            for child in children {
                let _ = remove_child(&self.root, &child, &self.limits, 0);
            }
        }
        let _ = std::fs::remove_dir(&self.staging);
    }
}

/// Does this error carry `errno`?
fn is(e: &std::io::Error, errno: i32) -> bool {
    e.raw_os_error() == Some(errno)
}

/// Remove `name` from `dir`, recursively if it is a directory.
///
/// Never follows a symbolic link: `unlinkat` without `AT_REMOVEDIR` removes the
/// link itself, and the recursion descends with `O_NOFOLLOW`. Depth is bounded
/// by `max_path_depth`, which is checked when a name is planned, so the tree
/// this walks cannot be deeper than the archive was allowed to build.
fn remove_child(dir: &Dir, name: &OsStr, limits: &Limits, depth: usize) -> std::io::Result<()> {
    if depth > limits.max_path_depth {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tree is deeper than max_path_depth",
        ));
    }
    match dir.unlink(name, false) {
        Ok(()) => Ok(()),
        Err(e) if is(&e, libc::ENOENT) => Ok(()),
        // Linux answers EISDIR; POSIX permits EPERM.
        Err(e) if is(&e, libc::EISDIR) || is(&e, libc::EPERM) => {
            // Before the open, not after. `finish` applies the image's own
            // restrictive directory modes just before the promoting rename, so
            // if that rename fails this teardown has to remove a tree it has
            // already made unreadable (0o000 cannot be opened) or unwritable
            // (0o500 can be listed but not emptied). Chmodding the child from
            // its parent is the only order that works for both, and without it
            // a refusal could leave behind exactly the tree invariant 9 says
            // never survives.
            let _ = dir.chmod_child(name, 0o700);
            let sub = dir.open_dir(name)?;
            for child in sub.entries()? {
                remove_child(&sub, &child, limits, depth + 1)?;
            }
            drop(sub);
            dir.unlink(name, true)
        }
        Err(e) => Err(e),
    }
}

/// Delete everything under `dir` except the paths in `keep`.
///
/// This is the opaque-whiteout rule stated exactly: a marker hides what the
/// lower layers left, so what survives is precisely what *this* layer wrote.
/// Because the answer is defined by the layer's contribution rather than by the
/// order entries arrived in, a marker that appears after its siblings gives the
/// same result as one that appears before them — which is what the OCI layer
/// specification requires ("applied first ... regardless of the ordering in
/// which the whiteout file was encountered").
fn prune(
    dir: &Dir,
    prefix: &[String],
    keep: &HashSet<String>,
    limits: &Limits,
    depth: usize,
) -> std::io::Result<()> {
    if depth > limits.max_path_depth {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tree is deeper than max_path_depth",
        ));
    }
    for child in dir.entries()? {
        let mut components = prefix.to_vec();
        // Every name in this tree was created by this crate from a validated
        // UTF-8 entry name, so the lossy conversion is exact.
        components.push(child.to_string_lossy().into_owned());
        let key = name::join(&components);
        if !keep.contains(&key) {
            remove_child(dir, &child, limits, depth)?;
            continue;
        }
        // Kept, but its *contents* may still be lower-layer material the marker
        // hides — so the rule is applied again one level down.
        let st = dir.lstat(&child)?;
        if sys::is_dir(&st) {
            let sub = dir.open_dir(&child)?;
            prune(&sub, &components, keep, limits, depth + 1)?;
        }
    }
    Ok(())
}

/// Count the extended-attribute PAX records this crate drops.
///
/// Extended attributes are not reproduced on the host tree: the operator's user
/// cannot set `trusted.*` at all, and a `security.*` attribute written outside a
/// VM is a host-policy change an image should not get to make. The count exists
/// so the pack step can say what was lost instead of losing it silently.
fn count_xattrs<R: Read>(entry: &mut tar::Entry<'_, R>) -> u64 {
    let Ok(Some(exts)) = entry.pax_extensions() else {
        return 0;
    };
    exts.filter_map(Result::ok)
        .filter(|e| {
            let k = e.key_bytes();
            k.starts_with(b"SCHILY.xattr.") || k.starts_with(b"LIBARCHIVE.xattr.")
        })
        .count() as u64
}
