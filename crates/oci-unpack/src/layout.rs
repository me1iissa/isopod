//! Reading an OCI image layout: the index, a manifest, a config, and the blobs.
//!
//! An [image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
//! is a directory holding an `oci-layout` marker, an `index.json`, and a
//! content-addressed `blobs/<algorithm>/<encoded>` store. It is what
//! `docker save`, `skopeo copy` and a registry pull all land in, so reading one
//! is the half of an import that has nothing to do with the network — which is
//! why it is built and attacked here, in the crate that already treats its input
//! as hostile, rather than beside the code that dials out.
//!
//! # What is trusted, and what is not
//!
//! The layout **root** is the operator's: they typed the path. Everything
//! inside it is the image author's, including every string that decides which
//! file gets opened next.
//!
//! - Blob addresses are [`Digest`]s or they are refused, so `blobs/` cannot be
//!   escaped by a manifest naming `sha256:../../../etc/shadow`.
//! - Every blob is **verified against the digest that named it before its bytes
//!   are used for anything** — parsed, decompressed or unpacked. An unverified
//!   blob is just a file the image told us to read.
//! - Metadata blobs are read under a ceiling. `index.json` is the first thing an
//!   import touches and a four-gigabyte one must not be read into memory to find
//!   that out.
//!
//! # What this module does not do
//!
//! It does not decompress. The layer media type is reported as a
//! [`Compression`] and the caller applies the decoder, because
//! [`Unpacker::apply_layer`](crate::Unpacker::apply_layer) takes an already
//! decompressed stream — that is what keeps the anti-bomb counters on the
//! decompressed side, where a bomb is measured by what it costs rather than by
//! what it declares.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::digest::{Digest, DigestError};

/// Largest metadata blob this module will read into memory.
///
/// An index, a manifest and a config are small by construction — a few
/// kilobytes each, tens of kilobytes for an image with a long history. The
/// ceiling exists because they are read *before* anything is known about the
/// image, so the alternative to a limit is letting the first file an import
/// touches decide how much memory it gets.
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;

/// How deep a chain of nested indexes is followed.
///
/// An index may point at another index. In practice it never does more than
/// once, and a layout whose indexes point at each other in a cycle must cost a
/// bounded amount of work rather than a stack.
const MAX_INDEX_DEPTH: usize = 4;

/// The `oci-layout` versions this reader accepts.
const LAYOUT_VERSIONS: &[&str] = &["1.0.0"];

// --- media types ----------------------------------------------------------

/// Media types naming an image index (a multi-platform manifest list).
const INDEX_TYPES: &[&str] = &[
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// Media types naming a single-platform image manifest.
const MANIFEST_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// Media types naming an image config blob.
const CONFIG_TYPES: &[&str] = &[
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
];

/// How a layer blob is compressed, derived from its media type.
///
/// The digest in a manifest covers the **compressed** blob; the `diff_ids` in
/// the config cover the decompressed tar. Verifying a layer is therefore always
/// a statement about the bytes on disk, never about what comes out of the
/// decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// An uncompressed tar.
    None,
    /// gzip — what essentially every image in the wild uses.
    Gzip,
    /// zstd.
    Zstd,
}

impl Compression {
    /// Classify a layer media type, or `None` if it does not name a layer this
    /// crate can unpack.
    #[must_use]
    pub fn of(media_type: &str) -> Option<Self> {
        // Foreign / "non-distributable" layers are deliberately absent: their
        // bytes are not in the layout at all, they are a URL the registry
        // expects the client to fetch from somewhere else. Treating one as a
        // missing blob is right, and quieter than pretending it could work.
        match media_type {
            "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.docker.image.rootfs.diff.tar" => Some(Self::None),
            "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Some(Self::Gzip),
            "application/vnd.oci.image.layer.v1.tar+zstd" => Some(Self::Zstd),
            _ => None,
        }
    }
}

// --- the wire types -------------------------------------------------------

/// A content descriptor: what a blob is, where it is, and how big it should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The blob's media type, verbatim.
    pub media_type: String,
    /// Its content digest — also its address under `blobs/`.
    pub digest: Digest,
    /// The size the manifest claims. Checked against the file.
    pub size: u64,
    /// The platform this descriptor is for, when it appears in an index.
    pub platform: Option<Platform>,
    /// Annotations, which carry the reference name in a `docker save` layout.
    pub annotations: BTreeMap<String, String>,
}

/// A platform selector from an image index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    /// `linux`, `windows`, …
    pub os: String,
    /// `amd64`, `arm64`, …
    pub architecture: String,
    /// `v7` and friends; absent for most platforms.
    pub variant: Option<String>,
}

impl Platform {
    /// The only platform isopod can boot: Firecracker on x86-64.
    #[must_use]
    pub fn host() -> Self {
        Self {
            os: "linux".into(),
            architecture: "amd64".into(),
            variant: None,
        }
    }

    /// Does `self` (from an index) satisfy a request for `want`?
    ///
    /// A variant the index does not state matches a request that does not state
    /// one; a variant it *does* state must be asked for, because `arm64/v8`
    /// code does not run on a host that asked for plain `arm64`.
    #[must_use]
    pub fn satisfies(&self, want: &Self) -> bool {
        self.os == want.os
            && self.architecture == want.architecture
            && (self.variant.is_none() || self.variant == want.variant)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        if let Some(v) = &self.variant {
            write!(f, "/{v}")?;
        }
        Ok(())
    }
}

/// A single-platform image manifest: one config blob and an ordered layer stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The config blob.
    pub config: Descriptor,
    /// Layers, in the order they must be applied.
    pub layers: Vec<Descriptor>,
}

/// The parts of an image config that survive into an isopod base.
///
/// `Entrypoint` and `Cmd` are recorded and never executed: isopod's PID 1 is the
/// guest agent, which does the overlay mounts, the pivot and the vsock RPC, so
/// an image's entrypoint cannot be PID 1 and "isopod runs your container" is not
/// a promise this can keep. They describe what the image is *for*.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageConfig {
    /// `PATH`-style environment, merged **under** a run's own env.
    pub env: Vec<String>,
    /// Default working directory for an exec.
    pub working_dir: Option<String>,
    /// Recorded, never executed.
    pub entrypoint: Vec<String>,
    /// Recorded, never executed.
    pub cmd: Vec<String>,
    /// Recorded and **ignored**: the agent execs as root.
    pub user: Option<String>,
    /// Uncompressed digests of each layer, in order.
    pub diff_ids: Vec<String>,
}

// --- deserialization ------------------------------------------------------
//
// Kept private and separate from the types above so the public surface is not
// whatever JSON happened to be in the file. Every field is optional on the wire
// and validated on the way out: real layouts in the wild omit things the
// specification requires.

#[derive(Deserialize)]
struct RawLayout {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: Option<String>,
}

#[derive(Deserialize)]
struct RawIndex {
    manifests: Option<Vec<RawDescriptor>>,
}

#[derive(Deserialize)]
struct RawManifest {
    config: Option<RawDescriptor>,
    layers: Option<Vec<RawDescriptor>>,
}

#[derive(Deserialize)]
struct RawDescriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: Option<String>,
    size: Option<i64>,
    platform: Option<RawPlatform>,
    annotations: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct RawPlatform {
    os: Option<String>,
    architecture: Option<String>,
    variant: Option<String>,
}

#[derive(Deserialize)]
struct RawConfig {
    config: Option<RawConfigInner>,
    rootfs: Option<RawRootfs>,
}

#[derive(Deserialize)]
struct RawConfigInner {
    #[serde(rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(rename = "User")]
    user: Option<String>,
}

#[derive(Deserialize)]
struct RawRootfs {
    diff_ids: Option<Vec<String>>,
}

// --- errors ---------------------------------------------------------------

/// Why a layout could not be read.
#[derive(Debug)]
pub enum LayoutError {
    /// The directory is not an image layout, or is one this reader cannot read.
    NotALayout {
        /// The path that was tried.
        path: PathBuf,
        /// What was wrong with it.
        detail: String,
    },
    /// A file could not be read.
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        detail: String,
    },
    /// A document did not parse, or did not carry what it must.
    Malformed {
        /// Which document.
        what: String,
        /// What is wrong with it.
        detail: String,
    },
    /// A digest string could not be parsed.
    BadDigest(DigestError),
    /// A blob's bytes do not hash to the digest that named it.
    DigestMismatch {
        /// What the manifest said.
        expected: String,
        /// What the bytes actually hash to.
        actual: String,
    },
    /// A blob is larger than the ceiling for its kind.
    TooLarge {
        /// Which document.
        what: String,
        /// The ceiling.
        cap: u64,
        /// What it claimed or measured.
        actual: u64,
    },
    /// No manifest in the index is for the platform asked for.
    NoSuchPlatform {
        /// What was asked for.
        want: String,
        /// What the index offers.
        have: Vec<String>,
    },
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotALayout { path, detail } => write!(
                f,
                "{} is not an OCI image layout: {detail}. A layout is a directory \
                 holding `oci-layout`, `index.json` and `blobs/` — what `skopeo \
                 copy … oci:DIR` and `docker save` produce.",
                path.display()
            ),
            Self::Io { path, detail } => {
                write!(f, "reading {} failed: {detail}", path.display())
            }
            Self::Malformed { what, detail } => write!(f, "{what} is malformed: {detail}"),
            Self::BadDigest(e) => write!(f, "{e}"),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "a blob does not match the digest that named it: the manifest \
                 says {expected}, the bytes hash to sha256:{actual}. The image is \
                 corrupt or was altered after it was signed; isopod refuses it \
                 rather than unpacking bytes nothing vouches for."
            ),
            Self::TooLarge { what, cap, actual } => write!(
                f,
                "{what} is {actual} bytes, over the {cap}-byte ceiling. Image \
                 metadata is kilobytes; something this size is not an index, a \
                 manifest or a config."
            ),
            Self::NoSuchPlatform { want, have } => write!(
                f,
                "this image has no manifest for {want}. It offers: {}. isopod \
                 boots x86-64 Linux guests, so an image without a linux/amd64 \
                 manifest cannot become a base.",
                if have.is_empty() {
                    "nothing".to_string()
                } else {
                    have.join(", ")
                }
            ),
        }
    }
}

impl std::error::Error for LayoutError {}

impl From<DigestError> for LayoutError {
    fn from(e: DigestError) -> Self {
        Self::BadDigest(e)
    }
}

// --- the reader -----------------------------------------------------------

/// An opened OCI image layout directory.
#[derive(Debug)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// Open the layout rooted at `root`.
    ///
    /// # Errors
    /// [`LayoutError::NotALayout`] if the marker file is missing, unreadable or
    /// declares a version this reader does not know.
    pub fn open(root: &Path) -> Result<Self, LayoutError> {
        let not = |detail: &str| LayoutError::NotALayout {
            path: root.to_path_buf(),
            detail: detail.to_string(),
        };
        if !root.is_dir() {
            return Err(not("not a directory"));
        }
        let marker = root.join("oci-layout");
        let bytes = std::fs::read(&marker).map_err(|e| not(&format!("no `oci-layout`: {e}")))?;
        let parsed: RawLayout = serde_json::from_slice(&bytes)
            .map_err(|e| not(&format!("`oci-layout` does not parse: {e}")))?;
        let version = parsed
            .image_layout_version
            .ok_or_else(|| not("`oci-layout` declares no imageLayoutVersion"))?;
        if !LAYOUT_VERSIONS.contains(&version.as_str()) {
            return Err(not(&format!(
                "layout version {version:?} is not one this build reads (knows: {})",
                LAYOUT_VERSIONS.join(", ")
            )));
        }
        if !root.join("index.json").is_file() {
            return Err(not("no `index.json`"));
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// The layout's root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The top-level `index.json` entries.
    ///
    /// # Errors
    /// [`LayoutError`] if the file is missing, too large, or does not parse.
    pub fn index(&self) -> Result<Vec<Descriptor>, LayoutError> {
        let path = self.root.join("index.json");
        let bytes = read_capped(&path, MAX_METADATA_BYTES, "index.json")?;
        let raw: RawIndex = serde_json::from_slice(&bytes).map_err(|e| LayoutError::Malformed {
            what: "index.json".into(),
            detail: e.to_string(),
        })?;
        descriptors(raw.manifests.unwrap_or_default(), "index.json")
    }

    /// Resolve the index down to the single manifest for `want`.
    ///
    /// An index entry may itself be an index; that is followed, bounded by
    /// `MAX_INDEX_DEPTH`, so a layout whose indexes point at one another costs
    /// a fixed amount of work rather than a stack.
    ///
    /// # Errors
    /// [`LayoutError::NoSuchPlatform`] when nothing matches, or any read error.
    pub fn resolve(&self, want: &Platform) -> Result<Manifest, LayoutError> {
        let mut entries = self.index()?;
        let mut offered: Vec<String> = Vec::new();
        for _ in 0..MAX_INDEX_DEPTH {
            let Some(chosen) = self.pick(&entries, want, &mut offered)? else {
                break;
            };
            if is_manifest(&chosen.media_type) {
                return self.manifest(&chosen);
            }
            // A nested index: replace the working set and go round again.
            entries = self.nested_index(&chosen)?;
        }
        offered.sort();
        offered.dedup();
        Err(LayoutError::NoSuchPlatform {
            want: want.to_string(),
            have: offered,
        })
    }

    /// Choose the entry to follow, recording what was on offer for the error
    /// message if nothing matches.
    fn pick(
        &self,
        entries: &[Descriptor],
        want: &Platform,
        offered: &mut Vec<String>,
    ) -> Result<Option<Descriptor>, LayoutError> {
        // A platform match wins outright.
        for d in entries {
            if let Some(p) = &d.platform {
                offered.push(p.to_string());
                if p.satisfies(want) && (is_manifest(&d.media_type) || is_index(&d.media_type)) {
                    return Ok(Some(d.clone()));
                }
            }
        }
        // Nothing stated a platform. A single-platform layout — which is what
        // `docker save` and `skopeo copy` of a concrete image produce — has one
        // manifest and no platform field anywhere, and refusing it for not
        // saying `linux/amd64` would reject the common case.
        let unplatformed: Vec<&Descriptor> = entries
            .iter()
            .filter(|d| d.platform.is_none() && is_manifest(&d.media_type))
            .collect();
        if let [only] = unplatformed[..] {
            return Ok(Some(only.clone()));
        }
        // Several manifests and not one of them says what it is for: guessing
        // would pick an architecture at random and the failure would arrive as
        // a guest that does not boot.
        if unplatformed.len() > 1 {
            offered.push(format!(
                "{} manifests with no platform recorded",
                unplatformed.len()
            ));
            return Ok(None);
        }
        // Otherwise follow a lone nested index, which is how a layout that
        // wraps a manifest list is shaped.
        let nested: Vec<&Descriptor> = entries.iter().filter(|d| is_index(&d.media_type)).collect();
        if let [only] = nested[..] {
            return Ok(Some(only.clone()));
        }
        Ok(None)
    }

    /// Read and parse a nested index blob.
    fn nested_index(&self, d: &Descriptor) -> Result<Vec<Descriptor>, LayoutError> {
        let bytes = self.metadata_blob(d, "a nested index")?;
        let raw: RawIndex = serde_json::from_slice(&bytes).map_err(|e| LayoutError::Malformed {
            what: format!("index {}", d.digest),
            detail: e.to_string(),
        })?;
        descriptors(raw.manifests.unwrap_or_default(), "a nested index")
    }

    /// Read, verify and parse an image manifest.
    ///
    /// # Errors
    /// [`LayoutError`] if the blob is missing, fails verification, does not
    /// parse, or declares a layer type this crate cannot unpack.
    pub fn manifest(&self, d: &Descriptor) -> Result<Manifest, LayoutError> {
        let bytes = self.metadata_blob(d, "a manifest")?;
        let raw: RawManifest =
            serde_json::from_slice(&bytes).map_err(|e| LayoutError::Malformed {
                what: format!("manifest {}", d.digest),
                detail: e.to_string(),
            })?;
        let config = raw
            .config
            .ok_or_else(|| LayoutError::Malformed {
                what: format!("manifest {}", d.digest),
                detail: "no config descriptor".into(),
            })
            .and_then(|c| descriptor(c, "a manifest's config"))?;
        if !CONFIG_TYPES.contains(&config.media_type.as_str()) {
            return Err(LayoutError::Malformed {
                what: format!("manifest {}", d.digest),
                detail: format!(
                    "its config blob is {:?}, which is not an image config",
                    config.media_type
                ),
            });
        }
        let layers = descriptors(raw.layers.unwrap_or_default(), "a manifest's layers")?;
        if layers.is_empty() {
            return Err(LayoutError::Malformed {
                what: format!("manifest {}", d.digest),
                detail: "no layers; an image with no filesystem cannot be a base".into(),
            });
        }
        // Refused here rather than at unpack time: an image half of whose layers
        // are a type this build cannot read should fail before the first one is
        // written, not in the middle of the stack.
        for l in &layers {
            if Compression::of(&l.media_type).is_none() {
                return Err(LayoutError::Malformed {
                    what: format!("manifest {}", d.digest),
                    detail: format!(
                        "layer {} is {:?}, which is not a tar layer isopod can unpack \
                         (foreign or non-distributable layers are not stored in the \
                         layout at all)",
                        l.digest, l.media_type
                    ),
                });
            }
        }
        Ok(Manifest { config, layers })
    }

    /// Read, verify and parse an image config blob.
    ///
    /// # Errors
    /// [`LayoutError`] if the blob is missing, fails verification or does not
    /// parse.
    pub fn config(&self, d: &Descriptor) -> Result<ImageConfig, LayoutError> {
        let bytes = self.metadata_blob(d, "a config")?;
        let raw: RawConfig =
            serde_json::from_slice(&bytes).map_err(|e| LayoutError::Malformed {
                what: format!("config {}", d.digest),
                detail: e.to_string(),
            })?;
        let inner = raw.config.unwrap_or(RawConfigInner {
            env: None,
            working_dir: None,
            entrypoint: None,
            cmd: None,
            user: None,
        });
        Ok(ImageConfig {
            env: inner.env.unwrap_or_default(),
            // An empty `WorkingDir` is how the field is spelled when there is
            // none; carrying it through as `Some("")` would make a run start in
            // a directory that does not exist.
            working_dir: inner.working_dir.filter(|s| !s.is_empty()),
            entrypoint: inner.entrypoint.unwrap_or_default(),
            cmd: inner.cmd.unwrap_or_default(),
            user: inner.user.filter(|s| !s.is_empty()),
            diff_ids: raw.rootfs.and_then(|r| r.diff_ids).unwrap_or_default(),
        })
    }

    /// A verified blob, opened for streaming.
    ///
    /// The digest is checked over the **whole file before the handle is
    /// returned**, deliberately, rather than while the caller reads. A consumer
    /// that stops early — and `tar` stops at the end-of-archive marker, before
    /// a blob's trailing bytes — would otherwise leave a hash computed over
    /// only the part it happened to want, which is a verification of nothing.
    /// The cost is one extra pass over a file that is almost always in the page
    /// cache.
    ///
    /// # Errors
    /// [`LayoutError`] if the blob is missing, the wrong size, or does not hash
    /// to its digest.
    pub fn blob(&self, d: &Descriptor) -> Result<std::fs::File, LayoutError> {
        let path = self.blob_path(d);
        self.verify(d, &path)?;
        std::fs::File::open(&path).map_err(|e| LayoutError::Io {
            path,
            detail: e.to_string(),
        })
    }

    /// Where a descriptor's blob lives. The digest components are validated at
    /// parse time, so neither can contain a separator or a `..`.
    #[must_use]
    pub fn blob_path(&self, d: &Descriptor) -> PathBuf {
        self.root.join(d.digest.blob_path())
    }

    /// Read a metadata blob under the ceiling, verifying it first.
    fn metadata_blob(&self, d: &Descriptor, what: &str) -> Result<Vec<u8>, LayoutError> {
        let path = self.blob_path(d);
        // The declared size is checked before the file is opened, so a manifest
        // claiming four gigabytes costs nothing to refuse.
        if d.size > MAX_METADATA_BYTES {
            return Err(LayoutError::TooLarge {
                what: what.to_string(),
                cap: MAX_METADATA_BYTES,
                actual: d.size,
            });
        }
        let bytes = read_capped(&path, MAX_METADATA_BYTES, what)?;
        check_digest(d, &bytes)?;
        Ok(bytes)
    }

    /// Verify a blob's size and digest by streaming it.
    fn verify(&self, d: &Descriptor, path: &Path) -> Result<(), LayoutError> {
        let io = |e: &dyn fmt::Display| LayoutError::Io {
            path: path.to_path_buf(),
            detail: e.to_string(),
        };
        let meta = std::fs::metadata(path).map_err(|e| io(&e))?;
        if meta.len() != d.size {
            return Err(LayoutError::Malformed {
                what: format!("blob {}", d.digest),
                detail: format!(
                    "the manifest declares {} bytes, the file is {}",
                    d.size,
                    meta.len()
                ),
            });
        }
        let mut file = std::fs::File::open(path).map_err(|e| io(&e))?;
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(|e| io(&e))?;
            if n == 0 {
                break;
            }
            sha2::Digest::update(&mut hasher, &buf[..n]);
        }
        let actual = hex::encode(sha2::Digest::finalize(hasher));
        if actual != d.digest.encoded() {
            return Err(LayoutError::DigestMismatch {
                expected: d.digest.to_string(),
                actual,
            });
        }
        Ok(())
    }
}

/// Read a file, refusing before the ceiling rather than after.
fn read_capped(path: &Path, cap: u64, what: &str) -> Result<Vec<u8>, LayoutError> {
    let io = |e: &dyn fmt::Display| LayoutError::Io {
        path: path.to_path_buf(),
        detail: e.to_string(),
    };
    let file = std::fs::File::open(path).map_err(|e| io(&e))?;
    let len = file.metadata().map_err(|e| io(&e))?.len();
    if len > cap {
        return Err(LayoutError::TooLarge {
            what: what.to_string(),
            cap,
            actual: len,
        });
    }
    // `take(cap + 1)` rather than trusting the stat: the file may grow between
    // the two calls, and the ceiling is the point.
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io(&e))?;
    if bytes.len() as u64 > cap {
        return Err(LayoutError::TooLarge {
            what: what.to_string(),
            cap,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

/// Compare a blob's bytes against the digest that named it.
fn check_digest(d: &Descriptor, bytes: &[u8]) -> Result<(), LayoutError> {
    if d.size != bytes.len() as u64 {
        return Err(LayoutError::Malformed {
            what: format!("blob {}", d.digest),
            detail: format!(
                "the manifest declares {} bytes, the file is {}",
                d.size,
                bytes.len()
            ),
        });
    }
    let actual = d.digest.compute(bytes);
    if actual != d.digest.encoded() {
        return Err(LayoutError::DigestMismatch {
            expected: d.digest.to_string(),
            actual,
        });
    }
    Ok(())
}

fn is_index(media_type: &str) -> bool {
    INDEX_TYPES.contains(&media_type)
}

fn is_manifest(media_type: &str) -> bool {
    MANIFEST_TYPES.contains(&media_type)
}

/// Validate a wire descriptor into the real thing.
fn descriptor(raw: RawDescriptor, what: &str) -> Result<Descriptor, LayoutError> {
    let malformed = |detail: &str| LayoutError::Malformed {
        what: what.to_string(),
        detail: detail.to_string(),
    };
    let digest = Digest::parse(
        &raw.digest
            .ok_or_else(|| malformed("a descriptor has no digest"))?,
    )?;
    let size = raw
        .size
        .ok_or_else(|| malformed("a descriptor has no size"))?;
    // A negative size is representable in JSON and would become an enormous
    // unsigned one; the ceiling checks are the only thing standing between a
    // descriptor and a read, so the conversion has to refuse rather than wrap.
    let size = u64::try_from(size).map_err(|_| malformed("a descriptor has a negative size"))?;
    Ok(Descriptor {
        media_type: raw
            .media_type
            .ok_or_else(|| malformed("a descriptor has no mediaType"))?,
        digest,
        size,
        platform: raw.platform.and_then(|p| {
            Some(Platform {
                os: p.os?,
                architecture: p.architecture?,
                variant: p.variant,
            })
        }),
        annotations: raw.annotations.unwrap_or_default(),
    })
}

fn descriptors(raw: Vec<RawDescriptor>, what: &str) -> Result<Vec<Descriptor>, LayoutError> {
    raw.into_iter().map(|d| descriptor(d, what)).collect()
}
