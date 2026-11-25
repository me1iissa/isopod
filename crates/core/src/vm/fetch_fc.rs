//! `isopod image fetch-fc` — install the pinned upstream Firecracker release,
//! and the guard that refuses a Firecracker with no seccomp filter.
//!
//! # Why a release binary and not the vendored build
//! Firecracker's seccomp filters are compiled in at build time from a
//! per-target JSON file, and upstream ships one only for the musl targets. A
//! build for any other target — which is what a plain `cargo build` on a glibc
//! host produces — is not rejected: its build script substitutes a filter whose
//! default action is *allow* and which lists no rules. The resulting binary
//! starts, runs, and reports `Seccomp: 2` in `/proc/<pid>/status`, because an
//! allow-everything filter is still an installed filter. Nothing at run time
//! distinguishes it from a filtered one.
//!
//! A correct musl build needs a musl C toolchain and a musl-built static
//! `libseccomp`, which upstream assembles inside its build container. Rather
//! than reproduce that, isopod installs upstream's own release artifact, pinned
//! by sha256 exactly as the guest kernel is. `isopod dev build-fc` remains for
//! working on Firecracker itself; what it produces is refused at run time
//! unless explicitly allowed.
//!
//! Public references: Firecracker `docs/seccomp.md`; `seccomp(2)`; `elf(5)`.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::paths;

// ---------------------------------------------------------------------------
// The pin. To bump: change the version, download the new
// `firecracker-<version>-x86_64.tgz` from the upstream releases page, check it
// against the `.sha256.txt` published beside it, and re-pin both digests
// (`sha256sum` of the archive and of the `firecracker` binary inside it). Keep
// it equal to the `vendor/firecracker` submodule tag — that is checked by
// review, not by a test; a test only ties the CLI help text to this version.
// ---------------------------------------------------------------------------

/// Upstream release tag.
pub const FC_RELEASE_VERSION: &str = "v1.16.2";
/// Where upstream publishes release archives.
const RELEASE_BASE: &str = "https://github.com/firecracker-microvm/firecracker/releases/download";
/// sha256 of `firecracker-v1.16.2-x86_64.tgz`.
const ARCHIVE_SHA256: &str = "32e3cdcd4081f91fe2b024a266f57dcb3b4e5fec5033e0cb22467ad7f7820bda";
/// sha256 of the `firecracker` binary inside it.
const FIRECRACKER_SHA256: &str = "8227875ceda44177a4d501052dae4a2f9d7837362f5399f02cf0748e68418377";
/// The archive is ~7.5 MiB; anything far beyond that is not the pinned file.
const ARCHIVE_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Ceiling for one extracted binary.
const BINARY_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Set to exactly `1` to run a Firecracker that has no seccomp filter.
///
/// Deliberately strict where the hardening switches are lenient: this one
/// *removes* a protection, so nothing but the documented value turns it on.
pub const ALLOW_UNFILTERED_VAR: &str = "ISOPOD_ALLOW_UNFILTERED_FC";

/// Report for `isopod image fetch-fc`.
#[derive(Debug, Clone, Serialize)]
pub struct FetchFcOutcome {
    /// Always `true` on success.
    pub ok: bool,
    /// Where the binary was installed.
    pub firecracker_path: PathBuf,
    /// The pinned upstream release.
    pub version: String,
    /// sha256 of the installed binary.
    pub sha256: String,
    /// `true` if the installed binary already matched and nothing was fetched.
    pub cached: bool,
}

/// Install the pinned Firecracker release to `~/.isopod/bin/firecracker`.
///
/// The archive is verified against its pinned digest before anything in it is
/// read, the binary is verified against its own pinned digest before it is
/// moved into place, and the move is a rename — so the path the boot resolver
/// looks at only ever holds bytes that hashed correctly.
///
/// # Errors
/// On any download, digest, archive or filesystem failure.
pub fn fetch_fc(force: bool) -> Result<FetchFcOutcome> {
    if !cfg!(target_arch = "x86_64") {
        bail!("fetch-fc pins the x86_64 release only; build or provide a Firecracker for this host and set $ISOPOD_FC_BIN");
    }
    let bin_dir = paths::isopod_home()?.join("bin");
    std::fs::create_dir_all(&bin_dir).with_context(|| format!("creating {}", bin_dir.display()))?;
    let dest = bin_dir.join("firecracker");

    if dest.exists() && !force && paths::sha256_file(&dest)? == FIRECRACKER_SHA256 {
        eprintln!(
            "fetch-fc: {} is already the pinned {FC_RELEASE_VERSION} release",
            dest.display()
        );
        return Ok(FetchFcOutcome {
            ok: true,
            firecracker_path: dest,
            version: FC_RELEASE_VERSION.to_string(),
            sha256: FIRECRACKER_SHA256.to_string(),
            cached: true,
        });
    }

    let name = format!("firecracker-{FC_RELEASE_VERSION}-x86_64");
    let url = format!("{RELEASE_BASE}/{FC_RELEASE_VERSION}/{name}.tgz");
    eprintln!("fetch-fc: downloading {url} (pinned)");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("isopod-image/0.1")
        .build()
        .context("building HTTP client")?;
    let resp = client
        .get(&url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("fetching {url}"))?;
    let mut archive = Vec::new();
    resp.take(ARCHIVE_MAX_BYTES + 1)
        .read_to_end(&mut archive)
        .with_context(|| format!("reading {url}"))?;
    if archive.len() as u64 > ARCHIVE_MAX_BYTES {
        bail!("{url} is larger than {ARCHIVE_MAX_BYTES} bytes; that is not the pinned archive");
    }
    let got = sha256_hex(&archive);
    if got != ARCHIVE_SHA256 {
        bail!(
            "{url} sha256 mismatch: expected {ARCHIVE_SHA256}, got {got} — refusing to unpack it"
        );
    }

    let wanted = format!("release-{FC_RELEASE_VERSION}-x86_64/{name}");
    let binary = extract_one(&archive, &wanted)?;
    let got = sha256_hex(&binary);
    if got != FIRECRACKER_SHA256 {
        bail!("{wanted} sha256 mismatch: expected {FIRECRACKER_SHA256}, got {got}");
    }

    // Beside the destination, so the rename is atomic; exclusive, so a name
    // someone else put there is an error rather than something written through.
    let tmp = bin_dir.join(format!(".firecracker.{}.partial", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        out.write_all(&binary)
            .with_context(|| format!("writing {}", tmp.display()))?;
        out.set_permissions(std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod 0755 {}", tmp.display()))?;
    }
    if let Err(e) = std::fs::rename(&tmp, &dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context(format!("installing {}", dest.display())));
    }

    Ok(FetchFcOutcome {
        ok: true,
        firecracker_path: dest,
        version: FC_RELEASE_VERSION.to_string(),
        sha256: got,
        cached: false,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Read exactly one regular file, named `wanted`, out of a gzipped tar held in
/// memory. Nothing is written to disk and no other entry is looked at beyond
/// its header, so the archive's other paths cannot matter.
fn extract_one(archive: &[u8], wanted: &str) -> Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries().context("reading the release archive")? {
        let entry = entry.context("reading a release archive entry")?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        if entry.path_bytes().as_ref() != wanted.as_bytes() {
            continue;
        }
        let mut out = Vec::new();
        entry
            .take(BINARY_MAX_BYTES + 1)
            .read_to_end(&mut out)
            .with_context(|| format!("extracting {wanted}"))?;
        if out.len() as u64 > BINARY_MAX_BYTES {
            bail!("{wanted} is larger than {BINARY_MAX_BYTES} bytes");
        }
        return Ok(out);
    }
    bail!("the release archive has no {wanted}")
}

/// Refuse a Firecracker binary that cannot have a seccomp filter.
///
/// The test is whether the ELF file asks for a dynamic loader (`PT_INTERP`).
/// Upstream's filtered builds are static musl binaries and have none; a build
/// for a glibc target has one, and is exactly the build that silently received
/// the allow-everything filter (see the module docs). It is a property of the
/// file, checked before anything is executed, and it cannot be satisfied by an
/// unfiltered build without deliberately linking glibc statically.
///
/// # Errors
/// If the binary is dynamically linked and `ISOPOD_ALLOW_UNFILTERED_FC` is not `1`,
/// or it cannot be read as an ELF file at all.
pub fn require_filtered(fc: &Path) -> Result<()> {
    let file = std::fs::File::open(fc).with_context(|| format!("opening {}", fc.display()))?;
    let mut head = Vec::new();
    file.take(64 * 1024)
        .read_to_end(&mut head)
        .with_context(|| format!("reading {}", fc.display()))?;
    let dynamic = elf_has_interp(&head)
        .with_context(|| format!("{} is not a usable ELF executable", fc.display()))?;
    if !dynamic {
        return Ok(());
    }
    if std::env::var(ALLOW_UNFILTERED_VAR).as_deref() == Ok("1") {
        eprintln!(
            "isopod: WARNING: {} has no seccomp filter and {ALLOW_UNFILTERED_VAR}=1 is set; \
             the VMM is running with an unrestricted system-call surface",
            fc.display()
        );
        return Ok(());
    }
    bail!(
        "{} is a dynamically linked Firecracker, which means it was built for a target \
         upstream ships no seccomp filter for and is running with an allow-everything one.\n\
         Install the pinned, filtered release (no root needed):\n\n    \
         isopod image fetch-fc\n\n\
         or set {ALLOW_UNFILTERED_VAR}=1 to run it anyway.",
        fc.display()
    )
}

/// Whether a 64-bit little-endian ELF image has a `PT_INTERP` program header.
/// `head` must hold the ELF header and the program header table.
fn elf_has_interp(head: &[u8]) -> Result<bool> {
    const PT_INTERP: u32 = 3;
    let field = |at: usize, len: usize| head.get(at..at + len).context("truncated ELF header");
    if field(0, 4)? != b"\x7fELF" {
        bail!("missing ELF magic");
    }
    // EI_CLASS = ELFCLASS64, EI_DATA = ELFDATA2LSB.
    if field(4, 2)? != [2, 1] {
        bail!("not a 64-bit little-endian ELF file");
    }
    let u16_at = |at| field(at, 2).map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])));
    let phoff = field(0x20, 8).map(|b| {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(b);
        u64::from_le_bytes(raw)
    })?;
    let phoff = usize::try_from(phoff).context("program header offset out of range")?;
    let (phentsize, phnum) = (u16_at(0x36)?, u16_at(0x38)?);
    if phentsize < 4 {
        bail!("implausible program header size");
    }
    for i in 0..phnum {
        let at = phoff
            .checked_add(
                i.checked_mul(phentsize)
                    .context("program header overflow")?,
            )
            .context("program header overflow")?;
        let p_type = field(at, 4)?;
        if u32::from_le_bytes([p_type[0], p_type[1], p_type[2], p_type[3]]) == PT_INTERP {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64 image with the given program header types.
    fn elf(types: &[u32]) -> Vec<u8> {
        let mut v = vec![0u8; 0x40];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[5] = 1;
        v[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        v[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        v[0x38..0x3a].copy_from_slice(&(types.len() as u16).to_le_bytes());
        for t in types {
            let mut ph = [0u8; 56];
            ph[..4].copy_from_slice(&t.to_le_bytes());
            v.extend_from_slice(&ph);
        }
        v
    }

    #[test]
    fn a_dynamic_binary_is_told_apart_from_a_static_one() {
        // PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3. A static-pie has a
        // PT_DYNAMIC and no PT_INTERP, which is why the loader request and not
        // the dynamic section is the test.
        assert!(!elf_has_interp(&elf(&[1, 1, 2])).expect("static"));
        assert!(elf_has_interp(&elf(&[6, 3, 1, 2])).expect("dynamic"));
        assert!(!elf_has_interp(&elf(&[])).expect("no headers"));
    }

    #[test]
    fn something_that_is_not_an_elf_file_is_an_error_not_a_pass() {
        assert!(elf_has_interp(b"#!/bin/sh\necho firecracker\n").is_err());
        assert!(elf_has_interp(&[]).is_err());
        // Claims more program headers than the bytes hold.
        let mut cut = elf(&[1, 3]);
        cut.truncate(0x40 + 56);
        assert!(elf_has_interp(&cut).is_err());
    }

    #[test]
    fn the_guard_refuses_this_test_binary_and_names_the_fix() {
        // The test executable is itself a dynamically linked glibc ELF file.
        let me = std::env::current_exe().expect("exe");
        if std::env::var(ALLOW_UNFILTERED_VAR).as_deref() == Ok("1") {
            return;
        }
        let err = require_filtered(&me).expect_err("must refuse");
        let text = format!("{err:#}");
        assert!(text.contains("isopod image fetch-fc"), "{text}");
        assert!(text.contains(ALLOW_UNFILTERED_VAR), "{text}");
    }

    #[test]
    fn the_cli_help_names_the_pinned_release() {
        // The help text states a version; it must be the one that is fetched.
        // (Nothing here can read the submodule's tag: keeping the vendored
        // source at the pinned release is a review item, per the pin block.)
        let cli = include_str!("../../../cli/src/main.rs");
        assert!(
            cli.contains(&format!("Firecracker ({FC_RELEASE_VERSION})")),
            "the CLI help names a different Firecracker version than the pin"
        );
    }
}
