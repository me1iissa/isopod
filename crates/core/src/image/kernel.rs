//! `isopod image fetch-kernel` — download a prebuilt Firecracker CI vmlinux.
//!
//! The default path downloads one **pinned, digest-verified** artifact (see
//! the F9 pin block below) directly from the public `spec.ccfc.min` bucket and
//! installs it atomically to `~/.isopod/images/vmlinux-<version>`; bytes whose
//! SHA-256 does not match the pin are refused before they reach the images
//! directory. With `allow_unpinned`, the fetcher instead enumerates the
//! bucket's `firecracker-ci/` prefixes (paginating as needed) and takes the
//! newest date-stamped prefix offering the requested series — unverified, used
//! to discover a new digest when bumping the pin.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::s3;
use crate::paths;

/// Public S3 endpoint for the Firecracker artifact bucket.
const BUCKET_URL: &str = "https://s3.amazonaws.com/spec.ccfc.min";
/// Top-level prefix under which all CI artifacts live.
const CI_PREFIX: &str = "firecracker-ci/";

// ---- kernel pin (F9) --------------------------------------------------------
//
// Like the busybox/apk artifacts, the guest kernel — the most privileged guest
// component — is fetched against a pinned digest. The CI bucket rebuilds the
// same kernel *version* into every date-stamped prefix with different bytes
// (non-reproducible builds), so the pin names the exact artifact (prefix +
// version + sha256), not just the version, and the default fetch downloads it
// directly instead of enumerating prefixes.
//
// To bump: run `fetch-kernel --allow-unpinned` (enumerates the newest prefix,
// downloads unverified, and reports the digest), cross-check that digest with
// an independent fetch from a second machine/network vantage, then update the
// three constants below.

/// Series the pinned kernel belongs to; fetching any other series requires
/// `allow_unpinned`.
const PINNED_SERIES: &str = "6.18";
/// Date-stamped CI prefix holding the blessed kernel build.
const PINNED_PREFIX: &str = "firecracker-ci/20260717-5ac3f5ffdcd7-0/";
/// Full version of the blessed kernel.
const PINNED_VERSION: &str = "6.18.36";
/// SHA-256 of the blessed vmlinux. Cross-checked 2026-07-23: an independent S3
/// fetch of this artifact matched the locally deployed kernel byte-for-byte.
const PINNED_SHA256: &str = "cd77172a1073b3da1c714496ee02f1f23a70fbd002588071581f14df5be9d22e";

/// Result of [`fetch_kernel`], serialized verbatim as the CLI's stdout JSON.
#[derive(Debug, Serialize)]
pub struct FetchKernelOutcome {
    /// Always `true` on the success path (the CLI emits `{ok:false,…}` on error).
    pub ok: bool,
    /// Absolute path to the downloaded (or already-cached) vmlinux.
    pub kernel_path: PathBuf,
    /// Full kernel version, e.g. `6.18.36`.
    pub version: String,
    /// Lowercase hex SHA-256 of the kernel file.
    pub sha256: String,
    /// The S3 prefix the kernel was resolved from.
    pub prefix_used: String,
    /// `true` if a matching file already existed and the download was skipped.
    pub cached: bool,
    /// `true` when the artifact's SHA-256 was verified against the built-in
    /// pin (F9); `false` only on the explicit `allow_unpinned` path.
    pub pinned: bool,
}

/// Fetch a prebuilt CI vmlinux for `series` (e.g. `"6.18"`).
///
/// The default path serves only the pinned, digest-verified artifact and hard
/// errors for any other series (F9); `allow_unpinned` switches to the newest
/// upstream build with **no digest verification** (the pin-bump discovery
/// path).
///
/// Idempotent: if `~/.isopod/images/vmlinux-<version>` already exists and `force`
/// is `false`, the large download is skipped and the existing file is hashed
/// (and, on the pinned path, verified).
pub fn fetch_kernel(series: &str, force: bool, allow_unpinned: bool) -> Result<FetchKernelOutcome> {
    if !allow_unpinned && series != PINNED_SERIES {
        bail!(
            "series {series} has no pinned kernel digest (pinned: {PINNED_SERIES} -> \
             vmlinux-{PINNED_VERSION}); fetch it with --allow-unpinned, verify the reported \
             sha256 independently, and add a pin"
        );
    }
    let images = paths::images_dir()?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("isopod-image/0.1")
        .build()
        .context("building HTTP client")?;

    if allow_unpinned {
        eprintln!(
            "fetch-kernel: WARNING: --allow-unpinned fetches the newest upstream build with \
             no digest verification; use only to discover a digest for a new pin"
        );
        fetch_unpinned(&client, &images, series, force)
    } else {
        fetch_pinned(&client, &images, force)
    }
}

/// The default path: download (or verify the cached copy of) the one blessed
/// artifact named by the pin block, refusing any digest mismatch (F9). No
/// prefix enumeration happens here — the artifact URL is fully determined by
/// the pin, so every machine fetches identical bytes.
fn fetch_pinned(
    client: &reqwest::blocking::Client,
    images: &std::path::Path,
    force: bool,
) -> Result<FetchKernelOutcome> {
    let dest = images.join(format!("vmlinux-{PINNED_VERSION}"));

    if dest.exists() && !force {
        let sha256 = paths::sha256_file(&dest)?;
        if sha256 != PINNED_SHA256 {
            bail!(
                "cached kernel {} sha256 mismatch: expected {PINNED_SHA256}, got {sha256} — \
                 the file is corrupt or tampered; delete it and re-run fetch-kernel",
                dest.display()
            );
        }
        eprintln!(
            "fetch-kernel: {} already present and digest-verified, skipping download",
            dest.display()
        );
        return Ok(FetchKernelOutcome {
            ok: true,
            kernel_path: dest,
            version: PINNED_VERSION.to_string(),
            sha256,
            prefix_used: PINNED_PREFIX.to_string(),
            cached: true,
            pinned: true,
        });
    }

    let url = format!("{BUCKET_URL}/{PINNED_PREFIX}x86_64/vmlinux-{PINNED_VERSION}");
    eprintln!("fetch-kernel: downloading {url} (pinned)");
    let sha256 = download_to(client, &url, images, &dest, Some(PINNED_SHA256))?;

    Ok(FetchKernelOutcome {
        ok: true,
        kernel_path: dest,
        version: PINNED_VERSION.to_string(),
        sha256,
        prefix_used: PINNED_PREFIX.to_string(),
        cached: false,
        pinned: true,
    })
}

/// The explicit `allow_unpinned` path: enumerate the date-stamped CI prefixes
/// newest-first and take the first offering `series`, with no digest
/// verification. Exists to discover the digest for a new pin.
fn fetch_unpinned(
    client: &reqwest::blocking::Client,
    images: &std::path::Path,
    series: &str,
    force: bool,
) -> Result<FetchKernelOutcome> {
    // 1. Enumerate the date-stamped CI prefixes, newest first.
    eprintln!("fetch-kernel: enumerating {CI_PREFIX} prefixes on S3…");
    let top = list_objects(client, CI_PREFIX, true)?;
    let prefixes: Vec<String> = top.common_prefixes.into_iter().map(|c| c.prefix).collect();
    let ordered = s3::date_stamped_prefixes_newest_first(&prefixes);
    if ordered.is_empty() {
        bail!("no date-stamped prefixes found under {CI_PREFIX}");
    }

    // 2. Walk newest-first; the first prefix offering the series wins.
    let mut resolved: Option<(String, s3::VmlinuxChoice)> = None;
    for prefix in &ordered {
        let listing = list_objects(client, &format!("{prefix}x86_64/"), true)?;
        let keys: Vec<String> = listing.contents.into_iter().map(|c| c.key).collect();
        if let Some(choice) = s3::select_vmlinux_for_series(&keys, series) {
            eprintln!(
                "fetch-kernel: selected vmlinux-{} from {prefix}",
                choice.version
            );
            resolved = Some((prefix.clone(), choice));
            break;
        }
    }
    let (prefix_used, choice) = resolved
        .with_context(|| format!("no CI prefix offers an x86_64 vmlinux for series {series}"))?;

    let dest = images.join(format!("vmlinux-{}", choice.version));

    // 3. Idempotency: reuse an existing file unless --force.
    if dest.exists() && !force {
        eprintln!(
            "fetch-kernel: {} already present, skipping download",
            dest.display()
        );
        let sha256 = paths::sha256_file(&dest)?;
        return Ok(FetchKernelOutcome {
            ok: true,
            kernel_path: dest,
            version: choice.version,
            sha256,
            prefix_used,
            cached: true,
            pinned: false,
        });
    }

    // 4. Atomic download: temp file in the images dir, then rename into place.
    let url = format!("{BUCKET_URL}/{}", choice.key);
    eprintln!("fetch-kernel: downloading {url}");
    let sha256 = download_to(client, &url, images, &dest, None)?;
    eprintln!("fetch-kernel: unpinned sha256 {sha256} — verify independently before pinning");

    Ok(FetchKernelOutcome {
        ok: true,
        kernel_path: dest,
        version: choice.version,
        sha256,
        prefix_used,
        cached: false,
        pinned: false,
    })
}

/// Issue an S3 `list-type=2` request for `prefix`, following continuation tokens
/// until the full result is assembled. `delimiter` toggles the `/` roll-up that
/// produces `<CommonPrefixes>`.
fn list_objects(
    client: &reqwest::blocking::Client,
    prefix: &str,
    delimiter: bool,
) -> Result<s3::ListBucketResult> {
    let mut merged = s3::ListBucketResult::default();
    let mut token: Option<String> = None;

    loop {
        let mut query: Vec<(&str, String)> = vec![
            ("list-type", "2".to_string()),
            ("prefix", prefix.to_string()),
        ];
        if delimiter {
            query.push(("delimiter", "/".to_string()));
        }
        if let Some(t) = &token {
            query.push(("continuation-token", t.clone()));
        }

        let body = client
            .get(BUCKET_URL)
            .query(&query)
            .send()
            .with_context(|| format!("listing {prefix}"))?
            .error_for_status()
            .with_context(|| format!("listing {prefix}"))?
            .text()
            .with_context(|| format!("reading list body for {prefix}"))?;

        let page = s3::parse_list_result(&body)?;
        merged.common_prefixes.extend(page.common_prefixes);
        merged.contents.extend(page.contents);

        if page.is_truncated {
            match page.next_continuation_token {
                Some(t) => token = Some(t),
                None => break,
            }
        } else {
            break;
        }
    }

    Ok(merged)
}

/// Stream `url` to a temp file in `dir`, compute its SHA-256, then atomically
/// rename it to `dest`. With `expected_sha256` set, a digest mismatch aborts
/// **before** the rename (the temp file is dropped), so unverified bytes never
/// land at a path the boot resolver would pick up (F9). Returns the lowercase
/// hex digest.
fn download_to(
    client: &reqwest::blocking::Client,
    url: &str,
    dir: &std::path::Path,
    dest: &std::path::Path,
    expected_sha256: Option<&str>,
) -> Result<String> {
    use sha2::{Digest, Sha256};

    let mut resp = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?;

    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;

    // Tee the response through the hasher as it is written to disk.
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut resp, &mut buf).context("reading response body")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        tmp.write_all(&buf[..n]).context("writing temp file")?;
    }
    let got = hex::encode(hasher.finalize());
    if let Some(expected) = expected_sha256 {
        if got != expected {
            bail!(
                "kernel sha256 mismatch for {url}: expected {expected}, got {got} — \
                 refusing to install (supply-chain tamper or corrupted download)"
            );
        }
    }
    tmp.as_file().sync_all().context("fsync temp file")?;
    tmp.persist(dest)
        .with_context(|| format!("renaming into {}", dest.display()))?;

    Ok(got)
}
