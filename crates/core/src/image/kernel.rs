//! `isopod image fetch-kernel` — download a prebuilt Firecracker CI vmlinux.
//!
//! Enumerates the public `spec.ccfc.min` bucket's `firecracker-ci/` prefixes
//! (paginating as needed), selects the newest date-stamped prefix that offers an
//! x86_64 vmlinux of the requested series, and downloads it atomically to
//! `~/.isopod/images/vmlinux-<version>`.

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
}

/// Fetch a prebuilt CI vmlinux for `series` (e.g. `"6.18"`).
///
/// Idempotent: if `~/.isopod/images/vmlinux-<version>` already exists and `force`
/// is `false`, the large download is skipped and the existing file is hashed.
pub fn fetch_kernel(series: &str, force: bool) -> Result<FetchKernelOutcome> {
    let images = paths::images_dir()?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("isopod-image/0.1")
        .build()
        .context("building HTTP client")?;

    // 1. Enumerate the date-stamped CI prefixes, newest first.
    eprintln!("fetch-kernel: enumerating {CI_PREFIX} prefixes on S3…");
    let top = list_objects(&client, CI_PREFIX, true)?;
    let prefixes: Vec<String> = top.common_prefixes.into_iter().map(|c| c.prefix).collect();
    let ordered = s3::date_stamped_prefixes_newest_first(&prefixes);
    if ordered.is_empty() {
        bail!("no date-stamped prefixes found under {CI_PREFIX}");
    }

    // 2. Walk newest-first; the first prefix offering the series wins.
    let mut resolved: Option<(String, s3::VmlinuxChoice)> = None;
    for prefix in &ordered {
        let listing = list_objects(&client, &format!("{prefix}x86_64/"), true)?;
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
        });
    }

    // 4. Atomic download: temp file in the images dir, then rename into place.
    let url = format!("{BUCKET_URL}/{}", choice.key);
    eprintln!("fetch-kernel: downloading {url}");
    let sha256 = download_to(&client, &url, &images, &dest)?;

    Ok(FetchKernelOutcome {
        ok: true,
        kernel_path: dest,
        version: choice.version,
        sha256,
        prefix_used,
        cached: false,
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
/// rename it to `dest`. Returns the lowercase hex digest.
fn download_to(
    client: &reqwest::blocking::Client,
    url: &str,
    dir: &std::path::Path,
    dest: &std::path::Path,
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
    tmp.as_file().sync_all().context("fsync temp file")?;
    tmp.persist(dest)
        .with_context(|| format!("renaming into {}", dest.display()))?;

    Ok(hex::encode(hasher.finalize()))
}
