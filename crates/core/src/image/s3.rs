//! S3 `ListObjectsV2` XML parsing and the pure kernel-selection logic.
//!
//! Firecracker publishes CI kernels to the public bucket `spec.ccfc.min`. The
//! historical `firecracker-ci/v<major.minor>/` prefix no longer exists for
//! current releases (the last versioned prefix is `v1.15`); modern kernels live
//! under date-stamped prefixes such as `firecracker-ci/20260717-5ac3f5ffdcd7-0/`.
//! Selection therefore *enumerates* prefixes and picks the newest date-stamped
//! one that actually offers a vmlinux of the requested series — never templates a
//! path. See docs/feasibility.md finding #2.
//!
//! The XML types and the selection helpers here are deliberately free of any I/O
//! so they can be unit-tested against fixtures (including pagination and decoy
//! prefixes). The network glue lives in [`super::kernel`].

use serde::Deserialize;

/// A parsed `<ListBucketResult>` from an S3 `list-type=2` response.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListBucketResult {
    /// True when the result was paginated; fetch the next page with
    /// [`ListBucketResult::next_continuation_token`].
    #[serde(default)]
    pub is_truncated: bool,
    /// Opaque token to pass back as `continuation-token` for the next page.
    #[serde(default)]
    pub next_continuation_token: Option<String>,
    /// `<CommonPrefixes>` entries (present when a `delimiter` is supplied).
    #[serde(default, rename = "CommonPrefixes")]
    pub common_prefixes: Vec<CommonPrefix>,
    /// `<Contents>` entries (object keys under the queried prefix).
    #[serde(default, rename = "Contents")]
    pub contents: Vec<Contents>,
}

/// One `<CommonPrefixes><Prefix>…</Prefix></CommonPrefixes>` entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CommonPrefix {
    /// The common prefix string, e.g. `firecracker-ci/20260717-5ac3f5ffdcd7-0/`.
    pub prefix: String,
}

/// One `<Contents>` object entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Contents {
    /// The full object key, e.g. `firecracker-ci/…/x86_64/vmlinux-6.18.36`.
    pub key: String,
}

/// Parse an S3 `ListObjectsV2` XML body.
pub fn parse_list_result(xml: &str) -> anyhow::Result<ListBucketResult> {
    quick_xml::de::from_str(xml).map_err(|e| anyhow::anyhow!("parsing S3 XML: {e}"))
}

/// The 8-digit `YYYYMMDD` date that opens a date-stamped CI prefix leaf, if any.
///
/// Leaf must look like `<8 digits>-…`. This is what distinguishes the current
/// date-stamped prefixes (`20260717-…`) from decoys such as `v1.9/`,
/// `vTest-bchalios/`, or `4360-tmp-artifacts/`.
fn date_stamp_of(prefix: &str) -> Option<&str> {
    // Strip a trailing '/', then take the final path segment.
    let leaf = prefix.trim_end_matches('/').rsplit('/').next()?;
    let bytes = leaf.as_bytes();
    if bytes.len() >= 9 && bytes[..8].iter().all(u8::is_ascii_digit) && bytes[8] == b'-' {
        Some(&leaf[..8])
    } else {
        None
    }
}

/// Given all common prefixes, return only the date-stamped ones, newest first.
///
/// Non-date-stamped prefixes (versioned `v1.x`, `vTest-*`, `NNNN-tmp-artifacts`)
/// are dropped. Ordering is a descending sort on the full prefix string, which
/// sorts by date first (fixed-width `YYYYMMDD`) and then deterministically breaks
/// same-day ties by the trailing commit hash.
pub fn date_stamped_prefixes_newest_first(prefixes: &[String]) -> Vec<String> {
    let mut kept: Vec<String> = prefixes
        .iter()
        .filter(|p| date_stamp_of(p).is_some())
        .cloned()
        .collect();
    kept.sort_by(|a, b| b.cmp(a));
    kept
}

/// A vmlinux artifact chosen for a requested kernel series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmlinuxChoice {
    /// Full object key to download.
    pub key: String,
    /// Full version string, e.g. `6.18.36`.
    pub version: String,
}

/// From the object keys under one prefix's `x86_64/` listing, pick the newest
/// patch of `vmlinux-<series>.<patch>`.
///
/// * Excludes `.config` sidecars and `bzImage-*` (uncompressed ELF vmlinux only).
/// * `series` is the `major.minor` string, e.g. `"6.18"`; the trailing dot in the
///   match guards against `6.1` spuriously matching `6.18`.
/// * Returns the highest numeric patch level, or `None` if the series is absent.
pub fn select_vmlinux_for_series(keys: &[String], series: &str) -> Option<VmlinuxChoice> {
    let needle = format!("vmlinux-{series}.");
    let mut best: Option<(u64, VmlinuxChoice)> = None;
    for key in keys {
        let base = key.rsplit('/').next().unwrap_or(key);
        let Some(rest) = base.strip_prefix(&needle) else {
            continue;
        };
        // `rest` must be a pure numeric patch (excludes `.config`, `-rc`, etc.).
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(patch) = rest.parse::<u64>() else {
            continue;
        };
        let choice = VmlinuxChoice {
            key: key.clone(),
            version: format!("{series}.{rest}"),
        };
        if best.as_ref().is_none_or(|(p, _)| patch > *p) {
            best = Some((patch, choice));
        }
    }
    best.map(|(_, c)| c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE1: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>spec.ccfc.min</Name>
  <Prefix>firecracker-ci/</Prefix>
  <Delimiter>/</Delimiter>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>TOKEN-ABC</NextContinuationToken>
  <CommonPrefixes><Prefix>firecracker-ci/v1.9/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>firecracker-ci/20260715-1faca2f70e7a-0/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>firecracker-ci/4360-tmp-artifacts/</Prefix></CommonPrefixes>
</ListBucketResult>"#;

    const PAGE2: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>spec.ccfc.min</Name>
  <IsTruncated>false</IsTruncated>
  <CommonPrefixes><Prefix>firecracker-ci/20260717-5ac3f5ffdcd7-0/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>firecracker-ci/vTest-bchalios/</Prefix></CommonPrefixes>
</ListBucketResult>"#;

    // A prefix's x86_64/ file listing, with decoys: a .config sidecar, a bzImage,
    // an older 6.18 patch, and an unrelated 6.1 series.
    const KERNEL_LISTING: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>false</IsTruncated>
  <Contents><Key>firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/vmlinux-5.10.260</Key></Contents>
  <Contents><Key>firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/vmlinux-6.1.176</Key></Contents>
  <Contents><Key>firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/vmlinux-6.18.9</Key></Contents>
  <Contents><Key>firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/vmlinux-6.18.36</Key></Contents>
  <Contents><Key>firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/vmlinux-6.18.36.config</Key></Contents>
  <Contents><Key>firecracker-ci/20260717-5ac3f5ffdcd7-0/x86_64/bzImage-6.18.36</Key></Contents>
</ListBucketResult>"#;

    #[test]
    fn parses_pagination_fields() {
        let p1 = parse_list_result(PAGE1).unwrap();
        assert!(p1.is_truncated);
        assert_eq!(p1.next_continuation_token.as_deref(), Some("TOKEN-ABC"));
        assert_eq!(p1.common_prefixes.len(), 3);

        let p2 = parse_list_result(PAGE2).unwrap();
        assert!(!p2.is_truncated);
        assert!(p2.next_continuation_token.is_none());
        assert_eq!(p2.common_prefixes.len(), 2);
    }

    #[test]
    fn newest_date_prefix_selected_across_pages_ignoring_decoys() {
        // Merge both pages the way the paginating client would.
        let mut prefixes: Vec<String> = Vec::new();
        for page in [PAGE1, PAGE2] {
            let r = parse_list_result(page).unwrap();
            prefixes.extend(r.common_prefixes.into_iter().map(|c| c.prefix));
        }
        let ordered = date_stamped_prefixes_newest_first(&prefixes);
        // v1.9, vTest-bchalios and 4360-tmp-artifacts are all filtered out.
        assert_eq!(
            ordered,
            vec![
                "firecracker-ci/20260717-5ac3f5ffdcd7-0/".to_string(),
                "firecracker-ci/20260715-1faca2f70e7a-0/".to_string(),
            ]
        );
    }

    #[test]
    fn selects_highest_patch_excluding_config_and_bzimage() {
        let r = parse_list_result(KERNEL_LISTING).unwrap();
        let keys: Vec<String> = r.contents.into_iter().map(|c| c.key).collect();
        let choice = select_vmlinux_for_series(&keys, "6.18").unwrap();
        assert_eq!(choice.version, "6.18.36");
        assert!(choice.key.ends_with("/vmlinux-6.18.36"));
    }

    #[test]
    fn series_6_1_does_not_match_6_18() {
        let keys = vec![
            "p/x86_64/vmlinux-6.18.36".to_string(),
            "p/x86_64/vmlinux-6.1.176".to_string(),
        ];
        let choice = select_vmlinux_for_series(&keys, "6.1").unwrap();
        assert_eq!(choice.version, "6.1.176");
    }

    #[test]
    fn absent_series_returns_none() {
        let keys = vec!["p/x86_64/vmlinux-6.1.176".to_string()];
        assert!(select_vmlinux_for_series(&keys, "6.18").is_none());
    }

    #[test]
    fn date_stamp_rejects_decoys() {
        assert!(date_stamp_of("firecracker-ci/20260717-abc-0/").is_some());
        assert!(date_stamp_of("firecracker-ci/4360-tmp-artifacts/").is_none());
        assert!(date_stamp_of("firecracker-ci/v1.9/").is_none());
        assert!(date_stamp_of("firecracker-ci/vTest-bchalios/").is_none());
    }
}
