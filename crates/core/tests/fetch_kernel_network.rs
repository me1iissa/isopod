//! Live network integration test for the kernel fetcher.
//!
//! Ignored by default (needs outbound HTTPS to S3). Run explicitly with:
//! `cargo test -p isopod-core --test fetch_kernel_network -- --ignored`

use std::io::Read;

#[test]
#[ignore = "requires network access to s3.amazonaws.com"]
fn fetch_kernel_downloads_real_vmlinux() {
    // Isolate the download under a scratch ISOPOD_HOME.
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("ISOPOD_HOME", tmp.path());

    let out = isopod_core::image::fetch_kernel("6.18", false, false).expect("fetch-kernel");
    assert!(out.ok);
    assert!(
        out.version.starts_with("6.18."),
        "version = {}",
        out.version
    );
    assert!(out.prefix_used.starts_with("firecracker-ci/"));
    assert_eq!(out.sha256.len(), 64);
    assert!(out.pinned, "the default path must be the pinned one");

    // The downloaded file must be a real (uncompressed) ELF vmlinux.
    let mut f = std::fs::File::open(&out.kernel_path).expect("open kernel");
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).expect("read magic");
    assert_eq!(&magic, b"\x7fELF", "kernel is not an ELF binary");

    // Second call must be a cache hit (no re-download) with the same digest.
    let again =
        isopod_core::image::fetch_kernel("6.18", false, false).expect("fetch-kernel cached");
    assert!(again.cached);
    assert_eq!(again.sha256, out.sha256);
}

/// Offline: a series with no pin must fail closed (no network I/O happens
/// before the guard) and point at the `--allow-unpinned` discovery path.
#[test]
fn fetch_kernel_refuses_unpinned_series() {
    let err = isopod_core::image::fetch_kernel("5.10", false, false)
        .expect_err("unpinned series must be refused");
    let msg = err.to_string();
    assert!(msg.contains("no pinned kernel digest"), "{msg}");
    assert!(msg.contains("--allow-unpinned"), "{msg}");
}
