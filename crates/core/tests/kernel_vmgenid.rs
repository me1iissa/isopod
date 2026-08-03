//! The guest kernel must be able to reseed after a snapshot resume.
//!
//! isopod's warm pool resumes one memory image many times. The property that
//! keeps those resumes from sharing a CSPRNG is **inherited**, not written here:
//! Firecracker attaches a VMGenID device to every microVM, and a
//! `CONFIG_VMGENID` kernel reseeds when the generation counter changes. Nothing
//! in isopod implements it, and — until this test — nothing asserted it.
//!
//! That is the dangerous shape for a security property. If a future kernel
//! arrived without the option, every warm resume would still succeed, every
//! test would still pass, and every warm sandbox would quietly share
//! `/dev/urandom`, `getrandom()`, ASLR offsets and TCP sequence numbers with
//! every other one built on the same snapshot.
//!
//! `cargo test -p isopod-core --test kernel_vmgenid -- --ignored`

use std::path::PathBuf;

/// The installed guest kernels, if any.
fn installed_kernels() -> Vec<PathBuf> {
    let Ok(home) = std::env::var("HOME") else {
        return Vec::new();
    };
    let images = PathBuf::from(home).join(".isopod/images");
    let Ok(entries) = std::fs::read_dir(images) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("vmlinux-"))
        })
        .collect()
}

#[test]
#[ignore = "requires an installed guest kernel; run with --ignored"]
fn every_installed_guest_kernel_can_reseed_after_a_fork() {
    let kernels = installed_kernels();
    if kernels.is_empty() {
        eprintln!("skipping: no guest kernel installed (run `isopod image fetch-kernel`)");
        return;
    }
    for k in &kernels {
        isopod_core::image::require_vmfork_reseed(k).unwrap_or_else(|e| panic!("{}", e));
        eprintln!("vmgenid: {} can reseed after a fork", k.display());
    }
}

/// The control. A guard that cannot fail proves nothing, and this one is a
/// substring search over a ~40 MB binary — exactly the shape that quietly
/// matches everything. An image with no reseed path must be refused.
#[test]
#[ignore = "runs beside the check above; run with --ignored"]
fn a_kernel_without_the_reseed_path_would_be_refused() {
    let dir = std::env::temp_dir().join("isopod-vmgenid-control");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let fake = dir.join("vmlinux-no-vmgenid");
    std::fs::write(&fake, vec![0x41u8; 1 << 20]).expect("write");
    let err = isopod_core::image::require_vmfork_reseed(&fake)
        .expect_err("a kernel with no reseed path must be refused");
    assert!(err.to_string().contains("CONFIG_VMGENID"), "{err}");
    let _ = std::fs::remove_file(&fake);
}
