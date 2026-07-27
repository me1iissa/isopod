//! No test may leave a copy-out staging file behind.
//!
//! `copy_out` streams into a sibling `.<name>.isopod-<pid>-<n>.part` and renames
//! it onto the destination only once the guest reports the file complete. The
//! invariant is that a failure unlinks it — enforced by a `Drop` guard rather
//! than by each error path remembering to.
//!
//! That invariant was broken once already: one `?` returned past the cleanup,
//! and because every attempt takes a fresh sequence number, a caller repeating
//! it leaked one file per attempt instead of reusing a name. Per-test assertions
//! catch it only in the tests that thought to look.
//!
//! This walks the temp directory the whole suite shares and fails if any
//! staging file survives it. Any test that exercises `copy_out` — including ones
//! written after this file — is covered without having to opt in.

use std::path::{Path, PathBuf};

/// The infix every staging file carries, from `stage_copy_out`.
const STAGING_INFIX: &str = ".isopod-";
const STAGING_SUFFIX: &str = ".part";

fn staging_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // unreadable or vanished mid-walk: not ours to report
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `symlink_metadata`, so a link is never followed out of the tree.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            staging_files_under(&path, out);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.')
                && name.contains(STAGING_INFIX)
                && name.ends_with(STAGING_SUFFIX)
            {
                out.push(path);
            }
        }
    }
}

#[test]
fn the_suite_leaves_no_copy_out_staging_files_behind() {
    // Only this process's own leftovers: a concurrent isopod run — a dogfooding
    // session, another CI job on a shared runner — legitimately has staging
    // files in flight, and failing on those would make this test flaky rather
    // than useful.
    let mine = format!("{}{}-", STAGING_INFIX, std::process::id());

    let mut found = Vec::new();
    staging_files_under(&std::env::temp_dir(), &mut found);

    let leaked: Vec<_> = found
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(&mine))
        })
        .collect();

    assert!(
        leaked.is_empty(),
        "copy-out staging files survived the test run — the Drop guard on the \
         staging path is not firing on some failure route:\n{}",
        leaked
            .iter()
            .map(|p| format!("  {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
