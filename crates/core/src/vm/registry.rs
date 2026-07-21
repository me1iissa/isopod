//! Listing and garbage-collecting recorded VM directories.
//!
//! Every boot writes `~/.isopod/vms/<vm_id>/meta.json` (id, vanity name,
//! flavor, created); this module makes those records browsable — the vanity
//! names are only useful if they can be looked up afterwards (dogfood finding
//! #1) — and prunes the otherwise unbounded directory growth (finding #2).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths;

/// One recorded VM directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRecord {
    /// The stable VM id (`dev-<8 hex>`), also the directory name.
    pub vm_id: String,
    /// Human-memorable vanity name.
    pub name: String,
    /// Rootfs flavor the VM booted.
    pub flavor: String,
    /// Unix timestamp of creation.
    pub created_unix: u64,
    /// Total bytes currently held by the VM directory (logs, sockets, copies).
    pub dir_bytes: u64,
}

/// Result of a [`gc`] pass.
#[derive(Debug, Clone, Serialize)]
pub struct GcReport {
    /// Always `true` (the CLI emits `{ok:false,…}` on error).
    pub ok: bool,
    /// VM ids removed.
    pub removed: Vec<String>,
    /// Records kept.
    pub kept: usize,
    /// Bytes freed by the removals.
    pub freed_bytes: u64,
}

/// List recorded VMs, newest first.
pub fn list() -> Result<Vec<VmRecord>> {
    list_in(&paths::vms_dir()?)
}

/// Remove old VM directories: keep the newest `keep_last`, plus anything
/// younger than `min_age` (safety margin so an in-flight run's directory is
/// never collected mid-boot).
pub fn gc(keep_last: usize, min_age: Duration) -> Result<GcReport> {
    gc_in(&paths::vms_dir()?, keep_last, min_age)
}

/// [`list`] against an explicit vms root. Directories without a readable
/// `meta.json` (crashes mid-create, pre-naming-era runs) are reported with
/// `"?"` fields rather than hidden — hiding them would make gc decisions
/// unreviewable.
fn list_in(root: &Path) -> Result<Vec<VmRecord>> {
    let mut records = Vec::new();
    for entry in std::fs::read_dir(root)
        .with_context(|| format!("reading vms dir {}", root.display()))?
        .flatten()
    {
        if !entry.path().is_dir() {
            continue;
        }
        records.push(read_record(&entry.path()));
    }
    records.sort_by_key(|r| std::cmp::Reverse(r.created_unix));
    Ok(records)
}

/// [`gc`] against an explicit vms root.
fn gc_in(root: &Path, keep_last: usize, min_age: Duration) -> Result<GcReport> {
    let records = list_in(root)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut removed = Vec::new();
    let mut freed = 0u64;
    let mut kept = 0usize;
    for (i, rec) in records.iter().enumerate() {
        let age_ok = now.saturating_sub(rec.created_unix) >= min_age.as_secs();
        if i < keep_last || !age_ok {
            kept += 1;
            continue;
        }
        let dir = root.join(&rec.vm_id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                freed += rec.dir_bytes;
                removed.push(rec.vm_id.clone());
            }
            Err(e) => eprintln!("vm gc: warning: could not remove {}: {e}", dir.display()),
        }
    }
    Ok(GcReport {
        ok: true,
        removed,
        kept,
        freed_bytes: freed,
    })
}

/// Read one VM directory into a record, tolerating missing/corrupt meta.
fn read_record(dir: &Path) -> VmRecord {
    let fallback_id = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "?".into());
    let meta: serde_json::Value = std::fs::read_to_string(dir.join("meta.json"))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(serde_json::Value::Null);
    let created_unix = meta
        .get("created_unix")
        .and_then(|v| v.as_u64())
        .or_else(|| dir_created_unix(dir))
        .unwrap_or(0);
    VmRecord {
        vm_id: meta
            .get("vm_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback_id)
            .to_string(),
        name: meta
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        flavor: meta
            .get("flavor")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        created_unix,
        dir_bytes: dir_size(dir),
    }
}

/// Directory mtime as a unix timestamp (fallback for meta-less dirs).
fn dir_created_unix(dir: &Path) -> Option<u64> {
    std::fs::metadata(dir)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

/// Recursive apparent size of a directory (best-effort; unreadable entries
/// count as zero).
fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_vm(vms: &Path, id: &str, name: &str, created: u64) {
        let dir = vms.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("meta.json"),
            format!(r#"{{"vm_id":"{id}","name":"{name}","flavor":"t","created_unix":{created}}}"#),
        )
        .unwrap();
        std::fs::write(dir.join("console.log"), "x".repeat(100)).unwrap();
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn list_newest_first_and_tolerates_missing_meta() {
        let vms = tempfile::tempdir().unwrap();
        fake_vm(vms.path(), "dev-aa", "old-one", 100);
        fake_vm(vms.path(), "dev-bb", "new-one", 200);
        std::fs::create_dir_all(vms.path().join("dev-cc")).unwrap(); // no meta

        let got = list_in(vms.path()).unwrap();
        assert_eq!(got.len(), 3);
        // The meta-less dir falls back to its mtime (fresh) — it sorts newest,
        // visible with "?" fields rather than hidden.
        assert_eq!(got[0].vm_id, "dev-cc");
        assert_eq!(got[0].name, "?");
        let newer = got.iter().position(|r| r.name == "new-one").unwrap();
        let older = got.iter().position(|r| r.name == "old-one").unwrap();
        assert!(newer < older, "meta'd records ordered newest-first");
    }

    #[test]
    fn gc_keeps_newest_and_young_dirs() {
        let vms = tempfile::tempdir().unwrap();
        fake_vm(vms.path(), "dev-01", "ancient", 100);
        fake_vm(vms.path(), "dev-02", "older", 200);
        fake_vm(vms.path(), "dev-03", "newest", now()); // young: protected by min_age

        let report = gc_in(vms.path(), 1, Duration::from_secs(60)).unwrap();
        // dev-03 kept (newest slot); dev-01/dev-02 are old and beyond keep_last.
        assert_eq!(report.kept, 1);
        assert_eq!(report.removed.len(), 2);
        assert!(!vms.path().join("dev-01").exists());
        assert!(vms.path().join("dev-03").exists());
        assert!(report.freed_bytes >= 200, "at least the two console.logs");
    }

    #[test]
    fn gc_zero_keep_removes_all_old() {
        let vms = tempfile::tempdir().unwrap();
        fake_vm(vms.path(), "dev-01", "a", 100);
        let report = gc_in(vms.path(), 0, Duration::ZERO).unwrap();
        assert_eq!(report.removed, vec!["dev-01".to_string()]);
        assert_eq!(report.kept, 0);
    }
}
