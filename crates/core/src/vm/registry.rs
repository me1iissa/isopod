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
    /// Whether the run that owns this directory is still going: its recorded
    /// owner pid is alive. `gc` refuses to touch these, and `vm list` showing
    /// them is how an operator tells "leftovers" from "in flight".
    #[serde(default)]
    pub live: bool,
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
/// never collected mid-boot). First reaps any orphaned firecracker processes so
/// a leaked VMM never keeps a slot wedged.
pub fn gc(keep_last: usize, min_age: Duration) -> Result<GcReport> {
    reap_orphans();
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

    // Every id with a firecracker process behind it right now. `min_age` was the
    // only thing standing between gc and a live run, and it is a guess: the MCP
    // tool passes 60 s while a run may ask for a timeout of an hour. Collecting a
    // live run's directory unlinked the vsock socket its every remaining RPC needs,
    // lost the scratch that `commit_as` was going to freeze, and — because the
    // reaper reads `owner.pid` out of that same directory and treats a missing one
    // as proof of orphanhood — armed the next pass to SIGKILL the VMM. The gc
    // manufactured the orphan its own reaper then acted on.
    let live_vmms: std::collections::HashSet<String> =
        firecracker_procs().into_iter().map(|(_, id)| id).collect();

    let mut removed = Vec::new();
    let mut freed = 0u64;
    let mut kept = 0usize;
    for (i, rec) in records.iter().enumerate() {
        let age_ok = now.saturating_sub(rec.created_unix) >= min_age.as_secs();
        let live = rec.live || live_vmms.contains(&rec.vm_id);
        if i < keep_last || !age_ok || live {
            kept += 1;
            continue;
        }
        // `vm_id` is a directory name read from the filesystem, so this holds by
        // construction; asserting it here keeps the deletion target obviously
        // confined even if that ever stops being where the field comes from.
        if Path::new(&rec.vm_id).components().count() != 1 {
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

/// Kill firecracker processes orphaned by a run whose owning CLI has exited.
///
/// A run records its CLI pid in `<vm_dir>/owner.pid`; firecracker carries
/// `--id <vm_id>` in its argv. For each live firecracker we map `--id` back to
/// its VM dir, and if the recorded owner pid is no longer alive the VMM is an
/// orphan (its `kill_on_drop` guard never ran) — SIGKILL it so its held tap /
/// resources are freed. Best-effort: every step is guarded; a live run's VMM
/// (owner still alive) is never touched. Unix-only; a no-op elsewhere.
pub fn reap_orphans() {
    let Ok(vms) = paths::vms_dir() else { return };
    for (pid, vm_id) in firecracker_procs() {
        let owner = vms.join(&vm_id).join("owner.pid");
        let owner_alive = std::fs::read_to_string(&owner)
            .ok()
            // no/unreadable owner pid ⇒ treat as orphan. Note this must parse the
            // same token format `owner_token` writes: a parse that failed on the
            // start-time suffix would read every live run as an orphan and SIGKILL
            // it.
            .is_some_and(|s| owner_token_alive(s.trim()));
        if !owner_alive {
            let _ = kill_pid(pid);
        }
    }
}

/// Enumerate `(pid, vm_id)` for every running `firecracker --id <vm_id>` by
/// scanning `/proc/<pid>/cmdline`.
fn firecracker_procs() -> Vec<(i32, String)> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(raw) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        // cmdline is NUL-separated argv.
        let args: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        if args.first().map(|a| a.ends_with("firecracker")) != Some(true) {
            continue;
        }
        if let Some(i) = args.iter().position(|a| a == "--id") {
            if let Some(id) = args.get(i + 1) {
                if id.starts_with("dev-") {
                    found.push((pid, id.clone()));
                }
            }
        }
    }
    found
}

/// Whether `pid` is a live process (`/proc/<pid>` exists).
fn pid_alive(pid: i32) -> bool {
    pid > 0 && std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// A process's start time, in clock ticks since boot (`/proc/<pid>/stat` field
/// 22). `None` if the process is gone or the file cannot be parsed.
///
/// Read after the last `)` because field 2 is the executable name in parentheses
/// and may itself contain spaces and parentheses — splitting the whole line on
/// whitespace is the classic way to get this wrong.
fn proc_starttime(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // Fields from 3 onward; starttime is field 22, i.e. index 19 here.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// What a run records in `owner.pid`: its pid and that pid's start time.
///
/// The pid alone is not an identity. Pids are recycled, and these records outlive
/// the runs that wrote them by design — so on a busy host a finished run's pid is
/// eventually reused by something unrelated, and a bare `/proc/<pid>` test then
/// reports that run as still going. That is not merely untidy: it is the
/// difference between `vm gc` skipping a directory forever and `vm list`
/// reporting `live: true` for a run that ended hours ago.
///
/// Pairing the pid with its start time makes the check an identity test rather
/// than an existence test, using only `/proc` and no new dependency.
pub(crate) fn owner_token() -> String {
    let pid = std::process::id();
    match proc_starttime(pid as i32) {
        Some(started) => format!("{pid} {started}"),
        None => pid.to_string(),
    }
}

/// Whether the process that wrote `token` is still running.
///
/// Accepts a bare pid as well as `"<pid> <starttime>"`, because records written
/// by an earlier isopod have only the pid. Those keep the old, weaker check —
/// there is nothing better to be had from them, and treating them as dead would
/// make gc collect live runs, which is the failure this whole path exists to
/// prevent.
fn owner_token_alive(token: &str) -> bool {
    let mut parts = token.split_whitespace();
    let Some(pid) = parts.next().and_then(|p| p.parse::<i32>().ok()) else {
        return false;
    };
    if !pid_alive(pid) {
        return false;
    }
    match parts.next().and_then(|s| s.parse::<u64>().ok()) {
        // A different start time means the pid was recycled: whatever is running
        // under it now is not the run that wrote this file.
        Some(recorded) => proc_starttime(pid) == Some(recorded),
        None => true,
    }
}

/// SIGKILL a pid.
///
/// Directly, not by spawning `/bin/kill`: that was here only because core once
/// took no `libc` dependency, and it made the reaper depend on a binary being on
/// `PATH` and on resolving to the real one.
fn kill_pid(pid: i32) -> std::io::Result<()> {
    eprintln!("vm: reaping orphaned firecracker pid {pid}");
    // SAFETY: `kill` is a plain syscall wrapper touching no memory. A positive
    // pid signals exactly that process (never a group), and the caller has
    // already established it is a firecracker this isopod started.
    if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    // Already gone between the liveness check and here: the reaper got what it
    // wanted, so this is success.
    match e.raw_os_error() {
        Some(libc::ESRCH) => Ok(()),
        _ => Err(e),
    }
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
        // The DIRECTORY NAME, deliberately — not meta.json's `vm_id`. The
        // directory is what `gc` deletes and what the reaper maps a live
        // firecracker's `--id` back to, and its name is the filesystem's answer
        // rather than a run's. Preferring the file's field meant a `vm_id` of
        // `"../../.."` inside any writable meta.json turned `remove_dir_all` into
        // a traversal, reachable through a `copy_out` destination.
        vm_id: fallback_id,
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
        live: owner_alive(dir),
    }
}

/// Whether the run that created `dir` is still running, by its recorded owner pid.
///
/// Unreadable or unparseable ⇒ `false`, which is the same reading the reaper takes
/// (`reap_orphans` treats a missing owner pid as an orphan). The pid is written
/// immediately after the directory is created, so the only window where a live run
/// looks dead is between those two operations, before any VMM exists.
fn owner_alive(dir: &Path) -> bool {
    owner_alive_at(dir, now_unix())
}

/// The longest a record may claim to be live on the strength of its owner pid.
///
/// A run's own wall budget is capped at [`crate::vm::MAX_TIMEOUT_S`], so a record
/// older than that has finished whatever its `owner.pid` says. The bound matters
/// because the pid identifies the **supervisor process**, which is the run's own
/// process for the CLI but the *long-lived server* for MCP: an MCP run that died
/// without clearing its file would otherwise be protected for as long as the
/// server stayed up, and `vm_gc` — whose whole job is pruning MCP run directories
/// — would never collect anything again.
const OWNER_CLAIM_MAX_AGE_S: u64 = crate::vm::MAX_TIMEOUT_S;

/// [`owner_alive`] with the clock injected.
fn owner_alive_at(dir: &Path, now: u64) -> bool {
    let Ok(token) = std::fs::read_to_string(dir.join("owner.pid")) else {
        // The ordinary end state: a finished run removes the file, so its absence
        // is the run saying it is done. This is what makes `live` mean "in
        // flight" rather than "started by a process that still exists".
        return false;
    };
    if !owner_token_alive(token.trim()) {
        return false;
    }
    // The file is still there and its writer is still alive. Under MCP that is
    // the server, so bound the claim by the longest a run is permitted to last.
    dir_created_unix(dir).is_none_or(|created| now.saturating_sub(created) < OWNER_CLAIM_MAX_AGE_S)
}

/// Seconds since the epoch, saturating to 0 on a clock before it.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Mark a run as finished by removing its `owner.pid`.
///
/// Called on every exit path of a run, successful or not. Without it `live` would
/// mean "the process that started this run still exists", which for a CLI run is
/// the same thing and for an MCP run is not: the supervisor is the server, so
/// every record it ever wrote would stay live until the server exited.
pub(crate) fn clear_owner(dir: &Path) {
    let _ = std::fs::remove_file(dir.join("owner.pid"));
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
    fn a_finished_run_is_not_live_even_though_its_supervisor_still_exists() {
        // The regression this exists to prevent: under the MCP server the owner
        // pid is the *server's*, which outlives every run it starts. So every
        // record the server ever wrote reported live forever and `vm_gc` — whose
        // whole job is pruning those directories — collected nothing. Observed on
        // a real host: 12 of 33 records "live" with one VM running.
        let vms = tempfile::tempdir().unwrap();
        fake_vm(vms.path(), "dev-mcp", "run-under-a-server", 100);
        let dir = vms.path().join("dev-mcp");
        // Our own pid stands in for the long-lived server: alive by definition.
        std::fs::write(dir.join("owner.pid"), owner_token()).unwrap();
        assert!(owner_alive(&dir), "while the run is in flight");

        // The run ends. The supervisor is still very much alive.
        clear_owner(&dir);
        assert!(
            !owner_alive(&dir),
            "a finished run must not be live just because its supervisor is"
        );
        let report = gc_in(vms.path(), 0, Duration::from_secs(0)).unwrap();
        assert_eq!(report.removed, vec!["dev-mcp".to_string()]);
    }

    #[test]
    fn a_stale_owner_file_stops_protecting_after_the_longest_permitted_run() {
        // A run that died without clearing its file (a panic, a SIGKILL) leaves
        // the token behind. Under MCP its writer is still alive, so the record
        // would be protected until the server exited. Bounded by the longest a
        // run is allowed to last: past that, whatever the file says, the run is
        // over.
        let vms = tempfile::tempdir().unwrap();
        fake_vm(vms.path(), "dev-crashed", "died-without-clearing", 100);
        let dir = vms.path().join("dev-crashed");
        std::fs::write(dir.join("owner.pid"), owner_token()).unwrap();

        let created = dir_created_unix(&dir).expect("dir mtime");
        assert!(owner_alive_at(&dir, created + 5), "still inside the window");
        assert!(
            !owner_alive_at(&dir, created + OWNER_CLAIM_MAX_AGE_S + 1),
            "past the longest permitted run, the claim expires"
        );
    }

    #[test]
    fn a_recycled_pid_does_not_resurrect_a_finished_run() {
        // Records outlive the runs that wrote them, so on a busy host a finished
        // run's pid gets reused. A bare `/proc/<pid>` test then reports that run as
        // live forever — which showed up the moment this was run against a real
        // host: five records claimed `live` with one VM actually running.
        let live = owner_token();
        assert!(
            live.split_whitespace().count() == 2,
            "a token should carry the start time on Linux: {live:?}"
        );
        assert!(owner_token_alive(&live), "our own token must read as live");

        // Same pid, a start time that is not ours: the pid was recycled.
        let pid = live.split_whitespace().next().unwrap();
        assert!(
            !owner_token_alive(&format!("{pid} 999999999")),
            "a mismatched start time must not read as live"
        );

        // A record written by an earlier isopod carries only a pid, and keeps the
        // old, weaker check rather than being read as dead — reading it as dead
        // would let gc collect a live run, which is the failure this path exists
        // to prevent.
        assert!(owner_token_alive(pid), "a bare pid still reads as live");
        assert!(!owner_token_alive("2147483646"), "a dead bare pid does not");
        assert!(!owner_token_alive(""), "an empty token is not live");
        assert!(!owner_token_alive("junk 1"), "an unparseable one is not");
    }

    #[test]
    fn gc_never_collects_a_run_that_is_still_going() {
        // `min_age` is a guess about how long runs last — 60 s over MCP, against a
        // permitted timeout of an hour — so age alone cannot protect a live run. A
        // collected run loses the vsock socket its remaining RPCs need and the
        // scratch `commit_as` was to freeze, and the missing `owner.pid` then reads
        // to the reaper as proof of orphanhood, so the next pass SIGKILLs its VMM.
        let vms = tempfile::tempdir().unwrap();
        fake_vm(vms.path(), "dev-live", "in-flight", 100);
        fake_vm(vms.path(), "dev-done", "finished", 100);
        // Our own pid: alive by definition, for as long as this test runs.
        std::fs::write(
            vms.path().join("dev-live").join("owner.pid"),
            std::process::id().to_string(),
        )
        .unwrap();
        // A pid that is not alive — the ordinary case for a finished run's dir.
        std::fs::write(vms.path().join("dev-done").join("owner.pid"), "2147483646").unwrap();

        let live = list_in(vms.path()).unwrap();
        assert!(live.iter().find(|r| r.vm_id == "dev-live").unwrap().live);
        assert!(!live.iter().find(|r| r.vm_id == "dev-done").unwrap().live);

        // The most aggressive request the tool surface can make.
        let report = gc_in(vms.path(), 0, Duration::from_secs(0)).unwrap();
        assert_eq!(report.removed, vec!["dev-done".to_string()]);
        assert_eq!(report.kept, 1);
        assert!(vms.path().join("dev-live").exists(), "live run survives gc");
    }

    #[test]
    fn gc_deletes_by_directory_name_not_by_what_meta_json_claims() {
        // `remove_dir_all(root.join(rec.vm_id))` with `vm_id` taken from meta.json
        // was a traversal: one write into any `vms/*/meta.json` — which `copy_out`
        // can perform whenever its confinement root covers the home directory —
        // and the next gc pass deleted a directory outside the vms root entirely.
        let vms = tempfile::tempdir().unwrap();
        let outside = vms.path().parent().unwrap().join("must-survive-gc");
        std::fs::create_dir_all(&outside).unwrap();

        let dir = vms.path().join("dev-evil");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("meta.json"),
            format!(
                r#"{{"vm_id":"../{}","name":"x","flavor":"t","created_unix":1}}"#,
                outside.file_name().unwrap().to_string_lossy()
            ),
        )
        .unwrap();

        let rec = read_record(&dir);
        assert_eq!(rec.vm_id, "dev-evil", "the directory name is authoritative");
        let report = gc_in(vms.path(), 0, Duration::from_secs(0)).unwrap();
        assert_eq!(report.removed, vec!["dev-evil".to_string()]);
        assert!(outside.exists(), "gc must not have escaped the vms root");
        std::fs::remove_dir_all(&outside).ok();
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
