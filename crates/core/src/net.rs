//! Host networking: the tap-slot model and the one-time privileged provisioning
//! (`isopod setup`).
//!
//! # Design (per PLAN.md "Networking", revised at M4)
//!
//! Firecracker VMs get egress through a **user-owned tap in the root network
//! namespace** — netns pools were dropped because entering a netns at runtime
//! needs root, which would break isopod's no-root-at-runtime property. The M0
//! spike proved an ordinary user can open a root-created tap.
//!
//! A fixed set of `slot_count` slots is provisioned once by `sudo isopod setup`.
//! Every slot `i` is a deterministic, collision-free bundle:
//!
//! | Resource   | Value                       |
//! |------------|-----------------------------|
//! | tap device | `isopod-tap<i>`             |
//! | host IP    | `10.107.<i>.1/30`           |
//! | guest IP   | `10.107.<i>.2/30`           |
//! | guest MAC  | `06:00:0a:6b:<i>:02`        |
//!
//! The guest MAC embeds the guest IP (`0a.6b.<i>.02` = `10.107.<i>.2`) so it is
//! unique per slot and stable across boots. Each slot is its own `/30`, so
//! distinct slots are on distinct subnets and cannot address one another even
//! before nftables isolation.
//!
//! At runtime a VM **claims** a free slot via an `O_EXCL` lockfile under
//! `~/.isopod/net/slot-<i>.lock` (containing the claiming pid) and **releases**
//! it by unlinking on [`Slot`] drop. A startup [`sweep_stale`] reclaims locks
//! whose owning pid is dead (crash recovery). The manifest
//! `~/.isopod/net/slots.json` records what `setup` provisioned.
//!
//! The `*_in(root)` helpers take an explicit state root so the slot logic is
//! unit-testable against a temp directory without a real `~/.isopod`.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths;

pub mod setup;

/// Default number of tap slots `isopod setup` provisions.
pub const DEFAULT_SLOT_COUNT: usize = 8;

/// Upper bound on the slot count: the slot index is the third octet of every
/// slot's `10.107.<i>.0/30`, so it must fit a `u8`; this leaves generous
/// headroom below 256 while keeping `isopod-tap<i>` within `IFNAMSIZ`.
pub const MAX_SLOT_COUNT: usize = 250;

/// Linux `IFNAMSIZ`: interface names are at most 15 bytes plus a NUL terminator.
const IFNAMSIZ: usize = 16;

/// Schema version of the [`Manifest`] written to `slots.json`.
pub const MANIFEST_VERSION: u32 = 1;

/// DNS resolvers baked into every networked guest (public resolvers, reachable
/// only via NAT egress — never the host). Passed to the guest on the kernel
/// command line as `isopod.dns=`.
pub const DEFAULT_DNS: &str = "1.1.1.1,8.8.8.8";

/// The whole address space isopod slots live in: `10.107.0.0/16`. Used by the
/// nftables masquerade/isolation rules.
pub const SLOT_SUPERNET: &str = "10.107.0.0/16";

/// Basename of the provisioning manifest inside the net state directory.
const MANIFEST_FILE: &str = "slots.json";

// ===========================================================================
// Slot parameters (pure, deterministic, unit-testable).
// ===========================================================================

/// The tap device name for slot `i` (`isopod-tap<i>`), validated to fit within
/// `IFNAMSIZ`.
///
/// # Errors
/// If the resulting name would meet or exceed `IFNAMSIZ` (15 usable bytes).
pub fn tap_name(i: usize) -> Result<String> {
    let name = format!("isopod-tap{i}");
    if name.len() >= IFNAMSIZ {
        bail!(
            "tap name {name:?} is {} bytes, exceeds IFNAMSIZ-1 ({})",
            name.len(),
            IFNAMSIZ - 1
        );
    }
    Ok(name)
}

/// The third IP octet for slot `i`, validated to fit a `u8`.
///
/// # Errors
/// If `i` does not fit in a `u8` (slot index out of the `10.107.<i>.0/30` range).
fn octet(i: usize) -> Result<u8> {
    u8::try_from(i).map_err(|_| anyhow!("slot index {i} does not fit the 10.107.<i>.0/30 scheme"))
}

/// The host-side IP for slot `i` (`10.107.<i>.1`).
#[must_use]
pub fn host_ip(i: usize) -> String {
    format!("10.107.{i}.1")
}

/// The guest-side IP for slot `i` (`10.107.<i>.2`).
#[must_use]
pub fn guest_ip(i: usize) -> String {
    format!("10.107.{i}.2")
}

/// The host-side CIDR for slot `i` (`10.107.<i>.1/30`) — the address `setup`
/// puts on the tap.
#[must_use]
pub fn host_cidr(i: usize) -> String {
    format!("10.107.{i}.1/30")
}

/// The guest-side CIDR for slot `i` (`10.107.<i>.2/30`) — passed to the guest as
/// `isopod.net=`.
#[must_use]
pub fn guest_cidr(i: usize) -> String {
    format!("10.107.{i}.2/30")
}

/// The deterministic guest MAC for slot `i` (`06:00:0a:6b:<i>:02`). The trailing
/// four octets are the guest IP (`0a.6b.<i>.02` = `10.107.<i>.2`), so the MAC is
/// unique per slot and stable across boots.
#[must_use]
pub fn guest_mac(i: usize) -> String {
    format!("06:00:0a:6b:{i:02x}:02")
}

// ===========================================================================
// Manifest + claimed slot.
// ===========================================================================

/// The provisioning manifest `setup` writes to `~/.isopod/net/slots.json`.
///
/// It records what the one-time privileged step provisioned so the runtime can
/// verify setup ran and learn how many slots exist without re-probing the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version ([`MANIFEST_VERSION`]).
    pub version: u32,
    /// Number of provisioned slots (`isopod-tap0..<slot_count-1>`).
    pub slot_count: usize,
    /// The host's default-route egress interface the NAT masquerades out of.
    pub default_iface: String,
    /// When `setup` wrote this manifest (Unix seconds).
    pub created_unix: u64,
}

/// A claimed network slot. Holds an `O_EXCL` lockfile for its lifetime;
/// [`Drop`] releases the slot by unlinking it, so a slot is never leaked even if
/// the run panics.
#[derive(Debug)]
pub struct Slot {
    index: usize,
    lock_path: PathBuf,
}

impl Slot {
    /// The slot index (also the third octet of every address).
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// This slot's tap device name (`isopod-tap<i>`).
    #[must_use]
    pub fn tap_name(&self) -> String {
        format!("isopod-tap{}", self.index)
    }

    /// This slot's host IP (`10.107.<i>.1`).
    #[must_use]
    pub fn host_ip(&self) -> String {
        host_ip(self.index)
    }

    /// This slot's guest IP (`10.107.<i>.2`).
    #[must_use]
    pub fn guest_ip(&self) -> String {
        guest_ip(self.index)
    }

    /// This slot's guest CIDR (`10.107.<i>.2/30`), for `isopod.net=`.
    #[must_use]
    pub fn guest_cidr(&self) -> String {
        guest_cidr(self.index)
    }

    /// This slot's deterministic guest MAC.
    #[must_use]
    pub fn guest_mac(&self) -> String {
        guest_mac(self.index)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        // Best-effort release: a failure to unlink only leaves a stale lock that
        // the next `sweep_stale` reclaims (our pid will be dead).
        let _ = fs::remove_file(&self.lock_path);
    }
}

// ===========================================================================
// Public API (resolves the state root through `crate::paths`).
// ===========================================================================

/// Whether `sudo isopod setup` has provisioned the host (the manifest exists).
#[must_use]
pub fn setup_manifest_exists() -> bool {
    match net_dir() {
        Ok(root) => root.join(MANIFEST_FILE).is_file(),
        Err(_) => false,
    }
}

/// Read the provisioning manifest.
///
/// # Errors
/// If the manifest is absent (setup has not run) or cannot be parsed.
pub fn read_manifest() -> Result<Manifest> {
    read_manifest_in(&net_dir()?)
}

/// Reclaim slot locks whose owning pid is dead (crash recovery), returning how
/// many were reclaimed.
///
/// # Errors
/// If the net directory exists but cannot be read.
pub fn sweep_stale() -> Result<usize> {
    sweep_stale_in(&net_dir()?)
}

/// Claim the lowest-numbered free slot, first reclaiming any stale locks.
///
/// The returned [`Slot`] releases itself on drop.
///
/// # Errors
/// If setup has not run, the manifest cannot be read, or every slot is in use.
pub fn claim() -> Result<Slot> {
    let root = net_dir()?;
    let manifest = read_manifest_in(&root).context(
        "network manifest ~/.isopod/net/slots.json is missing or unreadable; \
         run `sudo isopod setup` once, or pass --no-network",
    )?;
    claim_in(&root, manifest.slot_count)
}

// ===========================================================================
// Root-parameterized implementations (unit-testable without $ISOPOD_HOME).
// ===========================================================================

/// `~/.isopod/net`, created on demand (mode `0755`; a failure to set the mode is
/// tolerated so a caller lacking chmod rights on an existing dir still works).
pub(crate) fn net_dir() -> Result<PathBuf> {
    let dir = paths::isopod_home()?.join("net");
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o755));
    Ok(dir)
}

fn manifest_path_in(root: &Path) -> PathBuf {
    root.join(MANIFEST_FILE)
}

fn lock_path_in(root: &Path, i: usize) -> PathBuf {
    root.join(format!("slot-{i}.lock"))
}

fn read_manifest_in(root: &Path) -> Result<Manifest> {
    let path = manifest_path_in(root);
    let raw = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn write_manifest_in(root: &Path, manifest: &Manifest) -> Result<()> {
    let json = serde_json::to_string_pretty(manifest).context("serializing net manifest")?;
    let path = manifest_path_in(root);
    let tmp = root.join("slots.json.partial");
    fs::write(&tmp, format!("{json}\n")).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("finalizing {}", path.display()))
}

fn claim_in(root: &Path, slot_count: usize) -> Result<Slot> {
    if slot_count == 0 || slot_count > MAX_SLOT_COUNT {
        bail!("invalid slot_count {slot_count} (expected 1..={MAX_SLOT_COUNT})");
    }
    // Reclaim crashed owners first so a busy scan does not spuriously exhaust.
    let _ = sweep_stale_in(root);

    for i in 0..slot_count {
        // Validate the slot's derived names/addresses up front; a misconfigured
        // slot_count must never yield an out-of-range tap name or octet.
        tap_name(i)?;
        octet(i)?;
        if let Some(slot) = try_claim_slot(root, i)? {
            return Ok(slot);
        }
    }
    bail!(
        "all {slot_count} network slots are in use; wait for a run to finish or \
         provision more with `sudo isopod setup --slots N`"
    )
}

/// Try to claim slot `i`: create its lockfile with `O_EXCL`. Returns `Ok(Some)`
/// on success, `Ok(None)` if a live owner holds it, and reclaims-then-retries a
/// single time if the existing lock is stale.
fn try_claim_slot(root: &Path, i: usize) -> Result<Option<Slot>> {
    let lock = lock_path_in(root, i);
    match create_lock(&lock) {
        Ok(()) => Ok(Some(Slot {
            index: i,
            lock_path: lock,
        })),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale (dead owner)? Reclaim and retry exactly once; if someone else
            // wins the retry, treat the slot as busy.
            if lock_is_stale(&lock) {
                let _ = fs::remove_file(&lock);
                match create_lock(&lock) {
                    Ok(()) => Ok(Some(Slot {
                        index: i,
                        lock_path: lock,
                    })),
                    Err(e2) if e2.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
                    Err(e2) => Err(anyhow::Error::new(e2).context(format!("claiming slot {i}"))),
                }
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!("claiming slot {i}"))),
    }
}

/// Create the lockfile atomically (`O_EXCL`) and write our pid into it.
fn create_lock(lock: &Path) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock)?;
    write!(f, "{}", std::process::id())
}

/// A lock is stale if its recorded pid is unparseable or names a dead process.
fn lock_is_stale(lock: &Path) -> bool {
    match fs::read_to_string(lock) {
        Ok(s) => match s.trim().parse::<u32>() {
            Ok(pid) => !pid_is_alive(pid),
            Err(_) => true, // garbled lock: reclaim it
        },
        // Vanished between the readdir and the read: not our concern here.
        Err(_) => false,
    }
}

/// Whether `/proc/<pid>` exists (best-effort liveness; pid reuse is accepted for
/// v1, matching the PLAN's stale-pid sweep).
fn pid_is_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn sweep_stale_in(root: &Path) -> Result<usize> {
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("reading {}", root.display()))),
    };
    let mut reclaimed = 0;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading an entry in {}", root.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with("slot-") && name.ends_with(".lock")) {
            continue;
        }
        let path = entry.path();
        if lock_is_stale(&path) && fs::remove_file(&path).is_ok() {
            reclaimed += 1;
        }
    }
    Ok(reclaimed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tap_name_within_ifnamsiz() {
        assert_eq!(tap_name(0).unwrap(), "isopod-tap0");
        assert_eq!(tap_name(7).unwrap(), "isopod-tap7");
        assert_eq!(tap_name(249).unwrap(), "isopod-tap249"); // 13 bytes, fits
                                                             // A wildly out-of-range index would overflow IFNAMSIZ.
        assert!(tap_name(1_000_000_000).is_err());
    }

    #[test]
    fn addresses_are_per_slot_slash_30() {
        assert_eq!(host_ip(0), "10.107.0.1");
        assert_eq!(guest_ip(0), "10.107.0.2");
        assert_eq!(host_cidr(3), "10.107.3.1/30");
        assert_eq!(guest_cidr(3), "10.107.3.2/30");
        assert_eq!(host_ip(42), "10.107.42.1");
    }

    #[test]
    fn guest_mac_embeds_the_guest_ip() {
        // 0a.6b = 10.107; trailing .02 = host part 2; middle octet = slot index.
        assert_eq!(guest_mac(0), "06:00:0a:6b:00:02");
        assert_eq!(guest_mac(7), "06:00:0a:6b:07:02");
        assert_eq!(guest_mac(10), "06:00:0a:6b:0a:02");
        assert_eq!(guest_mac(200), "06:00:0a:6b:c8:02");
    }

    #[test]
    fn octet_rejects_out_of_range() {
        assert_eq!(octet(0).unwrap(), 0);
        assert_eq!(octet(255).unwrap(), 255);
        assert!(octet(256).is_err());
    }

    #[test]
    fn manifest_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let m = Manifest {
            version: MANIFEST_VERSION,
            slot_count: 8,
            default_iface: "eth0".into(),
            created_unix: 1_700_000_000,
        };
        write_manifest_in(dir.path(), &m).unwrap();
        assert!(manifest_path_in(dir.path()).is_file());
        assert_eq!(read_manifest_in(dir.path()).unwrap(), m);
    }

    #[test]
    fn claim_picks_lowest_free_and_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let a = claim_in(root, 3).unwrap();
        assert_eq!(a.index(), 0);
        assert_eq!(a.tap_name(), "isopod-tap0");
        assert!(lock_path_in(root, 0).exists());

        let b = claim_in(root, 3).unwrap();
        assert_eq!(b.index(), 1);

        // Releasing slot 0 (drop) frees it; the next claim reuses the lowest free.
        drop(a);
        assert!(!lock_path_in(root, 0).exists(), "drop must unlink the lock");
        let c = claim_in(root, 3).unwrap();
        assert_eq!(c.index(), 0, "lowest free slot reused after release");

        // Keep b/c alive to the end so their locks persist for the exhaustion check.
        let _ = (&b, &c);
    }

    #[test]
    fn claim_exhaustion_errors_when_all_held() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let _s0 = claim_in(root, 2).unwrap();
        let _s1 = claim_in(root, 2).unwrap();
        let err = claim_in(root, 2).expect_err("all slots held must error");
        assert!(err.to_string().contains("in use"), "{err}");
    }

    #[test]
    fn sweep_reclaims_dead_owner_then_claim_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Forge a lock owned by a pid that cannot exist (above any pid_max).
        let stale = lock_path_in(root, 0);
        fs::write(&stale, "999999999").unwrap();
        assert!(lock_is_stale(&stale), "a dead-pid lock must read as stale");

        // A single-slot pool would be exhausted unless the stale lock is reclaimed.
        let reclaimed = sweep_stale_in(root).unwrap();
        assert_eq!(reclaimed, 1);
        assert!(!stale.exists());

        let s = claim_in(root, 1).unwrap();
        assert_eq!(s.index(), 0);
    }

    #[test]
    fn live_lock_is_not_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Our own pid is alive, so this lock must survive a sweep.
        let live = lock_path_in(root, 0);
        fs::write(&live, format!("{}", std::process::id())).unwrap();
        assert!(!lock_is_stale(&live));
        assert_eq!(sweep_stale_in(root).unwrap(), 0);
        assert!(live.exists());
    }

    #[test]
    fn claim_reclaims_stale_lock_inline() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Slot 0 held by a dead pid; claim must reclaim it rather than skip to 1.
        fs::write(lock_path_in(root, 0), "999999999").unwrap();
        let s = claim_in(root, 4).unwrap();
        assert_eq!(s.index(), 0, "stale slot 0 reclaimed inline");
    }

    #[test]
    fn claim_rejects_bad_slot_count() {
        let dir = tempfile::tempdir().unwrap();
        assert!(claim_in(dir.path(), 0).is_err());
        assert!(claim_in(dir.path(), MAX_SLOT_COUNT + 1).is_err());
    }
}
