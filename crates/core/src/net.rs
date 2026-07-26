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

pub mod broker;
pub mod credentials;
pub mod egress;
pub mod inject;
pub mod secret;
pub mod setup;

/// Default number of tap slots `isopod setup` provisions.
///
/// Raised from 8 to 12 in 0.9.0 alongside [`DEFAULT_FILTERED_SLOTS`]: the four
/// filtered slots are *added* to the pool rather than carved out of it, so the
/// public-slot concurrency an existing install already has is unchanged.
pub const DEFAULT_SLOT_COUNT: usize = 12;

/// Default number of the provisioned slots that are filtered-egress.
///
/// Filtered slots forward nothing; their only reachable peer is the egress
/// broker on their own gateway ([`setup::build_nft_ruleset`]).
pub const DEFAULT_FILTERED_SLOTS: usize = 4;

/// The broker's SOCKS5 listener port on the slot gateway.
///
/// The three broker ports are compile-time constants because `sudo isopod
/// setup` bakes them into the nftables ruleset; the unprivileged runtime cannot
/// re-open a hole for a port chosen later. All three are above 1024 so the
/// runtime can bind them without privilege.
pub const BROKER_SOCKS_PORT: u16 = 1080;

/// The broker's HTTP `CONNECT` listener port on the slot gateway.
pub const BROKER_HTTP_PORT: u16 = 3128;

/// The broker's credential-injection listener port on the slot gateway.
///
/// Added in 0.10.0. A host provisioned before it has no nftables hole for this
/// port, so its filtered guests cannot reach the endpoint at all — which is why
/// [`Manifest::supports_credential_endpoint`] exists and why a run that asks for
/// `--inject` on such a host fails closed rather than booting a guest that will
/// see a silent connection refusal.
pub const BROKER_INJECT_PORT: u16 = 3129;

/// The broker's DNS listener port on the slot gateway.
///
/// The guest sends to `:53`; a setup-time `redirect` rewrites that to this
/// port, because an unprivileged process cannot bind a port below 1024 and
/// neither `ip_unprivileged_port_start` (host-global) nor `CAP_NET_BIND_SERVICE`
/// (a runtime privilege) is an acceptable price for three lines of nft.
pub const BROKER_DNS_PORT: u16 = 5353;

/// Every broker TCP port a current `isopod setup` opens on a filtered slot's
/// gateway, ascending — the exact set interpolated into the nftables ruleset and
/// recorded in the manifest.
///
/// Single source of truth so the ruleset, the manifest and the runtime's
/// reachability check cannot drift apart: adding a listener means adding it here
/// and re-provisioning, and a host that has not re-provisioned is detectable.
pub const BROKER_TCP_PORTS: [u16; 4] = [
    BROKER_SOCKS_PORT,
    BROKER_HTTP_PORT,
    BROKER_INJECT_PORT,
    BROKER_DNS_PORT,
];

/// The broker TCP ports a 0.9-era `isopod setup` baked in, before credential
/// injection existed. What a manifest with no recorded port list means.
const LEGACY_BROKER_TCP_PORTS: [u16; 3] = [BROKER_SOCKS_PORT, BROKER_HTTP_PORT, BROKER_DNS_PORT];

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

/// The guest that shares a slot's `/30` with host address `gw`.
///
/// The two addresses of a slot differ only in their last octet (`.1` host, `.2`
/// guest), and the broker needs the guest's to answer "is this connection from
/// the sandbox this broker belongs to, or from some other process on the host?".
/// Deriving it here rather than in the broker keeps the addressing scheme in the
/// one module that owns it.
#[must_use]
pub fn guest_for_gateway(gw: std::net::Ipv4Addr) -> std::net::Ipv4Addr {
    let mut octets = gw.octets();
    octets[3] = 2;
    std::net::Ipv4Addr::from(octets)
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
    /// Whether setup was run with `--allow-lan-egress` (guest→private-LAN egress
    /// permitted). Informational/audit; the live nftables ruleset is
    /// authoritative. `#[serde(default)]` keeps pre-existing on-disk manifests
    /// (which lack the field) deserializable without a `MANIFEST_VERSION` bump.
    #[serde(default)]
    pub allow_lan_egress: bool,
    /// Index of the first filtered-egress slot: slots `[filtered_from,
    /// slot_count)` forward nothing and reach only their gateway broker.
    ///
    /// **`Option`, not `#[serde(default)]`.** A bare `usize` default is `0`,
    /// which would read a pre-0.9 manifest (no such key) as "*every* slot is
    /// filtered" and break every existing install's networking on upgrade.
    /// `None` means "no filtered slots" and is resolved by
    /// [`Manifest::filtered_from`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filtered_from: Option<usize>,
    /// The broker TCP ports this provisioning opened on each filtered slot's
    /// gateway.
    ///
    /// Recorded rather than assumed, because the ruleset is baked once as root
    /// and the unprivileged runtime cannot open a hole for a port added by a
    /// later release. `None` — every manifest written before 0.10.0, and every
    /// install with no filtered slots — resolves to
    /// [`LEGACY_BROKER_TCP_PORTS`], the pre-credential-injection set. That is
    /// the fail-closed reading: a port this host never opened must never be
    /// assumed reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broker_tcp_ports: Option<Vec<u16>>,
}

impl Manifest {
    /// Build a manifest, normalising `filtered_from` to its wire form (`None`
    /// when no slot is filtered, so a fresh manifest with the feature unused is
    /// byte-identical to a pre-0.9 one).
    ///
    /// The broker port list is recorded only when this host actually has
    /// filtered slots, for the same reason: an install that uses none of this
    /// still produces the pre-0.9 manifest verbatim.
    #[must_use]
    pub fn new(
        slot_count: usize,
        default_iface: String,
        created_unix: u64,
        allow_lan_egress: bool,
        filtered_from: usize,
    ) -> Self {
        let filtered = filtered_from < slot_count;
        Self {
            version: MANIFEST_VERSION,
            slot_count,
            default_iface,
            created_unix,
            allow_lan_egress,
            filtered_from: filtered.then_some(filtered_from),
            broker_tcp_ports: filtered.then(|| BROKER_TCP_PORTS.to_vec()),
        }
    }

    /// The broker TCP ports this host's nftables ruleset opens on a filtered
    /// slot's gateway. An unrecorded list reads as the pre-0.10 set.
    #[must_use]
    pub fn broker_tcp_ports(&self) -> Vec<u16> {
        self.broker_tcp_ports
            .clone()
            .unwrap_or_else(|| LEGACY_BROKER_TCP_PORTS.to_vec())
    }

    /// Whether a filtered guest on this host can reach the credential-injection
    /// endpoint — i.e. whether `sudo isopod setup` opened
    /// [`BROKER_INJECT_PORT`].
    #[must_use]
    pub fn supports_credential_endpoint(&self) -> bool {
        self.broker_tcp_ports().contains(&BROKER_INJECT_PORT)
    }

    /// Index of the first filtered slot. An absent field (pre-0.9 manifests, or
    /// a `--filtered-slots 0` provisioning) resolves to `slot_count`, i.e. no
    /// slot is filtered — never `0`, which would mean "all of them".
    #[must_use]
    pub fn filtered_from(&self) -> usize {
        self.filtered_from
            .filter(|&f| f <= self.slot_count)
            .unwrap_or(self.slot_count)
    }

    /// How many provisioned slots are filtered-egress.
    #[must_use]
    pub fn filtered_count(&self) -> usize {
        self.slot_count.saturating_sub(self.filtered_from())
    }

    /// Whether slot `i` is a filtered-egress slot under this manifest.
    #[must_use]
    pub fn is_filtered(&self, i: usize) -> bool {
        i >= self.filtered_from() && i < self.slot_count
    }
}

/// A claimed network slot. Holds an `O_EXCL` lockfile for its lifetime;
/// [`Drop`] releases the slot by unlinking it, so a slot is never leaked even if
/// the run panics.
#[derive(Debug)]
pub struct Slot {
    index: usize,
    lock_path: PathBuf,
    /// The exact bytes this claim wrote into its lockfile, so release can tell
    /// "still mine" from "someone else's now" — including against a sibling run
    /// in the same process, which a pid cannot. See [`Drop for Slot`](Slot#impl-Drop).
    token: String,
    filtered: bool,
}

impl Slot {
    /// The slot index (also the third octet of every address).
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// Whether this is a filtered-egress slot (forwards nothing; reaches only
    /// the broker on its own gateway).
    #[must_use]
    pub fn is_filtered(&self) -> bool {
        self.filtered
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
        // Only if the lock is still *ours*, compared by the exact token this claim
        // wrote. Unlinking unconditionally meant that if the lock had been
        // replaced — a reclaimed-too-eagerly sweep being the way that happens —
        // release would delete the lock of whichever run held the slot now,
        // letting a third claim it while that run's VM and broker were still
        // addressed on it.
        //
        // The token and not the pid, because under the MCP server every
        // concurrent run shares one process: a pid comparison says "mine" for a
        // sibling run's lock, which is exactly the case that needed protecting.
        //
        // Best-effort otherwise: a failure to unlink only leaves a stale lock that
        // the next `sweep_stale` reclaims (our pid will be dead).
        let ours = fs::read_to_string(&self.lock_path).is_ok_and(|s| s.trim() == self.token);
        if ours {
            let _ = fs::remove_file(&self.lock_path);
        }
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

/// Whether the kernel currently exposes a network device named `name`
/// (a `/sys/class/net/<name>` entry).
fn tap_present(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

/// Whether every tap the recorded manifest provisioned is present in the kernel
/// right now. Returns `Ok(false)` — not an error — when a manifest exists but
/// its taps are gone, which is the signature of a host/WSL2 restart since
/// `sudo isopod setup` (tap devices do not survive a restart).
///
/// # Errors
/// If the manifest cannot be read or a slot index is out of the tap-name range.
pub fn provisioned_taps_present() -> Result<bool> {
    let manifest = read_manifest()?;
    all_taps_present(manifest.slot_count, tap_present)
}

/// Core of [`provisioned_taps_present`] with the presence predicate injected, so
/// the "one missing ⇒ not present" logic is unit-testable without touching
/// `/sys`.
fn all_taps_present(slot_count: usize, present: impl Fn(&str) -> bool) -> Result<bool> {
    for i in 0..slot_count {
        if !present(&tap_name(i)?) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Reclaim slot locks whose owning pid is dead (crash recovery), returning how
/// many were reclaimed.
///
/// # Errors
/// If the net directory exists but cannot be read.
pub fn sweep_stale() -> Result<usize> {
    sweep_stale_in(&net_dir()?)
}

/// Claim the lowest-numbered free **public** slot (NAT egress to the public
/// internet), first reclaiming any stale locks.
///
/// The returned [`Slot`] releases itself on drop.
///
/// # Errors
/// If setup has not run, the manifest cannot be read, or every public slot is
/// in use.
pub fn claim() -> Result<Slot> {
    let (root, manifest) = manifest_for_claim()?;
    claim_range_in(&root, 0, manifest.filtered_from(), false)
}

/// Claim the lowest-numbered free **filtered-egress** slot.
///
/// # Errors
/// If setup has not run, the host was provisioned without filtered slots (the
/// error names the exact re-provisioning command), or every filtered slot is in
/// use.
pub fn claim_filtered() -> Result<Slot> {
    let (root, manifest) = manifest_for_claim()?;
    if manifest.filtered_count() == 0 {
        bail!(
            "this host has no filtered-egress slots: `sudo isopod setup` was run \
             without --filtered-slots. Re-provision with \
             `sudo isopod setup --slots {total} --filtered-slots {suggest}` \
             (existing public slots are unaffected), or drop the --allow-host / \
             --allow-cidr flags to run with unfiltered public egress.",
            total = manifest.slot_count + DEFAULT_FILTERED_SLOTS,
            suggest = DEFAULT_FILTERED_SLOTS,
        );
    }
    claim_range_in(&root, manifest.filtered_from(), manifest.slot_count, true)
}

/// Verify this host was provisioned with the credential-injection port open.
///
/// The hole for [`BROKER_INJECT_PORT`] is baked into nftables once, as root. A
/// host provisioned by 0.9.x has no such rule, and the unprivileged runtime
/// cannot add one — so a run that asks for `--inject` there would boot, bind a
/// listener the guest cannot address, and present as a hung request rather than
/// a policy decision. Refusing up front, with the exact re-provisioning command,
/// is the same trap `filtered_from` already taught us to close.
///
/// # Errors
/// If setup has not run, or ran before this port existed.
pub fn require_credential_endpoint() -> Result<()> {
    let manifest = read_manifest().context(
        "network manifest ~/.isopod/net/slots.json is missing or unreadable; \
         run `sudo isopod setup` once",
    )?;
    if manifest.supports_credential_endpoint() {
        return Ok(());
    }
    // A host with no filtered slots at all is a different problem with a
    // different fix, and `claim_filtered` already words it well. Saying "you
    // were provisioned before credential injection" to someone who ran
    // `--filtered-slots 0` last week would be simply untrue, and would send them
    // looking for a version mismatch that does not exist.
    if manifest.filtered_count() == 0 {
        return Ok(());
    }
    let opened = manifest
        .broker_tcp_ports()
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    // Suggest the host's own shape, not the defaults: an operator who chose
    // `--slots 24 --filtered-slots 8` must not be told to shrink their pool.
    // Clamped, because a command that names more slots than `setup` accepts
    // would be rejected by the very tool we are telling them to run.
    let total = manifest.slot_count.min(MAX_SLOT_COUNT);
    let filtered = manifest.filtered_count().min(total);
    bail!(
        "this host was provisioned before credential injection: its nftables ruleset \
         opens only port(s) {opened} on a filtered slot's gateway, so a guest cannot \
         reach the credential endpoint on {BROKER_INJECT_PORT}. Re-provision with \
         `sudo isopod setup --slots {total} --filtered-slots {filtered}` (taps and \
         in-flight runs are unaffected), or drop --inject."
    )
}

/// The procfs path of a tap's IPv4 forwarding flag.
///
/// World-readable, which is the whole point: it is the one piece of a filtered
/// slot's enforcement an unprivileged process can check. Reading the live
/// nftables ruleset requires `CAP_NET_ADMIN`.
#[must_use]
pub fn tap_forwarding_proc(tap: &str) -> String {
    format!("/proc/sys/net/ipv4/conf/{tap}/forwarding")
}

/// Verify the kernel still refuses to forward what arrives on slot `i`'s tap.
///
/// `setup` clears this flag for every filtered tap ([`setup`]'s step 3b), giving
/// the routing layer a refusal that does not depend on the nftables ruleset being
/// loaded — and, because the file is world-readable while the live ruleset needs
/// `CAP_NET_ADMIN` to read, one an unprivileged runtime can check.
///
/// # What this does and does not tell you
///
/// **It detects** the flag being turned back on. That is not hypothetical:
/// writing `net.ipv4.ip_forward` stamps every interface at once, so a container
/// runtime starting or a sysctl reload does it.
///
/// **It does not detect a flushed ruleset.** Nothing in nftables writes this file,
/// so `nft flush ruleset` leaves it at `0` and this check passes. What the flag
/// does there is *contain* the flush rather than report it: the kernel still
/// refuses to forward off the tap, so the run reaches nothing. But the ruleset's
/// other half is gone, and the flag has nothing to say about it — in
/// `ip_route_input_slow` a packet for a host-local address takes the `RTN_LOCAL`
/// branch **before** the forwarding test, so guest→host delivery is governed by
/// the nftables input chain and by nothing else. SECURITY.md states this as a
/// non-claim; do not let this doc drift into promising more.
///
/// # Errors
/// If the flag is set, or cannot be read at all. Both are refusals: this runs on
/// the path of a run whose entire promise is that it forwards nothing, so
/// "cannot tell" and "no" are the same answer.
pub fn require_filtered_kernel_guard(i: usize) -> Result<()> {
    let tap = tap_name(i)?;
    let path = tap_forwarding_proc(&tap);
    require_forwarding_off(&tap, std::fs::read_to_string(&path).ok().as_deref())
}

/// [`require_filtered_kernel_guard`] across the whole filtered pool.
///
/// Called before anything boots, so a host whose guard has been clobbered says so
/// immediately rather than after a warm-pool snapshot build has cold-booted a
/// builder VM. The per-slot check still runs on the slot actually claimed — this
/// one is about *when* the refusal arrives, not whether it does.
///
/// The realistic way the guard goes missing is host-wide (writing
/// `net.ipv4.ip_forward` stamps every interface at once), so any filtered tap
/// forwarding is treated as the whole pool being unprovisioned.
///
/// # Errors
/// If the manifest is unreadable, or any filtered tap's guard is not in place.
pub fn require_filtered_pool_guard() -> Result<()> {
    let manifest = read_manifest().context(
        "network manifest ~/.isopod/net/slots.json is missing or unreadable; \
         run `sudo isopod setup` once",
    )?;
    for i in manifest.filtered_from()..manifest.slot_count.min(MAX_SLOT_COUNT) {
        require_filtered_kernel_guard(i)?;
    }
    Ok(())
}

/// [`require_filtered_kernel_guard`] with the procfs read injected, so the
/// decision is testable without a provisioned host.
fn require_forwarding_off(tap: &str, raw: Option<&str>) -> Result<()> {
    // Anything other than a clear "0" is a refusal, including a value this
    // version does not recognise.
    if raw.map(str::trim) == Some("0") {
        return Ok(());
    }
    let observed = match raw {
        Some(v) => format!("is {:?}", v.trim()),
        None => "could not be read".to_string(),
    };
    bail!(
        "the kernel's forwarding guard for filtered slot {i} is not in place: \
         {path} {observed}, and `sudo isopod setup` leaves it at \"0\" so that the \
         kernel refuses to forward anything arriving on {tap} even if the nftables \
         ruleset is gone. Something has re-enabled forwarding host-wide: writing \
         net.ipv4.ip_forward stamps every interface at once, so a container \
         runtime starting or a sysctl reload does it. \
         A filtered run will not boot into that: re-provision with\n\n    \
         sudo isopod setup\n\n(taps and in-flight runs are unaffected), or run with \
         unfiltered public egress by dropping --allow-host / --allow-cidr / --inject.",
        i = tap.trim_start_matches("isopod-tap"),
        path = tap_forwarding_proc(tap),
    )
}

/// Shared preamble for both claim paths: resolve the state root and read the
/// manifest, with the "setup has not run" guidance attached.
fn manifest_for_claim() -> Result<(PathBuf, Manifest)> {
    let root = net_dir()?;
    let manifest = read_manifest_in(&root).context(
        "network manifest ~/.isopod/net/slots.json is missing or unreadable; \
         run `sudo isopod setup` once, or pass --no-network",
    )?;
    Ok((root, manifest))
}

// ===========================================================================
// Root-parameterized implementations (unit-testable without $ISOPOD_HOME).
// ===========================================================================

/// `~/.isopod/net`, created on demand (mode `0700`, tightened but never loosened —
/// see [`paths`]; a failure to set the mode is tolerated so a caller lacking chmod
/// rights on an existing dir still works).
pub(crate) fn net_dir() -> Result<PathBuf> {
    let dir = paths::isopod_home()?.join("net");
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let loose = fs::metadata(&dir)
        .map(|m| m.permissions().mode() & 0o7777 & !0o700 != 0)
        .unwrap_or(false);
    if loose {
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
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

/// Claim the lowest-numbered free slot in `[lo, hi)`, marking it `filtered`.
///
/// Both pools share the lockfile namespace and the stale sweep; they differ
/// only in which indices they scan, which is what makes the public/filtered
/// split a pure setup-time decision with no runtime coordination.
fn claim_range_in(root: &Path, lo: usize, hi: usize, filtered: bool) -> Result<Slot> {
    if hi == 0 || hi > MAX_SLOT_COUNT || lo > hi {
        bail!("invalid slot range {lo}..{hi} (expected 0..=hi, hi in 1..={MAX_SLOT_COUNT})");
    }
    // Reclaim crashed owners first so a busy scan does not spuriously exhaust.
    let _ = sweep_stale_in(root);

    for i in lo..hi {
        // Validate the slot's derived names/addresses up front; a misconfigured
        // slot_count must never yield an out-of-range tap name or octet.
        tap_name(i)?;
        octet(i)?;
        if let Some(slot) = try_claim_slot(root, i, filtered)? {
            return Ok(slot);
        }
    }
    let kind = if filtered {
        "filtered-egress"
    } else {
        "network"
    };
    bail!(
        "all {n} {kind} slots are in use; wait for a run to finish or provision \
         more with `sudo isopod setup --slots N --filtered-slots M`",
        n = hi - lo,
    )
}

/// Try to claim slot `i`: create its lockfile with `O_EXCL`. Returns `Ok(Some)`
/// on success, `Ok(None)` if a live owner holds it, and reclaims-then-retries a
/// single time if the existing lock is stale.
fn try_claim_slot(root: &Path, i: usize, filtered: bool) -> Result<Option<Slot>> {
    let lock = lock_path_in(root, i);
    match create_lock(&lock) {
        Ok(token) => Ok(Some(Slot {
            index: i,
            lock_path: lock,
            token,
            filtered,
        })),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale (dead owner)? Reclaim and retry exactly once; if someone else
            // wins the retry, treat the slot as busy.
            //
            // KNOWN LIMIT: deciding staleness and unlinking are two operations,
            // so two claimants that read the same dead pid can both proceed — the
            // second unlinking a lock the first has already replaced. Both then
            // believe they hold the slot, and the loser's VM fails opaquely when
            // firecracker cannot open the tap. It needs a real lock (`flock`,
            // whose release the kernel handles on process death, and which
            // distinguishes two open file descriptions in one process) rather
            // than a staleness heuristic; that is a change to the claiming
            // protocol, not a patch to this branch. Documented in SECURITY.md.
            if lock_is_stale(&lock) {
                let _ = fs::remove_file(&lock);
                match create_lock(&lock) {
                    Ok(token) => Ok(Some(Slot {
                        index: i,
                        lock_path: lock,
                        token,
                        filtered,
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

/// Distinguishes two claims made by the *same process*.
///
/// The pid alone cannot: under the MCP server every concurrent run shares one
/// process, so two claims write byte-identical locks. A release that only checked
/// the pid would then happily unlink a lock belonging to a sibling run that was
/// still using the slot.
static CLAIM_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The token one claim writes into its lockfile: `<pid> <nonce>`.
fn claim_token() -> String {
    let n = CLAIM_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{} {n}", std::process::id())
}

/// Create the lockfile atomically (`O_EXCL`) and write our claim token into it.
fn create_lock(lock: &Path) -> std::io::Result<String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock)?;
    let token = claim_token();
    write!(f, "{token}")?;
    Ok(token)
}

/// How long a lock whose contents do not parse is left alone.
///
/// [`create_lock`] is two operations — `create_new`, then write the pid — so for
/// an instant a live claim is a zero-byte file, which parses as nothing. Without
/// this grace period a concurrent claimer's [`sweep_stale_in`] read that instant
/// as "garbled ⇒ reclaim", deleted a claim that was in the middle of being made,
/// and took the same slot: two runs on one tap, one address pair, and one
/// gateway, presenting as an opaque "Open tap device failed" from the second
/// firecracker. Generous, because the cost of waiting is a slot that stays busy
/// for another few seconds and the cost of not waiting is two runs sharing it.
const LOCK_WRITE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// A lock is stale if its recorded pid names a dead process, or its contents do
/// not parse *and* it is too old to be a claim still being written.
fn lock_is_stale(lock: &Path) -> bool {
    stale_from(fs::read_to_string(lock).ok().as_deref(), || {
        written_recently(lock)
    })
}

/// The staleness decision itself, with the mtime lookup injected so both arms are
/// testable without backdating a real file.
fn stale_from(contents: Option<&str>, recently_written: impl FnOnce() -> bool) -> bool {
    match contents {
        Some(s) => match s.trim().parse::<u32>() {
            Ok(pid) => !pid_is_alive(pid),
            Err(_) => !recently_written(),
        },
        // Vanished between the readdir and the read: not our concern here.
        None => false,
    }
}

/// Whether `path` was modified within [`LOCK_WRITE_GRACE`]. Unknowable ⇒ `false`,
/// so an unreadable timestamp does not make a genuinely corrupt lock permanent.
fn written_recently(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < LOCK_WRITE_GRACE)
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
    fn all_taps_present_detects_a_missing_tap() {
        // Every provisioned tap present -> Ok(true).
        assert!(all_taps_present(4, |_| true).unwrap());
        // Any tap missing (here: not tap2) -> Ok(false), the restart signature.
        assert!(!all_taps_present(4, |n| n != "isopod-tap2").unwrap());
        // Zero provisioned slots is vacuously present.
        assert!(all_taps_present(0, |_| false).unwrap());
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
    fn a_lock_still_being_written_is_not_swept_out_from_under_its_claimer() {
        // The state a live claim passes through between `create_new` and the pid
        // write. A sweeper that reclaimed it would delete a claim in progress and
        // then succeed in claiming the same slot itself.
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = lock_path_in(dir.path(), 3);
        fs::write(&lock, "").expect("write empty lock");
        assert!(
            !lock_is_stale(&lock),
            "a zero-byte lock written just now is a claim in progress"
        );
        assert_eq!(sweep_stale_in(dir.path()).expect("sweep"), 0);
        assert!(lock.exists(), "the sweep must not have removed it");
    }

    #[test]
    fn staleness_distinguishes_a_claim_in_progress_from_a_corrupt_lock() {
        // Unparseable contents are ambiguous: either a claim between its
        // `create_new` and its pid write, or a lock left corrupt by something
        // else. The mtime is what separates them, and getting it backwards either
        // way is a real failure — reclaiming live slots, or leaking them forever.
        assert!(!stale_from(Some(""), || true), "empty + just written");
        assert!(stale_from(Some(""), || false), "empty + old");
        assert!(!stale_from(Some("junk"), || true), "garbled + just written");
        assert!(stale_from(Some("junk"), || false), "garbled + old");
        // A live pid is never stale whatever the mtime says.
        let live = std::process::id().to_string();
        assert!(!stale_from(Some(&live), || false));
        // A vanished lock is somebody else's business, not a reclaim.
        assert!(!stale_from(None, || false));
    }

    #[test]
    fn a_release_does_not_free_a_sibling_run_s_slot_in_the_same_process() {
        // Under the MCP server every concurrent run shares one process, so a
        // pid-based ownership check reads a sibling's lock as "mine". The claim
        // token distinguishes them: same pid, different nonce.
        let dir = tempfile::tempdir().expect("tempdir");
        let first = try_claim_slot(dir.path(), 2, false)
            .expect("claim")
            .expect("slot 2 free");
        let lock = lock_path_in(dir.path(), 2);

        // A sibling claim in this same process takes the slot over (the shape a
        // too-eager reclaim produces).
        fs::remove_file(&lock).expect("simulate a reclaim");
        let second = try_claim_slot(dir.path(), 2, false)
            .expect("claim")
            .expect("slot 2 free again");
        assert_ne!(first.token, second.token, "same pid, different claims");

        // The first run finishing must not free the slot the second is using.
        drop(first);
        assert!(lock.exists(), "the sibling's lock must survive");
        assert_eq!(
            fs::read_to_string(&lock).unwrap().trim(),
            second.token,
            "and must still be the sibling's"
        );

        // The second's own release still works.
        drop(second);
        assert!(!lock.exists());
    }

    #[test]
    fn releasing_a_slot_never_removes_a_lock_that_is_no_longer_ours() {
        // Release used to unlink unconditionally, so a slot whose lock had been
        // replaced by another run's claim had that claim deleted when the first
        // run finished — while the second run's VM and broker were still live on
        // the slot's addresses.
        let dir = tempfile::tempdir().expect("tempdir");
        let slot = try_claim_slot(dir.path(), 5, false)
            .expect("claim")
            .expect("slot 5 is free");
        let lock = lock_path_in(dir.path(), 5);
        fs::write(&lock, "999999").expect("another claimer's pid");
        drop(slot);
        assert!(
            lock.exists(),
            "the other claimer's lock must have survived our release"
        );
    }

    #[test]
    fn the_kernel_guard_refuses_anything_but_a_clear_zero() {
        // Fail-closed in every direction: only a literal "0" is enforcement in
        // place. A missing file (no such tap, or a procfs layout this version does
        // not know) reads as "cannot tell", which on this path is the same answer
        // as "no".
        assert!(require_forwarding_off("isopod-tap8", Some("0")).is_ok());
        assert!(require_forwarding_off("isopod-tap8", Some("0\n")).is_ok());
        for bad in [
            None,
            Some("1"),
            Some("1\n"),
            Some(""),
            Some("2"),
            Some("0 1"),
        ] {
            assert!(
                require_forwarding_off("isopod-tap8", bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn the_kernel_guard_refusal_names_the_slot_the_file_and_the_fix() {
        // This message is the only thing an operator sees when a container runtime
        // has stamped ip_forward across every interface, so it has to carry the
        // whole answer rather than a symptom.
        let why = require_forwarding_off("isopod-tap12", Some("1"))
            .expect_err("must refuse")
            .to_string();
        assert!(why.contains("filtered slot 12"), "{why}");
        assert!(
            why.contains("/proc/sys/net/ipv4/conf/isopod-tap12/forwarding"),
            "{why}"
        );
        assert!(why.contains("sudo isopod setup"), "{why}");
        assert!(why.contains("net.ipv4.ip_forward"), "{why}");
    }

    #[test]
    fn guest_for_gateway_agrees_with_the_per_slot_addresses() {
        // The broker's peer check is only as good as this derivation: if it ever
        // disagreed with `guest_ip`, the check would refuse the sandbox's own
        // connections (a hard failure) or, worse, accept an address that is not
        // the guest's.
        for i in [0usize, 1, 7, 42, 200, MAX_SLOT_COUNT - 1] {
            let gw: std::net::Ipv4Addr = host_ip(i).parse().expect("host ip parses");
            let guest: std::net::Ipv4Addr = guest_ip(i).parse().expect("guest ip parses");
            assert_eq!(guest_for_gateway(gw), guest, "slot {i}");
        }
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
        let m = Manifest::new(12, "eth0".into(), 1_700_000_000, false, 8);
        write_manifest_in(dir.path(), &m).unwrap();
        assert!(manifest_path_in(dir.path()).is_file());
        assert_eq!(read_manifest_in(dir.path()).unwrap(), m);
        assert_eq!(m.filtered_from(), 8);
        assert_eq!(m.filtered_count(), 4);

        // Back-compat: a manifest written before allow_lan_egress existed parses
        // with the field defaulting to false (serde(default)).
        let legacy = r#"{"version":1,"slot_count":8,"default_iface":"eth0","created_unix":1}"#;
        let parsed: Manifest = serde_json::from_str(legacy).unwrap();
        assert!(!parsed.allow_lan_egress);
    }

    #[test]
    fn pre_0_9_manifest_reads_as_no_filtered_slots_not_all_of_them() {
        // THE upgrade trap: `filtered_from` absent must mean "none filtered".
        // A bare `#[serde(default)]` usize would yield 0 here, which reads as
        // "every slot is filtered" and would break networking on every existing
        // install the moment it upgraded.
        let legacy = r#"{"version":1,"slot_count":8,"default_iface":"eth0","created_unix":1}"#;
        let m: Manifest = serde_json::from_str(legacy).unwrap();
        assert_eq!(m.filtered_from(), 8, "absent field must mean no filtering");
        assert_eq!(m.filtered_count(), 0);
        for i in 0..8 {
            assert!(!m.is_filtered(i), "slot {i} must stay public");
        }

        // An out-of-range recorded value is clamped the same safe way rather
        // than filtering slots that were never provisioned as filtered.
        let bogus = r#"{"version":1,"slot_count":8,"default_iface":"eth0",
                        "created_unix":1,"filtered_from":99}"#;
        let m: Manifest = serde_json::from_str(bogus).unwrap();
        assert_eq!(m.filtered_from(), 8);
        assert_eq!(m.filtered_count(), 0);
    }

    #[test]
    fn a_pre_0_10_manifest_reports_no_credential_endpoint() {
        // THE 0.10 upgrade trap, structurally identical to `filtered_from`: a
        // host provisioned by 0.9.x has no nftables hole for 3129, and the
        // unprivileged runtime cannot open one. Assuming the port is there would
        // boot a guest that hangs against an unreachable listener.
        let legacy = r#"{"version":1,"slot_count":12,"default_iface":"eth0",
                         "created_unix":1,"filtered_from":8}"#;
        let m: Manifest = serde_json::from_str(legacy).unwrap();
        assert_eq!(m.filtered_count(), 4, "this host does have filtered slots");
        assert_eq!(m.broker_tcp_ports(), vec![1080, 3128, 5353]);
        assert!(
            !m.supports_credential_endpoint(),
            "an unrecorded port list must never be read as 'the port is open'"
        );

        // A manifest this build writes records the full set.
        let fresh = Manifest::new(12, "eth0".into(), 1, false, 8);
        assert_eq!(fresh.broker_tcp_ports(), vec![1080, 3128, 3129, 5353]);
        assert!(fresh.supports_credential_endpoint());

        // And it survives a disk round-trip, because that is how it is read.
        let dir = tempfile::tempdir().unwrap();
        write_manifest_in(dir.path(), &fresh).unwrap();
        assert!(read_manifest_in(dir.path())
            .unwrap()
            .supports_credential_endpoint());
    }

    #[test]
    fn manifest_with_no_filtered_slots_serializes_like_pre_0_9() {
        // `--filtered-slots 0` must not even write the keys, so an install that
        // does not use the feature produces a byte-identical manifest.
        let m = Manifest::new(8, "eth0".into(), 1, false, 8);
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("filtered_from"), "{json}");
        assert!(!json.contains("broker_tcp_ports"), "{json}");
        assert_eq!(m.filtered_from(), 8);
    }

    #[test]
    fn is_filtered_covers_exactly_the_top_of_the_pool() {
        let m = Manifest::new(12, "eth0".into(), 1, false, 8);
        for i in 0..8 {
            assert!(!m.is_filtered(i), "slot {i} is public");
        }
        for i in 8..12 {
            assert!(m.is_filtered(i), "slot {i} is filtered");
        }
        // Out of range on either side is not filtered.
        assert!(!m.is_filtered(12));
    }

    #[test]
    fn public_and_filtered_pools_claim_from_disjoint_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // A 6-slot pool split 4 public / 2 filtered.
        let p0 = claim_range_in(root, 0, 4, false).unwrap();
        let p1 = claim_range_in(root, 0, 4, false).unwrap();
        assert_eq!((p0.index(), p1.index()), (0, 1));
        assert!(!p0.is_filtered());

        let f0 = claim_range_in(root, 4, 6, true).unwrap();
        assert_eq!(f0.index(), 4, "filtered claims start at filtered_from");
        assert!(f0.is_filtered());

        // Exhausting the filtered pool does not touch the free public slots.
        let f1 = claim_range_in(root, 4, 6, true).unwrap();
        assert_eq!(f1.index(), 5);
        let err = claim_range_in(root, 4, 6, true).expect_err("filtered pool exhausted");
        assert!(err.to_string().contains("filtered-egress"), "{err}");
        // Slots 2 and 3 are still claimable as public.
        assert_eq!(claim_range_in(root, 0, 4, false).unwrap().index(), 2);

        let _ = (&p0, &p1, &f0, &f1);
    }

    #[test]
    fn claim_picks_lowest_free_and_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let a = claim_range_in(root, 0, 3, false).unwrap();
        assert_eq!(a.index(), 0);
        assert_eq!(a.tap_name(), "isopod-tap0");
        assert!(lock_path_in(root, 0).exists());

        let b = claim_range_in(root, 0, 3, false).unwrap();
        assert_eq!(b.index(), 1);

        // Releasing slot 0 (drop) frees it; the next claim reuses the lowest free.
        drop(a);
        assert!(!lock_path_in(root, 0).exists(), "drop must unlink the lock");
        let c = claim_range_in(root, 0, 3, false).unwrap();
        assert_eq!(c.index(), 0, "lowest free slot reused after release");

        // Keep b/c alive to the end so their locks persist for the exhaustion check.
        let _ = (&b, &c);
    }

    #[test]
    fn claim_exhaustion_errors_when_all_held() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let _s0 = claim_range_in(root, 0, 2, false).unwrap();
        let _s1 = claim_range_in(root, 0, 2, false).unwrap();
        let err = claim_range_in(root, 0, 2, false).expect_err("all slots held must error");
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

        let s = claim_range_in(root, 0, 1, false).unwrap();
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
        let s = claim_range_in(root, 0, 4, false).unwrap();
        assert_eq!(s.index(), 0, "stale slot 0 reclaimed inline");
    }

    #[test]
    fn claim_rejects_bad_slot_count() {
        let dir = tempfile::tempdir().unwrap();
        assert!(claim_range_in(dir.path(), 0, 0, false).is_err());
        assert!(claim_range_in(dir.path(), 0, MAX_SLOT_COUNT + 1, false).is_err());
    }
}
