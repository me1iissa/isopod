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
//! At runtime a VM **claims** a free slot by taking a non-blocking exclusive
//! `flock` on `~/.isopod/net/slot-<i>.lock`, and holds it for the run's whole
//! lifetime; [`Slot`] drop closes the descriptor, which is what releases it.
//! The *lock* needs no sweep and no bookkeeping: the kernel drops it when the
//! holding process dies, however it died. The *slot* is a different question —
//! a supervisor killed with `SIGKILL` leaves its Firecracker running and still
//! holding the tap, so callers run [`crate::vm::registry::reap_orphans`] before
//! claiming. The manifest `~/.isopod/net/slots.json` records what `setup`
//! provisioned.
//!
//! The `*_in(root)` helpers take an explicit state root so the slot logic is
//! unit-testable against a temp directory without a real `~/.isopod`.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
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

/// A claimed network slot. Holds an exclusive `flock` on its lockfile for its
/// whole lifetime, so a slot is never leaked even if the run panics — or is
/// `kill -9`'d, since the kernel drops the lock when the descriptor closes.
#[derive(Debug)]
pub struct Slot {
    index: usize,
    /// The flocked lockfile. **This handle is the claim**: dropping it is the
    /// release, and nothing else may close or duplicate it. It is otherwise
    /// unused, which is the point — see [`claim_lock`].
    _lock: fs::File,
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

// `Slot` needs no `Drop`: dropping the `File` closes the descriptor, and closing
// the descriptor is what releases the `flock`. Writing one that unlinked the
// lockfile would reintroduce the race this design exists to remove — between the
// unlink and the next claimant's `open` a third party can create the same path,
// and then two holders have flocked two different inodes under one name. The
// lockfiles are meant to stay: they are a fixed, slot-count-sized set of empty
// files, and an empty file that persists is cheaper than a race.

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

/// Claim the lowest-numbered free **public** slot (NAT egress to the public
/// internet).
///
/// The returned [`Slot`] releases itself on drop, and the kernel releases the
/// `flock` if the process dies instead — so there is no lock to sweep.
///
/// That is not the same as the slot being usable. A supervisor killed with
/// `SIGKILL` leaves its Firecracker alive and still holding the tap, and the
/// lock says nothing about that. Callers are expected to run
/// [`crate::vm::registry::reap_orphans`] first, which is what actually frees the
/// tap; both of isopod's do.
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
/// Both pools share the lockfile namespace; they differ only in which indices
/// they scan, which is what makes the public/filtered split a pure setup-time
/// decision with no runtime coordination.
fn claim_range_in(root: &Path, lo: usize, hi: usize, filtered: bool) -> Result<Slot> {
    if hi == 0 || hi > MAX_SLOT_COUNT || lo > hi {
        bail!("invalid slot range {lo}..{hi} (expected 0..=hi, hi in 1..={MAX_SLOT_COUNT})");
    }
    // A slot whose lockfile cannot be opened is *that slot's* problem. It used
    // to be the whole pool's: one `?` here turned a single stray inode — a
    // directory left where `slot-0.lock` belongs, say — into "no network at
    // all" while eleven slots stood free. The scan carries the reasons instead
    // and only fails when there is nothing left to try, which is also the only
    // case where an operator has to act.
    let mut unusable: Vec<String> = Vec::new();
    for i in lo..hi {
        // Validate the slot's derived names/addresses up front; a misconfigured
        // slot_count must never yield an out-of-range tap name or octet.
        tap_name(i)?;
        octet(i)?;
        match try_claim_slot(root, i, filtered) {
            Ok(Some(slot)) => return Ok(slot),
            Ok(None) => {}
            Err(e) => {
                // Once per slot, on stderr, so a degraded pool is visible in the
                // run that survived it rather than only in the one that does not.
                eprintln!("isopod: skipping slot {i}: {e:#}");
                unusable.push(format!("slot {i}: {e:#}"));
            }
        }
    }
    let kind = if filtered {
        "filtered-egress"
    } else {
        "network"
    };
    let n = hi - lo;
    // "Every slot is in use" and "no slot is openable" call for different
    // actions, so they must not share a message: the first says wait, and
    // waiting for a directory to stop being a directory never ends.
    if !unusable.is_empty() && unusable.len() == n {
        bail!(
            "none of the {n} {kind} slots is usable — every one of them failed to open its \
             lockfile in {root}. Each lockfile has to be an ordinary file; remove whatever \
             is in their place and isopod will recreate them:\n  {why}",
            root = root.display(),
            why = unusable.join("\n  "),
        );
    }
    let also = if unusable.is_empty() {
        String::new()
    } else {
        format!(
            ". {u} further slot(s) could not be opened and were skipped:\n  {why}",
            u = unusable.len(),
            why = unusable.join("\n  "),
        )
    };
    bail!(
        "all {n} {kind} slots are in use; wait for a run to finish or provision \
         more with `sudo isopod setup --slots N --filtered-slots M`{also}",
    )
}

/// Try to claim slot `i`. Returns `Ok(Some)` on success and `Ok(None)` if
/// another claimant — in any process, including this one — holds it.
fn try_claim_slot(root: &Path, i: usize, filtered: bool) -> Result<Option<Slot>> {
    let lock = claim_lock(&lock_path_in(root, i))
        .map_err(|e| anyhow::Error::new(e).context(format!("claiming slot {i}")))?;
    Ok(lock.map(|_lock| Slot {
        index: i,
        _lock,
        filtered,
    }))
}

/// Take a non-blocking exclusive `flock` on `path`, creating it if absent.
/// `Ok(None)` means somebody else holds it.
///
/// **The lockfile carries no contents, deliberately.** Every previous design
/// wrote the owner's identity into it and decided occupancy by reading that
/// back — a pid, then a `<pid> <nonce>` claim token — and each time the writer
/// and the reader were free to disagree. In 0.11.0 they did: the writer had
/// gained a nonce and the parser still expected a bare pid, so every live lock
/// failed to parse, was declared stale five seconds after it was written, and
/// was deleted out from under a running VM. There is nothing to parse now. The
/// only fact about a slot is whether the kernel will grant the lock, and only
/// the kernel answers it.
///
/// `flock` is the right primitive rather than `fcntl` record locking on two
/// counts. It is owned by the **open file description**, so two claims in one
/// process — the shape every concurrent run takes under the MCP server — are
/// correctly told apart, where `fcntl`'s per-process ownership would hand the
/// second claimant a lock the first still needs. And the kernel releases it when
/// the last descriptor closes, which covers `kill -9`, a panic, and an OOM kill
/// with no bookkeeping and no liveness guess.
///
/// The descriptor is close-on-exec (Rust's default), so firecracker does not
/// inherit the claim and cannot outlive the run holding it.
///
/// # What the open flags are for
///
/// The claim used to be `O_CREAT|O_EXCL`, which incidentally refused every path
/// that was not a fresh regular file. Dropping `O_EXCL` — required, because the
/// lockfile is now durable and reclaimed rather than created once — dropped that
/// refusal with it, and three shapes stopped being handled:
///
/// | `slot-<i>.lock` is | without these flags |
/// |---|---|
/// | a FIFO | `open(O_WRONLY)` **blocks until a reader arrives** — forever, with no timeout on this path, wedging an MCP blocking-pool thread |
/// | a symlink | followed, so the `flock` lands on an inode outside the `0700` directory, where anything can hold or replace it |
/// | a directory, socket, device | `EISDIR`/`ENXIO`, which the caller used to treat as a failure of the whole pool |
///
/// `O_NOFOLLOW` refuses the symlink at the final component. `O_NONBLOCK` turns
/// the FIFO's indefinite wait into an immediate `ENXIO`, and is ignored for
/// regular files. The `fstat` then refuses everything that is not a regular
/// file, because a lock on a device or a socket is not a lock on a slot. The
/// caller treats all of these as "this slot is unusable" and keeps scanning.
fn claim_lock(path: &Path) -> std::io::Result<Option<fs::File>> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        // Only applies when this call creates the file; the enclosing directory
        // is already 0700.
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let kind = file.metadata()?.file_type();
    if !kind.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is not a regular file ({kind:?}); a slot lock has to be one, so isopod \
                 will not flock this and claim the slot is held",
                path.display()
            ),
        ));
    }
    // SAFETY: `flock` takes a raw fd and an operation, mutating no memory. `file`
    // owns the descriptor and outlives the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let e = std::io::Error::last_os_error();
    // EWOULDBLOCK (== EAGAIN) is the whole point of LOCK_NB: held, not broken.
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(e)
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
    fn a_release_does_not_free_a_sibling_run_s_slot_in_the_same_process() {
        // Under the MCP server every concurrent run shares one process, so an
        // ownership test based on anything the process knows about itself — a pid,
        // most obviously — reads a sibling's lock as "mine". `flock` is held by
        // the open file description rather than the process, so a second claim on
        // a held slot is refused even from the very thread that holds it. (This is
        // exactly where `fcntl` record locking would go wrong: its locks are
        // per-process, so the second claim would be granted.)
        let dir = tempfile::tempdir().expect("tempdir");
        let first = try_claim_slot(dir.path(), 2, false)
            .expect("claim")
            .expect("slot 2 free");

        assert!(
            try_claim_slot(dir.path(), 2, false)
                .expect("claim")
                .is_none(),
            "a sibling run in this same process must not be handed a held slot"
        );

        // And the sibling's own release does not disturb the holder: nothing in
        // the release path touches shared state at all.
        drop(first);
        assert!(
            try_claim_slot(dir.path(), 2, false)
                .expect("claim")
                .is_some(),
            "released, so claimable again"
        );
    }

    #[test]
    fn releasing_a_slot_leaves_the_lockfile_in_place() {
        // Release closes the descriptor and stops there. Unlinking would reopen
        // the race the lock exists to close: between the unlink and the next
        // claimant's open, a third party can create the same path, and two holders
        // then hold two inodes under one name.
        let dir = tempfile::tempdir().expect("tempdir");
        let slot = try_claim_slot(dir.path(), 5, false)
            .expect("claim")
            .expect("slot 5 is free");
        let lock = lock_path_in(dir.path(), 5);
        assert!(lock.exists());
        drop(slot);
        assert!(lock.exists(), "the lockfile is durable, the lock is not");
        assert_eq!(fs::read(&lock).expect("read lock").len(), 0, "no contents");
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
    fn a_lockfile_nobody_holds_does_not_cost_a_slot() {
        // Crash recovery, which is now entirely the kernel's job. What a `kill -9`
        // leaves behind is an unlocked lockfile — indistinguishable on disk from
        // one a clean release left, which is the design: the file's existence has
        // never been the claim, and now nothing about the file is. A single-slot
        // pool would be permanently exhausted if it were.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(lock_path_in(root, 0), "").unwrap();

        let s = claim_range_in(root, 0, 1, false).unwrap();
        assert_eq!(s.index(), 0);
    }

    #[test]
    fn a_lockfile_left_by_an_older_isopod_is_claimable_despite_its_contents() {
        // 0.10.0 wrote a bare pid and 0.11.0 wrote `<pid> <nonce>`. Neither is read
        // any more, and an upgrade must not strand a slot on bytes it once parsed —
        // including bytes that name a pid this host really is running.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(lock_path_in(root, 0), format!("{} 0", std::process::id())).unwrap();
        fs::write(lock_path_in(root, 1), "999999999").unwrap();

        let s = claim_range_in(root, 0, 4, false).unwrap();
        assert_eq!(s.index(), 0, "an unheld lock is free whatever it says");
    }

    /// Age `path` by `secs`, so a test can push a lockfile past any grace period
    /// the claiming code might apply without sleeping for it.
    fn backdate(path: &Path, secs: i64) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_secs();
        let t = libc::timeval {
            tv_sec: i64::try_from(now).expect("epoch seconds fit an i64") - secs,
            tv_usec: 0,
        };
        let times = [t, t];
        let c = CString::new(path.as_os_str().as_bytes()).expect("a path with no NUL");
        // SAFETY: `c` is a valid NUL-terminated path and `times` is the
        // two-element array `utimes` expects; both outlive the call.
        let rc = unsafe { libc::utimes(c.as_ptr(), times.as_ptr()) };
        assert_eq!(
            rc,
            0,
            "utimes {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }

    #[test]
    fn a_held_slot_is_still_held_after_any_amount_of_time_passes() {
        // THE 0.11.0 regression. The claim wrote `<pid> <nonce>` into the lockfile
        // while the staleness parser still read it as a bare pid, so every real
        // lock took the "does not parse" branch and was declared stale the moment
        // it aged past a five-second write grace — with its owner alive and its VM
        // on the tap. The next claim then took an occupied slot and the loser's
        // firecracker died on "Open tap device failed ... resource busy".
        //
        // Age is not evidence of anything. A slot is held for exactly as long as
        // its owner holds the lock, whether that is nine seconds or nine hours.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        let held = claim_range_in(root, 0, 4, false).expect("first claim");
        assert_eq!(held.index(), 0);
        backdate(&lock_path_in(root, 0), 3600);

        assert!(
            try_claim_slot(root, 0, false).expect("re-claim").is_none(),
            "slot 0 has a live owner and must read as busy however old its lock is"
        );
        let next = claim_range_in(root, 0, 4, false).expect("second claim");
        assert_ne!(
            next.index(),
            held.index(),
            "the second claim landed on the slot the first is still using"
        );
        let _ = (&held, &next);
    }

    #[test]
    fn staggered_claims_in_one_process_land_on_different_slots() {
        // The live reproduction, in miniature: two runs started nine seconds apart
        // under one MCP server. Both succeeded when they were milliseconds apart
        // and collided when they were not, which is why every existing test passed
        // through the regression.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        let first = claim_range_in(root, 0, 4, false).expect("run 1");
        backdate(&lock_path_in(root, first.index()), 9);
        let second = claim_range_in(root, 0, 4, false).expect("run 2");

        assert_ne!(first.index(), second.index(), "two runs, two slots");
        assert_ne!(first.tap_name(), second.tap_name());
        assert_ne!(first.guest_ip(), second.guest_ip());
    }

    /// Put something that is not a lockfile where a lockfile belongs.
    ///
    /// One helper, four shapes, so the test below cannot quietly cover only the
    /// one that reproduced. A FIFO is the shape that hangs; a symlink is the one
    /// that silently relocates the lock; a directory is the one that used to
    /// fail the whole pool; a socket is the neighbour of the FIFO that nobody
    /// thinks of.
    fn plant(path: &Path, shape: &str) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        match shape {
            "fifo" => assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo"),
            "symlink" => {
                // Pointing outside the 0700 directory, which is the harm: the
                // flock would land on an inode anyone can hold or replace.
                let target = path.with_file_name("elsewhere-outside-the-dir");
                std::os::unix::fs::symlink(&target, path).unwrap();
            }
            "directory" => fs::create_dir(path).unwrap(),
            // Dropping a `UnixListener` closes the descriptor and leaves the
            // socket inode on disk, which is exactly the shape wanted here.
            "socket" => drop(std::os::unix::net::UnixListener::bind(path).unwrap()),
            other => panic!("unknown shape {other}"),
        }
    }

    #[test]
    fn a_lockfile_that_is_not_a_file_costs_its_own_slot_and_no_other() {
        // All three regressed together when `O_CREAT|O_EXCL` became `O_CREAT`.
        // The FIFO is the one that matters most: `open(O_WRONLY)` on it blocks
        // until a reader arrives, and nothing on this path has a timeout — under
        // the MCP server that wedges a blocking-pool thread for good. So the
        // first assertion each time is that the call *returns*.
        for shape in ["fifo", "symlink", "directory", "socket"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            plant(&lock_path_in(root, 0), shape);

            let started = std::time::Instant::now();
            let slot = claim_range_in(root, 0, 4, false)
                .unwrap_or_else(|e| panic!("{shape}: the rest of the pool must still work: {e:#}"));
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "{shape}: the claim must return promptly, not block"
            );
            assert_eq!(slot.index(), 1, "{shape}: slot 0 is skipped, not fatal");

            // Nothing may have been written through the planted inode: the
            // symlink's target in particular must not have been created.
            assert!(
                !root.join("elsewhere-outside-the-dir").exists(),
                "{shape}: the lock must not have landed outside the state directory"
            );
            // And the claim reports the shape rather than swallowing it.
            let why = try_claim_slot(root, 0, false)
                .expect_err("slot 0 is unusable")
                .to_string();
            assert!(why.contains("claiming slot 0"), "{shape}: {why}");
        }
    }

    #[test]
    fn a_pool_of_nothing_but_unusable_slots_says_so() {
        // The other end of the same change: skipping a bad slot must not turn a
        // wholly broken directory into the ordinary "all slots are in use"
        // message, which would send an operator looking for a run to wait for
        // that does not exist.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for i in 0..3 {
            plant(&lock_path_in(root, i), "directory");
        }
        let err = claim_range_in(root, 0, 3, false)
            .expect_err("nothing is claimable")
            .to_string();
        assert!(err.contains("none of the 3"), "{err}");
        assert!(err.contains("slot 0:"), "names each one: {err}");
        assert!(err.contains("slot 2:"), "names each one: {err}");

        // A partly-broken pool that is otherwise full says both things.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        plant(&lock_path_in(root, 0), "fifo");
        let _held = claim_range_in(root, 0, 2, false).expect("slot 1");
        let err = claim_range_in(root, 0, 2, false)
            .expect_err("slot 1 is held and slot 0 is unusable")
            .to_string();
        assert!(err.contains("in use"), "{err}");
        assert!(err.contains("skipped"), "{err}");
        assert!(err.contains("slot 0:"), "{err}");
    }

    #[test]
    fn claim_rejects_bad_slot_count() {
        let dir = tempfile::tempdir().unwrap();
        assert!(claim_range_in(dir.path(), 0, 0, false).is_err());
        assert!(claim_range_in(dir.path(), 0, MAX_SLOT_COUNT + 1, false).is_err());
    }
}
