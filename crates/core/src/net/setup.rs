//! `isopod setup` — the one-time privileged host provisioning (the *only* step
//! that needs root).
//!
//! Everything here runs as root under `sudo`. It is idempotent: re-running
//! converges to the same state (taps that already exist are skipped, the
//! nftables table is torn down and rebuilt atomically). `--remove` reverses it.
//!
//! What it provisions, per PLAN.md "Networking":
//!
//! 1. **Taps** — for each slot `i`, a persistent `isopod-tap<i>` owned by the
//!    invoking (non-root) user, addressed `10.107.<i>.1/30`, brought up.
//! 2. **One nftables table `inet isopod`** — masquerade for `10.107.0.0/16` out
//!    the default-route interface, and a forward chain that confines guests to
//!    **public-only egress**:
//!    - **drops tap↔tap** (inter-VM isolation);
//!    - **anti-spoof** — pins each `isopod-tap<i>` to its slot's exact guest IP
//!      (`10.107.<i>.2`), so a root guest cannot forge a source address onto the
//!      LAN/WAN or blind-spoof a sibling slot;
//!    - **IPv6 default-deny** for tap-sourced forwarding (there is no v6 NAT or
//!      routable v6 address, so no v6 egress path exists to permit);
//!    - **drops RFC1918 / CGNAT / link-local destinations** so a guest reaches
//!      the public internet but not the host's private LAN or cloud metadata
//!      (opt out with `--allow-lan-egress`);
//!    - lets guests reach the WAN (and established replies back) and **drops any
//!      other tap-sourced forwarding**.
//!
//!    An input chain **drops new guest→host connections** (host services are
//!    unreachable from guests).
//! 3. **`net.ipv4.ip_forward=1`** — set live and persisted to
//!    `/etc/sysctl.d/90-isopod.conf`.
//! 4. **The manifest** `~/.isopod/net/slots.json`, `chown`ed (with the net state
//!    dir) to the invoking user so the unprivileged runtime can claim slots.
//!
//! The privileged actions are factored into small, single-purpose helpers so the
//! whole file can be reviewed line-by-line before a human runs it as root. Pure
//! string-builders ([`build_nft_ruleset`], [`sysctl_conf_body`]) are unit-tested;
//! the command runners shell out to `ip`/`nft` (there is no root-free Rust netlink
//! path, and shelling out keeps the exact commands visible for audit).

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;

use super::{
    guest_ip, host_cidr, host_ip, net_dir, tap_name, write_manifest_in, Manifest, BROKER_DNS_PORT,
    BROKER_TCP_PORTS, DEFAULT_FILTERED_SLOTS, DEFAULT_SLOT_COUNT, MAX_SLOT_COUNT, SLOT_SUPERNET,
};

/// The single nftables table isopod owns.
const NFT_TABLE: &str = "inet isopod";

/// RFC1918 + CGNAT + link-local/metadata destinations a guest must never reach
/// (public-only egress). 10.107.0.0/16 (isopod's own supernet) is inside
/// 10.0.0.0/8, so cross-slot forwards and guest→gateway forwards are covered too.
/// Per RFC1918 / RFC6598 (100.64.0.0/10 CGNAT) / RFC3927 (169.254.0.0/16).
const PRIVATE_V4_DESTS: &str =
    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10";
/// Where `ip_forward=1` is persisted across reboots.
const SYSCTL_CONF: &str = "/etc/sysctl.d/90-isopod.conf";
/// The live sysctl knob for IPv4 forwarding.
const IP_FORWARD_PROC: &str = "/proc/sys/net/ipv4/ip_forward";

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct SetupOptions {
    /// Number of slots to provision (`isopod-tap0..<slots-1>`).
    pub slots: usize,
    /// Tear everything down instead of provisioning.
    pub remove: bool,
    /// Override the auto-detected default-route egress interface.
    pub iface: Option<String>,
    /// Permit guest egress to RFC1918 / CGNAT / link-local destinations (the
    /// host's private LAN and cloud metadata). INSECURE — enables lateral
    /// movement / SSRF from untrusted guests; off by default (public-only egress).
    pub allow_lan_egress: bool,
    /// How many of the provisioned slots are filtered-egress (the highest-
    /// numbered ones). Filtered slots forward nothing and reach only the egress
    /// broker on their own gateway. `0` provisions none, reproducing the pre-0.9
    /// ruleset exactly.
    pub filtered_slots: usize,
    /// Insert isopod's accept rules into Docker's `DOCKER-USER` chain when that
    /// chain exists, so a Docker install's `FORWARD` policy DROP does not
    /// silently swallow all guest egress. On by default: without it, isopod is
    /// simply broken on any host running Docker, and broken invisibly.
    ///
    /// Set false (`--no-docker-user`) if you curate that chain yourself.
    pub manage_docker_user: bool,
}

impl Default for SetupOptions {
    fn default() -> Self {
        Self {
            slots: DEFAULT_SLOT_COUNT,
            remove: false,
            iface: None,
            allow_lan_egress: false,
            filtered_slots: DEFAULT_FILTERED_SLOTS,
            manage_docker_user: true,
        }
    }
}

/// The JSON `isopod setup` prints (one object, per the CLI convention).
#[derive(Debug, Clone, Serialize)]
pub struct SetupReport {
    /// Always `true` on success (the CLI emits `{ok:false,…}` on error).
    pub ok: bool,
    /// `true` for a `--remove` teardown, `false` for provisioning.
    pub removed: bool,
    /// Number of slots provisioned (0 on teardown).
    pub slots: usize,
    /// How many of those slots are filtered-egress (0 on teardown).
    pub filtered_slots: usize,
    /// Taps newly created this run (already-present taps are not re-listed).
    pub taps_created: Vec<String>,
    /// Taps deleted this run (`--remove` only).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub taps_removed: Vec<String>,
    /// The nftables table name managed (`inet isopod`).
    pub nft_table: String,
    /// The live value of `net.ipv4.ip_forward` after this run.
    pub ip_forward: u8,
    /// The default-route interface NAT masquerades out of.
    pub default_iface: String,
    /// What was done about another tool owning the forward hook (see
    /// [`DockerUserStatus`]). Reported rather than left to be inferred from
    /// whether the network happens to work, because the failure it addresses is
    /// invisible to every other field here.
    pub docker_user: DockerUserStatus,
}

/// Run `isopod setup` (or `--remove`). Must be invoked as root via `sudo`.
///
/// # Errors
/// If not run as root, `SUDO_USER` is unusable, the default interface cannot be
/// detected, or any `ip`/`nft`/sysctl step fails.
pub fn run(opts: SetupOptions) -> Result<SetupReport> {
    require_root()?;
    if opts.remove {
        teardown()
    } else {
        provision(opts)
    }
}

// ===========================================================================
// Provision.
// ===========================================================================

fn provision(opts: SetupOptions) -> Result<SetupReport> {
    let slot_count = opts.slots;
    if slot_count == 0 || slot_count > MAX_SLOT_COUNT {
        bail!("--slots {slot_count} out of range (expected 1..={MAX_SLOT_COUNT})");
    }
    if opts.filtered_slots > slot_count {
        bail!(
            "--filtered-slots {} exceeds --slots {slot_count}; filtered slots are \
             taken from the top of the pool, so at most {slot_count} are available",
            opts.filtered_slots
        );
    }
    let filtered_from = slot_count - opts.filtered_slots;
    let user = sudo_user()?;
    let iface = match opts.iface {
        Some(i) => {
            validate_iface(&i)?;
            i
        }
        None => detect_default_iface()?,
    };

    // 1. Taps — create (idempotent), address (tolerate re-add), bring up.
    let mut taps_created = Vec::new();
    for i in 0..slot_count {
        let tap = tap_name(i)?;
        if !link_exists(&tap)? {
            run_cmd("ip", &["tuntap", "add", &tap, "mode", "tap", "user", &user])?;
            taps_created.push(tap.clone());
        }
        // `ip addr add` errors with "File exists" if the address is already set;
        // that is the converged state, so tolerate it.
        run_tolerating(
            "ip",
            &["addr", "add", &host_cidr(i), "dev", &tap],
            &ADDR_EXISTS,
        )?;
        run_cmd("ip", &["link", "set", &tap, "up"])?;
    }

    // 2. nftables — one table, rebuilt atomically so re-runs converge.
    apply_nft(&build_nft_ruleset(
        &iface,
        slot_count,
        opts.allow_lan_egress,
        filtered_from,
    ))?;

    // 2b. Coexistence with whoever else owns the forward hook. MUST follow
    //     apply_nft: this widens Docker's ip filter table, and that widening
    //     must never exist without `inet isopod`'s drops already in force.
    let docker_user = if opts.manage_docker_user {
        ensure_docker_user_accepts()?
    } else {
        DockerUserStatus::Skipped
    };

    // 3. ip_forward — live now, persisted for reboots.
    set_ip_forward(true)?;
    std::fs::write(SYSCTL_CONF, sysctl_conf_body())
        .with_context(|| format!("writing {SYSCTL_CONF}"))?;

    // 3b. Per-tap forwarding, which MUST follow the global write: setting
    //     net.ipv4.ip_forward stamps every interface's flag, so doing this first
    //     would undo it. A filtered tap gets 0 — the kernel then refuses to
    //     forward anything that arrives on it, independently of the ruleset above,
    //     and unlike the ruleset the flag is readable without privilege, so the
    //     unprivileged runtime can confirm it before every filtered run.
    for i in 0..slot_count {
        let tap = tap_name(i)?;
        set_tap_forwarding(&tap, i < filtered_from)?;
    }

    // 4. Manifest + ownership so the unprivileged runtime can claim slots.
    //    Resolve the net dir from the INVOKING user's home, not $HOME: under
    //    sudo, $HOME is often /root, which would strand the manifest where the
    //    unprivileged runtime never looks.
    let root = invoking_user_net_dir(&user)?;
    let manifest = Manifest::new(
        slot_count,
        iface.clone(),
        now_unix(),
        opts.allow_lan_egress,
        filtered_from,
    );
    write_manifest_in(&root, &manifest)?;
    chown_recursive(&user, &root)?;

    Ok(SetupReport {
        ok: true,
        removed: false,
        slots: slot_count,
        filtered_slots: opts.filtered_slots,
        taps_created,
        taps_removed: Vec::new(),
        nft_table: NFT_TABLE.to_string(),
        ip_forward: read_ip_forward(),
        default_iface: iface,
        docker_user,
    })
}

// ===========================================================================
// Teardown (`--remove`).
// ===========================================================================

fn teardown() -> Result<SetupReport> {
    // Learn the provisioned iface (best-effort) before we delete the manifest.
    // Prefer the invoking user's net dir (see provision); fall back to $HOME's.
    let root = sudo_user()
        .and_then(|u| invoking_user_net_dir(&u))
        .or_else(|_| net_dir())?;
    let default_iface = super::read_manifest_in(&root)
        .map(|m| m.default_iface)
        .unwrap_or_default();

    // Coexistence rules FIRST, before isopod's own enforcement goes: the mirror
    // of the provision ordering, so the ip-filter widening never outlives the
    // drops that made it safe.
    let docker_user = remove_docker_user_accepts()?;

    // nftables table (tolerate absence — a partial or repeated teardown).
    run_tolerating("nft", &["delete", "table", "inet", "isopod"], &ALREADY_GONE)?;

    // Every isopod tap in the root netns.
    let mut taps_removed = Vec::new();
    for tap in list_isopod_taps()? {
        run_tolerating("ip", &["link", "del", &tap], &ALREADY_GONE)?;
        taps_removed.push(tap);
    }

    // Persistence file + manifest (leave the live ip_forward value untouched so
    // we don't disrupt other tenants such as Docker that may rely on it).
    remove_if_present(Path::new(SYSCTL_CONF))?;
    remove_if_present(&root.join("slots.json"))?;

    Ok(SetupReport {
        ok: true,
        removed: true,
        slots: 0,
        filtered_slots: 0,
        taps_created: Vec::new(),
        taps_removed,
        nft_table: NFT_TABLE.to_string(),
        ip_forward: read_ip_forward(),
        default_iface,
        docker_user,
    })
}

// ===========================================================================
// Coexistence with another tool that owns the forward hook (Docker).
// ===========================================================================
//
// Docker sets the iptables `ip filter` FORWARD chain policy to DROP and jumps to
// a DOCKER-USER chain that, by default, contains only `RETURN`. Guest→WAN
// traffic therefore falls through to that DROP, and isopod cannot see it happen:
// `setup` creates its taps, installs its table, sets ip_forward, and reports
// complete success while no packet can leave. The first symptom is a timeout
// inside a guest — usually a DNS lookup, which reads as a resolver problem and
// sends the reader looking in the wrong place entirely (dogfood finding #51).
//
// The fix is two accept rules in DOCKER-USER, which is the chain Docker
// documents for exactly this. It is safe for a reason worth stating precisely,
// because the whole change rests on it: per nft(8) "OVERALL EVALUATION OF THE
// RULESET", an accept verdict "ends the evaluation of the current base chain …
// The packet advances to the next base chain", whereas a drop verdict
// "immediately ends the evaluation of the whole ruleset". `inet isopod`'s
// forward chain is a separate base chain at the same hook, so accepting in
// Docker's table removes Docker's drop WITHOUT removing isopod's — every drop
// in `build_nft_ruleset` (tap↔tap, anti-spoof, the IPv6 deny, the RFC1918
// guard, the filtered-slot drop, and the closing `iifname "isopod-tap*" drop`
// default-deny) still applies, unchanged and still hook-terminal.
//
// That was measured, not assumed, in throwaway network namespaces: with these
// accepts live, a drop in a separate `inet` chain still blocked the connection
// and its counter showed the packets arriving. See target/lint/nfprobe-forward.sh.

/// Docker's documented extension point in the iptables `ip filter` table.
const DOCKER_USER_CHAIN: &str = "DOCKER-USER";

/// Ownership marker carried by every rule isopod manages in a chain it does not
/// own, so a human reading `iptables -S DOCKER-USER` can tell where it came from.
///
/// **Frozen.** It is part of each rule's identity for `-C` and `-D` matching, so
/// changing this string would leave rules inserted by an older binary
/// unmatchable, and therefore unremovable, on every host already provisioned.
const DOCKER_USER_COMMENT: &str = "managed-by-isopod-setup";

/// Bounded wait for the xtables lock. Docker holds it while reconfiguring, and
/// an unbounded wait would let a busy daemon wedge `isopod setup` indefinitely.
const IPT_WAIT: &str = "10";

/// The iptables interface wildcard for isopod's taps.
///
/// `+` — NOT nft's `*`. The two ruleset languages spell this differently and the
/// wrong one silently matches an interface literally named with a trailing
/// asterisk, which is to say nothing at all.
const TAP_WILDCARD: &str = "isopod-tap+";

/// Stderr fragments meaning the kernel cannot do `-m comment`.
///
/// A kernel without `xt_comment` rejects the match at insert time. Without this
/// fallback `setup` would fail outright on such a host — a host where it
/// succeeds today, albeit with broken egress — which trades a silent bug for a
/// loud regression.
const NO_COMMENT_MATCH: [&str; 3] = [
    "Extension comment revision 0 not supported",
    "No chain/target/match by that name",
    "Couldn't load match `comment'",
];

/// Stderr fragments meaning another process holds the xtables lock.
const IPT_LOCKED: [&str; 2] = ["xtables lock", "Another app is currently holding"];

/// What `setup` did about the forward-hook coexistence problem, reported so the
/// answer is visible rather than inferred from whether the network happens to work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DockerUserStatus {
    /// Rules were missing and have been inserted.
    Installed,
    /// Rules were already exactly present; nothing was changed.
    AlreadyPresent,
    /// No DOCKER-USER chain on this host, so nothing to coexist with.
    ChainAbsent,
    /// No `iptables` binary. A healthy nft-only host, not an error.
    IptablesMissing,
    /// Another process held the xtables lock for longer than isopod's bounded
    /// wait. Reported honestly rather than as "chain absent", which would read
    /// as "nothing to do" on precisely the hosts where there is most to do.
    LockBusy,
    /// `--no-docker-user`: the operator curates that chain themselves.
    Skipped,
    /// Rules were removed (`--remove`).
    Removed,
}

/// The two rule specs isopod manages in DOCKER-USER, as iptables argv fragments
/// (everything after the chain name).
///
/// **Both are required.** A single inbound accept is not enough: the reply
/// packet arrives on the WAN interface and, with FORWARD policy DROP, dies
/// there — so even a TCP handshake fails. The return rule matches on `-d` in the
/// slot supernet because conntrack un-NATs the reply at nat prerouting
/// (priority -100) before the filter forward hook (priority 0) sees it, so by
/// then the destination is already the guest's address.
///
/// Scoped to isopod's own taps and its own supernet, so the widening is no
/// broader than isopod's own rules. A forged source address matches neither and
/// falls through to Docker's drop — and would be dropped by `inet isopod`'s
/// anti-spoof rule regardless.
#[must_use]
pub fn docker_user_rule_specs(with_comment: bool) -> [Vec<String>; 2] {
    let finish = |mut v: Vec<String>| -> Vec<String> {
        if with_comment {
            v.push("-m".into());
            v.push("comment".into());
            v.push("--comment".into());
            v.push(DOCKER_USER_COMMENT.into());
        }
        v.push("-j".into());
        v.push("ACCEPT".into());
        v
    };
    [
        // Guest egress.
        finish(vec![
            "-i".into(),
            TAP_WILDCARD.into(),
            "-s".into(),
            SLOT_SUPERNET.into(),
        ]),
        // Replies to it, and nothing else.
        finish(vec![
            "-o".into(),
            TAP_WILDCARD.into(),
            "-d".into(),
            SLOT_SUPERNET.into(),
            "-m".into(),
            "conntrack".into(),
            "--ctstate".into(),
            "RELATED,ESTABLISHED".into(),
        ]),
    ]
}

/// Outcome of one `iptables` invocation: `None` on success, `Some(stderr)` on a
/// non-zero exit. A missing binary surfaces as `Err`, so callers can tell "no
/// iptables on this host" from "iptables said no".
fn iptables(args: &[String]) -> std::io::Result<Option<String>> {
    let out = Command::new("iptables").args(args).output()?;
    if out.status.success() {
        Ok(None)
    } else {
        Ok(Some(String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

fn ipt_args(rest: &[String]) -> Vec<String> {
    let mut v = vec!["-w".to_string(), IPT_WAIT.to_string()];
    v.extend_from_slice(rest);
    v
}

fn matches_any(stderr: &str, fragments: &[&str]) -> bool {
    fragments.iter().any(|f| stderr.contains(f))
}

/// Is there a DOCKER-USER chain here, and can we talk to iptables at all?
fn probe_docker_user() -> DockerUserStatus {
    let args = ipt_args(&["-S".to_string(), DOCKER_USER_CHAIN.to_string()]);
    match iptables(&args) {
        Ok(None) => DockerUserStatus::AlreadyPresent, // chain exists; caller re-checks rules
        Ok(Some(stderr)) => {
            if matches_any(&stderr, &IPT_LOCKED) {
                DockerUserStatus::LockBusy
            } else {
                // "No chain/target/match by that name", and also legacy iptables
                // on a module-less kernel ("can't initialize iptables table").
                // Both mean there is nothing here to coexist with.
                DockerUserStatus::ChainAbsent
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DockerUserStatus::IptablesMissing,
        Err(_) => DockerUserStatus::ChainAbsent,
    }
}

/// Insert the coexistence accepts, idempotently.
///
/// Called AFTER [`apply_nft`], never before: the ip-filter widening must not
/// exist for even an instant without `inet isopod`'s drops in force.
fn ensure_docker_user_accepts() -> Result<DockerUserStatus> {
    match probe_docker_user() {
        DockerUserStatus::AlreadyPresent => {}
        other => return Ok(other),
    }

    let mut installed = false;
    // Positions 1 and 2 so both precede Docker's terminal `-j RETURN`.
    for (pos, idx) in [(1usize, 0usize), (2, 1)] {
        // Present already, in either spelling? Then leave it alone. Checking the
        // comment-less variant too means a host that fell back once is not
        // re-inserted into on every subsequent run.
        let mut present = false;
        for with_comment in [true, false] {
            let spec = &docker_user_rule_specs(with_comment)[idx];
            let mut args = ipt_args(&["-C".to_string(), DOCKER_USER_CHAIN.to_string()]);
            args.extend_from_slice(spec);
            if let Ok(None) = iptables(&args) {
                present = true;
                break;
            }
        }
        if present {
            continue;
        }

        // Insert, preferring the marked variant. A kernel without xt_comment
        // rejects it; fall back rather than failing a setup that works today.
        let mut last_err = String::new();
        let mut done = false;
        for with_comment in [true, false] {
            let spec = &docker_user_rule_specs(with_comment)[idx];
            let mut args = ipt_args(&[
                "-I".to_string(),
                DOCKER_USER_CHAIN.to_string(),
                pos.to_string(),
            ]);
            args.extend_from_slice(spec);
            match iptables(&args) {
                Ok(None) => {
                    if !with_comment {
                        eprintln!(
                            "setup: this kernel cannot do `-m comment`; the DOCKER-USER rules \
                             are installed unmarked (they are still matched exactly on teardown)"
                        );
                    }
                    installed = true;
                    done = true;
                    break;
                }
                Ok(Some(stderr)) => {
                    // Docker deleting the chain between probe and insert.
                    if with_comment && matches_any(&stderr, &NO_COMMENT_MATCH) {
                        last_err = stderr;
                        continue; // retry unmarked
                    }
                    if stderr.contains("No chain/target/match by that name") {
                        return Ok(DockerUserStatus::ChainAbsent);
                    }
                    if matches_any(&stderr, &IPT_LOCKED) {
                        return Ok(DockerUserStatus::LockBusy);
                    }
                    last_err = stderr;
                }
                Err(e) => bail!("spawning iptables to insert into {DOCKER_USER_CHAIN}: {e}"),
            }
        }
        if !done {
            bail!(
                "could not insert isopod's coexistence rule into {DOCKER_USER_CHAIN}: {}",
                last_err.trim()
            );
        }
    }

    Ok(if installed {
        DockerUserStatus::Installed
    } else {
        DockerUserStatus::AlreadyPresent
    })
}

/// Remove them again.
///
/// Called FIRST in [`teardown`], the mirror of the provision ordering, so the
/// widening is gone before isopod's own enforcement is.
///
/// Both spellings are attempted, and each in a bounded loop: a host that fell
/// back to unmarked rules, or accumulated duplicates through some path outside
/// isopod, must still end up clean rather than leaving an orphan nobody can
/// name.
fn remove_docker_user_accepts() -> Result<DockerUserStatus> {
    match probe_docker_user() {
        DockerUserStatus::AlreadyPresent => {}
        other => return Ok(other),
    }
    for idx in [0usize, 1] {
        for with_comment in [true, false] {
            let spec = &docker_user_rule_specs(with_comment)[idx];
            let mut args = ipt_args(&["-D".to_string(), DOCKER_USER_CHAIN.to_string()]);
            args.extend_from_slice(spec);
            // 16 is a backstop, not an expectation: normally one delete per
            // spec succeeds and the second reports nothing left to remove.
            for _ in 0..16 {
                match iptables(&args) {
                    Ok(None) => continue,
                    _ => break,
                }
            }
        }
    }
    Ok(DockerUserStatus::Removed)
}

// ===========================================================================
// Pure builders (unit-tested).
// ===========================================================================

/// Build the complete nftables ruleset applied via `nft -f -`.
///
/// The `add table` / `delete table` / re-add idiom makes the whole apply an
/// atomic convergence: the leading `add` guarantees the `delete` succeeds even
/// on a first run, then the table is rebuilt from scratch in the same
/// transaction. All chains use `policy accept` so unrelated host/Docker traffic
/// at the same hooks is never disturbed; isolation comes from explicit `drop`s.
///
/// The forward chain confines guests to **public-only egress** (evaluated
/// top-to-bottom, first terminal verdict wins):
///
/// 1. tap↔tap drop (inter-VM isolation);
/// 2. per-tap anti-spoof — one rule per provisioned slot pins `isopod-tap<i>` to
///    its exact guest IP `10.107.<i>.2`, so a root guest cannot forge a source
///    address (a guest cannot change which tap its packets arrive on);
/// 3. IPv6 default-deny for tap-sourced forwarding (no v6 NAT / route exists);
/// 4. RFC1918 / CGNAT / link-local **destination** drop (public-only egress),
///    omitted when `allow_lan_egress` is set;
/// 5. WAN→tap established/related reply accept (unchanged);
/// 6. tap→WAN egress accept (unchanged);
/// 7. tap-sourced default-deny (unchanged).
///
/// Public destinations — including the `DEFAULT_DNS` resolvers 1.1.1.1 / 8.8.8.8
/// — are outside all five private CIDRs, so they fall through to the egress
/// accept + masquerade. A guest reaching its own gateway `10.107.<i>.1` is local
/// delivery (input hook), not forwarding, so the destination guard never touches
/// it. In an `inet` table, `ip saddr`/`ip daddr` match IPv4 only and
/// `meta nfproto ipv6` matches IPv6 only, so the v4 and v6 rules never overlap.
///
/// # Filtered slots
///
/// Slots `[filtered_from, slots)` are **filtered-egress**. For each, three
/// blocks are emitted:
///
/// - **forward**: `iifname "isopod-tap<i>" drop` — not `oifname "<wan>" drop`.
///   Dropping *all* forwarding from a filtered tap is simpler, strictly
///   stronger, and cannot be widened by a future rule that introduces another
///   egress interface. A filtered slot forwards nothing, ever. The rule sits
///   after the destination guard and before the reply accept, which matches
///   `iifname "<wan>"` (the inbound direction) and so is unaffected.
/// - **prerouting**: `udp/tcp dport 53 redirect to :<BROKER_DNS_PORT>` — the
///   guest keeps addressing its gateway on `:53` while the unprivileged broker
///   binds a port it is allowed to bind.
/// - **input**: an accept for [`BROKER_TCP_PORTS`] (plus the UDP DNS port),
///   ahead of the existing generic `ct state new drop`. Pinned on `iifname` (a
///   root guest cannot change which tap its packets arrive on), on the exact
///   gateway address, and on the exact ports — the narrowest hole that makes the
///   broker reachable. The set is rendered from the constant, and the same
///   constant is recorded in the manifest, so the runtime can tell a host
///   provisioned before a port existed from one provisioned after it.
///
/// > The input rule matches the **post-DNAT** DNS port
/// > ([`BROKER_DNS_PORT`], 5353), not 53: the input hook runs after nat
/// > prerouting, so a rule written against `dport 53` looks correct and
/// > silently blackholes every DNS query.
///
/// `filtered_from >= slots` emits none of the above, producing a ruleset
/// byte-identical to the pre-0.9 output (asserted against a checked-in fixture).
#[must_use]
pub fn build_nft_ruleset(
    wan: &str,
    slots: usize,
    allow_lan_egress: bool,
    filtered_from: usize,
) -> String {
    // Per-tap anti-spoof: pin every tap to its slot's guest IP (one rule/slot).
    // A literal `isopod-tap<i>` name (not the `isopod-tap*` wildcard) is required
    // because each rule pins a different address.
    let mut antispoof = String::new();
    for i in 0..slots {
        antispoof.push_str(&format!(
            "\t\tiifname \"isopod-tap{i}\" ip saddr != {gip} drop\n",
            gip = guest_ip(i),
        ));
    }
    // Public-only egress unless the operator explicitly opts out: drop guest
    // packets destined for the host's private LAN / cloud metadata.
    let dst_guard = if allow_lan_egress {
        String::new()
    } else {
        format!("\t\tiifname \"isopod-tap*\" ip daddr {{ {PRIVATE_V4_DESTS} }} drop\n")
    };

    // Filtered slots: forward nothing, redirect :53 to the broker's
    // unprivileged port, and open exactly the three broker ports on the gateway.
    let mut filtered_forward = String::new();
    let mut filtered_prerouting = String::new();
    let mut filtered_input = String::new();
    // Rendered from the constant, never spelled out twice: the runtime decides
    // whether a listener is reachable by comparing against the same list, and a
    // ruleset that disagreed with it would be undetectable.
    let tcp_ports = BROKER_TCP_PORTS
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    for i in filtered_from..slots {
        filtered_forward.push_str(&format!("\t\tiifname \"isopod-tap{i}\" drop\n"));
        filtered_prerouting.push_str(&format!(
            "\t\tiifname \"isopod-tap{i}\" udp dport 53 redirect to :{BROKER_DNS_PORT}\n\
             \t\tiifname \"isopod-tap{i}\" tcp dport 53 redirect to :{BROKER_DNS_PORT}\n"
        ));
        // NOTE: the input hook runs AFTER nat prerouting, so DNS is matched on
        // the post-DNAT port. Writing 53 here blackholes every query silently.
        filtered_input.push_str(&format!(
            "\t\tiifname \"isopod-tap{i}\" ip daddr {gip} tcp dport \
             {{ {tcp_ports} }} accept\n\
             \t\tiifname \"isopod-tap{i}\" ip daddr {gip} udp dport {BROKER_DNS_PORT} accept\n",
            gip = host_ip(i),
        ));
    }
    // The prerouting chain exists only when something needs it, so an install
    // with no filtered slots emits the pre-0.9 table verbatim.
    let prerouting_chain = if filtered_prerouting.is_empty() {
        String::new()
    } else {
        format!(
            "\tchain prerouting {{\n\
             \t\ttype nat hook prerouting priority dstnat; policy accept;\n\
             {filtered_prerouting}\
             \t}}\n"
        )
    };

    format!(
        "add table inet isopod\n\
         delete table inet isopod\n\
         table inet isopod {{\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tip saddr {net} oifname \"{wan}\" masquerade\n\
         \t}}\n\
         {prerouting_chain}\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\tiifname \"isopod-tap*\" oifname \"isopod-tap*\" drop\n\
         {antispoof}\
         \t\tiifname \"isopod-tap*\" meta nfproto ipv6 drop\n\
         {dst_guard}\
         {filtered_forward}\
         \t\tiifname \"{wan}\" oifname \"isopod-tap*\" ct state established,related accept\n\
         \t\tiifname \"isopod-tap*\" oifname \"{wan}\" accept\n\
         \t\tiifname \"isopod-tap*\" drop\n\
         \t}}\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority filter; policy accept;\n\
         {filtered_input}\
         \t\tiifname \"isopod-tap*\" ct state new drop\n\
         \t}}\n\
         }}\n",
        net = SLOT_SUPERNET,
        wan = wan,
        antispoof = antispoof,
        dst_guard = dst_guard,
    )
}

/// The body of `/etc/sysctl.d/90-isopod.conf`.
#[must_use]
pub fn sysctl_conf_body() -> String {
    "# Managed by `isopod setup`; removed by `isopod setup --remove`.\n\
     net.ipv4.ip_forward = 1\n"
        .to_string()
}

// ===========================================================================
// Privileged command runners + probes.
// ===========================================================================

/// Effective-uid check via `/proc/self/status` (dependency-free; the core crate
/// takes no `libc` dependency).
fn require_root() -> Result<()> {
    match effective_uid() {
        Some(0) => Ok(()),
        Some(uid) => bail!(
            "isopod setup must run as root: re-run with `sudo isopod setup` (effective uid is {uid})"
        ),
        None => bail!("could not determine the effective uid (/proc/self/status unreadable)"),
    }
}

/// Parse the effective uid (the second value of the `Uid:` line) from
/// `/proc/self/status`.
fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Fields: real  effective  saved  fs.
            return rest.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        }
    }
    None
}

/// The non-root user that invoked `sudo` — taps are `chown`ed to and owned by
/// this user so the runtime can open them without privilege.
///
/// # Errors
/// If `SUDO_USER` is unset or `root` (isopod must be able to hand tap ownership
/// to a real unprivileged user).
fn sudo_user() -> Result<String> {
    match std::env::var("SUDO_USER") {
        Ok(u) if !u.is_empty() && u != "root" => Ok(u),
        _ => bail!(
            "SUDO_USER is not set to a non-root user; run isopod setup via \
             `sudo isopod setup` (not as a direct root shell), so tap ownership \
             can be handed to your unprivileged account"
        ),
    }
}

/// The invoking user's `~/.isopod/net`, resolved from their passwd entry rather
/// than `$HOME` (which `sudo` frequently rewrites to `/root`). An explicit
/// `$ISOPOD_HOME` still wins, so a test/CI override survives `sudo -E`.
fn invoking_user_net_dir(user: &str) -> Result<std::path::PathBuf> {
    if let Some(v) = std::env::var_os("ISOPOD_HOME").filter(|v| !v.is_empty()) {
        let dir = Path::new(&v).join("net");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        return Ok(dir);
    }
    let home = user_home(user)?;
    let dir = home.join(".isopod").join("net");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Look up a user's home directory from the passwd database via `getent passwd`
/// (honours LDAP/SSSD, not just `/etc/passwd`; no `libc` dependency).
fn user_home(user: &str) -> Result<std::path::PathBuf> {
    let out = Command::new("getent")
        .args(["passwd", user])
        .output()
        .context("running `getent passwd`")?;
    if !out.status.success() {
        bail!("`getent passwd {user}` found no entry for the invoking user");
    }
    let line = String::from_utf8_lossy(&out.stdout);
    // Format: name:passwd:uid:gid:gecos:home:shell — home is field 6.
    let home = line
        .trim_end()
        .split(':')
        .nth(5)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("passwd entry for {user} has no home directory field"))?;
    Ok(std::path::PathBuf::from(home))
}

/// Detect the default-route egress interface from `ip route show default`.
fn detect_default_iface() -> Result<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("running `ip route show default`")?;
    if !out.status.success() {
        bail!(
            "`ip route show default` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // First line, token after "dev": `default via 192.0.2.1 dev eth0 ...`.
    let iface = text
        .lines()
        .next()
        .and_then(|line| {
            let mut it = line.split_whitespace();
            while let Some(tok) = it.next() {
                if tok == "dev" {
                    return it.next();
                }
            }
            None
        })
        .ok_or_else(|| {
            anyhow!(
                "no default route found (`ip route show default` was empty); \
                 pass --iface <name> to name the egress interface explicitly"
            )
        })?;
    validate_iface(iface)?;
    Ok(iface.to_string())
}

/// Guard an interface name before it is interpolated into the nft ruleset or an
/// `ip` argument: allow only the characters real Linux interface names use.
fn validate_iface(iface: &str) -> Result<()> {
    if iface.is_empty() || iface.len() >= 16 {
        bail!("interface name {iface:?} is empty or too long (max 15 bytes)");
    }
    if !iface
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
    {
        bail!("interface name {iface:?} contains characters not allowed in an interface name");
    }
    Ok(())
}

/// Whether a link named `name` exists (`ip link show dev <name>` succeeds).
fn link_exists(name: &str) -> Result<bool> {
    let status = Command::new("ip")
        .args(["link", "show", "dev", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("running `ip link show`")?;
    Ok(status.success())
}

/// List every `isopod-tap*` link present in the root netns.
fn list_isopod_taps() -> Result<Vec<String>> {
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .context("running `ip -o link show`")?;
    if !out.status.success() {
        bail!(
            "`ip -o link show` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut taps = Vec::new();
    for line in text.lines() {
        // Format: `<idx>: <name>[@peer]: <flags> ...`.
        if let Some(name) = line.split_whitespace().nth(1) {
            let name = name.trim_end_matches(':');
            let name = name.split('@').next().unwrap_or(name);
            if name.starts_with("isopod-tap") {
                taps.push(name.to_string());
            }
        }
    }
    Ok(taps)
}

/// Set the live `net.ipv4.ip_forward` knob by writing the procfs file directly
/// (no `sysctl` binary dependency; transparent for review).
fn set_ip_forward(on: bool) -> Result<()> {
    std::fs::write(IP_FORWARD_PROC, if on { "1\n" } else { "0\n" })
        .with_context(|| format!("writing {IP_FORWARD_PROC}"))
}

/// Set the per-tap IPv4 forwarding knob.
///
/// Writing `net.ipv4.ip_forward` sets *every* interface's flag, so this must run
/// after [`set_ip_forward`] or it is immediately undone.
///
/// For a filtered slot this is a second, independent enforcement of "forwards
/// nothing": with the flag clear the kernel's routing layer refuses to forward a
/// packet that arrived on the tap, whether or not the nftables ruleset is loaded.
/// It is also the only part of the filtered guarantee an *unprivileged* process
/// can verify at run time — reading the live ruleset needs `CAP_NET_ADMIN`, this
/// file is world-readable — which is what [`crate::net::require_filtered_kernel_guard`]
/// checks before a filtered run boots.
fn set_tap_forwarding(tap: &str, on: bool) -> Result<()> {
    let path = crate::net::tap_forwarding_proc(tap);
    std::fs::write(&path, if on { "1\n" } else { "0\n" }).with_context(|| format!("writing {path}"))
}

/// Read the live `net.ipv4.ip_forward` value (0 if unreadable).
fn read_ip_forward() -> u8 {
    std::fs::read_to_string(IP_FORWARD_PROC)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// `chown -R <user>: <path>` — the trailing colon sets the group to the user's
/// login group. Applied to the net state dir so the runtime owns its lockfiles
/// and manifest.
fn chown_recursive(user: &str, path: &Path) -> Result<()> {
    let owner = format!("{user}:");
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("net state dir path is not valid UTF-8"))?;
    run_cmd("chown", &["-R", &owner, path_str])
}

/// Apply an nftables ruleset via `nft -f -` (whole file = one transaction).
fn apply_nft(ruleset: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `nft -f -` (is nftables installed?)")?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("nft stdin was not piped"))?;
        stdin
            .write_all(ruleset.as_bytes())
            .context("writing the ruleset to nft")?;
        // stdin drops here, closing the pipe so nft sees EOF.
    }
    let out = child.wait_with_output().context("waiting on `nft -f -`")?;
    if !out.status.success() {
        bail!(
            "`nft -f -` failed ({}): {}\nruleset was:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
            ruleset
        );
    }
    Ok(())
}

/// Run a command, failing with its stderr on a non-zero exit.
fn run_cmd(bin: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("spawning `{bin} {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`{bin} {}` failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Stderr fragments that mean "already in the state we were converging toward".
///
/// `ip addr add` reports an address that is already present in **two** different
/// ways depending on the iproute2/kernel version — `File exists` (the raw
/// `EEXIST`) and `Error: ipv4: Address already assigned.` (the newer
/// extended-ack message). Matching only the first made `isopod setup` fail on a
/// re-run on any host with the newer message, which is to say: the documented
/// idempotency did not hold, and the re-provisioning command printed by
/// [`super::require_credential_endpoint`] would fail for exactly the people who
/// need to run it — those with an already-provisioned host.
const ADDR_EXISTS: [&str; 2] = ["File exists", "Address already assigned"];
/// The same, for deletions that have already happened.
const ALREADY_GONE: [&str; 3] = ["No such file", "Cannot find", "does not exist"];

/// Run a command, treating a failure whose stderr contains any of `tolerate` as
/// success — the idempotent-re-run path.
fn run_tolerating(bin: &str, args: &[&str], tolerate: &[&str]) -> Result<()> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("spawning `{bin} {}`", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if tolerate.iter().any(|t| stderr.contains(t)) {
        eprintln!(
            "setup: tolerating expected condition from `{bin} {}`: {}",
            args.join(" "),
            stderr.trim()
        );
        return Ok(());
    }
    bail!(
        "`{bin} {}` failed ({}): {}",
        args.join(" "),
        out.status,
        stderr.trim()
    );
}

/// Remove a file, treating "already gone" as success.
fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("removing {}", path.display()))),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_ruleset_has_masquerade_isolation_and_input_drop() {
        let rs = build_nft_ruleset("eth0", 4, false, 4);
        // Atomic rebuild idiom.
        assert!(rs.contains("add table inet isopod"));
        assert!(rs.contains("delete table inet isopod"));
        // Masquerade for the whole supernet out the WAN.
        assert!(rs.contains("ip saddr 10.107.0.0/16 oifname \"eth0\" masquerade"));
        // Inter-VM isolation: tap<->tap dropped.
        assert!(rs.contains("iifname \"isopod-tap*\" oifname \"isopod-tap*\" drop"));
        // Guest->WAN allowed and established replies back.
        assert!(rs.contains("iifname \"isopod-tap*\" oifname \"eth0\" accept"));
        assert!(rs.contains("ct state established,related accept"));
        // Default-deny for any other tap-sourced forwarding.
        assert!(rs.contains("iifname \"isopod-tap*\" drop\n"));
        // Guests cannot open new connections to the host. Match on iifname, not
        // saddr: a guest running root code can spoof its source IP, but cannot
        // change which tap its packets arrive on.
        assert!(rs.contains("iifname \"isopod-tap*\" ct state new drop"));

        // F1: public-only egress — private/CGNAT/link-local destinations dropped.
        assert!(rs.contains(
            "iifname \"isopod-tap*\" ip daddr { 10.0.0.0/8, 172.16.0.0/12, \
             192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } drop"
        ));
        // F1: IPv6 default-deny for tap-sourced forwarding (no v6 NAT exists).
        assert!(rs.contains("iifname \"isopod-tap*\" meta nfproto ipv6 drop"));
        // F1: per-tap anti-spoof pins each tap to its slot's guest IP.
        assert!(rs.contains("iifname \"isopod-tap0\" ip saddr != 10.107.0.2 drop"));
        assert!(rs.contains("iifname \"isopod-tap3\" ip saddr != 10.107.3.2 drop"));
        // Public destinations (DNS resolvers) are NOT in the drop set.
        assert!(!rs.contains("1.1.1.1"));
        assert!(!rs.contains("8.8.8.8"));
        // Ordering: the new drops precede the egress accept.
        let egress = rs.find("oifname \"eth0\" accept").unwrap();
        assert!(rs.find("ip daddr {").unwrap() < egress);
        assert!(rs.find("ip saddr != 10.107.0.2").unwrap() < egress);
        assert!(rs.find("meta nfproto ipv6 drop").unwrap() < egress);
    }

    #[test]
    fn nft_ruleset_interpolates_the_named_iface() {
        let rs = build_nft_ruleset("wlp3s0", 8, false, 8);
        assert!(rs.contains("oifname \"wlp3s0\" masquerade"));
        assert!(!rs.contains("eth0"));
    }

    #[test]
    fn nft_ruleset_allow_lan_egress_omits_dest_drops() {
        let rs = build_nft_ruleset("eth0", 4, true, 4);
        assert!(
            !rs.contains("ip daddr {"),
            "opt-out must omit the destination guard"
        );
        // Anti-spoof and v6 default-deny remain even when LAN egress is allowed.
        assert!(rs.contains("iifname \"isopod-tap0\" ip saddr != 10.107.0.2 drop"));
        assert!(rs.contains("meta nfproto ipv6 drop"));
        // Egress + isolation still present.
        assert!(rs.contains("iifname \"isopod-tap*\" oifname \"eth0\" accept"));
        assert!(rs.contains("iifname \"isopod-tap*\" oifname \"isopod-tap*\" drop"));
    }

    #[test]
    fn nft_ruleset_antispoof_is_per_provisioned_slot() {
        let rs = build_nft_ruleset("eth0", 3, false, 3);
        for i in 0..3 {
            assert!(rs.contains(&format!(
                "iifname \"isopod-tap{i}\" ip saddr != 10.107.{i}.2 drop"
            )));
        }
        // No rule for an unprovisioned slot.
        assert!(!rs.contains("isopod-tap3"));
        // Zero slots ⇒ no anti-spoof lines, but the rest of the chain is intact.
        let none = build_nft_ruleset("eth0", 0, false, 0);
        assert!(!none.contains("ip saddr !="));
        assert!(none.contains("iifname \"isopod-tap*\" oifname \"eth0\" accept"));
    }

    // --- filtered slots ---------------------------------------------------

    /// The regression gate for acceptance criterion #4: with no filtered slots,
    /// the emitted ruleset must be **byte-identical** to the 0.8.1 output. The
    /// expected text is a checked-in fixture captured from the 0.8.1 code, not
    /// a string rebuilt from the same constants this function uses — otherwise a
    /// refactor could redefine "identical" and the test would still pass.
    #[test]
    fn no_filtered_slots_is_byte_identical_to_0_8_1() {
        let fixture = include_str!("../../tests/fixtures/nft-ruleset-0.8.1-12slots.txt");
        assert_eq!(build_nft_ruleset("eth0", 12, false, 12), fixture);

        let fixture_lan = include_str!("../../tests/fixtures/nft-ruleset-0.8.1-12slots-lan.txt");
        assert_eq!(build_nft_ruleset("eth0", 12, true, 12), fixture_lan);
    }

    #[test]
    fn filtered_slots_forward_nothing() {
        let rs = build_nft_ruleset("eth0", 12, false, 8);
        // Every filtered slot drops ALL forwarding, not just tap->WAN, so a
        // future second egress interface cannot widen the hole.
        for i in 8..12 {
            assert!(
                rs.contains(&format!("\t\tiifname \"isopod-tap{i}\" drop\n")),
                "slot {i} must drop all forwarding"
            );
        }
        // Public slots keep the generic egress accept and gain no drop of their own.
        for i in 0..8 {
            assert!(!rs.contains(&format!("\t\tiifname \"isopod-tap{i}\" drop\n")));
        }
        assert!(rs.contains("iifname \"isopod-tap*\" oifname \"eth0\" accept"));

        // Ordering: the filtered drop must precede the generic egress accept,
        // or first-terminal-verdict-wins would let filtered traffic out.
        let drop_at = rs.find("iifname \"isopod-tap8\" drop").unwrap();
        let accept_at = rs
            .find("iifname \"isopod-tap*\" oifname \"eth0\" accept")
            .unwrap();
        assert!(drop_at < accept_at, "filtered drop must come first");
    }

    #[test]
    fn filtered_slots_redirect_dns_to_the_unprivileged_port() {
        let rs = build_nft_ruleset("eth0", 12, false, 8);
        assert!(rs.contains("chain prerouting {"));
        assert!(rs.contains("type nat hook prerouting priority dstnat; policy accept;"));
        for i in 8..12 {
            assert!(rs.contains(&format!(
                "iifname \"isopod-tap{i}\" udp dport 53 redirect to :5353"
            )));
            assert!(rs.contains(&format!(
                "iifname \"isopod-tap{i}\" tcp dport 53 redirect to :5353"
            )));
        }
        // Public slots keep their direct path to the DEFAULT_DNS resolvers.
        assert!(!rs.contains("iifname \"isopod-tap0\" udp dport 53"));
    }

    #[test]
    fn filtered_input_accepts_the_broker_ports_on_the_post_dnat_port() {
        let rs = build_nft_ruleset("eth0", 12, false, 8);
        for i in 8..12 {
            // Pinned on all three axes: arrival tap, exact gateway, exact ports.
            // 3129 is the credential endpoint (0.10.0); a host provisioned
            // without it is caught by `net::require_credential_endpoint`.
            assert!(rs.contains(&format!(
                "iifname \"isopod-tap{i}\" ip daddr 10.107.{i}.1 tcp dport \
                 {{ 1080, 3128, 3129, 5353 }} accept"
            )));
            assert!(rs.contains(&format!(
                "iifname \"isopod-tap{i}\" ip daddr 10.107.{i}.1 udp dport 5353 accept"
            )));
        }
        // The input hook runs AFTER nat prerouting, so DNS is matched on 5353.
        // A rule written against dport 53 here would blackhole every query while
        // looking obviously correct.
        assert!(
            !rs.contains("udp dport 53 accept"),
            "input must match the post-DNAT port, never 53"
        );
        // The generic guest->host drop stays, and stays last.
        let accept_at = rs
            .find("tcp dport { 1080, 3128, 3129, 5353 } accept")
            .unwrap();
        let drop_at = rs
            .find("iifname \"isopod-tap*\" ct state new drop")
            .unwrap();
        assert!(accept_at < drop_at, "broker accept must precede the drop");
    }

    #[test]
    fn the_ruleset_opens_exactly_the_ports_the_manifest_records() {
        // The drift this closes: a listener added to the broker but not to the
        // provisioning would bind host-side and be unreachable from the guest,
        // presenting as a hang. Both sides read BROKER_TCP_PORTS, and the
        // manifest records it, so the runtime can detect a stale host.
        let rs = build_nft_ruleset("eth0", 12, false, 8);
        let manifest = Manifest::new(12, "eth0".into(), 1, false, 8);
        let rendered = manifest
            .broker_tcp_ports()
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            rs.contains(&format!("tcp dport {{ {rendered} }} accept")),
            "the ruleset must open exactly the ports the manifest claims"
        );
        assert!(manifest.supports_credential_endpoint());
    }

    #[test]
    fn public_slots_cannot_reach_a_filtered_slots_broker() {
        let rs = build_nft_ruleset("eth0", 12, false, 8);
        // Every broker accept names one tap and one gateway address, so there is
        // no wildcard rule a public (or sibling filtered) slot could ride in on.
        assert!(!rs.contains("iifname \"isopod-tap*\" ip daddr 10.107"));
        for i in 8..12 {
            let rule = format!("iifname \"isopod-tap{i}\" ip daddr 10.107.{i}.1");
            assert_eq!(
                rs.matches(&rule).count(),
                2,
                "slot {i} gets exactly one tcp + one udp accept"
            );
        }
    }

    #[test]
    fn every_slot_filtered_still_produces_a_coherent_table() {
        // The `--filtered-slots N == --slots N` edge: no public slots at all.
        let rs = build_nft_ruleset("eth0", 2, false, 0);
        assert!(rs.contains("iifname \"isopod-tap0\" drop"));
        assert!(rs.contains("iifname \"isopod-tap1\" drop"));
        assert!(rs.contains("chain prerouting {"));
        // The anti-spoof and isolation rules are unaffected by the mode.
        assert!(rs.contains("iifname \"isopod-tap0\" ip saddr != 10.107.0.2 drop"));
        assert!(rs.contains("iifname \"isopod-tap*\" oifname \"isopod-tap*\" drop"));
    }

    #[test]
    fn both_spellings_of_an_already_assigned_address_are_tolerated() {
        // Found by re-provisioning a real host: `ip addr add` reports an address
        // that is already present as either the raw EEXIST ("File exists") or
        // the newer extended-ack message. Matching only the first meant
        // `isopod setup` failed on a re-run — so the documented idempotency did
        // not hold, and the re-provisioning command that
        // `net::require_credential_endpoint` prints would fail for precisely the
        // people it is printed to.
        let observed = "Error: ipv4: Address already assigned.";
        assert!(
            ADDR_EXISTS.iter().any(|t| observed.contains(t)),
            "iproute2's extended-ack message must be tolerated"
        );
        assert!(ADDR_EXISTS.iter().any(|t| "File exists".contains(t)));
        // A genuine failure must still be a failure.
        for real in [
            "Error: Nexthop has invalid gateway.",
            "RTNETLINK answers: Operation not permitted",
        ] {
            assert!(
                !ADDR_EXISTS.iter().any(|t| real.contains(t)),
                "{real:?} must not be swallowed"
            );
        }
    }

    #[test]
    fn sysctl_body_enables_forwarding() {
        assert!(sysctl_conf_body().contains("net.ipv4.ip_forward = 1"));
    }

    #[test]
    fn validate_iface_accepts_real_names_rejects_junk() {
        for ok in ["eth0", "wlp3s0", "en-p0", "br_lan", "eth0.100", "veth@if2"] {
            assert!(validate_iface(ok).is_ok(), "{ok} should be valid");
        }
        assert!(validate_iface("").is_err());
        assert!(validate_iface("eth0; rm -rf /").is_err());
        assert!(validate_iface("iface with spaces").is_err());
        assert!(validate_iface("waytoolonginterfacename").is_err());
    }

    #[test]
    fn effective_uid_parses_self_status() {
        // Whatever it is, it must parse to *some* uid on Linux.
        let uid = effective_uid();
        assert!(uid.is_some(), "effective uid should be readable on Linux");
    }

    // -----------------------------------------------------------------------
    // Docker forward-hook coexistence (dogfood finding #51).
    // -----------------------------------------------------------------------

    /// The exact argv is FROZEN. It is each rule's identity for `iptables -C`
    /// and `-D`, so a change here makes rules an older binary inserted
    /// unmatchable — and therefore unremovable — on every host already
    /// provisioned. A failure of this test is not a test to update; it is a
    /// migration to think through.
    #[test]
    fn docker_user_rule_specs_are_frozen() {
        let [egress, reply] = docker_user_rule_specs(true);
        assert_eq!(
            egress,
            vec![
                "-i",
                "isopod-tap+",
                "-s",
                "10.107.0.0/16",
                "-m",
                "comment",
                "--comment",
                "managed-by-isopod-setup",
                "-j",
                "ACCEPT",
            ]
        );
        assert_eq!(
            reply,
            vec![
                "-o",
                "isopod-tap+",
                "-d",
                "10.107.0.0/16",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                "managed-by-isopod-setup",
                "-j",
                "ACCEPT",
            ]
        );
    }

    /// The unmarked fallback for kernels without `xt_comment` must differ from
    /// the marked spec ONLY by the comment match. If it diverged in any other
    /// way, a host that fell back would be re-inserted into on every run,
    /// because neither `-C` probe would match what is actually there.
    #[test]
    fn the_unmarked_fallback_differs_only_by_the_comment() {
        for idx in [0usize, 1] {
            let marked = docker_user_rule_specs(true)[idx].clone();
            let plain = docker_user_rule_specs(false)[idx].clone();
            let stripped: Vec<String> = {
                let mut v = marked.clone();
                let at = v
                    .windows(2)
                    .position(|w| w == ["-m", "comment"])
                    .expect("the marked spec carries `-m comment`");
                v.drain(at..at + 4); // -m comment --comment <value>
                v
            };
            assert_eq!(stripped, plain, "spec {idx} diverges beyond the comment");
        }
    }

    /// Both rules are required. A single inbound accept leaves the reply to die
    /// on Docker's policy DROP, so even a TCP handshake fails — measured, not
    /// assumed. Anything that reduces this to one rule has broken the fix.
    #[test]
    fn both_directions_are_covered_and_scoped_to_isopod() {
        let specs = docker_user_rule_specs(true);
        assert_eq!(specs.len(), 2, "the reply leg is not optional");

        let egress = specs[0].join(" ");
        let reply = specs[1].join(" ");
        assert!(
            egress.contains("-i isopod-tap+"),
            "egress matches on input iface"
        );
        assert!(
            reply.contains("-o isopod-tap+"),
            "reply matches on output iface"
        );

        // Scoped to isopod's own supernet in BOTH directions: the widening must
        // be no broader than isopod's own rules. The reply matches on -d
        // because conntrack un-NATs before the filter forward hook.
        for spec in &specs {
            let joined = spec.join(" ");
            assert!(
                joined.contains(SLOT_SUPERNET),
                "unscoped rule would widen beyond isopod's own addressing: {joined}"
            );
        }

        // Accept-only. The safety argument depends on `inet isopod` remaining
        // the sole policy layer; a DROP or REJECT here would put policy in a
        // chain isopod does not own and cannot reason about.
        for spec in &specs {
            assert_eq!(
                spec[spec.len() - 2..],
                ["-j", "ACCEPT"],
                "rules in a foreign chain must be accept-only"
            );
            let joined = spec.join(" ");
            assert!(!joined.contains("DROP") && !joined.contains("REJECT"));
        }

        assert!(
            reply.contains("--ctstate RELATED,ESTABLISHED"),
            "the reply rule must be conntrack-scoped, not a blanket accept inbound to the taps"
        );
    }

    /// nft spells the interface wildcard `*`; iptables spells it `+`. Using the
    /// nft form here would match an interface literally named with a trailing
    /// asterisk, which is to say nothing, and the rule would sit in the chain
    /// looking correct while doing nothing at all.
    #[test]
    fn the_wildcard_is_the_iptables_one_not_the_nft_one() {
        assert_eq!(TAP_WILDCARD, "isopod-tap+");
        for spec in docker_user_rule_specs(true) {
            let joined = spec.join(" ");
            assert!(
                !joined.contains("isopod-tap*"),
                "nft-style wildcard leaked into an iptables rule: {joined}"
            );
        }
    }

    /// The status is serialized into `isopod setup`'s JSON, so these strings are
    /// a public interface that CI and users read.
    #[test]
    fn docker_user_status_serializes_kebab_case() {
        let cases = [
            (DockerUserStatus::Installed, "\"installed\""),
            (DockerUserStatus::AlreadyPresent, "\"already-present\""),
            (DockerUserStatus::ChainAbsent, "\"chain-absent\""),
            (DockerUserStatus::IptablesMissing, "\"iptables-missing\""),
            (DockerUserStatus::LockBusy, "\"lock-busy\""),
            (DockerUserStatus::Skipped, "\"skipped\""),
            (DockerUserStatus::Removed, "\"removed\""),
        ];
        for (v, want) in cases {
            assert_eq!(serde_json::to_string(&v).unwrap(), want);
        }
    }

    /// The coexistence rules only remove ANOTHER tool's drop. isopod's own
    /// default-deny must still be the last word for tap-sourced forwarding, or
    /// the accepts would be widening rather than unblocking.
    #[test]
    fn isopod_keeps_its_own_default_deny_for_tap_traffic() {
        let rs = build_nft_ruleset("eth0", 2, false, 2);
        let forward = rs
            .split("chain forward {")
            .nth(1)
            .and_then(|s| s.split("chain input {").next())
            .expect("a forward chain");
        let last_drop = forward
            .lines()
            .rfind(|l| l.contains("drop"))
            .expect("the forward chain drops something");
        assert!(
            last_drop.contains("iifname \"isopod-tap*\" drop"),
            "the closing default-deny is what makes a DOCKER-USER accept safe; \
             found instead: {last_drop}"
        );
    }
}
