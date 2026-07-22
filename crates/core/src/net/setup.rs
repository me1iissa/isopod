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
    guest_ip, host_cidr, net_dir, tap_name, write_manifest_in, Manifest, DEFAULT_SLOT_COUNT,
    MANIFEST_VERSION, MAX_SLOT_COUNT, SLOT_SUPERNET,
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
}

impl Default for SetupOptions {
    fn default() -> Self {
        Self {
            slots: DEFAULT_SLOT_COUNT,
            remove: false,
            iface: None,
            allow_lan_egress: false,
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
            "File exists",
        )?;
        run_cmd("ip", &["link", "set", &tap, "up"])?;
    }

    // 2. nftables — one table, rebuilt atomically so re-runs converge.
    apply_nft(&build_nft_ruleset(&iface, slot_count, opts.allow_lan_egress))?;

    // 3. ip_forward — live now, persisted for reboots.
    set_ip_forward(true)?;
    std::fs::write(SYSCTL_CONF, sysctl_conf_body())
        .with_context(|| format!("writing {SYSCTL_CONF}"))?;

    // 4. Manifest + ownership so the unprivileged runtime can claim slots.
    //    Resolve the net dir from the INVOKING user's home, not $HOME: under
    //    sudo, $HOME is often /root, which would strand the manifest where the
    //    unprivileged runtime never looks.
    let root = invoking_user_net_dir(&user)?;
    let manifest = Manifest {
        version: MANIFEST_VERSION,
        slot_count,
        default_iface: iface.clone(),
        created_unix: now_unix(),
        allow_lan_egress: opts.allow_lan_egress,
    };
    write_manifest_in(&root, &manifest)?;
    chown_recursive(&user, &root)?;

    Ok(SetupReport {
        ok: true,
        removed: false,
        slots: slot_count,
        taps_created,
        taps_removed: Vec::new(),
        nft_table: NFT_TABLE.to_string(),
        ip_forward: read_ip_forward(),
        default_iface: iface,
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

    // nftables table (tolerate absence — a partial or repeated teardown).
    run_tolerating(
        "nft",
        &["delete", "table", "inet", "isopod"],
        "No such file",
    )?;

    // Every isopod tap in the root netns.
    let mut taps_removed = Vec::new();
    for tap in list_isopod_taps()? {
        run_tolerating("ip", &["link", "del", &tap], "Cannot find")?;
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
        taps_created: Vec::new(),
        taps_removed,
        nft_table: NFT_TABLE.to_string(),
        ip_forward: read_ip_forward(),
        default_iface,
    })
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
#[must_use]
pub fn build_nft_ruleset(wan: &str, slots: usize, allow_lan_egress: bool) -> String {
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
    format!(
        "add table inet isopod\n\
         delete table inet isopod\n\
         table inet isopod {{\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tip saddr {net} oifname \"{wan}\" masquerade\n\
         \t}}\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\tiifname \"isopod-tap*\" oifname \"isopod-tap*\" drop\n\
         {antispoof}\
         \t\tiifname \"isopod-tap*\" meta nfproto ipv6 drop\n\
         {dst_guard}\
         \t\tiifname \"{wan}\" oifname \"isopod-tap*\" ct state established,related accept\n\
         \t\tiifname \"isopod-tap*\" oifname \"{wan}\" accept\n\
         \t\tiifname \"isopod-tap*\" drop\n\
         \t}}\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority filter; policy accept;\n\
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

/// Run a command, but treat a failure whose stderr contains `tolerate` as
/// success (idempotent re-runs: "File exists", "No such file", "Cannot find").
fn run_tolerating(bin: &str, args: &[&str], tolerate: &str) -> Result<()> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("spawning `{bin} {}`", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains(tolerate) {
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
        let rs = build_nft_ruleset("eth0", 4, false);
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
        let rs = build_nft_ruleset("wlp3s0", 8, false);
        assert!(rs.contains("oifname \"wlp3s0\" masquerade"));
        assert!(!rs.contains("eth0"));
    }

    #[test]
    fn nft_ruleset_allow_lan_egress_omits_dest_drops() {
        let rs = build_nft_ruleset("eth0", 4, true);
        assert!(!rs.contains("ip daddr {"), "opt-out must omit the destination guard");
        // Anti-spoof and v6 default-deny remain even when LAN egress is allowed.
        assert!(rs.contains("iifname \"isopod-tap0\" ip saddr != 10.107.0.2 drop"));
        assert!(rs.contains("meta nfproto ipv6 drop"));
        // Egress + isolation still present.
        assert!(rs.contains("iifname \"isopod-tap*\" oifname \"eth0\" accept"));
        assert!(rs.contains("iifname \"isopod-tap*\" oifname \"isopod-tap*\" drop"));
    }

    #[test]
    fn nft_ruleset_antispoof_is_per_provisioned_slot() {
        let rs = build_nft_ruleset("eth0", 3, false);
        for i in 0..3 {
            assert!(rs.contains(&format!(
                "iifname \"isopod-tap{i}\" ip saddr != 10.107.{i}.2 drop"
            )));
        }
        // No rule for an unprovisioned slot.
        assert!(!rs.contains("isopod-tap3"));
        // Zero slots ⇒ no anti-spoof lines, but the rest of the chain is intact.
        let none = build_nft_ruleset("eth0", 0, false);
        assert!(!none.contains("ip saddr !="));
        assert!(none.contains("iifname \"isopod-tap*\" oifname \"eth0\" accept"));
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
}
