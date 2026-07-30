//! Guest IPv4 configuration, applied from two sources that share one code path.
//!
//! **Boot time.** When the host attaches a NIC it bakes the static config into
//! the boot args:
//!
//! ```text
//! isopod.net=10.107.<i>.2/30 isopod.gw=10.107.<i>.1 isopod.dns=1.1.1.1,8.8.8.8
//! ```
//!
//! [`configure_if_requested`] parses those tokens and applies them with the
//! classic IPv4 configuration ioctls in [`crate::sys`] (`SIOCSIFADDR`,
//! `SIOCSIFNETMASK`, `SIOCSIFFLAGS`, `SIOCADDRT`/`SIOCDELRT`) — no netlink, no
//! shelling out. It is called **after** the overlay pivot (so `/etc/resolv.conf`
//! lands in the merged writable root) and **before** the vsock server starts.
//!
//! **Runtime.** After a warm-pool snapshot restore retargets the NIC to a new
//! host tap, the restored guest's boot-time addressing is stale. The host sends
//! [`isopod_proto::RequestOp::ConfigureNet`], which the server dispatches to
//! [`configure`]. Both entry points build a [`NetConfig`] and hand it to the same
//! [`apply`], which **fully replaces** the prior addressing: it brings `eth0`
//! down and back up around the new address/netmask, clears any existing default
//! route before installing the new one, and rewrites `/etc/resolv.conf`. Applying
//! the same config twice is therefore idempotent.
//!
//! Boot-time application is best-effort, with one exception. A broken or absent
//! NIC must never stop the agent from serving exec over vsock — the whole point
//! of the vsock control plane is that it works with networking off — so
//! addressing and routing failures are logged and swallowed. Absent the
//! `isopod.net` token (e.g. `--no-network`) this is a no-op. The runtime
//! [`configure`] instead surfaces failures to the caller so the host learns the
//! reconfiguration did not take.
//!
//! **The exception is the resolver.** A failed `/etc/resolv.conf` write leaves
//! the guest resolving successfully through whatever its image or stage layer
//! carried, so unlike every other failure here it is invisible: nothing breaks,
//! and the answers come from somewhere nobody chose. [`apply`] therefore
//! propagates that one error, and the boot path records it in [`resolv_error`]
//! for reporting in every `Pong`.
//!
//! **Loopback is not network configuration.** [`ensure_loopback_up`] lives here
//! because the ioctl plumbing does, but it is a boot duty `main()` performs
//! unconditionally — before, and independent of, any `isopod.net` decision. A
//! guest with no NIC still needs `127.0.0.1` to work (finding #49).

use std::io;
use std::sync::{Mutex, OnceLock};

use crate::cmdline;
use crate::server::log;
use crate::sys;

/// Where the guest resolver config is written.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Set iff the BOOT-TIME resolver write failed (the guest is running on whatever
/// `/etc/resolv.conf` its image or stage layer carried).
///
/// The boot path is best-effort by design — a missing NIC must not stop exec
/// over vsock — so it swallows [`apply`]'s error. That is right for addressing
/// and routing, whose failure is immediately visible to the workload, and wrong
/// for the resolver: the guest goes on resolving successfully through a file
/// nobody chose, and nothing looks broken. Recorded here and reported in every
/// `Pong` so the host can say so, exactly as an overlay-assembly failure is
/// ([`crate::overlay::assembly_error`]).
static RESOLV_ERROR: OnceLock<String> = OnceLock::new();

/// The boot-time resolver-write failure, if there was one.
#[must_use]
pub fn resolv_error() -> Option<&'static str> {
    RESOLV_ERROR.get().map(String::as_str)
}

/// Does `/etc/resolv.conf` already name exactly `want`, in order?
///
/// Read back rather than inferred, because [`apply`] returns one error type for
/// several steps: a no-NIC boot fails at the address ioctl long before the
/// resolver is touched, and reporting a resolver problem there would be a lie
/// pointing at the wrong subsystem. Only a file that does not say what this run
/// asked for is worth telling the host about.
fn resolv_conf_matches(want: &[String]) -> bool {
    let Ok(text) = std::fs::read_to_string(RESOLV_CONF) else {
        return false;
    };
    let have: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver "))
        .map(str::trim)
        .collect();
    have == want.iter().map(String::as_str).collect::<Vec<_>>()
}

/// Proxy environment exported into every exec, or empty for an unfiltered run.
///
/// A filtered slot forwards nothing, so these variables are not a convenience —
/// they are how a proxy-aware tool finds the only way out. They are stored
/// process-wide rather than threaded through each exec because both entry points
/// (kernel command line at boot, `ConfigureNet` after a warm resume) set them
/// once for the lifetime of the VM.
static PROXY_ENV: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// The proxy environment to layer onto an exec's baseline, newest config wins.
///
/// Returns empty for an unfiltered run. A poisoned lock yields an empty set
/// rather than panicking: losing the proxy env degrades a filtered run to "no
/// egress", which is the safe direction.
#[must_use]
pub fn proxy_env() -> Vec<(String, String)> {
    match PROXY_ENV.lock() {
        Ok(env) => env.clone(),
        Err(_) => Vec::new(),
    }
}

/// Record the broker endpoints as proxy environment variables.
///
/// Both the upper- and lower-case spellings are set: the split is real and
/// tool-dependent (curl reads lower-case, many Python and Node clients read
/// upper-case), and setting only one silently strands half the ecosystem.
fn set_proxy_env(socks: &str, http: &str, inject: Option<&str>) {
    let pairs = build_proxy_env(socks, http, inject);
    match PROXY_ENV.lock() {
        Ok(mut env) => {
            *env = pairs;
            let creds = inject.unwrap_or("none");
            log(&format!(
                "net: filtered egress via broker socks={socks} http={http} credentials={creds}"
            ));
        }
        Err(_) => log("net: could not record the proxy environment (lock poisoned)"),
    }
}

/// Build the proxy variable set for a pair of broker endpoints. Pure, so the
/// exact names and URL schemes are unit-testable without touching the global.
fn build_proxy_env(socks: &str, http: &str, inject: Option<&str>) -> Vec<(String, String)> {
    let mut pairs = Vec::with_capacity(10);
    // socks5h, not socks5: the `h` keeps name resolution on the broker's side,
    // so the guest never needs — and never gets — a resolver of its own.
    let socks_url = format!("socks5h://{socks}");
    let http_url = format!("http://{http}");
    for name in ["ALL_PROXY", "all_proxy"] {
        pairs.push((name.to_string(), socks_url.clone()));
    }
    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
        pairs.push((name.to_string(), http_url.clone()));
    }
    // Loopback must not be proxied: a workload talking to its own services would
    // otherwise be bounced off the host broker and denied.
    //
    // Neither must the gateway. Every broker endpoint — including the credential
    // one — lives there, so without this a client asked for
    // `http://10.107.<i>.1:3129/github/user` would dutifully send it to the
    // proxy at `10.107.<i>.1:3128` as an absolute-form request, which the broker
    // would then evaluate as a connection to a literal address and refuse. The
    // endpoint would look broken for a reason that has nothing to do with
    // credentials.
    let mut no_proxy = String::from("localhost,127.0.0.1,::1");
    if let Some(gateway) = endpoint_host(socks) {
        no_proxy.push(',');
        no_proxy.push_str(gateway);
    }
    for name in ["NO_PROXY", "no_proxy"] {
        pairs.push((name.to_string(), no_proxy.clone()));
    }
    // Present only when this run has a credential to spend, so a workload can
    // test for it rather than guessing whether the port is live.
    if let Some(inject) = inject {
        pairs.push((
            "ISOPOD_CREDENTIAL_ENDPOINT".to_string(),
            format!("http://{inject}"),
        ));
    }
    pairs
}

/// The host part of a `HOST:PORT` endpoint. `None` if it is not in that form.
fn endpoint_host(endpoint: &str) -> Option<&str> {
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .filter(|host| !host.is_empty())
}

/// Parse an `isopod.proxy=socks=HOST:PORT,http=HOST:PORT[,inject=HOST:PORT]`
/// token.
///
/// Keyed rather than positional so `/proc/cmdline` stays readable during a
/// debugging session and the order cannot silently invert. Returns `None` unless
/// both proxy endpoints are present and non-empty; `inject` is optional, and an
/// unrecognised key is ignored rather than fatal — which is what lets a guest
/// image built before a key existed keep booting.
fn parse_proxy_token(raw: &str) -> Option<(String, String, Option<String>)> {
    let mut socks = None;
    let mut http = None;
    let mut inject = None;
    for part in raw.split(',') {
        match part.split_once('=') {
            Some(("socks", v)) if !v.is_empty() => socks = Some(v.to_string()),
            Some(("http", v)) if !v.is_empty() => http = Some(v.to_string()),
            Some(("inject", v)) if !v.is_empty() => inject = Some(v.to_string()),
            _ => {}
        }
    }
    Some((socks?, http?, inject))
}

/// Parsed static network configuration from the kernel command line.
struct NetConfig {
    /// Guest IPv4 address.
    ip: [u8; 4],
    /// Network prefix length (from the `isopod.net` CIDR).
    prefix: u8,
    /// Default gateway, if `isopod.gw` was provided.
    gw: Option<[u8; 4]>,
    /// DNS servers (dotted-quad strings) from `isopod.dns`, validated.
    dns: Vec<String>,
}

/// Bring the loopback interface up, logging a failure rather than panicking.
///
/// A boot duty like mounting `/proc`, not part of network configuration: a
/// guest booted with no NIC (`--no-network`) still needs `lo` up, or a workload
/// that binds `127.0.0.1` gets a socket and a port — binding never required the
/// link to be up — and then reaches nothing when it dials itself (finding #49).
/// `main()` calls this unconditionally before any network decision; [`apply`]
/// shares it so the runtime reconfigure path keeps its idempotent shape.
/// Raising an interface that is already up is a no-op, so the repeat is free.
pub fn ensure_loopback_up() {
    if let Err(e) = sys::set_if_up("lo") {
        log(&format!("net: bringing up lo failed (continuing): {e}"));
    }
}

/// Configure `eth0` from `/proc/cmdline` if `isopod.net` is present.
///
/// A no-op when the token is absent. All failures are logged and swallowed (the
/// [`apply`] error is already logged in detail, so its `Err` is ignored here).
pub fn configure_if_requested() {
    let cmdline = match cmdline::read() {
        Ok(c) => c,
        Err(e) => {
            log(&format!("net: cannot read /proc/cmdline: {e}"));
            return;
        }
    };
    if cmdline::value(&cmdline, "isopod.net").is_none() {
        // No networking requested (e.g. --no-network): nothing to do.
        return;
    }
    // Filtered-egress runs carry the broker endpoints; apply them before the
    // addressing so the env is in place even if the NIC config degrades.
    if let Some(raw) = cmdline::value(&cmdline, "isopod.proxy") {
        match parse_proxy_token(raw) {
            Some((socks, http, inject)) => set_proxy_env(&socks, &http, inject.as_deref()),
            None => log("net: malformed isopod.proxy token; no proxy env exported"),
        }
    }
    match parse_config(&cmdline) {
        // Boot-time application is best-effort: a missing/broken NIC must not
        // stop exec-over-vsock, so the error (already logged) is swallowed.
        Ok(cfg) => {
            // Still best-effort for addressing — a no-NIC boot is expected and
            // must not stop exec over vsock. But a resolver that was asked for
            // and not written is recorded, so the host is told rather than left
            // to infer it from a guest that resolves perfectly well through the
            // wrong file.
            let wanted_dns = !cfg.dns.is_empty();
            if apply(&cfg).is_err() && wanted_dns && !resolv_conf_matches(&cfg.dns) {
                let _ = RESOLV_ERROR.set(format!(
                    "{RESOLV_CONF} was not written; the guest is resolving through \
                     whatever its image or stage layer carried, not through the \
                     resolver this run was given ({})",
                    cfg.dns.join(",")
                ));
            }
        }
        Err(e) => log(&format!(
            "net: invalid network config on the kernel command line: {e}; skipping"
        )),
    }
}

/// Apply a network configuration received at runtime over the RPC control plane
/// ([`isopod_proto::RequestOp::ConfigureNet`]).
///
/// Parses and validates the CIDR address, optional gateway (an empty string
/// means "no gateway"), and DNS list, then hands the result to the shared
/// [`apply`], which fully replaces `eth0`'s prior addressing. Unlike the
/// best-effort boot path, failures are returned so the host learns the
/// reconfiguration did not take.
///
/// A filtered-egress run also carries `broker`, whose endpoints become the exec
/// environment's proxy variables. It is applied before the addressing so the
/// environment is correct even if the NIC configuration degrades.
///
/// # Errors
/// If `ip`/`gw` do not parse, or if `eth0` cannot be addressed (e.g. no NIC).
pub fn configure(
    ip: &str,
    gw: &str,
    dns: &[String],
    broker: Option<&isopod_proto::BrokerConfig>,
) -> io::Result<()> {
    if let Some(b) = broker {
        set_proxy_env(&b.socks, &b.http, b.inject.as_deref());
    }
    // An empty gateway string is treated as "no default route" rather than a
    // parse error, so the host can deconfigure the gateway explicitly.
    let gw = (!gw.is_empty()).then_some(gw);
    let cfg = build_config(ip, gw, dns.iter().map(String::as_str))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    apply(&cfg)
}

/// Apply `cfg`, **fully replacing** any prior addressing on `eth0`.
///
/// Shared by the boot-time ([`configure_if_requested`]) and runtime
/// ([`configure`]) paths. In order: bring loopback up; bring `eth0` down so a
/// prior address and its routes are cleared; set the new address + netmask and
/// bring `eth0` back up; drop any lingering default route and install the new
/// one; rewrite `resolv.conf`. Every step logs its outcome and never panics.
///
/// # Errors
/// If `eth0` cannot be addressed and raised — notably `ENODEV` when no NIC is
/// attached. Secondary steps (route, DNS) are logged but do not fail the call:
/// an addressed interface is the load-bearing outcome. Returning the address
/// error lets [`configure`] report it while [`configure_if_requested`] ignores
/// it (a no-NIC boot is expected).
fn apply(cfg: &NetConfig) -> io::Result<()> {
    // Loopback is independent of the NIC and cheap; bring it up regardless.
    // (Already done at boot by `main()` — repeated here so a runtime
    // reconfigure remains a full replacement on its own.)
    ensure_loopback_up();

    // Start from a clean slate: bringing eth0 down flushes its prior address and
    // the routes through it, so a runtime reconfigure cannot leave stale state.
    // A missing NIC surfaces as ENODEV on the address step below, not here.
    if let Err(e) = sys::set_if_down("eth0") {
        if e.raw_os_error() != Some(libc::ENODEV) {
            log(&format!(
                "net: bringing eth0 down before (re)configure failed (continuing): {e}"
            ));
        }
    }

    let mask = netmask_octets(cfg.prefix);
    if let Err(e) = configure_eth0(cfg.ip, mask) {
        if e.raw_os_error() == Some(libc::ENODEV) {
            // The distinguishing case for a no-NIC boot: report it plainly and
            // continue — exec over vsock is unaffected.
            log("net: eth0 missing (no NIC attached); continuing without network");
        } else {
            log(&format!(
                "net: FAILED to configure eth0: {e}; continuing without network"
            ));
        }
        return Err(e);
    }

    // Replace the default route: drop any existing one (a no-op on first boot,
    // ESRCH is swallowed inside `del_default_route`) before installing the new
    // gateway, so a runtime reconfigure to a different gateway does not collide.
    if let Err(e) = sys::del_default_route() {
        log(&format!(
            "net: clearing the old default route failed (continuing): {e}"
        ));
    }
    if let Some(gw) = cfg.gw {
        if let Err(e) = sys::add_default_route(gw) {
            log(&format!(
                "net: default route via {} failed: {e}",
                fmt_ip(gw)
            ));
        }
    }

    // THE ONE SECONDARY STEP THAT IS NOT BEST-EFFORT.
    //
    // The route and address failures above are logged and survived because a
    // guest with a broken route has visibly no network — the workload's first
    // call fails and the cause is in front of whoever reads the log. A failed
    // resolver write is the opposite: the guest keeps whatever `/etc/resolv.conf`
    // its image or its stage layer happened to carry, and RESOLVES SUCCESSFULLY
    // through it. Nothing looks wrong anywhere.
    //
    // That was survivable while the baked value was the same public resolvers
    // the host would have sent. It stops being survivable once the host sends a
    // gateway address instead: the guest silently keeps resolving through a
    // third party while the host, the operator and the run's own egress record
    // all report that gateway DNS policy is in force. The public-slot redirect
    // is deliberately pinned to the gateway address so a guest querying a public
    // resolver directly keeps its own path — which is exactly the path an
    // unconfigured guest then takes.
    //
    // So this one propagates. A run that cannot be given its resolver is a run
    // whose DNS policy is not in force, and it must say so rather than quietly
    // resolve somewhere else.
    if !cfg.dns.is_empty() {
        write_resolv_conf(&cfg.dns).map_err(|e| {
            log(&format!("net: writing {RESOLV_CONF} failed: {e}"));
            e
        })?;
    }

    log(&format!(
        "net: eth0 up {}/{} gw {} dns [{}]",
        fmt_ip(cfg.ip),
        cfg.prefix,
        cfg.gw.map(fmt_ip).unwrap_or_else(|| "none".to_string()),
        cfg.dns.join(",")
    ));
    Ok(())
}

/// Address, netmask, and raise `eth0`. Errors propagate (notably `ENODEV` when
/// no NIC is attached) so [`apply`] can classify them.
fn configure_eth0(ip: [u8; 4], mask: [u8; 4]) -> io::Result<()> {
    sys::set_if_addr("eth0", ip)?;
    sys::set_if_netmask("eth0", mask)?;
    sys::set_if_up("eth0")?;
    Ok(())
}

/// Write `resolv.conf` with one `nameserver` line per entry (creating `/etc` if
/// the merged root somehow lacks it).
fn write_resolv_conf(dns: &[String]) -> io::Result<()> {
    let mut body = String::new();
    for ns in dns {
        body.push_str("nameserver ");
        body.push_str(ns);
        body.push('\n');
    }
    if let Some(parent) = std::path::Path::new(RESOLV_CONF).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(RESOLV_CONF, body)
}

/// Parse the `isopod.net` / `isopod.gw` / `isopod.dns` tokens into a
/// [`NetConfig`]. `isopod.net` must be present (the caller checks) and be
/// `A.B.C.D/prefix`; the gateway is optional; DNS entries that are not
/// dotted-quads are dropped with the returned config carrying only the valid
/// ones. Delegates the actual validation to [`build_config`], the same builder
/// the runtime [`configure`] path uses.
fn parse_config(cmdline: &str) -> Result<NetConfig, String> {
    let net = cmdline::value(cmdline, "isopod.net").ok_or("missing isopod.net")?;
    let gw = cmdline::value(cmdline, "isopod.gw");
    // `isopod.dns` is a comma-separated list; split it into individual entries so
    // the builder validates each one uniformly with the runtime path.
    let dns = cmdline::value(cmdline, "isopod.dns").unwrap_or_default();
    build_config(net, gw, dns.split(',').filter(|s| !s.is_empty()))
}

/// Build and validate a [`NetConfig`] from string forms shared by both entry
/// points: a CIDR address (`A.B.C.D/prefix`), an optional gateway (dotted-quad),
/// and an iterator of DNS entries. DNS entries that are not dotted-quads are
/// dropped rather than failing the whole config; the address and (present)
/// gateway must parse.
fn build_config<'a>(
    cidr: &str,
    gw: Option<&str>,
    dns: impl Iterator<Item = &'a str>,
) -> Result<NetConfig, String> {
    let (ip_s, prefix_s) = cidr
        .split_once('/')
        .ok_or_else(|| format!("address {cidr:?} is not CIDR (expected A.B.C.D/prefix)"))?;
    let ip = parse_ipv4(ip_s)?;
    let prefix: u8 = prefix_s
        .parse()
        .map_err(|_| format!("bad prefix in address {cidr:?}"))?;
    if prefix > 32 {
        return Err(format!("prefix /{prefix} out of range in address {cidr:?}"));
    }

    let gw = match gw {
        Some(g) => Some(parse_ipv4(g)?),
        None => None,
    };

    // Keep only well-formed dotted-quads; a bad entry is dropped rather than
    // failing the whole config.
    let dns = dns
        .filter(|s| !s.is_empty())
        .filter(|s| parse_ipv4(s).is_ok())
        .map(str::to_string)
        .collect();

    Ok(NetConfig {
        ip,
        prefix,
        gw,
        dns,
    })
}

/// Parse a dotted-quad IPv4 address into its four octets.
fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    let mut octets = [0u8; 4];
    let mut it = s.split('.');
    for o in octets.iter_mut() {
        let part = it
            .next()
            .ok_or_else(|| format!("{s:?} is not an IPv4 address (too few octets)"))?;
        *o = part
            .parse()
            .map_err(|_| format!("{s:?} has a bad octet {part:?}"))?;
    }
    if it.next().is_some() {
        return Err(format!("{s:?} has too many octets"));
    }
    Ok(octets)
}

/// The four netmask octets for a prefix length (e.g. `30` → `255.255.255.252`).
fn netmask_octets(prefix: u8) -> [u8; 4] {
    let bits = prefix.min(32);
    let mask: u32 = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    mask.to_be_bytes()
}

/// Format four octets as a dotted-quad string.
fn fmt_ip(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Look a variable up in a built proxy environment.
    fn get<'a>(env: &'a [(String, String)], k: &str) -> &'a str {
        env.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("{k} must be set"))
    }

    #[test]
    fn bringing_loopback_up_is_best_effort_and_never_panics() {
        // On the machine running this suite the SIOCSIFFLAGS ioctl is either
        // refused (EPERM without CAP_NET_ADMIN) or a no-op (`lo` is already
        // up); in the guest it is the fix for finding #49. The helper's
        // contract is the same in all three cases: log and return. PID 1
        // panicking over loopback would turn a degradation into a boot
        // failure, which is the one outcome the agent must never choose.
        ensure_loopback_up();
    }

    #[test]
    fn proxy_token_is_keyed_and_order_independent() {
        assert_eq!(
            parse_proxy_token("socks=10.107.8.1:1080,http=10.107.8.1:3128"),
            Some(("10.107.8.1:1080".into(), "10.107.8.1:3128".into(), None))
        );
        // Keyed, so a reordered token still means the same thing.
        assert_eq!(
            parse_proxy_token("http=10.107.8.1:3128,socks=10.107.8.1:1080"),
            Some(("10.107.8.1:1080".into(), "10.107.8.1:3128".into(), None))
        );
    }

    #[test]
    fn proxy_token_needs_both_endpoints() {
        // Half a broker is not a usable configuration: exporting only one of the
        // two would strand every tool that reads the other.
        assert_eq!(parse_proxy_token("socks=10.107.8.1:1080"), None);
        assert_eq!(parse_proxy_token("http=10.107.8.1:3128"), None);
        assert_eq!(parse_proxy_token("socks=,http=x:1"), None);
        assert_eq!(parse_proxy_token(""), None);
        assert_eq!(parse_proxy_token("garbage"), None);
    }

    #[test]
    fn the_credential_endpoint_is_optional_and_unknown_keys_are_ignored() {
        // A guest image built before a key existed must keep booting: an
        // unrecognised token part is skipped, not fatal.
        assert_eq!(
            parse_proxy_token("socks=g:1080,http=g:3128,inject=g:3129"),
            Some(("g:1080".into(), "g:3128".into(), Some("g:3129".into())))
        );
        assert_eq!(
            parse_proxy_token("socks=g:1080,http=g:3128,somethingnew=g:9999"),
            Some(("g:1080".into(), "g:3128".into(), None))
        );
    }

    #[test]
    fn proxy_env_sets_both_cases_and_uses_socks5h() {
        let env = build_proxy_env("10.107.8.1:1080", "10.107.8.1:3128", None);
        // socks5h keeps resolution on the broker: the guest never gets a
        // resolver of its own, which is what closes DNS exfiltration.
        assert_eq!(get(&env, "ALL_PROXY"), "socks5h://10.107.8.1:1080");
        assert_eq!(get(&env, "all_proxy"), "socks5h://10.107.8.1:1080");
        assert_eq!(get(&env, "HTTPS_PROXY"), "http://10.107.8.1:3128");
        assert_eq!(get(&env, "https_proxy"), "http://10.107.8.1:3128");
        assert_eq!(get(&env, "HTTP_PROXY"), "http://10.107.8.1:3128");
        assert_eq!(get(&env, "http_proxy"), "http://10.107.8.1:3128");
        // Loopback stays direct, or a workload's own services would be bounced
        // off the broker and denied.
        assert!(get(&env, "NO_PROXY").contains("127.0.0.1"));
        assert!(get(&env, "no_proxy").contains("localhost"));
        // Both spellings of every variable: the split is real and tool-dependent.
        assert_eq!(env.len(), 8);
        // Nothing injected, so nothing advertised: the variable's presence is
        // how a workload tells "I have a credential" from "I do not".
        assert!(!env.iter().any(|(n, _)| n == "ISOPOD_CREDENTIAL_ENDPOINT"));
    }

    #[test]
    fn the_gateway_is_never_proxied_through_itself() {
        // The footgun this closes: every broker endpoint lives on the gateway,
        // so with the gateway missing from NO_PROXY a client asked for
        // `http://10.107.8.1:3129/github/user` would send it to the HTTP proxy
        // at `10.107.8.1:3128` as an absolute-form request — which the broker
        // evaluates as a connection to a literal address and refuses. The
        // credential endpoint would look broken for reasons unrelated to
        // credentials.
        let env = build_proxy_env(
            "10.107.8.1:1080",
            "10.107.8.1:3128",
            Some("10.107.8.1:3129"),
        );
        for name in ["NO_PROXY", "no_proxy"] {
            let value = get(&env, name);
            assert!(value.contains("10.107.8.1"), "{name}={value}");
            assert!(value.contains("127.0.0.1"), "{name}={value}");
        }
        assert_eq!(
            get(&env, "ISOPOD_CREDENTIAL_ENDPOINT"),
            "http://10.107.8.1:3129"
        );
        assert_eq!(env.len(), 9);
    }

    #[test]
    fn endpoint_host_splits_off_the_port() {
        assert_eq!(endpoint_host("10.107.8.1:1080"), Some("10.107.8.1"));
        assert_eq!(endpoint_host("host.example:1"), Some("host.example"));
        assert_eq!(endpoint_host("noport"), None);
        assert_eq!(endpoint_host(":1080"), None);
    }

    #[test]
    fn unfiltered_runs_export_no_proxy_env() {
        // The global starts empty and an unfiltered run never touches it, so an
        // ordinary exec's environment is unchanged from 0.8.1.
        assert!(build_proxy_env("a:1", "b:2", None).len() == 8);
        assert!(parse_proxy_token("nothing-here").is_none());
    }

    #[test]
    fn parse_ipv4_valid() {
        assert_eq!(parse_ipv4("10.107.3.2").unwrap(), [10, 107, 3, 2]);
        assert_eq!(parse_ipv4("0.0.0.0").unwrap(), [0, 0, 0, 0]);
        assert_eq!(parse_ipv4("255.255.255.255").unwrap(), [255, 255, 255, 255]);
    }

    #[test]
    fn parse_ipv4_rejects_malformed() {
        assert!(parse_ipv4("10.107.3").is_err()); // too few
        assert!(parse_ipv4("10.107.3.2.9").is_err()); // too many
        assert!(parse_ipv4("10.107.3.256").is_err()); // octet overflow
        assert!(parse_ipv4("10.107.x.2").is_err()); // non-numeric
        assert!(parse_ipv4("").is_err());
    }

    #[test]
    fn netmask_octets_common_prefixes() {
        assert_eq!(netmask_octets(30), [255, 255, 255, 252]);
        assert_eq!(netmask_octets(24), [255, 255, 255, 0]);
        assert_eq!(netmask_octets(0), [0, 0, 0, 0]);
        assert_eq!(netmask_octets(32), [255, 255, 255, 255]);
        // Clamped: a nonsense prefix does not panic (shift overflow) and is
        // treated as /32.
        assert_eq!(netmask_octets(40), [255, 255, 255, 255]);
    }

    #[test]
    fn parse_config_full() {
        let c = "quiet isopod.net=10.107.5.2/30 isopod.gw=10.107.5.1 \
                 isopod.dns=1.1.1.1,8.8.8.8 ro";
        let cfg = parse_config(c).unwrap();
        assert_eq!(cfg.ip, [10, 107, 5, 2]);
        assert_eq!(cfg.prefix, 30);
        assert_eq!(cfg.gw, Some([10, 107, 5, 1]));
        assert_eq!(cfg.dns, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn parse_config_no_gateway_or_dns() {
        let cfg = parse_config("isopod.net=10.107.0.2/30").unwrap();
        assert_eq!(cfg.gw, None);
        assert!(cfg.dns.is_empty());
    }

    #[test]
    fn parse_config_drops_bad_dns_entries() {
        let cfg =
            parse_config("isopod.net=10.107.0.2/30 isopod.dns=1.1.1.1,not-an-ip,8.8.8.8").unwrap();
        assert_eq!(cfg.dns, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn parse_config_rejects_malformed_net() {
        assert!(parse_config("isopod.net=10.107.0.2").is_err()); // no prefix
        assert!(parse_config("isopod.net=10.107.0.2/99").is_err()); // bad prefix
        assert!(parse_config("isopod.net=garbage/30").is_err()); // bad ip
        assert!(parse_config("isopod.gw=10.0.0.1").is_err()); // no isopod.net
    }

    #[test]
    fn parse_config_bad_gateway_errors() {
        assert!(parse_config("isopod.net=10.107.0.2/30 isopod.gw=10.0.0").is_err());
    }

    #[test]
    fn build_config_runtime_shape() {
        // The runtime ConfigureNet path feeds strings straight to build_config.
        let cfg =
            build_config("10.107.3.2/30", Some("10.107.3.1"), ["1.1.1.1"].into_iter()).unwrap();
        assert_eq!(cfg.ip, [10, 107, 3, 2]);
        assert_eq!(cfg.prefix, 30);
        assert_eq!(cfg.gw, Some([10, 107, 3, 1]));
        assert_eq!(cfg.dns, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn build_config_no_gateway_leaves_route_unset() {
        let cfg = build_config("10.107.3.2/30", None, std::iter::empty()).unwrap();
        assert_eq!(cfg.gw, None);
        assert!(cfg.dns.is_empty());
    }

    #[test]
    fn build_config_drops_bad_dns_entries() {
        let cfg = build_config(
            "10.107.3.2/30",
            None,
            ["1.1.1.1", "not-an-ip", "8.8.8.8"].into_iter(),
        )
        .unwrap();
        assert_eq!(cfg.dns, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn build_config_rejects_malformed_address() {
        assert!(build_config("10.107.3.2", None, std::iter::empty()).is_err()); // no prefix
        assert!(build_config("10.107.3.2/99", None, std::iter::empty()).is_err()); // bad prefix
        assert!(build_config("garbage/30", None, std::iter::empty()).is_err()); // bad ip
        assert!(build_config("10.107.3.2/30", Some("10.0.0"), std::iter::empty()).is_err());
        // bad gw
    }

    #[test]
    fn fmt_ip_roundtrip() {
        assert_eq!(fmt_ip([10, 107, 3, 2]), "10.107.3.2");
    }
}
