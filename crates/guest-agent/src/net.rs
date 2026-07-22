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
//! Boot-time application is best-effort: every failure is logged to serial and
//! swallowed. A broken or absent NIC must never stop the agent from serving exec
//! over vsock — the whole point of the vsock control plane is that it works with
//! networking off. Absent the `isopod.net` token (e.g. `--no-network`) this is a
//! no-op. The runtime [`configure`] instead surfaces failures to the caller so
//! the host learns the reconfiguration did not take.

use std::io;

use crate::cmdline;
use crate::server::log;
use crate::sys;

/// Where the guest resolver config is written.
const RESOLV_CONF: &str = "/etc/resolv.conf";

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
    match parse_config(&cmdline) {
        // Boot-time application is best-effort: a missing/broken NIC must not
        // stop exec-over-vsock, so the error (already logged) is swallowed.
        Ok(cfg) => {
            let _ = apply(&cfg);
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
/// # Errors
/// If `ip`/`gw` do not parse, or if `eth0` cannot be addressed (e.g. no NIC).
pub fn configure(ip: &str, gw: &str, dns: &[String]) -> io::Result<()> {
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
    if let Err(e) = sys::set_if_up("lo") {
        log(&format!("net: bringing up lo failed (continuing): {e}"));
    }

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

    if !cfg.dns.is_empty() {
        if let Err(e) = write_resolv_conf(&cfg.dns) {
            log(&format!("net: writing {RESOLV_CONF} failed: {e}"));
        }
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
