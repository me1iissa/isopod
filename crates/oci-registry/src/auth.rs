//! The bearer-token dance, and the rule about where a credential may travel.
//!
//! A registry answers an unauthenticated request with `401` and a
//! `WWW-Authenticate` header naming a token service. The client fetches a token
//! from that service and retries. The header is **the registry's** text, so the
//! realm in it is an attacker-chosen URL in exactly the case that matters — a
//! hostile or compromised registry — and a client that posts its credentials to
//! whatever realm it is handed has been talked into leaking them.
//!
//! Four rules fall out, and all four are enforced here rather than at the
//! call site:
//!
//! 1. A token realm must survive [`destination_is_allowed`] — the *same*
//!    predicate a redirect target must survive. It is not enough for a realm to
//!    be https: `https://169.254.169.254/` is https, and it is the cloud
//!    metadata endpoint of the machine doing the importing.
//! 2. `Authorization` never crosses an origin, and once it has stopped being
//!    carried it does not start again. Blob downloads redirect to CDNs as a
//!    matter of course, so this is the ordinary path, not an edge case.
//! 3. The loopback exemption belongs to the **operator**, not to the registry.
//!    It applies only when the operator themselves named a loopback registry.
//! 4. The floor judges the **address**, not the string. A URL check alone reads
//!    `https://blob.evil.example/` as an ordinary public host and dials
//!    whatever it resolves to, so a registry that controls a DNS name controls
//!    where the request lands. [`FlooredResolver`] resolves every name this
//!    client dials, applies [`address_is_allowed`] to *every* address the name
//!    answers with, and hands the connector the addresses it checked.
//!
//! Rules 1 and 3 exist because the first version of this module had one
//! destination floor for redirects and a second, laxer one for realms — so the
//! path that carries a credential was the one with the weaker check. Rule 4
//! exists because the floor used to stop at the URL, which made it a floor on
//! the spellings an attacker does not have to use.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use url::Url;

/// How long this client will wait for one name to resolve.
///
/// `getaddrinfo` has no cancellation: it runs on a blocking thread that keeps
/// going after the future holding it is dropped. Left unbounded, a name whose
/// authoritative nameserver accepts the query and never answers stalls for the
/// whole glibc resolver budget — several attempts against several nameservers —
/// and the operator sees an import that has simply stopped.
///
/// Deliberately more generous than the guest egress broker's five seconds: a
/// resolve that gives up there costs the guest one connection, and one that
/// gives up here fails the operator's whole import.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed `WWW-Authenticate: Bearer …` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Where to ask for a token.
    pub realm: Url,
    /// The `service` parameter, passed through verbatim.
    pub service: Option<String>,
    /// The `scope` parameter, passed through verbatim.
    pub scope: Option<String>,
}

/// Why a challenge was not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeError(String);

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ChallengeError {}

impl Challenge {
    /// Parse a `WWW-Authenticate` header value.
    ///
    /// `allow_local` is the operator's intent, not the registry's: true only
    /// when the operator themselves named a loopback registry. Without it, a
    /// *remote* registry could answer `401` with
    /// `realm="http://localhost:5000/token"` and have this client post the
    /// operator's credential, in the clear, to whatever is listening on their
    /// own machine — and hand back the response. The loopback exemption was
    /// ungated here while the identical exemption on the redirect path was
    /// gated, which is the same guard written twice and weaker once.
    ///
    /// # Errors
    /// [`ChallengeError`] if it is not a Bearer challenge, names no realm, or
    /// names one this client will not post a credential to.
    pub fn parse(header: &str, allow_local: bool) -> Result<Self, ChallengeError> {
        let rest = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or_else(|| {
                ChallengeError(format!(
                    "the registry answered 401 with {header:?}, which is not a \
                     Bearer challenge. isopod does not implement the other \
                     schemes."
                ))
            })?;

        let mut realm = None;
        let mut service = None;
        let mut scope = None;
        for (k, v) in params(rest) {
            match k.as_str() {
                "realm" => realm = Some(v),
                "service" => service = Some(v),
                "scope" => scope = Some(v),
                _ => {}
            }
        }
        let realm = realm.ok_or_else(|| {
            ChallengeError(format!(
                "the registry's challenge {header:?} names no realm, so there is \
                 nowhere to ask for a token"
            ))
        })?;
        let realm = Url::parse(&realm).map_err(|e| {
            ChallengeError(format!("the challenge's realm {realm:?} is not a URL: {e}"))
        })?;
        // The realm is the registry's text, and a credential is about to be
        // sent to it. It gets the same destination floor a redirect target
        // gets — the identical predicate, not a second, weaker restatement of
        // it — so `http://`, the operator's loopback, their private network and
        // the cloud metadata endpoint are all refused rather than dialled.
        if !destination_is_allowed(&realm, allow_local) {
            return Err(ChallengeError(format!(
                "the registry's token realm is {realm}, which is not a public \
                 https address. A token request carries a credential, and \
                 isopod will not send one to a host the registry chose out of \
                 the operator's own network — nor in the clear to anywhere."
            )));
        }
        Ok(Self {
            realm,
            service,
            scope,
        })
    }

    /// The URL to fetch a token from, with the challenge's parameters applied.
    #[must_use]
    pub fn token_url(&self) -> Url {
        let mut url = self.realm.clone();
        {
            let mut q = url.query_pairs_mut();
            if let Some(s) = &self.service {
                q.append_pair("service", s);
            }
            if let Some(s) = &self.scope {
                q.append_pair("scope", s);
            }
        }
        url
    }
}

/// Split a challenge's `k="v"` parameter list.
///
/// Hand-rolled because the values are quoted strings that may contain commas —
/// `scope="repository:library/alpine:pull,push"` is ordinary — so splitting on
/// commas first loses half the scope, and a client that then asks for the wrong
/// scope gets a token that does not work for a reason nothing explains.
fn params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        // Key.
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            chars.next();
            if c == '=' {
                break;
            }
            if c != ',' && !c.is_whitespace() {
                key.push(c);
            }
        }
        if key.is_empty() {
            break;
        }
        // Value: quoted, or bare up to the next comma.
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                value.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }
        out.push((key.to_ascii_lowercase(), value));
        // Consume the separator.
        while matches!(chars.peek(), Some(c) if *c == ',' || c.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
    }
    out
}

/// May a request carrying `Authorization` for `from` be re-sent to `to`?
///
/// Only when the origin is unchanged. A registry redirects blob downloads to
/// object storage constantly, and forwarding the bearer token along with the
/// redirect hands a registry credential to whatever host the registry named.
/// `reqwest` has its own view on this; the policy is stated here so it is a
/// thing this crate decided and a thing a test can exercise, rather than a
/// default that could change underneath it.
#[must_use]
pub fn may_carry_credential(from: &Url, to: &Url) -> bool {
    from.scheme() == to.scheme()
        && from.host_str() == to.host_str()
        && from.port_or_known_default() == to.port_or_known_default()
}

/// Is this URL pointed at the loopback interface?
fn is_loopback_url(u: &Url) -> bool {
    matches!(
        u.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    )
}

/// Would dialling `to` reach somewhere this client has no business reaching?
///
/// Two things take their address from a stranger: the `Location` of a redirect,
/// and the `realm` of a `WWW-Authenticate` challenge. Both are the registry's
/// text, so both are requests the image's publisher can aim — at a cloud
/// metadata endpoint, at a service on the operator's loopback, at something
/// inside their network. Digest verification means a redirect cannot inject
/// *content*, but the request still happens, and the request is what an SSRF
/// is. The realm is worse than the redirect, because a credential goes with it.
///
/// One predicate for both, because the two used to disagree: the redirect path
/// gated its loopback exemption on `allow_local` and the realm path did not,
/// so a *remote* registry could point a credentialed request at the operator's
/// own machine. Splitting a floor in two is how one half comes to be weaker.
///
/// A registry the operator deliberately named as loopback is exempt — that is
/// the local-registry workflow, and the operator typed it.
///
/// A **name** passes here on the strength of being a name; where it points is
/// [`FlooredResolver`]'s question, and it is asked at the moment the connector
/// asks for an address.
#[must_use]
pub fn destination_is_allowed(to: &Url, allow_local: bool) -> bool {
    if to.scheme() != "https" && !(allow_local && is_loopback_url(to)) {
        return false;
    }
    let Some(host) = to.host() else {
        return false;
    };
    match host {
        url::Host::Domain(d) => allow_local || !(d == "localhost" || d.ends_with(".localhost")),
        url::Host::Ipv4(ip) => address_is_allowed(IpAddr::V4(ip), allow_local),
        url::Host::Ipv6(ip) => address_is_allowed(IpAddr::V6(ip), allow_local),
    }
}

/// May this client open a connection to `ip`?
///
/// The address half of [`destination_is_allowed`], and the whole of what
/// [`FlooredResolver`] enforces — one set of rules, so a destination cannot be
/// judged differently for having been written as a literal rather than reached
/// through a name. It is the guest egress broker's rule set (see
/// `isopod_core::net::egress::is_dialable`) with the private ranges refused
/// unconditionally, because an image import has no `--allow-lan-egress` to opt
/// into them with.
#[must_use]
pub fn address_is_allowed(ip: IpAddr, allow_local: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_allowed(v4, allow_local),
        IpAddr::V6(v6) => {
            // An IPv6 address may *be* an IPv4 address wearing a different
            // spelling, and the v4 rules below are the ones with the addresses
            // that matter in them. Judging the spelling rather than the address
            // let `[::ffff:169.254.169.254]` — the cloud metadata endpoint —
            // straight through a floor written to block `169.254.169.254`.
            if let Some(v4) = embedded_ipv4(v6) {
                return ipv4_is_allowed(v4, allow_local);
            }
            if allow_local && v6.is_loopback() {
                return true;
            }
            // `is_unique_local`/`is_unicast_link_local` are not stable, so the
            // prefixes are matched directly: fc00::/7 unique-local, fe80::/10
            // link-local, and fec0::/10 site-local — the last deprecated but
            // still routed on plenty of networks, and refused by the broker, so
            // refusing it here too keeps the two floors from disagreeing.
            let seg = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg & 0xfe00) == 0xfc00
                || (seg & 0xffc0) == 0xfe80
                || (seg & 0xffc0) == 0xfec0)
        }
    }
}

/// The IPv4 address an IPv6 literal actually names, when it names one.
///
/// Three spellings reach an IPv4 destination: the IPv4-mapped range
/// (`::ffff:a.b.c.d`), the deprecated IPv4-compatible range (`::a.b.c.d`), and
/// the NAT64 well-known prefix (`64:ff9b::a.b.c.d`, RFC 6052), which a host
/// with a NAT64 gateway really will translate and route. Each is a way to write
/// `169.254.169.254` that does not look like it.
fn embedded_ipv4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = ip.segments();
    // 64:ff9b::/96 — the NAT64 well-known prefix.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        return Some(std::net::Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    // `::a.b.c.d`, excluding `::` and `::1`, which are their own cases above.
    if seg[..6] == [0, 0, 0, 0, 0, 0] && !(seg[6] == 0 && seg[7] <= 1) {
        return Some(std::net::Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    None
}

/// The destination rules for an IPv4 address, wherever it was spelled.
fn ipv4_is_allowed(ip: std::net::Ipv4Addr, allow_local: bool) -> bool {
    if allow_local && ip.is_loopback() {
        return true;
    }
    // Link-local covers 169.254.169.254, which is where every cloud keeps the
    // credentials of the machine doing the importing. Shared address space
    // (100.64.0.0/10) is carrier-grade NAT: not private by `is_private`'s
    // reckoning, and not somewhere a registry should be able to aim a request.
    let o = ip.octets();
    let is_shared = o[0] == 100 && (o[1] & 0xc0) == 0x40;
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || ip.is_unspecified()
        || is_shared)
}

/// The resolver `reqwest` calls, so the floor is about the address.
///
/// [`destination_is_allowed`] screens a URL. That is enough for a literal and
/// worth nothing for a name: `https://blob.evil.example/` is an ordinary public
/// host as a string, and the registry that named it chooses what it resolves
/// to. Resolving here means the check and the lookup are **one act** — the
/// connector dials the addresses this returns and performs no lookup of its own
/// — so there is no interval between "checked" and "connected" for an answer to
/// change in. That is what shuts the rebinding door, not the checking.
///
/// `ClientBuilder::resolve`/`resolve_to_addrs` would pin an address just as
/// firmly, but they take their map at *build* time and most of the hosts a pull
/// dials are not known then: the redirect targets and the token realm are the
/// registry's own text, produced mid-pull. Covering them would mean a fresh
/// client — and a fresh connection pool — at every hop.
///
/// Certificate validation is unaffected: only the socket address comes from
/// here, and TLS is still verified against the host name in the URL.
pub struct FlooredResolver {
    /// The operator's intent, as in [`destination_is_allowed`]: true only when
    /// they themselves named a loopback registry.
    allow_local: bool,
}

impl FlooredResolver {
    /// A resolver for a pull whose registry is (or is not) the operator's own
    /// loopback.
    #[must_use]
    pub fn new(allow_local: bool) -> Self {
        Self { allow_local }
    }
}

impl reqwest::dns::Resolve for FlooredResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_local = self.allow_local;
        let host = name.as_str().to_string();
        Box::pin(async move {
            // `lookup_host` rather than a blocking `to_socket_addrs`: the
            // blocking client drives every request on one current-thread
            // runtime, and its own request timeout is a timer on that runtime.
            // Blocking the thread inside `getaddrinfo` would be a request
            // timeout that cannot fire while the thing it is timing hangs.
            let addrs = match tokio::time::timeout(
                RESOLVE_TIMEOUT,
                tokio::net::lookup_host((host.as_str(), 0u16)),
            )
            .await
            {
                Ok(Ok(iter)) => iter.collect::<Vec<SocketAddr>>(),
                Ok(Err(e)) => return Err(format!("{host} did not resolve: {e}").into()),
                Err(_) => {
                    return Err(format!(
                        "{host} did not resolve within {} seconds",
                        RESOLVE_TIMEOUT.as_secs()
                    )
                    .into())
                }
            };
            screen_resolved(&host, addrs, allow_local)
                .map(|kept| Box::new(kept.into_iter()) as reqwest::dns::Addrs)
                .map_err(Into::into)
        })
    }
}

/// The addresses a name may be dialled at, or why it may not be dialled at all.
///
/// **One floored address refuses the whole name.** Not a filter: a name that
/// answers with a public address and a private one is not a name with a usable
/// half, it is the standard shape of a rebinding payload — the client keeps a
/// connection open to the public record while a second lookup, or a second
/// connection, lands on the private one. The guest egress broker filters
/// instead, and is right to: its names come from an allowlist the operator
/// wrote, and dropping a record there merely declines one address of a
/// multi-homed host the operator asked for. Here the name is as likely as not
/// the registry's own text, and there is nothing to preserve.
///
/// The refusal names the address, unlike the broker's, whose message reaches
/// the guest and must not describe the host's networks. This one reaches the
/// operator's terminal about their own machine, and it is the only thing that
/// tells them whether they hit an attack or their own split-horizon DNS.
fn screen_resolved(
    host: &str,
    addrs: Vec<SocketAddr>,
    allow_local: bool,
) -> Result<Vec<SocketAddr>, String> {
    if addrs.is_empty() {
        return Err(format!("{host} resolved to no addresses at all"));
    }
    if let Some(bad) = addrs
        .iter()
        .find(|a| !address_is_allowed(a.ip(), allow_local))
    {
        return Err(format!(
            "{host} resolves to {}, which isopod will not dial for an image \
             import: it is loopback, link-local (the cloud metadata endpoint \
             lives there), a private or carrier-NAT range, or otherwise not a \
             public address. A registry chooses its own redirect targets and \
             its own token realm, so a name it supplies is a request it aimed. \
             Every address a name answers with has to pass, because one that \
             does not is how a name is made to point somewhere else on the \
             next lookup.",
            bad.ip()
        ));
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realm that is fine, so every refusal below means something.
    const GOOD: &str = r#"Bearer realm="https://auth.docker.io/token""#;

    #[test]
    fn a_challenge_parses_including_the_scope_that_contains_a_comma() {
        // The value that breaks a naive `split(',')`: a pull,push scope. A
        // client that mangles it asks for the wrong scope and gets a token that
        // silently does not work.
        let c = Challenge::parse(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull,push""#,
            false,
        )
        .expect("must parse");
        assert_eq!(c.realm.as_str(), "https://auth.docker.io/token");
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(
            c.scope.as_deref(),
            Some("repository:library/alpine:pull,push"),
            "the scope must survive its own comma"
        );
        let url = c.token_url();
        assert!(url.as_str().starts_with("https://auth.docker.io/token?"));
        assert!(url.query().expect("query").contains("pull%2Cpush"));
    }

    #[test]
    fn a_realm_that_is_not_https_is_refused_because_a_token_is_a_credential() {
        let err = Challenge::parse(r#"Bearer realm="http://auth.example.com/token""#, false)
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("not a public https address"),
            "{err}"
        );

        // Not a Bearer challenge, no realm, not a web URL at all.
        assert!(Challenge::parse(r#"Bearer realm="file:///etc/shadow""#, false).is_err());
        assert!(Challenge::parse(r#"Bearer service="x""#, false).is_err());
        assert!(Challenge::parse(r#"Basic realm="https://x/""#, false).is_err());
        // The control: the good one parses, both ways.
        assert!(Challenge::parse(GOOD, false).is_ok());
        assert!(Challenge::parse(GOOD, true).is_ok());
    }

    #[test]
    fn a_remote_registry_cannot_aim_a_credential_at_the_operators_own_machine() {
        // The realm is the registry's text and a credential goes to it, so it
        // gets the destination floor a redirect gets. This used to be a bare
        // "https or loopback" check with the loopback half ungated, so ANY
        // registry could name the operator's loopback — and a test asserted
        // that it could.
        for hostile in [
            r#"Bearer realm="http://localhost:5000/token""#,
            r#"Bearer realm="http://127.0.0.1:80/token""#,
            r#"Bearer realm="https://127.0.0.1/token""#,
            r#"Bearer realm="https://[::1]/token""#,
            r#"Bearer realm="https://169.254.169.254/latest/meta-data/""#,
            r#"Bearer realm="https://[::ffff:169.254.169.254]/token""#,
            r#"Bearer realm="https://10.0.0.5/token""#,
            r#"Bearer realm="https://192.168.1.1/token""#,
            r#"Bearer realm="https://[fd00::1]/token""#,
        ] {
            assert!(
                Challenge::parse(hostile, false).is_err(),
                "{hostile} must not receive the operator's credential"
            );
        }

        // The neighbour that must still work: the operator named a loopback
        // registry themselves, which is the local-registry workflow. Only then.
        assert!(Challenge::parse(r#"Bearer realm="http://localhost:5000/token""#, true).is_ok());
        assert!(Challenge::parse(r#"Bearer realm="http://127.0.0.1:5000/token""#, true).is_ok());
    }

    #[test]
    fn a_credential_never_crosses_an_origin() {
        let base = Url::parse("https://registry-1.docker.io/v2/x/blobs/sha256:aa").expect("url");
        let same = Url::parse("https://registry-1.docker.io/other").expect("url");
        assert!(may_carry_credential(&base, &same));

        // Each of these differs from the original in exactly one part of the
        // origin, and each is a different host as far as a credential goes.
        for other in [
            "https://cdn.example.com/blob",           // the ordinary CDN redirect
            "http://registry-1.docker.io/v2/x",       // downgraded scheme
            "https://registry-1.docker.io:8443/v2/x", // different port
            "https://registry-1.docker.io.evil.com/", // suffix trick
        ] {
            let to = Url::parse(other).expect("url");
            assert!(
                !may_carry_credential(&base, &to),
                "{other} must not receive the Authorization header"
            );
        }
    }

    #[test]
    fn a_destination_cannot_be_aimed_at_the_hosts_own_network() {
        // Digest verification stops a redirect injecting content. It does not
        // stop the request happening, and the request is what an SSRF is.
        for blocked in [
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/admin",
            "https://[::1]/admin",
            "https://10.0.0.5/internal",
            "https://192.168.1.1/router",
            "https://172.16.3.4/internal",
            "https://[fd00::1]/internal",
            "https://[fe80::1]/internal",
            // fec0::/10, deprecated site-local. The broker refuses it; this
            // floor did not, which is the two of them disagreeing.
            "https://[fec0::1]/internal",
            "https://localhost/admin",
            "http://cdn.example.com/blob",
            "https://0.0.0.0/",
            "https://255.255.255.255/",
            "https://224.0.0.1/multicast",
            // Carrier-grade NAT: not "private" by is_private's reckoning, and
            // not somewhere a stranger should be able to aim a request.
            "https://100.64.1.1/cgnat",
        ] {
            let u = Url::parse(blocked).expect("url");
            assert!(
                !destination_is_allowed(&u, false),
                "{blocked} must not be dialled"
            );
        }

        // The same addresses wearing IPv6 spellings. Judging the spelling
        // rather than the address let every one of these through a floor
        // written to block the address.
        for blocked in [
            "https://[::ffff:169.254.169.254]/latest/meta-data/", // IPv4-mapped
            "https://[::ffff:127.0.0.1]/admin",
            "https://[::ffff:10.0.0.5]/internal",
            "https://[0:0:0:0:0:ffff:a9fe:a9fe]/", // the same, written out
            "https://[64:ff9b::a9fe:a9fe]/",       // NAT64 well-known prefix
            "https://[::a9fe:a9fe]/",              // deprecated IPv4-compatible
        ] {
            let u = Url::parse(blocked).expect("url");
            assert!(
                !destination_is_allowed(&u, false),
                "{blocked} is 169.254.169.254 / loopback / RFC1918 in another spelling"
            );
        }

        // The control: an ordinary CDN redirect, which is the common case and
        // must go through, or no image downloads at all. Including a genuine
        // public IPv6 host, so the v6 arm is not simply refusing everything.
        for allowed in [
            "https://production.cloudflare.docker.com/registry-v2/docker/…",
            "https://ghcr.io/v2/o/n/blobs/sha256:aa",
            "https://[2606:4700::6810:85e5]/blob",
            "https://8.8.8.8/blob",
        ] {
            let u = Url::parse(allowed).expect("url");
            assert!(
                destination_is_allowed(&u, false),
                "{allowed} must be dialled"
            );
        }

        // And the local-registry workflow, which the operator opted into by
        // naming a loopback registry.
        let local = Url::parse("http://127.0.0.1:5000/v2/n/blobs/sha256:aa").expect("url");
        assert!(destination_is_allowed(&local, true));
        assert!(!destination_is_allowed(&local, false));
        // `allow_local` unlocks loopback, and nothing else: a private-network
        // address is not what the operator opted into by typing `localhost`.
        for still_blocked in ["https://169.254.169.254/", "https://10.0.0.5/"] {
            let u = Url::parse(still_blocked).expect("url");
            assert!(
                !destination_is_allowed(&u, true),
                "{still_blocked} is not unlocked by a local registry"
            );
        }
    }

    /// Build an address list the way a resolver hands one over.
    fn resolved(ips: &[&str]) -> Vec<SocketAddr> {
        ips.iter()
            .map(|s| SocketAddr::new(s.parse().expect("an address"), 0))
            .collect()
    }

    #[test]
    fn a_name_is_judged_by_every_address_it_answers_with() {
        // The control first, and it has to be first: a floor that refuses
        // everything passes every one of the refusals below.
        let good = resolved(&["93.184.216.34", "2606:4700::6810:85e5"]);
        assert_eq!(
            screen_resolved("cdn.example.com", good.clone(), false),
            Ok(good),
            "a public name must resolve and be dialled, or nothing imports"
        );

        // One record, and it points into the operator's machine or network.
        // These are the addresses a URL check cannot see, because the URL says
        // `https://blob.evil.example/` in every one of them.
        for ip in [
            "169.254.169.254", // the cloud metadata endpoint
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.3.4",
            "100.64.1.1", // carrier-grade NAT, and not `is_private`
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "::ffff:169.254.169.254", // the same metadata endpoint, mapped
            "64:ff9b::a9fe:a9fe",     // and via the NAT64 prefix
            "::a9fe:a9fe",            // and IPv4-compatible
        ] {
            assert!(
                screen_resolved("blob.evil.example", resolved(&[ip]), false).is_err(),
                "a name resolving to {ip} must not be dialled"
            );
        }

        // The one the obvious implementation misses: a name with a good record
        // AND a bad one, in both orders. A check of `addrs[0]` alone accepts
        // the first of these and refuses the second — a floor whose answer
        // depends on which record the resolver happened to list first.
        for pair in [
            ["93.184.216.34", "169.254.169.254"],
            ["169.254.169.254", "93.184.216.34"],
            ["93.184.216.34", "10.0.0.5"],
            ["2606:4700::6810:85e5", "fd00::1"],
        ] {
            assert!(
                screen_resolved("blob.evil.example", resolved(&pair), false).is_err(),
                "{pair:?}: one floored record refuses the name, it does not \
                 leave a usable half"
            );
        }

        // A name that resolves to nothing is not a name that resolves to
        // anything permitted, and an empty address list handed to the connector
        // is a confusing failure somewhere further down.
        assert!(screen_resolved("nx.example", Vec::new(), false).is_err());

        // The operator's own loopback registry, which is the workflow the
        // exemption exists for — and it unlocks loopback only.
        assert!(screen_resolved("localhost", resolved(&["127.0.0.1", "::1"]), true).is_ok());
        assert!(screen_resolved("localhost", resolved(&["127.0.0.1"]), false).is_err());
        for still_blocked in ["10.0.0.5", "169.254.169.254"] {
            assert!(
                screen_resolved("lan.example", resolved(&[still_blocked]), true).is_err(),
                "{still_blocked} is not what the operator opted into by typing localhost"
            );
        }
    }

    #[test]
    fn an_ipv6_literal_reduces_to_the_ipv4_address_it_names() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let meta = Ipv4Addr::new(169, 254, 169, 254);
        for (spelling, want) in [
            ("::ffff:169.254.169.254", Some(meta)),
            ("64:ff9b::169.254.169.254", Some(meta)),
            ("::169.254.169.254", Some(meta)),
            ("2606:4700::6810:85e5", None),
            ("::", None),
            ("::1", None),
            ("fd00::1", None),
        ] {
            let ip: Ipv6Addr = spelling.parse().expect("v6");
            assert_eq!(embedded_ipv4(ip), want, "{spelling}");
        }
    }
}
