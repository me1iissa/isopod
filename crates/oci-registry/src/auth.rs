//! The bearer-token dance, and the rule about where a credential may travel.
//!
//! A registry answers an unauthenticated request with `401` and a
//! `WWW-Authenticate` header naming a token service. The client fetches a token
//! from that service and retries. The header is **the registry's** text, so the
//! realm in it is an attacker-chosen URL in exactly the case that matters — a
//! hostile or compromised registry — and a client that posts its credentials to
//! whatever realm it is handed has been talked into leaking them.
//!
//! Two rules fall out, and both are enforced here rather than at the call site:
//!
//! 1. A token realm must be **https**, and its host is recorded so a caller can
//!    decide whether it trusts it.
//! 2. `Authorization` never crosses an origin. Blob downloads redirect to CDNs
//!    as a matter of course, so this is the ordinary path, not an edge case.

use std::fmt;

use url::Url;

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
    /// # Errors
    /// [`ChallengeError`] if it is not a Bearer challenge, names no realm, or
    /// names one this client will not post a credential to.
    pub fn parse(header: &str) -> Result<Self, ChallengeError> {
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
        // The realm is the registry's text. A credential is about to be sent to
        // it, so `http://` — or anything that is not a web URL at all — is
        // refused rather than followed.
        if realm.scheme() != "https" && !is_loopback_url(&realm) {
            return Err(ChallengeError(format!(
                "the registry's token realm is {realm}, which is not https. A \
                 token request carries a credential, and isopod will not send \
                 one in the clear to a host the registry chose."
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

/// Would following `to` reach somewhere a redirect has no business reaching?
///
/// A registry chooses redirect targets, so a blob fetch is a request the image's
/// publisher can aim. Digest verification means they cannot inject *content*
/// that way, but the request still happens: at a cloud metadata endpoint, at a
/// service on the operator's loopback, at something inside their network. This
/// is the same destination floor the guest egress broker applies, applied to the
/// one host-side fetch that takes its address from a stranger.
///
/// A registry the operator deliberately named as loopback is exempt — that is
/// the local-registry workflow, and the operator typed it.
#[must_use]
pub fn redirect_target_is_allowed(to: &Url, allow_local: bool) -> bool {
    if to.scheme() != "https" && !(allow_local && is_loopback_url(to)) {
        return false;
    }
    let Some(host) = to.host() else {
        return false;
    };
    match host {
        url::Host::Domain(d) => allow_local || !(d == "localhost" || d.ends_with(".localhost")),
        url::Host::Ipv4(ip) => {
            if allow_local && ip.is_loopback() {
                return true;
            }
            // Link-local covers 169.254.169.254, which is where every cloud
            // keeps the credentials of the machine doing the importing.
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified())
        }
        url::Host::Ipv6(ip) => {
            if allow_local && ip.is_loopback() {
                return true;
            }
            // `is_unique_local`/`is_unicast_link_local` are not stable, so the
            // prefixes are matched directly: fc00::/7 and fe80::/10.
            let seg = ip.segments()[0];
            !(ip.is_loopback()
                || ip.is_unspecified()
                || (seg & 0xfe00) == 0xfc00
                || (seg & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_parses_including_the_scope_that_contains_a_comma() {
        // The value that breaks a naive `split(',')`: a pull,push scope. A
        // client that mangles it asks for the wrong scope and gets a token that
        // silently does not work.
        let c = Challenge::parse(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull,push""#,
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
        let err = Challenge::parse(r#"Bearer realm="http://auth.example.com/token""#)
            .expect_err("must refuse");
        assert!(err.to_string().contains("not https"), "{err}");

        // A loopback realm is the local-registry case and is allowed.
        assert!(Challenge::parse(r#"Bearer realm="http://localhost:5000/token""#).is_ok());

        // And the neighbours: a scheme that is not http at all, and no realm.
        assert!(Challenge::parse(r#"Bearer realm="file:///etc/shadow""#).is_err());
        assert!(Challenge::parse(r#"Bearer service="x""#).is_err());
        assert!(Challenge::parse(r#"Basic realm="https://x/""#).is_err());
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
    fn a_redirect_cannot_be_aimed_at_the_hosts_own_network() {
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
            "https://localhost/admin",
            "http://cdn.example.com/blob",
        ] {
            let u = Url::parse(blocked).expect("url");
            assert!(
                !redirect_target_is_allowed(&u, false),
                "{blocked} must not be followed"
            );
        }
        // The control: an ordinary CDN redirect, which is the common case and
        // must go through, or no image downloads at all.
        for allowed in [
            "https://production.cloudflare.docker.com/registry-v2/docker/…",
            "https://ghcr.io/v2/o/n/blobs/sha256:aa",
        ] {
            let u = Url::parse(allowed).expect("url");
            assert!(
                redirect_target_is_allowed(&u, false),
                "{allowed} must be followed"
            );
        }
        // And the local-registry workflow, which the operator opted into by
        // naming a loopback registry.
        let local = Url::parse("http://127.0.0.1:5000/v2/n/blobs/sha256:aa").expect("url");
        assert!(redirect_target_is_allowed(&local, true));
        assert!(!redirect_target_is_allowed(&local, false));
    }
}
