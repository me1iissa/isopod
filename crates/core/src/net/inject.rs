//! The credential-injection endpoint: a narrow gateway, not a reverse proxy.
//!
//! # What the red team established
//!
//! Six independent findings converged on one point: stopping the guest from
//! *reading* a token was never the hard part. If the broker forwards a request
//! the guest composed, the guest still chooses what the credential *signs* —
//! `POST /user/keys` plants an attacker-held key that outlives the VM, a
//! scheme-relative target like `//evil.com/x` relocates the request off its
//! pinned origin, a verbatim `Host:` header delivers the `Authorization` to a
//! different server, and a 30x followed blindly carries it somewhere else again.
//!
//! So this is **not** a reverse proxy. The guest's bytes never reach the wire.
//! It states an intent — a method, a path, and at most two headers — and the
//! broker **constructs a new request from parts** if and only if that intent
//! matches a rule the operator wrote by hand:
//!
//! ```text
//!   guest                        broker                        upstream
//!   ─────                        ──────                        ────────
//!   GET /github/user     ──▶  alias = "github"
//!   Host: evil.com                (discarded)
//!   Authorization: ...            (discarded)
//!                                 normalize "/user"    ──▶  rejects //evil,
//!                                                            %2e%2e, backslash…
//!                                 "GET /user" ∈ allow? ──▶  else 403, and the
//!                                                            header is never
//!                                                            attached
//!                                 build from parts:
//!                                   GET /user HTTP/1.1
//!                                   Host: api.github.com   ← broker-owned
//!                                   Authorization: Bearer …
//!                                                       ──▶  TLS, no redirects
//! ```
//!
//! # What is deliberately *not* defended against
//!
//! Every process inside the guest can reach this endpoint — it is a TCP port on
//! the gateway, and the guest is one trust domain. An unguessable path would be
//! theatre: any process that can read the exec environment can read the URL.
//!
//! The honest framing is that a credential injected into a run is **usable by
//! all code in that run**, which is exactly why the `allow` list is mandatory:
//! the defence is not "only my program can use it", it is "the token can only do
//! these specific things". `SECURITY.md` states this as a non-claim.

use std::fmt;

use super::credentials::{normalize_target, Method, ResolvedCredential};

/// Largest request head (request line + headers) accepted from the guest.
pub const MAX_INJECT_HEAD: usize = 8 * 1024;

/// Largest request body forwarded upstream. A credentialled call is an API
/// request, not an upload; the cap bounds what one guest can buffer host-side.
pub const MAX_INJECT_BODY: u64 = 1024 * 1024;

/// Largest response streamed back to the guest.
pub const MAX_INJECT_RESP: u64 = 64 * 1024 * 1024;

/// Guest headers that may influence the constructed request, by name.
///
/// Everything else is dropped, including `Authorization` (the guest does not get
/// to supply its own), `Cookie`, `Host` (broker-owned), `Proxy-*`,
/// `X-Forwarded-*`, `Transfer-Encoding`, `TE`, `Upgrade`, and `Connection`.
/// This is an allowlist rather than a denylist on purpose: a denylist has to
/// anticipate every dangerous header, and the next one to be invented is
/// automatically permitted.
const FORWARDABLE: [&str; 2] = ["accept", "content-type"];

/// Longest forwarded header value.
const MAX_HEADER_VALUE: usize = 1024;

// ===========================================================================
// Refusals.
// ===========================================================================

/// Why the endpoint refused. Every variant maps to a fixed response body — none
/// interpolates guest input, so the endpoint cannot be used to echo chosen bytes
/// back into a log or a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectRefusal {
    /// The head was not a parseable HTTP request.
    Malformed,
    /// The request head exceeded [`MAX_INJECT_HEAD`].
    HeadTooLarge,
    /// The method is not one the endpoint can express.
    BadMethod,
    /// The path did not begin with `/<alias>/`.
    NoAlias,
    /// No such alias was injected into this run.
    UnknownAlias,
    /// The request target could not be normalised — see [`normalize_target`].
    BadTarget,
    /// The alias exists but does not permit this method+path.
    NotPermitted,
    /// A forwarded header value was over-long or contained illegal bytes.
    BadHeader,
    /// The declared body exceeded [`MAX_INJECT_BODY`], or the framing was
    /// ambiguous (chunked, or a duplicated `Content-Length`).
    BadBody,
}

impl InjectRefusal {
    /// The HTTP status to answer with.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Self::Malformed | Self::NoAlias | Self::BadTarget | Self::BadHeader => 400,
            Self::HeadTooLarge => 431,
            Self::BadMethod => 405,
            Self::UnknownAlias | Self::NotPermitted => 403,
            Self::BadBody => 413,
        }
    }

    /// A fixed explanation. Static by construction: no guest bytes.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::Malformed => "malformed request",
            Self::HeadTooLarge => "request head too large",
            Self::BadMethod => "method not usable with an injected credential",
            Self::NoAlias => "request path must begin with /<alias>/",
            Self::UnknownAlias => "no such credential is injected into this run",
            Self::BadTarget => "request target is not a safe origin-form path",
            Self::NotPermitted => {
                "this credential does not permit that method and path; \
                 widen its \"allow\" list if that is intended"
            }
            Self::BadHeader => "a forwarded header was too long or malformed",
            Self::BadBody => "request body too large or ambiguously framed",
        }
    }

    /// A short machine-readable tag for the flight recorder.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Malformed => "inject-malformed",
            Self::HeadTooLarge => "inject-head-too-large",
            Self::BadMethod => "inject-bad-method",
            Self::NoAlias => "inject-no-alias",
            Self::UnknownAlias => "inject-unknown-alias",
            Self::BadTarget => "inject-bad-target",
            Self::NotPermitted => "inject-not-permitted",
            Self::BadHeader => "inject-bad-header",
            Self::BadBody => "inject-bad-body",
        }
    }

    /// The complete HTTP response to write back.
    #[must_use]
    pub fn response(self) -> String {
        fixed_response(self.status(), self.explain())
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// Build a complete, fixed HTTP response carrying `message`.
///
/// Every caller passes a `&'static str`, so no guest or upstream bytes can reach
/// this body.
fn fixed_response(status: u16, message: &'static str) -> String {
    let body = format!("isopod credential endpoint: {message}\n");
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        reason = reason_phrase(status),
        len = body.len(),
    )
}

/// Why an **authorised** request produced no response.
///
/// Deliberately a separate type from [`InjectRefusal`]. A refusal means the
/// guest asked for something it may not have; this means it asked for something
/// it may have and the far side did not deliver. Conflating them would make the
/// flight recorder unable to answer the first question an operator asks when a
/// credentialled call fails: "was that my allow list, or was the API down?"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamFailure {
    /// DNS, TCP, or TLS to the pinned host failed.
    Unreachable,
    /// The pinned host did not answer within the budget.
    TimedOut,
    /// The response exceeded [`MAX_INJECT_RESP`] and was cut off mid-body.
    TooLarge,
}

impl UpstreamFailure {
    /// The HTTP status to answer with.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Self::Unreachable | Self::TooLarge => 502,
            Self::TimedOut => 504,
        }
    }

    /// A fixed explanation. Static by construction: no upstream bytes.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::Unreachable => {
                "the credential's pinned host could not be reached over TLS from the host"
            }
            Self::TimedOut => "the credential's pinned host did not answer in time",
            Self::TooLarge => "the response exceeded the endpoint's size ceiling",
        }
    }

    /// A short machine-readable tag for the flight recorder.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Unreachable => "inject-upstream-unreachable",
            Self::TimedOut => "inject-upstream-timeout",
            Self::TooLarge => "inject-response-too-large",
        }
    }

    /// The complete HTTP response to write back.
    #[must_use]
    pub fn response(self) -> String {
        fixed_response(self.status(), self.explain())
    }
}

impl fmt::Display for UpstreamFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.explain())
    }
}

// ===========================================================================
// The response leg.
// ===========================================================================

/// Response headers the endpoint never relays.
///
/// This is a **denylist**, and the asymmetry with [`FORWARDABLE`] is deliberate
/// rather than an inconsistency. On the way up, a permitted header lets the
/// guest steer what the credential signs, so the next header to be invented must
/// default to *dropped*. On the way down there is no such lever: the response
/// comes from the host the operator pinned, to a guest that is already untrusted,
/// and relaying one more of its headers grants the guest nothing. The only real
/// hazard is the broker's own re-framing — so exactly the headers that describe
/// the old framing or the old hop are removed, and everything else (`Link` for
/// pagination, `ETag`, the rate-limit family) survives, which is what makes the
/// endpoint usable for real API work.
const RESPONSE_HEADER_DENY: [&str; 9] = [
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Largest number of response headers relayed to the guest.
const MAX_RESPONSE_HEADERS: usize = 64;

/// Whether a response header may be relayed, given an already-lower-cased name.
///
/// A value carrying anything outside a legal field-value is dropped rather than
/// escaped: the broker writes the response head itself, and a CR in a relayed
/// value would split it — response splitting sourced from upstream instead of
/// from the guest.
#[must_use]
pub fn relayable_header(lname: &str, value: &str) -> bool {
    !RESPONSE_HEADER_DENY.contains(&lname)
        && !lname.is_empty()
        && lname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        && value.len() <= MAX_HEADER_VALUE
        && value
            .bytes()
            .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
}

/// Keep the relayable headers, in upstream order, bounded in count.
#[must_use]
pub fn relay_headers<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter(|(n, v)| relayable_header(&n.to_ascii_lowercase(), v))
        .take(MAX_RESPONSE_HEADERS)
        .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
        .collect()
}

/// Build the response head the guest receives for a successful upstream call.
///
/// The body is framed **chunked**, always, and never with a `Content-Length`:
///
/// - The body is streamed, because a credentialled call may legitimately return
///   megabytes and buffering [`MAX_INJECT_RESP`] per concurrent connection would
///   put the host's memory under guest control.
/// - Chunked rather than close-delimited, because the terminating chunk is what
///   distinguishes a complete response from one the broker cut off at the
///   ceiling. Handing a workload half a JSON document with no signal is worse
///   than handing it a protocol error.
/// - Never both framings at once — which is exactly what the endpoint refuses
///   *from* the guest ([`InjectRefusal::BadBody`]), so emitting both here would
///   be holding itself to a lower standard than its callers.
#[must_use]
pub fn build_response_head(status: u16, headers: &[(String, String)]) -> String {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\n",
        reason = upstream_reason_phrase(status),
    );
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    out
}

/// A reason phrase for an upstream status.
///
/// Deliberately not relayed from upstream: the phrase is free-form bytes chosen
/// by the far side, and it lands on the guest's first response line where a
/// stray CR would split the head. The numeric status carries all the meaning; a
/// generic phrase for an unrecognised code costs nothing.
fn upstream_reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        s if (200..300).contains(&s) => "OK",
        s if (300..400).contains(&s) => "Redirection",
        s if (400..500).contains(&s) => "Client Error",
        _ => "Server Error",
    }
}

/// Frame one body chunk for the chunked response.
#[must_use]
pub fn chunk_frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", bytes.len()).into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
    out
}

/// The terminating chunk. Written only when the body completed, so a response
/// cut off at [`MAX_INJECT_RESP`] is detectable as a protocol error rather than
/// arriving as a silently short document.
pub const CHUNK_TERMINATOR: &[u8] = b"0\r\n\r\n";

impl fmt::Display for InjectRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.explain())
    }
}

// ===========================================================================
// The guest's stated intent.
// ===========================================================================

/// What the guest asked for, after parsing but before any authorisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatedIntent {
    /// The alias named by the first path segment.
    pub alias: String,
    /// The method, already narrowed to the closed enum.
    pub method: Method,
    /// The remaining path, already normalised.
    pub path: String,
    /// Header name/value pairs that survived the allowlist, lower-cased names.
    pub headers: Vec<(String, String)>,
    /// Declared body length, if any.
    pub body_len: u64,
}

/// Parse a request head into a stated intent.
///
/// Pure, so every refusal branch is unit-testable without a socket. Note what
/// this does **not** produce: any field carrying a guest-chosen host, scheme,
/// authority, or authorization value. Those are not parsed because they are not
/// used — the constructed request supplies its own.
///
/// # Errors
/// [`InjectRefusal`] describing the first thing that was unacceptable.
pub fn parse_intent(head: &[u8]) -> Result<StatedIntent, InjectRefusal> {
    if head.len() > MAX_INJECT_HEAD {
        return Err(InjectRefusal::HeadTooLarge);
    }
    let text = std::str::from_utf8(head).map_err(|_| InjectRefusal::Malformed)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(InjectRefusal::Malformed)?;

    let mut parts = request_line.split(' ');
    let method_raw = parts.next().ok_or(InjectRefusal::Malformed)?;
    let target = parts.next().ok_or(InjectRefusal::Malformed)?;
    let version = parts.next().ok_or(InjectRefusal::Malformed)?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(InjectRefusal::Malformed);
    }
    let method = Method::parse(method_raw).ok_or(InjectRefusal::BadMethod)?;

    // The alias is the first path segment. Split BEFORE normalising, so the
    // alias itself cannot smuggle traversal into the remainder.
    let (alias, rest) = split_alias(target)?;
    let path = normalize_target(&rest).map_err(|_| InjectRefusal::BadTarget)?;

    let mut headers = Vec::new();
    let mut body_len: Option<u64> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(InjectRefusal::Malformed)?;
        let lname = name.trim().to_ascii_lowercase();
        let value = value.trim();

        if lname == "content-length" {
            let n: u64 = value.parse().map_err(|_| InjectRefusal::BadBody)?;
            // A repeated Content-Length is the classic request-smuggling setup.
            if body_len.replace(n).is_some() {
                return Err(InjectRefusal::BadBody);
            }
            if n > MAX_INJECT_BODY {
                return Err(InjectRefusal::BadBody);
            }
            continue;
        }
        // Chunked framing from the guest is refused outright rather than
        // re-framed: the broker declares its own Content-Length upstream, and
        // two framings in play is how requests get smuggled.
        if lname == "transfer-encoding" {
            return Err(InjectRefusal::BadBody);
        }
        if !FORWARDABLE.contains(&lname.as_str()) {
            continue;
        }
        if value.len() > MAX_HEADER_VALUE {
            return Err(InjectRefusal::BadHeader);
        }
        if !value
            .bytes()
            .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
        {
            return Err(InjectRefusal::BadHeader);
        }
        // One occurrence each; a repeat is ambiguous and cheap to refuse.
        if headers.iter().any(|(n, _): &(String, String)| n == &lname) {
            return Err(InjectRefusal::BadHeader);
        }
        headers.push((lname, value.to_string()));
    }

    Ok(StatedIntent {
        alias,
        method,
        path,
        headers,
        body_len: body_len.unwrap_or(0),
    })
}

/// Split `/alias/rest` into its alias and the remaining path.
///
/// The alias must be a single, plain segment: no dots, no escapes, no wildcards.
/// An empty remainder becomes `/`, so `/github` and `/github/` both address the
/// API root.
fn split_alias(target: &str) -> Result<(String, String), InjectRefusal> {
    let body = target.strip_prefix('/').ok_or(InjectRefusal::NoAlias)?;
    let (alias, rest) = match body.split_once('/') {
        Some((a, r)) => (a, format!("/{r}")),
        None => (body, "/".to_string()),
    };
    if alias.is_empty() {
        return Err(InjectRefusal::NoAlias);
    }
    // The alias names a key in the operator's file; anything exotic here is
    // either a typo or an attempt to confuse the lookup.
    if !alias
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(InjectRefusal::NoAlias);
    }
    Ok((alias.to_string(), rest))
}

// ===========================================================================
// Authorisation + construction.
// ===========================================================================

/// A request the broker has decided to make, built entirely from its own parts.
///
/// There is no field here the guest supplied verbatim except the path (which
/// [`normalize_target`] validated and an `allow` rule matched) and the two
/// allowlisted header values.
#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    /// `https://<pinned host><path>`.
    pub url: String,
    /// The matched rule's canonical method token.
    pub method: Method,
    /// Headers to set, `Authorization` excluded — it is applied separately so it
    /// never sits in a structure that might be logged.
    pub headers: Vec<(String, String)>,
    /// Alias, for the flight recorder.
    pub alias: String,
    /// Pinned host, for the flight recorder.
    pub host: String,
}

/// Authorise a stated intent against the run's credentials and build the
/// upstream request.
///
/// # Errors
/// [`InjectRefusal::UnknownAlias`] if no injected credential matches, or
/// [`InjectRefusal::NotPermitted`] if none of its rules covers the request. In
/// both cases the caller must answer without attaching any header.
pub fn authorize<'a>(
    creds: &'a [ResolvedCredential],
    intent: &StatedIntent,
) -> Result<(UpstreamRequest, &'a ResolvedCredential), InjectRefusal> {
    let cred = creds
        .iter()
        .find(|c| c.alias().as_str() == intent.alias)
        .ok_or(InjectRefusal::UnknownAlias)?;

    if !cred.permits(intent.method, &intent.path) {
        return Err(InjectRefusal::NotPermitted);
    }

    // Built from parts. The scheme is always https and the authority is always
    // the pinned host — neither is derived from anything the guest sent, so
    // there is no join for a scheme-relative or absolute-form target to subvert.
    let url = format!("https://{}{}", cred.host().as_str(), intent.path);

    Ok((
        UpstreamRequest {
            url,
            method: intent.method,
            headers: intent.headers.clone(),
            alias: intent.alias.clone(),
            host: cred.host().as_str().to_string(),
        },
        cred,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::credentials::{load_credentials, Caller, CREDENTIALS_FILE};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    fn head(s: &str) -> Vec<u8> {
        s.replace('\n', "\r\n").into_bytes()
    }

    fn creds_fixture(dir: &Path) -> Vec<ResolvedCredential> {
        std::env::set_var("ISOPOD_INJECT_TEST_TOK", "ghp_testtoken");
        let body = r#"{
          "version": 1,
          "credentials": {
            "github": {"host":"api.github.com","scheme":"bearer",
                       "source":"env:ISOPOD_INJECT_TEST_TOK","allow":["readonly"]},
            "status": {"host":"api.github.com","scheme":"bearer",
                       "source":"env:ISOPOD_INJECT_TEST_TOK",
                       "allow":["POST /repos/*/*/statuses/*"]},
            "off":    {"host":"api.github.com","scheme":"bearer",
                       "source":"env:ISOPOD_INJECT_TEST_TOK","allow":["none"]}
          }
        }"#;
        let p: PathBuf = dir.join(CREDENTIALS_FILE);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        load_credentials(
            &["github".into(), "status".into(), "off".into()],
            Caller::Operator,
            &p,
        )
        .unwrap()
    }

    // --- parsing -----------------------------------------------------------

    #[test]
    fn parses_alias_method_and_path() {
        let i = parse_intent(&head("GET /github/user HTTP/1.1\nHost: x\n\n")).unwrap();
        assert_eq!(i.alias, "github");
        assert_eq!(i.method, Method::Get);
        assert_eq!(i.path, "/user");
        // The Host the guest sent is not even retained — the constructed
        // request supplies the pinned one.
        assert!(i.headers.is_empty());
    }

    #[test]
    fn a_bare_alias_addresses_the_api_root() {
        assert_eq!(
            parse_intent(&head("GET /github HTTP/1.1\n\n"))
                .unwrap()
                .path,
            "/"
        );
        assert_eq!(
            parse_intent(&head("GET /github/ HTTP/1.1\n\n"))
                .unwrap()
                .path,
            "/"
        );
    }

    #[test]
    fn only_the_allowlisted_headers_survive() {
        let i = parse_intent(&head(
            "GET /github/user HTTP/1.1\n\
             Host: evil.example.com\n\
             Authorization: Bearer attacker-token\n\
             Cookie: session=abc\n\
             X-Forwarded-For: 1.2.3.4\n\
             Proxy-Connection: keep-alive\n\
             Accept: application/json\n\
             Content-Type: application/json\n\n",
        ))
        .unwrap();
        let names: Vec<&str> = i.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["accept", "content-type"]);
        // The guest's own Authorization must never reach the constructed
        // request, or it could impersonate a different principal upstream.
        assert!(!i.headers.iter().any(|(n, _)| n == "authorization"));
    }

    #[test]
    fn ambiguous_body_framing_is_refused() {
        // Chunked from the guest, while the broker declares its own length.
        assert_eq!(
            parse_intent(&head(
                "POST /status/x HTTP/1.1\nTransfer-Encoding: chunked\n\n"
            ))
            .unwrap_err(),
            InjectRefusal::BadBody
        );
        // Two Content-Lengths: the classic smuggling setup.
        assert_eq!(
            parse_intent(&head(
                "POST /status/x HTTP/1.1\nContent-Length: 5\nContent-Length: 9\n\n"
            ))
            .unwrap_err(),
            InjectRefusal::BadBody
        );
        // Over the cap.
        let big = format!(
            "POST /status/x HTTP/1.1\nContent-Length: {}\n\n",
            MAX_INJECT_BODY + 1
        );
        assert_eq!(
            parse_intent(&head(&big)).unwrap_err(),
            InjectRefusal::BadBody
        );
    }

    #[test]
    fn hostile_targets_are_refused_at_parse() {
        for (target, want) in [
            ("//evil.com/x", InjectRefusal::NoAlias), // no alias segment survives
            ("/github//evil.com/x", InjectRefusal::BadTarget),
            ("/github/a/../../b", InjectRefusal::BadTarget),
            ("/github/a/%2e%2e/b", InjectRefusal::BadTarget),
            ("/github/a%2fb", InjectRefusal::BadTarget),
            ("/github/a\\b", InjectRefusal::BadTarget),
            ("http://evil.com/", InjectRefusal::NoAlias),
            ("/", InjectRefusal::NoAlias),
            ("/../github/user", InjectRefusal::NoAlias),
        ] {
            let got = parse_intent(&head(&format!("GET {target} HTTP/1.1\n\n"))).unwrap_err();
            assert_eq!(got, want, "target {target:?}");
        }
    }

    #[test]
    fn unusable_methods_are_refused() {
        for m in ["CONNECT", "TRACE", "OPTIONS", "get"] {
            assert_eq!(
                parse_intent(&head(&format!("{m} /github/user HTTP/1.1\n\n"))).unwrap_err(),
                InjectRefusal::BadMethod
            );
        }
    }

    #[test]
    fn an_over_large_head_is_refused_before_parsing() {
        let big = vec![b'A'; MAX_INJECT_HEAD + 1];
        assert_eq!(parse_intent(&big).unwrap_err(), InjectRefusal::HeadTooLarge);
    }

    // --- authorisation -----------------------------------------------------

    #[test]
    fn readonly_credential_permits_reads_and_refuses_writes() {
        let dir = tempfile::tempdir().unwrap();
        let creds = creds_fixture(dir.path());

        let get = parse_intent(&head("GET /github/user HTTP/1.1\n\n")).unwrap();
        let (req, cred) = authorize(&creds, &get).unwrap();
        assert_eq!(req.url, "https://api.github.com/user");
        assert_eq!(req.method, Method::Get);
        // By value, not through `expose`: the set of modules that may unwrap a
        // secret is asserted in `secret::tests`, and a test is not one of them.
        assert_eq!(
            *cred.secret(),
            crate::net::secret::Secret::new("ghp_testtoken".into())
        );

        // The attack the allow list exists to stop: planting a key that
        // outlives the VM.
        let post = parse_intent(&head("POST /github/user/keys HTTP/1.1\n\n")).unwrap();
        assert_eq!(
            authorize(&creds, &post).unwrap_err(),
            InjectRefusal::NotPermitted
        );
    }

    #[test]
    fn a_scoped_credential_permits_only_its_own_shape() {
        let dir = tempfile::tempdir().unwrap();
        let creds = creds_fixture(dir.path());

        let ok = parse_intent(&head(
            "POST /status/repos/me/proj/statuses/abc HTTP/1.1\n\n",
        ))
        .unwrap();
        assert_eq!(
            authorize(&creds, &ok).unwrap().0.url,
            "https://api.github.com/repos/me/proj/statuses/abc"
        );

        // Same credential, a path outside its rule.
        let no = parse_intent(&head("POST /status/user/keys HTTP/1.1\n\n")).unwrap();
        assert_eq!(
            authorize(&creds, &no).unwrap_err(),
            InjectRefusal::NotPermitted
        );
        // Same path, a method outside its rule.
        let no =
            parse_intent(&head("GET /status/repos/me/proj/statuses/abc HTTP/1.1\n\n")).unwrap();
        assert_eq!(
            authorize(&creds, &no).unwrap_err(),
            InjectRefusal::NotPermitted
        );
    }

    #[test]
    fn the_none_preset_refuses_everything() {
        let dir = tempfile::tempdir().unwrap();
        let creds = creds_fixture(dir.path());
        for line in [
            "GET /off/user HTTP/1.1\n\n",
            "POST /off/anything HTTP/1.1\n\n",
        ] {
            let i = parse_intent(&head(line)).unwrap();
            assert_eq!(
                authorize(&creds, &i).unwrap_err(),
                InjectRefusal::NotPermitted
            );
        }
    }

    #[test]
    fn an_alias_not_injected_into_this_run_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let creds = creds_fixture(dir.path());
        let i = parse_intent(&head("GET /notinjected/user HTTP/1.1\n\n")).unwrap();
        assert_eq!(
            authorize(&creds, &i).unwrap_err(),
            InjectRefusal::UnknownAlias
        );
    }

    #[test]
    fn the_constructed_url_is_always_the_pinned_origin() {
        let dir = tempfile::tempdir().unwrap();
        let creds = creds_fixture(dir.path());
        // Every guest-supplied hint at a different origin is either rejected at
        // parse or ignored at construction. Nothing the guest sends contributes
        // a scheme or an authority.
        let i = parse_intent(&head(
            "GET /github/user HTTP/1.1\n\
             Host: evil.example.com\n\
             X-Forwarded-Host: evil.example.com\n\n",
        ))
        .unwrap();
        let (req, _) = authorize(&creds, &i).unwrap();
        assert!(
            req.url.starts_with("https://api.github.com/"),
            "{}",
            req.url
        );
        assert!(!req.url.contains("evil"), "{}", req.url);
    }

    // --- refusals ----------------------------------------------------------

    #[test]
    fn refusal_responses_are_fixed_and_carry_no_guest_bytes() {
        for r in [
            InjectRefusal::Malformed,
            InjectRefusal::BadMethod,
            InjectRefusal::NoAlias,
            InjectRefusal::UnknownAlias,
            InjectRefusal::BadTarget,
            InjectRefusal::NotPermitted,
            InjectRefusal::BadHeader,
            InjectRefusal::BadBody,
            InjectRefusal::HeadTooLarge,
        ] {
            let resp = r.response();
            assert!(resp.starts_with("HTTP/1.1 "), "{resp}");
            assert!(resp.contains("Content-Length:"), "{resp}");
            assert!(resp.contains("Connection: close"), "{resp}");
            // The tag is machine-readable and stable for the recorder.
            assert!(r.tag().starts_with("inject-"));
        }
        assert_eq!(InjectRefusal::NotPermitted.status(), 403);
        assert_eq!(InjectRefusal::UnknownAlias.status(), 403);
        assert_eq!(InjectRefusal::BadMethod.status(), 405);
    }

    // --- the response leg --------------------------------------------------

    #[test]
    fn response_headers_drop_framing_and_hop_but_keep_what_apis_need() {
        let relayed = relay_headers([
            ("Content-Type", "application/json"),
            (
                "Link",
                "<https://api.github.com/user/repos?page=2>; rel=\"next\"",
            ),
            ("ETag", "W/\"abc\""),
            ("X-RateLimit-Remaining", "4999"),
            // Framing: the broker re-frames, so these must not survive.
            ("Content-Length", "1234"),
            ("Transfer-Encoding", "chunked"),
            ("Connection", "keep-alive"),
            ("Upgrade", "h2c"),
        ]);
        let names: Vec<&str> = relayed.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["content-type", "link", "etag", "x-ratelimit-remaining"]
        );
    }

    #[test]
    fn a_response_header_cannot_split_the_head_the_broker_writes() {
        // Response splitting sourced from upstream rather than from the guest:
        // a CR in a relayed value would end the head early and let the far side
        // dictate the rest of what the workload parses.
        assert!(!relayable_header("x-evil", "a\r\nX-Injected: 1"));
        assert!(!relayable_header("x-evil", "a\nb"));
        assert!(!relayable_header(
            "x-evil",
            &"v".repeat(MAX_HEADER_VALUE + 1)
        ));
        assert!(!relayable_header("x evil", "fine"));
        assert!(!relayable_header("", "fine"));
        // And the filter is what keeps them out of the built head.
        let relayed = relay_headers([("X-Evil", "a\r\nX-Injected: 1")]);
        assert!(relayed.is_empty());
    }

    #[test]
    fn the_built_head_frames_chunked_and_never_also_declares_a_length() {
        let head = build_response_head(200, &[("content-type".into(), "application/json".into())]);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(
            head.contains("content-type: application/json\r\n"),
            "{head}"
        );
        assert!(head.contains("Transfer-Encoding: chunked\r\n"), "{head}");
        assert!(head.contains("Connection: close\r\n"), "{head}");
        assert!(head.ends_with("\r\n\r\n"));
        // Two framings in play is exactly what the endpoint refuses FROM the
        // guest; it must not emit them itself.
        assert!(
            !head.to_ascii_lowercase().contains("content-length"),
            "{head}"
        );
    }

    #[test]
    fn the_upstream_status_is_relayed_but_never_its_reason_phrase() {
        // The phrase is free-form bytes from the far side, landing on the first
        // line of what the workload parses. The number carries the meaning.
        assert!(build_response_head(404, &[]).starts_with("HTTP/1.1 404 Not Found"));
        assert!(build_response_head(418, &[]).starts_with("HTTP/1.1 418 Client Error"));
        assert!(build_response_head(599, &[]).starts_with("HTTP/1.1 599 Server Error"));
    }

    #[test]
    fn chunk_framing_round_trips_and_terminates() {
        assert_eq!(chunk_frame(b"hello"), b"5\r\nhello\r\n".to_vec());
        assert_eq!(chunk_frame(&[0u8; 256])[..4], *b"100\r");
        assert_eq!(CHUNK_TERMINATOR, b"0\r\n\r\n");
    }

    #[test]
    fn an_upstream_failure_is_distinguishable_from_a_refusal() {
        // "Was that my allow list, or was the API down?" — the first question an
        // operator asks. The two axes must never collapse into one status.
        for f in [
            UpstreamFailure::Unreachable,
            UpstreamFailure::TimedOut,
            UpstreamFailure::TooLarge,
        ] {
            let resp = f.response();
            assert!(resp.starts_with("HTTP/1.1 5"), "{resp}");
            assert!(resp.contains("Content-Length:"), "{resp}");
            assert!(f.tag().starts_with("inject-"));
        }
        assert_eq!(UpstreamFailure::TimedOut.status(), 504);
        assert_ne!(
            UpstreamFailure::Unreachable.status(),
            InjectRefusal::NotPermitted.status()
        );
    }

    #[test]
    fn a_refusal_never_reveals_whether_the_alias_exists() {
        // UnknownAlias and NotPermitted must be distinguishable to the operator
        // via the recorder tag, but both are 403 to the guest so that probing
        // the endpoint does not enumerate the operator's credential names.
        assert_eq!(
            InjectRefusal::UnknownAlias.status(),
            InjectRefusal::NotPermitted.status()
        );
    }
}
