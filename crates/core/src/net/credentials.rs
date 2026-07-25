//! Host-side credential declaration: `~/.isopod/credentials.json`.
//!
//! # Why a run cannot name a secret
//!
//! An earlier design let the caller supply the secret inline
//! (`inject_bearer: {"host": "file:/home/u/.ssh/id_rsa"}`). Over MCP the caller
//! is a model whose context can be poisoned by the very code being sandboxed, so
//! that was an arbitrary-host-file read-and-exfiltrate primitive wearing a
//! credential's clothes.
//!
//! Here, **everything that matters is declared on the host**: which secret, where
//! it comes from, which host it may be sent to, and which requests it may
//! authorise. A run names an *alias*, and nothing else. There is deliberately no
//! way to express "use this token against that host" at call time.
//!
//! # Why the `allow` list is mandatory
//!
//! Stopping the guest from *reading* a token was never the hard part. The guest
//! still chooses the request the broker signs, so a credential scoped only by
//! host means "anything this token can do to that API" — including
//! `POST /user/keys`, which plants an attacker-held key that outlives the VM.
//!
//! Every credential therefore carries a non-empty `allow` list of method+path
//! rules. There is no default: a credential without one fails to load. Common
//! shapes have names ([`RequestRule::preset`]) so the ordinary case stays one
//! word, but the operator still has to say it — "I did not think about this" and
//! "I chose read-only" must not look identical in the file.
//!
//! ```jsonc
//! {
//!   "version": 1,
//!   "credentials": {
//!     "github":   { "host": "api.github.com", "scheme": "bearer",
//!                   "source": "env:GH_TOKEN", "allow": ["readonly"], "mcp": true },
//!     "statuses": { "host": "api.github.com", "scheme": "bearer",
//!                   "source": "file:/home/me/.secrets/gh",
//!                   "allow": ["POST /repos/*/*/statuses/*"] }
//!   }
//! }
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

use super::egress::SafeName;
use super::secret::Secret;

/// Schema version this build understands. An unrecognised version is a hard
/// error, never a best-effort parse — a half-understood credential file is a
/// security question, not a compatibility one.
pub const CREDENTIALS_VERSION: u32 = 1;

/// Largest `file:` source accepted. A credential is a token, not a payload; the
/// cap stops a mistyped path at a huge file (or a device) from pulling it into
/// memory.
const MAX_SOURCE_BYTES: u64 = 64 * 1024;

/// Basename of the credential store inside the isopod home.
pub const CREDENTIALS_FILE: &str = "credentials.json";

// ===========================================================================
// Who is asking.
// ===========================================================================

/// Who requested a credential, which decides how much a failure may say.
///
/// An operator at a terminal needs the specific reason. A model does not:
/// distinguishable "no such alias" and "that alias exists but you may not use
/// it" responses are an oracle for enumerating the operator's credential names.
/// Over MCP every refusal renders identically, and the detail goes to the host's
/// stderr where the operator can still read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// The CLI — the human who owns the file. Errors are specific.
    Operator,
    /// An MCP client. Errors are deliberately uniform.
    Model,
}

// ===========================================================================
// Errors.
// ===========================================================================

/// Why a credential could not be provided.
///
/// No variant carries a secret value or the contents of a `source`. That matters
/// for a mistake an operator will actually make: pasting a raw token into
/// `source` instead of `env:NAME`. Echoing the offending value would put the
/// token into stderr, the logs, and possibly a model's context.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredError {
    /// The store does not exist, but a run named an alias.
    #[error(
        "no credential store at {0}; create it (mode 0600) with a \"credentials\" \
         object before using --inject"
    )]
    NoStore(PathBuf),
    /// The store is readable by group or other.
    #[error(
        "credential store {path} is mode {mode:04o}; it must not be readable by \
         group or other. Fix with: chmod 600 {path}"
    )]
    BadMode { path: PathBuf, mode: u32 },
    /// The store is not a regular file — a symlink, FIFO, or device.
    #[error("credential store {0} is not a regular file")]
    NotRegular(PathBuf),
    /// The store could not be read or parsed.
    #[error("credential store {path} could not be read: {reason}")]
    Unreadable { path: PathBuf, reason: String },
    /// The store declares a version this build does not understand.
    #[error(
        "credential store declares version {found}, but this isopod understands \
         version {CREDENTIALS_VERSION}"
    )]
    BadVersion { found: u32 },
    /// A credential's declaration is malformed. Names the alias and the problem,
    /// never the offending value.
    #[error("credential {alias:?} is invalid: {problem}")]
    BadSpec { alias: String, problem: String },
    /// The alias is unusable — absent, not opted in for this caller, or its
    /// source did not resolve. Deliberately one variant: see [`Caller`].
    #[error(
        "credential {alias:?} is not available. Check that it exists in the \
         credential store, that its source resolves, and (for MCP callers) that \
         it is marked \"mcp\": true"
    )]
    Unavailable { alias: String },
    /// The same, rendered for a model: no alias, nothing to enumerate with.
    #[error(
        "the requested credential is not available to this caller. Credentials \
         are declared host-side and opted in explicitly by the operator"
    )]
    UnavailableOpaque,
}

impl CredError {
    /// Render for `caller`, collapsing anything alias-specific for a model.
    #[must_use]
    pub fn for_caller(self, caller: Caller) -> Self {
        match (caller, &self) {
            (Caller::Model, Self::Unavailable { .. }) => Self::UnavailableOpaque,
            _ => self,
        }
    }
}

// ===========================================================================
// Method + path rules.
// ===========================================================================

/// HTTP methods a credential may authorise. Closed on purpose: the token written
/// to the wire is this enum's `&'static str`, never bytes from the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
}

impl Method {
    /// Parse a method name, case-sensitively as it appears on the wire.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            _ => return None,
        })
    }

    /// The canonical token to put on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    /// Whether the method only reads, which is what the `readonly` preset means.
    #[must_use]
    pub fn is_safe(self) -> bool {
        matches!(self, Self::Get | Self::Head)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A path pattern: literal segments, `*` for exactly one segment, and a single
/// trailing `**` for any suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGlob {
    segments: Vec<String>,
    trailing: bool,
}

impl PathGlob {
    /// Parse a path pattern.
    ///
    /// # Errors
    /// If the pattern is not absolute, or contains a query, a percent escape, a
    /// backslash, a dot segment, an empty segment, or a partial-segment wildcard
    /// — each of which would make matching ambiguous against a normalised target.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if !raw.starts_with('/') {
            return Err(format!("path pattern {raw:?} must start with '/'"));
        }
        if raw.contains('?') || raw.contains('#') {
            return Err("path patterns match the path only, not a query or fragment".into());
        }
        if raw.contains('%') {
            return Err("path patterns must not contain percent-escapes".into());
        }
        if raw.contains('\\') {
            return Err("path patterns must not contain a backslash".into());
        }
        if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err("path patterns must be visible ASCII with no spaces".into());
        }

        let body = &raw[1..];
        let mut segments = Vec::new();
        let mut trailing = false;
        if !body.is_empty() {
            let parts: Vec<&str> = body.split('/').collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "**" {
                    if i + 1 != parts.len() {
                        return Err("'**' is only allowed as the final segment".into());
                    }
                    trailing = true;
                    break;
                }
                if part.is_empty() {
                    return Err("path patterns must not contain an empty segment".into());
                }
                if *part == "." || *part == ".." {
                    return Err("path patterns must not contain '.' or '..' segments".into());
                }
                if part.contains('*') && *part != "*" {
                    return Err("'*' must be a whole segment, not part of one".into());
                }
                segments.push((*part).to_string());
            }
        }
        Ok(Self { segments, trailing })
    }

    /// Whether an already-[normalised](normalize_target) path matches.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        let body = path.strip_prefix('/').unwrap_or(path);
        let actual: Vec<&str> = if body.is_empty() {
            Vec::new()
        } else {
            body.split('/').collect()
        };
        if self.trailing {
            if actual.len() < self.segments.len() {
                return false;
            }
        } else if actual.len() != self.segments.len() {
            return false;
        }
        self.segments
            .iter()
            .zip(actual.iter())
            .all(|(pat, got)| pat == "*" || pat == got)
    }
}

impl fmt::Display for PathGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.segments.join("/"))?;
        if self.trailing {
            f.write_str(if self.segments.is_empty() {
                "**"
            } else {
                "/**"
            })?;
        }
        Ok(())
    }
}

/// One permitted request shape: a set of methods and a path pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRule {
    methods: Vec<Method>,
    path: PathGlob,
}

impl RequestRule {
    /// Parse one `allow` entry: a preset name, or `"METHOD /path/glob"`.
    ///
    /// # Errors
    /// If the entry is neither a known preset nor a well-formed method+path pair.
    pub fn parse(raw: &str) -> Result<Vec<Self>, String> {
        let trimmed = raw.trim();
        if let Some(preset) = Self::preset(trimmed) {
            return Ok(preset);
        }
        let (method, path) = trimmed.split_once(' ').ok_or_else(|| {
            format!("allow entry {raw:?} must be \"METHOD /path\" or a preset name")
        })?;
        let parsed = Method::parse(method.trim()).ok_or_else(|| {
            format!(
                "allow entry {raw:?} names method {:?}, which is not one of \
                 GET HEAD POST PUT PATCH DELETE",
                method.trim()
            )
        })?;
        Ok(vec![Self {
            methods: vec![parsed],
            path: PathGlob::parse(path.trim())?,
        }])
    }

    /// Expand a preset name, or `None` if it is not one.
    #[must_use]
    pub fn preset(name: &str) -> Option<Vec<Self>> {
        match name {
            // Everything the token can read, nothing it can change.
            "readonly" => Some(vec![Self {
                methods: vec![Method::Get, Method::Head],
                path: PathGlob {
                    segments: Vec::new(),
                    trailing: true,
                },
            }]),
            // Deny everything: for asserting that the endpoint refuses, and for
            // disabling a credential without deleting its declaration.
            "none" => Some(Vec::new()),
            _ => None,
        }
    }

    /// Whether this rule permits `method` on an already-normalised `path`.
    #[must_use]
    pub fn permits(&self, method: Method, path: &str) -> bool {
        self.methods.contains(&method) && self.path.matches(path)
    }

    /// A printable form for the flight recorder and error text.
    #[must_use]
    pub fn display(&self) -> String {
        let methods: Vec<&str> = self.methods.iter().map(|m| m.as_str()).collect();
        format!("{} {}", methods.join("|"), self.path)
    }
}

/// Normalise a guest-supplied request target, or reject it.
///
/// This is the choke point that keeps a credentialled request on its pinned
/// origin. Everything rejected here is a way of writing a target that a naive
/// `base + path` join would relocate:
///
/// - `//evil.com/x` — scheme-relative; against a base it becomes `https://evil.com/x`.
/// - `/\evil.com`, `\\evil.com` — the same trick with backslashes, which several
///   URL parsers fold to `/`.
/// - `http://evil.com/`, `evil.com:443` — absolute-form and authority-form.
/// - `/a/../../b`, `/a/%2e%2e/b` — dot segments, encoded or not, climbing out of
///   the prefix an `allow` rule pinned.
/// - `%2f`, `%5c` — an encoded separator that would decode into a new segment
///   *after* the rule already matched.
///
/// The query is preserved verbatim: it cannot change the origin, and rewriting it
/// would break legitimate API calls.
///
/// # Errors
/// A short static reason, suitable for a fixed error body. Never echoes the input.
pub fn normalize_target(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Err("empty request target");
    }
    if !raw.starts_with('/') {
        return Err("request target must be origin-form, beginning with '/'");
    }
    if raw.starts_with("//") {
        return Err("request target must not begin with '//' (scheme-relative)");
    }
    if raw.as_bytes().get(1) == Some(&b'\\') {
        return Err("request target must not begin with '/\\'");
    }
    if raw.contains('\\') {
        return Err("request target must not contain a backslash");
    }
    if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("request target must be visible ASCII with no spaces or control bytes");
    }

    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };

    // Encoded separators and dot segments are rejected rather than decoded:
    // decoding would create segments after the allow rule had already matched.
    let lowered = path.to_ascii_lowercase();
    for enc in ["%2f", "%5c", "%2e"] {
        if lowered.contains(enc) {
            return Err("request target must not percent-encode '/', '\\' or '.'");
        }
    }
    if path.split('/').any(|s| s == "." || s == "..") {
        return Err("request target must not contain '.' or '..' segments");
    }
    if path.contains("//") {
        return Err("request target must not contain an empty segment");
    }

    Ok(match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    })
}

// ===========================================================================
// The on-disk store.
// ===========================================================================

/// How the secret is attached. Bearer only in 0.10.0 — each scheme is a distinct
/// way to build a header and deserves its own review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredScheme {
    /// `Authorization: Bearer <token>`.
    Bearer,
}

/// One credential as written in the file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialSpec {
    host: String,
    scheme: CredScheme,
    source: String,
    allow: Vec<String>,
    /// Whether an MCP caller may name this alias. Default-deny: a model should
    /// not reach a credential the operator has not deliberately shared with it.
    #[serde(default)]
    mcp: bool,
}

/// The whole file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialStore {
    version: u32,
    #[serde(default)]
    credentials: BTreeMap<String, CredentialSpec>,
}

/// The single host a credential may ever be sent to: an exact, normalised name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedHost(SafeName);

impl PinnedHost {
    /// The host name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The host as a [`SafeName`], for recording.
    #[must_use]
    pub fn name(&self) -> &SafeName {
        &self.0
    }
}

impl fmt::Display for PinnedHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// A credential with its secret resolved and its rules parsed — the only form the
/// broker ever sees.
///
/// There is no way to build one without a [`Secret`], so a pinned host can never
/// exist without a token behind it. That is what stops a half-failed resolution
/// from leaving a destination reachable but unauthenticated.
#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    alias: SafeName,
    host: PinnedHost,
    scheme: CredScheme,
    allow: Vec<RequestRule>,
    secret: Secret,
}

impl ResolvedCredential {
    /// The alias this credential was named by.
    #[must_use]
    pub fn alias(&self) -> &SafeName {
        &self.alias
    }

    /// The single host this credential may be sent to.
    #[must_use]
    pub fn host(&self) -> &PinnedHost {
        &self.host
    }

    /// The scheme used to build the header.
    #[must_use]
    pub fn scheme(&self) -> CredScheme {
        self.scheme
    }

    /// The permitted request shapes, for reporting.
    #[must_use]
    pub fn allow(&self) -> &[RequestRule] {
        &self.allow
    }

    /// Whether `method` on an already-normalised `path` is permitted.
    #[must_use]
    pub fn permits(&self, method: Method, path: &str) -> bool {
        self.allow.iter().any(|r| r.permits(method, path))
    }

    /// The secret, for the one call site that writes the header.
    #[must_use]
    pub fn secret(&self) -> &Secret {
        &self.secret
    }
}

/// Resolve every named alias, or fail without resolving any.
///
/// All-or-nothing on purpose. A partial success would let a run proceed believing
/// it holds a credential it does not — and, before the pinned host was removed
/// from the guest allowlist, would have left that host reachable *without*
/// authentication.
///
/// An empty `required` returns `Ok(vec![])` with **zero I/O**: a host with no
/// credential store must keep working for every run that does not ask for one.
///
/// # Errors
/// [`CredError`], already rendered for `caller`.
pub fn load_credentials(
    required: &[String],
    caller: Caller,
    store_path: &Path,
) -> Result<Vec<ResolvedCredential>, CredError> {
    if required.is_empty() {
        return Ok(Vec::new());
    }
    let store = read_store(store_path)?;
    let mut out = Vec::with_capacity(required.len());
    for alias in required {
        out.push(resolve_one(alias, &store, caller, store_path)?);
    }
    Ok(out)
}

/// Read, mode-check and parse the store.
fn read_store(path: &Path) -> Result<CredentialStore, CredError> {
    // symlink_metadata, not metadata: a world-writable symlink pointing at a
    // 0600 file must not pass by inheriting the target's bits.
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CredError::NoStore(path.to_path_buf())
        } else {
            CredError::Unreadable {
                path: path.to_path_buf(),
                reason: e.kind().to_string(),
            }
        }
    })?;
    if !meta.file_type().is_file() {
        // Rejects symlinks, FIFOs and devices alike: a FIFO would block the
        // read, and a device could be unbounded.
        return Err(CredError::NotRegular(path.to_path_buf()));
    }
    use std::os::unix::fs::PermissionsExt as _;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CredError::BadMode {
            path: path.to_path_buf(),
            mode,
        });
    }
    if meta.len() > MAX_SOURCE_BYTES {
        return Err(CredError::Unreadable {
            path: path.to_path_buf(),
            reason: format!("larger than {MAX_SOURCE_BYTES} bytes"),
        });
    }
    let raw = std::fs::read_to_string(path).map_err(|e| CredError::Unreadable {
        path: path.to_path_buf(),
        reason: e.kind().to_string(),
    })?;
    // Report the parse failure by position, never by content: serde's message
    // quotes the offending value, which in this file could be a token.
    let store: CredentialStore = serde_json::from_str(&raw).map_err(|e| CredError::Unreadable {
        path: path.to_path_buf(),
        reason: format!("malformed JSON at line {}, column {}", e.line(), e.column()),
    })?;
    if store.version != CREDENTIALS_VERSION {
        return Err(CredError::BadVersion {
            found: store.version,
        });
    }
    Ok(store)
}

/// Resolve one alias into a usable credential.
fn resolve_one(
    alias: &str,
    store: &CredentialStore,
    caller: Caller,
    store_path: &Path,
) -> Result<ResolvedCredential, CredError> {
    let unavailable = || {
        CredError::Unavailable {
            alias: alias.to_string(),
        }
        .for_caller(caller)
    };

    let Some(spec) = store.credentials.get(alias) else {
        note_operator(caller, alias, "no such alias in the credential store");
        return Err(unavailable());
    };
    if caller == Caller::Model && !spec.mcp {
        note_operator(
            caller,
            alias,
            "exists but is not opted in for MCP callers (set \"mcp\": true)",
        );
        return Err(unavailable());
    }

    let alias_name = SafeName::parse(alias).map_err(|_| CredError::BadSpec {
        alias: alias.to_string(),
        problem: "alias is not a well-formed name".into(),
    })?;
    if spec.host.contains('*') {
        return Err(CredError::BadSpec {
            alias: alias.to_string(),
            problem: "\"host\" must be an exact name; wildcards are not accepted".into(),
        });
    }
    let host = SafeName::parse(&spec.host).map_err(|_| CredError::BadSpec {
        alias: alias.to_string(),
        problem: "\"host\" is not a well-formed host name (exact name, no wildcard, no port)"
            .into(),
    })?;

    // `allow` is mandatory. `["none"]` is how you say "deny everything".
    if spec.allow.is_empty() {
        return Err(CredError::BadSpec {
            alias: alias.to_string(),
            problem: "\"allow\" is required and must not be empty; use [\"readonly\"] for \
                      GET+HEAD, [\"none\"] to deny everything, or explicit \
                      \"METHOD /path\" entries"
                .into(),
        });
    }
    let mut allow = Vec::new();
    for entry in &spec.allow {
        allow.extend(
            RequestRule::parse(entry).map_err(|problem| CredError::BadSpec {
                alias: alias.to_string(),
                problem,
            })?,
        );
    }

    let secret = resolve_source(&spec.source, alias, store_path).map_err(|why| {
        note_operator(caller, alias, &why);
        unavailable()
    })?;

    Ok(ResolvedCredential {
        alias: alias_name,
        host: PinnedHost(host),
        scheme: spec.scheme,
        allow,
        secret,
    })
}

/// Resolve `env:NAME` or `file:/abs/path` into a secret.
///
/// None of these messages includes the source *value*: an operator who pastes a
/// raw token into `source` by mistake must not have it echoed back.
fn resolve_source(source: &str, alias: &str, store_path: &Path) -> Result<Secret, String> {
    let secret = if let Some(name) = source.strip_prefix("env:") {
        if name.is_empty() {
            return Err("\"source\" is \"env:\" with no variable name".into());
        }
        let value = std::env::var(name)
            .map_err(|_| format!("environment variable {name} is unset or not valid UTF-8"))?;
        Secret::new(value)
    } else if let Some(path) = source.strip_prefix("file:") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("\"source\" file path must be absolute".into());
        }
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("source file could not be read: {}", e.kind()))?;
        if !meta.file_type().is_file() {
            return Err("source file is not a regular file".into());
        }
        if meta.len() > MAX_SOURCE_BYTES {
            return Err(format!(
                "source file is larger than {MAX_SOURCE_BYTES} bytes"
            ));
        }
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "source file is mode {mode:04o}; it must not be readable by group or other"
            ));
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("source file could not be read: {}", e.kind()))?;
        // A token in a file almost always ends in a newline, and sending that in
        // a header is a request-splitting hazard.
        Secret::new(raw.trim_end_matches(['\n', '\r']).to_string())
    } else {
        // Deliberately vague: if the operator pasted a literal token here, this
        // message must not repeat it.
        return Err(format!(
            "\"source\" must begin with \"env:\" or \"file:\" (see {})",
            store_path.display()
        ));
    };

    if secret.is_blank() {
        return Err("resolved credential is empty".into());
    }
    if secret.has_illegal_header_bytes() {
        return Err(format!(
            "resolved credential for {alias:?} contains bytes that cannot appear in an \
             HTTP header (a newline or control character); check for a stray line break"
        ));
    }
    Ok(secret)
}

/// Put the specific reason on the host's stderr when the caller is a model, so
/// the operator can still diagnose what the model was not told.
fn note_operator(caller: Caller, alias: &str, reason: &str) {
    if caller == Caller::Model {
        eprintln!("credential {alias:?} refused to an MCP caller: {reason}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn write_store(dir: &Path, body: &str, mode: u32) -> PathBuf {
        let p = dir.join(CREDENTIALS_FILE);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    const GOOD: &str = r#"{
      "version": 1,
      "credentials": {
        "github":   {"host":"api.github.com","scheme":"bearer","source":"env:ISOPOD_TEST_TOK","allow":["readonly"],"mcp":true},
        "deploykey": {"host":"api.github.com","scheme":"bearer","source":"env:ISOPOD_TEST_TOK","allow":["POST /repos/*/*/statuses/*"]}
      }
    }"#;

    // --- Method + PathGlob -------------------------------------------------

    #[test]
    fn methods_round_trip_and_reject_junk() {
        for m in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(Method::parse(m).unwrap().as_str(), m);
        }
        // Case-sensitive: accepting "get" would mean the matched rule's canonical
        // wire token differed from what the operator wrote.
        assert!(Method::parse("get").is_none());
        assert!(Method::parse("CONNECT").is_none());
        assert!(Method::parse("TRACE").is_none());
        assert!(Method::parse("").is_none());
        assert!(Method::Get.is_safe() && Method::Head.is_safe());
        assert!(!Method::Post.is_safe() && !Method::Delete.is_safe());
    }

    #[test]
    fn path_glob_star_is_exactly_one_segment() {
        let g = PathGlob::parse("/repos/*/*").unwrap();
        assert!(g.matches("/repos/me/proj"));
        assert!(!g.matches("/repos/me"), "too few segments");
        assert!(!g.matches("/repos/me/proj/issues"), "too many segments");
        assert!(!g.matches("/orgs/me/proj"), "literal must match");
    }

    #[test]
    fn path_glob_double_star_is_any_suffix() {
        let g = PathGlob::parse("/repos/*/*/contents/**").unwrap();
        assert!(g.matches("/repos/me/proj/contents/a"));
        assert!(g.matches("/repos/me/proj/contents/a/b/c"));
        assert!(g.matches("/repos/me/proj/contents"), "** may match nothing");
        assert!(!g.matches("/repos/me/proj/issues/a"));

        let root = PathGlob::parse("/**").unwrap();
        assert!(root.matches("/"));
        assert!(root.matches("/anything/at/all"));
    }

    #[test]
    fn path_glob_rejects_ambiguous_patterns() {
        for bad in [
            "repos/*", "/a/**/b", "/a//b", "/a/../b", "/a/./b", "/a%2fb", "/a?x=1", "/a#f",
            "/a\\b", "/pre*fix",
        ] {
            assert!(PathGlob::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    // --- request-target normalisation: the origin-pinning choke point -------

    #[test]
    fn normalize_target_rejects_every_origin_relocation() {
        // The ledger from the red team. Each of these, joined naively against a
        // pinned base URL, sends the credential somewhere else.
        for bad in [
            "//evil.com/x",
            "///evil.com/x",
            "/\\evil.com/x",
            "\\\\evil.com/x",
            "/a\\b",
            "http://evil.com/",
            "https://evil.com/",
            "evil.com:443",
            "/a/../../b",
            "/a/%2e%2e/b",
            "/a/%2E%2E/b",
            "/a%2fb",
            "/a%5Cb",
            "/a//b",
            "",
            "/a b",
            "/a\u{7}b",
        ] {
            assert!(
                normalize_target(bad).is_err(),
                "{bad:?} must not normalise to a usable target"
            );
        }
    }

    #[test]
    fn normalize_target_accepts_and_preserves_ordinary_paths() {
        assert_eq!(normalize_target("/user").unwrap(), "/user");
        assert_eq!(normalize_target("/").unwrap(), "/");
        // A query cannot change the origin, and rewriting it would break real
        // API calls, so it is preserved verbatim.
        assert_eq!(
            normalize_target("/search?q=a+b&sort=x").unwrap(),
            "/search?q=a+b&sort=x"
        );
        assert_eq!(normalize_target("/s?q=%41").unwrap(), "/s?q=%41");
    }

    // --- rules + presets ---------------------------------------------------

    #[test]
    fn readonly_preset_is_safe_methods_any_path() {
        let rules = RequestRule::preset("readonly").unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].permits(Method::Get, "/user"));
        assert!(rules[0].permits(Method::Head, "/repos/a/b/contents/deep/path"));
        // The whole point: no state change, whatever else the token could do.
        assert!(!rules[0].permits(Method::Post, "/user/keys"));
        assert!(!rules[0].permits(Method::Delete, "/repos/a/b"));
        assert_eq!(rules[0].display(), "GET|HEAD /**");
    }

    #[test]
    fn none_preset_denies_everything() {
        assert!(RequestRule::preset("none").unwrap().is_empty());
        assert!(RequestRule::preset("nonsense").is_none());
    }

    #[test]
    fn explicit_rules_parse_and_scope() {
        let rules = RequestRule::parse("POST /repos/*/*/statuses/*").unwrap();
        assert!(rules[0].permits(Method::Post, "/repos/me/proj/statuses/abc123"));
        assert!(!rules[0].permits(Method::Get, "/repos/me/proj/statuses/abc123"));
        assert!(!rules[0].permits(Method::Post, "/user/keys"));
        assert!(RequestRule::parse("BREW /coffee").is_err());
        assert!(RequestRule::parse("GET").is_err());
        assert!(RequestRule::parse("GET relative").is_err());
    }

    // --- store loading -----------------------------------------------------

    #[test]
    fn empty_request_does_no_io_at_all() {
        // A host with no credential store must keep working for every run that
        // does not ask for one — even pointed at a path that does not exist.
        let missing = Path::new("/nonexistent/isopod/credentials.json");
        assert!(load_credentials(&[], Caller::Operator, missing)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn missing_store_errors_only_when_an_alias_is_named() {
        let missing = Path::new("/nonexistent/isopod/credentials.json");
        let err = load_credentials(&["github".into()], Caller::Operator, missing).unwrap_err();
        assert!(matches!(err, CredError::NoStore(_)), "{err}");
    }

    #[test]
    fn permissive_mode_is_refused_with_the_fix_in_the_message() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_store(dir.path(), GOOD, 0o644);
        std::env::set_var("ISOPOD_TEST_TOK", "tok");
        let err = load_credentials(&["github".into()], Caller::Operator, &p).unwrap_err();
        match &err {
            CredError::BadMode { mode, .. } => assert_eq!(*mode, 0o644),
            other => panic!("expected BadMode, got {other}"),
        }
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }

    #[test]
    fn a_symlinked_store_is_refused_even_when_its_target_is_locked_down() {
        // The mode check must inspect the link, not the target — otherwise an
        // attacker-writable symlink to a 0600 file passes.
        let dir = tempfile::tempdir().unwrap();
        let real = write_store(dir.path(), GOOD, 0o600);
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        std::env::set_var("ISOPOD_TEST_TOK", "tok");
        let err = load_credentials(&["github".into()], Caller::Operator, &link).unwrap_err();
        assert!(matches!(err, CredError::NotRegular(_)), "{err}");
    }

    #[test]
    fn version_and_unknown_keys_are_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("ISOPOD_TEST_TOK", "tok");

        let p = write_store(
            dir.path(),
            &GOOD.replace("\"version\": 1", "\"version\": 2"),
            0o600,
        );
        assert!(matches!(
            load_credentials(&["github".into()], Caller::Operator, &p).unwrap_err(),
            CredError::BadVersion { found: 2 }
        ));

        // A typo in this file is a security question ("did my allow list
        // apply?"), so an unknown key must not be silently ignored.
        let typo = GOOD.replace("\"allow\":[\"readonly\"]", "\"alow\":[\"readonly\"]");
        let p = write_store(dir.path(), &typo, 0o600);
        assert!(load_credentials(&["github".into()], Caller::Operator, &p).is_err());
    }

    #[test]
    fn allow_is_mandatory_and_the_error_names_the_way_out() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("ISOPOD_TEST_TOK", "tok");
        let body = r#"{"version":1,"credentials":{"x":{"host":"a.example","scheme":"bearer","source":"env:ISOPOD_TEST_TOK","allow":[]}}}"#;
        let p = write_store(dir.path(), body, 0o600);
        let err = load_credentials(&["x".into()], Caller::Operator, &p).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("\"allow\" is required"), "{msg}");
        assert!(msg.contains("readonly"), "must name the easy option: {msg}");
        assert!(msg.contains("none"), "{msg}");
    }

    #[test]
    fn model_callers_are_default_denied_and_cannot_enumerate() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("ISOPOD_TEST_TOK", "tok");
        let p = write_store(dir.path(), GOOD, 0o600);

        // "deploykey" exists but is not opted in for MCP.
        let denied = load_credentials(&["deploykey".into()], Caller::Model, &p).unwrap_err();
        // A name that does not exist at all.
        let absent = load_credentials(&["nosuchalias".into()], Caller::Model, &p).unwrap_err();
        assert_eq!(
            denied.to_string(),
            absent.to_string(),
            "a model must not be able to tell an existing alias from an absent one"
        );
        assert!(!denied.to_string().contains("deploykey"), "no alias echoed");

        // The operator gets a specific message naming the alias.
        let op = load_credentials(&["nosuchalias".into()], Caller::Operator, &p).unwrap_err();
        assert!(op.to_string().contains("nosuchalias"), "{op}");

        // And an opted-in alias works for a model.
        let ok = load_credentials(&["github".into()], Caller::Model, &p).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].host().as_str(), "api.github.com");
    }

    #[test]
    fn resolution_is_all_or_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("ISOPOD_TEST_TOK", "tok");
        let p = write_store(dir.path(), GOOD, 0o600);
        // One good alias, one absent: the whole call fails, so a run can never
        // proceed holding a partial set.
        let err = load_credentials(
            &["github".into(), "nosuchalias".into()],
            Caller::Operator,
            &p,
        )
        .unwrap_err();
        assert!(matches!(err, CredError::Unavailable { .. }), "{err}");
    }

    #[test]
    fn an_unset_env_source_fails_rather_than_yielding_an_empty_token() {
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var("ISOPOD_TEST_ABSENT");
        let body = r#"{"version":1,"credentials":{"x":{"host":"a.example","scheme":"bearer","source":"env:ISOPOD_TEST_ABSENT","allow":["readonly"]}}}"#;
        let p = write_store(dir.path(), body, 0o600);
        assert!(load_credentials(&["x".into()], Caller::Operator, &p).is_err());
    }

    #[test]
    fn a_file_source_is_trimmed_of_its_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let tok = dir.path().join("tok");
        std::fs::write(&tok, "ghp_abc123\n").unwrap();
        std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o600)).unwrap();
        let body = format!(
            r#"{{"version":1,"credentials":{{"x":{{"host":"a.example","scheme":"bearer","source":"file:{}","allow":["readonly"]}}}}}}"#,
            tok.display()
        );
        let p = write_store(dir.path(), &body, 0o600);
        let creds = load_credentials(&["x".into()], Caller::Operator, &p).unwrap();
        // The newline would otherwise split the header the broker builds.
        assert_eq!(creds[0].secret().expose(), "ghp_abc123");
    }

    #[test]
    fn a_pasted_raw_token_is_never_echoed_back() {
        // The operator mistake this guards: writing the token itself into
        // "source" instead of env:/file:. Echoing it would put the token into
        // stderr, the logs, and possibly a model's context.
        let dir = tempfile::tempdir().unwrap();
        let body = r#"{"version":1,"credentials":{"x":{"host":"a.example","scheme":"bearer","source":"ghp_SUPERSECRETVALUE","allow":["readonly"]}}}"#;
        let p = write_store(dir.path(), body, 0o600);
        let err = load_credentials(&["x".into()], Caller::Operator, &p).unwrap_err();
        assert!(
            !err.to_string().contains("ghp_SUPERSECRETVALUE"),
            "the pasted value must not appear in the error: {err}"
        );
    }

    #[test]
    fn a_credential_containing_a_newline_is_refused_at_load() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("ISOPOD_TEST_CRLF", "tok\r\nX-Injected: 1");
        let body = r#"{"version":1,"credentials":{"x":{"host":"a.example","scheme":"bearer","source":"env:ISOPOD_TEST_CRLF","allow":["readonly"]}}}"#;
        let p = write_store(dir.path(), body, 0o600);
        // Header injection sourced from configuration rather than from the guest.
        assert!(load_credentials(&["x".into()], Caller::Operator, &p).is_err());
        std::env::remove_var("ISOPOD_TEST_CRLF");
    }

    #[test]
    fn a_wildcard_host_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("ISOPOD_TEST_TOK", "tok");
        let body = r#"{"version":1,"credentials":{"x":{"host":"*.github.com","scheme":"bearer","source":"env:ISOPOD_TEST_TOK","allow":["readonly"]}}}"#;
        let p = write_store(dir.path(), body, 0o600);
        let err = load_credentials(&["x".into()], Caller::Operator, &p).unwrap_err();
        assert!(err.to_string().contains("exact name"), "{err}");
    }

    #[test]
    fn resolved_credential_permits_only_its_declared_shapes() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("ISOPOD_TEST_TOK", "tok");
        let p = write_store(dir.path(), GOOD, 0o600);
        let creds = load_credentials(&["deploykey".into()], Caller::Operator, &p).unwrap();
        let c = &creds[0];
        assert!(c.permits(Method::Post, "/repos/me/proj/statuses/sha"));
        // The attack the allow list exists to stop.
        assert!(!c.permits(Method::Post, "/user/keys"));
        assert!(!c.permits(Method::Get, "/user"));
        assert_eq!(c.alias().as_str(), "deploykey");
    }
}
