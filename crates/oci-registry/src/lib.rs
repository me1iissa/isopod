//! Pull an OCI image from a registry into a local image layout.
//!
//! This crate is the network half of an image import, and it is deliberately
//! *only* that: it fetches bytes and writes them into a directory that
//! [`isopod_oci_unpack::layout`] then reads. Nothing here interprets a layer,
//! and nothing here writes outside the layout directory it was given.
//!
//! # The split, and why it is where it is
//!
//! `isopod-oci-unpack` exists to be attacked with no network in it at all. Its
//! wave was finished, reviewed and mutation-tested before this crate was
//! written, so a defect here cannot be excused as "the extractor will catch it"
//! — the extractor's guarantees were established independently and are not
//! weakened by anything below.
//!
//! What this crate must get right is narrower, and is not about tar:
//!
//! - **A credential never crosses an origin.** Registries redirect blob
//!   downloads to object storage as the ordinary path, so forwarding
//!   `Authorization` through a redirect would hand a registry token to whatever
//!   host the registry named. See [`auth::may_carry_credential`].
//! - **Nothing the registry names can be aimed at the host's own network.** The
//!   publisher of an image chooses where a blob fetch is redirected *and* which
//!   token realm a challenge names. Digest verification stops them injecting
//!   content; it does not stop the request, and a request to `169.254.169.254`
//!   is an SSRF from the operator's machine — with a credential attached, in the
//!   realm's case. One predicate governs both: [`auth::destination_is_allowed`].
//!   It judges the URL, and [`auth::FlooredResolver`] judges what a name in that
//!   URL resolves to — every address it answers with, at the moment the
//!   connector asks, so the address that is checked is the address that is
//!   dialled. A name is otherwise a way to write `169.254.169.254` that no
//!   amount of reading the string can catch.
//! - **A credential belongs to the registry it was stored for.** The Docker Hub
//!   entry in `~/.docker/config.json` authenticates to Docker Hub and to nothing
//!   else, and no credential is sent to a host reached by redirect.
//! - **Every blob is verified against the digest that named it, and nothing is
//!   written under a name it does not hash to.** A blob is streamed to a
//!   temporary file, hashed as it goes, and only then renamed to its
//!   content-addressed name — so a partial or altered download can never be
//!   picked up by the reader as a valid blob.
//! - **A reference is parsed once.** `localhost:5000/nginx` names a port, not a
//!   tag; `alpine` means `docker.io/library/alpine:latest`. See
//!   [`reference::Reference`].

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod reference;

#[cfg(test)]
mod registry_tests;

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use isopod_oci_unpack::digest::Digest;
use url::Url;

use crate::auth::Challenge;
use crate::reference::{Reference, Want};

/// Media types this client will accept for a manifest or an index, in the order
/// a registry should prefer them.
const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
                      application/vnd.oci.image.manifest.v1+json, \
                      application/vnd.docker.distribution.manifest.list.v2+json, \
                      application/vnd.docker.distribution.manifest.v2+json";

/// Ceiling on a manifest or index document.
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// Ceiling on one layer blob. The extractor has its own, on what a layer
/// *expands* to; this one is on what is downloaded, so a hostile registry
/// cannot fill the disk before anything has been unpacked.
const MAX_BLOB_BYTES: u64 = 16 << 30;

/// How many redirects a single blob fetch may follow.
const MAX_REDIRECTS: usize = 5;

/// How long any one request may take to produce headers.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a pull failed.
#[derive(Debug)]
pub enum PullError {
    /// The reference could not be parsed.
    Reference(reference::ReferenceError),
    /// The registry's authentication challenge was unusable.
    Challenge(auth::ChallengeError),
    /// A transport-level failure.
    Transport {
        /// What was being fetched.
        what: String,
        /// The underlying error.
        detail: String,
    },
    /// The registry answered with a status this client cannot use.
    Status {
        /// What was being fetched.
        what: String,
        /// The HTTP status.
        status: u16,
        /// The registry's own message, when it sent a usable one.
        detail: String,
    },
    /// The registry host itself is somewhere this client will not dial.
    Destination {
        /// The host, as it was written.
        host: String,
        /// Why it was refused.
        detail: String,
    },
    /// A redirect went somewhere this client will not follow.
    Redirect {
        /// Where it pointed.
        to: String,
        /// Why it was refused.
        detail: String,
    },
    /// A blob's bytes do not hash to the digest that named it.
    DigestMismatch {
        /// What was asked for.
        expected: String,
        /// What arrived.
        actual: String,
    },
    /// Something exceeded a ceiling.
    TooLarge {
        /// What was being fetched.
        what: String,
        /// The ceiling.
        cap: u64,
        /// What it claimed or reached.
        actual: u64,
    },
    /// A local file operation failed.
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        detail: String,
    },
}

impl fmt::Display for PullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reference(e) => write!(f, "{e}"),
            Self::Challenge(e) => write!(f, "{e}"),
            Self::Transport { what, detail } => write!(f, "fetching {what} failed: {detail}"),
            Self::Status {
                what,
                status,
                detail,
            } => {
                write!(f, "the registry answered {status} for {what}")?;
                if !detail.is_empty() {
                    write!(f, ": {detail}")?;
                }
                if *status == 401 || *status == 403 {
                    write!(
                        f,
                        ". If the image is private, isopod reads `~/.docker/config.json` \
                         — log in with `docker login` (the credential store is for \
                         guest runs and deliberately does not hold registry secrets)."
                    )?;
                }
                Ok(())
            }
            Self::Destination { host, detail } => write!(
                f,
                "the registry {host} is not somewhere isopod will dial: {detail}"
            ),
            Self::Redirect { to, detail } => write!(
                f,
                "the registry redirected to {to}, which isopod will not follow: \
                 {detail}. A registry chooses its own redirect targets, so this \
                 request would be one the image's publisher aimed."
            ),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "a downloaded blob does not match the digest that named it: asked \
                 for {expected}, received bytes hashing to sha256:{actual}. \
                 Nothing was kept."
            ),
            Self::TooLarge { what, cap, actual } => write!(
                f,
                "{what} is {actual} bytes, over the {cap}-byte ceiling for what it is."
            ),
            Self::Io { path, detail } => write!(f, "{}: {detail}", path.display()),
        }
    }
}

impl std::error::Error for PullError {}

impl From<reference::ReferenceError> for PullError {
    fn from(e: reference::ReferenceError) -> Self {
        Self::Reference(e)
    }
}

impl From<auth::ChallengeError> for PullError {
    fn from(e: auth::ChallengeError) -> Self {
        Self::Challenge(e)
    }
}

/// What a pull produced.
#[derive(Debug, Clone)]
pub struct Pulled {
    /// The layout directory the image was written into.
    pub layout: PathBuf,
    /// The digest the reference actually resolved to — the thing to record,
    /// because a tag is not stable and this is.
    pub manifest_digest: Digest,
    /// Bytes downloaded, blobs already present excluded.
    pub bytes_downloaded: u64,
    /// Blobs that were already in the layout and so were not fetched again.
    pub blobs_reused: usize,
}

/// A registry client for one reference.
pub struct Puller {
    reference: Reference,
    http: reqwest::blocking::Client,
    token: Option<String>,
    basic: Option<String>,
}

impl fmt::Debug for Puller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never derive this: a token in a panic message or a log line is a
        // leaked credential, and `Debug` is the easiest way for one to get out.
        f.debug_struct("Puller")
            .field("reference", &self.reference)
            .field("authenticated", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

impl Puller {
    /// Build a client for `reference`.
    ///
    /// See `http_client` for what the client does and does not decide for
    /// itself: redirects are followed by hand, and every name it dials is
    /// resolved through the destination floor.
    ///
    /// # Errors
    /// [`PullError::Reference`] if the reference does not parse,
    /// [`PullError::Destination`] if the reference names an address this client
    /// will not dial, or [`PullError::Transport`] if the HTTP client cannot be
    /// built.
    pub fn new(reference: &str) -> Result<Self, PullError> {
        let reference = Reference::parse(reference)?;
        let http = http_client(reference.is_local())?;
        let basic = docker_config_auth(&reference);
        let puller = Self {
            reference,
            http,
            token: None,
            basic,
        };
        puller.refuse_a_floored_literal_host()?;
        Ok(puller)
    }

    /// The reference this client was built for.
    #[must_use]
    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    /// The base URL for this registry's `/v2/` API.
    fn base(&self) -> String {
        let scheme = if self.reference.is_local() {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{}", self.reference.host())
    }

    /// Refuse a registry host that is an address the floor blocks.
    ///
    /// A registry named by *name* is floored when [`auth::FlooredResolver`]
    /// resolves it, but an address literal never reaches a resolver at all: the
    /// connector parses the authority as an address and dials it. So
    /// `isopod image import 169.254.169.254/x/y` would issue a request to the
    /// cloud metadata endpoint past a floor that stops the identical
    /// destination the moment a name leads to it — and this is the only place
    /// it can be caught. The guest broker has the same asymmetry and the same
    /// answer for a credential's pinned host.
    ///
    /// Judged through `url`, which is the parser that will dial it, so a
    /// spelling this disagrees with cannot be the spelling that connects.
    fn refuse_a_floored_literal_host(&self) -> Result<(), PullError> {
        let base = self.base();
        let host = Url::parse(&base)
            .map_err(|e| PullError::Destination {
                host: self.reference.host().to_string(),
                detail: format!("it is not a URL: {e}"),
            })?
            .host()
            .map(|h| match h {
                url::Host::Domain(d) => Ok(d.to_string()),
                url::Host::Ipv4(ip) => Err(std::net::IpAddr::V4(ip)),
                url::Host::Ipv6(ip) => Err(std::net::IpAddr::V6(ip)),
            });
        let Some(Err(ip)) = host else {
            return Ok(()); // a name, or no host at all: the resolver's problem
        };
        if auth::address_is_allowed(ip, self.reference.is_local()) {
            return Ok(());
        }
        Err(PullError::Destination {
            host: self.reference.host().to_string(),
            detail: format!(
                "{ip} is loopback, link-local (the cloud metadata endpoint lives \
                 there), a private or carrier-NAT range, or otherwise not a \
                 public address. An address written into the reference is dialled \
                 directly rather than resolved, so it would bypass the check a \
                 registry named by hostname goes through; the import is refused \
                 instead. A registry on your own machine is reachable as \
                 `localhost:<port>`, which isopod treats as your decision"
            ),
        })
    }
}

/// The HTTP client every request in a pull goes through.
///
/// Redirects are followed by hand rather than by the client, so where a
/// credential may travel and where a request may be aimed stay this crate's
/// decisions rather than a library default that could change.
///
/// The resolver is the other half of that: with [`auth::FlooredResolver`]
/// installed, the connector asks *it* for an address and dials what it gets
/// back, which is the same act as the check. `resolve`/`resolve_to_addrs` pin
/// just as firmly but take their map when the client is built, and the hosts a
/// pull dials are not all known then — a redirect target and a token realm
/// arrive mid-pull, in the registry's own text — so covering them that way
/// would mean a new client, and a new connection pool, at every hop.
///
/// The environment's proxy settings are still honoured, and they are the one
/// way past the resolver: a proxied request hands the *host* to the proxy in a
/// `CONNECT` and the proxy resolves it, so nothing resolves on this machine for
/// the floor to judge. Refusing to import through a proxy would break the
/// operators who need one to reach a registry at all, so it stays, and
/// `SECURITY.md` says so rather than claiming a floor that has a hole in it.
fn http_client(allow_local: bool) -> Result<reqwest::blocking::Client, PullError> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("isopod/", env!("CARGO_PKG_VERSION")))
        .dns_resolver(std::sync::Arc::new(auth::FlooredResolver::new(allow_local)))
        .build()
        .map_err(|e| PullError::Transport {
            what: "the HTTP client".into(),
            detail: transport_detail(&e),
        })
}

/// A `reqwest` failure with its causes, not just its headline.
///
/// `Display` on a `reqwest::Error` says what it was doing and to which URL, and
/// nothing about why it failed — the reason lives in the source chain. The
/// destination floor's refusal arrives that way, and an operator told only
/// "error sending request" has been told nothing they can act on.
fn transport_detail(e: &reqwest::Error) -> String {
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        let text = cause.to_string();
        // Hyper repeats its inner message in its own `Display` often enough
        // that a naive chain reads as a stutter.
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

/// One descriptor, as much of it as deciding what to fetch next requires. The
/// full validation is [`isopod_oci_unpack::layout`]'s, once the layout exists.
#[derive(serde::Deserialize)]
struct WireDescriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: Option<String>,
    size: Option<i64>,
    platform: Option<WirePlatform>,
}

#[derive(serde::Deserialize)]
struct WirePlatform {
    os: Option<String>,
    architecture: Option<String>,
}

#[derive(serde::Deserialize)]
struct WireDoc {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    manifests: Option<Vec<WireDescriptor>>,
    config: Option<WireDescriptor>,
    layers: Option<Vec<WireDescriptor>>,
}

impl WireDescriptor {
    /// The digest and size, or a refusal. Parsed through the same [`Digest`]
    /// the extractor uses, so a registry cannot name a path here either.
    fn parts(&self, what: &str) -> Result<(Digest, u64), PullError> {
        let malformed = |detail: &str| PullError::Status {
            what: what.to_string(),
            status: 200,
            detail: detail.to_string(),
        };
        let d = self
            .digest
            .as_deref()
            .ok_or_else(|| malformed("a descriptor with no digest"))?;
        let digest = Digest::parse(d).map_err(|e| malformed(&e.to_string()))?;
        let size = self
            .size
            .ok_or_else(|| malformed("a descriptor with no size"))?;
        let size =
            u64::try_from(size).map_err(|_| malformed("a descriptor with a negative size"))?;
        Ok((digest, size))
    }
}

impl Puller {
    /// Fetch the image into an OCI layout at `root`, which is created if it
    /// does not exist.
    ///
    /// Blobs already present and already hashing to their names are not fetched
    /// again, so a re-import after a failure resumes rather than restarts.
    ///
    /// # Errors
    /// Any [`PullError`]. A failure leaves the layout incomplete but never
    /// inconsistent: no blob is ever written under a name it does not hash to,
    /// and `index.json` is written last, so an interrupted pull is a directory
    /// the reader refuses rather than one it half-believes.
    pub fn pull_into(&mut self, root: &Path) -> Result<Pulled, PullError> {
        let mut bytes_downloaded = 0u64;
        let mut blobs_reused = 0usize;

        // 1. The manifest the reference names, which may be an index.
        let (mut body, mut media_type) = self.fetch_manifest(&self.reference.manifest_path())?;
        let mut digest = manifest_digest(&self.reference, &body);
        // A pinned reference is a promise about these exact bytes, so it is
        // checked here rather than left to whoever writes them out. The
        // by-digest fetch *inside* the index branch below already does this; the
        // top-level one did not, and the difference only showed when the blob
        // was already cached — `write_blob_bytes` skips a blob that is present
        // and correct, so the substituted body was never hashed, while the
        // descriptors driving the rest of the pull were parsed straight out of
        // it. Verifying here makes it one rule for both, before anything reads
        // the bytes.
        if let Want::Digest(want) = &self.reference.want {
            let actual = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&body));
            if actual != want.encoded() {
                return Err(PullError::DigestMismatch {
                    expected: want.to_string(),
                    actual,
                });
            }
        }

        let mut doc: WireDoc = serde_json::from_slice(&body).map_err(|e| PullError::Status {
            what: "the manifest".into(),
            status: 200,
            detail: format!("it does not parse: {e}"),
        })?;
        let doc_type = doc.media_type.clone().unwrap_or_else(|| media_type.clone());

        // 2. If it is an index, pick this platform's manifest and fetch that.
        //    The whole index is kept as a blob so the layout records what was
        //    actually published, not just the slice that was used.
        let index_entries = if is_index(&doc_type) {
            doc.manifests.take()
        } else {
            None
        };
        let manifest_doc = if let Some(entries) = index_entries {
            let index_digest = digest.clone();
            self.write_blob_bytes(root, &index_digest, &body)?;
            let chosen = entries
                .iter()
                .find(|e| {
                    e.platform.as_ref().is_some_and(|p| {
                        p.os.as_deref() == Some("linux")
                            && p.architecture.as_deref() == Some("amd64")
                    })
                })
                .ok_or_else(|| PullError::Status {
                    what: format!("{}", self.reference),
                    status: 200,
                    detail: "this image publishes no linux/amd64 manifest, and isopod \
                             boots x86-64 Linux guests"
                        .into(),
                })?;
            let (d, _) = chosen.parts("the index")?;
            let (b, mt) =
                self.fetch_manifest(&format!("/v2/{}/manifests/{d}", self.reference.repository))?;
            // A registry that answers a by-digest request with something else
            // is the case content addressing exists to catch.
            let actual = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&b));
            if actual != d.encoded() {
                return Err(PullError::DigestMismatch {
                    expected: d.to_string(),
                    actual,
                });
            }
            digest = d;
            media_type = chosen.media_type.clone().unwrap_or(mt);
            body = b;
            serde_json::from_slice::<WireDoc>(&body).map_err(|e| PullError::Status {
                what: "the manifest".into(),
                status: 200,
                detail: format!("it does not parse: {e}"),
            })?
        } else {
            doc
        };

        // 3. The manifest itself, then its config and layers.
        self.write_blob_bytes(root, &digest, &body)?;
        let config = manifest_doc.config.ok_or_else(|| PullError::Status {
            what: "the manifest".into(),
            status: 200,
            detail: "it has no config descriptor".into(),
        })?;
        let layers = manifest_doc.layers.unwrap_or_default();
        if layers.is_empty() {
            return Err(PullError::Status {
                what: "the manifest".into(),
                status: 200,
                detail: "it has no layers; an image with no filesystem cannot be a base".into(),
            });
        }
        for (desc, what) in std::iter::once((&config, "the config blob"))
            .chain(layers.iter().map(|l| (l, "a layer blob")))
        {
            let (d, size) = desc.parts(what)?;
            let dest = root.join(d.blob_path());
            if blob_is_present(&dest, &d, size) {
                blobs_reused += 1;
                continue;
            }
            bytes_downloaded += self.fetch_blob(&d, &dest, what)?;
        }

        // 4. `index.json` last: until it exists there is nothing for a reader
        //    to believe, which is what makes an interrupted pull safe.
        write_layout_metadata(
            root,
            &digest,
            &media_type,
            body.len() as u64,
            &self.reference,
        )?;
        Ok(Pulled {
            layout: root.to_path_buf(),
            manifest_digest: digest,
            bytes_downloaded,
            blobs_reused,
        })
    }

    /// GET a manifest path, returning its body and the media type it came back
    /// as.
    fn fetch_manifest(&mut self, path: &str) -> Result<(Vec<u8>, String), PullError> {
        let url =
            Url::parse(&format!("{}{path}", self.base())).map_err(|e| PullError::Transport {
                what: path.to_string(),
                detail: e.to_string(),
            })?;
        let resp = self.get(&url, path)?;
        let media_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/vnd.oci.image.manifest.v1+json")
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if let Some(len) = resp.content_length() {
            if len > MAX_MANIFEST_BYTES {
                return Err(PullError::TooLarge {
                    what: path.to_string(),
                    cap: MAX_MANIFEST_BYTES,
                    actual: len,
                });
            }
        }
        let mut body = Vec::new();
        resp.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| PullError::Transport {
                what: path.to_string(),
                detail: e.to_string(),
            })?;
        if body.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(PullError::TooLarge {
                what: path.to_string(),
                cap: MAX_MANIFEST_BYTES,
                actual: body.len() as u64,
            });
        }
        Ok((body, media_type))
    }

    /// GET a blob and stream it to `dest`, verified.
    fn fetch_blob(&mut self, d: &Digest, dest: &Path, what: &str) -> Result<u64, PullError> {
        let url = Url::parse(&format!(
            "{}/v2/{}/blobs/{d}",
            self.base(),
            self.reference.repository
        ))
        .map_err(|e| PullError::Transport {
            what: what.to_string(),
            detail: e.to_string(),
        })?;
        let resp = self.get(&url, what)?;
        stream_verified(resp, dest, d, MAX_BLOB_BYTES, what)
    }

    /// Write bytes already in memory as a blob, verified the same way.
    fn write_blob_bytes(&self, root: &Path, d: &Digest, bytes: &[u8]) -> Result<(), PullError> {
        let dest = root.join(d.blob_path());
        if blob_is_present(&dest, d, bytes.len() as u64) {
            return Ok(());
        }
        stream_verified(bytes, &dest, d, MAX_MANIFEST_BYTES, "a manifest blob").map(|_| ())
    }

    /// GET `url`, authenticating once if challenged and following redirects by
    /// hand under this crate's policy.
    fn get(&mut self, url: &Url, what: &str) -> Result<reqwest::blocking::Response, PullError> {
        let mut current = url.clone();
        let mut carry_credential = true;
        let mut challenged = false;
        for _ in 0..=MAX_REDIRECTS {
            let mut req = self
                .http
                .get(current.clone())
                .header(reqwest::header::ACCEPT, ACCEPT);
            if carry_credential {
                if let Some(t) = &self.token {
                    req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
                } else if let Some(b) = &self.basic {
                    req = req.header(reqwest::header::AUTHORIZATION, format!("Basic {b}"));
                }
            }
            let resp = req.send().map_err(|e| PullError::Transport {
                what: what.to_string(),
                detail: transport_detail(&e),
            })?;
            let status = resp.status();

            // `carry_credential` gates the challenge too, not only the header.
            // A 401 answered by a host this client was *redirected* to is that
            // host asking for the registry's credential, and answering it means
            // fetching a token from a realm that host chose and paying for it
            // with the operator's `~/.docker/config.json` entry. A CDN has no
            // business challenging us; if one does, the pull fails with its 401
            // rather than starting a credentialed conversation with it.
            if status == reqwest::StatusCode::UNAUTHORIZED && !challenged && carry_credential {
                challenged = true;
                let header = resp
                    .headers()
                    .get(reqwest::header::WWW_AUTHENTICATE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let challenge = Challenge::parse(&header, self.reference.is_local())?;
                self.token = Some(self.fetch_token(&challenge)?);
                continue;
            }

            if status.is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| PullError::Redirect {
                        to: "(no Location header)".into(),
                        detail: "the registry redirected without saying where".into(),
                    })?
                    .to_string();
                let next = current.join(&location).map_err(|e| PullError::Redirect {
                    to: location.clone(),
                    detail: e.to_string(),
                })?;
                if !auth::destination_is_allowed(&next, self.reference.is_local()) {
                    return Err(PullError::Redirect {
                        to: next.to_string(),
                        detail: "it is not a public https address".into(),
                    });
                }
                // The rule that matters most on this path: a blob redirect to
                // object storage must not carry the registry's token.
                //
                // A **latch**, not a recomputation. `may_carry_credential`
                // compares this hop's two ends, so once a redirect has taken us
                // to the attacker's origin, every further hop *within* that
                // origin compares their host to their host and says yes — and
                // the credential the first hop correctly dropped comes back on
                // the second. Two redirects instead of one defeated the whole
                // rule. Once a credential has left its origin it does not
                // return.
                carry_credential &= auth::may_carry_credential(&current, &next);
                current = next;
                continue;
            }

            if !status.is_success() {
                let detail = resp.text().unwrap_or_default();
                return Err(PullError::Status {
                    what: what.to_string(),
                    status: status.as_u16(),
                    detail: detail.chars().take(400).collect(),
                });
            }
            return Ok(resp);
        }
        Err(PullError::Redirect {
            to: current.to_string(),
            detail: format!("more than {MAX_REDIRECTS} redirects"),
        })
    }

    /// Exchange the challenge for a bearer token.
    fn fetch_token(&self, challenge: &Challenge) -> Result<String, PullError> {
        let url = challenge.token_url();
        let mut req = self.http.get(url.clone());
        // The operator's registry credential goes to the token service, which
        // is the one place it is supposed to go — and only over https, which
        // `Challenge::parse` has already established.
        if let Some(b) = &self.basic {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Basic {b}"));
        }
        let resp = req.send().map_err(|e| PullError::Transport {
            what: "a token".into(),
            detail: transport_detail(&e),
        })?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            return Err(PullError::Status {
                what: "a token".into(),
                status,
                detail: resp.text().unwrap_or_default().chars().take(400).collect(),
            });
        }
        let body: serde_json::Value = resp.json().map_err(|e| PullError::Transport {
            what: "a token".into(),
            detail: transport_detail(&e),
        })?;
        body.get("token")
            .or_else(|| body.get("access_token"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| PullError::Transport {
                what: "a token".into(),
                detail: "the token service returned no token".into(),
            })
    }
}

/// Is this blob already on disk, the right size, and hashing to its own name?
///
/// The hash is what makes reuse safe: a `.partial` that was renamed by an older
/// build, or a file truncated by a full disk, must not be mistaken for a
/// complete download just because the name is right.
fn blob_is_present(path: &Path, d: &Digest, size: u64) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() != size {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => sha2::Digest::update(&mut hasher, &buf[..n]),
            Err(_) => return false,
        }
    }
    hex::encode(sha2::Digest::finalize(hasher)) == d.encoded()
}

fn is_index(media_type: &str) -> bool {
    media_type == "application/vnd.oci.image.index.v1+json"
        || media_type == "application/vnd.docker.distribution.manifest.list.v2+json"
}

/// A `Basic` credential for this registry from `~/.docker/config.json`, if there
/// is one.
///
/// Deliberately not isopod's own credential store. That store's whole design is
/// "the *run* names an alias and never holds the secret", for secrets a guest
/// uses; a registry credential is the *host* authenticating on the operator's
/// behalf with no guest involved, and putting it there would blur the one
/// boundary the store exists to draw.
fn docker_config_auth(reference: &Reference) -> Option<String> {
    docker_config_auth_in(&dirs_config()?.join(".docker/config.json"), reference)
}

/// Docker's legacy key for Hub. Nothing else is keyed this way.
const HUB_LEGACY_KEY: &str = "https://index.docker.io/v1/";

/// [`docker_config_auth`] against an explicit config path.
///
/// Split out because the real one reads `HOME`, which is process-global: a test
/// that sets it steers every other test running beside it, and this session
/// already lost an hour to exactly that in the import suite. The credential
/// rule is the thing worth testing, and it does not need an environment.
fn docker_config_auth_in(path: &Path, reference: &Reference) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let auths = json.get("auths")?.as_object()?;

    for (key, entry) in auths {
        if !key_names_registry(key, reference) {
            continue;
        }
        if let Some(auth) = entry.get("auth").and_then(|v| v.as_str()) {
            // An empty `auth` is what Docker writes when the secret lives in a
            // `credsStore`/`credHelpers` keychain instead. There is no
            // credential here to send, and an empty `Basic ` header is not a
            // degraded version of one.
            if !auth.is_empty() {
                return Some(auth.to_string());
            }
        }
    }
    None
}

/// Does a `config.json` key name the registry this pull is for?
///
/// Docker stores keys in several shapes (`ghcr.io`, `https://ghcr.io`,
/// `https://ghcr.io/v1/`), so the key is reduced to the host it names before
/// comparing — the same reduction Docker's own credential resolution does.
///
/// The Hub legacy key is matched **only for Hub**. It used to be tried for
/// every registry, on the reasoning that Hub is keyed unusually and so the key
/// has to be in the list. It does — but only when Hub is what was asked for.
/// Unconditional, it meant any operator who had ever run `docker login` sent
/// their Hub credential to every registry they subsequently named, on the first
/// request, before any challenge.
fn key_names_registry(key: &str, reference: &Reference) -> bool {
    if reference.is_default_registry() {
        if key == HUB_LEGACY_KEY {
            return true;
        }
    } else if key == HUB_LEGACY_KEY {
        // Never a fallback for anyone else.
        return false;
    }
    let host = config_key_host(key);
    // Exact host equality only. A key is not a pattern: `ghcr.io.evil.com`
    // must not be answered with the credential for `ghcr.io`, and vice versa.
    host == reference.registry || host == reference.host()
}

/// Reduce a `config.json` key to the host it names.
fn config_key_host(key: &str) -> &str {
    let k = key
        .strip_prefix("https://")
        .or_else(|| key.strip_prefix("http://"))
        .unwrap_or(key);
    k.split('/').next().unwrap_or(k)
}

fn dirs_config() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Stream `body` into `dest`, hashing as it goes, refusing past `cap`.
///
/// The file is written under a temporary name and renamed only once the hash
/// matches, so a blob store can never contain a file that does not hash to the
/// name it is under — which is the assumption every later reader makes.
fn stream_verified(
    mut body: impl Read,
    dest: &Path,
    expect: &Digest,
    cap: u64,
    what: &str,
) -> Result<u64, PullError> {
    let io = |path: &Path, e: &dyn fmt::Display| PullError::Io {
        path: path.to_path_buf(),
        detail: e.to_string(),
    };
    let parent = dest.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| io(parent, &e))?;
    let tmp = parent.join(format!(
        ".{}.partial.{}",
        dest.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let mut file = std::fs::File::create(&tmp).map_err(|e| io(&tmp, &e))?;
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 256 * 1024];
    let result = (|| loop {
        let n = body.read(&mut buf).map_err(|e| PullError::Transport {
            what: what.to_string(),
            detail: e.to_string(),
        })?;
        if n == 0 {
            return Ok(());
        }
        total += n as u64;
        if total > cap {
            return Err(PullError::TooLarge {
                what: what.to_string(),
                cap,
                actual: total,
            });
        }
        sha2::Digest::update(&mut hasher, &buf[..n]);
        file.write_all(&buf[..n]).map_err(|e| PullError::Io {
            path: tmp.clone(),
            detail: e.to_string(),
        })?;
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let actual = hex::encode(sha2::Digest::finalize(hasher));
    if actual != expect.encoded() {
        let _ = std::fs::remove_file(&tmp);
        return Err(PullError::DigestMismatch {
            expected: expect.to_string(),
            actual,
        });
    }
    file.sync_all().map_err(|e| io(&tmp, &e))?;
    drop(file);
    std::fs::rename(&tmp, dest).map_err(|e| io(dest, &e))?;
    Ok(total)
}

/// Write the `oci-layout` marker and an `index.json` naming one manifest.
fn write_layout_metadata(
    root: &Path,
    manifest: &Digest,
    media_type: &str,
    size: u64,
    reference: &Reference,
) -> Result<(), PullError> {
    let io = |path: &Path, e: &dyn fmt::Display| PullError::Io {
        path: path.to_path_buf(),
        detail: e.to_string(),
    };
    std::fs::create_dir_all(root).map_err(|e| io(root, &e))?;
    let marker = root.join("oci-layout");
    std::fs::write(&marker, br#"{"imageLayoutVersion":"1.0.0"}"#).map_err(|e| io(&marker, &e))?;
    // The reference is recorded as the conventional annotation so a layout on
    // disk can say what it came from without a sidecar of isopod's own.
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": media_type,
            "digest": manifest.to_string(),
            "size": size,
            "annotations": {
                "org.opencontainers.image.ref.name": reference.to_string(),
            },
        }],
    });
    let path = root.join("index.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&index).map_err(|e| io(&path, &e))?,
    )
    .map_err(|e| io(&path, &e))
}

/// The digest a manifest response should be recorded under.
///
/// Preferring the reference's own digest when it has one is not an
/// optimisation: it is the difference between recording what was asked for and
/// recording what the registry chose to say.
fn manifest_digest(reference: &Reference, body: &[u8]) -> Digest {
    match &reference.want {
        Want::Digest(d) => d.clone(),
        Want::Tag(_) => Digest::parse(&format!(
            "sha256:{}",
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(body),)
        ))
        .expect("a sha256 of our own computing always parses"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_is_only_named_by_a_digest_it_actually_hashes_to() {
        // The invariant every later reader depends on: a file under
        // `blobs/sha256/<hex>` hashes to `<hex>`. The failing case must leave
        // nothing at all — not a partial file, not a `.partial`, not an empty
        // one at the final name.
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = Digest::parse(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .expect("parse");
        let dest = dir.path().join("blobs/sha256/e3b0…");

        let err = stream_verified(&b"not empty"[..], &dest, &empty, 1 << 20, "a blob")
            .expect_err("must refuse");
        assert!(matches!(err, PullError::DigestMismatch { .. }), "{err:?}");
        assert!(!dest.exists(), "a mismatched blob must not be kept");
        let strays: Vec<_> = std::fs::read_dir(dest.parent().expect("parent"))
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert!(strays.is_empty(), "a partial download survived: {strays:?}");

        // The control: the matching case is written, under its own name.
        let n = stream_verified(&b""[..], &dest, &empty, 1 << 20, "a blob").expect("must accept");
        assert_eq!(n, 0);
        assert!(dest.exists());
    }

    #[test]
    fn a_download_stops_at_the_ceiling_rather_than_after_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let d = Digest::parse(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .expect("parse");
        let dest = dir.path().join("blob");
        let err = stream_verified(std::io::repeat(0).take(4096), &dest, &d, 1024, "a blob")
            .expect_err("must refuse");
        match err {
            PullError::TooLarge { cap, actual, .. } => {
                assert_eq!(cap, 1024);
                assert!(
                    actual <= cap + 256 * 1024,
                    "the refusal must arrive at the cap, not at the end of the stream"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(!dest.exists());
    }

    #[test]
    fn a_tag_records_the_digest_that_answered_and_a_digest_records_itself() {
        let by_tag = Reference::parse("alpine:3.20").expect("parse");
        let got = manifest_digest(&by_tag, b"body");
        assert!(got.matches(b"body"), "a tag records what actually arrived");

        let pinned = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let by_digest = Reference::parse(&format!("alpine@{pinned}")).expect("parse");
        assert_eq!(
            manifest_digest(&by_digest, b"body").to_string(),
            pinned,
            "a pinned reference records what was asked for, not what was sent"
        );
    }

    #[test]
    fn the_debug_of_a_client_cannot_print_a_token() {
        let mut p = Puller::new("alpine").expect("client");
        p.token = Some("secret-token-value".into());
        let shown = format!("{p:?}");
        assert!(
            !shown.contains("secret-token-value"),
            "a token reached Debug output: {shown}"
        );
        assert!(shown.contains("authenticated: true"), "{shown}");
    }
}
