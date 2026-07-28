//! Parsing an image reference — `alpine`, `python:3.12`, `ghcr.io/o/n@sha256:…`.
//!
//! The grammar is not obvious and the defaults are historical: a bare `alpine`
//! means `docker.io/library/alpine:latest`, and whether the first slash-separated
//! component is a registry or the first part of a repository is decided by
//! whether it contains a `.` or a `:`. Getting that wrong does not produce a
//! parse error, it produces a request to the wrong host — so it is parsed once,
//! here, and every field the rest of the crate uses comes out of this type.

use std::fmt;

use isopod_oci_unpack::digest::Digest;

/// The registry a bare name resolves to.
const DEFAULT_REGISTRY: &str = "docker.io";
/// What `docker.io` actually serves from. The name in a reference and the host
/// that answers for it are not the same string, and never have been.
const DEFAULT_REGISTRY_HOST: &str = "registry-1.docker.io";
/// The namespace a single-component repository on Docker Hub lives in.
const DEFAULT_NAMESPACE: &str = "library";
/// The tag a reference without one means.
const DEFAULT_TAG: &str = "latest";

/// What a reference asks for: a tag, or an exact digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Want {
    /// A mutable tag. What it resolves to today is not what it resolved to
    /// yesterday, which is why an import records the digest it actually got.
    Tag(String),
    /// An immutable digest. The manifest that comes back is checked against it.
    Digest(Digest),
}

impl fmt::Display for Want {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tag(t) => write!(f, ":{t}"),
            Self::Digest(d) => write!(f, "@{d}"),
        }
    }
}

/// A parsed image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// The registry as written, or the default. `docker.io`, `ghcr.io`,
    /// `localhost:5000`.
    pub registry: String,
    /// The repository path, namespace included: `library/alpine`, `org/name`.
    pub repository: String,
    /// The tag or digest asked for.
    pub want: Want,
}

/// Why a reference could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceError {
    /// The reference as given.
    pub input: String,
    /// What is wrong with it.
    pub detail: String,
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not an image reference: {}. The form is \
             `[registry/][namespace/]name[:tag|@digest]`, as in `alpine:3.20`, \
             `ghcr.io/org/name:v1` or `python@sha256:…`.",
            self.input, self.detail
        )
    }
}

impl std::error::Error for ReferenceError {}

impl Reference {
    /// Parse a reference, applying the historical defaults.
    ///
    /// # Errors
    /// [`ReferenceError`] if the shape, the repository characters, the tag or
    /// the digest is not one a registry would accept.
    pub fn parse(input: &str) -> Result<Self, ReferenceError> {
        let bad = |detail: &str| ReferenceError {
            input: input.to_string(),
            detail: detail.to_string(),
        };
        if input.is_empty() {
            return Err(bad("it is empty"));
        }

        // The digest separator is decided before the tag one: `name:tag@sha256:x`
        // is legal, and the `:` inside the digest must not be read as a tag.
        let (head, want) = match input.split_once('@') {
            Some((head, digest)) => {
                let d = Digest::parse(digest).map_err(|e| bad(&e.to_string()))?;
                // `name:tag@digest` — the tag is decoration once a digest is
                // present, and is dropped rather than half-honoured.
                (head, Want::Digest(d))
            }
            None => (input, Want::Tag(String::new())),
        };

        // Split the registry off the front. The rule is positional, not
        // syntactic: a first component containing `.` or `:`, or spelled
        // `localhost`, is a host; anything else is part of the repository. So
        // `ubuntu/nginx` is a Docker Hub repository and `example.com/nginx` is
        // not.
        let (registry, rest) = match head.split_once('/') {
            Some((first, rest))
                if first == "localhost" || first.contains('.') || first.contains(':') =>
            {
                (first.to_string(), rest)
            }
            _ => (DEFAULT_REGISTRY.to_string(), head),
        };
        if registry.is_empty() {
            return Err(bad("the registry is empty"));
        }

        // Now the tag, which can only be in what is left after the registry —
        // otherwise `localhost:5000/name` reads its port as a tag.
        let (path, want) = match want {
            Want::Digest(d) => (rest.split(':').next().unwrap_or(rest), Want::Digest(d)),
            Want::Tag(_) => match rest.rsplit_once(':') {
                Some((path, tag)) => (path, Want::Tag(tag.to_string())),
                None => (rest, Want::Tag(DEFAULT_TAG.to_string())),
            },
        };

        if path.is_empty() {
            return Err(bad("it names no repository"));
        }
        // Docker Hub is the only registry that invents a namespace, and only
        // for a single-component path.
        let repository = if registry == DEFAULT_REGISTRY && !path.contains('/') {
            format!("{DEFAULT_NAMESPACE}/{path}")
        } else {
            path.to_string()
        };
        check_repository(&repository).map_err(|d| bad(&d))?;
        if let Want::Tag(t) = &want {
            check_tag(t).map_err(|d| bad(&d))?;
        }
        Ok(Self {
            registry,
            repository,
            want,
        })
    }

    /// The host to actually connect to, which is not always the registry as
    /// written: `docker.io` is a name in references and nothing else.
    #[must_use]
    pub fn host(&self) -> &str {
        if self.registry == DEFAULT_REGISTRY {
            DEFAULT_REGISTRY_HOST
        } else {
            &self.registry
        }
    }

    /// `true` for a registry that may be reached over plain HTTP without the
    /// operator saying so: a loopback one, which cannot be a third party.
    #[must_use]
    pub fn is_local(&self) -> bool {
        let host = self.registry.split(':').next().unwrap_or(&self.registry);
        host == "localhost" || host == "127.0.0.1" || host == "::1"
    }

    /// What a `/v2/` request path for this repository looks like.
    #[must_use]
    pub fn manifest_path(&self) -> String {
        let want = match &self.want {
            Want::Tag(t) => t.clone(),
            Want::Digest(d) => d.to_string(),
        };
        format!("/v2/{}/manifests/{}", self.repository, want)
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}{}", self.registry, self.repository, self.want)
    }
}

/// The repository grammar, as a registry enforces it.
///
/// Checked rather than trusted because the repository goes into a request path
/// verbatim: a component that is `..`, or one carrying a `/` smuggled in
/// through some other spelling, would address a different endpoint than the one
/// the message says it is fetching.
fn check_repository(path: &str) -> Result<(), String> {
    if path.len() > 255 {
        return Err("the repository is longer than 255 characters".into());
    }
    for component in path.split('/') {
        if component.is_empty() {
            return Err("it has an empty path component".into());
        }
        if component == "." || component == ".." {
            return Err(format!("{component:?} is not a repository component"));
        }
        if !component
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(format!(
                "{component:?} is not a legal repository component — registries \
                 accept lowercase letters, digits, and `.`, `_`, `-` only \
                 (an uppercase name is the usual cause)"
            ));
        }
    }
    Ok(())
}

/// The tag grammar, as a registry enforces it.
fn check_tag(tag: &str) -> Result<(), String> {
    if tag.is_empty() {
        return Err("the tag is empty".into());
    }
    if tag.len() > 128 {
        return Err("the tag is longer than 128 characters".into());
    }
    let first = tag.as_bytes()[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return Err(format!("a tag cannot start with {:?}", first as char));
    }
    if !tag
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(format!(
            "{tag:?} is not a legal tag — letters, digits, and `.`, `_`, `-` only"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Reference {
        Reference::parse(s).unwrap_or_else(|e| panic!("{s} should parse: {e}"))
    }

    #[test]
    fn the_historical_defaults_are_applied_exactly_once() {
        let r = p("alpine");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine", "a bare name is namespaced");
        assert_eq!(r.want, Want::Tag("latest".into()));
        assert_eq!(r.host(), "registry-1.docker.io", "the name is not the host");
        assert_eq!(r.manifest_path(), "/v2/library/alpine/manifests/latest");

        // Two components on Docker Hub are already namespaced; inventing
        // `library/` again would address a repository that does not exist.
        assert_eq!(p("ubuntu/nginx").repository, "ubuntu/nginx");
        // And nowhere else invents one at all.
        let g = p("ghcr.io/org/name:v1");
        assert_eq!(g.registry, "ghcr.io");
        assert_eq!(g.repository, "org/name");
        assert_eq!(g.host(), "ghcr.io");
    }

    #[test]
    fn a_registry_is_told_from_a_namespace_by_position_not_by_hope() {
        // The rule that decides whether the first component is a host. Each of
        // these differs from its neighbour by one character and means something
        // completely different.
        assert_eq!(p("example.com/nginx").registry, "example.com");
        assert_eq!(p("example/nginx").registry, "docker.io");
        assert_eq!(p("example/nginx").repository, "example/nginx");
        assert_eq!(p("localhost/nginx").registry, "localhost");
        assert_eq!(p("localhost:5000/nginx").registry, "localhost:5000");
    }

    #[test]
    fn a_port_is_never_read_as_a_tag() {
        // The bug this ordering exists to prevent: splitting the tag off before
        // the registry turns `localhost:5000/nginx` into the repository
        // `localhost` at tag `5000/nginx`, and the request goes to Docker Hub.
        let r = p("localhost:5000/nginx");
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "nginx");
        assert_eq!(r.want, Want::Tag("latest".into()));

        let t = p("localhost:5000/nginx:1.2");
        assert_eq!(t.registry, "localhost:5000");
        assert_eq!(t.repository, "nginx");
        assert_eq!(t.want, Want::Tag("1.2".into()));
    }

    #[test]
    fn a_digest_wins_over_a_tag_and_is_parsed_by_the_one_parser() {
        let d = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r = p(&format!("alpine@{d}"));
        assert_eq!(r.want, Want::Digest(Digest::parse(d).expect("parse")));
        assert_eq!(
            r.manifest_path(),
            format!("/v2/library/alpine/manifests/{d}")
        );

        // `name:tag@digest` is legal and the digest is what is fetched. A
        // parser that kept the tag would ask for one thing and verify another.
        let both = p(&format!("alpine:3.20@{d}"));
        assert_eq!(both.repository, "library/alpine");
        assert_eq!(both.want, Want::Digest(Digest::parse(d).expect("parse")));

        // And a digest that is not one is refused here rather than becoming a
        // path segment: this is the same check that stops `blobs/` being
        // escaped, reached through a different door.
        assert!(Reference::parse("alpine@sha256:../../etc/shadow").is_err());
        assert!(Reference::parse("alpine@nonsense").is_err());
    }

    #[test]
    fn references_a_registry_would_reject_are_rejected_here() {
        for (input, why) in [
            ("", "empty"),
            ("Alpine", "uppercase"),
            ("org/Name", "uppercase in a component"),
            ("alpine:", "empty tag"),
            ("alpine:-3.20", "a tag starting with a dash"),
            ("alpine:a b", "a space in the tag"),
            ("../../etc/passwd", "a traversal"),
            ("example.com/../secret", "a traversal after a host"),
            ("example.com//nginx", "an empty component"),
        ] {
            assert!(
                Reference::parse(input).is_err(),
                "{input:?} ({why}) was accepted as {:?}",
                Reference::parse(input)
            );
        }
    }

    #[test]
    fn only_a_loopback_registry_counts_as_local() {
        // This decides whether plain HTTP is allowed without the operator
        // saying so, so a name that merely *looks* local must not qualify.
        assert!(p("localhost:5000/n").is_local());
        assert!(p("127.0.0.1:5000/n").is_local());
        assert!(!p("localhost.evil.com/n").is_local());
        assert!(!p("notlocalhost/n").is_local());
        assert!(!p("alpine").is_local());
    }

    #[test]
    fn a_reference_round_trips_to_something_that_parses_again() {
        // The Display is what an import records and what an error message
        // quotes, so it has to name the same image.
        for input in [
            "alpine",
            "python:3.12",
            "ghcr.io/org/name:v1",
            "localhost:5000/n:t",
        ] {
            let once = p(input);
            let twice = p(&once.to_string());
            assert_eq!(once, twice, "{input} did not survive a round trip");
        }
    }
}
