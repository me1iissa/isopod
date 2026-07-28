//! Content digests, and the one place a registry-supplied string becomes a path.
//!
//! A descriptor's `digest` is the only thing that makes a blob the blob it
//! claims to be, and in an image layout it is *also* how the blob is addressed:
//! `blobs/<algorithm>/<encoded>`. Both halves of that are attacker-chosen text.
//! `sha256:../../../../etc/shadow` is a perfectly well-formed JSON string, and a
//! reader that joins it onto a path reads whatever it names — before any layer
//! has been looked at, before any VM exists.
//!
//! So a digest is parsed into this type or it is refused, and the type is the
//! only way to build a blob path. The grammar is the one the OCI image
//! specification gives (`algorithm ":" encoded`), narrowed to what this crate
//! will actually verify.

use std::fmt;

use sha2::{Digest as _, Sha256};

/// A parsed, verified-shape content digest.
///
/// Constructing one is the whole check: an instance's `encoded` is known to be
/// lowercase hex of exactly the length its algorithm produces, and its
/// `algorithm` is one this crate can compute. Nothing else in the crate parses
/// a digest string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest {
    algorithm: String,
    encoded: String,
}

/// Why a digest string was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// No `:` separator, or an empty half.
    Malformed(String),
    /// An algorithm this crate cannot compute, so a blob claiming it could
    /// never be verified.
    UnsupportedAlgorithm(String),
    /// The encoded half is not lowercase hex of the algorithm's length.
    BadEncoding(String),
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(s) => write!(
                f,
                "{s:?} is not a digest. The form is `<algorithm>:<hex>`, as in \
                 `sha256:e3b0c442…`."
            ),
            Self::UnsupportedAlgorithm(s) => write!(
                f,
                "digest algorithm {s:?} is not one isopod can compute, so a blob \
                 claiming it could not be verified against it. Only `sha256` is \
                 accepted; re-push the image with a registry that uses it."
            ),
            Self::BadEncoding(s) => write!(
                f,
                "digest {s:?} does not encode the number of lowercase hex \
                 characters its algorithm produces. A digest is also how a blob \
                 is addressed inside an image layout, so anything but plain hex \
                 is refused rather than turned into a path."
            ),
        }
    }
}

impl std::error::Error for DigestError {}

/// Algorithms this crate will verify, with the hex length each produces.
///
/// Deliberately a short list. An algorithm that cannot be computed here is
/// worse than useless: it would let a blob be *addressed* by a digest nothing
/// ever checks it against, which is a verification that silently is not one.
const ALGORITHMS: &[(&str, usize)] = &[("sha256", 64)];

impl Digest {
    /// Parse `<algorithm>:<encoded>`.
    ///
    /// # Errors
    /// [`DigestError`] if the shape, the algorithm or the encoding is not one
    /// this crate can both address and verify.
    pub fn parse(s: &str) -> Result<Self, DigestError> {
        let (algorithm, encoded) = s
            .split_once(':')
            .ok_or_else(|| DigestError::Malformed(s.to_string()))?;
        if algorithm.is_empty() || encoded.is_empty() {
            return Err(DigestError::Malformed(s.to_string()));
        }
        let Some((_, len)) = ALGORITHMS.iter().find(|(a, _)| *a == algorithm) else {
            return Err(DigestError::UnsupportedAlgorithm(algorithm.to_string()));
        };
        // Length *and* alphabet, together. Either one alone lets something
        // through: the right number of `.` characters passes a length check,
        // and hex of the wrong length names a blob no verification can match.
        if encoded.len() != *len
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DigestError::BadEncoding(s.to_string()));
        }
        Ok(Self {
            algorithm: algorithm.to_string(),
            encoded: encoded.to_string(),
        })
    }

    /// The algorithm half — a known-safe directory name.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The hex half — a known-safe file name.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Does `bytes` hash to this digest?
    ///
    /// The comparison is on the hex text rather than on raw bytes because the
    /// text is what the manifest said, and reporting a mismatch has to be able
    /// to quote both sides.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.compute(bytes) == self.encoded
    }

    /// This digest's algorithm applied to `bytes`, as lowercase hex.
    #[must_use]
    pub fn compute(&self, bytes: &[u8]) -> String {
        match self.algorithm.as_str() {
            "sha256" => hex::encode(Sha256::digest(bytes)),
            // Unreachable: `parse` is the only constructor and it refuses
            // anything not in `ALGORITHMS`. Stated as a panic rather than a
            // default so that adding an algorithm to the list without adding it
            // here fails loudly instead of verifying nothing.
            other => unreachable!("digest algorithm {other:?} parsed but cannot be computed"),
        }
    }

    /// Where this blob lives inside an image layout, relative to its root.
    ///
    /// Both components come from the parse above, so neither can contain a
    /// separator, a `.` component, or anything but `[a-z0-9]`.
    #[must_use]
    pub fn blob_path(&self) -> std::path::PathBuf {
        std::path::Path::new("blobs")
            .join(&self.algorithm)
            .join(&self.encoded)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest is the only string in an image layout that becomes a path, so
    /// this is the traversal test for the metadata half of an import — the same
    /// question the entry-name planner answers for the layer half.
    #[test]
    fn nothing_that_could_name_a_path_survives_parsing() {
        for hostile in [
            "sha256:../../../../etc/shadow",
            "sha256:..",
            "sha256:/etc/shadow",
            "sha256:a/b",
            "../../etc:0000000000000000000000000000000000000000000000000000000000000000",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
            "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "sha256:",
            ":deadbeef",
            "sha256",
            "",
            // The shapes a length-only or alphabet-only check would admit:
            // sixty-four dots, and sixty-four characters of the wrong alphabet.
            "sha256:................................................................",
            "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ] {
            let got = Digest::parse(hostile);
            assert!(got.is_err(), "{hostile:?} parsed as {got:?}");
        }
    }

    #[test]
    fn a_real_digest_parses_verifies_and_addresses_its_blob() {
        // The empty-input sha256, so the fixture is checkable by hand.
        let d = Digest::parse(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .expect("the canonical empty digest must parse");
        assert_eq!(d.algorithm(), "sha256");
        assert!(d.matches(b""), "the empty input hashes to it");
        assert!(!d.matches(b"x"), "and nothing else does");
        assert_eq!(
            d.blob_path(),
            std::path::Path::new("blobs/sha256")
                .join("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            d.to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "round-trips to what the manifest said"
        );
    }

    #[test]
    fn an_algorithm_isopod_cannot_compute_is_refused_rather_than_addressed() {
        // sha512 is a legitimate OCI algorithm. Accepting it *as an address*
        // while having no way to compute it would mean a blob addressed by a
        // digest nothing verifies — a verification that silently is not one.
        let err = Digest::parse(&format!("sha512:{}", "a".repeat(128))).expect_err("refused");
        assert!(
            matches!(err, DigestError::UnsupportedAlgorithm(ref a) if a == "sha512"),
            "{err:?}"
        );
        assert!(err.to_string().contains("could not be verified"), "{err}");
    }
}
