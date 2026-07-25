//! A credential value that the type system will not let you leak.
//!
//! The threat this addresses is not a clever attacker — it is an ordinary future
//! edit. A secret sitting in a plain `String` inside a struct is one
//! `#[derive(Debug)]`, one `.context(format!("… {value}"))`, or one added
//! `Serialize` away from appearing in an error message, a log line,
//! `egress.jsonl`, or a `RunReport` that goes straight into a model's context.
//!
//! [`Secret`] makes each of those a compile error or a redaction rather than a
//! runtime leak:
//!
//! - `Debug` is implemented by hand and prints `Secret(<redacted>)`. Formatting a
//!   containing struct with `{:?}` is therefore safe by default.
//! - `Display` is **not** implemented, so `format!("{secret}")` does not compile
//!   and a value cannot be interpolated into a message by accident.
//! - `Serialize` is **not** implemented, and must never be. Adding
//!   `#[derive(Serialize)]` to any struct that holds a `Secret` fails to compile
//!   — which is the entire point. That compile error is a feature; do not
//!   "fix" it by adding a serializer here.
//! - The inner bytes are reachable only through [`Secret::expose`], whose name is
//!   deliberately awkward and whose call sites are asserted by a test to live in
//!   only the two modules that legitimately need them.
//!
//! What this does **not** do: it is not a guard against an attacker who can read
//! this process's memory, and it does not zeroize on drop. Those are host-local
//! concerns on a single-user machine, and claiming otherwise would overstate it.

use std::fmt;

/// A credential value, redacted in every rendering the compiler will let you
/// reach.
///
/// See the module docs for the invariants — in particular, **do not implement
/// `Display` or `Serialize` for this type.**
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a resolved credential value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The raw value, for the one place that must put it on the wire.
    ///
    /// Named to be conspicuous in review and in a grep. A test asserts this is
    /// called only from the modules that construct an upstream request.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the value is empty once surrounding whitespace is ignored.
    ///
    /// An empty token is always a configuration mistake — an unset variable that
    /// expanded to nothing, or a file containing only a newline — and sending an
    /// empty `Authorization` header upstream would turn that mistake into a
    /// confusing 401 instead of a clear local error.
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }

    /// Bytes in the value. Safe to report: a length is not a secret, and it lets
    /// an operator tell "my token is truncated" from "my token is wrong".
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value has no bytes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the value contains a byte that cannot appear in an HTTP header
    /// field-value (RFC 9110 §5.5: visible ASCII, plus space and horizontal tab).
    ///
    /// A token carrying CR or LF would let a malformed credentials file split
    /// the request the broker builds — header injection sourced from
    /// configuration rather than from the guest. Rejected at load time, so the
    /// request builder never has to think about it.
    #[must_use]
    pub fn has_illegal_header_bytes(&self) -> bool {
        !self
            .0
            .bytes()
            .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
    }
}

impl fmt::Debug for Secret {
    /// Always redacts. This is what makes `{:?}` on a containing struct safe.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

// Deliberately absent, and to stay absent:
//   impl fmt::Display for Secret   — would allow `format!("{secret}")`
//   impl Serialize for Secret      — would allow a containing struct to derive it
//   impl AsRef<str> / Deref        — would launder the value into any &str sink

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_even_inside_a_containing_struct() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            alias: String,
            token: Secret,
        }
        let h = Holder {
            alias: "github".into(),
            token: Secret::new("ghp_verysecrettokenvalue".into()),
        };
        let rendered = format!("{h:?}");
        assert!(
            !rendered.contains("ghp_verysecrettokenvalue"),
            "a derived Debug on a containing struct must not leak: {rendered}"
        );
        assert!(rendered.contains("Secret(<redacted>)"), "{rendered}");
        // The non-secret fields still render, so the type stays debuggable.
        assert!(rendered.contains("github"), "{rendered}");
    }

    #[test]
    fn direct_debug_redacts() {
        let s = Secret::new("hunter2".into());
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
    }

    #[test]
    fn blank_and_length_helpers() {
        assert!(Secret::new(String::new()).is_blank());
        assert!(Secret::new("   \n\t ".into()).is_blank());
        assert!(!Secret::new("ghp_x".into()).is_blank());
        assert!(Secret::new(String::new()).is_empty());
        assert_eq!(Secret::new("abcde".into()).len(), 5);
    }

    #[test]
    fn illegal_header_bytes_are_detectable() {
        // The case that matters: a token with CRLF would split the request the
        // broker builds, injecting headers from the credentials file.
        assert!(!Secret::new("good_token_value".into()).has_illegal_header_bytes());
        assert!(Secret::new("tok\r\nX-Evil: 1".into()).has_illegal_header_bytes());
        assert!(Secret::new("tok\nmore".into()).has_illegal_header_bytes());
        assert!(Secret::new("tok\0".into()).has_illegal_header_bytes());
        // Tab and space are legal in a field-value.
        assert!(!Secret::new("tok with space".into()).has_illegal_header_bytes());
        assert!(!Secret::new("tok\twith tab".into()).has_illegal_header_bytes());
        // Non-ASCII is not a legal field-value byte.
        assert!(Secret::new("tökén".into()).has_illegal_header_bytes());
    }

    #[test]
    fn expose_returns_the_value_verbatim() {
        // The one sanctioned way out. Verbatim matters: trimming here would
        // silently alter a token whose trailing space is significant.
        let s = Secret::new("ghp_abc ".into());
        assert_eq!(s.expose(), "ghp_abc ");
    }
}
