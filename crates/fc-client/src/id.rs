//! Validated identifiers.
//!
//! Two newtypes guard identifiers that Firecracker (or the host kernel) is
//! picky about:
//!
//! * [`VmId`] — the `--id` passed to the Firecracker binary. Firecracker
//!   accepts only `[A-Za-z0-9_-]{1,60}`; anything else (notably a `.`) makes
//!   the process abort with `SIGABRT` before it produces any useful log
//!   output. Validating up front turns that crash into a typed error.
//! * [`IfName`] — a host network interface name derived per-VM. The kernel's
//!   `IFNAMSIZ` limit means a usable interface name is at most 15 bytes; a
//!   16th byte silently truncates or is rejected at `TUNSETIFF` time.

use std::fmt;
use std::str::FromStr;

/// Maximum length Firecracker accepts for a VM id.
pub const VM_ID_MAX_LEN: usize = 60;

/// Maximum usable interface name length (`IFNAMSIZ` is 16, one byte is the NUL
/// terminator, leaving 15 usable bytes).
pub const IF_NAME_MAX_LEN: usize = 15;

/// Error returned when constructing a [`VmId`] or [`IfName`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// The identifier was empty.
    #[error("identifier must not be empty")]
    Empty,
    /// The VM id exceeded [`VM_ID_MAX_LEN`] bytes.
    #[error("VM id is {len} chars, exceeds the {VM_ID_MAX_LEN}-char limit")]
    TooLong {
        /// The offending length.
        len: usize,
    },
    /// The VM id contained a character outside `[A-Za-z0-9_-]`.
    ///
    /// A `.` is the classic offender: `firecracker --id def6.1-1` aborts with
    /// `SIGABRT` and no log line.
    #[error("VM id contains invalid character {ch:?}; allowed set is [A-Za-z0-9_-]")]
    InvalidChar {
        /// The first invalid character encountered.
        ch: char,
    },
    /// The interface name exceeded [`IF_NAME_MAX_LEN`] bytes (`IFNAMSIZ`).
    #[error("interface name is {len} bytes, exceeds the {IF_NAME_MAX_LEN}-byte IFNAMSIZ limit")]
    IfNameTooLong {
        /// The offending byte length.
        len: usize,
    },
    /// The interface name contained a character the kernel disallows
    /// (whitespace, `/`, `:`, or a control byte).
    #[error("interface name contains invalid character {ch:?}")]
    IfNameInvalidChar {
        /// The first invalid character encountered.
        ch: char,
    },
}

/// A validated Firecracker instance id (`--id`).
///
/// Guaranteed to match `[A-Za-z0-9_-]{1,60}`, so it can never trip the
/// dot-in-id `SIGABRT`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmId(String);

impl VmId {
    /// Validates `s` and constructs a [`VmId`].
    ///
    /// # Errors
    /// Returns [`IdError`] if `s` is empty, longer than [`VM_ID_MAX_LEN`], or
    /// contains a character outside `[A-Za-z0-9_-]`.
    pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(IdError::Empty);
        }
        if s.len() > VM_ID_MAX_LEN {
            return Err(IdError::TooLong { len: s.len() });
        }
        if let Some(ch) = s
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
        {
            return Err(IdError::InvalidChar { ch });
        }
        Ok(VmId(s))
    }

    /// Returns the id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Builds a host interface name of the form `<prefix><id>`, validated
    /// against `IFNAMSIZ`.
    ///
    /// Handy for deriving a per-VM tap/veth name from the VM id while keeping
    /// the 15-byte kernel limit enforced at construction.
    ///
    /// # Errors
    /// Returns [`IdError::IfNameTooLong`] if the combined name exceeds
    /// [`IF_NAME_MAX_LEN`] bytes, or [`IdError::IfNameInvalidChar`] if it
    /// contains a kernel-disallowed character.
    pub fn ifname_with_prefix(&self, prefix: &str) -> Result<IfName, IdError> {
        IfName::new(format!("{prefix}{}", self.0))
    }
}

impl fmt::Display for VmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for VmId {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        VmId::new(s)
    }
}

impl TryFrom<String> for VmId {
    type Error = IdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        VmId::new(s)
    }
}

impl TryFrom<&str> for VmId {
    type Error = IdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        VmId::new(s)
    }
}

impl AsRef<str> for VmId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A validated host network interface name (`IFNAMSIZ`-safe, at most 15 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IfName(String);

impl IfName {
    /// Validates `s` and constructs an [`IfName`].
    ///
    /// # Errors
    /// Returns [`IdError`] if `s` is empty, longer than [`IF_NAME_MAX_LEN`]
    /// bytes, or contains whitespace, `/`, `:`, or a control character.
    pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(IdError::Empty);
        }
        if s.len() > IF_NAME_MAX_LEN {
            return Err(IdError::IfNameTooLong { len: s.len() });
        }
        if let Some(ch) = s
            .chars()
            .find(|c| c.is_whitespace() || c.is_control() || *c == '/' || *c == ':')
        {
            return Err(IdError::IfNameInvalidChar { ch });
        }
        Ok(IfName(s))
    }

    /// Returns the interface name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for IfName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_ids() {
        for s in ["a", "vm-0", "VM_1", "def6-1-1", "abcABC012_-"] {
            assert!(VmId::new(s).is_ok(), "should accept {s:?}");
        }
    }

    #[test]
    fn rejects_dot_in_id() {
        // The exact M0 failure: `firecracker --id def6.1-1` SIGABRTs.
        match VmId::new("def6.1-1") {
            Err(IdError::InvalidChar { ch: '.' }) => {}
            other => panic!("expected InvalidChar('.'), got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_and_overlong() {
        assert_eq!(VmId::new(""), Err(IdError::Empty));
        let long = "a".repeat(61);
        assert_eq!(VmId::new(long), Err(IdError::TooLong { len: 61 }));
        // Exactly 60 is fine.
        assert!(VmId::new("a".repeat(60)).is_ok());
    }

    #[test]
    fn rejects_other_punctuation() {
        for bad in ["vm.1", "vm/1", "vm 1", "vm:1", "vm!", "vm+1"] {
            assert!(
                matches!(VmId::new(bad), Err(IdError::InvalidChar { .. })),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn ifname_enforces_ifnamsiz() {
        assert!(IfName::new("isopod-tap0").is_ok());
        // 15 bytes is the max usable length.
        assert!(IfName::new("a".repeat(15)).is_ok());
        assert_eq!(
            IfName::new("a".repeat(16)),
            Err(IdError::IfNameTooLong { len: 16 })
        );
        // The M0 failure: a 17-char interface name.
        assert!(matches!(
            IfName::new("isopod-tap-slot99"),
            Err(IdError::IfNameTooLong { len: 17 })
        ));
    }

    #[test]
    fn ifname_rejects_bad_chars() {
        for bad in ["eth 0", "eth/0", "eth:0"] {
            assert!(
                matches!(IfName::new(bad), Err(IdError::IfNameInvalidChar { .. })),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn derive_ifname_from_vmid() {
        let id = VmId::new("slot3").expect("valid id");
        let name = id.ifname_with_prefix("iso-tap-").expect("fits");
        assert_eq!(name.as_str(), "iso-tap-slot3");
        // Overlong prefix+id combination is rejected.
        let long = VmId::new("abcdefghij").expect("valid");
        assert!(long.ifname_with_prefix("isopod-veth-").is_err());
    }
}
