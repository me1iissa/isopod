//! Kernel command-line (`/proc/cmdline`) parsing shared by the overlay and
//! network configuration paths.
//!
//! isopod passes boot-time configuration as `key=value` tokens on the kernel
//! command line (e.g. `isopod.layers=3`, `isopod.net=10.107.0.2/30`). This keeps
//! boot configuration out of the vsock RPC protocol — the agent reads it once at
//! start, before the server is even listening.

use std::io;

/// Read `/proc/cmdline`.
///
/// # Errors
/// If the file cannot be read (proc not mounted yet, etc.).
pub fn read() -> io::Result<String> {
    std::fs::read_to_string("/proc/cmdline")
}

/// Return the value of the `key=value` token whose key is exactly `key`, or
/// `None` if the key is absent.
///
/// Only the first match is returned. A bare `key` with no `=` does not match
/// (isopod's keys always carry a value).
pub fn value<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline.split_whitespace().find_map(|tok| {
        let (k, v) = tok.split_once('=')?;
        (k == key).then_some(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_finds_present_key() {
        let c = "console=ttyS0 isopod.layers=3 isopod.net=10.107.0.2/30 quiet";
        assert_eq!(value(c, "isopod.layers"), Some("3"));
        assert_eq!(value(c, "isopod.net"), Some("10.107.0.2/30"));
        assert_eq!(value(c, "console"), Some("ttyS0"));
    }

    #[test]
    fn value_absent_key_is_none() {
        let c = "console=ttyS0 quiet";
        assert_eq!(value(c, "isopod.net"), None);
    }

    #[test]
    fn value_empty_value_is_some_empty() {
        assert_eq!(value("isopod.dns=", "isopod.dns"), Some(""));
    }

    #[test]
    fn value_bare_flag_without_equals_does_not_match() {
        assert_eq!(value("quiet ro isopod.net", "isopod.net"), None);
    }

    #[test]
    fn value_returns_first_match() {
        assert_eq!(value("k=a k=b", "k"), Some("a"));
    }
}
